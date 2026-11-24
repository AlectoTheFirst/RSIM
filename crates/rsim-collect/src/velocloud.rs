//! The VeloCloud source: the Portal API and the API v2 of a VeloCloud
//! Orchestrator over HTTPS. One device is one enterprise of an
//! orchestrator, and one read of the enterprise gives all its edges.
//!
//! The source keeps the modules of each edge across cycles and reads them
//! again only for an edge whose signature changed, whose modules are older
//! than the refresh ceiling, or whose modules it does not hold. The
//! enterprise devices of one orchestrator share one `getAggregates` read in
//! each cycle and the workers of the orchestrator.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::future::join_all;
use rsim_store::{
    Cell, Class, Format, Row, Store, TableSchema, VELOCLOUD_BGP_SESSION, VELOCLOUD_EDGE_STATE,
    VELOCLOUD_LINK_STATE, VELOCLOUD_ROUTE,
};
use serde_json::{Map, Value, json};
use tokio::sync::{OnceCell, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

pub use crate::redact::{REDACTED, redact};
use crate::{
    BoxFuture, Clock, Device, Extract, HttpReply, Https, RawSection, SectionSpec, Source, Timeouts,
    TransportError, Vendor,
};

/// The Portal read of the numeric id of each enterprise.
pub const AGGREGATES: &str = "/portal/rest/monitoring/getAggregates";
/// The Portal read of the edges of an enterprise.
pub const EDGES: &str = "/portal/rest/enterprise/getEnterpriseEdges";
/// The Portal read of the profiles of an enterprise.
pub const PROFILES: &str = "/portal/rest/enterprise/getEnterpriseConfigurations";
/// The Portal read of the overlay route table of an enterprise.
pub const ROUTE_TABLE: &str = "/portal/rest/enterprise/getEnterpriseRouteTable";
/// The Portal read of the modules of one edge.
pub const MODULES: &str = "/portal/rest/edge/getEdgeConfigurationModules";
/// The Portal read of the SD-WAN peers of one edge.
pub const SDWAN_PEERS: &str = "/portal/rest/edge/getEdgeSDWANPeers";
/// The Portal read of the BGP peers of each edge of an enterprise.
pub const BGP_PEER_STATUS: &str = "/portal/rest/monitoring/getEnterpriseEdgeBgpPeerStatus";
/// The Portal read of the address groups and the port groups.
pub const OBJECT_GROUPS: &str = "/portal/rest/enterprise/getObjectGroups";

/// The Portal paths that the source sends. Each is a read.
pub const READ_PATHS: &[&str] = &[
    AGGREGATES,
    EDGES,
    PROFILES,
    ROUTE_TABLE,
    MODULES,
    SDWAN_PEERS,
    BGP_PEER_STATUS,
    OBJECT_GROUPS,
];

/// The statuses of a Portal read that give a gap.
pub const PORTAL_GAP_STATUSES: &[u16] = &[400, 403, 404, 405, 501];

/// The statuses of the `bgpSessions` read that give a gap.
pub const BGP_GAP_STATUSES: &[u16] = &[403, 404, 405, 501];

/// The largest number of pages of one paged read.
pub const MAX_PAGES: usize = 10_000;

/// The API v2 base path with no setting.
pub const DEFAULT_BASE: &str = "/api/sdwan/v2";

/// The requests in flight to one orchestrator with no setting.
pub const DEFAULT_CONCURRENCY: usize = 4;

/// The largest number of requests in flight to one orchestrator.
pub const MAX_CONCURRENCY: usize = 16;

/// The refresh ceiling of the modules of an edge with no setting.
pub const DEFAULT_REFRESH: Duration = Duration::from_secs(1800);

/// The members of `with` of the edge read.
const EDGE_WITH: [&str; 4] = ["site", "links", "ha", "configuration"];

/// The modules of the module read.
const EDGE_MODULES: [&str; 2] = ["WAN", "controlPlane"];

/// The time of the device on top of the time of the pipeline: 60 s for
/// each of the 4 large reads.
const LARGE_READS_TIME: Duration = Duration::from_secs(4 * 60);

/// The settings of an orchestrator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Orchestrator {
    /// The API v2 base path.
    pub base: String,
    /// The orchestrator release, with 3 or 4 numbers. A device with no
    /// release fails before any read.
    pub release: Option<String>,
    /// The requests in flight to the orchestrator, from 1 to
    /// [`MAX_CONCURRENCY`].
    pub concurrency: usize,
    /// The refresh ceiling of the modules of an edge. Zero reads them in
    /// each cycle.
    pub refresh: Duration,
    /// The identity of the token, from [`token_id`]. A new token makes the
    /// module memory of the device cold.
    pub token_id: String,
}

impl Default for Orchestrator {
    fn default() -> Orchestrator {
        Orchestrator {
            base: DEFAULT_BASE.to_string(),
            release: None,
            concurrency: DEFAULT_CONCURRENCY,
            refresh: DEFAULT_REFRESH,
            token_id: String::new(),
        }
    }
}

/// The identity of a token: a BLAKE3 key derivation of the token, as hex.
pub fn token_id(token: &str) -> String {
    blake3::Hash::from(blake3::derive_key(
        "rsim-collect velocloud token identity",
        token.as_bytes(),
    ))
    .to_hex()
    .to_string()
}

pub use rsim_inventory::env::{check_release, enterprise_device as device_id, enterprise_ids};

/// A positive numeric id: a positive integer or a whole float. A boolean,
/// 0, a negative number and a string are not ids.
pub fn numeric_id(v: &Value) -> Option<u64> {
    let Value::Number(n) = v else {
        return None;
    };
    if let Some(i) = n.as_u64() {
        return (i > 0).then_some(i);
    }
    let f = n.as_f64()?;
    // The cast is exact for a whole float below 2^64.
    (f > 0.0 && f.fract() == 0.0 && f < 18_446_744_073_709_551_616.0).then_some(f as u64)
}

/// The rows of an answer: a bare array, or the `data` array of an object.
fn items(v: &Value) -> &[Value] {
    match v {
        Value::Array(a) => a.as_slice(),
        Value::Object(m) => match m.get("data") {
            Some(Value::Array(a)) => a.as_slice(),
            _ => &[],
        },
        _ => &[],
    }
}

/// A string or a number as text.
fn text_of(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The last word of a path of the Portal API, the name of its operation.
fn operation(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The signature of an edge row: the BLAKE3 hash in hex of the compact
/// JSON with sorted keys of its serial number, the identity fields of its
/// links in sorted order and its `configuration` block. A missing field is
/// `null`.
pub fn signature(edge: &Value) -> String {
    const LINK_IDENTITY: [&str; 6] = [
        "logicalId",
        "internalId",
        "interface",
        "ipAddress",
        "ipV6Address",
        "netmask",
    ];
    let mut links: Vec<String> = items(edge.get("links").unwrap_or(&Value::Null))
        .iter()
        .map(|l| {
            let m: Map<String, Value> = LINK_IDENTITY
                .iter()
                .map(|k| (k.to_string(), l.get(*k).cloned().unwrap_or(Value::Null)))
                .collect();
            Value::Object(m).to_string()
        })
        .collect();
    links.sort();
    let links: Vec<Value> = links
        .iter()
        .map(|l| serde_json::from_str(l).expect("the text is JSON"))
        .collect();
    let v = json!({
        "serial": edge.get("serialNumber").cloned().unwrap_or(Value::Null),
        "links": links,
        "configuration": edge.get("configuration").cloned().unwrap_or(Value::Null),
    });
    blake3::hash(v.to_string().as_bytes()).to_hex().to_string()
}

/// The modules of an edge from an earlier read.
#[derive(Clone, Debug, PartialEq)]
struct Module {
    value: Map<String, Value>,
    observed_at_ms: u64,
    signature: String,
    /// The memory key of the run that read the module.
    key: String,
}

/// The modules of the edges of one enterprise device.
#[derive(Debug, Default)]
struct Edges {
    /// The memory key of the modules. `None` for modules from a stored
    /// section, whose own keys the next fetch compares with its key.
    key: Option<String>,
    modules: BTreeMap<String, Module>,
}

/// The answer of `getAggregates` in one cycle.
#[derive(Clone, Debug)]
enum Aggregates {
    Answer(Value),
    Gap(String),
}

/// The state of the source across cycles: the modules of each edge, the
/// `getAggregates` answer of each orchestrator and token in the current
/// cycle and the workers of each orchestrator. The source of each cycle
/// shares one.
#[derive(Debug, Default)]
pub struct VelocloudMemory {
    devices: Mutex<HashMap<String, Edges>>,
    aggregates: Mutex<HashMap<(String, String), Arc<OnceCell<Aggregates>>>>,
    workers: Mutex<HashMap<String, (usize, Arc<Semaphore>)>>,
}

impl VelocloudMemory {
    pub fn new() -> VelocloudMemory {
        VelocloudMemory::default()
    }

    /// Fills the modules of a device from the bytes of its stored
    /// `edge_modules` section. A gap and an entry with no signature or no
    /// memory key are not modules. Gives the number of edges with modules.
    pub fn warm(&self, device: &str, bytes: &[u8]) -> Result<usize, String> {
        let v: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let Value::Object(edges) = v else {
            return Err("the section is not an object".into());
        };
        let mut modules = BTreeMap::new();
        for (edge, value) in edges {
            let Value::Object(mut value) = value else {
                continue;
            };
            if value.contains_key("_capability") {
                continue;
            }
            let Some(fresh) = value.remove("_freshness") else {
                continue;
            };
            let (Some(observed_at_ms), Some(signature), Some(key)) = (
                fresh.get("observed_at_ms").and_then(Value::as_u64),
                fresh.get("signature").and_then(Value::as_str),
                fresh.get("key").and_then(Value::as_str),
            ) else {
                continue;
            };
            modules.insert(
                edge,
                Module {
                    value,
                    observed_at_ms,
                    signature: signature.to_string(),
                    key: key.to_string(),
                },
            );
        }
        let n = modules.len();
        self.devices
            .lock()
            .expect("the lock is not poisoned")
            .insert(device.to_string(), Edges { key: None, modules });
        Ok(n)
    }

    /// Fills the modules of each VeloCloud device of the newest snapshot
    /// of a store from its `edge_modules` section. Gives the number of
    /// devices.
    pub fn warm_from(&self, store: &Store) -> Result<usize, String> {
        let Some(snap) = store.latest().map_err(|e| e.to_string())? else {
            return Ok(0);
        };
        let mut n = 0;
        for (device, m) in &snap.devices {
            if m.vendor != Vendor::Velocloud.name() {
                continue;
            }
            let Some(blob) = m.section("edge_modules").and_then(|s| s.blob) else {
                continue;
            };
            let bytes = store.read_blob(&blob).map_err(|e| e.to_string())?;
            self.warm(device, &bytes)
                .map_err(|e| format!("{device}: {e}"))?;
            n += 1;
        }
        Ok(n)
    }

    /// The edges with modules of a device, in logicalId order.
    pub fn edges(&self, device: &str) -> Vec<String> {
        self.devices
            .lock()
            .expect("the lock is not poisoned")
            .get(device)
            .map(|e| e.modules.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// The workers of an orchestrator.
    fn workers(&self, address: &str, concurrency: usize) -> Arc<Semaphore> {
        let mut w = self.workers.lock().expect("the lock is not poisoned");
        let e = w
            .entry(address.to_string())
            .or_insert_with(|| (concurrency, Arc::new(Semaphore::new(concurrency))));
        if e.0 != concurrency {
            *e = (concurrency, Arc::new(Semaphore::new(concurrency)));
        }
        e.1.clone()
    }

    /// The `getAggregates` answer of an orchestrator and a token in the
    /// current cycle.
    fn aggregates(&self, address: &str, token_id: &str) -> Arc<OnceCell<Aggregates>> {
        self.aggregates
            .lock()
            .expect("the lock is not poisoned")
            .entry((address.to_string(), token_id.to_string()))
            .or_default()
            .clone()
    }
}

/// Reads the enterprises of VeloCloud orchestrators.
pub struct VelocloudSource {
    https: Arc<dyn Https>,
    memory: Arc<VelocloudMemory>,
    clock: Arc<dyn Clock>,
    orchestrators: HashMap<String, Orchestrator>,
}

impl VelocloudSource {
    pub fn new(
        https: Arc<dyn Https>,
        memory: Arc<VelocloudMemory>,
        clock: Arc<dyn Clock>,
    ) -> VelocloudSource {
        VelocloudSource {
            https,
            memory,
            clock,
            orchestrators: HashMap::new(),
        }
    }

    /// Sets the orchestrator settings of a device. A device with no
    /// settings has the defaults.
    pub fn with_orchestrator(mut self, device: &str, o: Orchestrator) -> VelocloudSource {
        self.orchestrators.insert(device.to_string(), o);
        self
    }

    fn orchestrator(&self, device: &Device) -> Orchestrator {
        self.orchestrators
            .get(&device.id)
            .cloned()
            .unwrap_or_default()
    }
}

fn spec(
    name: &'static str,
    command: String,
    class: Class,
    volatile: &'static [&'static str],
    keep: &'static [&'static str],
    extracts: &'static [&'static dyn Extract],
) -> SectionSpec {
    SectionSpec {
        name,
        command,
        class,
        format: Format::Json,
        volatile,
        extracts,
        keep,
        optional: true,
    }
}

/// The sections of an enterprise, in the order of the reads. Each section
/// can be absent: a gap of its read, or an enterprise or a fallback that
/// does not read it.
pub fn sections(base: &str, enterprise: &str) -> Vec<SectionSpec> {
    use Class::{Configuration, Observation};
    let post = |p: &str| format!("POST {p}");
    vec![
        spec(
            "aggregates",
            post(AGGREGATES),
            Configuration,
            &[],
            AGGREGATES_KEEP,
            &[],
        ),
        spec(
            "edges",
            post(EDGES),
            Configuration,
            EDGES_VOLATILE,
            &[],
            &[],
        ),
        spec(
            "edge_state",
            post(EDGES),
            Observation,
            &[],
            EDGE_STATE_KEEP,
            &[&EdgeStateExtract, &LinkStateExtract],
        ),
        spec("profiles", post(PROFILES), Configuration, &[], &[], &[]),
        spec(
            "route_table",
            post(ROUTE_TABLE),
            Observation,
            &[],
            ROUTE_TABLE_KEEP,
            &[&RouteExtract],
        ),
        spec(
            "edges_v2",
            format!("GET {base}/enterprises/{enterprise}/edges"),
            Configuration,
            &[],
            &[],
            &[],
        ),
        spec(
            "edge_modules",
            post(MODULES),
            Configuration,
            &["/*/_freshness"],
            &[],
            &[],
        ),
        spec(
            "sdwan_peers",
            post(SDWAN_PEERS),
            Observation,
            &["/*/*/scoreAfter*", "/*/*/pathQoe"],
            &[],
            &[],
        ),
        spec(
            "bgp_sessions",
            format!("GET {base}/enterprises/{enterprise}/bgpSessions"),
            Observation,
            &[],
            BGP_SESSIONS_KEEP,
            &[&BgpSessionExtract],
        ),
        spec(
            "bgp_peer_status",
            post(BGP_PEER_STATUS),
            Observation,
            &[],
            BGP_PEER_STATUS_KEEP,
            &[],
        ),
        spec(
            "object_groups",
            post(OBJECT_GROUPS),
            Configuration,
            &[],
            &[],
            &[],
        ),
    ]
}

/// The index of each section in [`sections`].
const S_AGGREGATES: usize = 0;
const S_EDGES: usize = 1;
const S_EDGE_STATE: usize = 2;
const S_PROFILES: usize = 3;
const S_ROUTE_TABLE: usize = 4;
const S_EDGES_V2: usize = 5;
const S_EDGE_MODULES: usize = 6;
const S_SDWAN_PEERS: usize = 7;
const S_BGP_SESSIONS: usize = 8;
const S_BGP_PEER_STATUS: usize = 9;
const S_OBJECT_GROUPS: usize = 10;
const SECTION_COUNT: usize = 11;

const AGGREGATES_KEEP: &[&str] = &[
    "enterprises/*/id",
    "enterprises/*/logicalId",
    "*/id",
    "*/logicalId",
];

const EDGES_VOLATILE: &[&str] = &[
    "/*/edgeState",
    "/*/haState",
    "/*/ha/data/haState",
    "/*/lastActive",
    "/*/links/*/state",
    "/*/links/*/linkMode",
    "/*/links/*/vpnState",
    "/*/links/*/backupState",
    "/*/links/*/lastActive",
];

const EDGE_STATE_KEEP: &[&str] = &[
    "*/id",
    "*/logicalId",
    "*/edgeState",
    "*/haState",
    "*/ha/data/haState",
    "*/links/*/logicalId",
    "*/links/*/internalId",
    "*/links/*/state",
    "*/links/*/linkMode",
    "*/links/*/vpnState",
    "*/links/*/backupState",
];

/// `*Exits` is `preferredExits` and `eligableExits`.
const ROUTE_TABLE_KEEP: &[&str] = &[
    "profiles",
    "subnets/*/subnet",
    "subnets/*/ipVersion",
    "subnets/*/learnedRoute/cidrIp",
    "subnets/*/learnedRoute/cidrPrefix",
    "subnets/*/learnedRoute/segmentId",
    "subnets/*/learnedRoute/logicalId",
    "subnets/*/*Exits/*/type",
    "subnets/*/*Exits/*/exitType",
    "subnets/*/*Exits/*/entity",
    "subnets/*/*Exits/*/state",
    "subnets/*/*Exits/*/protocol",
    "subnets/*/*Exits/*/routeType",
    "subnets/*/*Exits/*/cost",
    "subnets/*/*Exits/*/metric",
    "subnets/*/*Exits/*/segmentId",
    "subnets/*/*Exits/*/edgeId",
    "subnets/*/*Exits/*/edgeLogicalId",
    "subnets/*/*Exits/*/interface",
    "subnets/*/*Exits/*/neighborIp",
    "subnets/*/*Exits/*/nextHopIp",
    "subnets/*/*Exits/*/cidrIp",
    "subnets/*/*Exits/*/cidrPrefix",
    "subnets/*/*Exits/*/isOwner",
    "subnets/*/*Exits/*/advertise",
    "subnets/*/*Exits/*/neighborTag",
    "subnets/*/*Exits/*/learnedBy",
    "subnets/*/*Exits/*/filtered",
];

const BGP_SESSIONS_KEEP: &[&str] = &[
    "*/edge/_href",
    "*/edge/logicalId",
    "*/neighborIp",
    "*/neighborAS",
    "*/state",
];

const BGP_PEER_STATUS_KEEP: &[&str] = &[
    "*/edgeId",
    "*/edgeLogicalId",
    "*/state",
    "*/data/enterpriseLogicalId",
    "*/data/neighborIp",
    "*/data/neighborAS",
    "*/data/state",
];

/// The result of one section: the bytes, or an absent section.
type Outcome = Result<Vec<u8>, TransportError>;

fn absent(reason: impl Into<String>) -> Outcome {
    Err(TransportError::NotFound(reason.into()))
}

fn bytes(v: &Value) -> Outcome {
    Ok(v.to_string().into_bytes())
}

/// The answer of a Portal read, or the reason of its gap.
enum Portal {
    Answer(Value),
    Gap(String),
}

/// The pages of a paged read, or the status that ended it.
enum Paged {
    Pages(Vec<Value>),
    Status(u16, String),
}

/// The error message of a 200 answer with an `error` member.
fn error_message(v: &Value) -> Option<String> {
    match v.get("error")? {
        Value::Object(e) => Some(
            e.get("message")
                .and_then(Value::as_str)
                .unwrap_or("error")
                .to_string(),
        ),
        _ => None,
    }
}

/// The gap of one edge in `edge_modules` and `sdwan_peers`.
fn edge_gap(reason: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(
        "_capability".into(),
        json!({"status": "unavailable", "reason": reason}),
    );
    m
}

fn parse(body: &[u8], path: &str) -> Result<Value, String> {
    let mut v: Value = serde_json::from_slice(body)
        .map_err(|e| format!("{}: the answer is not JSON: {e}", operation(path)))?;
    redact(&mut v);
    Ok(v)
}

/// A query value with each byte other than an unreserved character
/// percent-encoded.
fn query_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Runs a read until `deadline`, if one is set.
async fn within<T>(
    deadline: Option<Instant>,
    f: impl Future<Output = Result<T, TransportError>>,
) -> Result<T, TransportError> {
    match deadline {
        Some(d) => tokio::time::timeout_at(d, f)
            .await
            .unwrap_or(Err(TransportError::Timeout)),
        None => f.await,
    }
}

/// Reads each page of a paged API v2 read. Page 1 sends `query`, and each
/// next page sends only the `nextPageLink` token of the page before it.
/// No `metaData` ends the read. A `metaData` that is not an object, a
/// token that is not a string, a repeated token or more than
/// [`MAX_PAGES`] pages fail the read.
async fn pages(
    https: &dyn Https,
    device: &Device,
    path: &str,
    query: &str,
    deadline: Option<Instant>,
    workers: Option<&Arc<Semaphore>>,
) -> Result<Paged, String> {
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    let mut seen = BTreeSet::new();
    loop {
        if out.len() >= MAX_PAGES {
            return Err(format!("{path}: more than {MAX_PAGES} pages"));
        }
        let url = match &token {
            None if query.is_empty() => path.to_string(),
            None => format!("{path}?{query}"),
            Some(t) => format!("{path}?nextPageLink={}", query_value(t)),
        };
        let permit = match workers {
            Some(w) => Some(acquire(w).await),
            None => None,
        };
        let reply = within(deadline, https.get_status(device, &url))
            .await
            .map_err(|e| format!("{path}: {e}"))?;
        drop(permit);
        let page = match reply {
            HttpReply::Body(b) => parse(&b, path)?,
            HttpReply::Status { status, text } => return Ok(Paged::Status(status, text)),
        };
        let meta = match &page {
            Value::Object(m) => m.get("metaData").cloned(),
            _ => None,
        };
        out.push(page);
        match meta {
            None | Some(Value::Null) => return Ok(Paged::Pages(out)),
            Some(Value::Object(m)) => match m.get("nextPageLink") {
                None | Some(Value::Null) => return Ok(Paged::Pages(out)),
                Some(Value::String(t)) if t.is_empty() => return Ok(Paged::Pages(out)),
                Some(Value::String(t)) => {
                    if !seen.insert(t.clone()) {
                        return Err(format!("{path}: the page tokens are cyclic"));
                    }
                    token = Some(t.clone());
                }
                Some(_) => return Err(format!("{path}: the page token is not a string")),
            },
            Some(_) => return Err(format!("{path}: the metaData of a page is not an object")),
        }
    }
}

/// The rows of the pages joined in page order. A page that is not an
/// array or an object with a `data` array fails.
fn joined(pages: Vec<Value>, path: &str) -> Result<Vec<Value>, String> {
    let mut rows = Vec::new();
    for page in pages {
        match page {
            Value::Array(a) => rows.extend(a),
            Value::Object(mut m) => match m.remove("data") {
                Some(Value::Array(a)) => rows.extend(a),
                _ => return Err(format!("{path}: a page is not an array")),
            },
            _ => return Err(format!("{path}: a page is not an array")),
        }
    }
    Ok(rows)
}

async fn acquire(workers: &Arc<Semaphore>) -> OwnedSemaphorePermit {
    workers
        .clone()
        .acquire_owned()
        .await
        .expect("the semaphore is not closed")
}

/// The enterprises of an orchestrator: the logicalId and the name of each,
/// from the paged `GET <base>/enterprises`.
pub async fn discover(
    https: &dyn Https,
    device: &Device,
    base: &str,
) -> Result<Vec<(String, Option<String>)>, String> {
    let path = format!("{base}/enterprises");
    let rows = match pages(https, device, &path, "", None, None).await? {
        Paged::Pages(p) => joined(p, &path)?,
        Paged::Status(status, text) => return Err(format!("{path}: HTTP {status}: {text}")),
    };
    Ok(rows
        .iter()
        .filter_map(|r| {
            let id = text_of(r.get("logicalId"))?;
            Some((id, text_of(r.get("name"))))
        })
        .collect())
}

/// Reads one edge of each enterprise with `GET <base>/enterprises/{id}/edges`
/// and `limit=1`, or one enterprise with `GET <base>/enterprises` and
/// `limit=1` for an empty list. Gives the name of each read with its
/// result.
pub async fn probe(
    https: &dyn Https,
    device: &Device,
    base: &str,
    enterprises: &[String],
) -> Vec<(String, Result<(), String>)> {
    let paths: Vec<(String, String)> = if enterprises.is_empty() {
        vec![("enterprises".into(), format!("{base}/enterprises?limit=1"))]
    } else {
        enterprises
            .iter()
            .map(|e| (e.clone(), format!("{base}/enterprises/{e}/edges?limit=1")))
            .collect()
    };
    let mut out = Vec::new();
    for (name, path) in paths {
        let r = match https.get_status(device, &path).await {
            Ok(HttpReply::Body(b)) => serde_json::from_slice::<Value>(&b)
                .map(|_| ())
                .map_err(|e| format!("the answer is not JSON: {e}")),
            Ok(HttpReply::Status { status, text }) => Err(format!("HTTP {status}: {text}")),
            Err(e) => Err(e.to_string()),
        };
        out.push((name, r));
    }
    out
}

/// An edge of the listing.
struct Edge {
    logical: String,
    id: Option<u64>,
    signature: String,
}

/// The read of a module of one edge.
enum ModuleRead {
    Module(Map<String, Value>),
    Gap(String),
    /// A transport error, a 429 after its retries or a 5xx.
    Transient,
}

/// The time of `reads` requests at `concurrency` requests in each second.
fn pace_time(reads: usize, concurrency: usize) -> Duration {
    let ms = reads.saturating_mul(1000) / concurrency.max(1);
    Duration::from_millis(u64::try_from(ms).unwrap_or(u64::MAX))
}

/// The fetch of one enterprise device.
struct Run<'a> {
    source: &'a VelocloudSource,
    device: &'a Device,
    orch: Orchestrator,
    enterprise: String,
    workers: Arc<Semaphore>,
    workers_count: usize,
    /// The end of the time of the device. The module reads extend it.
    deadline: Mutex<Instant>,
    now: u64,
}

impl Run<'_> {
    fn deadline(&self) -> Instant {
        *self.deadline.lock().expect("the lock is not poisoned")
    }

    fn extend(&self, d: Duration) {
        *self.deadline.lock().expect("the lock is not poisoned") += d;
    }

    /// A Portal read on a worker of the orchestrator. A gap status or a
    /// 200 answer with an `error` member gives a gap, each other status,
    /// an answer that is not JSON and a transport error fail.
    async fn portal(&self, path: &'static str, body: Value) -> Result<Portal, String> {
        let reply = self.post(path, body).await;
        let op = operation(path);
        match reply {
            Ok(HttpReply::Body(b)) => {
                let v = parse(&b, path)?;
                Ok(match error_message(&v) {
                    Some(m) => Portal::Gap(format!("{op}: {m}")),
                    None => Portal::Answer(v),
                })
            }
            Ok(HttpReply::Status { status, .. }) if PORTAL_GAP_STATUSES.contains(&status) => {
                Ok(Portal::Gap(format!("{op}: {status}")))
            }
            Ok(HttpReply::Status { status, text }) => Err(format!("{op}: HTTP {status}: {text}")),
            Err(e) => Err(format!("{op}: {e}")),
        }
    }

    async fn post(&self, path: &'static str, body: Value) -> Result<HttpReply, TransportError> {
        let _permit = acquire(&self.workers).await;
        within(
            Some(self.deadline()),
            self.source
                .https
                .post_read(self.device, READ_PATHS, path, &body),
        )
        .await
    }

    async fn aggregates(&self) -> Result<Aggregates, String> {
        let cell = self
            .source
            .memory
            .aggregates(&self.device.address, &self.orch.token_id);
        cell.get_or_try_init(|| async {
            Ok::<_, String>(match self.portal(AGGREGATES, json!({})).await? {
                Portal::Answer(v) => Aggregates::Answer(v),
                Portal::Gap(g) => Aggregates::Gap(g),
            })
        })
        .await
        .cloned()
    }

    /// The modules of one edge: from the memory when the gate holds, else
    /// from a read. A 401, another status that is not a gap and an answer
    /// that is not JSON fail the device.
    async fn module(
        &self,
        e: &Edge,
        enterprise_id: Option<u64>,
    ) -> Result<Map<String, Value>, String> {
        let now = self.now;
        let (Some(eid), Some(id)) = (enterprise_id, e.id) else {
            return Ok(with_freshness(
                edge_gap("no numeric id for this edge"),
                now,
                false,
                None,
            ));
        };
        let key = self.key();
        let held = self.held(&e.logical, &key);
        let refresh = u64::try_from(self.orch.refresh.as_millis()).unwrap_or(u64::MAX);
        if let Some(m) = &held
            && m.signature == e.signature
            && now >= m.observed_at_ms
            && now - m.observed_at_ms < refresh
        {
            return Ok(with_freshness(
                m.value.clone(),
                m.observed_at_ms,
                false,
                Some((m.signature.as_str(), key.as_str())),
            ));
        }
        let body = json!({"enterpriseId": eid, "edgeId": id, "modules": EDGE_MODULES});
        Ok(match self.read_module(body).await? {
            ModuleRead::Module(value) => {
                self.hold(
                    &e.logical,
                    Module {
                        value: value.clone(),
                        observed_at_ms: now,
                        signature: e.signature.clone(),
                        key: key.clone(),
                    },
                );
                with_freshness(
                    value,
                    now,
                    false,
                    Some((e.signature.as_str(), key.as_str())),
                )
            }
            ModuleRead::Gap(g) => with_freshness(edge_gap(&g), now, false, None),
            ModuleRead::Transient => match held.filter(|m| m.signature == e.signature) {
                Some(m) => {
                    let signature = m.signature.clone();
                    with_freshness(
                        m.value,
                        m.observed_at_ms,
                        true,
                        Some((signature.as_str(), key.as_str())),
                    )
                }
                None => with_freshness(edge_gap("Observation refresh failed"), now, true, None),
            },
        })
    }

    async fn read_module(&self, body: Value) -> Result<ModuleRead, String> {
        let op = operation(MODULES);
        Ok(match self.post(MODULES, body).await {
            Ok(HttpReply::Body(b)) => {
                let v = parse(&b, MODULES)?;
                match (error_message(&v), v) {
                    (Some(m), _) => ModuleRead::Gap(format!("{op}: {m}")),
                    (None, Value::Object(m)) => ModuleRead::Module(m),
                    (None, _) => ModuleRead::Gap(format!("{op}: the answer is not an object")),
                }
            }
            Ok(HttpReply::Status { status, .. }) if PORTAL_GAP_STATUSES.contains(&status) => {
                ModuleRead::Gap(format!("{op}: {status}"))
            }
            Ok(HttpReply::Status { status, .. }) if status == 429 || status >= 500 => {
                ModuleRead::Transient
            }
            Ok(HttpReply::Status { status, text }) => {
                return Err(format!("{op}: HTTP {status}: {text}"));
            }
            Err(_) => ModuleRead::Transient,
        })
    }

    /// The module memory key of the device: a BLAKE3 hash of the
    /// orchestrator address, the base, the release, the enterprise and the
    /// identity of the token.
    fn key(&self) -> String {
        let text = format!(
            "{}\n{}\n{}\n{}\n{}",
            self.device.address,
            self.orch.base,
            self.orch.release.as_deref().unwrap_or(""),
            self.enterprise,
            self.orch.token_id
        );
        blake3::hash(text.as_bytes()).to_hex().to_string()
    }

    /// The module of an edge that the memory holds under `key`. The first
    /// call with a new key drops each module of another key.
    fn held(&self, edge: &str, key: &str) -> Option<Module> {
        let mut devices = self
            .source
            .memory
            .devices
            .lock()
            .expect("the lock is not poisoned");
        let e = devices.entry(self.device.id.clone()).or_default();
        if e.key.as_deref() != Some(key) {
            e.modules.retain(|_, m| m.key == key);
            e.key = Some(key.to_string());
        }
        e.modules.get(edge).cloned()
    }

    fn hold(&self, edge: &str, m: Module) {
        self.source
            .memory
            .devices
            .lock()
            .expect("the lock is not poisoned")
            .entry(self.device.id.clone())
            .or_default()
            .modules
            .insert(edge.to_string(), m);
    }

    /// Drops the modules of the edges that the cycle did not see.
    fn evict(&self, seen: &BTreeSet<&str>) {
        if let Some(e) = self
            .source
            .memory
            .devices
            .lock()
            .expect("the lock is not poisoned")
            .get_mut(&self.device.id)
        {
            e.modules.retain(|k, _| seen.contains(k.as_str()));
        }
    }

    /// The SD-WAN peers of one edge, or its gap.
    async fn peers(&self, e: &Edge, enterprise_id: Option<u64>) -> Result<Value, String> {
        let (Some(eid), Some(id)) = (enterprise_id, e.id) else {
            return Ok(Value::Object(edge_gap("no numeric id for this edge")));
        };
        Ok(
            match self
                .portal(SDWAN_PEERS, json!({"enterpriseId": eid, "edgeId": id}))
                .await?
            {
                Portal::Answer(v) => v,
                Portal::Gap(g) => Value::Object(edge_gap(&g)),
            },
        )
    }

    /// The sections of the enterprise, or the error that fails the device.
    async fn sections(&self) -> Result<Vec<Outcome>, String> {
        let mut out: Vec<Outcome> = (0..SECTION_COUNT).map(|_| absent("not read")).collect();
        let release = self
            .orch
            .release
            .as_deref()
            .ok_or("the orchestrator has no release")?;
        check_release(release)?;
        // getAggregates
        let enterprise_id = match self.aggregates().await? {
            Aggregates::Answer(v) => {
                out[S_AGGREGATES] = bytes(&v);
                let rows = match &v {
                    Value::Object(m) => m.get("enterprises").unwrap_or(&Value::Null),
                    other => other,
                };
                items(rows)
                    .iter()
                    .filter(|r| {
                        text_of(r.get("logicalId")).as_deref() == Some(self.enterprise.as_str())
                    })
                    .find_map(|r| numeric_id(r.get("id").unwrap_or(&Value::Null)))
            }
            Aggregates::Gap(g) => {
                out[S_AGGREGATES] = absent(g);
                None
            }
        };
        let mut edge_rows: Vec<Value> = Vec::new();
        let mut needs_v2 = true;
        match enterprise_id {
            None => {
                let reason = "no numeric id for enterprise";
                for i in [
                    S_EDGES,
                    S_EDGE_STATE,
                    S_PROFILES,
                    S_ROUTE_TABLE,
                    S_BGP_PEER_STATUS,
                    S_OBJECT_GROUPS,
                ] {
                    out[i] = absent(reason);
                }
            }
            Some(eid) => {
                let body = json!({"enterpriseId": eid, "with": EDGE_WITH});
                match self.portal(EDGES, body).await? {
                    Portal::Answer(v) => {
                        edge_rows = items(&v)
                            .iter()
                            .filter(|r| text_of(r.get("logicalId")).is_some())
                            .cloned()
                            .collect();
                        if edge_rows.is_empty() {
                            out[S_EDGES] = absent("getEnterpriseEdges: no edge answered");
                            out[S_EDGE_STATE] = absent("getEnterpriseEdges: no edge answered");
                        } else {
                            needs_v2 = false;
                            out[S_EDGES] = bytes(&v);
                            out[S_EDGE_STATE] = bytes(&v);
                        }
                    }
                    Portal::Gap(g) => {
                        out[S_EDGES] = absent(g.clone());
                        out[S_EDGE_STATE] = absent(g);
                    }
                }
                let body = json!({"enterpriseId": eid, "with": ["modules"]});
                out[S_PROFILES] = match self.portal(PROFILES, body).await? {
                    Portal::Answer(v)
                        if items(&v)
                            .iter()
                            .any(|r| numeric_id(r.get("id").unwrap_or(&Value::Null)).is_some()) =>
                    {
                        bytes(&v)
                    }
                    Portal::Answer(_) => absent("getEnterpriseConfigurations: no profile answered"),
                    Portal::Gap(g) => absent(g),
                };
                out[S_ROUTE_TABLE] = match self
                    .portal(ROUTE_TABLE, json!({"enterpriseId": eid}))
                    .await?
                {
                    Portal::Answer(v) => bytes(&v),
                    Portal::Gap(g) => absent(g),
                };
            }
        }
        // The API v2 edges, when the Portal gives none.
        if needs_v2 {
            let path = format!("{}/enterprises/{}/edges", self.orch.base, self.enterprise);
            let rows = match pages(
                self.source.https.as_ref(),
                self.device,
                &path,
                "",
                Some(self.deadline()),
                Some(&self.workers),
            )
            .await?
            {
                Paged::Pages(p) => joined(p, &path)?,
                Paged::Status(status, text) => {
                    return Err(format!("{path}: HTTP {status}: {text}"));
                }
            };
            out[S_EDGES_V2] = bytes(&Value::Array(rows.clone()));
            edge_rows = rows
                .into_iter()
                .filter(|r| text_of(r.get("logicalId")).is_some())
                .collect();
        } else {
            out[S_EDGES_V2] = absent("not needed");
        }
        let mut edges: Vec<Edge> = edge_rows
            .iter()
            .map(|r| Edge {
                logical: text_of(r.get("logicalId")).expect("the rows have a logicalId"),
                id: if needs_v2 {
                    None
                } else {
                    numeric_id(r.get("id").unwrap_or(&Value::Null))
                },
                signature: signature(r),
            })
            .collect();
        edges.sort_by(|a, b| a.logical.cmp(&b.logical));
        edges.dedup_by(|a, b| a.logical == b.logical);
        let reads = 2 * edges.iter().filter(|e| e.id.is_some()).count();
        self.extend(pace_time(reads, self.workers_count));
        // The modules and the SD-WAN peers of each edge, on the workers.
        let modules = join_all(edges.iter().map(|e| self.module(e, enterprise_id))).await;
        let mut section = Map::new();
        for (e, m) in edges.iter().zip(modules) {
            section.insert(e.logical.clone(), Value::Object(m?));
        }
        out[S_EDGE_MODULES] = bytes(&Value::Object(section));
        let peers = join_all(edges.iter().map(|e| self.peers(e, enterprise_id))).await;
        let mut section = Map::new();
        for (e, p) in edges.iter().zip(peers) {
            section.insert(e.logical.clone(), p?);
        }
        out[S_SDWAN_PEERS] = bytes(&Value::Object(section));
        // bgpSessions
        let path = format!(
            "{}/enterprises/{}/bgpSessions",
            self.orch.base, self.enterprise
        );
        out[S_BGP_SESSIONS] = match pages(
            self.source.https.as_ref(),
            self.device,
            &path,
            "state%5Bis%5D=ESTABLISHED",
            Some(self.deadline()),
            Some(&self.workers),
        )
        .await?
        {
            Paged::Pages(p) => bytes(&Value::Array(joined(p, &path)?)),
            Paged::Status(status, _) if BGP_GAP_STATUSES.contains(&status) => {
                absent(format!("bgpSessions: {status}"))
            }
            Paged::Status(status, text) => return Err(format!("{path}: HTTP {status}: {text}")),
        };
        if let Some(eid) = enterprise_id {
            for (i, path) in [
                (S_BGP_PEER_STATUS, BGP_PEER_STATUS),
                (S_OBJECT_GROUPS, OBJECT_GROUPS),
            ] {
                out[i] = match self.portal(path, json!({"enterpriseId": eid})).await? {
                    Portal::Answer(v) => bytes(&v),
                    Portal::Gap(g) => absent(g),
                };
            }
        }
        let seen: BTreeSet<&str> = edges.iter().map(|e| e.logical.as_str()).collect();
        self.evict(&seen);
        Ok(out)
    }
}

/// A module object or a gap with its `_freshness` member.
fn with_freshness(
    mut m: Map<String, Value>,
    observed_at_ms: u64,
    stale: bool,
    held: Option<(&str, &str)>,
) -> Map<String, Value> {
    let mut f = json!({"observed_at_ms": observed_at_ms, "stale": stale});
    if let Some((signature, key)) = held {
        f["signature"] = Value::String(signature.to_string());
        f["key"] = Value::String(key.to_string());
    }
    m.insert("_freshness".into(), f);
    m
}

impl Source for VelocloudSource {
    fn vendor(&self) -> Vendor {
        Vendor::Velocloud
    }

    fn sections(&self, device: &Device) -> Vec<SectionSpec> {
        sections(
            &self.orchestrator(device).base,
            device.site.as_deref().unwrap_or_default(),
        )
    }

    fn fetch<'a>(
        &'a self,
        device: &'a Device,
        timeouts: Timeouts,
    ) -> BoxFuture<'a, Vec<RawSection>> {
        Box::pin(async move {
            let specs = self.sections(device);
            let orch = self.orchestrator(device);
            let deadline = timeouts
                .deadline
                .unwrap_or_else(|| Instant::now() + timeouts.section)
                + LARGE_READS_TIME;
            let concurrency = orch.concurrency.clamp(1, MAX_CONCURRENCY);
            let run = Run {
                source: self,
                device,
                workers: self.memory.workers(&device.address, concurrency),
                workers_count: concurrency,
                enterprise: device.site.clone().unwrap_or_default(),
                orch,
                deadline: Mutex::new(deadline),
                now: self.clock.now_ms(),
            };
            let results = if run.enterprise.is_empty() {
                Err("the device has no enterprise logicalId".to_string())
            } else {
                run.sections().await
            };
            let results: Vec<Outcome> = match results {
                Ok(r) => r,
                Err(e) => (0..specs.len())
                    .map(|_| Err(TransportError::Command(e.clone())))
                    .collect(),
            };
            specs
                .into_iter()
                .zip(results)
                .map(|(spec, result)| RawSection { spec, result })
                .collect()
        })
    }

    fn begin_cycle(&self) {
        self.memory
            .aggregates
            .lock()
            .expect("the lock is not poisoned")
            .clear();
    }
}

fn str_cell(v: Option<&Value>) -> Cell {
    text_of(v).map_or(Cell::Null, Cell::Str)
}

fn at<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().try_fold(v, |v, k| v.get(*k))
}

fn rows_of(bytes: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|e| e.to_string())
}

/// `edge_state`: one row for each edge.
pub struct EdgeStateExtract;

impl Extract for EdgeStateExtract {
    fn table(&self) -> &'static TableSchema {
        &VELOCLOUD_EDGE_STATE
    }

    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
        let v = rows_of(bytes)?;
        Ok(items(&v)
            .iter()
            .filter_map(|e| {
                let edge = text_of(e.get("logicalId"))?;
                let ha = match str_cell(e.get("haState")) {
                    Cell::Null => str_cell(at(e, &["ha", "data", "haState"])),
                    h => h,
                };
                Some(vec![Cell::Str(edge), str_cell(e.get("edgeState")), ha])
            })
            .collect())
    }
}

/// `edge_state`: one row for each link of each edge.
pub struct LinkStateExtract;

impl Extract for LinkStateExtract {
    fn table(&self) -> &'static TableSchema {
        &VELOCLOUD_LINK_STATE
    }

    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
        let v = rows_of(bytes)?;
        let mut rows = Vec::new();
        for e in items(&v) {
            let Some(edge) = text_of(e.get("logicalId")) else {
                continue;
            };
            for l in items(e.get("links").unwrap_or(&Value::Null)) {
                rows.push(vec![
                    Cell::Str(edge.clone()),
                    str_cell(l.get("logicalId")),
                    str_cell(l.get("internalId")),
                    str_cell(l.get("state")),
                    str_cell(l.get("linkMode")),
                    str_cell(l.get("vpnState")),
                    str_cell(l.get("backupState")),
                ]);
            }
        }
        Ok(rows)
    }
}

/// `route_table`: one row for each preferred and each eligible exit of each
/// subnet. A subnet `<prefix>:<segment>` splits at its last colon.
pub struct RouteExtract;

impl Extract for RouteExtract {
    fn table(&self) -> &'static TableSchema {
        &VELOCLOUD_ROUTE
    }

    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
        let v = rows_of(bytes)?;
        let mut rows = Vec::new();
        for s in items(v.get("subnets").unwrap_or(&Value::Null)) {
            let learned = s.get("learnedRoute");
            let (prefix, segment) = match s.get("subnet").and_then(Value::as_str) {
                Some(subnet) => match subnet.rsplit_once(':') {
                    Some((p, seg))
                        if !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()) =>
                    {
                        (p.to_string(), Some(seg.to_string()))
                    }
                    _ => (subnet.to_string(), None),
                },
                None => {
                    let ip = learned.and_then(|l| text_of(l.get("cidrIp")));
                    let len = learned.and_then(|l| text_of(l.get("cidrPrefix")));
                    match (ip, len) {
                        (Some(ip), Some(len)) => (format!("{ip}/{len}"), None),
                        _ => continue,
                    }
                }
            };
            let segment = segment.or_else(|| learned.and_then(|l| text_of(l.get("segmentId"))));
            for (bucket, selection) in [
                ("preferredExits", "preferred"),
                ("eligableExits", "eligible"),
            ] {
                for x in items(s.get(bucket).unwrap_or(&Value::Null)) {
                    let segment = segment
                        .clone()
                        .or_else(|| text_of(x.get("segmentId")))
                        .map_or(Cell::Null, Cell::Str);
                    let cost = match x.get("cost") {
                        Some(Value::Number(n)) => n.as_u64().map_or(Cell::Null, Cell::U64),
                        Some(Value::String(c)) => c.parse().map_or(Cell::Null, Cell::U64),
                        _ => Cell::Null,
                    };
                    rows.push(vec![
                        segment,
                        Cell::Str(prefix.clone()),
                        str_cell(x.get("exitType")),
                        str_cell(x.get("edgeLogicalId")),
                        Cell::Str(selection.to_string()),
                        str_cell(x.get("state")),
                        cost,
                    ]);
                }
            }
        }
        Ok(rows)
    }
}

/// `bgp_sessions`: one row for each session row. The edge is
/// `edge.logicalId`, else the last part of `edge._href`.
pub struct BgpSessionExtract;

impl Extract for BgpSessionExtract {
    fn table(&self) -> &'static TableSchema {
        &VELOCLOUD_BGP_SESSION
    }

    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
        let v = rows_of(bytes)?;
        Ok(items(&v)
            .iter()
            .filter_map(|r| {
                let address = text_of(r.get("neighborIp"))?;
                let edge = text_of(at(r, &["edge", "logicalId"])).or_else(|| {
                    at(r, &["edge", "_href"])
                        .and_then(Value::as_str)
                        .and_then(|h| h.trim_end_matches('/').rsplit('/').next())
                        .filter(|x| !x.is_empty())
                        .map(str::to_string)
                });
                Some(vec![
                    edge.map_or(Cell::Null, Cell::Str),
                    Cell::Str(address),
                    str_cell(r.get("neighborAS")),
                    str_cell(r.get("state")),
                ])
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_numeric_id_is_a_positive_integer_or_a_whole_float() {
        let id = |v: Value| numeric_id(&v);
        assert_eq!(id(json!(12)), Some(12));
        assert_eq!(id(json!(12.0)), Some(12));
        assert_eq!(id(json!(12.5)), None);
        assert_eq!(id(json!(true)), None);
        assert_eq!(id(json!(false)), None);
        assert_eq!(id(json!(0)), None);
        assert_eq!(id(json!(-1)), None);
        assert_eq!(id(json!(-1.0)), None);
        assert_eq!(id(json!("12")), None);
        assert_eq!(id(Value::Null), None);
        assert_eq!(id(json!({})), None);
    }

    #[test]
    fn a_release_has_3_or_4_numbers_from_5_0() {
        assert!(check_release("6.4.0").is_ok());
        assert!(check_release("5.0.0.0").is_ok());
        assert!(check_release("4.5.1").is_err());
        assert!(check_release("6.4").is_err());
        assert!(check_release("6.4.0.1.2").is_err());
        assert!(check_release("6.x.0").is_err());
    }

    #[test]
    fn the_enterprises_split_on_commas_and_lines() {
        assert_eq!(
            enterprise_ids(" ent-a,ent-b\nent-c\n\n, "),
            ["ent-a", "ent-b", "ent-c"]
        );
    }

    #[test]
    fn the_secrets_are_replaced_and_the_keys_stay() {
        let mut v = json!({
            "activationKey": "AAAA-BBBB",
            "name": "edge-1",
            "bgp": {"neighbors": [{"neighborIp": "192.0.2.1", "password": "fake-1"}]},
            "snmp": {"community": "fake-2", "port": 161},
            "radius": {"sharedSecret": "fake-3"},
            "vpn": [{"name": "psk", "value": "fake-4"}],
            "keepalive": 10,
            "communities": ["65000:1"],
        });
        redact(&mut v);
        assert_eq!(
            v,
            json!({
                "activationKey": REDACTED,
                "name": "edge-1",
                "bgp": {"neighbors": [{"neighborIp": "192.0.2.1", "password": REDACTED}]},
                "snmp": {"community": REDACTED, "port": 161},
                "radius": {"sharedSecret": REDACTED},
                "vpn": [{"name": "psk", "value": REDACTED}],
                "keepalive": 10,
                "communities": ["65000:1"],
            })
        );
    }

    #[test]
    fn the_signature_leaves_out_the_link_state_and_the_link_order() {
        let a = json!({
            "serialNumber": "S-1",
            "edgeState": "CONNECTED",
            "links": [
                {"logicalId": "l1", "interface": "GE1", "state": "STABLE"},
                {"logicalId": "l2", "interface": "GE2"},
            ],
            "configuration": {"enterprise": {"id": 77}},
        });
        let b = json!({
            "serialNumber": "S-1",
            "edgeState": "OFFLINE",
            "links": [
                {"logicalId": "l2", "interface": "GE2"},
                {"logicalId": "l1", "interface": "GE1", "state": "DEAD"},
            ],
            "configuration": {"enterprise": {"id": 77}},
        });
        assert_eq!(signature(&a), signature(&b));
        let mut c = a.clone();
        c["links"][0]["ipAddress"] = json!("203.0.113.9");
        assert_ne!(signature(&a), signature(&c));
    }

    #[test]
    fn a_query_value_is_percent_encoded() {
        assert_eq!(query_value("a b/c=d~e"), "a%20b%2Fc%3Dd~e");
    }
}
