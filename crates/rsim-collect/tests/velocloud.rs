//! The VeloCloud source on a fake orchestrator: the order and the bodies of
//! the reads, the paging, the gaps of each read, the fallback to the API v2
//! edges, the numeric ids, the module gate with its ceiling, its stale
//! modules and its eviction, the request counts, the failures of a device,
//! the change hashes, the tables, the secrets, and the commands `discover`
//! and `probe`. The answers are the synthetic files of
//! `tests/fixtures/velocloud/` and the edges of a builder.

#![cfg(feature = "velocloud")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use arrow_array::{Array, RecordBatch, StringArray, UInt64Array};
use rsim_collect::fake::FakeTransport;
use rsim_collect::velocloud::{
    self, AGGREGATES, BGP_PEER_STATUS, EDGES, MODULES, OBJECT_GROUPS, Orchestrator, PROFILES,
    ROUTE_TABLE, SDWAN_PEERS, VelocloudMemory, VelocloudSource,
};
use rsim_collect::*;
use rsim_store::{
    Class, SectionStatus, Store, TableSchema, VELOCLOUD_BGP_SESSION, VELOCLOUD_EDGE_STATE,
    VELOCLOUD_LINK_STATE, VELOCLOUD_ROUTE,
};
use serde_json::{Value, json};

#[path = "support/keys.rs"]
mod keys;

/// 2026-11-23 08:00:00 UTC.
const T0: u64 = 1_795_420_800_000;
const URL: &str = "https://198.51.100.10";
const BASE: &str = "/api/sdwan/v2";
const MINUTE: Duration = Duration::from_secs(60);

/// The orchestrator settings of the tests: release 6.4.0 and the defaults.
fn orchestrator() -> Orchestrator {
    Orchestrator {
        release: Some("6.4.0".into()),
        token_id: velocloud::token_id("fake-token"),
        ..Orchestrator::default()
    }
}

fn fixture(name: &str) -> Value {
    let p = format!(
        "{}/tests/fixtures/velocloud/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"));
    serde_json::from_str(&text).unwrap()
}

fn post(path: &str, body: Value) -> String {
    format!("POST {path} {body}")
}

fn edges_body(id: u64) -> Value {
    json!({"enterpriseId": id, "with": ["site", "links", "ha", "configuration"]})
}

fn modules_body(id: u64, edge: u64) -> Value {
    json!({"enterpriseId": id, "edgeId": edge, "modules": ["WAN", "controlPlane"]})
}

fn bgp_path(enterprise: &str) -> String {
    format!("{BASE}/enterprises/{enterprise}/bgpSessions?state%5Bis%5D=ESTABLISHED")
}

fn device(enterprise: &str) -> Device {
    Device {
        id: velocloud::device_id("lab", enterprise),
        vendor: Vendor::Velocloud,
        address: URL.into(),
        credential: "velocloud-lab".into(),
        site: Some(enterprise.into()),
        capture_bgp: Default::default(),
        route: Default::default(),
        interval: DEFAULT_INTERVAL,
    }
}

/// An edge row of the listing of the builder.
fn edge_row(id: u64, logical: &str) -> Value {
    json!({
        "id": id,
        "logicalId": logical,
        "name": format!("edge {id}"),
        "serialNumber": format!("S-{id:06}"),
        "modelNumber": "edge610",
        "edgeState": "CONNECTED",
        "isHub": false,
        "activationKey": "FAKE-ACTV-0000",
        "site": {"name": format!("site {id}")},
        "links": [{
            "logicalId": format!("{logical}-l1"),
            "internalId": format!("int-{logical}-l1"),
            "interface": "GE3",
            "ipAddress": "203.0.113.10",
            "state": "STABLE",
            "linkMode": "ACTIVE",
        }],
        "configuration": {
            "enterprise": {
                "id": 77,
                "modules": [
                    {"name": "deviceSettings", "version": "2", "isEdgeSpecific": false},
                    {"name": "WAN", "version": "2", "isEdgeSpecific": false},
                ],
            },
        },
    })
}

fn default_modules() -> Value {
    json!({
        "WAN": {"version": "2", "type": "WAN", "data": {"links": [], "networks": []}},
        "controlPlane": {"version": "0", "data": {"segments": []}},
    })
}

fn default_peers(logical: &str) -> Value {
    json!([{
        "edgeLogicalId": logical,
        "deviceLogicalId": "gatewayg-1",
        "peerType": "GATEWAY",
        "pathStatusCount": {"stable": 1, "total": 1},
        "pathQoe": 4.0,
    }])
}

/// An enterprise of the fake orchestrator.
#[derive(Clone)]
struct Ent {
    logical: String,
    /// The id of the enterprise in the `getAggregates` answer.
    id: Value,
    edges: Value,
    profiles: Value,
    route_table: Value,
    /// The module answer of an edge by its numeric id. Each other edge has
    /// the default modules.
    modules: BTreeMap<u64, Value>,
    /// The SD-WAN peers of an edge by its numeric id.
    peers: BTreeMap<u64, Value>,
    bgp: Value,
    bgp_peer_status: Value,
    object_groups: Value,
}

impl Ent {
    fn numeric(&self) -> Option<u64> {
        velocloud::numeric_id(&self.id)
    }

    fn rows(&self) -> &Vec<Value> {
        self.edges.as_array().unwrap()
    }

    fn rows_mut(&mut self) -> &mut Vec<Value> {
        self.edges.as_array_mut().unwrap()
    }
}

/// The fake orchestrator: its enterprises on a fake transport.
struct Vco {
    t: Arc<FakeTransport>,
    ents: Vec<Ent>,
}

impl Vco {
    /// One enterprise `ent-a` with the id 12, from the fixture files.
    fn small(delay: Duration) -> Vco {
        let ent = Ent {
            logical: "ent-a".into(),
            id: json!(12),
            edges: fixture("edges.json"),
            profiles: fixture("profiles.json"),
            route_table: fixture("route_table.json"),
            modules: BTreeMap::from([(101, fixture("modules_branch.json"))]),
            peers: BTreeMap::from([(101, fixture("sdwan_peers.json"))]),
            bgp: fixture("bgp_sessions.json"),
            bgp_peer_status: fixture("bgp_peer_status.json"),
            object_groups: fixture("object_groups.json"),
        };
        let v = Vco {
            t: Arc::new(FakeTransport::new(delay)),
            ents: vec![ent],
        };
        v.load();
        v
    }

    /// `n` enterprises `ent-<k>` with the ids `10 + k`, each with `m` edges
    /// of the builder.
    fn fleet(n: usize, m: usize, delay: Duration) -> Vco {
        let ents = (0..n)
            .map(|k| {
                let rows: Vec<Value> = (0..m)
                    .map(|i| {
                        let id = (k as u64 + 1) * 10_000 + i as u64 + 1;
                        edge_row(id, &format!("edge-{k}-{i:04}"))
                    })
                    .collect();
                Ent {
                    logical: format!("ent-{k}"),
                    id: json!(10 + k),
                    edges: Value::Array(rows),
                    profiles: json!([{"id": 77, "name": "profile", "modules": []}]),
                    route_table: json!({"profiles": [77], "subnets": []}),
                    modules: BTreeMap::new(),
                    peers: BTreeMap::new(),
                    bgp: json!({"data": [], "metaData": {"nextPageLink": null}}),
                    bgp_peer_status: json!([]),
                    object_groups: json!([]),
                }
            })
            .collect();
        let v = Vco {
            t: Arc::new(FakeTransport::new(delay)),
            ents,
        };
        v.load();
        v
    }

    fn dev(&self, k: usize) -> String {
        velocloud::device_id("lab", &self.ents[k].logical)
    }

    fn devices(&self) -> Vec<Device> {
        self.ents.iter().map(|e| device(&e.logical)).collect()
    }

    fn aggregates(&self) -> Value {
        let rows: Vec<Value> = self
            .ents
            .iter()
            .map(|e| json!({"logicalId": e.logical, "id": e.id, "name": e.logical}))
            .collect();
        json!({"edgeCount": 0, "enterprises": rows})
    }

    /// Sets the answers of each read of each enterprise.
    fn load(&self) {
        for k in 0..self.ents.len() {
            self.load_ent(k);
        }
    }

    fn load_ent(&self, k: usize) {
        let e = &self.ents[k];
        let d = self.dev(k);
        let reply = |command: String, v: &Value| {
            self.t.reply(&d, &command, Ok(v.to_string().into_bytes()));
        };
        reply(post(AGGREGATES, json!({})), &self.aggregates());
        let v2: Vec<Value> = e
            .rows()
            .iter()
            .map(|r| json!({"logicalId": r["logicalId"], "name": r["name"]}))
            .collect();
        reply(
            format!("{BASE}/enterprises/{}/edges", e.logical),
            &json!({"data": v2, "metaData": {}}),
        );
        reply(bgp_path(&e.logical), &e.bgp);
        let Some(id) = e.numeric() else {
            return;
        };
        reply(post(EDGES, edges_body(id)), &e.edges);
        reply(
            post(PROFILES, json!({"enterpriseId": id, "with": ["modules"]})),
            &e.profiles,
        );
        reply(
            post(ROUTE_TABLE, json!({"enterpriseId": id})),
            &e.route_table,
        );
        for r in e.rows() {
            let Some(edge) = velocloud::numeric_id(&r["id"]) else {
                continue;
            };
            let logical = r["logicalId"].as_str().unwrap();
            reply(
                post(MODULES, modules_body(id, edge)),
                e.modules.get(&edge).unwrap_or(&default_modules()),
            );
            reply(
                post(SDWAN_PEERS, json!({"enterpriseId": id, "edgeId": edge})),
                e.peers.get(&edge).unwrap_or(&default_peers(logical)),
            );
        }
        reply(
            post(BGP_PEER_STATUS, json!({"enterpriseId": id})),
            &e.bgp_peer_status,
        );
        reply(
            post(OBJECT_GROUPS, json!({"enterpriseId": id})),
            &e.object_groups,
        );
    }

    /// The reads of the log of one operation.
    fn count(&self, op: &str) -> usize {
        self.t.log().iter().filter(|(_, c)| c.contains(op)).count()
    }

    fn commands(&self) -> Vec<String> {
        self.t.log().into_iter().map(|(_, c)| c).collect()
    }
}

/// The operations of the log, each with its count.
fn counts(v: &Vco) -> BTreeMap<&'static str, usize> {
    [
        ("aggregates", AGGREGATES),
        ("edges", EDGES),
        ("profiles", PROFILES),
        ("route_table", ROUTE_TABLE),
        ("edges_v2", "/edges"),
        ("modules", MODULES),
        ("sdwan_peers", SDWAN_PEERS),
        ("bgp_sessions", "/bgpSessions"),
        ("bgp_peer_status", BGP_PEER_STATUS),
        ("object_groups", OBJECT_GROUPS),
    ]
    .into_iter()
    .map(|(name, op)| (name, v.count(op)))
    .collect()
}

fn source(
    v: &Vco,
    memory: &Arc<VelocloudMemory>,
    clock: &Arc<TokioClock>,
    orch: &Orchestrator,
) -> Arc<VelocloudSource> {
    let mut s = VelocloudSource::new(v.t.clone(), memory.clone(), clock.clone());
    for d in v.devices() {
        s = s.with_orchestrator(&d.id, orch.clone());
    }
    Arc::new(s)
}

/// A collector of the enterprises of a fake orchestrator.
struct Env {
    _dir: tempfile::TempDir,
    v: Vco,
    memory: Arc<VelocloudMemory>,
    clock: Arc<TokioClock>,
    c: Collector,
}

fn env(v: Vco, orch: Orchestrator) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TokioClock::new(T0));
    let memory = Arc::new(VelocloudMemory::new());
    let store = Store::open(dir.path(), keys::keys()).unwrap();
    let c = Collector::new(
        store,
        Box::new(v.devices()),
        Schedule {
            spread: false,
            ..Schedule::default()
        },
        Limits::default(),
        clock.clone(),
    )
    .unwrap()
    .with_source(source(&v, &memory, &clock, &orch));
    Env {
        _dir: dir,
        v,
        memory,
        clock,
        c,
    }
}

impl Env {
    fn entry(&self, device: &str, section: &str) -> rsim_store::SectionEntry {
        let s = self.c.store().latest().unwrap().unwrap();
        s.devices[device].section(section).unwrap().clone()
    }

    fn bytes(&self, device: &str, section: &str) -> String {
        let blob = self.entry(device, section).blob.unwrap();
        String::from_utf8(self.c.store().read_blob(&blob).unwrap()).unwrap()
    }

    fn json(&self, device: &str, section: &str) -> Value {
        serde_json::from_str(&self.bytes(device, section)).unwrap()
    }

    /// The cells of the rows of one device in a table, as text.
    fn rows(&self, t: &TableSchema, device: &str) -> Vec<Vec<String>> {
        let s = self.c.store().latest().unwrap().unwrap();
        let all = self.c.store().read_table(&s, t).unwrap();
        let Some((_, b)) = all.into_iter().find(|(d, _)| d == device) else {
            return Vec::new();
        };
        text(&b, t)
    }
}

fn text(b: &RecordBatch, t: &TableSchema) -> Vec<Vec<String>> {
    (0..b.num_rows())
        .map(|i| {
            t.columns
                .iter()
                .map(|c| {
                    let a = b.column_by_name(c.name).unwrap();
                    if a.is_null(i) {
                        return "-".to_string();
                    }
                    let any = a.as_any();
                    match any.downcast_ref::<StringArray>() {
                        Some(x) => x.value(i).to_string(),
                        None => any
                            .downcast_ref::<UInt64Array>()
                            .unwrap()
                            .value(i)
                            .to_string(),
                    }
                })
                .collect()
        })
        .collect()
}

fn row(cells: &[&str]) -> Vec<String> {
    cells.iter().map(|s| s.to_string()).collect()
}

/// A fetch of one device with no pipeline.
async fn fetch(src: &VelocloudSource, d: &Device) -> Vec<RawSection> {
    src.fetch(d, Timeouts::from(Duration::from_secs(20))).await
}

fn section<'a>(s: &'a [RawSection], name: &str) -> &'a RawSection {
    s.iter().find(|r| r.spec.name == name).unwrap()
}

fn answer(s: &[RawSection], name: &str) -> Value {
    let raw = section(s, name);
    serde_json::from_slice(raw.result.as_ref().unwrap()).unwrap()
}

/// The reason of an absent section.
fn absent(s: &[RawSection], name: &str) -> String {
    let raw = section(s, name);
    assert!(raw.absent(), "{name}: {:?}", raw.result);
    match &raw.result {
        Err(TransportError::NotFound(r)) => r.clone(),
        other => panic!("{name}: {other:?}"),
    }
}

/// True if each section failed with an error that holds `text`.
fn device_failed(s: &[RawSection], text: &str) -> bool {
    s.iter().all(|r| {
        matches!(&r.result, Err(TransportError::Command(e)) if e.contains(text)) && !r.absent()
    })
}

/// A source and its memory for fetches with no pipeline.
fn bare(v: &Vco, orch: Orchestrator) -> (Arc<VelocloudSource>, Arc<VelocloudMemory>) {
    let memory = Arc::new(VelocloudMemory::new());
    let clock = Arc::new(TokioClock::new(T0));
    (source(v, &memory, &clock, &orch), memory)
}

/// The reads that fail on release 6.4. The source does not send them.
const NOT_SENT: &[&str] = &[
    "getEnterpriseHubClusters",
    "getEdgeConfigurationStack",
    "/wan",
];

#[tokio::test(start_paused = true)]
async fn the_reads_go_in_order_with_their_exact_bodies() {
    let v = Vco::small(Duration::from_millis(5));
    let (src, _) = bare(&v, orchestrator());
    let d = device("ent-a");
    let s = fetch(&src, &d).await;
    assert!(s.iter().all(|r| r.result.is_ok() || r.absent()), "{s:?}");
    let want = vec![
        post(AGGREGATES, json!({})),
        post(EDGES, edges_body(12)),
        post(PROFILES, json!({"enterpriseId": 12, "with": ["modules"]})),
        post(ROUTE_TABLE, json!({"enterpriseId": 12})),
        post(MODULES, modules_body(12, 101)),
        post(MODULES, modules_body(12, 102)),
        post(SDWAN_PEERS, json!({"enterpriseId": 12, "edgeId": 101})),
        post(SDWAN_PEERS, json!({"enterpriseId": 12, "edgeId": 102})),
        bgp_path("ent-a"),
        post(BGP_PEER_STATUS, json!({"enterpriseId": 12})),
        post(OBJECT_GROUPS, json!({"enterpriseId": 12})),
    ];
    assert_eq!(v.commands(), want);
    for c in v.commands() {
        assert!(NOT_SENT.iter().all(|x| !c.contains(x)), "{c}");
    }
    assert!(
        NOT_SENT
            .iter()
            .all(|x| velocloud::READ_PATHS.iter().all(|p| !p.contains(x)))
    );
    assert_eq!(absent(&s, "edges_v2"), "not needed");
    let modules = answer(&s, "edge_modules");
    let keys: Vec<&String> = modules.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["edge-branch", "edge-hub"]);
    assert_eq!(
        modules["edge-branch"]["WAN"]["data"]["links"][0]["mode"],
        "PRIVATE"
    );
    assert_eq!(
        modules["edge-branch"]["_freshness"]["observed_at_ms"],
        json!(T0)
    );
    assert_eq!(modules["edge-branch"]["_freshness"]["stale"], json!(false));
    let peers = answer(&s, "sdwan_peers");
    assert_eq!(peers["edge-branch"][0]["peerType"], "HUB");
    assert_eq!(answer(&s, "bgp_sessions").as_array().unwrap().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_page_token_goes_back_as_the_only_parameter() {
    let v = Vco::small(Duration::ZERO);
    let d = v.dev(0);
    let row = |ip: &str| json!({"edge": {"logicalId": "edge-branch"}, "neighborIp": ip, "state": "ESTABLISHED"});
    let page = |rows: Value, meta: Value| {
        Ok(json!({"data": rows, "metaData": meta})
            .to_string()
            .into_bytes())
    };
    v.t.reply(
        &d,
        &bgp_path("ent-a"),
        page(
            json!([row("10.10.10.1")]),
            json!({"nextPageLink": "second token"}),
        ),
    );
    v.t.reply(
        &d,
        &format!("{BASE}/enterprises/ent-a/bgpSessions?nextPageLink=second%20token"),
        page(json!([row("10.10.10.2")]), json!({"nextPageLink": ""})),
    );
    let (src, _) = bare(&v, orchestrator());
    let s = fetch(&src, &device("ent-a")).await;
    let sessions = answer(&s, "bgp_sessions");
    let ips: Vec<&str> = sessions
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["neighborIp"].as_str().unwrap())
        .collect();
    assert_eq!(ips, ["10.10.10.1", "10.10.10.2"]);
    assert_eq!(v.count("/bgpSessions"), 2);
}

#[tokio::test(start_paused = true)]
async fn a_bare_array_is_one_page() {
    let v = Vco::small(Duration::ZERO);
    let d = v.dev(0);
    v.t.reply(
        &d,
        &bgp_path("ent-a"),
        Ok(br#"[{"neighborIp": "10.10.10.1", "state": "ESTABLISHED"}]"#.to_vec()),
    );
    let (src, _) = bare(&v, orchestrator());
    let s = fetch(&src, &device("ent-a")).await;
    assert_eq!(answer(&s, "bgp_sessions").as_array().unwrap().len(), 1);
    assert_eq!(v.count("/bgpSessions"), 1);
}

#[tokio::test(start_paused = true)]
async fn a_bad_page_fails_the_device_before_another_request() {
    let cases = [
        (json!({"data": [], "metaData": 5}), 1, "metaData"),
        (
            json!({"data": [], "metaData": {"nextPageLink": 7}}),
            1,
            "page token",
        ),
        (
            json!({"data": [], "metaData": {"nextPageLink": "again"}}),
            2,
            "cyclic",
        ),
    ];
    for (first, requests, error) in cases {
        let v = Vco::small(Duration::ZERO);
        let d = v.dev(0);
        v.t.reply(&d, &bgp_path("ent-a"), Ok(first.to_string().into_bytes()));
        v.t.reply(
            &d,
            &format!("{BASE}/enterprises/ent-a/bgpSessions?nextPageLink=again"),
            Ok(first.to_string().into_bytes()),
        );
        let (src, _) = bare(&v, orchestrator());
        let s = fetch(&src, &device("ent-a")).await;
        assert!(device_failed(&s, error), "{error}: {s:?}");
        assert_eq!(v.count("/bgpSessions"), requests, "{error}");
    }
}

#[tokio::test(start_paused = true)]
async fn each_gap_status_of_a_portal_read_gives_an_absent_section() {
    for (op, sections) in [
        (EDGES, &["edges", "edge_state"][..]),
        (PROFILES, &["profiles"][..]),
        (ROUTE_TABLE, &["route_table"][..]),
        (BGP_PEER_STATUS, &["bgp_peer_status"][..]),
        (OBJECT_GROUPS, &["object_groups"][..]),
    ] {
        for status in velocloud::PORTAL_GAP_STATUSES {
            let v = Vco::small(Duration::ZERO);
            let d = v.dev(0);
            let body = if op == EDGES {
                edges_body(12)
            } else if op == PROFILES {
                json!({"enterpriseId": 12, "with": ["modules"]})
            } else {
                json!({"enterpriseId": 12})
            };
            v.t.reply_status(&d, &post(op, body), *status, "refused");
            let (src, _) = bare(&v, orchestrator());
            let s = fetch(&src, &device("ent-a")).await;
            let name = op.rsplit('/').next().unwrap();
            for sec in sections {
                assert_eq!(absent(&s, sec), format!("{name}: {status}"));
            }
            assert!(section(&s, "aggregates").result.is_ok());
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_200_with_an_error_member_or_no_rows_is_a_gap() {
    let error = json!({"error": {"code": -32603, "message": "methodError"}});
    let cases = [
        (
            post(ROUTE_TABLE, json!({"enterpriseId": 12})),
            error.clone(),
            "route_table",
            "getEnterpriseRouteTable: methodError",
        ),
        (
            post(PROFILES, json!({"enterpriseId": 12, "with": ["modules"]})),
            error.clone(),
            "profiles",
            "getEnterpriseConfigurations: methodError",
        ),
        (
            post(PROFILES, json!({"enterpriseId": 12, "with": ["modules"]})),
            json!([]),
            "profiles",
            "getEnterpriseConfigurations: no profile answered",
        ),
        (
            post(EDGES, edges_body(12)),
            error,
            "edges",
            "getEnterpriseEdges: methodError",
        ),
        (
            post(EDGES, edges_body(12)),
            json!([]),
            "edges",
            "getEnterpriseEdges: no edge answered",
        ),
    ];
    for (command, reply, name, reason) in cases {
        let v = Vco::small(Duration::ZERO);
        v.t.reply(&v.dev(0), &command, Ok(reply.to_string().into_bytes()));
        let (src, _) = bare(&v, orchestrator());
        let s = fetch(&src, &device("ent-a")).await;
        assert_eq!(absent(&s, name), reason);
    }
}

#[tokio::test(start_paused = true)]
async fn an_edge_gap_falls_back_to_the_api_v2_edges_with_no_module_read() {
    let v = Vco::small(Duration::ZERO);
    v.t.reply_status(&v.dev(0), &post(EDGES, edges_body(12)), 403, "forbidden");
    let (src, _) = bare(&v, orchestrator());
    let s = fetch(&src, &device("ent-a")).await;
    assert_eq!(absent(&s, "edges"), "getEnterpriseEdges: 403");
    let v2 = answer(&s, "edges_v2");
    assert_eq!(v2.as_array().unwrap().len(), 2);
    let gap = json!({"status": "unavailable", "reason": "no numeric id for this edge"});
    let modules = answer(&s, "edge_modules");
    assert_eq!(modules["edge-branch"]["_capability"], gap);
    assert_eq!(modules["edge-hub"]["_capability"], gap);
    assert_eq!(answer(&s, "sdwan_peers")["edge-hub"]["_capability"], gap);
    assert_eq!((v.count(MODULES), v.count(SDWAN_PEERS)), (0, 0));
    // The API v2 edges come after the profiles and the route table.
    let c = v.commands();
    let at = |op: &str| c.iter().position(|x| x.contains(op)).unwrap();
    assert!(at(ROUTE_TABLE) < at("/edges"));
    assert!(section(&s, "profiles").result.is_ok());
}

#[tokio::test(start_paused = true)]
async fn an_error_of_the_api_v2_edges_fails_the_device() {
    let v = Vco::small(Duration::ZERO);
    let d = v.dev(0);
    v.t.reply_status(&d, &post(EDGES, edges_body(12)), 404, "missing");
    v.t.reply_status(
        &d,
        &format!("{BASE}/enterprises/ent-a/edges"),
        404,
        "missing",
    );
    let (src, _) = bare(&v, orchestrator());
    let s = fetch(&src, &device("ent-a")).await;
    assert!(device_failed(&s, "HTTP 404"), "{s:?}");
}

#[tokio::test(start_paused = true)]
async fn an_enterprise_with_no_numeric_id_reads_only_the_api_v2() {
    for id in [json!(true), json!(0), json!(-1), json!("12"), json!(12.5)] {
        let mut v = Vco::small(Duration::ZERO);
        v.ents[0].id = id.clone();
        v.load();
        let (src, _) = bare(&v, orchestrator());
        let s = fetch(&src, &device("ent-a")).await;
        assert!(section(&s, "aggregates").result.is_ok(), "{id}");
        for name in [
            "edges",
            "edge_state",
            "profiles",
            "route_table",
            "bgp_peer_status",
            "object_groups",
        ] {
            assert_eq!(absent(&s, name), "no numeric id for enterprise", "{id}");
        }
        assert_eq!(answer(&s, "edges_v2").as_array().unwrap().len(), 2);
        assert!(section(&s, "bgp_sessions").result.is_ok());
        assert_eq!(
            answer(&s, "edge_modules")["edge-hub"]["_capability"]["reason"],
            "no numeric id for this edge"
        );
        let c = counts(&v);
        assert_eq!(
            (
                c["aggregates"],
                c["edges_v2"],
                c["bgp_sessions"],
                c["modules"]
            ),
            (1, 1, 1, 0)
        );
        assert_eq!(c.values().sum::<usize>(), 3, "{id}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_whole_float_is_a_numeric_id() {
    let mut v = Vco::small(Duration::ZERO);
    v.ents[0].id = json!(12.0);
    v.ents[0].rows_mut()[0]["id"] = json!(true);
    v.load();
    let (src, _) = bare(&v, orchestrator());
    let s = fetch(&src, &device("ent-a")).await;
    assert!(section(&s, "edges").result.is_ok());
    let modules = answer(&s, "edge_modules");
    assert_eq!(
        modules["edge-branch"]["_capability"]["reason"],
        "no numeric id for this edge"
    );
    // The hub has the id 102.0 in the listing.
    assert_eq!(modules["edge-hub"]["WAN"]["version"], "2");
    assert_eq!(
        v.commands()
            .iter()
            .filter(|c| c.contains(MODULES))
            .collect::<Vec<_>>(),
        [&post(MODULES, modules_body(12, 102))]
    );
}

#[tokio::test(start_paused = true)]
async fn the_bgp_sessions_have_their_own_gap_statuses() {
    for (status, gap) in [
        (403, true),
        (404, true),
        (405, true),
        (501, true),
        (400, false),
    ] {
        let v = Vco::small(Duration::ZERO);
        v.t.reply_status(&v.dev(0), &bgp_path("ent-a"), status, "no");
        let (src, _) = bare(&v, orchestrator());
        let s = fetch(&src, &device("ent-a")).await;
        if gap {
            assert_eq!(absent(&s, "bgp_sessions"), format!("bgpSessions: {status}"));
        } else {
            assert!(device_failed(&s, "HTTP 400"), "{s:?}");
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_status_that_is_not_a_gap_or_an_answer_that_is_not_json_fails_the_device() {
    for (status, text) in [(500, "HTTP 500"), (401, "HTTP 401"), (409, "HTTP 409")] {
        let v = Vco::small(Duration::ZERO);
        v.t.reply_status(
            &v.dev(0),
            &post(PROFILES, json!({"enterpriseId": 12, "with": ["modules"]})),
            status,
            "refused",
        );
        let (src, _) = bare(&v, orchestrator());
        assert!(device_failed(&fetch(&src, &device("ent-a")).await, text));
    }
    let v = Vco::small(Duration::ZERO);
    v.t.reply(
        &v.dev(0),
        &post(ROUTE_TABLE, json!({"enterpriseId": 12})),
        Ok(b"<html>".to_vec()),
    );
    let (src, _) = bare(&v, orchestrator());
    assert!(device_failed(
        &fetch(&src, &device("ent-a")).await,
        "not JSON"
    ));
}

#[tokio::test(start_paused = true)]
async fn a_module_401_fails_the_device_and_a_module_gap_does_not() {
    let v = Vco::small(Duration::ZERO);
    v.t.reply_status(
        &v.dev(0),
        &post(MODULES, modules_body(12, 101)),
        401,
        "expired",
    );
    let (src, _) = bare(&v, orchestrator());
    assert!(device_failed(
        &fetch(&src, &device("ent-a")).await,
        "HTTP 401"
    ));

    let v = Vco::small(Duration::ZERO);
    v.t.reply_status(
        &v.dev(0),
        &post(MODULES, modules_body(12, 101)),
        403,
        "denied",
    );
    let (src, memory) = bare(&v, orchestrator());
    let s = fetch(&src, &device("ent-a")).await;
    assert_eq!(
        answer(&s, "edge_modules")["edge-branch"]["_capability"]["reason"],
        "getEdgeConfigurationModules: 403"
    );
    // A gap is never held as a module.
    assert_eq!(memory.edges(&v.dev(0)), ["edge-hub"]);
}

#[tokio::test(start_paused = true)]
async fn a_module_200_with_an_error_member_is_a_gap_and_not_a_module() {
    let v = Vco::small(Duration::ZERO);
    v.t.reply(
        &v.dev(0),
        &post(MODULES, modules_body(12, 101)),
        Ok(
            json!({"error": {"code": -32603, "message": "edgeNotFound"}})
                .to_string()
                .into_bytes(),
        ),
    );
    let (src, memory) = bare(&v, orchestrator());
    let s = fetch(&src, &device("ent-a")).await;
    let modules = answer(&s, "edge_modules");
    assert_eq!(
        modules["edge-branch"]["_capability"]["reason"],
        "getEdgeConfigurationModules: edgeNotFound"
    );
    assert_eq!(modules["edge-branch"].get("WAN"), None);
    assert_eq!(memory.edges(&v.dev(0)), ["edge-hub"]);
}

#[tokio::test(start_paused = true)]
async fn a_gap_of_the_sdwan_peers_of_an_edge_does_not_fail_the_device() {
    let v = Vco::small(Duration::ZERO);
    let command = post(SDWAN_PEERS, json!({"enterpriseId": 12, "edgeId": 101}));
    v.t.reply_status(&v.dev(0), &command, 403, "denied");
    v.t.reply(
        &v.dev(0),
        &post(SDWAN_PEERS, json!({"enterpriseId": 12, "edgeId": 102})),
        Ok(json!({"error": {"message": "methodError"}})
            .to_string()
            .into_bytes()),
    );
    let (src, _) = bare(&v, orchestrator());
    let s = fetch(&src, &device("ent-a")).await;
    assert!(
        s.iter()
            .all(|r| !matches!(r.result, Err(TransportError::Command(_))))
    );
    let peers = answer(&s, "sdwan_peers");
    assert_eq!(
        peers["edge-branch"]["_capability"]["reason"],
        "getEdgeSDWANPeers: 403"
    );
    assert_eq!(
        peers["edge-hub"]["_capability"]["reason"],
        "getEdgeSDWANPeers: methodError"
    );
}

#[tokio::test(start_paused = true)]
async fn a_release_before_5_fails_the_device_before_any_read() {
    let v = Vco::small(Duration::ZERO);
    let orch = Orchestrator {
        release: Some("4.5.0".into()),
        ..orchestrator()
    };
    let (src, _) = bare(&v, orch);
    assert!(device_failed(
        &fetch(&src, &device("ent-a")).await,
        "before 5.0.0.0"
    ));
    assert_eq!(v.t.calls(), 0);

    let (src, _) = bare(
        &v,
        Orchestrator {
            release: None,
            ..orchestrator()
        },
    );
    assert!(device_failed(
        &fetch(&src, &device("ent-a")).await,
        "no release"
    ));
    assert_eq!(v.t.calls(), 0);
}

/// The module reads of the log.
fn module_reads(v: &Vco) -> usize {
    v.count(MODULES)
}

#[tokio::test(start_paused = true)]
async fn each_of_5_single_edge_changes_reads_one_edge_again() {
    type Change = fn(&mut Value);
    let changes: [(&str, Change); 5] = [
        ("module version", |e| {
            e["configuration"]["enterprise"]["modules"][0]["version"] = json!("3")
        }),
        ("edge-specific data", |e| {
            e["configuration"]["enterprise"]["modules"][0]["edgeSpecificData"] =
                json!({"lan": {"networks": []}})
        }),
        ("profile", |e| {
            e["configuration"]["enterprise"]["id"] = json!(78)
        }),
        ("link address", |e| {
            e["links"][0]["ipAddress"] = json!("203.0.113.11")
        }),
        ("serial", |e| e["serialNumber"] = json!("S-999999")),
    ];
    let mut v = Vco::fleet(1, 3, Duration::ZERO);
    let (src, _) = bare(&v, orchestrator());
    let d = device("ent-0");
    fetch(&src, &d).await;
    assert_eq!(module_reads(&v), 3);
    let mut minutes = 0;
    for (name, change) in changes {
        v.t.clear_log();
        change(&mut v.ents[0].rows_mut()[1]);
        v.load();
        tokio::time::advance(MINUTE).await;
        minutes += 1;
        let s = fetch(&src, &d).await;
        assert_eq!(
            v.commands()
                .iter()
                .filter(|c| c.contains(MODULES))
                .cloned()
                .collect::<Vec<_>>(),
            [post(MODULES, modules_body(10, 10_002))],
            "{name}"
        );
        assert_eq!(
            answer(&s, "edge_modules")["edge-0-0001"]["_freshness"]["observed_at_ms"],
            json!(T0 + minutes * 60_000),
            "{name}"
        );
    }
    // A link state is not in the signature.
    v.t.clear_log();
    v.ents[0].rows_mut()[2]["links"][0]["state"] = json!("DEAD");
    v.load();
    tokio::time::advance(MINUTE).await;
    fetch(&src, &d).await;
    assert_eq!(module_reads(&v), 0);
}

#[tokio::test(start_paused = true)]
async fn the_ceiling_reads_each_module_again_and_zero_reads_them_each_time() {
    let v = Vco::fleet(1, 2, Duration::ZERO);
    let (src, _) = bare(&v, orchestrator());
    let d = device("ent-0");
    fetch(&src, &d).await;
    tokio::time::advance(Duration::from_secs(1799)).await;
    v.t.clear_log();
    fetch(&src, &d).await;
    assert_eq!(module_reads(&v), 0);
    tokio::time::advance(Duration::from_secs(2)).await;
    v.t.clear_log();
    fetch(&src, &d).await;
    assert_eq!(module_reads(&v), 2);

    let v = Vco::fleet(1, 2, Duration::ZERO);
    let orch = Orchestrator {
        refresh: Duration::ZERO,
        ..orchestrator()
    };
    let (src, _) = bare(&v, orch);
    for _ in 0..3 {
        v.t.clear_log();
        fetch(&src, &d).await;
        assert_eq!(module_reads(&v), 2);
        tokio::time::advance(MINUTE).await;
    }
}

#[tokio::test(start_paused = true)]
async fn a_failed_refresh_keeps_the_module_with_its_first_time_as_stale() {
    let v = Vco::small(Duration::ZERO);
    let orch = Orchestrator {
        refresh: Duration::ZERO,
        ..orchestrator()
    };
    let (src, _) = bare(&v, orch);
    let d = device("ent-a");
    let first = fetch(&src, &d).await;
    let before = answer(&first, "edge_modules");
    tokio::time::advance(MINUTE).await;
    let command = post(MODULES, modules_body(12, 101));
    v.t.reply_status(&v.dev(0), &command, 503, "busy");
    let s = fetch(&src, &d).await;
    let after = answer(&s, "edge_modules");
    let branch = &after["edge-branch"];
    assert_eq!(branch["WAN"], before["edge-branch"]["WAN"]);
    assert_eq!(branch["_freshness"]["observed_at_ms"], json!(T0));
    assert_eq!(branch["_freshness"]["stale"], json!(true));
    assert_eq!(after["edge-hub"]["_freshness"]["stale"], json!(false));
    // The stale flag does not change the hash of the section.
    let spec = &section(&s, "edge_modules").spec;
    let keys = keys::keys();
    let hash = |bytes: &[u8]| {
        rsim_store::change_hash_kept(&keys, spec.format, bytes, spec.volatile, spec.keep).unwrap()
    };
    assert_eq!(
        hash(
            section(&first, "edge_modules")
                .result
                .as_ref()
                .unwrap()
                .as_slice()
        ),
        hash(
            section(&s, "edge_modules")
                .result
                .as_ref()
                .unwrap()
                .as_slice()
        )
    );
    // A transport error is a failed refresh too.
    v.t.reply(&v.dev(0), &command, Err(TransportError::Timeout));
    let s = fetch(&src, &d).await;
    assert_eq!(
        answer(&s, "edge_modules")["edge-branch"]["_freshness"]["stale"],
        json!(true)
    );
}

#[tokio::test(start_paused = true)]
async fn a_changed_edge_or_a_cold_edge_whose_refresh_fails_gets_the_gap() {
    let failed = json!({"status": "unavailable", "reason": "Observation refresh failed"});
    let mut v = Vco::small(Duration::ZERO);
    let (src, _) = bare(&v, orchestrator());
    let d = device("ent-a");
    fetch(&src, &d).await;
    v.ents[0].rows_mut()[0]["serialNumber"] = json!("S-0009");
    v.load();
    let command = post(MODULES, modules_body(12, 101));
    v.t.reply_status(&v.dev(0), &command, 502, "bad gateway");
    let s = fetch(&src, &d).await;
    let branch = &answer(&s, "edge_modules")["edge-branch"];
    assert_eq!(branch["_capability"], failed);
    assert_eq!(branch["_freshness"]["stale"], json!(true));

    let v = Vco::small(Duration::ZERO);
    v.t.reply_status(&v.dev(0), &command, 429, "slow down");
    let (src, _) = bare(&v, orchestrator());
    let s = fetch(&src, &d).await;
    assert_eq!(
        answer(&s, "edge_modules")["edge-branch"]["_capability"],
        failed
    );
}

#[tokio::test(start_paused = true)]
async fn the_modules_of_an_edge_that_leaves_the_listing_are_dropped() {
    let mut v = Vco::small(Duration::ZERO);
    let (src, memory) = bare(&v, orchestrator());
    let d = device("ent-a");
    let id = v.dev(0);
    fetch(&src, &d).await;
    assert_eq!(memory.edges(&id), ["edge-branch", "edge-hub"]);
    let hub = v.ents[0].rows_mut().remove(1);
    v.load();
    // A gap of another edge does not stop the eviction.
    v.t.reply_status(&id, &post(MODULES, modules_body(12, 101)), 403, "denied");
    tokio::time::advance(Duration::from_secs(1801)).await;
    fetch(&src, &d).await;
    assert_eq!(memory.edges(&id), ["edge-branch"]);
    v.load();
    tokio::time::advance(MINUTE).await;
    fetch(&src, &d).await;
    v.ents[0].rows_mut().push(hub);
    v.load();
    tokio::time::advance(MINUTE).await;
    v.t.clear_log();
    fetch(&src, &d).await;
    assert_eq!(
        v.commands()
            .iter()
            .filter(|c| c.contains(MODULES))
            .cloned()
            .collect::<Vec<_>>(),
        [post(MODULES, modules_body(12, 102))]
    );
    assert_eq!(memory.edges(&id), ["edge-branch", "edge-hub"]);
}

#[tokio::test(start_paused = true)]
async fn three_enterprises_of_1002_edges_take_1015_reads_cold_and_13_warm() {
    let v = Vco::fleet(3, 334, Duration::from_millis(1));
    let mut e = env(v, orchestrator());
    let r = e.c.run_cycle().await.unwrap();
    assert!(r.failed.is_empty(), "{r:?}");
    let want = BTreeMap::from([
        ("aggregates", 1),
        ("edges", 3),
        ("profiles", 3),
        ("route_table", 3),
        ("edges_v2", 0),
        ("modules", 1002),
        ("sdwan_peers", 1002),
        ("bgp_sessions", 3),
        ("bgp_peer_status", 3),
        ("object_groups", 3),
    ]);
    let cold = counts(&e.v);
    assert_eq!(cold, want);
    let design: usize = [
        "aggregates",
        "edges",
        "profiles",
        "route_table",
        "modules",
        "bgp_sessions",
    ]
    .iter()
    .map(|k| cold[k])
    .sum();
    assert_eq!(design, 1015);
    tokio::time::advance(MINUTE).await;
    e.v.t.clear_log();
    let r = e.c.run_cycle().await.unwrap();
    assert!(r.failed.is_empty(), "{r:?}");
    let warm = counts(&e.v);
    let design: usize = [
        "aggregates",
        "edges",
        "profiles",
        "route_table",
        "modules",
        "bgp_sessions",
    ]
    .iter()
    .map(|k| warm[k])
    .sum();
    assert_eq!(design, 13);
    assert_eq!((warm["modules"], warm["sdwan_peers"]), (0, 1002));
    assert_eq!(r.snapshot, None);
}

#[tokio::test(start_paused = true)]
async fn the_requests_in_flight_to_an_orchestrator_stay_at_its_concurrency() {
    let v = Vco::fleet(2, 12, Duration::from_millis(10));
    let orch = Orchestrator {
        concurrency: 2,
        ..orchestrator()
    };
    let mut e = env(v, orch);
    let r = e.c.run_cycle().await.unwrap();
    assert!(r.failed.is_empty(), "{r:?}");
    assert_eq!(e.v.t.max_calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_cycle_with_no_change_writes_nothing_and_a_link_flap_changes_only_the_edge_state() {
    let v = Vco::small(Duration::from_millis(5));
    let d = v.dev(0);
    let mut e = env(v, orchestrator());
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.snapshot, Some(0));
    tokio::time::advance(MINUTE).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!((r.due, r.snapshot), (1, None));
    let edges = e.entry(&d, "edges").change_hash;
    let state = e.entry(&d, "edge_state").change_hash;
    e.v.ents[0].rows_mut()[0]["links"][0]["state"] = json!("DEAD");
    e.v.ents[0].rows_mut()[0]["links"][0]["vpnState"] = json!("DEAD");
    e.v.load();
    e.v.t.clear_log();
    tokio::time::advance(MINUTE).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.changed, [(d.clone(), vec![Class::Observation])]);
    assert_eq!(e.entry(&d, "edges").change_hash, edges);
    assert_ne!(e.entry(&d, "edge_state").change_hash, state);
    assert_eq!(e.v.count(MODULES), 0);
    assert_eq!(
        e.rows(&VELOCLOUD_LINK_STATE, &d)[0],
        row(&[
            "edge-branch",
            "link-b-mpls",
            "int-b-mpls",
            "DEAD",
            "ACTIVE",
            "DEAD",
            "UNCONFIGURED"
        ])
    );
}

#[tokio::test(start_paused = true)]
async fn the_forced_full_collection_sends_no_module_read() {
    let v = Vco::small(Duration::from_millis(5));
    let d = v.dev(0);
    let mut e = env(v, orchestrator());
    e.c.run_cycle().await.unwrap();
    let first = e.entry(&d, "edge_modules");
    // A cycle that is not forced writes no snapshot.
    tokio::time::advance(MINUTE).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!((r.due, r.snapshot), (1, None));
    tokio::time::advance(Duration::from_secs(840)).await;
    e.v.t.clear_log();
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.due, 1);
    assert!(r.failed.is_empty(), "{r:?}");
    // The forced cycle stores each section again: a snapshot with no
    // changed class.
    assert_eq!(r.snapshot, Some(1));
    assert!(r.changed.is_empty(), "{r:?}");
    assert_eq!(e.v.count(MODULES), 0);
    assert_eq!(e.v.count(EDGES), 1);
    // The modules come from the memory, with the time of their read.
    let again = e.entry(&d, "edge_modules");
    assert_eq!(again.blob, first.blob);
    assert!(again.collected_at > first.collected_at, "{again:?}");
    assert_eq!(
        e.json(&d, "edge_modules")["edge-branch"]["_freshness"]["observed_at_ms"],
        json!(T0)
    );
}

#[tokio::test(start_paused = true)]
async fn a_503_on_the_profiles_keeps_the_last_good_snapshot_of_the_whole_device() {
    let v = Vco::small(Duration::from_millis(5));
    let d = v.dev(0);
    let mut e = env(v, orchestrator());
    e.c.run_cycle().await.unwrap();
    let before = e.c.store().latest().unwrap().unwrap().devices[&d].clone();
    e.v.ents[0].rows_mut()[0]["edgeState"] = json!("OFFLINE");
    e.v.load();
    e.v.t.reply_status(
        &d,
        &post(PROFILES, json!({"enterpriseId": 12, "with": ["modules"]})),
        503,
        "busy",
    );
    tokio::time::advance(MINUTE).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.failed, std::slice::from_ref(&d));
    let after = e.c.store().latest().unwrap().unwrap().devices[&d].clone();
    for s in &before.sections {
        let a = after.section(&s.name).unwrap();
        assert_eq!(a.blob, s.blob, "{}", s.name);
        match s.status {
            SectionStatus::Absent { .. } => assert_eq!(a.status, s.status, "{}", s.name),
            _ => assert!(matches!(a.status, SectionStatus::Old { .. }), "{}", s.name),
        }
    }
    assert_eq!(e.rows(&VELOCLOUD_EDGE_STATE, &d)[0][1], "CONNECTED");
}

#[tokio::test(start_paused = true)]
async fn the_modules_of_the_stored_section_warm_a_new_memory() {
    let v = Vco::small(Duration::from_millis(5));
    let mut e = env(v, orchestrator());
    e.c.run_cycle().await.unwrap();
    assert_eq!(e.memory.edges(&e.v.dev(0)), ["edge-branch", "edge-hub"]);
    let memory = Arc::new(VelocloudMemory::new());
    assert_eq!(memory.warm_from(e.c.store()), Ok(1));
    assert_eq!(memory.edges(&e.v.dev(0)), ["edge-branch", "edge-hub"]);
    let src: Arc<dyn Source> = source(&e.v, &memory, &e.clock, &orchestrator());
    e.c.reconfigure(Box::new(e.v.devices()), vec![src], BTreeMap::new());
    tokio::time::advance(MINUTE).await;
    e.v.t.clear_log();
    let r = e.c.run_cycle().await.unwrap();
    assert!(r.failed.is_empty(), "{r:?}");
    assert_eq!(e.v.count(MODULES), 0);
    assert_eq!(e.v.count(EDGES), 1);

    // A new release or a new token makes the warmed memory cold.
    for orch in [
        Orchestrator {
            release: Some("6.4.1".into()),
            ..orchestrator()
        },
        Orchestrator {
            token_id: velocloud::token_id("fake-token-2"),
            ..orchestrator()
        },
    ] {
        let memory = Arc::new(VelocloudMemory::new());
        assert_eq!(memory.warm_from(e.c.store()), Ok(1));
        let src: Arc<dyn Source> = source(&e.v, &memory, &e.clock, &orch);
        e.c.reconfigure(Box::new(e.v.devices()), vec![src], BTreeMap::new());
        tokio::time::advance(MINUTE).await;
        e.v.t.clear_log();
        let r = e.c.run_cycle().await.unwrap();
        assert!(r.failed.is_empty(), "{r:?}");
        assert_eq!(e.v.count(MODULES), 2, "{orch:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_new_token_makes_the_module_memory_cold() {
    let v = Vco::small(Duration::ZERO);
    let memory = Arc::new(VelocloudMemory::new());
    let clock = Arc::new(TokioClock::new(T0));
    let d = device("ent-a");
    fetch(&source(&v, &memory, &clock, &orchestrator()), &d).await;
    assert_eq!(module_reads(&v), 2);
    tokio::time::advance(MINUTE).await;
    v.t.clear_log();
    fetch(&source(&v, &memory, &clock, &orchestrator()), &d).await;
    assert_eq!(module_reads(&v), 0);
    let orch = Orchestrator {
        token_id: velocloud::token_id("fake-token-2"),
        ..orchestrator()
    };
    tokio::time::advance(MINUTE).await;
    v.t.clear_log();
    fetch(&source(&v, &memory, &clock, &orch), &d).await;
    assert_eq!(module_reads(&v), 2);
}

#[tokio::test(start_paused = true)]
async fn the_tables_hold_the_edges_the_links_the_routes_and_the_sessions() {
    let v = Vco::small(Duration::from_millis(5));
    let d = v.dev(0);
    let mut e = env(v, orchestrator());
    let r = e.c.run_cycle().await.unwrap();
    assert!(r.extract_errors.is_empty(), "{r:?}");
    assert_eq!(
        e.rows(&VELOCLOUD_EDGE_STATE, &d),
        [
            row(&["edge-branch", "CONNECTED", "READY"]),
            row(&["edge-hub", "CONNECTED", "UNCONFIGURED"]),
        ]
    );
    assert_eq!(e.rows(&VELOCLOUD_LINK_STATE, &d).len(), 4);
    assert_eq!(
        e.rows(&VELOCLOUD_ROUTE, &d),
        [
            row(&[
                "1",
                "10.20.20.0/24",
                "EDGE",
                "edge-hub",
                "preferred",
                "-",
                "0"
            ]),
            row(&["1", "10.20.20.0/24", "ROUTER", "-", "eligible", "-", "10"]),
            row(&[
                "0",
                "10.10.10.0/24",
                "EDGE",
                "edge-branch",
                "preferred",
                "-",
                "0"
            ]),
            row(&[
                "1",
                "2001:db8::/32",
                "EDGE",
                "edge-hub",
                "preferred",
                "UNREACHABLE",
                "5"
            ]),
            row(&[
                "2",
                "10.30.0.0/16",
                "EDGE",
                "edge-branch",
                "preferred",
                "-",
                "1"
            ]),
        ]
    );
    assert_eq!(
        e.rows(&VELOCLOUD_BGP_SESSION, &d),
        [
            row(&["edge-branch", "10.10.10.254", "65000", "ESTABLISHED"]),
            row(&["edge-hub", "172.16.20.1", "65001", "IDLE"]),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn the_secrets_are_replaced_before_the_store() {
    let v = Vco::small(Duration::from_millis(5));
    let d = v.dev(0);
    let mut e = env(v, orchestrator());
    e.c.run_cycle().await.unwrap();
    for (section, secrets) in [
        (
            "edges",
            &["FAKE-ACTV-0001", "FAKE-ACTV-0003", "fake-bgp-secret"][..],
        ),
        ("edge_state", &["FAKE-ACTV-0001"][..]),
        (
            "profiles",
            &["fake-radius-secret", "fake-tacacs-key", "fake-ipsec-psk"][..],
        ),
        ("edge_modules", &["fake-snmp-community"][..]),
    ] {
        let text = e.bytes(&d, section);
        for (i, s) in secrets.iter().enumerate() {
            assert!(!text.contains(s), "{section}: secret {i}");
        }
    }
    let edges = e.json(&d, "edges");
    assert_eq!(edges[0]["activationKey"], velocloud::REDACTED);
    assert_eq!(edges[0]["serialNumber"], "S-0001");
    let profiles = e.json(&d, "profiles");
    assert_eq!(
        profiles[0]["modules"][0]["data"]["vpn"]["thirdParty"][0],
        json!({"name": "psk", "value": velocloud::REDACTED})
    );
}

#[tokio::test(start_paused = true)]
async fn discover_reads_each_page_of_the_enterprises() {
    let t = FakeTransport::new(Duration::ZERO);
    let d = Device {
        id: "vco-lab".into(),
        site: None,
        ..device("ent-a")
    };
    t.reply(
        &d.id,
        &format!("{BASE}/enterprises"),
        Ok(json!({"data": [{"logicalId": "ent-a", "name": "Enterprise A"}], "metaData": {"nextPageLink": "p2"}})
            .to_string()
            .into_bytes()),
    );
    t.reply(
        &d.id,
        &format!("{BASE}/enterprises?nextPageLink=p2"),
        Ok(json!({"data": [{"logicalId": "ent-b"}], "metaData": {}})
            .to_string()
            .into_bytes()),
    );
    assert_eq!(
        velocloud::discover(&t, &d, BASE).await,
        Ok(vec![
            ("ent-a".to_string(), Some("Enterprise A".to_string())),
            ("ent-b".to_string(), None),
        ])
    );
}

#[tokio::test(start_paused = true)]
async fn probe_reads_one_edge_of_each_enterprise() {
    let t = FakeTransport::new(Duration::ZERO);
    let d = Device {
        id: "vco-lab".into(),
        site: None,
        ..device("ent-a")
    };
    t.reply(
        &d.id,
        &format!("{BASE}/enterprises/ent-a/edges?limit=1"),
        Ok(br#"{"data": [], "metaData": {}}"#.to_vec()),
    );
    t.reply_status(
        &d.id,
        &format!("{BASE}/enterprises/ent-b/edges?limit=1"),
        403,
        "denied",
    );
    let got = velocloud::probe(&t, &d, BASE, &["ent-a".into(), "ent-b".into()]).await;
    assert_eq!(
        got,
        [
            ("ent-a".to_string(), Ok(())),
            ("ent-b".to_string(), Err("HTTP 403: denied".to_string())),
        ]
    );
    t.reply(
        &d.id,
        &format!("{BASE}/enterprises?limit=1"),
        Ok(b"[]".to_vec()),
    );
    assert_eq!(
        velocloud::probe(&t, &d, BASE, &[]).await,
        [("enterprises".to_string(), Ok(()))]
    );
}
