//! The Equinix Fabric source. One device is one account of the API at the
//! address of the device. The source reads the Fabric ports, the
//! connections of the ports and, with Network Edge on, the Network Edge
//! devices, their device link groups and their connections. Each section
//! is the list of the items of all pages of one collection, with the
//! secrets redacted, sorted by `uuid` and then by the canonical bytes.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use rsim_store::{Class, Format};
use serde_json::{Value, json};
use tokio::time::Instant;

use crate::redact::redact;
use crate::{
    BoxFuture, Device, HttpReply, Https, RawSection, SectionSpec, Source, Timeouts, TransportError,
    Vendor,
};

/// The Fabric ports of the account.
pub const PORTS: &str = "/fabric/v4/ports";
/// The search of the connections.
pub const SEARCH: &str = "/fabric/v4/connections/search";
/// The Network Edge devices of the account.
pub const EDGE_DEVICES: &str = "/ne/v1/devices";
/// The Network Edge device link groups of the account.
pub const EDGE_LINKS: &str = "/ne/v1/links";

/// The POST paths that the source sends. The connection search changes
/// nothing in the account.
pub const READ_PATHS: &[&str] = &[SEARCH];

/// The items of one page with no setting.
pub const DEFAULT_PAGE_SIZE: u32 = 100;
/// The largest page size.
pub const MAX_PAGE_SIZE: u32 = 1000;
/// The largest number of pages of one section.
pub const MAX_PAGES: usize = 10_000;

/// The search properties of the 2 ends of a connection on a Fabric port.
pub const PORT_PROPERTIES: [&str; 2] = [
    "/aSide/accessPoint/port/uuid",
    "/zSide/accessPoint/port/uuid",
];
/// The search properties of the 2 ends of a connection on a Network Edge
/// device. They come from the Go SDK of Equinix and are not confirmed on a
/// live answer.
pub const DEVICE_PROPERTIES: [&str; 2] = [
    "/aSide/accessPoint/virtualDevice/uuid",
    "/zSide/accessPoint/virtualDevice/uuid",
];

const PORTS_KEEP: &[&str] = &[
    "*/uuid",
    "*/name",
    "*/state",
    "*/bandwidth",
    "*/physicalPortsSpeed",
    "*/encapsulation/type",
    "*/encapsulation/tagProtocolId",
    "*/location/ibx",
    "*/location/metroCode",
    "*/redundancy/priority",
    "*/lag/enabled",
    "*/lag/name",
    "*/physicalPorts/*/tether/crossConnectId",
];

const CONNECTIONS_KEEP: &[&str] = &[
    "*/uuid",
    "*/name",
    "*/type",
    "*/state",
    "*/bandwidth",
    "*/aSide/accessPoint/type",
    "*/aSide/accessPoint/port/uuid",
    "*/aSide/accessPoint/interface/uuid",
    "*/aSide/accessPoint/interface/id",
    "*/aSide/accessPoint/linkProtocol/type",
    "*/aSide/accessPoint/linkProtocol/vlanTag",
    "*/aSide/accessPoint/linkProtocol/vlanSTag",
    "*/aSide/accessPoint/linkProtocol/vlanCTag",
    "*/aSide/accessPoint/profile/uuid",
    "*/aSide/accessPoint/profile/name",
    "*/aSide/accessPoint/virtualDevice/uuid",
    "*/aSide/accessPoint/virtualDevice/name",
    "*/zSide/accessPoint/type",
    "*/zSide/accessPoint/port/uuid",
    "*/zSide/accessPoint/interface/uuid",
    "*/zSide/accessPoint/interface/id",
    "*/zSide/accessPoint/linkProtocol/type",
    "*/zSide/accessPoint/linkProtocol/vlanTag",
    "*/zSide/accessPoint/linkProtocol/vlanSTag",
    "*/zSide/accessPoint/linkProtocol/vlanCTag",
    "*/zSide/accessPoint/profile/uuid",
    "*/zSide/accessPoint/profile/name",
    "*/zSide/accessPoint/virtualDevice/uuid",
    "*/zSide/accessPoint/virtualDevice/name",
];

const EDGE_DEVICES_KEEP: &[&str] = &[
    "*/uuid",
    "*/name",
    "*/hostName",
    "*/deviceTypeCode",
    "*/deviceTypeVendor",
    "*/deviceTypeCategory",
    "*/status",
    "*/version",
    "*/ibx",
    "*/metroCode",
    "*/redundancyType",
    "*/sshIpAddress",
    "*/interfaces/*/id",
    "*/interfaces/*/name",
    "*/interfaces/*/type",
    "*/interfaces/*/status",
    "*/interfaces/*/assignedType",
    "*/interfaces/*/uuid",
    "*/interfaces/*/macAddress",
];

const EDGE_LINKS_KEEP: &[&str] = &[
    "*/uuid",
    "*/groupName",
    "*/status",
    "*/redundancyType",
    "*/metroLinks/*/throughput",
    "*/metroLinks/*/throughputUnit",
    "*/linkDevices/*/deviceUuid",
    "*/linkDevices/*/interfaceId",
    "*/linkDevices/*/status",
];

/// The settings of an account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    /// True if the source reads the Network Edge sections.
    pub network_edge: bool,
    /// The items of one page, from 1 to [`MAX_PAGE_SIZE`].
    pub page_size: u32,
}

impl Default for Account {
    fn default() -> Account {
        Account {
            network_edge: false,
            page_size: DEFAULT_PAGE_SIZE,
        }
    }
}

fn spec(name: &'static str, command: String, keep: &'static [&'static str]) -> SectionSpec {
    SectionSpec {
        name,
        command,
        class: Class::Configuration,
        format: Format::Json,
        volatile: &[],
        extracts: &[],
        keep,
        optional: false,
    }
}

/// The sections of an account, in the order of the reads. The Network Edge
/// sections are optional.
pub fn sections(account: &Account) -> Vec<SectionSpec> {
    let mut out = vec![
        spec("ports", format!("GET {PORTS}"), PORTS_KEEP),
        spec("connections", format!("POST {SEARCH}"), CONNECTIONS_KEEP),
    ];
    if account.network_edge {
        for s in [
            spec(
                "edge_devices",
                format!("GET {EDGE_DEVICES}"),
                EDGE_DEVICES_KEEP,
            ),
            spec("edge_links", format!("GET {EDGE_LINKS}"), EDGE_LINKS_KEEP),
            spec("edge_connections", format!("POST {SEARCH}"), &[]),
        ] {
            out.push(SectionSpec {
                optional: true,
                ..s
            });
        }
    }
    out
}

/// The body of a connection search for the values of 2 properties.
pub fn search_body(properties: [&str; 2], values: &[String], offset: usize, limit: u32) -> Value {
    json!({
        "filter": {"or": [
            {"property": properties[0], "operator": "IN", "values": values},
            {"property": properties[1], "operator": "IN", "values": values},
        ]},
        "pagination": {"offset": offset, "limit": limit},
        "sort": [{"property": "/changeLog/createdDateTime", "direction": "ASC"}],
    })
}

/// The read of one page.
enum Read<'a> {
    Get(&'static str),
    Search([&'static str; 2], &'a [String]),
}

impl Read<'_> {
    fn path(&self) -> &'static str {
        match self {
            Read::Get(p) => p,
            Read::Search(..) => SEARCH,
        }
    }
}

/// The items of a page: the objects of its `data` list or of the page as a
/// list, with the `pagination.total` of the page. A page of another shape
/// is an error.
fn page_items(page: Value, path: &str) -> Result<(Vec<Value>, Option<u64>), String> {
    let (items, total) = match page {
        Value::Array(a) => (a, None),
        Value::Object(mut m) => {
            let total = m
                .get("pagination")
                .and_then(|p| p.get("total"))
                .and_then(Value::as_u64);
            match m.remove("data") {
                Some(Value::Array(a)) => (a, total),
                _ => return Err(format!("{path}: a page has no data list")),
            }
        }
        _ => return Err(format!("{path}: a page is not a list")),
    };
    Ok((items.into_iter().filter(Value::is_object).collect(), total))
}

/// The error of a status of a read. A 404 of an optional Network Edge list
/// gives an absent section.
fn status_error(path: &str, status: u16, text: &str) -> TransportError {
    match status {
        404 if path == EDGE_DEVICES || path == EDGE_LINKS => {
            TransportError::NotFound(format!("HTTP 404 for {path}"))
        }
        401 | 403 => TransportError::Command(format!("HTTP {status} for {path}: not authorized")),
        _ => TransportError::Command(format!("HTTP {status} for {path}: {text}")),
    }
}

/// The `uuid` of an item, or an empty text.
fn uuid(v: &Value) -> &str {
    v.get("uuid").and_then(Value::as_str).unwrap_or_default()
}

/// The `uuid` of each item, each once, in sorted order.
fn uuids(items: &[Value]) -> Vec<String> {
    let set: BTreeSet<&str> = items.iter().map(uuid).filter(|u| !u.is_empty()).collect();
    set.into_iter().map(str::to_string).collect()
}

/// The section of the items: the list sorted by `uuid` and then by the
/// canonical bytes.
fn section_bytes(items: &[Value]) -> Vec<u8> {
    let mut keyed: Vec<(&str, String)> = items.iter().map(|v| (uuid(v), v.to_string())).collect();
    keyed.sort();
    let body: Vec<&str> = keyed.iter().map(|(_, t)| t.as_str()).collect();
    format!("[{}]", body.join(",")).into_bytes()
}

/// The Equinix source.
pub struct EquinixSource {
    https: Arc<dyn Https>,
    accounts: HashMap<String, Account>,
}

impl EquinixSource {
    pub fn new(https: Arc<dyn Https>) -> EquinixSource {
        EquinixSource {
            https,
            accounts: HashMap::new(),
        }
    }

    /// Sets the settings of the account of a device.
    pub fn with_account(mut self, device: &str, account: Account) -> EquinixSource {
        self.accounts.insert(device.to_string(), account);
        self
    }

    fn account(&self, device: &Device) -> Account {
        self.accounts.get(&device.id).copied().unwrap_or_default()
    }

    /// Reads all pages of one collection, ported from HST `_pages`. With
    /// `pagination.total`, the read goes on until the offset reaches the
    /// total, and an empty page before it is an error. With no total, an
    /// empty or short page ends the read.
    async fn pages(
        &self,
        device: &Device,
        read: &Read<'_>,
        limit: u32,
    ) -> Result<Vec<Value>, TransportError> {
        let path = read.path();
        let failed = |e: String| TransportError::Command(e);
        let mut items = Vec::new();
        let mut offset = 0usize;
        for _ in 0..MAX_PAGES {
            let reply = match read {
                Read::Get(p) => {
                    self.https
                        .get_status(device, &format!("{p}?offset={offset}&limit={limit}"))
                        .await?
                }
                Read::Search(properties, values) => {
                    let body = search_body(*properties, values, offset, limit);
                    self.https
                        .post_read(device, READ_PATHS, SEARCH, &body)
                        .await?
                }
            };
            let body = match reply {
                HttpReply::Body(b) => b,
                HttpReply::Status { status, text } => {
                    return Err(status_error(path, status, &text));
                }
            };
            let page: Value = serde_json::from_slice(&body)
                .map_err(|e| failed(format!("{path}: the answer is not JSON: {e}")))?;
            let (page, total) = page_items(page, path).map_err(failed)?;
            let n = page.len();
            offset += n;
            items.extend(page);
            match total {
                Some(t) if offset as u64 >= t => return Ok(items),
                Some(t) if n == 0 => {
                    return Err(failed(format!(
                        "{path}: paging stopped at {offset} of {t} items"
                    )));
                }
                Some(_) => {}
                None if n == 0 || n < limit as usize => return Ok(items),
                None => {}
            }
        }
        Err(failed(format!("{path}: more than {MAX_PAGES} pages")))
    }

    /// Reads one section within the time of a section and the deadline of
    /// the device, and gives its items with the secrets redacted.
    async fn section(
        &self,
        device: &Device,
        read: Read<'_>,
        limit: u32,
        timeouts: Timeouts,
    ) -> Result<Vec<Value>, TransportError> {
        let end = Instant::now() + timeouts.section;
        let end = timeouts.deadline.map_or(end, |d| d.min(end));
        let mut items = tokio::time::timeout_at(end, self.pages(device, &read, limit))
            .await
            .unwrap_or(Err(TransportError::Timeout))?;
        items.iter_mut().for_each(redact);
        Ok(items)
    }
}

/// The result of a section that waits for the section `before`: no read
/// when `before` failed or is absent, an empty list when it has no uuid.
fn after(
    before: &Result<Vec<Value>, TransportError>,
    name: &str,
) -> Result<Option<Vec<String>>, TransportError> {
    match before {
        Ok(items) => {
            let u = uuids(items);
            Ok((!u.is_empty()).then_some(u))
        }
        Err(TransportError::NotFound(_)) => Err(TransportError::NotFound(format!(
            "not sent: {name} is absent"
        ))),
        Err(_) => Err(TransportError::Command(format!(
            "not sent: the read of {name} failed"
        ))),
    }
}

impl Source for EquinixSource {
    fn vendor(&self) -> Vendor {
        Vendor::Equinix
    }

    fn sections(&self, device: &Device) -> Vec<SectionSpec> {
        sections(&self.account(device))
    }

    /// Reads the sections in order. The first read logs in. A connect
    /// error, such as a login that fails, fails each section that is not
    /// read yet with the same error, and the source sends nothing more.
    fn fetch<'a>(
        &'a self,
        device: &'a Device,
        timeouts: Timeouts,
    ) -> BoxFuture<'a, Vec<RawSection>> {
        Box::pin(async move {
            let account = self.account(device);
            let limit = account.page_size.clamp(1, MAX_PAGE_SIZE);
            let specs = sections(&account);
            let mut results: Vec<Result<Vec<Value>, TransportError>> = Vec::new();
            let mut stop: Option<TransportError> = None;
            for spec in &specs {
                if let Some(e) = &stop {
                    results.push(Err(e.clone()));
                    continue;
                }
                let result = match spec.name {
                    "ports" => {
                        self.section(device, Read::Get(PORTS), limit, timeouts)
                            .await
                    }
                    "connections" => match after(&results[0], "ports") {
                        Ok(None) => Ok(Vec::new()),
                        Ok(Some(u)) => {
                            self.section(device, Read::Search(PORT_PROPERTIES, &u), limit, timeouts)
                                .await
                        }
                        Err(e) => Err(e),
                    },
                    "edge_devices" => {
                        self.section(device, Read::Get(EDGE_DEVICES), limit, timeouts)
                            .await
                    }
                    "edge_links" => {
                        self.section(device, Read::Get(EDGE_LINKS), limit, timeouts)
                            .await
                    }
                    _ => match after(&results[2], "edge_devices") {
                        Ok(None) => Ok(Vec::new()),
                        Ok(Some(u)) => {
                            self.section(
                                device,
                                Read::Search(DEVICE_PROPERTIES, &u),
                                limit,
                                timeouts,
                            )
                            .await
                        }
                        Err(e) => Err(e),
                    },
                };
                if let Err(e @ TransportError::Connect(_)) = &result {
                    stop = Some(e.clone());
                }
                results.push(result);
            }
            specs
                .into_iter()
                .zip(results)
                .map(|(spec, r)| RawSection {
                    spec,
                    result: r.map(|items| section_bytes(&items)),
                })
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_is_a_data_list_with_a_total_or_a_list() {
        let (items, total) = page_items(
            json!({"data": [{"uuid": "a"}, 7], "pagination": {"total": 3}}),
            PORTS,
        )
        .unwrap();
        assert_eq!((items, total), (vec![json!({"uuid": "a"})], Some(3)));
        let (items, total) = page_items(json!([{"uuid": "b"}]), PORTS).unwrap();
        assert_eq!((items, total), (vec![json!({"uuid": "b"})], None));
        assert!(page_items(json!({"items": []}), PORTS).is_err());
        assert!(page_items(json!("x"), PORTS).is_err());
    }

    #[test]
    fn the_section_order_does_not_depend_on_the_page_order() {
        let a = [
            json!({"uuid": "b", "n": 1}),
            json!({"uuid": "a"}),
            json!({"uuid": "b", "n": 0}),
        ];
        let b = [
            json!({"uuid": "b", "n": 0}),
            json!({"uuid": "b", "n": 1}),
            json!({"uuid": "a"}),
        ];
        assert_eq!(section_bytes(&a), section_bytes(&b));
        assert_eq!(
            String::from_utf8(section_bytes(&a)).unwrap(),
            r#"[{"uuid":"a"},{"n":0,"uuid":"b"},{"n":1,"uuid":"b"}]"#
        );
    }

    #[test]
    fn a_404_is_absent_only_for_the_network_edge_lists() {
        assert!(matches!(
            status_error(EDGE_LINKS, 404, ""),
            TransportError::NotFound(_)
        ));
        assert!(matches!(
            status_error(SEARCH, 404, ""),
            TransportError::Command(_)
        ));
        let TransportError::Command(e) = status_error(SEARCH, 400, "{\"code\":\"EQ-3040\"}") else {
            panic!("a 400 of a search fails the section");
        };
        assert!(e.contains("EQ-3040"), "{e}");
        let TransportError::Command(e) = status_error(PORTS, 403, "denied") else {
            panic!("a 403 fails the section");
        };
        assert!(e.ends_with("not authorized"), "{e}");
    }

    #[test]
    fn no_keep_path_names_a_secret() {
        for p in PORTS_KEEP
            .iter()
            .chain(CONNECTIONS_KEEP)
            .chain(EDGE_DEVICES_KEEP)
            .chain(EDGE_LINKS_KEEP)
        {
            for key in p.split('/').filter(|k| *k != "*") {
                let mut m = serde_json::Map::new();
                m.insert(key.to_string(), json!("x"));
                let mut v = Value::Object(m);
                redact(&mut v);
                assert_eq!(v[key], "x", "{p}");
            }
        }
    }
}
