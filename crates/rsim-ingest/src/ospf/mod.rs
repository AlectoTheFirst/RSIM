//! The OSPF link-state databases of a device from its collected OSPF
//! sections: one [`Database`] of `rsim-routing` for each VRF, process and
//! version, with the outcome of the read of each version.
//!
//! The process section gives the router ID and the area types, the
//! interface section the interfaces with their address, interface ID and
//! cost, and each database section the LSAs of one type with the span of
//! each LSA. NX-OS answers with JSON for all VRFs, IOS-XE and IOS-XR with
//! text, VyOS with the FRR JSON of each VRF for OSPFv2 and of the default
//! VRF for OSPFv3. The OSPF commands and their fields are not confirmed on
//! a device.

pub mod inputs;
mod json;
pub mod routes;
mod text;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rsim_core::{Prefix, SourceSpan};
use rsim_routing::ospf::{
    Body, Database, LinkKind, Lsa, LsaType, Reference, RouterLink, Version, mask_len,
};
use rsim_store::{Hash, Snapshot, Store, StoreError};

use crate::bgp::{Answer, Collected, Outcome, Scope, SectionOutcome};

/// The sections of one OSPF version.
#[derive(Clone, Copy, Debug)]
pub struct VersionSections {
    pub version: Version,
    /// The process: the router ID and the areas.
    pub process: &'static str,
    pub interfaces: &'static str,
    pub neighbors: &'static str,
    /// The database sections, each with the LSA type of its command.
    pub lsdb: &'static [(&'static str, LsaType)],
}

/// The OSPFv2 sections.
pub const V2: VersionSections = VersionSections {
    version: Version::V2,
    process: "ospf",
    interfaces: "ospf_interfaces",
    neighbors: "ospf_neighbors",
    lsdb: &[
        ("ospf_lsdb_router", LsaType::Router),
        ("ospf_lsdb_network", LsaType::Network),
        ("ospf_lsdb_summary", LsaType::Summary),
        ("ospf_lsdb_asbr_summary", LsaType::AsbrSummary),
        ("ospf_lsdb_external", LsaType::External),
        ("ospf_lsdb_nssa_external", LsaType::NssaExternal),
    ],
};

/// The OSPFv3 sections.
pub const V3: VersionSections = VersionSections {
    version: Version::V3,
    process: "ospfv3",
    interfaces: "ospfv3_interfaces",
    neighbors: "ospfv3_neighbors",
    lsdb: &[
        ("ospfv3_lsdb_router", LsaType::Router),
        ("ospfv3_lsdb_network", LsaType::Network),
        ("ospfv3_lsdb_inter_area_prefix", LsaType::Summary),
        ("ospfv3_lsdb_inter_area_router", LsaType::AsbrSummary),
        ("ospfv3_lsdb_external", LsaType::External),
        ("ospfv3_lsdb_nssa", LsaType::NssaExternal),
        ("ospfv3_lsdb_link", LsaType::Link),
        ("ospfv3_lsdb_intra_area_prefix", LsaType::IntraAreaPrefix),
    ],
};

/// The running config section, which gives the VRF of an IOS-XE process.
pub const CONFIG: &str = "config";

impl VersionSections {
    /// The names of the sections, in order.
    pub fn names(&self) -> Vec<&'static str> {
        let mut out = vec![self.process, self.interfaces, self.neighbors];
        out.extend(self.lsdb.iter().map(|(n, _)| *n));
        out
    }

    /// The address family of the scope of an outcome.
    fn family(&self) -> &'static str {
        match self.version {
            Version::V2 => "ipv4",
            Version::V3 => "ipv6",
        }
    }
}

/// The sections that a vendor reads for OSPF.
pub fn sections(vendor: &str) -> Vec<&'static str> {
    match vendor {
        "nxos" | "iosxr" | "iosxe" | "vyos" => {
            let mut out = V2.names();
            out.extend(V3.names());
            if vendor == "iosxe" {
                out.push(CONFIG);
            }
            out
        }
        _ => Vec::new(),
    }
}

/// The OSPF sections of a device by name.
pub type OspfSections = BTreeMap<String, Collected>;

/// The OSPF databases of a device and the outcome of the read of each
/// version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceOspf {
    /// The databases by version, VRF and process.
    pub databases: Vec<Database>,
    pub outcomes: BTreeMap<Version, SectionOutcome>,
}

impl DeviceOspf {
    /// The databases that the builder makes from the router config, with a
    /// complete outcome for each version.
    pub fn built(databases: Vec<Database>) -> DeviceOspf {
        let complete = || SectionOutcome {
            outcome: Outcome::Complete,
            scope: Scope(BTreeSet::new()),
            detail: None,
        };
        DeviceOspf {
            databases,
            outcomes: BTreeMap::from([(V2.version, complete()), (V3.version, complete())]),
        }
    }

    /// The databases of a version in a VRF.
    pub fn of(&self, version: Version, vrf: &str) -> impl Iterator<Item = &Database> {
        self.databases
            .iter()
            .filter(move |d| d.version == version && d.vrf == vrf)
    }
}

/// The databases of a device of a vendor from its OSPF sections.
pub fn read(vendor: &str, s: &OspfSections) -> DeviceOspf {
    let a = |name: &str| s.get(name).map_or(Answer::NotCollected, Collected::answer);
    let mut out = DeviceOspf {
        databases: Vec::new(),
        outcomes: BTreeMap::new(),
    };
    for v in [V2, V3] {
        let mut b = match vendor {
            "nxos" => json::nxos(&v, &a),
            "vyos" => json::frr(&v, &a),
            "iosxe" => text::cisco(&v, &a, Some(a(CONFIG))),
            "iosxr" => text::cisco(&v, &a, None),
            _ => Build::default(),
        };
        let o = outcome(&v, &a, &mut b);
        out.outcomes.insert(v.version, o);
        out.databases.extend(b.dbs.into_values());
    }
    out
}

/// The OSPF sections of each device of a snapshot.
pub fn inputs(
    store: &Store,
    snap: &Snapshot,
) -> Result<BTreeMap<String, OspfSections>, StoreError> {
    let mut out = BTreeMap::new();
    for (device, m) in &snap.devices {
        let mut sections = OspfSections::new();
        for name in self::sections(&m.vendor) {
            let Some(entry) = m.section(name) else {
                continue;
            };
            let (bytes, file) = match entry.blob {
                Some(b) => (
                    Some(store.read_blob(&b)?),
                    format!("{device}/{name}@{}", short(&b)),
                ),
                None => (None, format!("{device}/{name}")),
            };
            sections.insert(name.to_string(), Collected::of(entry, bytes, file));
        }
        out.insert(device.clone(), sections);
    }
    Ok(out)
}

/// The OSPF databases of each device of a snapshot whose vendor reads
/// OSPF.
pub fn of_snapshot(
    store: &Store,
    snap: &Snapshot,
) -> Result<BTreeMap<String, DeviceOspf>, StoreError> {
    let sections = inputs(store, snap)?;
    Ok(snap
        .devices
        .iter()
        .filter(|(_, m)| !self::sections(&m.vendor).is_empty())
        .map(|(d, m)| {
            let none = OspfSections::new();
            (d.clone(), read(&m.vendor, sections.get(d).unwrap_or(&none)))
        })
        .collect())
}

fn short(h: &Hash) -> String {
    h.to_string().chars().take(12).collect()
}

/// The databases of one version while the sections are read, the parts
/// that are not read, and the processes whose VRF is not read.
#[derive(Default)]
pub(crate) struct Build {
    pub dbs: BTreeMap<(String, String), Database>,
    pub unread: Vec<String>,
    pub vrf_unread: Vec<String>,
    pub lsas: usize,
}

impl Build {
    pub fn db(&mut self, version: Version, vrf: &str, process: &str) -> &mut Database {
        self.dbs
            .entry((vrf.to_string(), process.to_string()))
            .or_insert_with(|| Database::new(version, vrf, process))
    }

    /// Adds the LSA of a raw row, or the reason why it is not read.
    pub fn add(&mut self, version: Version, lsa_type: LsaType, raw: &RawLsa) {
        match to_lsa(version, lsa_type, raw) {
            Ok(lsa) => {
                self.lsas += 1;
                self.db(version, &raw.vrf, &raw.process).insert(lsa);
            }
            Err(e) => self
                .unread
                .push(format!("{} at {}: {e}", lsa_type.name(version), raw.span)),
        }
    }
}

/// The outcome of the database sections of a version. The outcome is
/// `NotCaptured` when no section is collected or each is absent. It is
/// `Failed` when a read failed, or when no LSA is read and some sections are
/// absent or some parts are not read. It is `Partial` when some sections
/// are absent, some parts are not read or the VRF of a process is not read.
/// Else it is `Complete` or `CompleteEmpty`. The scope is the VRFs of the
/// databases.
fn outcome<'a>(
    v: &VersionSections,
    a: &impl Fn(&str) -> Answer<'a>,
    b: &mut Build,
) -> SectionOutcome {
    let answers: Vec<(&str, Answer<'_>)> = v.lsdb.iter().map(|(n, _)| (*n, a(n))).collect();
    let scope = Scope(
        b.dbs
            .keys()
            .map(|(vrf, _)| (vrf.clone(), v.family().to_string()))
            .collect(),
    );
    let with = |outcome, detail: Option<String>| SectionOutcome {
        outcome,
        scope: scope.clone(),
        detail,
    };
    if answers.iter().all(|(_, x)| *x == Answer::NotCollected) {
        return with(Outcome::NotCaptured, Some("section not collected".into()));
    }
    let failed: Vec<String> = answers
        .iter()
        .filter_map(|(n, x)| match x {
            Answer::Failed(e) => Some(format!("{n}: {e}")),
            _ => None,
        })
        .collect();
    if !failed.is_empty() {
        return with(
            Outcome::Failed,
            Some(format!("read failed: {}", failed.join(", "))),
        );
    }
    let absent: Vec<String> = answers
        .iter()
        .filter_map(|(n, x)| match x {
            Answer::Absent(r) => Some(format!("{n}: {r}")),
            Answer::NotCollected => Some(format!("{n}: not collected")),
            _ => None,
        })
        .collect();
    if absent.len() == answers.len() {
        return with(
            Outcome::NotCaptured,
            Some(format!("command not on the device: {}", absent.join(", "))),
        );
    }
    let mut notes = Vec::new();
    if !absent.is_empty() {
        notes.push(format!("not on the device: {}", absent.join(", ")));
    }
    if !b.unread.is_empty() {
        notes.push(format!("not read: {}", b.unread.join(", ")));
    }
    let lost = !notes.is_empty();
    if !b.vrf_unread.is_empty() {
        notes.push(format!("VRF not read: {}", b.vrf_unread.join(", ")));
    }
    let outcome = match (b.lsas, lost, notes.is_empty()) {
        (0, _, true) => Outcome::CompleteEmpty,
        (_, _, true) => Outcome::Complete,
        (0, true, _) => Outcome::Failed,
        _ => Outcome::Partial,
    };
    with(outcome, (!notes.is_empty()).then(|| notes.join(", ")))
}

/// One link of a router LSA as a section gives it.
#[derive(Clone, Debug, Default)]
pub(crate) struct RawLink {
    pub kind: Option<String>,
    pub id: Option<String>,
    pub data: Option<String>,
    pub metric: Option<String>,
    pub interface_id: Option<String>,
    pub neighbor_interface_id: Option<String>,
}

/// One prefix of an OSPFv3 LSA with its length and metric. The prefix is
/// empty when the row has no prefix field.
#[derive(Clone, Debug, Default)]
pub(crate) struct RawPrefix {
    pub prefix: String,
    pub len: Option<String>,
    pub metric: Option<String>,
}

/// One LSA as a section gives it, before the checks of its type.
#[derive(Clone, Debug)]
pub(crate) struct RawLsa {
    pub vrf: String,
    pub process: String,
    pub area: Option<String>,
    pub lsid: Option<String>,
    pub adv: Option<String>,
    pub seq: Option<String>,
    pub age: Option<String>,
    pub links: Vec<RawLink>,
    /// An attached router is empty when its row has no router field.
    pub attached: Vec<String>,
    pub mask: Option<String>,
    pub prefix: Option<String>,
    pub prefix_len: Option<String>,
    pub metric: Option<String>,
    pub metric_type: Option<String>,
    pub forwarding: Option<String>,
    pub router: Option<String>,
    pub link_local: Option<String>,
    pub interface: Option<String>,
    pub prefixes: Vec<RawPrefix>,
    pub reference: Option<String>,
    pub reference_id: Option<String>,
    pub reference_adv: Option<String>,
    pub span: SourceSpan,
}

impl RawLsa {
    pub fn new(vrf: &str, process: &str, span: SourceSpan) -> RawLsa {
        RawLsa {
            vrf: vrf.to_string(),
            process: process.to_string(),
            area: None,
            lsid: None,
            adv: None,
            seq: None,
            age: None,
            links: Vec::new(),
            attached: Vec::new(),
            mask: None,
            prefix: None,
            prefix_len: None,
            metric: None,
            metric_type: None,
            forwarding: None,
            router: None,
            link_local: None,
            interface: None,
            prefixes: Vec::new(),
            reference: None,
            reference_id: None,
            reference_adv: None,
            span,
        }
    }
}

/// A number in decimal or with `0x` in hexadecimal.
pub(crate) fn num(s: &str) -> Option<u32> {
    let t = s.trim().trim_end_matches(',');
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => u32::from_str_radix(h, 16).ok(),
        None => t.parse().ok(),
    }
}

/// An ID in dotted form or as a decimal number: an area, a link-state ID or
/// an interface ID. The first word counts, so `0.0.0.1 [Stub]` is
/// `0.0.0.1`.
pub(crate) fn dotted(s: &str) -> Option<Ipv4Addr> {
    let w = s.split_whitespace().next()?.trim_end_matches(',');
    if w.bytes().all(|b| b.is_ascii_digit()) {
        return w.parse::<u32>().ok().map(Ipv4Addr::from);
    }
    w.parse().ok()
}

/// A mask in dotted form, as a length, or as a length after `/`.
pub(crate) fn mask(s: &str) -> Option<Ipv4Addr> {
    let t = s.trim().trim_start_matches('/');
    if let Ok(len) = t.parse::<u32>() {
        return (len <= 32).then(|| Ipv4Addr::from(u32::MAX.checked_shl(32 - len).unwrap_or(0)));
    }
    t.parse().ok()
}

/// A prefix as `address/length`, or an address with a separate length.
/// The host bits are cleared.
pub(crate) fn prefix(s: &str, len: Option<&str>) -> Option<Prefix> {
    let s = s.trim();
    let (a, l) = match s.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (s, len),
    };
    let addr: IpAddr = a.trim().parse().ok()?;
    let len: u8 = l?.trim().trim_end_matches(',').parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    (len <= max).then(|| Prefix::new(addr, len))
}

/// The link type of a word or a phrase: the numbers of RFC 2328 A.4.2, the
/// words of the platforms and the phrases of a Cisco database.
pub(crate) fn link_kind(s: &str) -> Option<LinkKind> {
    let l = s.trim().to_ascii_lowercase();
    match l.as_str() {
        "1" => return Some(LinkKind::PointToPoint),
        "2" => return Some(LinkKind::Transit),
        "3" => return Some(LinkKind::Stub),
        "4" => return Some(LinkKind::Virtual),
        _ => {}
    }
    if l.contains("transit") {
        Some(LinkKind::Transit)
    } else if l.contains("stub") {
        Some(LinkKind::Stub)
    } else if l.contains("virtual") {
        Some(LinkKind::Virtual)
    } else if l.contains("point") || l.contains("p2p") || l.contains("router") {
        Some(LinkKind::PointToPoint)
    } else {
        None
    }
}

/// The metric type 1 or 2 of a word such as `2`, `E2` or `type-2`.
pub(crate) fn metric_type(s: &str) -> Option<String> {
    s.chars()
        .find(|c| *c == '1' || *c == '2')
        .map(|c| c.to_string())
}

/// True for a JSON or text flag that is set.
pub(crate) fn truthy(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "true" | "yes" | "enabled" | "1"
    )
}

fn req<'r>(v: &'r Option<String>, what: &str) -> Result<&'r str, String> {
    v.as_deref().ok_or_else(|| format!("no {what}"))
}

fn router_id(v: &Option<String>, what: &str) -> Result<Ipv4Addr, String> {
    let s = req(v, what)?;
    s.split_whitespace()
        .next()
        .and_then(|w| w.parse().ok())
        .ok_or_else(|| format!("{what} {s} not an address"))
}

fn number(v: &Option<String>, what: &str) -> Result<u32, String> {
    let s = req(v, what)?;
    num(s).ok_or_else(|| format!("{what} {s} not a number"))
}

fn v2_prefix(lsid: Ipv4Addr, raw: &RawLsa) -> Result<Prefix, String> {
    let m = req(&raw.mask, "mask")?;
    let len = mask(m)
        .and_then(mask_len)
        .ok_or_else(|| format!("mask {m} not read"))?;
    Ok(Prefix::new(IpAddr::V4(lsid), len))
}

/// The prefix of a prefix row of an OSPFv3 LSA.
fn row_prefix(p: &RawPrefix) -> Result<Prefix, String> {
    if p.prefix.trim().is_empty() {
        return Err("a prefix row has no prefix".into());
    }
    prefix(&p.prefix, p.len.as_deref()).ok_or_else(|| format!("prefix {} not read", p.prefix))
}

fn v3_prefix(raw: &RawLsa) -> Result<Prefix, String> {
    let p = req(&raw.prefix, "prefix")?;
    prefix(p, raw.prefix_len.as_deref()).ok_or_else(|| format!("prefix {p} not read"))
}

fn to_link(version: Version, l: &RawLink) -> Result<RouterLink, String> {
    let kind_word = req(&l.kind, "link type")?;
    let kind = link_kind(kind_word).ok_or_else(|| format!("link type {kind_word} not read"))?;
    let metric = number(&l.metric, "link metric")?;
    let id = router_id(&l.id, "link ID")?;
    match version {
        Version::V2 => {
            let data = match &l.data {
                Some(d) => Some(
                    d.split_whitespace()
                        .next()
                        .and_then(|w| w.parse().ok())
                        .ok_or_else(|| format!("link data {d} not an address"))?,
                ),
                None => None,
            };
            if kind == LinkKind::Stub && data.and_then(mask_len).is_none() {
                return Err(format!("stub link {id} has no usable mask"));
            }
            Ok(RouterLink {
                kind,
                id,
                data,
                metric,
                interface_id: None,
                neighbor_interface_id: None,
            })
        }
        Version::V3 => {
            if kind == LinkKind::Stub {
                return Err("OSPFv3 has no stub link".into());
            }
            let ifid = |v: &Option<String>, what: &str| -> Result<u32, String> {
                let s = req(v, what)?;
                dotted(s)
                    .map(u32::from)
                    .ok_or_else(|| format!("{what} {s} not read"))
            };
            Ok(RouterLink {
                kind,
                id,
                data: None,
                metric,
                interface_id: Some(ifid(&l.interface_id, "interface ID")?),
                neighbor_interface_id: Some(ifid(
                    &l.neighbor_interface_id,
                    "neighbour interface ID",
                )?),
            })
        }
    }
}

/// The LSA of a raw row of a database section of `lsa_type`.
pub(crate) fn to_lsa(version: Version, lsa_type: LsaType, raw: &RawLsa) -> Result<Lsa, String> {
    let adv = router_id(&raw.adv, "advertising router")?;
    let lsid = match (&raw.lsid, lsa_type, version) {
        (Some(s), _, _) => dotted(s).ok_or_else(|| format!("link-state ID {s} not read"))?,
        (None, LsaType::Router, Version::V2) => adv,
        (None, LsaType::Router, Version::V3) => Ipv4Addr::UNSPECIFIED,
        (None, _, _) => return Err("no link-state ID".into()),
    };
    let area = if lsa_type.area_scoped() {
        let s = req(&raw.area, "area")?;
        Some(dotted(s).ok_or_else(|| format!("area {s} not read"))?)
    } else {
        None
    };
    let body = match lsa_type {
        LsaType::Router => {
            if version == Version::V2 && lsid != adv {
                return Err(format!(
                    "link-state ID {lsid} is not the advertising router {adv}"
                ));
            }
            Body::Router {
                links: raw
                    .links
                    .iter()
                    .map(|l| to_link(version, l))
                    .collect::<Result<_, _>>()?,
            }
        }
        LsaType::Network => Body::Network {
            mask: match version {
                Version::V2 => Some(raw.mask.as_deref().and_then(mask).ok_or("no usable mask")?),
                Version::V3 => None,
            },
            attached: raw
                .attached
                .iter()
                .map(|r| match r.trim() {
                    "" => Err("an attached router row has no router".to_string()),
                    t => t
                        .parse()
                        .map_err(|_| format!("attached router {r} not read")),
                })
                .collect::<Result<_, _>>()?,
        },
        LsaType::Summary => Body::Summary {
            prefix: match version {
                Version::V2 => v2_prefix(lsid, raw)?,
                Version::V3 => v3_prefix(raw)?,
            },
            metric: number(&raw.metric, "metric")?,
        },
        LsaType::AsbrSummary => Body::AsbrSummary {
            router: match (&raw.router, version) {
                (Some(_), _) => router_id(&raw.router, "destination router")?,
                (None, Version::V2) => lsid,
                (None, Version::V3) => return Err("no destination router".into()),
            },
            metric: number(&raw.metric, "metric")?,
        },
        LsaType::External | LsaType::NssaExternal => Body::External {
            prefix: match version {
                Version::V2 => v2_prefix(lsid, raw)?,
                Version::V3 => v3_prefix(raw)?,
            },
            metric: number(&raw.metric, "metric")?,
            metric_type: raw
                .metric_type
                .as_deref()
                .and_then(metric_type)
                .and_then(|t| t.parse().ok()),
            forwarding: match &raw.forwarding {
                Some(f) => Some(
                    f.split_whitespace()
                        .next()
                        .and_then(|w| w.parse().ok())
                        .ok_or_else(|| format!("forwarding address {f} not read"))?,
                ),
                None => None,
            },
        },
        LsaType::Link => Body::Link {
            address: match &raw.link_local {
                Some(a) => Some(
                    a.trim()
                        .parse::<Ipv6Addr>()
                        .map_err(|_| format!("link-local address {a} not read"))?,
                ),
                None => None,
            },
            prefixes: raw
                .prefixes
                .iter()
                .map(row_prefix)
                .collect::<Result<_, _>>()?,
            interface: raw.interface.clone(),
        },
        LsaType::IntraAreaPrefix => {
            let r = req(&raw.reference, "referenced LSA type")?.to_ascii_lowercase();
            let reference = if r.contains("router") || r.contains("2001") || r.contains("8193") {
                Reference::Router
            } else if r.contains("network") || r.contains("2002") || r.contains("8194") {
                let id = req(&raw.reference_id, "referenced link-state ID")?;
                Reference::Network(
                    dotted(id)
                        .map(u32::from)
                        .ok_or_else(|| format!("referenced link-state ID {id} not read"))?,
                )
            } else {
                return Err(format!("referenced LSA type {r} not read"));
            };
            Body::IntraAreaPrefix {
                reference,
                router: match &raw.reference_adv {
                    Some(_) => router_id(&raw.reference_adv, "referenced advertising router")?,
                    None => adv,
                },
                prefixes: raw
                    .prefixes
                    .iter()
                    .map(|p| {
                        let pf = row_prefix(p)?;
                        let m = p
                            .metric
                            .as_deref()
                            .ok_or_else(|| format!("prefix {} has no metric", p.prefix))?;
                        num(m)
                            .map(|m| (pf, m))
                            .ok_or_else(|| format!("metric {m} of prefix {} not read", p.prefix))
                    })
                    .collect::<Result<_, _>>()?,
            }
        }
    };
    Ok(Lsa {
        lsa_type,
        area,
        lsid,
        adv_router: adv,
        seq: raw.seq.as_deref().and_then(num),
        age: raw.age.as_deref().and_then(num),
        body,
        span: raw.span.clone(),
    })
}

/// The VRF name of a VRF field: the default VRF is `default`.
pub(crate) fn vrf_name(s: Option<&str>) -> String {
    match s.map(str::trim) {
        None | Some("") | Some("default") => "default".to_string(),
        Some(v) => v.to_string(),
    }
}
