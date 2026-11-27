//! The OSPF config of a VyOS router: `protocols ospf` and `protocols
//! ospfv3` of the main VRF and of each `vrf name <name>`, in the form of
//! `rsim_routing::ospf::config`.
//!
//! The schema of each version classifies the lines of a process. A line
//! with no entry in the schema goes into `Process::unhandled`. A handled
//! line is read unless the reader puts it into `Process::unhandled`.
//! `log-adjacency-changes` is known-irrelevant.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use rsim_core::{Prefix, SourceSpan};
use rsim_routing::ospf::config::{
    Area, DefaultOriginate, NetworkType, OspfInterface, Process, Redistribute, RouterConfig, Source,
};
use rsim_routing::ospf::{AreaId, AreaType, Version};

use crate::bgp_peers::DEFAULT_VRF;
use crate::coverage::{Reach, State, Table};
use crate::stanza::{Body, Document, Stanza};
use Reach::{Node, Subtree};
use State::{Handled, Irrelevant};

/// The process name of each VyOS process. FRR on VyOS has one unnamed
/// process for each VRF and version.
const PROCESS: &str = "";

/// The key of each version below `protocols`.
const VERSIONS: [(&str, Version); 2] = [("ospf", Version::V2), ("ospfv3", Version::V3)];

/// The redistribute sources of OSPFv2.
const SOURCES_V2: &[&str] = &[
    "babel",
    "bgp",
    "connected",
    "isis",
    "kernel",
    "nhrp",
    "rip",
    "static",
];

/// The redistribute sources of OSPFv3.
const SOURCES_V3: &[&str] = &[
    "babel",
    "bgp",
    "connected",
    "isis",
    "kernel",
    "ripng",
    "static",
];

/// The options of a redistribute source and of `default-information
/// originate`.
const ROUTE_OPTIONS: &[&str] = &["metric", "metric-type", "route-map"];

/// The lines of an OSPFv2 process, relative to the process.
const SCHEMA_V2: &[(&str, State, Reach)] = &[
    ("parameters", Handled, Node),
    ("parameters/router-id", Handled, Subtree),
    ("auto-cost", Handled, Node),
    ("auto-cost/reference-bandwidth", Handled, Subtree),
    ("area", Handled, Node),
    ("area/*", Handled, Node),
    ("area/*/network", Handled, Subtree),
    ("area/*/area-type", Handled, Node),
    ("area/*/area-type/normal", Handled, Subtree),
    ("area/*/area-type/stub", Handled, Node),
    ("area/*/area-type/stub/no-summary", Handled, Subtree),
    ("area/*/area-type/stub/default-cost", Handled, Subtree),
    ("area/*/area-type/nssa", Handled, Node),
    ("area/*/area-type/nssa/no-summary", Handled, Subtree),
    ("area/*/area-type/nssa/default-cost", Handled, Subtree),
    ("interface", Handled, Node),
    ("interface/*", Handled, Node),
    ("interface/*/area", Handled, Subtree),
    ("interface/*/cost", Handled, Subtree),
    ("interface/*/bandwidth", Handled, Subtree),
    ("interface/*/network", Handled, Subtree),
    ("interface/*/priority", Handled, Subtree),
    ("interface/*/passive", Handled, Node),
    ("interface/*/passive/disable", Handled, Subtree),
    ("passive-interface", Handled, Subtree),
    ("redistribute", Handled, Node),
    ("default-information", Handled, Node),
    ("default-information/originate", Handled, Node),
    ("default-information/originate/always", Handled, Subtree),
    ("log-adjacency-changes", Irrelevant, Subtree),
];

/// The lines of an OSPFv3 process, relative to the process.
const SCHEMA_V3: &[(&str, State, Reach)] = &[
    ("parameters", Handled, Node),
    ("parameters/router-id", Handled, Subtree),
    ("auto-cost", Handled, Node),
    ("auto-cost/reference-bandwidth", Handled, Subtree),
    ("area", Handled, Node),
    ("area/*", Handled, Node),
    ("area/*/interface", Handled, Subtree),
    ("area/*/area-type", Handled, Node),
    ("area/*/area-type/stub", Handled, Node),
    ("area/*/area-type/stub/no-summary", Handled, Subtree),
    ("area/*/area-type/nssa", Handled, Node),
    ("area/*/area-type/nssa/no-summary", Handled, Subtree),
    ("interface", Handled, Node),
    ("interface/*", Handled, Node),
    ("interface/*/area", Handled, Subtree),
    ("interface/*/cost", Handled, Subtree),
    ("interface/*/network", Handled, Subtree),
    ("interface/*/priority", Handled, Subtree),
    ("interface/*/passive", Handled, Subtree),
    ("redistribute", Handled, Node),
    ("default-information", Handled, Node),
    ("default-information/originate", Handled, Node),
    ("default-information/originate/always", Handled, Subtree),
    ("log-adjacency-changes", Irrelevant, Subtree),
];

fn sources(version: Version) -> &'static [&'static str] {
    match version {
        Version::V2 => SOURCES_V2,
        Version::V3 => SOURCES_V3,
    }
}

/// The entries of a process of one version, relative to the process.
fn schema(version: Version) -> Vec<(String, State, Reach)> {
    let fixed = match version {
        Version::V2 => SCHEMA_V2,
        Version::V3 => SCHEMA_V3,
    };
    let mut out: Vec<(String, State, Reach)> = fixed
        .iter()
        .map(|(p, s, r)| ((*p).to_string(), *s, *r))
        .collect();
    for opt in ROUTE_OPTIONS {
        out.push((
            format!("default-information/originate/{opt}"),
            Handled,
            Subtree,
        ));
    }
    for src in sources(version) {
        out.push((format!("redistribute/{src}"), Handled, Node));
        for opt in ROUTE_OPTIONS {
            out.push((format!("redistribute/{src}/{opt}"), Handled, Subtree));
        }
    }
    out
}

/// The classification table of a process of one version, relative to the
/// process.
fn process_table(version: Version) -> Table {
    let mut t = Table::new(&[]);
    for (p, s, r) in schema(version) {
        t.push(&p, s, r);
    }
    t
}

/// Adds the entries of the OSPF processes of the main VRF and of each VRF
/// to the classification table of the vendor.
pub(crate) fn push_entries(t: &mut Table) {
    for (key, version) in VERSIONS {
        for base in ["protocols", "vrf/name/*/protocols"] {
            t.push(&format!("{base}/{key}"), Handled, Node);
            for (p, s, r) in schema(version) {
                t.push(&format!("{base}/{key}/{p}"), s, r);
            }
        }
    }
}

/// The OSPF processes of a config: the version, the VRF and the stanza.
fn processes(root: &Stanza) -> Vec<(Version, String, &Stanza)> {
    let mut out = Vec::new();
    for (key, version) in VERSIONS {
        if let Some(s) = root.at(&["protocols", key]) {
            out.push((version, DEFAULT_VRF.to_string(), s));
        }
    }
    if let Some(names) = root.at(&["vrf", "name"]) {
        for v in names.children() {
            for (key, version) in VERSIONS {
                if let Some(s) = v.at(&["protocols", key]) {
                    out.push((version, v.key.clone(), s));
                }
            }
        }
    }
    out
}

/// The words of a line: the keys of the path and the values of a leaf.
fn words(path: &[&str], s: &Stanza) -> String {
    let mut w = path.join(" ");
    for t in s.texts() {
        w.push(' ');
        w.push_str(t);
    }
    w
}

fn mark_all(s: &Stanza, read: &mut BTreeSet<u32>) {
    read.insert(s.first_line);
    for c in s.children() {
        mark_all(c, read);
    }
}

/// Marks the handled and the known-irrelevant lines below `s`, and adds
/// each line with no entry to `out` with its words and its first and last
/// line. The lines below an unhandled line are not visited.
fn walk<'s>(
    t: &Table,
    s: &'s Stanza,
    path: &mut Vec<&'s str>,
    read: &mut BTreeSet<u32>,
    out: &mut Vec<(String, u32, u32)>,
) {
    for c in s.children() {
        path.push(&c.key);
        match t.state(path) {
            State::Handled => {
                read.insert(c.first_line);
                walk(t, c, path, read, out);
            }
            State::Irrelevant => mark_all(c, read),
            State::Unhandled => out.push((words(path, c), c.first_line, c.last_line)),
        }
        path.pop();
    }
}

/// Marks the read lines of each OSPF process in `read`: the handled lines
/// with no line of an entry of `Process::unhandled`.
pub(crate) fn mark(root: &Stanza, read: &mut BTreeSet<u32>) {
    build(root, "", read);
}

/// An interface of the config with the facts that OSPF reads.
#[derive(Clone, Debug)]
struct Link {
    name: String,
    /// The static addresses with their prefix length.
    addresses: Vec<(IpAddr, u8)>,
    /// The `dhcp` and `dhcpv6` values of `address`, with the words and the
    /// first and the last line of each.
    dynamic: Vec<(String, String, u32, u32)>,
    disabled: bool,
    vrf: String,
    /// The network type that FRR takes for the interface kind.
    network: NetworkType,
}

/// The network type of an interface with no `network` line: loopback for a
/// loopback, point-to-point for an interface that the kernel marks
/// point-to-point, and broadcast for each other interface. A tunnel is
/// point-to-point if it has a remote address and is not a layer 2 GRE
/// tunnel. An OpenVPN interface is point-to-point unless its device type
/// is `tap`.
fn default_network(kind: &str, s: &Stanza) -> NetworkType {
    match kind {
        "loopback" => NetworkType::Loopback,
        "pppoe" | "sstpc" | "wireguard" | "vti" => NetworkType::PointToPoint,
        "openvpn" => {
            if s.get("device-type").and_then(Stanza::text) == Some("tap") {
                NetworkType::Broadcast
            } else {
                NetworkType::PointToPoint
            }
        }
        "tunnel" => {
            let layer2 = s
                .get("encapsulation")
                .and_then(Stanza::text)
                .is_some_and(|e| e.ends_with("gretap"));
            if layer2 || s.get("remote").is_none() {
                NetworkType::Broadcast
            } else {
                NetworkType::PointToPoint
            }
        }
        _ => NetworkType::Broadcast,
    }
}

/// An address with its prefix length, for example `192.0.2.1/24`.
fn address(t: &str) -> Option<(IpAddr, u8)> {
    let (a, l) = t.split_once('/')?;
    Some((a.parse().ok()?, l.parse().ok()?))
}

/// The address values that a DHCP client sets.
const DYNAMIC: [&str; 2] = ["dhcp", "dhcpv6"];

/// The link of the interface stanza `s`. `path` is the words of the
/// stanza.
fn link(s: &Stanza, name: String, path: &str, network: NetworkType, parent_disabled: bool) -> Link {
    let values = s.get("address").map(values).unwrap_or_default();
    Link {
        name,
        addresses: values.iter().filter_map(|(t, _)| address(t)).collect(),
        dynamic: values
            .iter()
            .filter(|(t, _)| DYNAMIC.contains(t))
            .map(|(t, x)| {
                (
                    (*t).to_string(),
                    format!("{path} address {t}"),
                    x.first_line,
                    x.last_line,
                )
            })
            .collect(),
        disabled: parent_disabled || s.get("disable").is_some(),
        vrf: s
            .get("vrf")
            .and_then(Stanza::text)
            .unwrap_or(DEFAULT_VRF)
            .to_string(),
        network,
    }
}

/// The interfaces of each kind below `interfaces`, with their VLAN
/// subinterfaces (`vif`) and their 802.1ad subinterfaces (`vif-s` and
/// `vif-c`).
fn links(root: &Stanza) -> Vec<Link> {
    let mut out = Vec::new();
    let Some(ifs) = root.get("interfaces") else {
        return out;
    };
    for kind in ifs.children() {
        for i in kind.children() {
            let network = default_network(&kind.key, i);
            let path = format!("interfaces {} {}", kind.key, i.key);
            let parent = link(i, i.key.clone(), &path, network, false);
            let disabled = parent.disabled;
            out.push(parent);
            for v in i.get("vif").map(Stanza::children).unwrap_or_default() {
                let name = format!("{}.{}", i.key, v.key);
                let words = format!("{path} vif {}", v.key);
                out.push(link(v, name, &words, network, disabled));
            }
            for s in i.get("vif-s").map(Stanza::children).unwrap_or_default() {
                let name = format!("{}.{}", i.key, s.key);
                let words = format!("{path} vif-s {}", s.key);
                let outer = link(s, name.clone(), &words, network, disabled);
                let outer_disabled = outer.disabled;
                out.push(outer);
                for c in s.get("vif-c").map(Stanza::children).unwrap_or_default() {
                    out.push(link(
                        c,
                        format!("{name}.{}", c.key),
                        &format!("{words} vif-c {}", c.key),
                        network,
                        outer_disabled,
                    ));
                }
            }
        }
    }
    out
}

/// An area ID in its decimal or its dotted form.
fn area_id(t: &str) -> Option<AreaId> {
    t.parse::<u32>()
        .map(Ipv4Addr::from)
        .ok()
        .or_else(|| t.parse().ok())
}

/// The values of a leaf with each value stanza: the leaf for a single
/// value, each element for a multi-value leaf.
fn values(s: &Stanza) -> Vec<(&str, &Stanza)> {
    match &s.body {
        Body::Scalar(t) => vec![(t.as_str(), s)],
        Body::Array(c) => c.iter().filter_map(|x| Some((x.text()?, x))).collect(),
        Body::Object(_) => Vec::new(),
    }
}

/// The settings of one `interface <name>` stanza of a process.
struct Settings {
    /// The area with the words and the span of the `area` line.
    area: Option<(AreaId, String, SourceSpan)>,
    cost: Option<u32>,
    bandwidth_kbps: Option<u64>,
    network: Option<NetworkType>,
    /// `Some(false)` for `passive disable`.
    passive: Option<bool>,
    priority: Option<u8>,
    span: SourceSpan,
}

/// A `network` line of an area.
struct Network {
    prefix: Prefix,
    area: AreaId,
    words: String,
    span: SourceSpan,
}

/// The reader of one process.
struct Reader<'a> {
    file: &'a str,
    version: Version,
    unhandled: Vec<(String, SourceSpan)>,
}

impl Reader<'_> {
    fn span(&self, s: &Stanza) -> SourceSpan {
        SourceSpan::new(self.file, s.first_line, s.last_line)
    }

    fn bad(&mut self, words: String, s: &Stanza) {
        let span = self.span(s);
        self.unhandled.push((words, span));
    }

    /// The value of the leaf `key` of `s`. A value that does not parse goes
    /// into the unhandled lines.
    fn value<T: FromStr>(&mut self, s: &Stanza, key: &str, path: &str) -> Option<T> {
        let x = s.get(key)?;
        let t = x.text().unwrap_or_default();
        match t.parse() {
            Ok(v) => Some(v),
            Err(_) => {
                self.bad(format!("{path} {key} {t}"), x);
                None
            }
        }
    }

    fn metric_type(&mut self, s: &Stanza, path: &str) -> Option<u8> {
        let v: u8 = self.value(s, "metric-type", path)?;
        if v == 1 || v == 2 {
            Some(v)
        } else {
            self.bad(
                format!("{path} metric-type {v}"),
                s.get("metric-type").unwrap_or(s),
            );
            None
        }
    }

    fn network_type(&mut self, i: &Stanza, path: &str) -> Option<NetworkType> {
        let x = i.get("network")?;
        match x.text().unwrap_or_default() {
            "broadcast" => Some(NetworkType::Broadcast),
            "point-to-point" => Some(NetworkType::PointToPoint),
            other => {
                self.bad(format!("{path} network {other}"), x);
                None
            }
        }
    }

    fn area(&mut self, a: &Stanza) -> Area {
        let mut area = Area {
            kind: AreaType::Normal,
            no_summary: false,
            default_cost: None,
            span: self.span(a),
        };
        let path = format!("area {} area-type", a.key);
        for t in a.get("area-type").map(Stanza::children).unwrap_or_default() {
            area.kind = match (t.key.as_str(), self.version) {
                ("normal", Version::V2) => AreaType::Normal,
                ("stub", _) => AreaType::Stub,
                ("nssa", _) => AreaType::Nssa,
                _ => continue,
            };
            area.no_summary = t.get("no-summary").is_some();
            if self.version == Version::V2 {
                area.default_cost = self.value(t, "default-cost", &format!("{path} {}", t.key));
            }
        }
        area
    }

    fn settings(&mut self, i: &Stanza) -> Settings {
        let path = format!("interface {}", i.key);
        let area = i.get("area").and_then(|x| {
            let t = x.text().unwrap_or_default();
            let words = format!("{path} area {t}");
            match area_id(t) {
                Some(id) => Some((id, words, self.span(x))),
                None => {
                    self.bad(words, x);
                    None
                }
            }
        });
        let passive = match self.version {
            Version::V2 => i.get("passive").map(|p| p.get("disable").is_none()),
            Version::V3 => i.get("passive").map(|_| true),
        };
        let bandwidth_kbps = match self.version {
            Version::V2 => self
                .value::<u64>(i, "bandwidth", &path)
                .map(|mbps| mbps * 1000),
            Version::V3 => None,
        };
        Settings {
            area,
            cost: self.value(i, "cost", &path),
            bandwidth_kbps,
            network: self.network_type(i, &path),
            passive,
            priority: self.value(i, "priority", &path),
            span: self.span(i),
        }
    }

    fn redistribute(&mut self, s: &Stanza) -> Vec<Redistribute> {
        let mut out = Vec::new();
        for src in sources(self.version) {
            let Some(r) = s.at(&["redistribute", src]) else {
                continue;
            };
            let path = format!("redistribute {src}");
            let source = match *src {
                "connected" => Source::Connected,
                "static" => Source::Static,
                "bgp" => Source::Bgp,
                other => Source::Other(other.to_string()),
            };
            out.push(Redistribute {
                source,
                metric: self.value(r, "metric", &path),
                metric_type: self.metric_type(r, &path),
                route_map: r
                    .get("route-map")
                    .and_then(Stanza::text)
                    .map(str::to_string),
                span: self.span(r),
            });
        }
        out
    }

    fn default_originate(&mut self, s: &Stanza) -> Option<DefaultOriginate> {
        let o = s.at(&["default-information", "originate"])?;
        let path = "default-information originate";
        Some(DefaultOriginate {
            always: o.get("always").is_some(),
            metric: self.value(o, "metric", path),
            metric_type: self.metric_type(o, path),
            route_map: o
                .get("route-map")
                .and_then(Stanza::text)
                .map(str::to_string),
            span: self.span(o),
        })
    }
}

/// The first IPv6 address of an interface that is not link-local.
fn global_ipv6(link: &Link) -> Option<(IpAddr, u8)> {
    link.addresses
        .iter()
        .copied()
        .find(|(a, _)| matches!(a, IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 != 0xfe80))
}

/// The unhandled entries of the DHCP addresses of a link that a process of
/// `version` can take: `dhcp` for OSPFv2 and `dhcpv6` for OSPFv3. The
/// config does not hold the leased address.
fn dynamic(link: &Link, version: Version, file: &str) -> Vec<(String, SourceSpan)> {
    let key = match version {
        Version::V2 => "dhcp",
        Version::V3 => "dhcpv6",
    };
    link.dynamic
        .iter()
        .filter(|(t, ..)| t == key)
        .map(|(_, w, f, l)| (w.clone(), SourceSpan::new(file, *f, *l)))
        .collect()
}

/// One OSPF interface.
fn interface(
    link: &Link,
    area: AreaId,
    address: Option<(IpAddr, u8)>,
    set: Option<&Settings>,
    passive_default: bool,
    span: SourceSpan,
) -> OspfInterface {
    OspfInterface {
        name: link.name.clone(),
        area,
        address,
        cost: set.and_then(|s| s.cost),
        bandwidth_kbps: set.and_then(|s| s.bandwidth_kbps),
        network: set.and_then(|s| s.network).unwrap_or(link.network),
        passive: set.and_then(|s| s.passive).unwrap_or(passive_default),
        priority: set.and_then(|s| s.priority).unwrap_or(1),
        up: !link.disabled,
        span,
    }
}

fn process(
    version: Version,
    vrf: &str,
    s: &Stanza,
    links: &[Link],
    file: &str,
    walked: Vec<(String, u32, u32)>,
) -> Process {
    let mut r = Reader {
        file,
        version,
        unhandled: walked
            .into_iter()
            .map(|(w, f, l)| (w, SourceSpan::new(file, f, l)))
            .collect(),
    };
    let router_id = s
        .get("parameters")
        .and_then(|p| r.value::<Ipv4Addr>(p, "router-id", "parameters"));
    let reference_bandwidth_mbps = s
        .get("auto-cost")
        .and_then(|a| r.value::<u32>(a, "reference-bandwidth", "auto-cost"));
    let passive_default = match (version, s.get("passive-interface")) {
        (Version::V2, Some(p)) => match p.text() {
            Some("default") => true,
            _ => {
                r.bad(words(&["passive-interface"], p), p);
                false
            }
        },
        _ => false,
    };

    let mut areas: BTreeMap<AreaId, Area> = BTreeMap::new();
    let mut networks: Vec<Network> = Vec::new();
    // The interfaces of `area <a> interface <name>`, with the area, the
    // words of the line and the span of the value.
    let mut listed: BTreeMap<String, (AreaId, String, SourceSpan)> = BTreeMap::new();
    for a in s.get("area").map(Stanza::children).unwrap_or_default() {
        let Some(id) = area_id(&a.key) else {
            r.bad(format!("area {}", a.key), a);
            continue;
        };
        areas.insert(id, r.area(a));
        match version {
            Version::V2 => {
                for (t, x) in a.get("network").map(values).unwrap_or_default() {
                    let words = format!("area {} network {t}", a.key);
                    match Prefix::from_str(t) {
                        Ok(prefix) if prefix.is_ipv4() => networks.push(Network {
                            prefix,
                            area: id,
                            words,
                            span: r.span(x),
                        }),
                        _ => r.bad(words, x),
                    }
                }
            }
            Version::V3 => {
                for (t, x) in a.get("interface").map(values).unwrap_or_default() {
                    let words = format!("area {} interface {t}", a.key);
                    listed
                        .entry(t.to_string())
                        .or_insert((id, words, r.span(x)));
                }
            }
        }
    }

    let mut settings: BTreeMap<String, Settings> = BTreeMap::new();
    for i in s.get("interface").map(Stanza::children).unwrap_or_default() {
        let set = r.settings(i);
        settings.insert(i.key.clone(), set);
    }

    let mut interfaces: Vec<OspfInterface> = Vec::new();
    // The interfaces with an area of their own line: `interface <name>
    // area <a>`, else `area <a> interface <name>` of OSPFv3. Each has the
    // area, the span of the interface, and the words and the span of the
    // line.
    let mut own: BTreeMap<String, (AreaId, SourceSpan, String, SourceSpan)> = BTreeMap::new();
    for (name, set) in &settings {
        if let Some((area, words, line)) = &set.area {
            own.insert(
                name.clone(),
                (*area, set.span.clone(), words.clone(), line.clone()),
            );
        }
    }
    for (name, (area, words, span)) in &listed {
        own.entry(name.clone())
            .or_insert_with(|| (*area, span.clone(), words.clone(), span.clone()));
    }
    for (name, (area, span, words, line)) in &own {
        let Some(link) = links.iter().find(|l| l.name == *name && l.vrf == vrf) else {
            r.unhandled.push((words.clone(), line.clone()));
            continue;
        };
        r.unhandled.extend(dynamic(link, version, file));
        let set = settings.get(name);
        let addresses: Vec<Option<(IpAddr, u8)>> = match version {
            Version::V2 => {
                let v4: Vec<Option<(IpAddr, u8)>> = link
                    .addresses
                    .iter()
                    .filter(|(a, _)| a.is_ipv4())
                    .map(|x| Some(*x))
                    .collect();
                if v4.is_empty() { vec![None] } else { v4 }
            }
            Version::V3 => vec![global_ipv6(link)],
        };
        for address in addresses {
            interfaces.push(interface(
                link,
                *area,
                address,
                set,
                passive_default,
                span.clone(),
            ));
        }
    }
    if version == Version::V2 {
        let mut conflicts: BTreeSet<usize> = BTreeSet::new();
        for l in links.iter().filter(|l| l.vrf == vrf) {
            if own.contains_key(&l.name) {
                continue;
            }
            if !networks.is_empty() && !l.disabled {
                r.unhandled.extend(dynamic(l, version, file));
            }
            for &(ip, len) in &l.addresses {
                let covering: Vec<usize> = networks
                    .iter()
                    .enumerate()
                    .filter(|(_, n)| n.prefix.len() <= len && n.prefix.contains(ip))
                    .map(|(k, _)| k)
                    .collect();
                let Some(&first) = covering.first() else {
                    continue;
                };
                let area = networks[first].area;
                if covering.iter().any(|k| networks[*k].area != area) {
                    conflicts.extend(covering);
                    continue;
                }
                let set = settings.get(&l.name);
                let span = set.map_or_else(|| networks[first].span.clone(), |x| x.span.clone());
                interfaces.push(interface(
                    l,
                    area,
                    Some((ip, len)),
                    set,
                    passive_default,
                    span,
                ));
            }
        }
        for k in conflicts {
            let n = &networks[k];
            r.unhandled.push((n.words.clone(), n.span.clone()));
        }
    }
    interfaces.sort_by(|a, b| (&a.name, a.address).cmp(&(&b.name, b.address)));
    for i in &interfaces {
        areas.entry(i.area).or_insert_with(|| Area {
            kind: AreaType::Normal,
            no_summary: false,
            default_cost: None,
            span: i.span.clone(),
        });
    }

    let redistribute = r.redistribute(s);
    let default_originate = r.default_originate(s);
    let mut unhandled = r.unhandled;
    unhandled.sort_by(|a, b| (a.1.first_line, &a.0).cmp(&(b.1.first_line, &b.0)));
    Process {
        version,
        vrf: vrf.to_string(),
        process: PROCESS.to_string(),
        router_id,
        reference_bandwidth_mbps,
        areas,
        interfaces,
        redistribute,
        default_originate,
        passive_default,
        unhandled,
        span: SourceSpan::new(file, s.first_line, s.last_line),
    }
}

/// The OSPF config of a VyOS router. `file` is the file of the config for
/// the source spans. The address, the VRF, the admin state and the default
/// network type of each interface come from `interfaces`. The bandwidth of
/// an interface is the `bandwidth` line of the process, else `None`.
pub fn read(doc: &Document, file: &str) -> RouterConfig {
    build(&doc.root, file, &mut BTreeSet::new())
}

/// The OSPF config of `root`. Adds the read lines of each process to
/// `read`.
fn build(root: &Stanza, file: &str, read: &mut BTreeSet<u32>) -> RouterConfig {
    let links = links(root);
    let tables = [process_table(Version::V2), process_table(Version::V3)];
    let mut processes_out = Vec::new();
    for (version, vrf, s) in processes(root) {
        let t = &tables[usize::from(version == Version::V3)];
        let mut walked = Vec::new();
        let mut lines = BTreeSet::from([s.first_line]);
        walk(t, s, &mut Vec::new(), &mut lines, &mut walked);
        let p = process(version, &vrf, s, &links, file, walked);
        for (_, span) in &p.unhandled {
            if s.first_line <= span.first_line && span.last_line <= s.last_line {
                lines.retain(|l| !(span.first_line..=span.last_line).contains(l));
            }
        }
        read.extend(lines);
        processes_out.push(p);
    }
    RouterConfig {
        processes: processes_out,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::classify;
    use crate::route_tables::RouteTables;
    use crate::stanza::read_json;

    const FILE: &str = "config.json";

    fn doc(json: &str) -> Document {
        read_json(json.as_bytes()).unwrap()
    }

    fn ip(t: &str) -> Option<(IpAddr, u8)> {
        address(t)
    }

    fn area(t: &str) -> AreaId {
        area_id(t).unwrap()
    }

    fn one(json: &str) -> Process {
        let mut cfg = read(&doc(json), FILE);
        assert_eq!(cfg.processes.len(), 1);
        cfg.processes.remove(0)
    }

    fn iface<'p>(p: &'p Process, name: &str) -> &'p OspfInterface {
        p.interfaces.iter().find(|i| i.name == name).unwrap()
    }

    fn unhandled(p: &Process) -> Vec<&str> {
        p.unhandled.iter().map(|(w, _)| w.as_str()).collect()
    }

    /// The first line of each stanza below `s` that has no entry in `t`
    /// or is not in `read`, with no line below such a stanza.
    fn unread_tops<'s>(
        t: &Table,
        s: &'s Stanza,
        path: &mut Vec<&'s str>,
        read: &BTreeSet<u32>,
        out: &mut BTreeSet<u32>,
    ) {
        for c in s.children() {
            path.push(&c.key);
            let state = t.state(path);
            if state == State::Unhandled || !read.contains(&c.first_line) {
                out.insert(c.first_line);
            } else if state == State::Handled {
                unread_tops(t, c, path, read, out);
            }
            path.pop();
        }
    }

    /// Checks that the lines of each process that are unhandled or not
    /// read are the first lines of the entries of `Process::unhandled` in
    /// the process, and that the unread lines of the vendor are OSPF lines.
    fn check_coverage(json: &str) {
        let d = doc(json);
        let mut read_lines = BTreeSet::new();
        mark(&d.root, &mut read_lines);
        let cfg = super::super::read(&d);
        assert!(read_lines.is_subset(&cfg.read));
        let procs = read(&d, FILE).processes;
        let tables = [process_table(Version::V2), process_table(Version::V3)];
        for ((version, _, s), p) in processes(&d.root).into_iter().zip(&procs) {
            let t = &tables[usize::from(version == Version::V3)];
            let mut tops = BTreeSet::new();
            unread_tops(t, s, &mut Vec::new(), &cfg.read, &mut tops);
            let lines: BTreeSet<u32> = p
                .unhandled
                .iter()
                .filter(|(_, x)| s.first_line <= x.first_line && x.last_line <= s.last_line)
                .map(|(_, x)| x.first_line)
                .collect();
            assert_eq!(tops, lines, "{:?}", p.unhandled);
        }
        for rows in [true, false] {
            let table =
                super::super::table(&RouteTables::uniform(rows, super::super::dynamic_vrfs(&d)));
            let unread = super::super::unread(&d, &table, &cfg.read);
            assert!(unread.iter().all(|p| p.contains("/ospf")), "{unread:?}");
            if procs.iter().all(|p| p.unhandled.is_empty()) {
                assert_eq!(unread, Vec::<String>::new());
            }
        }
    }

    const V2: &str = r#"{
      "interfaces": {
        "ethernet": {
          "eth0": {"address": ["192.0.2.1/24", "2001:db8::1/64"]},
          "eth1": {"address": "198.51.100.1/30", "vif": {"10": {"address": "203.0.113.1/28"}}},
          "eth2": {"address": "203.0.113.129/25", "disable": {}}
        },
        "loopback": {"lo": {"address": "198.51.100.255/32"}},
        "wireguard": {"wg0": {"address": "198.51.100.9/31", "port": "51820"}}
      },
      "protocols": {
        "ospf": {
          "parameters": {"router-id": "198.51.100.255"},
          "auto-cost": {"reference-bandwidth": "10000"},
          "area": {
            "0": {"network": ["192.0.2.0/24", "198.51.100.255/32", "198.51.100.8/31"]},
            "0.0.0.1": {"area-type": {"stub": {"no-summary": {}, "default-cost": "20"}}},
            "2": {"area-type": {"nssa": {}}, "network": "203.0.113.0/24"}
          },
          "interface": {
            "eth0": {"passive": {"disable": {}}, "priority": "10", "bandwidth": "1000"},
            "eth1": {"area": "1", "cost": "30", "network": "point-to-point"}
          },
          "passive-interface": "default",
          "log-adjacency-changes": {"detail": {}},
          "redistribute": {
            "connected": {"metric": "20", "metric-type": "1", "route-map": "RM-CONN"},
            "static": {},
            "kernel": {}
          },
          "default-information": {
            "originate": {"always": {}, "metric": "5", "metric-type": "2", "route-map": "RM-DEF"}
          }
        }
      }
    }"#;

    #[test]
    fn the_process_settings_come_from_the_config() {
        let p = one(V2);
        assert_eq!(p.version, Version::V2);
        assert_eq!(p.vrf, "default");
        assert_eq!(p.process, "");
        assert_eq!(p.router_id, Some(Ipv4Addr::new(198, 51, 100, 255)));
        assert_eq!(p.reference_bandwidth_mbps, Some(10_000));
        assert!(p.passive_default);
        assert_eq!(unhandled(&p), Vec::<&str>::new());
        let d = doc(V2);
        let s = d.root.at(&["protocols", "ospf"]).unwrap();
        assert_eq!(
            (p.span.first_line, p.span.last_line),
            (s.first_line, s.last_line)
        );
        assert_eq!(&*p.span.file, FILE);
    }

    #[test]
    fn the_area_type_comes_from_the_area_lines() {
        let p = one(V2);
        let a0 = &p.areas[&area("0")];
        assert_eq!(
            (a0.kind, a0.no_summary, a0.default_cost),
            (AreaType::Normal, false, None)
        );
        let a1 = &p.areas[&area("0.0.0.1")];
        assert_eq!(
            (a1.kind, a1.no_summary, a1.default_cost),
            (AreaType::Stub, true, Some(20))
        );
        let a2 = &p.areas[&area("0.0.0.2")];
        assert_eq!(
            (a2.kind, a2.no_summary, a2.default_cost),
            (AreaType::Nssa, false, None)
        );
    }

    #[test]
    fn a_network_line_puts_each_covered_interface_in_its_area() {
        let p = one(V2);
        let eth0 = iface(&p, "eth0");
        assert_eq!(eth0.area, area("0"));
        assert_eq!(eth0.address, ip("192.0.2.1/24"));
        let lo = iface(&p, "lo");
        assert_eq!(lo.area, area("0"));
        assert_eq!(lo.network, NetworkType::Loopback);
        let wg = iface(&p, "wg0");
        assert_eq!(wg.network, NetworkType::PointToPoint);
        let eth2 = iface(&p, "eth2");
        assert_eq!(eth2.area, area("2"));
        assert!(!eth2.up);
        assert_eq!(iface(&p, "eth1.10").area, area("2"));
        assert_eq!(p.interfaces.iter().filter(|i| i.name == "eth1").count(), 1);
    }

    #[test]
    fn the_interface_lines_set_the_interface() {
        let p = one(V2);
        let eth0 = iface(&p, "eth0");
        assert!(!eth0.passive);
        assert_eq!(eth0.priority, 10);
        assert_eq!(eth0.bandwidth_kbps, Some(1_000_000));
        assert_eq!(eth0.cost, None);
        assert_eq!(eth0.network, NetworkType::Broadcast);
        let eth1 = iface(&p, "eth1");
        assert_eq!(eth1.area, area("1"));
        assert_eq!(eth1.address, ip("198.51.100.1/30"));
        assert_eq!(eth1.cost, Some(30));
        assert_eq!(eth1.bandwidth_kbps, None);
        assert_eq!(eth1.network, NetworkType::PointToPoint);
        assert!(eth1.passive);
        assert_eq!(eth1.priority, 1);
        assert!(eth1.up);
        let d = doc(V2);
        let s = d
            .root
            .at(&["protocols", "ospf", "interface", "eth1"])
            .unwrap();
        assert_eq!(eth1.span.first_line, s.first_line);
    }

    #[test]
    fn the_redistribute_and_default_lines_are_read() {
        let p = one(V2);
        let r: Vec<_> = p
            .redistribute
            .iter()
            .map(|r| {
                (
                    r.source.clone(),
                    r.metric,
                    r.metric_type,
                    r.route_map.clone(),
                )
            })
            .collect();
        assert_eq!(
            r,
            [
                (
                    Source::Connected,
                    Some(20),
                    Some(1),
                    Some("RM-CONN".to_string())
                ),
                (Source::Other("kernel".to_string()), None, None, None),
                (Source::Static, None, None, None),
            ]
        );
        let d = p.default_originate.unwrap();
        assert!(d.always);
        assert_eq!(
            (d.metric, d.metric_type, d.route_map),
            (Some(5), Some(2), Some("RM-DEF".to_string()))
        );
    }

    #[test]
    fn each_read_line_is_handled() {
        check_coverage(V2);
        check_coverage(V3);
        check_coverage(UNREAD);
        check_coverage(REJECTED);
    }

    const REJECTED: &str = r#"{
      "interfaces": {"ethernet": {"eth0": {"address": "192.0.2.1/24"}}},
      "protocols": {
        "ospf": {
          "parameters": {"router-id": "192.0.2.300"},
          "area": {
            "0": {"network": ["192.0.2.0/24", "2001:db8::/32", "192.0.2.0/33"]},
            "1": {"network": "192.0.0.0/16", "area-type": {"stub": {"default-cost": "x"}}}
          },
          "interface": {
            "eth0": {"network": "point-to-multipoint"},
            "bond0": {"area": "0"}
          },
          "passive-interface": "eth0",
          "redistribute": {"connected": {"metric-type": "3"}}
        }
      }
    }"#;

    #[test]
    fn a_line_that_the_reader_rejects_is_not_read() {
        let p = one(REJECTED);
        assert_eq!(
            unhandled(&p),
            [
                "area 0 network 192.0.2.0/24",
                "area 0 network 2001:db8::/32",
                "area 0 network 192.0.2.0/33",
                "area 1 area-type stub default-cost x",
                "area 1 network 192.0.0.0/16",
                "interface bond0 area 0",
                "interface eth0 network point-to-multipoint",
                "parameters router-id 192.0.2.300",
                "passive-interface eth0",
                "redistribute connected metric-type 3",
            ]
        );
        let d = doc(REJECTED);
        let cfg = super::super::read(&d);
        let table =
            super::super::table(&RouteTables::uniform(true, super::super::dynamic_vrfs(&d)));
        assert_eq!(
            super::super::unread(&d, &table, &cfg.read),
            [
                "protocols/ospf/area/0/network/0",
                "protocols/ospf/area/0/network/1",
                "protocols/ospf/area/0/network/2",
                "protocols/ospf/area/1/area-type/stub/default-cost",
                "protocols/ospf/area/1/network",
                "protocols/ospf/interface/bond0/area",
                "protocols/ospf/interface/eth0/network",
                "protocols/ospf/parameters/router-id",
                "protocols/ospf/passive-interface",
                "protocols/ospf/redistribute/connected/metric-type",
            ]
        );
    }

    #[test]
    fn a_passive_interface_line_with_2_values_is_not_read() {
        let json = r#"{
              "interfaces": {"ethernet": {"eth0": {"address": "192.0.2.1/24"}}},
              "protocols": {"ospf": {
                "area": {"0": {"network": "192.0.2.0/24"}},
                "passive-interface": ["eth0", "eth1"]
              }}
            }"#;
        let p = one(json);
        assert_eq!(unhandled(&p), ["passive-interface eth0 eth1"]);
        assert!(!p.passive_default);
        check_coverage(json);
    }

    const UNREAD: &str = r#"{
      "interfaces": {"ethernet": {"eth0": {"address": "192.0.2.1/24"}}},
      "protocols": {
        "ospf": {
          "area": {"0": {"network": "192.0.2.0/24", "range": {"192.0.2.0/23": {}}}},
          "interface": {"eth0": {"hello-interval": "5", "network": "non-broadcast"}},
          "redistribute": {"table": {"100": {}}},
          "parameters": {"rfc1583-compatibility": {}},
          "log-adjacency-changes": {}
        }
      }
    }"#;

    #[test]
    fn a_line_that_is_not_read_is_unhandled() {
        let p = one(UNREAD);
        assert_eq!(
            unhandled(&p),
            [
                "area 0 range",
                "interface eth0 hello-interval 5",
                "interface eth0 network non-broadcast",
                "parameters rfc1583-compatibility",
                "redistribute table",
            ]
        );
        let d = doc(UNREAD);
        let range = d
            .root
            .at(&["protocols", "ospf", "area", "0", "range"])
            .unwrap();
        assert_eq!(
            (p.unhandled[0].1.first_line, p.unhandled[0].1.last_line),
            (range.first_line, range.last_line)
        );
        let eth0 = iface(&p, "eth0");
        assert_eq!(eth0.network, NetworkType::Broadcast);
        let table =
            super::super::table(&RouteTables::uniform(true, super::super::dynamic_vrfs(&d)));
        let cov = classify(&d, &table);
        let paths: Vec<&str> = cov.unhandled.keys().map(String::as_str).collect();
        assert_eq!(
            paths,
            [
                "protocols/ospf/area/*/range",
                "protocols/ospf/interface/*/hello-interval",
                "protocols/ospf/parameters/rfc1583-compatibility",
                "protocols/ospf/redistribute/table",
            ]
        );
    }

    #[test]
    fn network_lines_of_2_areas_that_cover_one_address_are_unhandled() {
        let p = one(r#"{
              "interfaces": {"ethernet": {"eth0": {"address": "192.0.2.1/24"}}},
              "protocols": {"ospf": {"area": {
                "0": {"network": "192.0.2.0/24"},
                "1": {"network": "192.0.0.0/16"}
              }}}
            }"#);
        assert!(p.interfaces.is_empty());
        assert_eq!(
            unhandled(&p),
            ["area 0 network 192.0.2.0/24", "area 1 network 192.0.0.0/16"]
        );
    }

    #[test]
    fn a_network_line_longer_than_the_address_prefix_does_not_cover_it() {
        let p = one(r#"{
              "interfaces": {"ethernet": {"eth0": {"address": "192.0.2.1/24"}}},
              "protocols": {"ospf": {"area": {"0": {"network": "192.0.2.0/25"}}}}
            }"#);
        assert!(p.interfaces.is_empty());
    }

    #[test]
    fn an_interface_area_line_of_an_interface_that_is_not_in_the_config_is_unhandled() {
        let p = one(r#"{
              "protocols": {"ospf": {"interface": {"bond0": {"area": "0"}}}}
            }"#);
        assert!(p.interfaces.is_empty());
        assert_eq!(unhandled(&p), ["interface bond0 area 0"]);
    }

    #[test]
    fn the_network_type_of_an_interface_kind_is_the_default() {
        let p = one(r#"{
              "interfaces": {
                "dummy": {"dum0": {"address": "192.0.2.1/32"}},
                "tunnel": {
                  "tun0": {"address": "192.0.2.5/30", "encapsulation": "gre", "remote": "203.0.113.9"},
                  "tun1": {"address": "192.0.2.9/30", "encapsulation": "gretap", "remote": "203.0.113.9"}
                },
                "bonding": {"bond0": {"vif": {"20": {"address": "192.0.2.17/29"}}}}
              },
              "protocols": {"ospf": {"area": {"0": {"network": "192.0.2.0/24"}}}}
            }"#);
        assert_eq!(iface(&p, "dum0").network, NetworkType::Broadcast);
        assert_eq!(iface(&p, "tun0").network, NetworkType::PointToPoint);
        assert_eq!(iface(&p, "tun1").network, NetworkType::Broadcast);
        assert_eq!(iface(&p, "bond0.20").network, NetworkType::Broadcast);
        assert!(iface(&p, "bond0.20").up);
    }

    #[test]
    fn a_vrf_process_takes_only_the_interfaces_of_its_vrf() {
        let cfg = read(
            &doc(r#"{
                  "interfaces": {"ethernet": {
                    "eth0": {"address": "192.0.2.1/24"},
                    "eth1": {"address": "192.0.2.65/26", "vrf": "BLUE"}
                  }},
                  "protocols": {"ospf": {"area": {"0": {"network": "192.0.2.0/24"}}}},
                  "vrf": {"name": {"BLUE": {"table": "100", "protocols": {"ospf": {
                    "parameters": {"router-id": "192.0.2.65"},
                    "area": {"0": {"network": "192.0.2.0/24"}}
                  }}}}}
                }"#),
            FILE,
        );
        let names: Vec<(&str, Vec<&str>)> = cfg
            .processes
            .iter()
            .map(|p| {
                (
                    p.vrf.as_str(),
                    p.interfaces.iter().map(|i| i.name.as_str()).collect(),
                )
            })
            .collect();
        assert_eq!(names, [("default", vec!["eth0"]), ("BLUE", vec!["eth1"])]);
        assert_eq!(
            cfg.processes[1].router_id,
            Some(Ipv4Addr::new(192, 0, 2, 65))
        );
    }

    #[test]
    fn a_dhcp_address_that_a_network_line_can_cover_is_unhandled() {
        let p = one(r#"{
              "interfaces": {"ethernet": {
                "eth0": {"address": "192.0.2.1/24"},
                "eth1": {"address": ["dhcp", "dhcpv6"]},
                "eth2": {"vif": {"10": {"address": "dhcp"}}},
                "eth3": {"address": "dhcp", "disable": {}}
              }},
              "protocols": {"ospf": {"area": {"0": {"network": "192.0.2.0/24"}}}}
            }"#);
        let names: Vec<&str> = p.interfaces.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["eth0"]);
        assert_eq!(
            unhandled(&p),
            [
                "interfaces ethernet eth1 address dhcp",
                "interfaces ethernet eth2 vif 10 address dhcp",
            ]
        );
    }

    #[test]
    fn a_dhcp_address_with_no_network_line_is_not_unhandled() {
        let p = one(r#"{
              "interfaces": {"ethernet": {"eth1": {"address": "dhcp"}}},
              "protocols": {"ospf": {"parameters": {"router-id": "192.0.2.1"}}}
            }"#);
        assert_eq!(unhandled(&p), Vec::<&str>::new());
    }

    #[test]
    fn a_named_interface_with_a_dhcp_address_has_no_address_and_is_unhandled() {
        let json = r#"{
              "interfaces": {"ethernet": {"eth1": {"address": ["dhcp", "dhcpv6"]}}},
              "protocols": {
                "ospf": {"interface": {"eth1": {"area": "0"}}},
                "ospfv3": {"interface": {"eth1": {"area": "0"}}}
              }
            }"#;
        let cfg = read(&doc(json), FILE);
        for (p, words) in cfg.processes.iter().zip([
            "interfaces ethernet eth1 address dhcp",
            "interfaces ethernet eth1 address dhcpv6",
        ]) {
            let eth1 = iface(p, "eth1");
            assert_eq!(eth1.area, area("0"));
            assert_eq!(eth1.address, None);
            assert_eq!(unhandled(p), [words]);
        }
        check_coverage(json);
    }

    #[test]
    fn an_openvpn_tun_and_a_ppp_interface_are_point_to_point() {
        let p = one(r#"{
              "interfaces": {
                "openvpn": {
                  "vtun0": {"mode": "site-to-site"},
                  "vtun1": {"device-type": "tun"},
                  "vtun2": {"device-type": "tap"}
                },
                "sstpc": {"sstpc0": {"server": "vpn.example.com"}}
              },
              "protocols": {"ospf": {"interface": {
                "vtun0": {"area": "0"},
                "vtun1": {"area": "0"},
                "vtun2": {"area": "0"},
                "sstpc0": {"area": "0"}
              }}}
            }"#);
        assert_eq!(iface(&p, "vtun0").network, NetworkType::PointToPoint);
        assert_eq!(iface(&p, "vtun1").network, NetworkType::PointToPoint);
        assert_eq!(iface(&p, "vtun2").network, NetworkType::Broadcast);
        assert_eq!(iface(&p, "sstpc0").network, NetworkType::PointToPoint);
    }

    const V3: &str = r#"{
      "interfaces": {"ethernet": {
        "eth0": {"address": ["fe80::1/64", "2001:db8:0:1::1/64", "192.0.2.1/24"]},
        "eth1": {"address": "2001:db8:0:2::1/64"},
        "eth2": {"address": "2001:db8:0:3::1/64"}
      }},
      "protocols": {"ospfv3": {
        "parameters": {"router-id": "192.0.2.1"},
        "area": {
          "0": {},
          "0.0.0.1": {"area-type": {"stub": {"no-summary": {}}}, "interface": "eth2"}
        },
        "interface": {
          "eth0": {"area": "0", "cost": "15", "passive": {}},
          "eth1": {"area": "0.0.0.1", "network": "point-to-point", "priority": "0"}
        },
        "redistribute": {"connected": {"route-map": "RM6"}},
        "default-information": {"originate": {}}
      }}
    }"#;

    #[test]
    fn an_ospfv3_process_is_read() {
        let p = one(V3);
        assert_eq!(p.version, Version::V3);
        assert_eq!(p.router_id, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(unhandled(&p), Vec::<&str>::new());
        let eth0 = iface(&p, "eth0");
        assert_eq!(eth0.area, area("0"));
        assert_eq!(eth0.address, ip("2001:db8:0:1::1/64"));
        assert_eq!(eth0.cost, Some(15));
        assert!(eth0.passive);
        let eth1 = iface(&p, "eth1");
        assert_eq!(eth1.network, NetworkType::PointToPoint);
        assert_eq!(eth1.priority, 0);
        assert!(!eth1.passive);
        let eth2 = iface(&p, "eth2");
        assert_eq!(eth2.area, area("1"));
        assert_eq!(eth2.address, ip("2001:db8:0:3::1/64"));
        let a1 = &p.areas[&area("1")];
        assert_eq!((a1.kind, a1.no_summary), (AreaType::Stub, true));
        assert_eq!(p.redistribute[0].route_map.as_deref(), Some("RM6"));
        assert!(p.default_originate.is_some());
    }

    #[test]
    fn an_ospfv3_area_has_no_default_cost_line() {
        let p = one(
            r#"{"protocols": {"ospfv3": {"area": {"0": {"area-type": {"stub": {"default-cost": "5"}}}}}}}"#,
        );
        assert_eq!(p.areas[&area("0")].default_cost, None);
        assert_eq!(unhandled(&p), ["area 0 area-type stub default-cost 5"]);
    }
}
