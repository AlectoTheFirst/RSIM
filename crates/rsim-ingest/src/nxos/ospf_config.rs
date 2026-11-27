//! The OSPF config of an NX-OS running config: the `router ospf` and
//! `router ospfv3` stanzas with their `vrf` stanzas, and the OSPF lines of
//! the interfaces.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use rsim_core::SourceSpan;
use rsim_routing::ospf::config::{
    Area, DefaultOriginate, NetworkType, OspfInterface, Process, Redistribute, RouterConfig, Source,
};
use rsim_routing::ospf::{AreaId, AreaType, Version};

use super::config::{Config, Interface};
use crate::coverage::{Reach, State, Table};
use crate::route_tables::{RouteTables, VRF};
use crate::stanza::{Document, Stanza};

/// The VRF of a process or an interface with no VRF line.
const DEFAULT_VRF: &str = "default";

/// The handled lines of a process, at the top of the router stanza and in
/// a `vrf` stanza.
const PROCESS_LINES: &[&str] = &[
    "router-id *",
    "auto-cost reference-bandwidth *",
    "auto-cost reference-bandwidth * Mbps",
    "auto-cost reference-bandwidth * Gbps",
    "passive-interface default",
    "area * stub",
    "area * stub no-summary",
    "area * nssa",
    "area * nssa no-summary",
    "area * default-cost *",
];

/// The handled lines of the redistribution: in the process of OSPFv2, and
/// in `address-family ipv6 unicast` of OSPFv3.
const REDISTRIBUTE_LINES: &[&str] = &[
    "redistribute * route-map *",
    "redistribute * * route-map *",
    "default-information originate",
    "default-information originate always",
    "default-information originate route-map *",
    "default-information originate always route-map *",
    "default-metric *",
];

/// The process lines with no effect on the LSAs.
const LOG_LINES: &[&str] = &["log-adjacency-changes", "log-adjacency-changes detail"];

/// The address family stanza of an OSPFv3 process.
const AF: &str = "address-family ipv6 unicast";

/// The handled OSPFv2 lines of an interface.
const INTERFACE_V2: &[&str] = &[
    "ip router ospf * area *",
    "ip router ospf * area * secondaries none",
    "ip ospf cost *",
    "ip ospf network point-to-point",
    "ip ospf network broadcast",
    "ip ospf passive-interface",
    "no ip ospf passive-interface",
    "ip ospf priority *",
    "ip ospf shutdown",
];

/// The handled OSPFv3 lines of an interface.
const INTERFACE_V3: &[&str] = &[
    "ipv6 router ospfv3 * area *",
    "ospfv3 cost *",
    "ospfv3 network point-to-point",
    "ospfv3 network broadcast",
    "ospfv3 passive-interface",
    "no ospfv3 passive-interface",
    "ospfv3 priority *",
    "ospfv3 shutdown",
];

/// The `feature` lines of OSPF.
const FEATURES: &[&str] = &["feature ospf", "feature ospfv3"];

/// Adds the entries of the OSPF lines that [`read`] reads: the router
/// stanzas, their `vrf` and address family stanzas, the process lines, the
/// log lines and the OSPF lines of the interfaces. The other lines of a
/// router stanza keep the state of the routing lines of their VRF. Call it
/// before the entries of the routing processes.
pub(crate) fn push_entries(t: &mut Table, tables: &RouteTables) {
    let node = |t: &mut Table, levels: &[&str]| t.push_levels(levels, State::Handled, Reach::Node);
    for f in FEATURES {
        t.push(f, State::Handled, Reach::Subtree);
    }
    node(t, &["router ospf *"]);
    tables.push_handled_vrfs(t, &["router ospf ..", &format!("vrf {VRF}")]);
    node(t, &["router ospfv3 *"]);
    node(t, &["router ospfv3 *", "vrf *"]);
    let v2: Vec<&str> = PROCESS_LINES
        .iter()
        .chain(REDISTRIBUTE_LINES)
        .copied()
        .collect();
    for scope in [vec!["router ospf *"], vec!["router ospf *", "vrf *"]] {
        push_lines(t, &scope, &v2);
    }
    for scope in [vec!["router ospfv3 *"], vec!["router ospfv3 *", "vrf *"]] {
        push_lines(t, &scope, PROCESS_LINES);
        let mut af = scope.clone();
        af.push(AF);
        node(t, &af);
        push_lines(t, &af, REDISTRIBUTE_LINES);
    }
    for line in INTERFACE_V2.iter().chain(INTERFACE_V3) {
        t.push_levels(&["interface *", *line], State::Handled, Reach::Subtree);
    }
}

/// Adds the handled lines and the log lines below a scope.
fn push_lines(t: &mut Table, scope: &[&str], lines: &[&str]) {
    for (list, state) in [(lines, State::Handled), (LOG_LINES, State::Irrelevant)] {
        for line in list {
            let levels: Vec<&str> = scope.iter().copied().chain([*line]).collect();
            t.push_levels(&levels, state, Reach::Subtree);
        }
    }
}

/// A table of one level for the lines of one scope.
fn scope_table(handled: &[&[&str]]) -> Table {
    let mut t = Table::new(&[]);
    for list in handled {
        for line in *list {
            t.push(line, State::Handled, Reach::Subtree);
        }
    }
    for line in LOG_LINES {
        t.push(line, State::Irrelevant, Reach::Subtree);
    }
    t
}

fn words(s: &str) -> Vec<&str> {
    s.split_whitespace().collect()
}

/// The reader state: the file of the spans, the first line of each stanza
/// that the reader read, and the scope tables.
struct R<'a> {
    file: &'a str,
    read: &'a mut BTreeSet<u32>,
    v2: Table,
    v3: Table,
    v3_af: Table,
    iface_v2: Table,
    iface_v3: Table,
}

impl R<'_> {
    fn lines(&self, first: u32, last: u32) -> SourceSpan {
        let first = first.max(1);
        SourceSpan::new(self.file, first, last.max(first))
    }

    fn span(&self, s: &Stanza) -> SourceSpan {
        self.lines(s.first_line, s.last_line)
    }

    fn mark(&mut self, s: &Stanza) {
        self.read.insert(s.first_line);
    }

    fn unhandled(&self, p: &mut Process, s: &Stanza) {
        p.unhandled.push((super::mask(&s.key), self.span(s)));
    }
}

/// The key of a process: the version, the VRF and the process tag.
type Key = (Version, String, String);

fn process(version: Version, vrf: &str, tag: &str, span: SourceSpan) -> Process {
    Process {
        version,
        vrf: vrf.to_string(),
        process: tag.to_string(),
        router_id: None,
        reference_bandwidth_mbps: None,
        areas: BTreeMap::new(),
        interfaces: Vec::new(),
        redistribute: Vec::new(),
        default_originate: None,
        passive_default: false,
        unhandled: Vec::new(),
        span,
    }
}

/// Reads the OSPF config of a switch: each process of `router ospf` and
/// `router ospfv3` and of their `vrf` stanzas, with the interfaces that
/// join it. The addresses, the VRF and the admin state of an interface come
/// from `cfg`. The bandwidth of an interface is the `bandwidth` line, and
/// `None` with no such line. A line of a router stanza or an OSPF line of
/// a joined interface that the reader does not read goes into the
/// `unhandled` list of its process, masked.
pub fn read(doc: &Document, cfg: &Config, file: &str) -> RouterConfig {
    let mut read = BTreeSet::new();
    parse(doc, &cfg.interfaces, file, &mut read)
}

/// Reads the OSPF config and adds the first line of each stanza that it
/// reads to `read`. The lines that it reads do not depend on `interfaces`.
pub(crate) fn parse(
    doc: &Document,
    interfaces: &[Interface],
    file: &str,
    read: &mut BTreeSet<u32>,
) -> RouterConfig {
    let mut r = R {
        file,
        read,
        v2: scope_table(&[PROCESS_LINES, REDISTRIBUTE_LINES]),
        v3: scope_table(&[PROCESS_LINES]),
        v3_af: scope_table(&[REDISTRIBUTE_LINES]),
        iface_v2: scope_table(&[INTERFACE_V2]),
        iface_v3: scope_table(&[INTERFACE_V3]),
    };
    let mut procs: BTreeMap<Key, Process> = BTreeMap::new();
    let mut routers: BTreeMap<(Version, String), SourceSpan> = BTreeMap::new();
    for s in doc.root.children() {
        let w = words(&s.key);
        let version = match w.as_slice() {
            ["feature", "ospf" | "ospfv3"] => {
                r.mark(s);
                continue;
            }
            ["router", "ospf", _] => Version::V2,
            ["router", "ospfv3", _] => Version::V3,
            _ => continue,
        };
        let tag = w[2];
        r.mark(s);
        routers.insert((version, tag.to_string()), r.span(s));
        let mut top = process(version, DEFAULT_VRF, tag, r.span(s));
        body(&mut r, s, &mut top, true);
        procs.insert((version, DEFAULT_VRF.to_string(), tag.to_string()), top);
        for c in s.children() {
            if let ["vrf", v] = words(&c.key).as_slice() {
                r.mark(c);
                let mut p = process(version, v, tag, r.span(c));
                body(&mut r, c, &mut p, false);
                procs.insert((version, (*v).to_string(), tag.to_string()), p);
            }
        }
    }
    let by_name: BTreeMap<&str, &Interface> =
        interfaces.iter().map(|i| (i.name.as_str(), i)).collect();
    for s in doc.root.children() {
        let ["interface", name] = words(&s.key)[..] else {
            continue;
        };
        let mut common = Common {
            config: by_name.get(name).copied(),
            ..Common::default()
        };
        for c in s.children() {
            if let ["bandwidth", n] = words(&c.key)[..] {
                r.mark(c);
                match n.parse::<u64>() {
                    Ok(kbps) => common.bandwidth = Some(kbps),
                    Err(_) => common.unhandled.push((super::mask(&c.key), r.span(c))),
                }
            }
        }
        for version in [Version::V2, Version::V3] {
            interface(&mut r, s, name, &common, version, &routers, &mut procs);
        }
    }
    RouterConfig {
        processes: procs.into_values().collect(),
    }
}

/// Reads the lines of a router stanza or of its `vrf` stanza into `p`.
/// `top` is true for the router stanza, whose `vrf` stanzas are separate
/// processes.
fn body(r: &mut R, s: &Stanza, p: &mut Process, top: bool) {
    let mut default_metric = None;
    for c in s.children() {
        let w = words(&c.key);
        if top && matches!(w.as_slice(), ["vrf", _]) {
            continue;
        }
        if p.version == Version::V3 && c.key.split_whitespace().eq(AF.split_whitespace()) {
            r.mark(c);
            for a in c.children() {
                line(r, a, p, true, &mut default_metric);
            }
            continue;
        }
        line(r, c, p, false, &mut default_metric);
    }
    if let Some(m) = default_metric {
        for d in &mut p.redistribute {
            if d.metric.is_none() && d.source != Source::Connected {
                d.metric = Some(m);
            }
        }
    }
}

/// Reads one process line. `af` is true for a line of the OSPFv3 address
/// family.
fn line(r: &mut R, c: &Stanza, p: &mut Process, af: bool, default_metric: &mut Option<u32>) {
    let table = match (p.version, af) {
        (Version::V2, _) => &r.v2,
        (Version::V3, false) => &r.v3,
        (Version::V3, true) => &r.v3_af,
    };
    match table.state(&[c.key.as_str()]) {
        State::Irrelevant => {}
        State::Unhandled => r.unhandled(p, c),
        State::Handled => {
            r.mark(c);
            if !apply(p, &words(&c.key), r.span(c), default_metric) {
                r.unhandled(p, c);
            }
        }
    }
}

/// An area ID in its dotted or its decimal form.
fn area_id(text: &str) -> Option<AreaId> {
    text.parse::<Ipv4Addr>()
        .ok()
        .or_else(|| text.parse::<u32>().ok().map(Ipv4Addr::from))
}

fn area_mut(p: &mut Process, id: AreaId, span: SourceSpan) -> &mut Area {
    p.areas.entry(id).or_insert(Area {
        kind: AreaType::Normal,
        no_summary: false,
        default_cost: None,
        span,
    })
}

/// The source of a `redistribute` line.
fn source(word: &str) -> Source {
    match word {
        "direct" => Source::Connected,
        "static" => Source::Static,
        "bgp" => Source::Bgp,
        other => Source::Other(other.to_string()),
    }
}

/// Applies one handled process line. False if a value does not parse.
fn apply(p: &mut Process, w: &[&str], span: SourceSpan, default_metric: &mut Option<u32>) -> bool {
    match w {
        ["router-id", a] => match a.parse() {
            Ok(id) => p.router_id = Some(id),
            Err(_) => return false,
        },
        ["auto-cost", "reference-bandwidth", n, unit @ ..] => {
            let factor = match unit {
                [] | ["Mbps"] => 1,
                ["Gbps"] => 1000,
                _ => return false,
            };
            match n.parse::<u32>().ok().and_then(|n| n.checked_mul(factor)) {
                Some(mbps) => p.reference_bandwidth_mbps = Some(mbps),
                None => return false,
            }
        }
        ["passive-interface", "default"] => p.passive_default = true,
        ["area", a, kind @ ("stub" | "nssa"), rest @ ..] => {
            let Some(id) = area_id(a) else {
                return false;
            };
            let area = area_mut(p, id, span);
            area.kind = if *kind == "stub" {
                AreaType::Stub
            } else {
                AreaType::Nssa
            };
            area.no_summary = rest == ["no-summary"];
        }
        ["area", a, "default-cost", n] => match (area_id(a), n.parse()) {
            (Some(id), Ok(cost)) => area_mut(p, id, span).default_cost = Some(cost),
            _ => return false,
        },
        ["redistribute", src, rest @ ..] => {
            let route_map = match (*src, rest) {
                ("direct" | "static", ["route-map", rm]) => rm,
                ("direct" | "static", _) => return false,
                (_, [_, "route-map", rm]) => rm,
                _ => return false,
            };
            p.redistribute.push(Redistribute {
                source: source(src),
                metric: None,
                metric_type: None,
                route_map: Some((*route_map).to_string()),
                span,
            });
        }
        ["default-information", "originate", rest @ ..] => {
            let (always, rest) = match rest {
                ["always", tail @ ..] => (true, tail),
                _ => (false, rest),
            };
            let route_map = match rest {
                [] => None,
                ["route-map", rm] => Some((*rm).to_string()),
                _ => return false,
            };
            p.default_originate = Some(DefaultOriginate {
                always,
                metric: None,
                metric_type: None,
                route_map,
                span,
            });
        }
        ["default-metric", n] => match n.parse() {
            Ok(m) => *default_metric = Some(m),
            Err(_) => return false,
        },
        _ => return false,
    }
    true
}

/// The network type of an interface with no network line: loopback for a
/// loopback, point-to-point for a tunnel and broadcast for each other
/// interface.
fn default_network(name: &str) -> NetworkType {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("loopback") {
        NetworkType::Loopback
    } else if lower.starts_with("tunnel") {
        NetworkType::PointToPoint
    } else {
        NetworkType::Broadcast
    }
}

/// The admin state of an interface with no `shutdown` or `no shutdown`
/// line: up for a loopback and the management interface, and not known for
/// each other interface.
fn default_admin(name: &str) -> Option<bool> {
    let lower = name.to_ascii_lowercase();
    (lower.starts_with("loopback") || lower.starts_with("mgmt")).then_some(true)
}

/// An address with its prefix length, for example `192.0.2.1/24`.
fn address(text: &str) -> Option<(IpAddr, u8)> {
    let (a, l) = text.split_once('/')?;
    Some((a.parse().ok()?, l.parse().ok()?))
}

/// True for an interface line of a version that the reader does not read
/// and that can change the OSPF config of the interface.
fn ospf_line(version: Version, w: &[&str]) -> bool {
    match version {
        Version::V2 => {
            matches!(
                w,
                ["ip", "ospf", ..] | ["no", "ip", "ospf", ..] | ["ip", "router", "ospf", ..]
            ) || matches!(w, ["ip", "unnumbered", ..] | ["medium", ..])
        }
        Version::V3 => matches!(
            w,
            ["ospfv3", ..] | ["no", "ospfv3", ..] | ["ipv6", "router", "ospfv3", ..]
        ),
    }
}

/// The lines of an interface that both versions read.
#[derive(Default)]
struct Common<'a> {
    config: Option<&'a Interface>,
    /// The `bandwidth` line in kb/s.
    bandwidth: Option<u64>,
    /// The masked `bandwidth` line whose value does not parse.
    unhandled: Vec<(String, SourceSpan)>,
}

/// The settings of the OSPF lines of one interface and one version.
#[derive(Default)]
struct Settings {
    /// The process tag, the area, true if the secondary addresses join, and
    /// the span of the line.
    join: Option<(String, AreaId, bool, SourceSpan)>,
    cost: Option<u32>,
    network: Option<NetworkType>,
    passive: Option<bool>,
    priority: Option<u8>,
    shutdown: bool,
    unhandled: Vec<(String, SourceSpan)>,
}

/// Reads the OSPF lines of one version of an interface and adds the
/// interface to its process. An interface that names no process of a
/// router stanza joins no process.
fn interface(
    r: &mut R,
    s: &Stanza,
    name: &str,
    common: &Common,
    version: Version,
    routers: &BTreeMap<(Version, String), SourceSpan>,
    procs: &mut BTreeMap<Key, Process>,
) {
    let config = common.config;
    let mut l = Settings {
        unhandled: common.unhandled.clone(),
        ..Settings::default()
    };
    for c in s.children() {
        let w = words(&c.key);
        let table = match version {
            Version::V2 => &r.iface_v2,
            Version::V3 => &r.iface_v3,
        };
        if table.state(&[c.key.as_str()]) != State::Handled {
            if ospf_line(version, &w) {
                l.unhandled.push((super::mask(&c.key), r.span(c)));
            }
            continue;
        }
        r.mark(c);
        let span = r.span(c);
        let ok = match w.as_slice() {
            ["ip", "router", "ospf", tag, "area", a, rest @ ..]
            | ["ipv6", "router", "ospfv3", tag, "area", a, rest @ ..] => match area_id(a) {
                Some(id) => {
                    l.join = Some(((*tag).to_string(), id, rest.is_empty(), span.clone()));
                    true
                }
                None => false,
            },
            ["ip", "ospf", "cost", n] | ["ospfv3", "cost", n] => {
                l.cost = n.parse().ok();
                l.cost.is_some()
            }
            ["ip", "ospf", "network", t] | ["ospfv3", "network", t] => {
                l.network = Some(if *t == "broadcast" {
                    NetworkType::Broadcast
                } else {
                    NetworkType::PointToPoint
                });
                true
            }
            ["ip", "ospf", "passive-interface"] | ["ospfv3", "passive-interface"] => {
                l.passive = Some(true);
                true
            }
            ["no", "ip", "ospf", "passive-interface"] | ["no", "ospfv3", "passive-interface"] => {
                l.passive = Some(false);
                true
            }
            ["ip", "ospf", "priority", n] | ["ospfv3", "priority", n] => {
                l.priority = n.parse().ok();
                l.priority.is_some()
            }
            ["ip", "ospf", "shutdown"] | ["ospfv3", "shutdown"] => {
                l.shutdown = true;
                true
            }
            _ => false,
        };
        if !ok {
            l.unhandled.push((super::mask(&c.key), span));
        }
    }
    let Some((tag, area, secondaries, join_span)) = l.join else {
        return;
    };
    let vrf = config
        .and_then(|i| i.vrf.clone())
        .unwrap_or_else(|| DEFAULT_VRF.to_string());
    let key = (version, vrf.clone(), tag.clone());
    if !procs.contains_key(&key) {
        let Some(span) = routers.get(&(version, tag.clone())) else {
            return;
        };
        procs.insert(key.clone(), process(version, &vrf, &tag, span.clone()));
    }
    let Some(p) = procs.get_mut(&key) else {
        return;
    };
    p.unhandled.extend(l.unhandled);
    let mut addr = None;
    if let Some(i) = config {
        match version {
            Version::V2 => {
                for a in &i.addresses {
                    if !a.secondary && addr.is_none() {
                        addr = address(&a.prefix);
                    } else if a.secondary && secondaries {
                        let span = r.lines(a.lines.first, a.lines.last);
                        p.unhandled
                            .push((format!("ip address {} secondary", a.prefix), span));
                    }
                }
            }
            Version::V3 => {
                for (a, lines) in &i.ipv6 {
                    if addr.is_none() {
                        addr = address(a);
                    } else {
                        let span = r.lines(lines.first, lines.last);
                        p.unhandled.push((format!("ipv6 address {a}"), span));
                    }
                }
            }
        }
    }
    let admin = config
        .and_then(|i| i.admin_up)
        .or_else(|| default_admin(name));
    if admin.is_none() {
        p.unhandled.push((
            format!("interface {name} with no shutdown line, admin state not known"),
            r.span(s),
        ));
    }
    p.areas.entry(area).or_insert(Area {
        kind: AreaType::Normal,
        no_summary: false,
        default_cost: None,
        span: join_span,
    });
    let passive = l.passive.unwrap_or(p.passive_default);
    p.interfaces.push(OspfInterface {
        name: name.to_string(),
        area,
        address: addr,
        cost: l.cost,
        bandwidth_kbps: common.bandwidth,
        network: l.network.unwrap_or_else(|| default_network(name)),
        passive,
        priority: l.priority.unwrap_or(1),
        up: admin.unwrap_or(true) && !l.shutdown,
        span: r.span(s),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stanza::read_indented;

    fn text(lines: &[&str]) -> String {
        lines.join("\n")
    }

    /// The number of the first line that starts with `line` after its
    /// indentation, from 1.
    fn line_of(text: &str, line: &str) -> u32 {
        let i = text
            .lines()
            .position(|l| l.trim_start().starts_with(line))
            .unwrap();
        u32::try_from(i).unwrap() + 1
    }

    fn span(text: &str, first: &str, last: &str) -> SourceSpan {
        SourceSpan::new("sw1", line_of(text, first), line_of(text, last))
    }

    fn ospf(text: &str) -> RouterConfig {
        let doc = read_indented(text);
        let tables = RouteTables::uniform(false, super::super::dynamic_vrfs(&doc));
        let cfg = super::super::read(&doc, &super::super::table(&tables));
        read(&doc, &cfg, "sw1")
    }

    fn interface<'a>(p: &'a Process, name: &str) -> &'a OspfInterface {
        p.interfaces.iter().find(|i| i.name == name).unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// The OSPF lines of the router stanzas and of the interfaces are read
    /// exactly where the table of the vendor makes them handled, with no
    /// route rows, with rows in each VRF and with rows in the VRF `RED`.
    fn read_is_handled(text: &str) {
        let doc = read_indented(text);
        let dynamic = super::super::dynamic_vrfs(&doc);
        for tables in [
            RouteTables::uniform(false, dynamic.clone()),
            RouteTables::uniform(true, dynamic.clone()),
            RouteTables::new(["RED".to_string()], dynamic),
        ] {
            let table = super::super::table(&tables);
            let cfg = super::super::read(&doc, &table);
            assert_eq!(
                super::super::unread(&doc, &table, &cfg.read),
                Vec::<String>::new()
            );
            let mut path = Vec::new();
            for s in doc.root.children() {
                walk(s, &table, &cfg.read, &mut path, false);
            }
        }
    }

    fn walk<'a>(
        s: &'a Stanza,
        table: &Table,
        read: &BTreeSet<u32>,
        path: &mut Vec<&'a str>,
        router: bool,
    ) {
        path.push(&s.key);
        let w = words(&s.key);
        let top = path.len() == 1
            && matches!(
                w.as_slice(),
                ["router", "ospf" | "ospfv3", ..] | ["feature", "ospf" | "ospfv3"]
            );
        let option = path.len() == 2
            && path[0].starts_with("interface ")
            && (ospf_line(Version::V2, &w)
                || ospf_line(Version::V3, &w)
                || w.first() == Some(&"bandwidth"));
        if router || top || option {
            assert_eq!(
                read.contains(&s.first_line),
                table.state(path) == State::Handled,
                "{path:?}"
            );
        }
        for c in s.children() {
            walk(c, table, read, path, router || top);
        }
        path.pop();
    }

    fn process_lines() -> String {
        text(&[
            "feature ospf",
            "interface loopback0",
            "  ip address 192.0.2.1/32",
            "  ip router ospf UNDERLAY area 0.0.0.0",
            "interface Ethernet1/1",
            "  no switchport",
            "  bandwidth 10000000",
            "  ip address 198.51.100.1/30",
            "  ip ospf cost 20",
            "  ip ospf network point-to-point",
            "  ip ospf priority 0",
            "  ip router ospf UNDERLAY area 0.0.0.1",
            "  no shutdown",
            "interface Vlan10",
            "  no shutdown",
            "  ip address 203.0.113.1/25",
            "  ip router ospf UNDERLAY area 10",
            "  no ip ospf passive-interface",
            "interface Vlan20",
            "  no shutdown",
            "  ip address 203.0.113.129/25",
            "  ip router ospf UNDERLAY area 0.0.0.0",
            "interface Tunnel1",
            "  no shutdown",
            "  ip address 192.0.2.9/30",
            "  ip ospf shutdown",
            "  ip router ospf UNDERLAY area 0.0.0.0",
            "interface Ethernet1/9",
            "  no switchport",
            "  bandwidth 1000000",
            "  ip address 198.51.100.9/30",
            "  no shutdown",
            "router ospf UNDERLAY",
            "  router-id 192.0.2.1",
            "  auto-cost reference-bandwidth 100 Gbps",
            "  passive-interface default",
            "  log-adjacency-changes detail",
            "  area 0.0.0.1 stub no-summary",
            "  area 0.0.0.1 default-cost 15",
            "  area 0.0.0.2 nssa",
            "  area 0.0.0.3 nssa no-summary",
            "  area 0.0.0.4 stub",
            "  default-metric 50",
            "  redistribute direct route-map CONNECTED",
            "  redistribute static route-map STATIC",
            "  redistribute bgp 64500 route-map FROM-BGP",
            "  default-information originate always route-map DEFAULT",
        ])
    }

    #[test]
    fn the_process_lines_give_the_process() {
        let t = process_lines();
        let c = ospf(&t);
        assert_eq!(c.processes.len(), 1);
        let p = &c.processes[0];
        assert_eq!(
            (p.version, p.vrf.as_str(), p.process.as_str()),
            (Version::V2, "default", "UNDERLAY")
        );
        assert_eq!(p.span, span(&t, "router ospf", "default-information"));
        assert_eq!(p.router_id, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(p.reference_bandwidth_mbps, Some(100_000));
        assert!(p.passive_default);
        assert_eq!(p.unhandled, Vec::new());
        let areas: Vec<(AreaId, AreaType, bool, Option<u32>)> = p
            .areas
            .iter()
            .map(|(id, a)| (*id, a.kind, a.no_summary, a.default_cost))
            .collect();
        assert_eq!(
            areas,
            [
                (Ipv4Addr::new(0, 0, 0, 0), AreaType::Normal, false, None),
                (Ipv4Addr::new(0, 0, 0, 1), AreaType::Stub, true, Some(15)),
                (Ipv4Addr::new(0, 0, 0, 2), AreaType::Nssa, false, None),
                (Ipv4Addr::new(0, 0, 0, 3), AreaType::Nssa, true, None),
                (Ipv4Addr::new(0, 0, 0, 4), AreaType::Stub, false, None),
                (Ipv4Addr::new(0, 0, 0, 10), AreaType::Normal, false, None),
            ]
        );
        assert_eq!(
            p.areas[&Ipv4Addr::new(0, 0, 0, 1)].span,
            span(&t, "area 0.0.0.1 stub", "area 0.0.0.1 stub")
        );
        let redistribute: Vec<(Source, Option<u32>, Option<&str>)> = p
            .redistribute
            .iter()
            .map(|r| (r.source.clone(), r.metric, r.route_map.as_deref()))
            .collect();
        assert_eq!(
            redistribute,
            [
                (Source::Connected, None, Some("CONNECTED")),
                (Source::Static, Some(50), Some("STATIC")),
                (Source::Bgp, Some(50), Some("FROM-BGP")),
            ]
        );
        let d = p.default_originate.as_ref().unwrap();
        assert!(d.always);
        assert_eq!(d.route_map.as_deref(), Some("DEFAULT"));
        assert_eq!(
            d.span,
            span(&t, "default-information", "default-information")
        );
    }

    #[test]
    fn the_interface_lines_give_the_interfaces() {
        let t = process_lines();
        let c = ospf(&t);
        let p = &c.processes[0];
        let names: Vec<&str> = p.interfaces.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(
            names,
            ["loopback0", "Ethernet1/1", "Vlan10", "Vlan20", "Tunnel1"]
        );
        let lo = interface(p, "loopback0");
        assert_eq!(lo.network, NetworkType::Loopback);
        assert_eq!(lo.address, Some((ip("192.0.2.1"), 32)));
        assert_eq!(lo.area, Ipv4Addr::UNSPECIFIED);
        assert!(lo.passive && lo.up);
        assert_eq!((lo.cost, lo.priority, lo.bandwidth_kbps), (None, 1, None));
        assert_eq!(lo.span, span(&t, "interface loopback0", "ip router ospf"));
        let eth = interface(p, "Ethernet1/1");
        assert_eq!(eth.network, NetworkType::PointToPoint);
        assert_eq!(eth.area, Ipv4Addr::new(0, 0, 0, 1));
        assert_eq!(eth.cost, Some(20));
        assert_eq!(eth.priority, 0);
        assert_eq!(eth.bandwidth_kbps, Some(10_000_000));
        assert_eq!(eth.address, Some((ip("198.51.100.1"), 30)));
        assert!(eth.passive && eth.up);
        let v10 = interface(p, "Vlan10");
        assert_eq!(v10.network, NetworkType::Broadcast);
        assert_eq!(v10.area, Ipv4Addr::new(0, 0, 0, 10));
        assert!(!v10.passive);
        let v20 = interface(p, "Vlan20");
        assert!(v20.passive);
        let tunnel = interface(p, "Tunnel1");
        assert_eq!(tunnel.network, NetworkType::PointToPoint);
        assert!(!tunnel.up);
    }

    #[test]
    fn each_read_line_of_the_process_lines_is_handled() {
        read_is_handled(&process_lines());
    }

    #[test]
    fn an_interface_line_makes_one_interface_passive() {
        let t = text(&[
            "interface Ethernet1/1",
            "  no switchport",
            "  ip address 198.51.100.1/30",
            "  ip ospf passive-interface",
            "  ip ospf network broadcast",
            "  ip router ospf 1 area 0",
            "  no shutdown",
            "interface Ethernet1/2",
            "  no switchport",
            "  ip address 198.51.100.5/30",
            "  ip router ospf 1 area 0",
            "  shutdown",
            "router ospf 1",
        ]);
        let c = ospf(&t);
        let p = &c.processes[0];
        assert!(!p.passive_default);
        let e1 = interface(p, "Ethernet1/1");
        assert!(e1.passive && e1.up);
        assert_eq!(e1.network, NetworkType::Broadcast);
        let e2 = interface(p, "Ethernet1/2");
        assert!(!e2.passive && !e2.up);
        assert_eq!(p.unhandled, Vec::new());
        read_is_handled(&t);
    }

    fn vrf_lines() -> String {
        text(&[
            "vrf context RED",
            "interface Ethernet1/2",
            "  no switchport",
            "  vrf member RED",
            "  ip address 198.51.100.5/30",
            "  ip router ospf 1 area 0.0.0.0",
            "  no shutdown",
            "interface Ethernet1/3",
            "  no switchport",
            "  vrf member BLUE",
            "  ip address 198.51.100.9/30",
            "  ip router ospf 1 area 0.0.0.0",
            "  no shutdown",
            "interface Ethernet1/4",
            "  no switchport",
            "  ip address 198.51.100.13/30",
            "  ip router ospf 9 area 0.0.0.0",
            "  no shutdown",
            "router ospf 1",
            "  router-id 192.0.2.1",
            "  vrf RED",
            "    router-id 192.0.2.2",
            "    area 0.0.0.5 stub",
            "    passive-interface default",
            "    redistribute static route-map RED-STATIC",
            "    log-adjacency-changes",
        ])
    }

    #[test]
    fn a_vrf_stanza_and_a_vrf_member_give_a_process_of_the_vrf() {
        let t = vrf_lines();
        let c = ospf(&t);
        let keys: Vec<(&str, &str)> = c
            .processes
            .iter()
            .map(|p| (p.vrf.as_str(), p.process.as_str()))
            .collect();
        assert_eq!(keys, [("BLUE", "1"), ("RED", "1"), ("default", "1")]);
        let blue = &c.processes[0];
        assert_eq!(
            blue.span,
            span(&t, "router ospf 1", "log-adjacency-changes")
        );
        assert_eq!(blue.router_id, None);
        assert_eq!(blue.interfaces.len(), 1);
        assert_eq!(blue.interfaces[0].name, "Ethernet1/3");
        let red = &c.processes[1];
        assert_eq!(red.span, span(&t, "vrf RED", "log-adjacency-changes"));
        assert_eq!(red.router_id, Some(Ipv4Addr::new(192, 0, 2, 2)));
        assert_eq!(red.areas[&Ipv4Addr::new(0, 0, 0, 5)].kind, AreaType::Stub);
        assert_eq!(red.redistribute.len(), 1);
        assert_eq!(red.interfaces.len(), 1);
        assert_eq!(red.interfaces[0].name, "Ethernet1/2");
        assert!(red.interfaces[0].passive);
        assert_eq!(red.unhandled, Vec::new());
        let default = &c.processes[2];
        assert_eq!(default.router_id, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!default.passive_default);
        assert!(default.interfaces.is_empty());
        assert!(default.redistribute.is_empty());
        read_is_handled(&t);
    }

    fn unread_lines() -> String {
        text(&[
            "interface Ethernet1/1",
            "  no switchport",
            "  ip address 198.51.100.1/30",
            "  ip address 198.51.100.65/26 secondary",
            "  ip router ospf 1 area 0.0.0.0",
            "  ip ospf hello-interval 5",
            "  ip ospf authentication-key 3 FAKEOSPFKEY",
            "  no shutdown",
            "interface Ethernet1/5",
            "  no switchport",
            "  ip address 203.0.113.1/30",
            "  ip ospf cost high",
            "  ip router ospf 1 area 0.0.0.0",
            "router ospf 1",
            "  router-id 192.0.2.1",
            "  maximum-paths 4",
            "  area 0.0.0.1 range 192.0.2.0/24",
            "  timers throttle spf 10 100 5000",
            "  log-adjacency-changes",
        ])
    }

    #[test]
    fn a_line_that_the_reader_does_not_read_is_unhandled() {
        let t = unread_lines();
        let c = ospf(&t);
        let p = &c.processes[0];
        let one = |l: &str| span(&t, l, l);
        let m = super::super::mask;
        assert_eq!(
            p.unhandled[..7],
            [
                (m("maximum-paths 4"), one("maximum-paths")),
                (
                    m("area 0.0.0.1 range 192.0.2.0/24"),
                    one("area 0.0.0.1 range")
                ),
                (m("timers throttle spf 10 100 5000"), one("timers")),
                (m("ip ospf hello-interval 5"), one("ip ospf hello")),
                (
                    m("ip ospf authentication-key 3 FAKEOSPFKEY"),
                    one("ip ospf authentication-key")
                ),
                (
                    "ip address 198.51.100.65/26 secondary".to_string(),
                    one("ip address 198.51.100.65/26")
                ),
                (m("ip ospf cost high"), one("ip ospf cost high")),
            ]
        );
        assert_eq!(p.unhandled.len(), 8);
        assert!(p.unhandled.iter().all(|(l, _)| !l.contains("FAKEOSPFKEY")));
        let last = p.unhandled.last().unwrap();
        assert!(last.0.starts_with("interface Ethernet1/5"));
        assert_eq!(
            last.1,
            SourceSpan::new(
                "sw1",
                line_of(&t, "interface Ethernet1/5"),
                line_of(&t, "router ospf 1") - 1
            )
        );
        assert_eq!(interface(p, "Ethernet1/5").cost, None);
        read_is_handled(&t);
    }

    #[test]
    fn the_unread_process_lines_keep_the_state_of_the_routing_lines() {
        let t = unread_lines();
        let doc = read_indented(&t);
        let dynamic = super::super::dynamic_vrfs(&doc);
        let bare = super::super::table(&RouteTables::uniform(false, dynamic.clone()));
        let rows = super::super::table(&RouteTables::uniform(true, dynamic));
        for line in ["maximum-paths 4", "timers throttle spf 10 100 5000"] {
            assert_eq!(bare.state(&["router ospf 1", line]), State::Unhandled);
            assert_eq!(rows.state(&["router ospf 1", line]), State::Irrelevant);
        }
        for table in [&bare, &rows] {
            assert_eq!(
                table.state(&["router ospf 1", "log-adjacency-changes"]),
                State::Irrelevant
            );
            assert_eq!(
                table.state(&["router ospf 1", "router-id 192.0.2.1"]),
                State::Handled
            );
            assert_eq!(
                table.state(&["interface Ethernet1/1", "ip ospf cost 5"]),
                State::Handled
            );
        }
    }

    fn v3_lines() -> String {
        text(&[
            "feature ospfv3",
            "interface Ethernet1/1",
            "  no switchport",
            "  ipv6 address 2001:db8::1/64",
            "  ipv6 address 2001:db8:1::1/64",
            "  ipv6 router ospfv3 CORE area 0.0.0.0",
            "  ospfv3 cost 7",
            "  ospfv3 network point-to-point",
            "  ospfv3 hello-interval 3",
            "  no shutdown",
            "interface loopback0",
            "  ipv6 address 2001:db8:ff::1/128",
            "  ipv6 router ospfv3 CORE area 0.0.0.1",
            "  no ospfv3 passive-interface",
            "router ospfv3 CORE",
            "  router-id 192.0.2.1",
            "  area 0.0.0.1 nssa no-summary",
            "  passive-interface default",
            "  auto-cost reference-bandwidth 400000",
            "  address-family ipv6 unicast",
            "    redistribute direct route-map V6-CONNECTED",
            "    default-information originate",
            "    maximum-paths 8",
        ])
    }

    #[test]
    fn the_ospfv3_lines_give_an_ospfv3_process() {
        let t = v3_lines();
        let c = ospf(&t);
        assert_eq!(c.processes.len(), 1);
        let p = &c.processes[0];
        assert_eq!(
            (p.version, p.vrf.as_str(), p.process.as_str()),
            (Version::V3, "default", "CORE")
        );
        assert_eq!(p.router_id, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(p.reference_bandwidth_mbps, Some(400_000));
        assert!(p.passive_default);
        let nssa = &p.areas[&Ipv4Addr::new(0, 0, 0, 1)];
        assert_eq!((nssa.kind, nssa.no_summary), (AreaType::Nssa, true));
        assert_eq!(p.redistribute.len(), 1);
        assert_eq!(p.redistribute[0].source, Source::Connected);
        assert_eq!(p.redistribute[0].route_map.as_deref(), Some("V6-CONNECTED"));
        let d = p.default_originate.as_ref().unwrap();
        assert!(!d.always && d.route_map.is_none());
        let one = |l: &str| span(&t, l, l);
        assert_eq!(
            p.unhandled,
            [
                ("maximum-paths 8".to_string(), one("maximum-paths")),
                ("ospfv3 hello-interval 3".to_string(), one("ospfv3 hello")),
                (
                    "ipv6 address 2001:db8:1::1/64".to_string(),
                    one("ipv6 address 2001:db8:1::1/64")
                ),
            ]
        );
        let eth = interface(p, "Ethernet1/1");
        assert_eq!(eth.address, Some((ip("2001:db8::1"), 64)));
        assert_eq!(eth.cost, Some(7));
        assert_eq!(eth.network, NetworkType::PointToPoint);
        assert!(eth.passive && eth.up);
        let lo = interface(p, "loopback0");
        assert_eq!(lo.network, NetworkType::Loopback);
        assert_eq!(lo.area, Ipv4Addr::new(0, 0, 0, 1));
        assert!(!lo.passive);
        read_is_handled(&t);
    }

    #[test]
    fn an_ospfv2_join_does_not_add_the_interface_to_an_ospfv3_process() {
        let t = text(&[
            "interface Ethernet1/1",
            "  no switchport",
            "  ip address 198.51.100.1/30",
            "  ipv6 address 2001:db8::1/64",
            "  ip router ospf CORE area 0.0.0.0",
            "  no shutdown",
            "router ospf CORE",
            "router ospfv3 CORE",
        ]);
        let c = ospf(&t);
        let joined: Vec<(Version, usize)> = c
            .processes
            .iter()
            .map(|p| (p.version, p.interfaces.len()))
            .collect();
        assert_eq!(joined, [(Version::V2, 1), (Version::V3, 0)]);
    }
}
