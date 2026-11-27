//! The OSPF config of an IOS-XE router: the `router ospf`, `router ospfv3`
//! and `ipv6 router ospf` stanzas and the OSPF lines of the interfaces, as
//! one [`RouterConfig`].
//!
//! - `router ospf <n> [vrf <v>]` gives one OSPFv2 process. `ipv6 router
//!   ospf <n>` gives one OSPFv3 process of the default VRF. `router ospfv3
//!   <n>` gives one OSPFv3 process for each `address-family ipv6 unicast
//!   [vrf <v>]` stanza, with the lines of the process and of the address
//!   family, or one process of the default VRF if it has no such stanza.
//! - An interface joins the process of its `ip ospf <n> area <a>` line, or
//!   of its `ospfv3 <n> ipv6 area <a>` or `ipv6 ospf <n> area <a>` line, in
//!   the VRF of the interface. An interface with no such line joins an
//!   OSPFv2 process of its VRF whose `network` statement covers its primary
//!   address. The first statement of the process that covers the address
//!   gives the area. If statements of 2 or more processes cover the
//!   address, the interface joins no process, and each of the processes
//!   gets the interface as an unhandled line.
//! - A line of a process that the reader does not read goes to the
//!   unhandled lines of the process, through the mask of the table, except
//!   the lines of [`NO_EFFECT`]. An OSPF line of an interface that the
//!   reader does not read goes to the unhandled lines of the process of the
//!   interface in the same version.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use rsim_core::SourceSpan;
use rsim_routing::ospf::config::{
    Area, DefaultOriginate, NetworkType, OspfInterface, Process, Redistribute, RouterConfig, Source,
};
use rsim_routing::ospf::{AreaId, AreaType, Version};

use super::config::{Config, Interface};
use super::profile::{DEFAULT_VRF, UP_WITHOUT_SHUTDOWN};
use crate::coverage::{Reach, State, Table};
use crate::route_tables::{RouteTables, VRF};
use crate::stanza::{Document, Stanza};

const V2: &str = "router ospf ..";
const V3: &str = "router ospfv3 *";
const V3_LEGACY: &str = "ipv6 router ospf *";
const AF: &str = "address-family ipv6 unicast ..";

/// The lines of a process that the reader reads, for each version.
const PROCESS_LINES: &[&str] = &[
    "router-id *",
    "auto-cost reference-bandwidth *",
    "area * stub",
    "area * stub no-summary",
    "area * nssa",
    "area * nssa no-summary",
    "area * default-cost *",
    "passive-interface default",
    "passive-interface *",
    "no passive-interface *",
    "redistribute ..",
    "default-information originate ..",
];

/// The lines of a process with no effect on the LSAs and the routes in the
/// steady state.
const NO_EFFECT: &[&str] = &[
    "log-adjacency-changes ..",
    "no log-adjacency-changes",
    "timers ..",
    "nsf ..",
    "graceful-restart ..",
    "exit-address-family",
];

/// The OSPF lines of an interface that the reader reads.
const INTERFACE_LINES: &[&str] = &[
    "ip ospf * area *",
    "ip ospf cost *",
    "ip ospf network point-to-point",
    "ip ospf network broadcast",
    "ip ospf priority *",
    "ospfv3 * ipv6 area *",
    "ospfv3 cost *",
    "ospfv3 network point-to-point",
    "ospfv3 network broadcast",
    "ospfv3 priority *",
    "ipv6 ospf * area *",
    "ipv6 ospf cost *",
    "ipv6 ospf network point-to-point",
    "ipv6 ospf network broadcast",
    "ipv6 ospf priority *",
];

/// The interface kinds, by the lower-case letters at the start of the
/// name, with the default network type of each.
const KINDS: &[(&str, NetworkType)] = &[
    ("loopback", NetworkType::Loopback),
    ("tunnel", NetworkType::PointToPoint),
    ("ethernet", NetworkType::Broadcast),
    ("fastethernet", NetworkType::Broadcast),
    ("gigabitethernet", NetworkType::Broadcast),
    ("twogigabitethernet", NetworkType::Broadcast),
    ("fivegigabitethernet", NetworkType::Broadcast),
    ("tengigabitethernet", NetworkType::Broadcast),
    ("twentyfivegige", NetworkType::Broadcast),
    ("fortygigabitethernet", NetworkType::Broadcast),
    ("hundredgige", NetworkType::Broadcast),
    ("appgigabitethernet", NetworkType::Broadcast),
    ("port-channel", NetworkType::Broadcast),
    ("vlan", NetworkType::Broadcast),
    ("bdi", NetworkType::Broadcast),
];

/// Adds the entries of the OSPF lines that the reader reads, as handled,
/// and of the lines of [`NO_EFFECT`], as known-irrelevant. The other lines
/// of an OSPF stanza keep the state of the routing lines of their VRF, and
/// the other OSPF lines of an interface the state of the routing lines of
/// an interface. Call it before the entries of the routing processes.
pub fn push_entries(t: &mut Table, tables: &RouteTables) {
    use Reach::{Node, Subtree};
    use State::{Handled, Irrelevant};
    t.push_levels(&["router ospf *"], Handled, Node);
    tables.push_handled_vrfs(t, &[&format!("router ospf * vrf {VRF}")]);
    t.push_levels(&[V3], Handled, Node);
    t.push_levels(&[V3, "address-family ipv6 unicast"], Handled, Node);
    tables.push_handled_vrfs(
        t,
        &[
            "router ospfv3 ..",
            &format!("address-family ipv6 unicast vrf {VRF}"),
        ],
    );
    t.push_levels(&[V3_LEGACY], Handled, Node);
    let parents: [&[&str]; 4] = [&[V2], &[V3], &[V3, AF], &[V3_LEGACY]];
    for parent in parents {
        let mut lines: Vec<&str> = PROCESS_LINES.to_vec();
        if parent[0] == V2 {
            lines.push("network * * area *");
        }
        for (list, state) in [(&lines[..], Handled), (NO_EFFECT, Irrelevant)] {
            for line in list {
                let mut levels = parent.to_vec();
                levels.push(*line);
                t.push_levels(&levels, state, Subtree);
            }
        }
    }
    for line in INTERFACE_LINES {
        t.push_levels(&["interface *", *line], Handled, Subtree);
    }
    let default = tables.routing(DEFAULT_VRF);
    t.push_levels(&["router ospfv3 .."], default, Subtree);
    tables.push_vrfs(
        t,
        &[
            "router ospfv3 ..",
            &format!("address-family ipv6 unicast vrf {VRF} .."),
        ],
    );
    t.push_levels(&[V3_LEGACY, ".."], default, Subtree);
    let shared = tables.shared();
    for option in ["ipv6 ospf ..", "ospfv3 .."] {
        t.push_levels(&["interface *", option], shared, Subtree);
    }
}

/// The OSPF config of a router. `file` is the name of the running config
/// in the spans, and `table` is the table of [`super::table`].
pub fn router_config(file: &str, doc: &Document, cfg: &Config, table: &Table) -> RouterConfig {
    run(file, doc, cfg, table).0
}

/// The first lines of the lines of the OSPF stanzas that the reader reads.
/// The reader of the interfaces marks the OSPF lines of an interface.
pub(super) fn read_lines(doc: &Document, cfg: &Config, table: &Table) -> BTreeSet<u32> {
    run("", doc, cfg, table).1
}

fn words(s: &str) -> Vec<&str> {
    s.split_whitespace().collect()
}

fn span(file: &str, s: &Stanza) -> SourceSpan {
    SourceSpan::new(file, s.first_line, s.last_line.max(s.first_line))
}

/// An area ID as a decimal number or in the dotted form.
fn area_id(w: &str) -> Option<AreaId> {
    w.parse::<Ipv4Addr>()
        .ok()
        .or_else(|| w.parse::<u32>().ok().map(Ipv4Addr::from))
}

/// A `network <address> <wildcard> area <area>` statement.
struct Network {
    address: u32,
    wildcard: u32,
    area: AreaId,
    span: SourceSpan,
}

impl Network {
    fn covers(&self, a: Ipv4Addr) -> bool {
        (u32::from(a) ^ self.address) & !self.wildcard == 0
    }
}

/// A process while the reader reads it.
struct Building {
    process: Process,
    networks: Vec<Network>,
    passive: BTreeSet<String>,
    active: BTreeSet<String>,
}

impl Building {
    fn new(version: Version, vrf: &str, process: &str, span: SourceSpan) -> Building {
        Building {
            process: Process {
                version,
                vrf: vrf.to_string(),
                process: process.to_string(),
                router_id: None,
                reference_bandwidth_mbps: None,
                areas: BTreeMap::new(),
                interfaces: Vec::new(),
                redistribute: Vec::new(),
                default_originate: None,
                passive_default: false,
                unhandled: Vec::new(),
                span,
            },
            networks: Vec::new(),
            passive: BTreeSet::new(),
            active: BTreeSet::new(),
        }
    }

    /// Adds an area of an interface or a `network` statement with the
    /// settings of a normal area if the process has no `area` line for it.
    fn touch_area(&mut self, area: AreaId, span: &SourceSpan) {
        self.process.areas.entry(area).or_insert_with(|| Area {
            kind: AreaType::Normal,
            no_summary: false,
            default_cost: None,
            span: span.clone(),
        });
    }
}

struct Reader<'a> {
    file: &'a str,
    table: &'a Table,
    read: BTreeSet<u32>,
}

impl Reader<'_> {
    /// Reads the lines below a process stanza at `path` into `b`. A child
    /// whose key is in `skip` is not read here.
    fn lines(&mut self, s: &Stanza, path: &[&str], b: &mut Building, skip: &dyn Fn(&str) -> bool) {
        for c in s.children() {
            if skip(&c.key) {
                continue;
            }
            let mut p = path.to_vec();
            p.push(&c.key);
            let state = self.table.state(&p);
            if state == State::Handled {
                self.read.insert(c.first_line);
            }
            let sp = span(self.file, c);
            if state == State::Handled && process_line(b, &words(&c.key), &sp) {
                continue;
            }
            if !no_effect(&c.key) {
                b.process
                    .unhandled
                    .push((self.table.report_key(&c.key), sp));
            }
        }
    }
}

/// True for a line of [`NO_EFFECT`].
fn no_effect(key: &str) -> bool {
    let w = words(key);
    NO_EFFECT.iter().any(|p| {
        let p = words(p);
        match p.split_last() {
            Some((&"..", head)) => w.starts_with(head),
            _ => w == p,
        }
    })
}

/// Reads one line of a process. False for a form that the reader cannot
/// read.
fn process_line(b: &mut Building, w: &[&str], sp: &SourceSpan) -> bool {
    let p = &mut b.process;
    match w {
        ["router-id", id] => match id.parse() {
            Ok(id) => p.router_id = Some(id),
            Err(_) => return false,
        },
        ["auto-cost", "reference-bandwidth", n] => match n.parse() {
            Ok(n) => p.reference_bandwidth_mbps = Some(n),
            Err(_) => return false,
        },
        ["area", a, kind @ ("stub" | "nssa"), rest @ ..] => {
            let Some(a) = area_id(a) else {
                return false;
            };
            let no_summary = match rest {
                [] => false,
                ["no-summary"] => true,
                _ => return false,
            };
            let kind = if *kind == "stub" {
                AreaType::Stub
            } else {
                AreaType::Nssa
            };
            let area = p.areas.entry(a).or_insert_with(|| Area {
                kind,
                no_summary,
                default_cost: None,
                span: sp.clone(),
            });
            area.kind = kind;
            area.no_summary = no_summary;
            area.span = sp.clone();
        }
        ["area", a, "default-cost", n] => {
            let (Some(a), Ok(n)) = (area_id(a), n.parse()) else {
                return false;
            };
            p.areas
                .entry(a)
                .or_insert_with(|| Area {
                    kind: AreaType::Normal,
                    no_summary: false,
                    default_cost: None,
                    span: sp.clone(),
                })
                .default_cost = Some(n);
        }
        ["passive-interface", "default"] => p.passive_default = true,
        ["passive-interface", i] => {
            b.passive.insert((*i).to_string());
        }
        ["no", "passive-interface", i] => {
            b.active.insert((*i).to_string());
        }
        ["redistribute", rest @ ..] => match redistribute(rest, p.version, sp) {
            Some(r) => p.redistribute.push(r),
            None => return false,
        },
        ["default-information", "originate", rest @ ..] => {
            let mut d = DefaultOriginate {
                always: false,
                metric: None,
                metric_type: None,
                route_map: None,
                span: sp.clone(),
            };
            let mut i = 0;
            while i < rest.len() {
                match &rest[i..] {
                    ["always", ..] if !d.always => d.always = true,
                    [k, v, ..]
                        if option(k, v, &mut d.metric, &mut d.metric_type, &mut d.route_map) =>
                    {
                        i += 1;
                    }
                    _ => return false,
                }
                i += 1;
            }
            p.default_originate = Some(d);
        }
        ["network", a, m, "area", area] if p.version == Version::V2 => {
            let (Ok(a), Ok(m), Some(area)) =
                (a.parse::<Ipv4Addr>(), m.parse::<Ipv4Addr>(), area_id(area))
            else {
                return false;
            };
            b.networks.push(Network {
                address: u32::from(a),
                wildcard: u32::from(m),
                area,
                span: sp.clone(),
            });
        }
        _ => return false,
    }
    true
}

/// Reads one option of `redistribute` or `default-information originate`
/// with its value: `metric`, `metric-type` and `route-map`, each once.
fn option(
    k: &str,
    v: &str,
    metric: &mut Option<u32>,
    metric_type: &mut Option<u8>,
    route_map: &mut Option<String>,
) -> bool {
    match k {
        "metric" if metric.is_none() => v.parse().map(|v| *metric = Some(v)).is_ok(),
        "metric-type" if metric_type.is_none() => match v {
            "1" => {
                *metric_type = Some(1);
                true
            }
            "2" => {
                *metric_type = Some(2);
                true
            }
            _ => false,
        },
        "route-map" if route_map.is_none() => {
            *route_map = Some(v.to_string());
            true
        }
        _ => false,
    }
}

/// Reads the words after `redistribute`: `connected`, `static` or `bgp
/// <asn>`, then the options. An OSPFv2 statement needs `subnets`.
fn redistribute(w: &[&str], version: Version, sp: &SourceSpan) -> Option<Redistribute> {
    let (source, rest) = match w {
        ["connected", rest @ ..] => (Source::Connected, rest),
        ["static", rest @ ..] => (Source::Static, rest),
        ["bgp", asn, rest @ ..] if crate::bgp_peers::parse_asn(asn).is_some() => {
            (Source::Bgp, rest)
        }
        _ => return None,
    };
    let mut r = Redistribute {
        source,
        metric: None,
        metric_type: None,
        route_map: None,
        span: sp.clone(),
    };
    let mut subnets = false;
    let mut i = 0;
    while i < rest.len() {
        match &rest[i..] {
            ["subnets", ..] if version == Version::V2 && !subnets => subnets = true,
            [k, v, ..] if option(k, v, &mut r.metric, &mut r.metric_type, &mut r.route_map) => {
                i += 1;
            }
            _ => return None,
        }
        i += 1;
    }
    (version == Version::V3 || subnets).then_some(r)
}

/// The processes of the OSPF stanzas, in the order of the config.
fn processes(r: &mut Reader, doc: &Document) -> Vec<Building> {
    let mut out = Vec::new();
    for s in doc.root.children() {
        let w = words(&s.key);
        let path = [s.key.as_str()];
        if r.table.state(&path) != State::Handled {
            continue;
        }
        let sp = span(r.file, s);
        let (version, vrf, process) = match w.as_slice() {
            ["router", "ospf", n] => (Version::V2, DEFAULT_VRF, *n),
            ["router", "ospf", n, "vrf", v] => (Version::V2, *v, *n),
            ["ipv6", "router", "ospf", n] => (Version::V3, DEFAULT_VRF, *n),
            ["router", "ospfv3", n] => {
                r.read.insert(s.first_line);
                ospfv3(r, s, n, &sp, &mut out);
                continue;
            }
            _ => continue,
        };
        r.read.insert(s.first_line);
        let mut b = Building::new(version, vrf, process, sp);
        r.lines(s, &path, &mut b, &|_| false);
        out.push(b);
    }
    out
}

/// The processes of one `router ospfv3` stanza.
fn ospfv3(r: &mut Reader, s: &Stanza, n: &str, sp: &SourceSpan, out: &mut Vec<Building>) {
    let is_af = |k: &str| k.starts_with("address-family ");
    let families: Vec<&Stanza> = s
        .children()
        .iter()
        .filter(|c| {
            matches!(
                words(&c.key).as_slice(),
                ["address-family", "ipv6", "unicast"]
                    | ["address-family", "ipv6", "unicast", "vrf", _]
            )
        })
        .collect();
    let mut built: Vec<Building> = if families.is_empty() {
        vec![Building::new(Version::V3, DEFAULT_VRF, n, sp.clone())]
    } else {
        families
            .iter()
            .map(|af| {
                let vrf = match words(&af.key).as_slice() {
                    [.., "vrf", v] => (*v).to_string(),
                    _ => DEFAULT_VRF.to_string(),
                };
                Building::new(Version::V3, &vrf, n, sp.clone())
            })
            .collect()
    };
    let path = [s.key.as_str()];
    for b in &mut built {
        r.lines(s, &path, b, &is_af);
    }
    for (af, b) in families.iter().zip(&mut built) {
        let path = [s.key.as_str(), af.key.as_str()];
        if r.table.state(&path) == State::Handled {
            r.read.insert(af.first_line);
        }
        r.lines(af, &path, b, &|_| false);
    }
    // An address family that is not IPv6 unicast goes to each process of
    // the stanza.
    for c in s.children() {
        if is_af(&c.key) && !families.iter().any(|f| f.first_line == c.first_line) {
            for b in &mut built {
                b.process
                    .unhandled
                    .push((r.table.report_key(&c.key), span(r.file, c)));
            }
        }
    }
    out.extend(built);
}

/// The OSPF settings of the lines of one interface for one version.
#[derive(Default)]
struct Settings {
    /// The process and the area of the area line.
    area: Option<(String, AreaId)>,
    cost: Option<u32>,
    network: Option<NetworkType>,
    priority: Option<u8>,
    /// The lines that the reader does not read, each with the process of
    /// its words if it has one.
    unhandled: Vec<(Option<String>, String, SourceSpan)>,
}

/// The OSPF settings of an interface stanza for OSPFv2 and OSPFv3, and its
/// bandwidth, or the unread `bandwidth` line.
struct IfaceLines {
    v2: Settings,
    v3: Settings,
    bandwidth: Option<u64>,
    bad_bandwidth: Option<(String, SourceSpan)>,
}

fn interface_lines(r: &Reader, s: &Stanza) -> IfaceLines {
    let mut out = IfaceLines {
        v2: Settings::default(),
        v3: Settings::default(),
        bandwidth: None,
        bad_bandwidth: None,
    };
    for c in s.children() {
        let w = words(&c.key);
        let sp = span(r.file, c);
        let handled = r.table.state(&[&s.key, &c.key]) == State::Handled;
        let (v3, rest) = match w.as_slice() {
            ["bandwidth", n] => {
                match n.parse() {
                    Ok(n) if handled => out.bandwidth = Some(n),
                    _ => out.bad_bandwidth = Some((r.table.report_key(&c.key), sp)),
                }
                continue;
            }
            ["ip", "ospf", rest @ ..] => (false, rest),
            ["ipv6", "ospf", rest @ ..] | ["ospfv3", rest @ ..] => (true, rest),
            _ => continue,
        };
        let set = if v3 { &mut out.v3 } else { &mut out.v2 };
        let ok = handled
            && match rest {
                [p, "area", a] | [p, "ipv6", "area", a] => match area_id(a) {
                    Some(a) => {
                        set.area = Some(((*p).to_string(), a));
                        true
                    }
                    None => false,
                },
                ["cost", n] => n.parse().map(|n| set.cost = Some(n)).is_ok(),
                ["priority", n] => n.parse().map(|n| set.priority = Some(n)).is_ok(),
                ["network", "point-to-point"] => {
                    set.network = Some(NetworkType::PointToPoint);
                    true
                }
                ["network", "broadcast"] => {
                    set.network = Some(NetworkType::Broadcast);
                    true
                }
                _ => false,
            };
        if !ok {
            let process = match rest {
                [p, "area", ..] | [p, _, "area", ..] => Some((*p).to_string()),
                _ => None,
            };
            let key = format!(
                "{}/{}",
                r.table.report_key(&s.key),
                r.table.report_key(&c.key)
            );
            set.unhandled.push((process, key, sp));
        }
    }
    out
}

/// The default network type of an interface by its name.
fn default_network(name: &str) -> Option<NetworkType> {
    let kind: String = name
        .chars()
        .take_while(|c| c.is_ascii_alphabetic() || *c == '-')
        .collect::<String>()
        .to_ascii_lowercase();
    KINDS.iter().find(|(k, _)| *k == kind).map(|(_, n)| *n)
}

/// The primary IPv4 address of an interface.
fn primary(i: &Interface) -> Option<(Ipv4Addr, u8)> {
    let a = i.addresses.iter().find(|a| !a.secondary)?;
    let (addr, len) = a.prefix.split_once('/')?;
    Some((addr.parse().ok()?, len.parse().ok()?))
}

/// The global IPv6 addresses of an interface.
fn global_ipv6(i: &Interface) -> Vec<(IpAddr, u8)> {
    i.ipv6
        .iter()
        .filter_map(|(a, _)| {
            let (addr, len) = a.split_once('/')?;
            let addr: std::net::Ipv6Addr = addr.parse().ok()?;
            let link_local = addr.segments()[0] & 0xffc0 == 0xfe80;
            (!link_local).then_some((IpAddr::V6(addr), len.parse().ok()?))
        })
        .collect()
}

fn run(file: &str, doc: &Document, cfg: &Config, table: &Table) -> (RouterConfig, BTreeSet<u32>) {
    let mut r = Reader {
        file,
        table,
        read: BTreeSet::new(),
    };
    let mut built = processes(&mut r, doc);
    let stanzas: BTreeMap<u32, &Stanza> = doc
        .root
        .children()
        .iter()
        .map(|s| (s.first_line, s))
        .collect();
    for i in &cfg.interfaces {
        let Some(s) = stanzas.get(&i.lines.first) else {
            continue;
        };
        let vrf = i.vrf.as_ref().map_or(DEFAULT_VRF, |(v, _)| v.as_str());
        let lines = interface_lines(&r, s);
        let sp = span(file, s);
        let key = table.report_key(&s.key);
        for (version, set) in [(Version::V2, &lines.v2), (Version::V3, &lines.v3)] {
            let find = |built: &[Building], p: &str| {
                built.iter().position(|b| {
                    b.process.version == version && b.process.vrf == vrf && b.process.process == p
                })
            };
            let member = match &set.area {
                Some((p, a)) => find(&built, p).map(|at| (at, *a, sp.clone())),
                None if version == Version::V2 => by_network(&mut built, i, vrf, &key, &sp),
                None => None,
            };
            // The unread lines go to the process of their words, else to the
            // process of the interface.
            for (p, line, lsp) in &set.unhandled {
                let at = p
                    .as_deref()
                    .and_then(|p| find(&built, p))
                    .or(member.as_ref().map(|m| m.0));
                if let Some(at) = at {
                    built[at]
                        .process
                        .unhandled
                        .push((line.clone(), lsp.clone()));
                }
            }
            let Some((at, area, area_span)) = member else {
                continue;
            };
            let b = &mut built[at];
            b.touch_area(area, &area_span);
            if let Some((line, lsp)) = &lines.bad_bandwidth {
                b.process
                    .unhandled
                    .push((format!("{key}/{line}"), lsp.clone()));
            }
            let mut secs = Vec::new();
            let address = match version {
                Version::V2 => {
                    for a in i.addresses.iter().filter(|a| a.secondary) {
                        match crate::ospf::inputs::address(&a.prefix) {
                            Some(x) => secs.push(x),
                            None => b.process.unhandled.push((
                                format!("{key}/ip address {} secondary", a.prefix),
                                SourceSpan::new(file, a.lines.first, a.lines.last),
                            )),
                        }
                    }
                    primary(i).map(|(a, l)| (IpAddr::V4(a), l))
                }
                Version::V3 => {
                    let all = global_ipv6(i);
                    if all.len() > 1 {
                        b.process.unhandled.push((key.clone(), sp.clone()));
                    }
                    all.first().copied()
                }
            };
            let network = match set.network.or_else(|| default_network(&i.name)) {
                Some(n) => n,
                None => {
                    b.process.unhandled.push((key.clone(), sp.clone()));
                    NetworkType::Broadcast
                }
            };
            let passive = if b.process.passive_default {
                !b.active.contains(&i.name)
            } else {
                b.passive.contains(&i.name)
            };
            b.process.interfaces.push(OspfInterface {
                name: i.name.clone(),
                area,
                address,
                secondaries: secs,
                cost: set.cost,
                bandwidth_kbps: lines.bandwidth,
                network,
                passive,
                priority: set.priority.unwrap_or(1),
                up: i.admin_up.unwrap_or(UP_WITHOUT_SHUTDOWN),
                span: sp.clone(),
            });
        }
    }
    for b in &mut built {
        let areas: Vec<(AreaId, SourceSpan)> = b
            .networks
            .iter()
            .map(|n| (n.area, n.span.clone()))
            .collect();
        for (a, s) in areas {
            b.touch_area(a, &s);
        }
    }
    let processes = built.into_iter().map(|b| b.process).collect();
    (RouterConfig { processes }, r.read)
}

/// The OSPFv2 process and the area of the first `network` statement that
/// covers the primary address of an interface in `vrf`. If statements of 2
/// or more processes cover it, each of them gets the interface as an
/// unhandled line, and the interface joins none.
fn by_network(
    built: &mut [Building],
    i: &Interface,
    vrf: &str,
    key: &str,
    sp: &SourceSpan,
) -> Option<(usize, AreaId, SourceSpan)> {
    let (addr, _) = primary(i)?;
    let hits: Vec<(usize, AreaId, SourceSpan)> = built
        .iter()
        .enumerate()
        .filter(|(_, b)| b.process.version == Version::V2 && b.process.vrf == vrf)
        .filter_map(|(at, b)| {
            let n = b.networks.iter().find(|n| n.covers(addr))?;
            Some((at, n.area, n.span.clone()))
        })
        .collect();
    if hits.len() > 1 {
        for (at, _, _) in &hits {
            built[*at]
                .process
                .unhandled
                .push((key.to_string(), sp.clone()));
        }
        return None;
    }
    hits.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RED: &str = "RED";

    /// The OSPF config of a running config, with the route rows of each VRF
    /// if `rib` is true. Each handled line is read.
    fn read_with(text: &str, rib: bool) -> RouterConfig {
        let doc = super::super::read_text(text.as_bytes());
        let tables = RouteTables::uniform(rib, super::super::dynamic_vrfs(&doc));
        let table = super::super::table(&tables);
        let cfg = super::super::read(&doc, &table);
        assert_eq!(
            super::super::unread(&doc, &table, &cfg.read),
            Vec::<String>::new()
        );
        router_config("r1", &doc, &cfg, &table)
    }

    /// The OSPF config, which is the same with and without route rows.
    fn read(text: &str) -> RouterConfig {
        let with = read_with(text, true);
        assert_eq!(with, read_with(text, false));
        with
    }

    fn state(text: &str, path: &[&str], rib: bool) -> State {
        let doc = super::super::read_text(text.as_bytes());
        let tables = RouteTables::uniform(rib, super::super::dynamic_vrfs(&doc));
        super::super::table(&tables).state(path)
    }

    fn a(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn unhandled(p: &Process) -> Vec<&str> {
        p.unhandled.iter().map(|(k, _)| k.as_str()).collect()
    }

    /// The name, the area, the address, the network type, the passive state
    /// and the admin state of an interface.
    type Row<'a> = (&'a str, AreaId, Option<String>, NetworkType, bool, bool);

    fn interfaces(p: &Process) -> Vec<Row<'_>> {
        p.interfaces
            .iter()
            .map(|i| {
                (
                    i.name.as_str(),
                    i.area,
                    i.address.map(|(a, l)| format!("{a}/{l}")),
                    i.network,
                    i.passive,
                    i.up,
                )
            })
            .collect()
    }

    const V2_CONFIG: &str = "\
hostname r1
interface Loopback0
 ip address 192.0.2.1 255.255.255.255
interface GigabitEthernet1
 ip address 198.51.100.1 255.255.255.0
 ip ospf cost 10
 ip ospf priority 0
 bandwidth 100000
interface GigabitEthernet2
 ip address 198.51.100.129 255.255.255.128
 ip ospf network point-to-point
 shutdown
interface GigabitEthernet3
 ip address 203.0.113.1 255.255.255.0
 ip ospf 1 area 0
interface Tunnel0
 ip address 203.0.113.253 255.255.255.252
interface Vlan10
 vrf forwarding RED
 ip address 192.0.2.65 255.255.255.192
interface GigabitEthernet4
 ip address 192.0.2.129 255.255.255.192
 ip ospf network broadcast
router ospf 1
 router-id 192.0.2.1
 auto-cost reference-bandwidth 100000
 area 1 stub no-summary
 area 0.0.0.2 nssa
 area 2 default-cost 5
 passive-interface default
 no passive-interface GigabitEthernet1
 network 192.0.2.1 0.0.0.0 area 0
 network 198.51.100.0 0.0.0.127 area 1
 network 198.51.100.0 0.0.0.255 area 2
 network 203.0.113.0 0.0.0.255 area 2
 log-adjacency-changes
router ospf 2 vrf RED
 passive-interface Vlan10
 network 0.0.0.0 255.255.255.255 area 0
end
";

    #[test]
    fn the_network_statements_and_the_interface_lines_of_ospfv2() {
        let rc = read(V2_CONFIG);
        assert_eq!(rc.processes.len(), 2);
        let p = &rc.processes[0];
        assert_eq!(
            (p.version, p.vrf.as_str(), p.process.as_str()),
            (Version::V2, "default", "1")
        );
        assert_eq!(p.router_id, Some(a("192.0.2.1")));
        assert_eq!(p.reference_bandwidth_mbps, Some(100_000));
        assert!(p.passive_default);
        assert_eq!(unhandled(p), Vec::<&str>::new());
        use NetworkType::{Broadcast, Loopback, PointToPoint};
        let some = |s: &str| Some(s.to_string());
        assert_eq!(
            interfaces(p),
            [
                (
                    "Loopback0",
                    a("0.0.0.0"),
                    some("192.0.2.1/32"),
                    Loopback,
                    true,
                    true
                ),
                (
                    "GigabitEthernet1",
                    a("0.0.0.1"),
                    some("198.51.100.1/24"),
                    Broadcast,
                    false,
                    true
                ),
                (
                    "GigabitEthernet2",
                    a("0.0.0.2"),
                    some("198.51.100.129/25"),
                    PointToPoint,
                    true,
                    false
                ),
                (
                    "GigabitEthernet3",
                    a("0.0.0.0"),
                    some("203.0.113.1/24"),
                    Broadcast,
                    true,
                    true
                ),
                (
                    "Tunnel0",
                    a("0.0.0.2"),
                    some("203.0.113.253/30"),
                    PointToPoint,
                    true,
                    true
                ),
            ]
        );
        let gi1 = &p.interfaces[1];
        assert_eq!(
            (gi1.cost, gi1.priority, gi1.bandwidth_kbps),
            (Some(10), 0, Some(100_000))
        );
        let gi2 = &p.interfaces[2];
        assert_eq!(
            (gi2.cost, gi2.priority, gi2.bandwidth_kbps),
            (None, 1, None)
        );
        let areas: Vec<(AreaId, AreaType, bool, Option<u32>)> = p
            .areas
            .iter()
            .map(|(id, x)| (*id, x.kind, x.no_summary, x.default_cost))
            .collect();
        assert_eq!(
            areas,
            [
                (a("0.0.0.0"), AreaType::Normal, false, None),
                (a("0.0.0.1"), AreaType::Stub, true, None),
                (a("0.0.0.2"), AreaType::Nssa, false, Some(5)),
            ]
        );
        let red = &rc.processes[1];
        assert_eq!((red.vrf.as_str(), red.process.as_str()), (RED, "2"));
        assert!(!red.passive_default);
        assert_eq!(
            interfaces(red),
            [(
                "Vlan10",
                a("0.0.0.0"),
                some("192.0.2.65/26"),
                Broadcast,
                true,
                true
            )]
        );
    }

    #[test]
    fn the_read_lines_are_handled_in_each_vrf() {
        use State::{Handled, Irrelevant, Unhandled};
        let p = "router ospf 2 vrf RED";
        for (path, rib, no_rib) in [
            (&["router ospf 1"][..], Handled, Handled),
            (&[p], Handled, Handled),
            (
                &[p, "network 0.0.0.0 255.255.255.255 area 0"],
                Handled,
                Handled,
            ),
            (&["router ospf 1", "router-id 192.0.2.1"], Handled, Handled),
            (
                &["router ospf 1", "log-adjacency-changes"],
                Irrelevant,
                Irrelevant,
            ),
            (
                &["router ospf 1", "area 0 range 192.0.2.0 255.255.255.0"],
                Irrelevant,
                Unhandled,
            ),
            (&[p, "max-metric router-lsa"], Irrelevant, Unhandled),
            (&["interface Gi1", "ip ospf 1 area 0"], Handled, Handled),
            (
                &["interface Gi1", "ip ospf network non-broadcast"],
                Irrelevant,
                Unhandled,
            ),
            (&["interface Gi1", "ospfv3 1 ipv6 area 0"], Handled, Handled),
            (
                &["interface Gi1", "ospfv3 1 ipv4 area 0"],
                Irrelevant,
                Unhandled,
            ),
            (&["interface Gi1", "ipv6 ospf 1 area 0"], Handled, Handled),
            (
                &["interface Gi1", "ipv6 ospf hello-interval 5"],
                Irrelevant,
                Unhandled,
            ),
            (&["interface Gi1", "bandwidth 1000"], Handled, Handled),
            (
                &["interface Gi1", "bandwidth qos-reference 1000"],
                Irrelevant,
                Irrelevant,
            ),
            (&["router ospfv3 1"], Handled, Handled),
            (
                &["router ospfv3 1", "address-family ipv6 unicast"],
                Handled,
                Handled,
            ),
            (
                &["router ospfv3 1", "address-family ipv6 unicast vrf RED"],
                Handled,
                Handled,
            ),
            (
                &["router ospfv3 1", "address-family ipv4 unicast"],
                Irrelevant,
                Unhandled,
            ),
            (
                &[
                    "router ospfv3 1",
                    "address-family ipv6 unicast",
                    "passive-interface Gi1",
                ],
                Handled,
                Handled,
            ),
            (
                &[
                    "router ospfv3 1",
                    "address-family ipv6 unicast vrf RED",
                    "area 0 range 2001:db8::/32",
                ],
                Irrelevant,
                Unhandled,
            ),
            (&["ipv6 router ospf 1"], Handled, Handled),
            (
                &["ipv6 router ospf 1", "router-id 192.0.2.1"],
                Handled,
                Handled,
            ),
            (
                &["ipv6 router ospf 1", "area 0 range 2001:db8::/32"],
                Irrelevant,
                Unhandled,
            ),
        ] {
            assert_eq!(state("", path, true), rib, "{path:?}");
            assert_eq!(state("", path, false), no_rib, "{path:?}");
        }
    }

    #[test]
    fn redistribution_and_the_default_route() {
        let text = "\
interface GigabitEthernet1
 ip address 192.0.2.1 255.255.255.0
 ip ospf 1 area 0
router ospf 1
 redistribute connected subnets
 redistribute static metric 100 metric-type 1 subnets route-map STATIC
 redistribute bgp 64496 subnets
 default-information originate always metric 10 metric-type 1 route-map DEFAULT
";
        let rc = read(text);
        let p = &rc.processes[0];
        type Statement<'a> = (Source, Option<u32>, Option<u8>, Option<&'a str>);
        let r: Vec<Statement> = p
            .redistribute
            .iter()
            .map(|r| {
                (
                    r.source.clone(),
                    r.metric,
                    r.metric_type,
                    r.route_map.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            r,
            [
                (Source::Connected, None, None, None),
                (Source::Static, Some(100), Some(1), Some("STATIC")),
                (Source::Bgp, None, None, None),
            ]
        );
        let d = p.default_originate.as_ref().unwrap();
        assert_eq!(
            (d.always, d.metric, d.metric_type, d.route_map.as_deref()),
            (true, Some(10), Some(1), Some("DEFAULT"))
        );
        let rc = read("router ospf 1\n default-information originate\n");
        let d = rc.processes[0].default_originate.as_ref().unwrap();
        assert_eq!((d.always, d.metric, d.metric_type), (false, None, None));
        assert_eq!(unhandled(&rc.processes[0]), Vec::<&str>::new());
    }

    #[test]
    fn a_line_that_is_not_read_is_unhandled() {
        let text = "\
interface GigabitEthernet1
 ip address 192.0.2.1 255.255.255.0
 ip address 198.51.100.1 255.255.255.0 secondary
 ip ospf 1 area 0
 ip ospf message-digest-key 1 md5 7 FAKEOSPFKEY
 ip ospf network point-to-multipoint
 bandwidth inherit
interface GigabitEthernet2
 ip address 203.0.113.1 255.255.255.0
 ip ospf hello-interval 5
router ospf 1
 redistribute connected
 redistribute rip subnets
 redistribute static tag 7 subnets
 area 1 nssa default-information-originate
 area 0 range 192.0.2.0 255.255.255.0
 max-metric router-lsa
 timers throttle spf 50 200 5000
 router-id 192.0.2.300
";
        let rc = read(text);
        let p = &rc.processes[0];
        assert_eq!(
            unhandled(p),
            [
                "redistribute connected",
                "redistribute rip subnets",
                "redistribute static tag 7 subnets",
                "area 1 nssa default-information-originate",
                "area 0 range 192.0.2.0 255.255.255.0",
                "max-metric router-lsa",
                "router-id 192.0.2.300",
                "interface GigabitEthernet1/ip ospf message-digest-key <secret>",
                "interface GigabitEthernet1/ip ospf network point-to-multipoint",
                "interface GigabitEthernet1/bandwidth inherit",
            ]
        );
        assert!(p.unhandled.iter().all(|(_, s)| &*s.file == "r1"));
        assert_eq!(p.unhandled[0].1.first_line, 12);
        assert_eq!(p.router_id, None);
        assert_eq!(p.interfaces.len(), 1);
        assert_eq!(p.interfaces[0].network, NetworkType::Broadcast);
    }

    #[test]
    fn an_address_that_2_processes_cover_and_an_unknown_kind() {
        let text = "\
interface GigabitEthernet1
 ip address 192.0.2.1 255.255.255.0
interface Serial0/1/0
 ip address 198.51.100.1 255.255.255.252
 ip ospf 1 area 0
router ospf 1
 network 192.0.2.0 0.0.0.255 area 0
router ospf 2
 network 0.0.0.0 255.255.255.255 area 0
";
        let rc = read(text);
        assert_eq!(
            unhandled(&rc.processes[0]),
            ["interface GigabitEthernet1", "interface Serial0/1/0"]
        );
        assert_eq!(unhandled(&rc.processes[1]), ["interface GigabitEthernet1"]);
        assert_eq!(
            interfaces(&rc.processes[0])
                .iter()
                .map(|i| i.0)
                .collect::<Vec<_>>(),
            ["Serial0/1/0"]
        );
        assert!(rc.processes[1].interfaces.is_empty());
    }

    #[test]
    fn the_processes_and_the_interfaces_of_ospfv3() {
        let text = "\
interface Loopback0
 ipv6 address 2001:DB8::1/128
 ospfv3 1 ipv6 area 0
interface GigabitEthernet1
 ipv6 address FE80::1 link-local
 ipv6 address 2001:DB8:1::1/64
 ipv6 ospf 7 area 0.0.0.1
 ipv6 ospf cost 20
 ipv6 ospf priority 5
interface GigabitEthernet2
 vrf forwarding RED
 ipv6 address 2001:DB8:2::1/64
 ospfv3 1 ipv6 area 0
 ospfv3 network point-to-point
router ospfv3 1
 router-id 192.0.2.1
 area 1 stub
 !
 address-family ipv6 unicast
  passive-interface Loopback0
  redistribute connected metric 30
 exit-address-family
 !
 address-family ipv6 unicast vrf RED
  default-information originate
 exit-address-family
ipv6 router ospf 7
 router-id 192.0.2.3
 area 0.0.0.1 nssa no-summary
 log-adjacency-changes
";
        let rc = read(text);
        let key = |p: &Process| (p.version, p.vrf.clone(), p.process.clone());
        assert_eq!(
            rc.processes.iter().map(key).collect::<Vec<_>>(),
            [
                (Version::V3, "default".to_string(), "1".to_string()),
                (Version::V3, RED.to_string(), "1".to_string()),
                (Version::V3, "default".to_string(), "7".to_string()),
            ]
        );
        for p in &rc.processes {
            assert_eq!(unhandled(p), Vec::<&str>::new());
        }
        let (d, red, seven) = (&rc.processes[0], &rc.processes[1], &rc.processes[2]);
        assert_eq!(d.router_id, Some(a("192.0.2.1")));
        assert_eq!(red.router_id, Some(a("192.0.2.1")));
        assert_eq!(red.areas[&a("0.0.0.1")].kind, AreaType::Stub);
        let some = |s: &str| Some(s.to_string());
        use NetworkType::{Broadcast, Loopback, PointToPoint};
        assert_eq!(
            interfaces(d),
            [(
                "Loopback0",
                a("0.0.0.0"),
                some("2001:db8::1/128"),
                Loopback,
                true,
                true
            )]
        );
        assert_eq!(d.redistribute.len(), 1);
        assert_eq!(
            (d.redistribute[0].source.clone(), d.redistribute[0].metric),
            (Source::Connected, Some(30))
        );
        assert!(d.default_originate.is_none());
        assert_eq!(
            interfaces(red),
            [(
                "GigabitEthernet2",
                a("0.0.0.0"),
                some("2001:db8:2::1/64"),
                PointToPoint,
                false,
                true
            )]
        );
        assert!(red.default_originate.is_some());
        assert_eq!(
            interfaces(seven),
            [(
                "GigabitEthernet1",
                a("0.0.0.1"),
                some("2001:db8:1::1/64"),
                Broadcast,
                false,
                true
            )]
        );
        assert_eq!(
            (seven.interfaces[0].cost, seven.interfaces[0].priority),
            (Some(20), 5)
        );
        let nssa = &seven.areas[&a("0.0.0.1")];
        assert_eq!((nssa.kind, nssa.no_summary), (AreaType::Nssa, true));
    }

    #[test]
    fn an_ospfv3_address_family_of_ipv4_is_unhandled() {
        let text = "\
router ospfv3 1
 address-family ipv4 unicast
  redistribute connected
 exit-address-family
";
        let rc = read(text);
        assert_eq!(rc.processes.len(), 1);
        assert_eq!(unhandled(&rc.processes[0]), ["address-family ipv4 unicast"]);
    }
}
