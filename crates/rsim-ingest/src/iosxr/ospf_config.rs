//! The OSPF config of an IOS-XR running config: the `router ospf` and
//! `router ospfv3` stanzas with their `vrf`, `area` and `interface`
//! stanzas.
//!
//! The cost, the network type, the passive state and the priority of an
//! interface come from the `interface` stanza, else from its `area`
//! stanza, else from the process level of the default VRF or of the `vrf`
//! stanza.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rsim_core::SourceSpan;
use rsim_routing::ospf::config::{
    Area, DefaultOriginate, NetworkType, OspfInterface, Process, Redistribute, RouterConfig, Source,
};
use rsim_routing::ospf::{AreaId, AreaType, Version};

use super::config::{Config, Lines};
use super::profile::{DEFAULT_VRF, UP_WITHOUT_SHUTDOWN};
use crate::coverage::{Reach, State, Table};
use crate::route_tables::{RouteTables, VRF};
use crate::stanza::Stanza;

/// The first words of the OSPF lines with no effect on the LSAs of the
/// router: the logging, the timers, the authentication, the graceful
/// restart and BFD. The twin forms an adjacency from the subnets of the
/// interfaces.
const IRRELEVANT: &[&str] = &[
    "log",
    "nsr",
    "nsf",
    "timers",
    "bfd",
    "authentication",
    "authentication-key",
    "message-digest-key",
    "hello-interval",
    "dead-interval",
    "retransmit-interval",
    "transmit-delay",
    "mtu-ignore",
];

/// The lines of the inherited settings, at the process, area and
/// interface level.
const LEVEL: &[&str] = &[
    "cost *",
    "network point-to-point",
    "network broadcast",
    "passive",
    "passive enable",
    "passive disable",
    "priority *",
];

/// The handled lines of the process level, without the area stanzas.
const PROCESS: &[&str] = &[
    "router-id *",
    "auto-cost reference-bandwidth *",
    "redistribute ..",
    "default-information originate ..",
];

/// The first words of the process lines that a `vrf` stanza inherits.
const INHERITED: &[&str] = &["cost", "network", "passive", "priority", "auto-cost"];

/// The first words of the process lines that apply only to the default VRF.
/// A `vrf` stanza inherits each other unread or unreadable process line.
const DEFAULT_ONLY: &[&str] = &[
    "router-id",
    "redistribute",
    "default-information",
    "area",
    "vrf",
    "address-family",
    "max-metric",
    "summary-prefix",
    "distance",
    "maximum",
    "default-metric",
];

/// The handled lines of an area stanza, without the interface stanzas.
const AREA: &[&str] = &[
    "stub",
    "stub no-summary",
    "nssa",
    "nssa no-summary",
    "default-cost *",
];

/// The settings that an interface takes from its stanza, its area or its
/// process.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    pub cost: Option<u32>,
    pub network: Option<NetworkType>,
    pub passive: Option<bool>,
    pub priority: Option<u8>,
}

impl Settings {
    /// The settings of `self`, else of `parent`.
    fn over(&self, parent: &Settings) -> Settings {
        Settings {
            cost: self.cost.or(parent.cost),
            network: self.network.or(parent.network),
            passive: self.passive.or(parent.passive),
            priority: self.priority.or(parent.priority),
        }
    }
}

/// An `interface` stanza of an area.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OspfIface {
    pub name: String,
    pub settings: Settings,
    /// True with an OSPF `shutdown` line.
    pub shutdown: bool,
    pub lines: Lines,
}

/// An `area` stanza.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OspfArea {
    pub id: AreaId,
    pub kind: AreaType,
    pub no_summary: bool,
    pub default_cost: Option<u32>,
    pub settings: Settings,
    pub interfaces: Vec<OspfIface>,
    pub lines: Lines,
}

/// A `redistribute` or a `default-information originate` line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    /// `None` for `default-information originate`.
    pub source: Option<Source>,
    pub always: bool,
    pub metric: Option<u32>,
    pub metric_type: Option<u8>,
    pub route_policy: Option<String>,
    pub lines: Lines,
}

/// The router ID of a `router-id` line: an address or an interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouterIdLine {
    Address(Ipv4Addr),
    Interface(String),
}

/// The process level of the default VRF or a `vrf` stanza of a `router
/// ospf` or `router ospfv3` stanza.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OspfProcess {
    pub version: Version,
    pub process: String,
    pub vrf: String,
    pub router_id: Option<(RouterIdLine, Lines)>,
    pub reference_bandwidth_mbps: Option<u32>,
    pub settings: Settings,
    pub areas: BTreeMap<AreaId, OspfArea>,
    pub redistribute: Vec<Export>,
    pub default_originate: Option<Export>,
    /// The masked lines of the scope that the reader does not read, and the
    /// handled lines with a form that the reader cannot read.
    pub unhandled: Vec<(String, Lines)>,
    /// The masked lines of the process level that a `vrf` stanza inherits
    /// (see [`inherited`]), while [`read`] reads the stanza. Empty after
    /// [`read`].
    pub inheritable: Vec<(String, Lines)>,
    pub lines: Lines,
}

fn lines_of(s: &Stanza) -> Lines {
    Lines {
        first: s.first_line,
        last: s.last_line,
    }
}

fn words(s: &str) -> Vec<&str> {
    s.split_whitespace().collect()
}

/// Adds the entries of the OSPF lines that [`read`] reads, and of the
/// irrelevant OSPF lines. An entry of a handled line matches only the forms
/// that [`read`] reads. The other lines of an OSPFv2 stanza keep the
/// state of the routing lines of their VRF. The other lines of an OSPFv3
/// stanza are unhandled. Call it before the entries of the routing
/// processes.
pub fn push_entries(t: &mut Table, tables: &RouteTables) {
    fn push(t: &mut Table, levels: &[String], state: State, reach: Reach) {
        let l: Vec<&str> = levels.iter().map(String::as_str).collect();
        t.push_levels(&l, state, reach);
    }
    fn handled(t: &mut Table, levels: &[String]) {
        let l: Vec<&str> = levels.iter().map(String::as_str).collect();
        t.push_checked(&l, State::Handled, Reach::Subtree, readable);
    }
    fn at(scope: &[String], extra: &[&str]) -> Vec<String> {
        let mut out = scope.to_vec();
        out.extend(extra.iter().map(|e| (*e).to_string()));
        out
    }
    tables.push_handled_vrfs(t, &["router ospf ..", &format!("vrf {VRF}")]);
    for (top, af) in [("router ospf *", "ipv4"), ("router ospfv3 *", "ipv6")] {
        let process = vec![top.to_string()];
        let vrf = vec![top.to_string(), "vrf *".to_string()];
        push(t, &process, State::Handled, Reach::Node);
        push(t, &vrf, State::Handled, Reach::Node);
        for scope in [process, vrf] {
            for f in [
                format!("address-family {af}"),
                format!("address-family {af} unicast"),
            ] {
                push(t, &at(&scope, &[&f]), State::Handled, Reach::Node);
            }
            for line in PROCESS {
                handled(t, &at(&scope, &[*line]));
            }
            let area = at(&scope, &["area *"]);
            let interface = at(&area, &["interface *"]);
            push(t, &area, State::Handled, Reach::Node);
            push(t, &interface, State::Handled, Reach::Node);
            for line in AREA {
                handled(t, &at(&area, &[*line]));
            }
            push(
                t,
                &at(&interface, &["shutdown"]),
                State::Handled,
                Reach::Subtree,
            );
            for level in [&scope, &area, &interface] {
                for line in LEVEL {
                    handled(t, &at(level, &[*line]));
                }
                for w in IRRELEVANT {
                    let line = format!("{w} ..");
                    push(t, &at(level, &[&line]), State::Irrelevant, Reach::Subtree);
                }
            }
        }
    }
}

/// True if [`read`] reads the handled line `key` of a process, an area or
/// an interface.
fn readable(key: &str) -> bool {
    let none = Lines::default();
    match words(key).as_slice() {
        ["router-id", id] => router_id(id).is_some(),
        ["auto-cost", "reference-bandwidth", n] => reference_bandwidth(n).is_some(),
        ["redistribute", rest @ ..] => redistribute(rest, none).is_some(),
        ["default-information", "originate", rest @ ..] => default_originate(rest, none).is_some(),
        ["stub" | "nssa", rest @ ..] => rest.is_empty() || rest == ["no-summary"],
        ["default-cost", n] => n.parse::<u32>().is_ok(),
        other => matches!(level(other, &mut Settings::default()), Parse::Read),
    }
}

/// The router ID of a `router-id` line: an IPv4 address, or a name that
/// starts with a letter and holds a digit.
fn router_id(id: &str) -> Option<RouterIdLine> {
    if let Ok(a) = id.parse::<Ipv4Addr>() {
        Some(RouterIdLine::Address(a))
    } else if id.chars().next().is_some_and(char::is_alphabetic)
        && id.chars().any(|c| c.is_ascii_digit())
    {
        Some(RouterIdLine::Interface(id.to_string()))
    } else {
        None
    }
}

/// The reference bandwidth of an `auto-cost reference-bandwidth` line, in
/// Mbit/s, more than 0.
fn reference_bandwidth(n: &str) -> Option<u32> {
    n.parse::<u32>().ok().filter(|n| *n > 0)
}

/// The state of a parse of a handled line.
enum Parse {
    /// The reader read the line.
    Read,
    /// The line is handled, and its form is not one that the reader reads.
    Unreadable,
    /// The line is not one of these lines.
    Other,
}

/// Reads a settings line into `s`.
fn level(w: &[&str], s: &mut Settings) -> Parse {
    let ok = |b: bool| if b { Parse::Read } else { Parse::Unreadable };
    match w {
        ["cost", n] => match n.parse::<u32>() {
            Ok(n) if (1..=65_535).contains(&n) => {
                s.cost = Some(n);
                Parse::Read
            }
            _ => Parse::Unreadable,
        },
        ["network", "point-to-point"] => {
            s.network = Some(NetworkType::PointToPoint);
            Parse::Read
        }
        ["network", "broadcast"] => {
            s.network = Some(NetworkType::Broadcast);
            Parse::Read
        }
        ["passive"] | ["passive", "enable"] => {
            s.passive = Some(true);
            Parse::Read
        }
        ["passive", "disable"] => {
            s.passive = Some(false);
            Parse::Read
        }
        ["priority", n] => {
            let p = n.parse::<u8>().ok();
            s.priority = p.or(s.priority);
            ok(p.is_some())
        }
        _ => Parse::Other,
    }
}

fn irrelevant(w: &[&str]) -> bool {
    w.first().is_some_and(|f| IRRELEVANT.contains(f))
}

/// True if a `vrf` stanza inherits the process line `w` of the default VRF
/// with the parse `parse`: a line with a first word of [`INHERITED`], and
/// an unread or unreadable line with a first word that is not in
/// [`DEFAULT_ONLY`] or [`IRRELEVANT`].
fn inherited(w: &[&str], parse: &Parse) -> bool {
    let Some(first) = w.first() else {
        return false;
    };
    INHERITED.contains(first)
        || (!matches!(parse, Parse::Read)
            && !DEFAULT_ONLY.contains(first)
            && !IRRELEVANT.contains(first))
}

/// An area ID as a decimal number or in dotted form.
fn area_id(text: &str) -> Option<AreaId> {
    text.parse::<Ipv4Addr>()
        .ok()
        .or_else(|| text.parse::<u32>().ok().map(Ipv4Addr::from))
}

/// The options of a `redistribute` or a `default-information originate`
/// line after the source: `always` (only with `default`), `metric <n>`,
/// `metric-type 1|2` and `route-policy <name>`. `None` for each other
/// word.
fn options(mut w: &[&str], default: bool, e: &mut Export) -> Option<()> {
    while let Some((first, rest)) = w.split_first() {
        w = match (*first, rest) {
            ("always", rest) if default => {
                e.always = true;
                rest
            }
            ("metric", [n, rest @ ..]) => {
                e.metric = Some(n.parse().ok()?);
                rest
            }
            ("metric-type", [n @ ("1" | "2"), rest @ ..]) => {
                e.metric_type = Some(n.parse().ok()?);
                rest
            }
            ("route-policy", [name, rest @ ..]) => {
                e.route_policy = Some((*name).to_string());
                rest
            }
            _ => return None,
        };
    }
    Some(())
}

/// The words of the options of a `redistribute` line.
const OPTION_WORDS: &[&str] = &["metric", "metric-type", "route-policy"];

fn redistribute(w: &[&str], lines: Lines) -> Option<Export> {
    let (source, rest) = match w {
        ["connected", rest @ ..] => (Source::Connected, rest),
        ["static", rest @ ..] => (Source::Static, rest),
        ["bgp", asn, rest @ ..] => {
            crate::bgp_peers::parse_asn(asn)?;
            (Source::Bgp, rest)
        }
        [other, arg, rest @ ..] if !OPTION_WORDS.contains(arg) => {
            (Source::Other(format!("{other} {arg}")), rest)
        }
        [other, rest @ ..] => (Source::Other((*other).to_string()), rest),
        [] => return None,
    };
    let mut e = Export {
        source: Some(source),
        always: false,
        metric: None,
        metric_type: None,
        route_policy: None,
        lines,
    };
    options(rest, false, &mut e)?;
    Some(e)
}

fn default_originate(w: &[&str], lines: Lines) -> Option<Export> {
    let mut e = Export {
        source: None,
        always: false,
        metric: None,
        metric_type: None,
        route_policy: None,
        lines,
    };
    options(w, true, &mut e)?;
    Some(e)
}

struct Reader<'a> {
    read: &'a mut BTreeSet<u32>,
    table: &'a Table,
    version: Version,
}

impl Reader<'_> {
    fn mark(&mut self, s: &Stanza) {
        self.read.insert(s.first_line);
    }

    fn unhandled(&self, s: &Stanza) -> (String, Lines) {
        (self.table.report_key(&s.key), lines_of(s))
    }

    fn family(&self) -> &'static str {
        match self.version {
            Version::V2 => "ipv4",
            Version::V3 => "ipv6",
        }
    }
}

/// Reads a `router ospf <name>` or `router ospfv3 <name>` stanza: the
/// process of the default VRF, then the process of each `vrf` stanza.
/// Each line that the reader reads goes into `read`. The process of a `vrf`
/// stanza gets the inherited lines of the default VRF (see [`inherited`])
/// as unhandled lines.
pub fn read(s: &Stanza, read: &mut BTreeSet<u32>, table: &Table) -> Vec<OspfProcess> {
    let w = words(&s.key);
    let version = if w.get(1) == Some(&"ospfv3") {
        Version::V3
    } else {
        Version::V2
    };
    let name = w.get(2).copied().unwrap_or_default();
    let mut r = Reader {
        read,
        table,
        version,
    };
    r.mark(s);
    let mut default = scope(&mut r, s, name, DEFAULT_VRF, true);
    let mut out = Vec::new();
    for c in s.children() {
        if let ["vrf", v] = words(&c.key).as_slice() {
            r.mark(c);
            let mut p = scope(&mut r, c, name, v, false);
            p.unhandled.extend(default.inheritable.iter().cloned());
            p.unhandled.sort_by_key(|u| (u.1.first, u.1.last));
            p.inheritable.clear();
            out.push(p);
        }
    }
    default.inheritable.clear();
    out.insert(0, default);
    out
}

/// Reads the process level of the default VRF or of a `vrf` stanza.
fn scope(r: &mut Reader, s: &Stanza, name: &str, vrf: &str, top: bool) -> OspfProcess {
    let mut p = OspfProcess {
        version: r.version,
        process: name.to_string(),
        vrf: vrf.to_string(),
        router_id: None,
        reference_bandwidth_mbps: None,
        settings: Settings::default(),
        areas: BTreeMap::new(),
        redistribute: Vec::new(),
        default_originate: None,
        unhandled: Vec::new(),
        inheritable: Vec::new(),
        lines: lines_of(s),
    };
    let family = r.family();
    for c in s.children() {
        let w = words(&c.key);
        let lines = lines_of(c);
        let parse = match w.as_slice() {
            ["vrf", _] if top => continue,
            ["router-id", id] => match router_id(id) {
                Some(id) => {
                    p.router_id = Some((id, lines));
                    Parse::Read
                }
                None => Parse::Unreadable,
            },
            ["auto-cost", "reference-bandwidth", n] => match reference_bandwidth(n) {
                Some(n) => {
                    p.reference_bandwidth_mbps = Some(n);
                    Parse::Read
                }
                None => Parse::Unreadable,
            },
            ["redistribute", rest @ ..] => match redistribute(rest, lines) {
                Some(e) => {
                    p.redistribute.push(e);
                    Parse::Read
                }
                None => Parse::Unreadable,
            },
            ["default-information", "originate", rest @ ..] => {
                match default_originate(rest, lines) {
                    Some(e) => {
                        p.default_originate = Some(e);
                        Parse::Read
                    }
                    None => Parse::Unreadable,
                }
            }
            ["address-family", f] | ["address-family", f, "unicast"] if *f == family => {
                for g in c.children() {
                    let u = r.unhandled(g);
                    if inherited(&words(&g.key), &Parse::Other) {
                        p.inheritable.push(u.clone());
                    }
                    p.unhandled.push(u);
                }
                Parse::Read
            }
            ["area", a] => match area_id(a) {
                Some(id) => {
                    r.mark(c);
                    let a = area(r, c, id, &mut p.unhandled);
                    match p.areas.get_mut(&id) {
                        Some(old) => merge(old, a),
                        None => {
                            p.areas.insert(id, a);
                        }
                    }
                    continue;
                }
                None => {
                    r.mark(c);
                    let mut below = Vec::new();
                    area(r, c, Ipv4Addr::UNSPECIFIED, &mut below);
                    p.unhandled.push(r.unhandled(c));
                    continue;
                }
            },
            other => match level(other, &mut p.settings) {
                Parse::Other if irrelevant(other) => continue,
                x => x,
            },
        };
        if inherited(&w, &parse) {
            p.inheritable.push(r.unhandled(c));
        }
        match parse {
            Parse::Read => r.mark(c),
            Parse::Unreadable => {
                r.mark(c);
                p.unhandled.push(r.unhandled(c));
            }
            Parse::Other => p.unhandled.push(r.unhandled(c)),
        }
    }
    p
}

/// Adds the lines of a second `area` stanza with the same area ID.
fn merge(old: &mut OspfArea, new: OspfArea) {
    if new.kind != AreaType::Normal {
        old.kind = new.kind;
        old.no_summary = new.no_summary;
    }
    old.default_cost = new.default_cost.or(old.default_cost);
    old.settings = new.settings.over(&old.settings);
    old.interfaces.extend(new.interfaces);
}

fn area(r: &mut Reader, s: &Stanza, id: AreaId, unhandled: &mut Vec<(String, Lines)>) -> OspfArea {
    let mut a = OspfArea {
        id,
        kind: AreaType::Normal,
        no_summary: false,
        default_cost: None,
        settings: Settings::default(),
        interfaces: Vec::new(),
        lines: lines_of(s),
    };
    for c in s.children() {
        let w = words(&c.key);
        let parse = match w.as_slice() {
            [kind @ ("stub" | "nssa"), rest @ ..] if rest.is_empty() || rest == ["no-summary"] => {
                a.kind = if *kind == "stub" {
                    AreaType::Stub
                } else {
                    AreaType::Nssa
                };
                a.no_summary = !rest.is_empty();
                Parse::Read
            }
            ["default-cost", n] => match n.parse::<u32>() {
                Ok(n) => {
                    a.default_cost = Some(n);
                    Parse::Read
                }
                Err(_) => Parse::Unreadable,
            },
            ["interface", name] => {
                r.mark(c);
                let i = interface(r, c, name, unhandled);
                a.interfaces.push(i);
                continue;
            }
            other => match level(other, &mut a.settings) {
                Parse::Other if irrelevant(other) => continue,
                x => x,
            },
        };
        match parse {
            Parse::Read => r.mark(c),
            Parse::Unreadable => {
                r.mark(c);
                unhandled.push(r.unhandled(c));
            }
            Parse::Other => unhandled.push(r.unhandled(c)),
        }
    }
    a
}

fn interface(
    r: &mut Reader,
    s: &Stanza,
    name: &str,
    unhandled: &mut Vec<(String, Lines)>,
) -> OspfIface {
    let mut i = OspfIface {
        name: name.to_string(),
        settings: Settings::default(),
        shutdown: false,
        lines: lines_of(s),
    };
    for c in s.children() {
        let w = words(&c.key);
        let parse = match w.as_slice() {
            ["shutdown"] => {
                i.shutdown = true;
                Parse::Read
            }
            other => match level(other, &mut i.settings) {
                Parse::Other if irrelevant(other) => continue,
                x => x,
            },
        };
        match parse {
            Parse::Read => r.mark(c),
            Parse::Unreadable => {
                r.mark(c);
                unhandled.push(r.unhandled(c));
            }
            Parse::Other => unhandled.push(r.unhandled(c)),
        }
    }
    i
}

/// The network type of an interface with no `network` line, from the
/// type of its name. `None` for a type with no known default.
pub fn default_network(name: &str) -> Option<NetworkType> {
    let kind: String = name
        .chars()
        .take_while(|c| !c.is_ascii_digit())
        .collect::<String>()
        .to_ascii_lowercase();
    match kind.as_str() {
        "loopback" => Some(NetworkType::Loopback),
        "tunnel-ip" | "tunnel-te" | "pos" | "serial" => Some(NetworkType::PointToPoint),
        "gigabitethernet" | "tengige" | "twentyfivegige" | "fortygige" | "fiftygige"
        | "hundredgige" | "fourhundredgige" | "bundle-ether" | "mgmteth" | "bvi" => {
            Some(NetworkType::Broadcast)
        }
        _ => None,
    }
}

/// An address with its prefix length, as `address/length`.
fn prefix<A: std::str::FromStr>(text: &str) -> Option<(A, u8)> {
    let (a, len) = text.split_once('/')?;
    Some((a.parse().ok()?, len.parse().ok()?))
}

fn link_local(a: &Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

/// The OSPF config of the router from the OSPF processes of the typed
/// config. The address, the `bandwidth` and the `shutdown` line of each
/// OSPF interface come from its `interface` stanza. The address of an
/// OSPFv2 interface is its primary IPv4 address. The address of an OSPFv3
/// interface is its first IPv6 address that is not link-local. A
/// secondary IPv4 address or a second such IPv6 address goes into the
/// unhandled lines of the process. An OSPF interface with no `interface`
/// stanza, and an OSPFv2 interface with no primary IPv4 address, goes into
/// the unhandled lines of the process. A process of the
/// default VRF with no area, router ID, redistribution, default route or
/// unhandled line is left out.
pub fn router_config(cfg: &Config, file: &str) -> RouterConfig {
    let span = |l: Lines| SourceSpan::new(file, l.first, l.last);
    let mut out = RouterConfig::default();
    for p in &cfg.ospf {
        let mut unhandled: Vec<(String, Lines)> = p.unhandled.clone();
        let find = |name: &str| cfg.interfaces.iter().find(|i| i.name == name);
        let router_id = match &p.router_id {
            Some((RouterIdLine::Address(a), _)) => Some(*a),
            Some((RouterIdLine::Interface(name), l)) => {
                let a = find(name)
                    .and_then(|i| i.addresses.iter().find(|a| !a.secondary))
                    .and_then(|a| prefix::<Ipv4Addr>(&a.prefix))
                    .map(|a| a.0);
                if a.is_none() {
                    unhandled.push((format!("router-id {name}"), *l));
                }
                a
            }
            None => None,
        };
        let mut interfaces = Vec::new();
        for a in p.areas.values() {
            for oi in &a.interfaces {
                let s = oi.settings.over(&a.settings.over(&p.settings));
                let i = find(&oi.name);
                let mut secs = Vec::new();
                let address = match (i, p.version) {
                    (Some(i), Version::V2) => {
                        for x in i.addresses.iter().filter(|x| x.secondary) {
                            match prefix::<Ipv4Addr>(&x.prefix) {
                                Some((a, l)) => secs.push((IpAddr::V4(a), l)),
                                None => unhandled.push((
                                    format!("ipv4 address {} secondary", x.prefix),
                                    x.lines,
                                )),
                            }
                        }
                        let primary = i
                            .addresses
                            .iter()
                            .find(|x| !x.secondary)
                            .and_then(|x| prefix::<Ipv4Addr>(&x.prefix))
                            .map(|(a, l)| (IpAddr::V4(a), l));
                        if primary.is_none() {
                            unhandled.push((format!("interface {}", oi.name), oi.lines));
                        }
                        primary
                    }
                    (Some(i), Version::V3) => {
                        let global: Vec<((Ipv6Addr, u8), Lines)> = i
                            .ipv6
                            .iter()
                            .filter_map(|(t, l)| prefix::<Ipv6Addr>(t).map(|a| (a, *l)))
                            .filter(|(a, _)| !link_local(&a.0))
                            .collect();
                        for (x, l) in global.iter().skip(1) {
                            unhandled.push((format!("ipv6 address {}/{}", x.0, x.1), *l));
                        }
                        global.first().map(|((a, l), _)| (IpAddr::V6(*a), *l))
                    }
                    (None, _) => {
                        unhandled.push((format!("interface {}", oi.name), oi.lines));
                        None
                    }
                };
                let network = match s.network.or_else(|| default_network(&oi.name)) {
                    Some(n) => n,
                    None => {
                        unhandled.push((format!("interface {}", oi.name), oi.lines));
                        NetworkType::Broadcast
                    }
                };
                let down = i.map_or(!UP_WITHOUT_SHUTDOWN, |i| i.shutdown);
                interfaces.push(OspfInterface {
                    name: oi.name.clone(),
                    area: a.id,
                    address,
                    secondaries: secs,
                    cost: s.cost,
                    bandwidth_kbps: i.and_then(|i| i.bandwidth.map(|b| b.0)),
                    network,
                    passive: s.passive.unwrap_or(false),
                    priority: s.priority.unwrap_or(1),
                    up: !down && !oi.shutdown,
                    span: span(oi.lines),
                });
            }
        }
        unhandled.sort_by_key(|u| (u.1.first, u.1.last));
        unhandled.dedup();
        if p.vrf == DEFAULT_VRF
            && p.areas.is_empty()
            && router_id.is_none()
            && p.redistribute.is_empty()
            && p.default_originate.is_none()
            && unhandled.is_empty()
        {
            continue;
        }
        let export = |e: &Export| Redistribute {
            source: e.source.clone().unwrap_or(Source::Connected),
            metric: e.metric,
            metric_type: e.metric_type,
            route_map: e.route_policy.clone(),
            span: span(e.lines),
        };
        out.processes.push(Process {
            version: p.version,
            vrf: p.vrf.clone(),
            process: p.process.clone(),
            router_id,
            reference_bandwidth_mbps: p.reference_bandwidth_mbps,
            areas: p
                .areas
                .values()
                .map(|a| {
                    (
                        a.id,
                        Area {
                            kind: a.kind,
                            no_summary: a.no_summary,
                            default_cost: a.default_cost,
                            span: span(a.lines),
                        },
                    )
                })
                .collect(),
            interfaces,
            redistribute: p.redistribute.iter().map(export).collect(),
            default_originate: p.default_originate.as_ref().map(|e| DefaultOriginate {
                always: e.always,
                metric: e.metric,
                metric_type: e.metric_type,
                route_map: e.route_policy.clone(),
                span: span(e.lines),
            }),
            passive_default: p.settings.passive.unwrap_or(false),
            unhandled: unhandled.into_iter().map(|(k, l)| (k, span(l))).collect(),
            span: span(p.lines),
        });
    }
    out
}
