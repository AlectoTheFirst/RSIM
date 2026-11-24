//! The rule reader of the firewall and of the business policy. The match of
//! a rule becomes typed predicates; a field whose match is not exact is a
//! bound of the rule. The action is kept as read.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rsim_core::{Prefix, SourceSpan};
use serde_json::Value;

use super::effective::{Effective, Merged, Ruled};
use super::json::{J, address, int, mask_len, max_len, netmask_len, open, text};
use super::reader::{HubRef, HubRole, Hubs};

/// The address family of a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
    Both,
}

/// An address entry of a rule or of an address group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddrEntry {
    Prefix(Prefix),
    /// An address with a wildcard mask that is not a prefix: the set bits of
    /// `wildcard` are free.
    Wildcard {
        addr: IpAddr,
        wildcard: IpAddr,
    },
}

impl AddrEntry {
    pub fn is_ipv6(&self) -> bool {
        match self {
            AddrEntry::Prefix(p) => !p.is_ipv4(),
            AddrEntry::Wildcard { addr, .. } => addr.is_ipv6(),
        }
    }
}

/// The match of an address field of one family.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AddrMatch {
    /// Each address. A field with a bound is `Any`, its upper bound.
    #[default]
    Any,
    /// The addresses of the entries. No entry matches no address.
    Set(Vec<AddrEntry>),
}

/// A port range, with the protocol of a port group entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortRange {
    pub protocol: Option<u8>,
    pub low: u16,
    pub high: u16,
}

/// The match of a port field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PortMatch {
    /// Each port. A field with a bound is `Any`, its upper bound.
    #[default]
    Any,
    Set(Vec<PortRange>),
}

/// A match key whose match is not exact: its packets are a match bound.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bound {
    pub key: String,
    pub value: String,
}

/// The match of a rule. The IPv4 and the IPv6 address of each side are
/// separate fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Match {
    pub ip_version: Option<IpVersion>,
    pub source: AddrMatch,
    pub source_v6: AddrMatch,
    pub destination: AddrMatch,
    pub destination_v6: AddrMatch,
    pub protocol: Option<u8>,
    pub source_ports: PortMatch,
    pub destination_ports: PortMatch,
    pub dscp: Option<u8>,
    pub source_interface: Option<String>,
    pub source_vlan: Option<u16>,
    /// The keys whose match is not exact, sorted.
    pub bounds: Vec<Bound>,
}

/// The match keys with an exact predicate.
const EXACT_KEYS: &[&str] = &[
    "sip",
    "ssm",
    "s_rule_type",
    "sipV6",
    "sAddressGroup",
    "dip",
    "dsm",
    "d_rule_type",
    "dipV6",
    "dAddressGroup",
    "ipVersion",
    "proto",
    "sport_low",
    "sport_high",
    "dport_low",
    "dport_high",
    "sPortGroup",
    "dPortGroup",
    "dscp",
    "sInterface",
    "svlan",
];

/// The match keys that set no packet field when they are 0 or false.
const FLAGS: &[&str] = &[
    "sip_prenat_enabled",
    "sip_prenat_enabledV6",
    "dip_prenat_enabled",
    "dip_prenat_enabledV6",
];

fn bound(m: J<'_>, key: &str) -> Bound {
    let value = match m.v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => String::new(),
    };
    Bound {
        key: key.to_string(),
        value,
    }
}

/// The inverse of a mask.
fn invert(a: IpAddr) -> IpAddr {
    match a {
        IpAddr::V4(x) => IpAddr::V4(Ipv4Addr::from(!u32::from(x))),
        IpAddr::V6(x) => IpAddr::V6(Ipv6Addr::from(!u128::from(x))),
    }
}

/// An address entry from an address, a mask and a rule type: `exact` is the
/// address, `prefix` and `netmask` (also with no type) take the mask as a
/// netmask or a length, and with no mask the address is a host; `wildcard`
/// takes the mask as a wildcard mask.
pub fn addr_entry(ip: &str, mask: Option<&str>, rule_type: Option<&str>) -> Option<AddrEntry> {
    let addr = address(ip)?;
    let max = max_len(addr);
    match rule_type.unwrap_or("") {
        "exact" => Some(AddrEntry::Prefix(Prefix::host(addr))),
        "wildcard" => {
            let w: IpAddr = mask?.trim().parse().ok()?;
            if w.is_ipv4() != addr.is_ipv4() {
                return None;
            }
            match netmask_len(invert(w)) {
                Some(len) if len <= max => Some(AddrEntry::Prefix(Prefix::new(addr, len))),
                _ => Some(AddrEntry::Wildcard { addr, wildcard: w }),
            }
        }
        "" | "prefix" | "netmask" => {
            let inline = ip.split_once('/').map(|(_, l)| l);
            let len = match mask.or(inline) {
                Some(m) => mask_len(m)?,
                None => max,
            };
            (len <= max).then(|| AddrEntry::Prefix(Prefix::new(addr, len)))
        }
        _ => None,
    }
}

fn port(v: Option<&Value>) -> Option<u16> {
    v.and_then(int).and_then(|n| u16::try_from(n).ok())
}

/// The address match of one key of one family.
fn single(
    m: J<'_>,
    key: &str,
    mask: Option<&str>,
    rule_type: Option<&str>,
    v6: bool,
    bounds: &mut Vec<Bound>,
) -> AddrMatch {
    let v = m.v.get(key);
    if open(v) {
        return AddrMatch::Any;
    }
    let entry = v
        .and_then(Value::as_str)
        .and_then(|ip| addr_entry(ip, mask.and_then(|k| m.str(k)), rule_type));
    match entry {
        Some(e) if e.is_ipv6() == v6 => AddrMatch::Set(vec![e]),
        _ => {
            bounds.push(bound(m, key));
            AddrMatch::Any
        }
    }
}

/// The IPv4 and the IPv6 match of one side: its addresses, or its address
/// group.
fn side(
    m: J<'_>,
    groups: &ObjectGroups,
    source: bool,
    bounds: &mut Vec<Bound>,
) -> (AddrMatch, AddrMatch) {
    let (ip, mask, kind, ip6, group) = if source {
        ("sip", "ssm", "s_rule_type", "sipV6", "sAddressGroup")
    } else {
        ("dip", "dsm", "d_rule_type", "dipV6", "dAddressGroup")
    };
    let rule_type = m.str(kind);
    let v4 = single(m, ip, Some(mask), rule_type, false, bounds);
    let v6 = single(m, ip6, None, rule_type, true, bounds);
    if open(m.v.get(group)) {
        return (v4, v6);
    }
    if v4 != AddrMatch::Any || v6 != AddrMatch::Any {
        bounds.push(bound(m, group));
        return (AddrMatch::Any, AddrMatch::Any);
    }
    let found = m.v.get(group).and_then(text).and_then(|r| groups.find(&r));
    let Some(g) = found else {
        bounds.push(bound(m, group));
        return (AddrMatch::Any, AddrMatch::Any);
    };
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for e in &g.entries {
        match e {
            GroupEntry::Address(a) if a.is_ipv6() => v6.push(a.clone()),
            GroupEntry::Address(a) => v4.push(a.clone()),
            _ => {
                bounds.push(bound(m, group));
                return (AddrMatch::Any, AddrMatch::Any);
            }
        }
    }
    (AddrMatch::Set(v4), AddrMatch::Set(v6))
}

/// The port match of one side: its port range, or its port group.
fn ports(m: J<'_>, groups: &ObjectGroups, source: bool, bounds: &mut Vec<Bound>) -> PortMatch {
    let (low, high, group) = if source {
        ("sport_low", "sport_high", "sPortGroup")
    } else {
        ("dport_low", "dport_high", "dPortGroup")
    };
    let range = if open(m.v.get(low)) {
        PortMatch::Any
    } else {
        let lo = port(m.v.get(low));
        let hi = if open(m.v.get(high)) {
            lo
        } else {
            port(m.v.get(high))
        };
        match (lo, hi) {
            (Some(l), Some(h)) if l <= h => PortMatch::Set(vec![PortRange {
                protocol: None,
                low: l,
                high: h,
            }]),
            _ => {
                bounds.push(bound(m, low));
                PortMatch::Any
            }
        }
    };
    if open(m.v.get(group)) {
        return range;
    }
    if range != PortMatch::Any {
        bounds.push(bound(m, group));
        return PortMatch::Any;
    }
    let found = m.v.get(group).and_then(text).and_then(|r| groups.find(&r));
    let Some(g) = found else {
        bounds.push(bound(m, group));
        return PortMatch::Any;
    };
    let mut out = Vec::new();
    for e in &g.entries {
        match e {
            GroupEntry::Port(p) => out.push(p.clone()),
            _ => {
                bounds.push(bound(m, group));
                return PortMatch::Any;
            }
        }
    }
    PortMatch::Set(out)
}

/// The match of a rule. An open value leaves its field open. The keys
/// `appid`, `classid`, `hostname`, `os_version`, `dInterface`, `dvlan`,
/// `smac` and `dmac`, each key that the reader does not map, a value that
/// does not read, an address group with a domain, a group that is not in
/// the object groups, and an address of the family that `ipVersion` leaves
/// out are bounds.
pub fn read_match(m: Option<J<'_>>, groups: &ObjectGroups) -> Match {
    let mut out = Match::default();
    let Some(m) = m else {
        return out;
    };
    let mut bounds = Vec::new();
    if !open(m.v.get("ipVersion")) {
        match m.str("ipVersion") {
            Some("IPv4") => out.ip_version = Some(IpVersion::V4),
            Some("IPv6") => out.ip_version = Some(IpVersion::V6),
            Some("IPv4v6") => out.ip_version = Some(IpVersion::Both),
            _ => bounds.push(bound(m, "ipVersion")),
        }
    }
    (out.source, out.source_v6) = side(m, groups, true, &mut bounds);
    (out.destination, out.destination_v6) = side(m, groups, false, &mut bounds);
    let v4_set = !open(m.v.get("sip")) || !open(m.v.get("dip"));
    let v6_set = !open(m.v.get("sipV6")) || !open(m.v.get("dipV6"));
    match out.ip_version {
        Some(IpVersion::V6) if v4_set => bounds.push(Bound {
            key: "ipVersion".to_string(),
            value: "IPv6 with an IPv4 address".to_string(),
        }),
        Some(IpVersion::V4) if v6_set => bounds.push(Bound {
            key: "ipVersion".to_string(),
            value: "IPv4 with an IPv6 address".to_string(),
        }),
        _ => {}
    }
    out.source_ports = ports(m, groups, true, &mut bounds);
    out.destination_ports = ports(m, groups, false, &mut bounds);
    if !open(m.v.get("proto")) {
        out.protocol = m.int("proto").and_then(|n| u8::try_from(n).ok());
        if out.protocol.is_none() {
            bounds.push(bound(m, "proto"));
        }
    }
    if !open(m.v.get("dscp")) {
        out.dscp = m
            .int("dscp")
            .and_then(|n| u8::try_from(n).ok())
            .filter(|d| *d < 64);
        if out.dscp.is_none() {
            bounds.push(bound(m, "dscp"));
        }
    }
    if !open(m.v.get("sInterface")) {
        out.source_interface = m.v.get("sInterface").and_then(text);
        if out.source_interface.is_none() {
            bounds.push(bound(m, "sInterface"));
        }
    }
    if !open(m.v.get("svlan")) {
        out.source_vlan = m
            .int("svlan")
            .and_then(|n| u16::try_from(n).ok())
            .filter(|v| *v < 4096);
        if out.source_vlan.is_none() {
            bounds.push(bound(m, "svlan"));
        }
    }
    for (key, v) in m.members() {
        if EXACT_KEYS.contains(&key) || open(Some(v.v)) {
            continue;
        }
        let off = matches!(v.v, Value::Bool(false)) || v.v.as_i64() == Some(0);
        if FLAGS.contains(&key) && off {
            continue;
        }
        bounds.push(bound(m, key));
    }
    bounds.sort();
    bounds.dedup();
    out.bounds = bounds;
    out
}

/// A value of the action as read: not stated, one of the values that the
/// reader knows, or another text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Word<T> {
    NotStated,
    Known(T),
    Other(String),
}

fn word<T>(v: Option<&Value>, known: impl Fn(&str) -> Option<T>) -> Word<T> {
    if open(v) {
        return Word::NotStated;
    }
    let Some(t) = v.and_then(text) else {
        return Word::NotStated;
    };
    match known(&t) {
        Some(k) => Word::Known(k),
        None => Word::Other(t),
    }
}

/// A rule of the firewall or of the business policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule<A> {
    /// The `ruleLogicalId`, else `rule-<n>` or `default-<n>` by the place of
    /// the rule in its list, from 1.
    pub id: String,
    pub name: Option<String>,
    /// True for a rule of the edge-specific data.
    pub from_edge: bool,
    /// True for a rule of the `defaults` of a segment.
    pub default: bool,
    pub matches: Match,
    pub action: A,
    pub span: SourceSpan,
}

fn read_rules<'a, A>(
    list: &[Ruled<'a>],
    prefix: &str,
    default: bool,
    groups: &ObjectGroups,
    action: impl Fn(Option<J<'a>>) -> A,
) -> Vec<Rule<A>> {
    list.iter()
        .enumerate()
        .map(|(i, r)| Rule {
            id: r
                .rule
                .text("ruleLogicalId")
                .unwrap_or_else(|| format!("{prefix}-{}", i + 1)),
            name: r.rule.text("name"),
            from_edge: r.edge,
            default,
            matches: read_match(r.rule.obj("match"), groups),
            action: action(r.rule.obj("action")),
            span: r.rule.span(),
        })
        .collect()
}

/// The rules of one segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSet<A> {
    pub segment: Option<u32>,
    pub segment_name: Option<String>,
    /// `stateful_firewall_enabled` of a firewall segment.
    pub stateful: Option<bool>,
    /// The rules in order: the edge rules, then the profile rules, then the
    /// default rules.
    pub rules: Vec<Rule<A>>,
    /// Why the rules after `rules` are not known: the profile part is not
    /// known.
    pub unknown_tail: Option<String>,
}

/// A policy whose module is read, or the reason that it is not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Policy<T> {
    Read(T),
    NotRead(String),
}

/// The action of an outbound firewall rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FirewallAction {
    Allow,
    Deny,
    Drop,
    Reject,
    Skip,
    NotStated,
    Other(String),
}

fn firewall_action(a: Option<J<'_>>) -> FirewallAction {
    match a.and_then(|a| a.str("allow_or_deny")) {
        Some("allow") => FirewallAction::Allow,
        Some("deny") => FirewallAction::Deny,
        Some("drop") => FirewallAction::Drop,
        Some("reject") => FirewallAction::Reject,
        Some("skip") => FirewallAction::Skip,
        Some(o) => FirewallAction::Other(o.to_string()),
        None => FirewallAction::NotStated,
    }
}

/// The kind of an inbound firewall rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundKind {
    PortForwarding,
    OneToOneNat,
}

/// The action of an inbound firewall rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inbound {
    pub kind: Word<InboundKind>,
    pub lan_ip: Option<IpAddr>,
    pub lan_port: Option<u16>,
    pub outbound: Option<bool>,
    pub interface: Option<String>,
    pub subinterface: Option<i64>,
}

fn inbound(a: Option<J<'_>>) -> Inbound {
    let nat = a.and_then(|a| a.obj("nat"));
    Inbound {
        kind: word(a.and_then(|a| a.v.get("type")), |t| match t {
            "port_forwarding" => Some(InboundKind::PortForwarding),
            "one_to_one_nat" => Some(InboundKind::OneToOneNat),
            _ => None,
        }),
        lan_ip: nat.and_then(|n| n.str("lan_ip")).and_then(address),
        lan_port: nat.and_then(|n| port(n.v.get("lan_port"))),
        outbound: nat.and_then(|n| n.bool("outbound")),
        interface: a.and_then(|a| a.text("interface")),
        subinterface: a.and_then(|a| a.int("subinterfaceId")),
    }
}

/// The firewall of an edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Firewall {
    pub enabled: Option<bool>,
    pub stateful: Option<bool>,
    /// The outbound rules of each segment.
    pub segments: Vec<RuleSet<FirewallAction>>,
    pub inbound: Vec<Rule<Inbound>>,
    pub inbound_v6: Vec<Rule<Inbound>>,
    /// Why the profile part is not known: the segments and the inbound
    /// rules of the profile are not known.
    pub unknown_tail: Option<String>,
}

/// The firewall of the effective `firewall` module. With no body, the
/// firewall is not read.
pub fn firewall(e: &Effective<'_>, groups: &ObjectGroups) -> Policy<Firewall> {
    let b = &e.body;
    if b.is_empty() {
        return Policy::NotRead(
            e.profile_unknown
                .clone()
                .unwrap_or_else(|| "no firewall module".to_string()),
        );
    }
    let tail = e.profile_unknown.clone();
    let flag = |m: &Merged<'_>, k: &str| m.get(k).and_then(|j| j.v.as_bool());
    Policy::Read(Firewall {
        enabled: flag(b, "firewall_enabled"),
        stateful: flag(b, "stateful_firewall_enabled"),
        segments: b
            .segments()
            .iter()
            .map(|s| RuleSet {
                segment: s.segment_id(),
                segment_name: s.segment_name(),
                stateful: flag(s, "stateful_firewall_enabled"),
                rules: read_rules(s.rules("outbound"), "rule", false, groups, firewall_action),
                unknown_tail: tail.clone(),
            })
            .collect(),
        inbound: read_rules(b.rules("inbound"), "rule", false, groups, inbound),
        inbound_v6: read_rules(b.rules("inboundV6"), "rule", false, groups, inbound),
        unknown_tail: tail,
    })
}

/// The traffic of a route action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// `edge2EdgeRouteAction`
    Edge,
    /// `edge2DataCenterRouteAction`
    DataCenter,
    /// `edge2CloudRouteAction`
    Cloud,
}

const TARGETS: &[(&str, Target)] = &[
    ("edge2EdgeRouteAction", Target::Edge),
    ("edge2DataCenterRouteAction", Target::DataCenter),
    ("edge2CloudRouteAction", Target::Cloud),
];

/// The `routePolicy` values that the reader knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutePolicy {
    Direct,
    Gateway,
    Backhaul,
    Auto,
}

/// The `linkPolicy` values that the reader knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkPolicy {
    Fixed,
    Auto,
    Mpls,
    Private,
    Internet,
    Public,
    Direct,
    Wireless,
    Lte,
}

/// The DSCP names of the Portal API.
const DSCP_NAMES: &[(&str, u8)] = &[
    ("EF", 46),
    ("VA", 44),
    ("AF11", 10),
    ("AF12", 12),
    ("AF13", 14),
    ("AF21", 18),
    ("AF22", 20),
    ("AF23", 22),
    ("AF31", 26),
    ("AF32", 28),
    ("AF33", 30),
    ("AF41", 34),
    ("AF42", 36),
    ("AF43", 38),
    ("CS0", 0),
    ("CS1", 8),
    ("CS2", 16),
    ("CS3", 24),
    ("CS4", 32),
    ("CS5", 40),
    ("CS6", 48),
    ("CS7", 56),
];

/// The DSCP value of a name of the Portal API or of a number below 64.
pub fn dscp_tag(t: &str) -> Option<u8> {
    let t = t.trim();
    t.parse::<u8>().ok().filter(|d| *d < 64).or_else(|| {
        DSCP_NAMES
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(t))
            .map(|(_, d)| *d)
    })
}

/// A route action of a business rule, as read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteAction {
    pub target: Target,
    pub route_policy: Word<RoutePolicy>,
    pub link_policy: Word<LinkPolicy>,
    pub service_group: Option<String>,
    pub wanlink: Option<String>,
    pub link_internal: Option<String>,
    pub interface: Option<String>,
    pub vlan: Option<i64>,
    pub outer_dscp: Word<u8>,
    pub inner_dscp: Word<u8>,
    /// The hubs of `routeCfg.backhaulEdges`, in order.
    pub backhaul: Vec<HubRef>,
    pub span: SourceSpan,
}

/// The QoS values of a business rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Qos {
    pub class: Option<String>,
    pub priority_tx: Option<String>,
    pub priority_rx: Option<String>,
    pub cap_tx: Option<i64>,
    pub cap_rx: Option<i64>,
}

/// The action of a business rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusinessAction {
    pub route_type: Option<String>,
    pub routes: Vec<RouteAction>,
    pub qos: Option<Qos>,
    /// True if `nat` or `natV6` names a source or a destination address.
    pub nat: bool,
}

fn opt_text(j: Option<J<'_>>, key: &str) -> Option<String> {
    let v = j?.v.get(key);
    if open(v) { None } else { v.and_then(text) }
}

fn opt_int(j: Option<J<'_>>, key: &str) -> Option<i64> {
    let v = j?.v.get(key);
    if open(v) { None } else { v.and_then(int) }
}

fn route_action(target: Target, r: J<'_>, hubs: &Hubs) -> RouteAction {
    let r1 = Some(r);
    let tag = |k: &str| word(r.v.get(k), dscp_tag);
    RouteAction {
        target,
        route_policy: word(r.v.get("routePolicy"), |t| {
            match t.to_ascii_lowercase().as_str() {
                "direct" => Some(RoutePolicy::Direct),
                "gateway" => Some(RoutePolicy::Gateway),
                "backhaul" => Some(RoutePolicy::Backhaul),
                "auto" => Some(RoutePolicy::Auto),
                _ => None,
            }
        }),
        link_policy: word(r.v.get("linkPolicy"), |t| {
            match t.to_ascii_lowercase().as_str() {
                "fixed" => Some(LinkPolicy::Fixed),
                "auto" => Some(LinkPolicy::Auto),
                "mpls" => Some(LinkPolicy::Mpls),
                "private" => Some(LinkPolicy::Private),
                "internet" => Some(LinkPolicy::Internet),
                "public" => Some(LinkPolicy::Public),
                "direct" => Some(LinkPolicy::Direct),
                "wireless" => Some(LinkPolicy::Wireless),
                "lte" => Some(LinkPolicy::Lte),
                _ => None,
            }
        }),
        service_group: opt_text(r1, "serviceGroup"),
        wanlink: opt_text(r1, "wanlink"),
        link_internal: opt_text(r1, "linkInternalLogicalId"),
        interface: opt_text(r1, "interface"),
        vlan: opt_int(r1, "vlanId"),
        outer_dscp: tag("linkOuterDscpTag"),
        inner_dscp: tag("linkInnerDscpTag"),
        backhaul: r
            .obj("routeCfg")
            .map(|c| c.list("backhaulEdges"))
            .unwrap_or_default()
            .into_iter()
            .map(|h| hubs.hub_ref(h, HubRole::Backhaul))
            .collect(),
        span: r.span(),
    }
}

fn business_action(a: Option<J<'_>>, hubs: &Hubs) -> BusinessAction {
    let routes = TARGETS
        .iter()
        .filter_map(|(k, t)| Some(route_action(*t, a?.obj(k)?, hubs)))
        .collect();
    let qos = a.and_then(|a| a.obj("QoS")).map(|q| {
        let tx = q.obj("txScheduler");
        let rx = q.obj("rxScheduler");
        Qos {
            class: opt_text(Some(q), "type"),
            priority_tx: opt_text(tx, "priority"),
            priority_rx: opt_text(rx, "priority"),
            cap_tx: opt_int(tx, "bandwidthCapPct"),
            cap_rx: opt_int(rx, "bandwidthCapPct"),
        }
    });
    let nat = ["nat", "natV6"].iter().any(|k| {
        let n = a.and_then(|a| a.obj(k));
        ["sourceIp", "destIp"]
            .iter()
            .any(|f| opt_text(n, f).is_some_and(|v| !v.eq_ignore_ascii_case("no")))
    });
    BusinessAction {
        route_type: opt_text(a, "routeType"),
        routes,
        qos,
        nat,
    }
}

/// The business policy of an edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Business {
    pub segments: Vec<RuleSet<BusinessAction>>,
    /// Why the profile part is not known: the segments and the rules of the
    /// profile are not known.
    pub unknown_tail: Option<String>,
}

/// The business policy of the effective `QOS` module: the `rules` of each
/// segment, then its `defaults`. With no body, the policy is not read.
pub fn business(e: &Effective<'_>, groups: &ObjectGroups, hubs: &Hubs) -> Policy<Business> {
    let b = &e.body;
    if b.is_empty() {
        return Policy::NotRead(
            e.profile_unknown
                .clone()
                .unwrap_or_else(|| "no QOS module".to_string()),
        );
    }
    let tail = e.profile_unknown.clone();
    let action = |a: Option<J<'_>>| business_action(a, hubs);
    Policy::Read(Business {
        segments: b
            .segments()
            .iter()
            .map(|s| {
                let mut rules = read_rules(s.rules("rules"), "rule", false, groups, action);
                rules.extend(read_rules(
                    s.rules("defaults"),
                    "default",
                    true,
                    groups,
                    action,
                ));
                RuleSet {
                    segment: s.segment_id(),
                    segment_name: s.segment_name(),
                    stateful: None,
                    rules,
                    unknown_tail: tail.clone(),
                }
            })
            .collect(),
        unknown_tail: tail,
    })
}

/// An entry of an object group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupEntry {
    Address(AddrEntry),
    Port(PortRange),
    Domain(String),
    /// An entry that the reader does not read, as JSON text.
    Unread(String),
}

/// An address group or a port group of `enterprise/getObjectGroups`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectGroup {
    pub logical_id: Option<String>,
    pub name: Option<String>,
    pub kind: Option<String>,
    pub entries: Vec<GroupEntry>,
    pub span: SourceSpan,
}

/// The object groups of an enterprise.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectGroups {
    pub groups: Vec<ObjectGroup>,
    /// True if the section is collected.
    pub collected: bool,
}

impl ObjectGroups {
    /// The groups of the `object_groups` section.
    pub fn read(root: Option<J<'_>>) -> ObjectGroups {
        let Some(root) = root else {
            return ObjectGroups::default();
        };
        let groups = root
            .rows()
            .into_iter()
            .map(|g| ObjectGroup {
                logical_id: g.text("logicalId"),
                name: g.text("name"),
                kind: g.text("type"),
                entries: g
                    .get("data")
                    .map(J::elems)
                    .unwrap_or_default()
                    .into_iter()
                    .map(entry)
                    .collect(),
                span: g.span(),
            })
            .collect();
        ObjectGroups {
            groups,
            collected: true,
        }
    }

    /// The group of a rule reference: by logicalId, else by name.
    pub fn find(&self, reference: &str) -> Option<&ObjectGroup> {
        self.groups
            .iter()
            .find(|g| g.logical_id.as_deref() == Some(reference))
            .or_else(|| {
                self.groups
                    .iter()
                    .find(|g| g.name.as_deref() == Some(reference))
            })
    }
}

fn entry(e: J<'_>) -> GroupEntry {
    if let Some(d) = e.text("domain") {
        return GroupEntry::Domain(d);
    }
    if let Some(ip) = e.str("ip")
        && let Some(a) = addr_entry(ip, e.str("mask"), e.str("rule_type"))
    {
        return GroupEntry::Address(a);
    }
    if !open(e.v.get("port_low"))
        && let Some(low) = port(e.v.get("port_low"))
    {
        let high = if open(e.v.get("port_high")) {
            Some(low)
        } else {
            port(e.v.get("port_high"))
        };
        if let Some(high) = high.filter(|h| *h >= low) {
            return GroupEntry::Port(PortRange {
                protocol: e.int("proto").and_then(|p| u8::try_from(p).ok()),
                low,
                high,
            });
        }
    }
    GroupEntry::Unread(e.v.to_string())
}
