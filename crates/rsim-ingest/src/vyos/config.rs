//! The handlers of a VyOS configuration: typed structures from the stanza
//! tree. Each handler records the stanzas that it reads.

use std::collections::{BTreeMap, BTreeSet};

use crate::stanza::{Body, Document, Stanza};

/// A line range of the canonical form.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lines {
    pub first: u32,
    pub last: u32,
}

impl Lines {
    fn of(s: &Stanza) -> Lines {
        Lines {
            first: s.first_line,
            last: s.last_line,
        }
    }
}

/// The kind of an interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Ethernet,
    Dummy,
    Loopback,
    Pppoe,
    Wireguard,
}

/// An interface or a VLAN subinterface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    /// The name of the interface in the kernel, for example `eth0.10`.
    pub name: String,
    pub kind: Kind,
    /// The static addresses with their prefix length, for example
    /// `192.0.2.1/24`.
    pub addresses: Vec<String>,
    /// The address options that the device sets at run time, for example
    /// `dhcp`, `dhcpv6` or `autoconf`.
    pub dynamic: Vec<String>,
    pub disabled: bool,
    /// The underlay interface of a PPPoE interface.
    pub source_interface: Option<String>,
    /// The VRF of the interface, `None` for the default VRF.
    pub vrf: Option<String>,
    /// The listen port of a WireGuard interface.
    pub port: Option<String>,
    /// The peers of a WireGuard interface that are not disabled, in name
    /// order.
    pub peers: Vec<WireguardPeer>,
    /// The text of the `description` option.
    pub description: Option<(String, Lines)>,
    pub lines: Lines,
}

/// A peer of a WireGuard interface. The keys are not read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireguardPeer {
    pub name: String,
    pub allowed_ips: Vec<String>,
    /// The address of the endpoint.
    pub address: Option<String>,
    /// The UDP port of the endpoint.
    pub port: Option<String>,
    pub lines: Lines,
}

/// The action of a firewall rule or of a default action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Accept,
    Drop,
    Reject,
    /// An action that the handler does not know. The rule is unhandled.
    Other(String),
}

impl Action {
    fn parse(s: &str) -> Action {
        match s {
            "accept" => Action::Accept,
            "drop" => Action::Drop,
            "reject" => Action::Reject,
            other => Action::Other(other.to_string()),
        }
    }
}

/// The source or the destination of a rule, as text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Side {
    pub address: Option<String>,
    pub port: Option<String>,
    pub address_group: Option<String>,
    pub network_group: Option<String>,
    pub port_group: Option<String>,
}

/// The match options of a rule, as text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleMatch {
    pub protocol: Option<String>,
    pub source: Side,
    pub destination: Side,
    pub inbound_interface: Option<String>,
    pub outbound_interface: Option<String>,
    pub icmp_type_name: Option<String>,
    pub state: Vec<String>,
}

/// A rule of a firewall rule set, a NAT rule or a policy route rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub number: u32,
    pub action: Option<Action>,
    pub matches: RuleMatch,
    pub disabled: bool,
    /// The translation address of a NAT rule, for example `masquerade`.
    pub translation_address: Option<String>,
    pub translation_port: Option<String>,
    /// The table of a policy route rule, for example `main` or `100`.
    pub table: Option<String>,
    /// The options with no handler. A rule with such an option is
    /// unhandled.
    pub unhandled: Vec<String>,
    pub lines: Lines,
}

/// The IP family of a rule set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

/// A named firewall rule set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSet {
    pub family: Family,
    pub name: String,
    pub default_action: Option<Action>,
    /// The rules, by rule number.
    pub rules: Vec<Rule>,
    pub lines: Lines,
}

/// The rule sets of the traffic from one zone to another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneFrom {
    pub from: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub lines: Lines,
}

/// A firewall zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Zone {
    pub name: String,
    pub members: Vec<String>,
    /// The VRFs of `member vrf`.
    pub member_vrfs: Vec<String>,
    pub local: bool,
    pub default_action: Option<Action>,
    /// The action of the traffic between 2 interfaces of the zone.
    pub intra_zone: Option<Action>,
    pub from: Vec<ZoneFrom>,
    pub lines: Lines,
}

/// The actions of the global state policy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatePolicy {
    pub established: Option<Action>,
    pub related: Option<Action>,
    pub invalid: Option<Action>,
    pub lines: Lines,
}

/// A static route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticRoute {
    pub prefix: String,
    /// The table, `None` for the main table.
    pub table: Option<String>,
    pub gateways: Vec<String>,
    pub interfaces: Vec<String>,
    pub blackhole: bool,
    /// The administrative distance of each next hop that states one, by
    /// `next-hop <address>`, `interface <name>` or `blackhole`.
    pub distances: BTreeMap<String, u8>,
    pub unhandled: Vec<String>,
    pub lines: Lines,
}

/// A policy route set with its interfaces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRoute {
    /// `V4` for `policy route`, `V6` for `policy route6`.
    pub family: Family,
    pub name: String,
    pub interfaces: Vec<String>,
    pub rules: Vec<Rule>,
    pub lines: Lines,
}

/// A QoS policy on an interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Qos {
    pub interface: String,
    pub direction: String,
    pub policy: String,
    pub lines: Lines,
}

/// The handled parts of a VyOS configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub interfaces: Vec<Interface>,
    pub zones: Vec<Zone>,
    pub rule_sets: Vec<RuleSet>,
    pub address_groups: Groups,
    pub network_groups: Groups,
    pub port_groups: Groups,
    pub ipv6_address_groups: Groups,
    pub ipv6_network_groups: Groups,
    pub state_policy: StatePolicy,
    pub source_nat: Vec<Rule>,
    pub destination_nat: Vec<Rule>,
    pub policy_routes: Vec<PolicyRoute>,
    pub static_routes: Vec<StaticRoute>,
    pub qos: Vec<Qos>,
    /// True if the config has a global forward filter, which the handlers
    /// do not read.
    pub forward_filter: bool,
    /// True if the config has a global input filter, which the handlers do
    /// not read.
    pub input_filter: bool,
    /// True if the config has a global output filter, which the handlers
    /// do not read.
    pub output_filter: bool,
    /// True if the config has policy routes of the packets of the router
    /// itself (`policy local-route` or `local-route6`), which the handlers
    /// do not read.
    pub local_route: bool,
    /// The children of `protocols` that can add routes, for example `bgp`
    /// or `ospf`.
    pub routing_protocols: Vec<(String, Lines)>,
    /// The BGP processes, neighbours and listen ranges.
    pub bgp: crate::bgp_peers::BgpConfig,
    /// The first lines of the stanzas that the handlers read.
    pub read: BTreeSet<u32>,
}

impl Config {
    /// The rule set of a family and a name.
    pub fn rule_set(&self, family: Family, name: &str) -> Option<&RuleSet> {
        self.rule_sets
            .iter()
            .find(|r| r.family == family && r.name == name)
    }
}

/// Firewall groups by name: the members with the members of the `include`
/// groups, or the reason that the members are not known.
pub type Groups = BTreeMap<String, Result<Vec<String>, String>>;

/// The children of `protocols` that add no routes to the route table.
pub(crate) const NO_ROUTES: &[&str] = &["static", "pim", "igmp-proxy"];

struct Reader {
    read: BTreeSet<u32>,
}

impl Reader {
    fn mark(&mut self, s: &Stanza) {
        self.read.insert(s.first_line);
    }

    fn mark_all(&mut self, s: &Stanza) {
        self.read.insert(s.first_line);
        for c in s.children() {
            self.mark_all(c);
        }
    }

    /// The child at a path, with the stanzas on the path marked.
    fn at<'a>(&mut self, s: &'a Stanza, path: &[&str]) -> Option<&'a Stanza> {
        let mut cur = s;
        for k in path {
            cur = cur.get(k)?;
            self.mark(cur);
        }
        Some(cur)
    }

    /// The texts of a leaf, with the leaf marked as a whole.
    fn texts(&mut self, s: &Stanza, key: &str) -> Vec<String> {
        match s.get(key) {
            Some(c) => {
                self.mark_all(c);
                c.texts().into_iter().map(str::to_string).collect()
            }
            None => Vec::new(),
        }
    }

    fn text(&mut self, s: &Stanza, key: &str) -> Option<String> {
        self.texts(s, key).into_iter().next()
    }

    /// True if the stanza has the key, with the key marked as a whole.
    fn flag(&mut self, s: &Stanza, key: &str) -> bool {
        match s.get(key) {
            Some(c) => {
                self.mark_all(c);
                true
            }
            None => false,
        }
    }
}

fn members(s: &Stanza) -> &[Stanza] {
    match &s.body {
        Body::Object(c) => c,
        _ => &[],
    }
}

/// Reads the handled parts of a VyOS configuration.
pub fn read(doc: &Document) -> Config {
    let mut r = Reader {
        read: BTreeSet::new(),
    };
    let root = &doc.root;
    let mut c = Config::default();
    if let Some(ifs) = r.at(root, &["interfaces"]) {
        read_interfaces(&mut r, ifs, &mut c);
    }
    if let Some(fw) = r.at(root, &["firewall"]) {
        read_firewall(&mut r, fw, &mut c);
    }
    if let Some(nat) = r.at(root, &["nat"]) {
        if let Some(src) = r.at(nat, &["source", "rule"]) {
            c.source_nat = read_rules(&mut r, src);
        }
        if let Some(dst) = r.at(nat, &["destination", "rule"]) {
            c.destination_nat = read_rules(&mut r, dst);
        }
    }
    if let Some(policy) = root.get("policy") {
        c.local_route = policy.get("local-route").is_some() || policy.get("local-route6").is_some();
    }
    if let Some(policy) = r.at(root, &["policy"]) {
        for (key, family) in [("route", Family::V4), ("route6", Family::V6)] {
            let Some(route) = r.at(policy, &[key]) else {
                continue;
            };
            for p in members(route) {
                r.mark(p);
                let rules = r
                    .at(p, &["rule"])
                    .map(|x| read_rules(&mut r, x))
                    .unwrap_or_default();
                c.policy_routes.push(PolicyRoute {
                    family,
                    name: p.key.clone(),
                    interfaces: r.texts(p, "interface"),
                    rules,
                    lines: Lines::of(p),
                });
            }
        }
    }
    if let Some(protocols) = root.get("protocols") {
        c.routing_protocols = members(protocols)
            .iter()
            .filter(|p| !NO_ROUTES.contains(&p.key.as_str()))
            .map(|p| (p.key.clone(), Lines::of(p)))
            .collect();
    }
    if let Some(st) = r.at(root, &["protocols"]).and_then(|p| p.get("static")) {
        r.mark(st);
        if let Some(routes) = st.get("route") {
            r.mark(routes);
            read_static(&mut r, routes, None, &mut c);
        }
        if let Some(routes) = st.get("route6") {
            r.mark(routes);
            read_static(&mut r, routes, None, &mut c);
        }
        if let Some(tables) = st.get("table") {
            r.mark(tables);
            for t in members(tables) {
                r.mark(t);
                for key in ["route", "route6"] {
                    if let Some(routes) = t.get(key) {
                        r.mark(routes);
                        read_static(&mut r, routes, Some(t.key.clone()), &mut c);
                    }
                }
            }
        }
    }
    if let Some(qos) = r.at(root, &["qos"]) {
        r.mark_all(qos);
        if let Some(ifs) = qos.get("interface") {
            for i in members(ifs) {
                for d in members(i) {
                    c.qos.push(Qos {
                        interface: i.key.clone(),
                        direction: d.key.clone(),
                        policy: d.text().unwrap_or_default().to_string(),
                        lines: Lines::of(d),
                    });
                }
            }
        }
    }
    c.bgp = super::bgp::read(root, &mut r.read);
    super::ospf_config::mark(root, &mut r.read);
    c.read = r.read;
    c
}

fn read_interfaces(r: &mut Reader, ifs: &Stanza, c: &mut Config) {
    let kinds = [
        ("ethernet", Kind::Ethernet),
        ("dummy", Kind::Dummy),
        ("loopback", Kind::Loopback),
        ("pppoe", Kind::Pppoe),
        ("wireguard", Kind::Wireguard),
    ];
    for (key, kind) in kinds {
        let Some(group) = ifs.get(key) else {
            continue;
        };
        r.mark(group);
        for i in members(group) {
            r.mark(i);
            let parent = read_interface(r, i, i.key.clone(), kind);
            let parent_disabled = parent.disabled;
            c.interfaces.push(parent);
            if let Some(vifs) = i.get("vif") {
                r.mark(vifs);
                for v in members(vifs) {
                    r.mark(v);
                    let name = format!("{}.{}", i.key, v.key);
                    let mut vif = read_interface(r, v, name, kind);
                    vif.disabled |= parent_disabled;
                    c.interfaces.push(vif);
                }
            }
        }
    }
}

fn read_interface(r: &mut Reader, s: &Stanza, name: String, kind: Kind) -> Interface {
    let mut addresses = Vec::new();
    let mut dynamic = Vec::new();
    for a in r.texts(s, "address") {
        if a.contains('/') {
            addresses.push(a);
        } else {
            dynamic.push(a);
        }
    }
    if let Some(v6) = s.get("ipv6") {
        r.mark(v6);
        if let Some(a) = v6.get("address") {
            r.mark_all(a);
            for opt in members(a) {
                dynamic.push(format!("ipv6-{}", opt.key));
            }
        }
    }
    if let Some(ip) = s.get("ip") {
        r.mark(ip);
    }
    if let Some(pd) = s.get("dhcpv6-options") {
        r.mark_all(pd);
        dynamic.push("dhcpv6-pd".to_string());
    }
    if kind == Kind::Pppoe {
        dynamic.push("pppoe".to_string());
        r.flag(s, "default-route");
    }
    let mut peers = Vec::new();
    if let Some(ps) = s.get("peer") {
        r.mark(ps);
        for p in members(ps) {
            r.mark(p);
            let peer = WireguardPeer {
                name: p.key.clone(),
                allowed_ips: r.texts(p, "allowed-ips"),
                address: r.text(p, "address"),
                port: r.text(p, "port"),
                lines: Lines::of(p),
            };
            if !r.flag(p, "disable") {
                peers.push(peer);
            }
        }
    }
    peers.sort_by(|a, b| a.name.cmp(&b.name));
    let description = match s.get("description") {
        Some(d) => r.text(s, "description").map(|t| (t, Lines::of(d))),
        None => None,
    };
    Interface {
        description,
        name,
        kind,
        addresses,
        dynamic,
        disabled: r.flag(s, "disable"),
        source_interface: r.text(s, "source-interface"),
        vrf: r.text(s, "vrf"),
        port: r.text(s, "port"),
        peers,
        lines: Lines::of(s),
    }
}

fn read_firewall(r: &mut Reader, fw: &Stanza, c: &mut Config) {
    for family in ["ipv4", "ipv6"] {
        c.forward_filter |= fw.at(&[family, "forward"]).is_some();
        c.input_filter |= fw.at(&[family, "input"]).is_some();
        c.output_filter |= fw.at(&[family, "output"]).is_some();
    }
    if let Some(groups) = fw.get("group") {
        r.mark(groups);
        for key in [
            "address-group",
            "network-group",
            "port-group",
            "ipv6-address-group",
            "ipv6-network-group",
        ] {
            let Some(g) = groups.get(key) else {
                continue;
            };
            r.mark_all(g);
            let (field, map) = match key {
                "port-group" => ("port", &mut c.port_groups),
                "network-group" => ("network", &mut c.network_groups),
                "ipv6-network-group" => ("network", &mut c.ipv6_network_groups),
                "ipv6-address-group" => ("address", &mut c.ipv6_address_groups),
                _ => ("address", &mut c.address_groups),
            };
            *map = read_groups(g, field);
        }
    }
    if let Some(sp) = r.at(fw, &["global-options", "state-policy"]) {
        r.mark_all(sp);
        let action = |k: &str| {
            sp.at(&[k, "action"])
                .and_then(Stanza::text)
                .map(Action::parse)
        };
        c.state_policy = StatePolicy {
            established: action("established"),
            related: action("related"),
            invalid: action("invalid"),
            lines: Lines::of(sp),
        };
    }
    for (key, family) in [("ipv4", Family::V4), ("ipv6", Family::V6)] {
        let Some(names) = r.at(fw, &[key, "name"]) else {
            continue;
        };
        for n in members(names) {
            r.mark(n);
            let rules = r
                .at(n, &["rule"])
                .map(|x| read_rules(r, x))
                .unwrap_or_default();
            c.rule_sets.push(RuleSet {
                family,
                name: n.key.clone(),
                default_action: r.text(n, "default-action").map(|a| Action::parse(&a)),
                rules,
                lines: Lines::of(n),
            });
        }
    }
    if let Some(zones) = r.at(fw, &["zone"]) {
        for z in members(zones) {
            r.mark(z);
            let mut from = Vec::new();
            if let Some(f) = z.get("from") {
                r.mark(f);
                for x in members(f) {
                    r.mark(x);
                    let fwk = x.get("firewall");
                    if let Some(fwk) = fwk {
                        r.mark(fwk);
                    }
                    from.push(ZoneFrom {
                        from: x.key.clone(),
                        ipv4: fwk.and_then(|f| r.text(f, "name")),
                        ipv6: fwk.and_then(|f| r.text(f, "ipv6-name")),
                        lines: Lines::of(x),
                    });
                }
            }
            let (members_of, member_vrfs) = z
                .get("member")
                .map(|m| {
                    r.mark(m);
                    (r.texts(m, "interface"), r.texts(m, "vrf"))
                })
                .unwrap_or_default();
            let intra = z.get("intra-zone-filtering").map(|i| {
                r.mark_all(i);
                i.get("action")
                    .and_then(Stanza::text)
                    .map_or(Action::Other("firewall".into()), Action::parse)
            });
            c.zones.push(Zone {
                name: z.key.clone(),
                members: members_of,
                member_vrfs,
                local: r.flag(z, "local-zone"),
                default_action: r.text(z, "default-action").map(|a| Action::parse(&a)),
                intra_zone: intra,
                from,
                lines: Lines::of(z),
            });
        }
    }
}

/// The options that a rule handler reads. An option that is not here makes
/// the rule unhandled.
const RULE_KEYS: &[&str] = &[
    "action",
    "disable",
    "protocol",
    "state",
    "source",
    "destination",
    "inbound-interface",
    "outbound-interface",
    "icmp",
    "translation",
    "set",
];

const SIDE_KEYS: &[&str] = &["address", "port", "group"];
const GROUP_KEYS: &[&str] = &["address-group", "network-group", "port-group"];

/// The members of an option other than `known`, each as `<key> <member>`.
fn others(s: &Stanza, key: &str, known: &[&str]) -> Vec<String> {
    members(s)
        .iter()
        .filter(|o| !known.contains(&o.key.as_str()))
        .map(|o| format!("{key} {}", o.key))
        .collect()
}

/// The groups of one kind, each with the members of its `include` groups.
/// An include of a group that does not exist, or an option other than
/// `field`, `include` and `description`, makes the members of the group
/// unknown.
fn read_groups(g: &Stanza, field: &str) -> Groups {
    let texts = |x: &Stanza, k: &str| -> Vec<String> {
        x.get(k)
            .map(|v| v.texts().into_iter().map(str::to_string).collect())
            .unwrap_or_default()
    };
    let by_name: BTreeMap<&str, &Stanza> = members(g).iter().map(|x| (x.key.as_str(), x)).collect();
    let mut out = Groups::new();
    for name in by_name.keys() {
        let mut values: Vec<String> = Vec::new();
        let mut problem = None;
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut stack: Vec<String> = vec![(*name).to_string()];
        while let Some(n) = stack.pop() {
            let Some(x) = by_name.get(n.as_str()) else {
                problem = Some(format!("{} {n} does not exist", g.key));
                break;
            };
            if !seen.insert(x.key.as_str()) {
                continue;
            }
            if let Some(o) = members(x)
                .iter()
                .find(|o| ![field, "include", "description"].contains(&o.key.as_str()))
            {
                problem = Some(format!("{} {n} has the option {}", g.key, o.key));
                break;
            }
            for v in texts(x, field) {
                if !values.contains(&v) {
                    values.push(v);
                }
            }
            stack.extend(texts(x, "include").into_iter().rev());
        }
        out.insert((*name).to_string(), problem.map_or(Ok(values), Err));
    }
    out
}

fn read_rules(r: &mut Reader, rules: &Stanza) -> Vec<Rule> {
    let mut out = Vec::new();
    for x in members(rules) {
        r.mark(x);
        let mut unhandled = Vec::new();
        for opt in members(x) {
            if !RULE_KEYS.contains(&opt.key.as_str())
                && opt.key != "description"
                && opt.key != "log"
            {
                unhandled.push(opt.key.clone());
            }
        }
        let side = |r: &mut Reader, key: &str, unhandled: &mut Vec<String>| -> Side {
            let Some(s) = x.get(key) else {
                return Side::default();
            };
            r.mark(s);
            for o in members(s) {
                if !SIDE_KEYS.contains(&o.key.as_str()) {
                    unhandled.push(format!("{key} {}", o.key));
                }
            }
            let mut side = Side {
                address: r.text(s, "address"),
                port: r.text(s, "port"),
                ..Side::default()
            };
            if let Some(g) = s.get("group") {
                r.mark(g);
                for o in members(g) {
                    if !GROUP_KEYS.contains(&o.key.as_str()) {
                        unhandled.push(format!("{key} group {}", o.key));
                    }
                }
                side.address_group = r.text(g, "address-group");
                side.network_group = r.text(g, "network-group");
                side.port_group = r.text(g, "port-group");
            }
            side
        };
        let source = side(r, "source", &mut unhandled);
        let destination = side(r, "destination", &mut unhandled);
        let iface = |r: &mut Reader, key: &str, unhandled: &mut Vec<String>| {
            x.get(key).and_then(|s| {
                r.mark(s);
                if !matches!(s.body, Body::Object(_)) {
                    unhandled.push(key.to_string());
                    return None;
                }
                unhandled.extend(others(s, key, &["name"]));
                r.text(s, "name")
            })
        };
        let inbound_interface = iface(r, "inbound-interface", &mut unhandled);
        let outbound_interface = iface(r, "outbound-interface", &mut unhandled);
        let icmp_type_name = x.get("icmp").and_then(|s| {
            r.mark(s);
            unhandled.extend(others(s, "icmp", &["type-name"]));
            r.text(s, "type-name")
        });
        let (translation_address, translation_port) = match x.get("translation") {
            Some(t) => {
                r.mark(t);
                unhandled.extend(others(t, "translation", &["address", "port"]));
                (r.text(t, "address"), r.text(t, "port"))
            }
            None => (None, None),
        };
        let table = x.get("set").and_then(|s| {
            r.mark(s);
            for o in members(s) {
                if o.key != "table" {
                    unhandled.push(format!("set {}", o.key));
                }
            }
            r.text(s, "table")
        });
        let state = r.texts(x, "state");
        if state.is_empty() && x.get("state").is_some() {
            unhandled.push("state".to_string());
        }
        out.push(Rule {
            number: x.key.parse().unwrap_or(u32::MAX),
            action: r.text(x, "action").map(|a| Action::parse(&a)),
            matches: RuleMatch {
                protocol: r.text(x, "protocol"),
                source,
                destination,
                inbound_interface,
                outbound_interface,
                icmp_type_name,
                state,
            },
            disabled: r.flag(x, "disable"),
            translation_address,
            translation_port,
            table,
            unhandled,
            lines: Lines::of(x),
        });
    }
    out.sort_by_key(|x| x.number);
    out
}

/// The `distance` of a next hop of a static route: a number from 1 to 255.
fn distance(r: &mut Reader, h: &Stanza, key: &str, route: &mut StaticRoute) {
    let Some(d) = r.text(h, "distance") else {
        return;
    };
    match d.parse::<u8>() {
        Ok(n) if n > 0 => {
            route.distances.insert(key.to_string(), n);
        }
        _ => route.unhandled.push(format!("{key} distance {d}")),
    }
}

fn read_static(r: &mut Reader, routes: &Stanza, table: Option<String>, c: &mut Config) {
    for p in members(routes) {
        r.mark(p);
        let mut route = StaticRoute {
            prefix: p.key.clone(),
            table: table.clone(),
            gateways: Vec::new(),
            interfaces: Vec::new(),
            blackhole: false,
            distances: BTreeMap::new(),
            unhandled: Vec::new(),
            lines: Lines::of(p),
        };
        for opt in members(p) {
            match opt.key.as_str() {
                "next-hop" | "interface" => {
                    r.mark_all(opt);
                    for h in members(opt) {
                        if h.get("disable").is_some() {
                            continue;
                        }
                        let key = format!("{} {}", opt.key, h.key);
                        route.unhandled.extend(others(h, &key, &["distance"]));
                        distance(r, h, &key, &mut route);
                        if opt.key == "next-hop" {
                            route.gateways.push(h.key.clone());
                        } else {
                            route.interfaces.push(h.key.clone());
                        }
                    }
                }
                "blackhole" => {
                    r.mark_all(opt);
                    route
                        .unhandled
                        .extend(others(opt, "blackhole", &["distance"]));
                    distance(r, opt, "blackhole", &mut route);
                    route.blackhole = true;
                }
                "description" => r.mark_all(opt),
                other => route.unhandled.push(other.to_string()),
            }
        }
        c.static_routes.push(route);
    }
}
