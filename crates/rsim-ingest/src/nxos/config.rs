//! The handlers of an NX-OS running config: the typed structures of the
//! lines that the lowering reads.

use std::collections::{BTreeMap, BTreeSet};

use crate::coverage::{State, Table};
use crate::stanza::{Document, Stanza};

/// The first and the last line of a stanza.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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

/// The NAT role of an interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatRole {
    Inside,
    Outside,
}

/// An IPv4 address of an interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    /// The address with its prefix length, for example `192.0.2.1/24`.
    pub prefix: String,
    pub secondary: bool,
    pub lines: Lines,
}

/// A layer 3 interface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    /// `Some(false)` with `shutdown`, `Some(true)` with `no shutdown`, and
    /// `None` if the config has neither line.
    pub admin_up: Option<bool>,
    pub vrf: Option<String>,
    pub addresses: Vec<Address>,
    /// An address that the config does not state, for example from DHCP.
    pub dynamic_address: bool,
    /// The IPv6 addresses of the `ipv6 address` lines with their prefix
    /// length, for example `2001:db8::1/64`. An address that the config
    /// does not state in full, as with `eui64`, is not listed.
    pub ipv6: Vec<(String, Lines)>,
    pub acl_in: Option<(String, Lines)>,
    pub acl_out: Option<(String, Lines)>,
    pub nat: Option<(NatRole, Lines)>,
    /// The QoS policies of the input and the output.
    pub qos_in: Option<(String, Lines)>,
    pub qos_out: Option<(String, Lines)>,
    /// `Some(true)` with a `switchport` line, `Some(false)` with
    /// `no switchport`, and `None` with neither.
    pub switchport: Option<bool>,
    pub mode: Option<PortMode>,
    pub access_vlan: Option<u16>,
    pub native_vlan: Option<u16>,
    /// The allowed VLANs of a trunk as ranges, or `None` if the config does
    /// not state them.
    pub allowed: Option<Vec<(u16, u16)>>,
    /// The port channel of a member port.
    pub channel_group: Option<u32>,
    /// The HSRP and VRRP groups.
    pub fhrp: Vec<Fhrp>,
    /// The vPC role of a port channel.
    pub vpc: Option<VpcPort>,
    /// True with `ip forward`: the interface routes with no address of its
    /// own, for example the SVI of a layer 3 VNI.
    pub ip_forward: bool,
    /// True with `fabric forwarding mode anycast-gateway`.
    pub anycast_gateway: bool,
    /// The text of the `description` line.
    pub description: Option<(String, Lines)>,
    /// The masked lines of the unhandled options of the interface.
    pub unhandled: Vec<String>,
    pub lines: Lines,
}

/// The vPC role of a port channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VpcPort {
    PeerLink,
    Member(u32),
}

/// The vPC domain of a switch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VpcDomain {
    pub id: u32,
    pub peer_gateway: bool,
    /// The masked lines of the domain that the lowering does not read.
    pub unhandled: Vec<String>,
    pub lines: Lines,
}

/// The mode of a switch port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortMode {
    Access,
    Trunk,
}

/// The protocol of a gateway group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FhrpKind {
    Hsrp,
    Vrrp,
}

/// An HSRP or a VRRP group of an interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fhrp {
    pub kind: FhrpKind,
    pub group: u32,
    /// The virtual address.
    pub vip: Option<String>,
    pub lines: Lines,
}

/// How a VNI sends its broadcast and unknown frames to the other tunnel
/// ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Replication {
    /// A copy to each peer tunnel end that BGP gives.
    Ingress,
    /// One copy to a multicast group of the underlay.
    Multicast(String),
    /// The config states neither.
    Unstated,
}

/// A `member vni` of the NVE interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NveMember {
    pub vni: u32,
    /// True with `associate-vrf`: a layer 3 VNI.
    pub l3: bool,
    pub replication: Replication,
    pub lines: Lines,
}

/// The NVE interface: the VXLAN tunnel end of the switch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Nve {
    pub name: String,
    pub admin_up: Option<bool>,
    /// The interface whose address is the tunnel end.
    pub source: Option<(String, Lines)>,
    /// True with `host-reachability protocol bgp`.
    pub bgp: bool,
    /// The replication of a member with no replication line, from a
    /// `global` line.
    pub global: Option<Replication>,
    pub members: Vec<NveMember>,
    /// The masked lines that the lowering does not read.
    pub unhandled: Vec<String>,
    pub lines: Lines,
}

/// The action of an ACL entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AclAction {
    Permit,
    Deny,
}

/// The address of one side of an ACL entry or a member of an address group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddrSpec {
    Any,
    /// An address with a prefix length, or a host address.
    Prefix(String),
    /// An address with a wildcard mask.
    Wildcard(String, String),
    /// An address group.
    Group(String),
}

/// The port condition of one side of an ACL entry or a member of a port
/// group. A port is a number or a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortSpec {
    Any,
    Eq(Vec<String>),
    Neq(String),
    Lt(String),
    Gt(String),
    Range(String, String),
    Group(String),
}

/// An entry of an IP access list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ace {
    pub seq: String,
    pub action: AclAction,
    /// The protocol as written, for example `tcp`, `ip` or `47`.
    pub protocol: String,
    pub source: AddrSpec,
    pub source_port: PortSpec,
    pub destination: AddrSpec,
    pub destination_port: PortSpec,
    /// The ICMP type as written, with the code if there is one.
    pub icmp: Option<(String, Option<String>)>,
    pub established: bool,
    /// The words of the options that the lowering does not read.
    pub unhandled: Vec<String>,
    pub lines: Lines,
}

/// An IP access list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Acl {
    pub name: String,
    pub entries: Vec<Ace>,
    /// The masked lines that the handler cannot read.
    pub unreadable: Vec<String>,
    pub lines: Lines,
}

/// A static route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticRoute {
    pub vrf: String,
    pub prefix: String,
    pub interface: Option<String>,
    pub next_hop: Option<String>,
    /// The preference of the route, 1 if the line states none.
    pub preference: u8,
    /// The words that the lowering does not read, for example `vrf`.
    pub unhandled: Vec<String>,
    pub lines: Lines,
}

/// The target of a dynamic NAT rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NatTarget {
    Pool(String),
    Interface(String),
}

/// A NAT rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NatKind {
    /// `ip nat inside source static [tcp|udp] <local> [<port>] <global> [<port>]`.
    Static {
        protocol: Option<String>,
        local: String,
        local_port: Option<String>,
        global: String,
        global_port: Option<String>,
        /// The word of the line that the lowering does not model, for
        /// example `extendable`. The packets that the rule can translate
        /// are then `Unknown`.
        uncertain: Option<String>,
    },
    /// `ip nat inside source list <acl> pool <pool>|interface <if> [overload]`.
    List {
        acl: String,
        target: NatTarget,
        overload: bool,
    },
    /// A form that the lowering does not read, as the masked line.
    Other(String),
}

/// A NAT rule with its lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NatRule {
    pub kind: NatKind,
    pub lines: Lines,
}

/// A NAT pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NatPool {
    pub start: String,
    pub end: String,
    pub lines: Lines,
}

/// The typed structures of a running config.
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub interfaces: Vec<Interface>,
    pub acls: BTreeMap<String, Acl>,
    pub address_groups: BTreeMap<String, Vec<AddrSpec>>,
    pub port_groups: BTreeMap<String, Vec<PortSpec>>,
    pub static_routes: Vec<StaticRoute>,
    /// The VRFs of the config, with the lines of their `vrf context`.
    pub vrfs: BTreeMap<String, Lines>,
    pub nat_rules: Vec<NatRule>,
    pub nat_pools: BTreeMap<String, NatPool>,
    /// The VLANs of the `vlan` lines, as ranges.
    pub vlans: Vec<(u16, u16)>,
    /// The VLANs with a line that the lowering does not read.
    pub unknown_vlans: Vec<(u16, u16)>,
    /// The masked `vlan filter` lines with their VLANs, 1-4094 if the list
    /// cannot be read.
    pub vlan_filters: Vec<(String, Vec<(u16, u16)>)>,
    /// The masked `vlan dot1q tag native` line.
    pub native_tagging: Option<String>,
    /// The VNI of each VLAN with `vn-segment`.
    pub segments: BTreeMap<u16, (u32, Lines)>,
    /// The NVE interface.
    pub nve: Option<Nve>,
    /// The layer 3 VNI of each VRF, from `vrf context */vni`.
    pub vrf_vnis: BTreeMap<String, (u32, Lines)>,
    /// The MAC of `fabric forwarding anycast-gateway-mac`.
    pub anycast_mac: Option<(String, Lines)>,
    /// True if `router bgp` has an `advertise-pip` line, with its lines.
    pub advertise_pip: Option<Lines>,
    /// The BGP processes, neighbours and listen ranges.
    pub bgp: crate::bgp_peers::BgpConfig,
    /// The name of the line `hostname`.
    pub hostname: Option<String>,
    pub vpc_domain: Option<VpcDomain>,
    /// The masked `vlan` lines whose list the handler cannot read.
    pub unreadable_vlans: Vec<String>,
    /// `Some(true)` with `system default switchport`, `Some(false)` with
    /// `no system default switchport`.
    pub default_switchport: Option<bool>,
    /// The VRFs with a dynamic routing protocol, with the lines that show
    /// it.
    pub dynamic_vrfs: BTreeMap<String, Vec<(u32, u32)>>,
    /// The first line of each stanza that a handler read.
    pub read: BTreeSet<u32>,
}

struct R<'a> {
    table: &'a Table,
    read: BTreeSet<u32>,
}

impl R<'_> {
    fn mark(&mut self, s: &Stanza) {
        self.read.insert(s.first_line);
    }

    /// The masked keys of the stanzas below a stanza that the table
    /// classifies as unhandled, at the top of each unhandled part.
    fn unhandled_children(&self, parent: &Stanza) -> Vec<String> {
        let mut out = Vec::new();
        let mut path = vec![parent.key.as_str()];
        self.unhandled_below(parent, &mut path, &mut out);
        out
    }

    fn unhandled_below<'a>(&self, s: &'a Stanza, path: &mut Vec<&'a str>, out: &mut Vec<String>) {
        for c in s.children() {
            path.push(&c.key);
            if self.table.state(path) == State::Unhandled {
                out.push(self.table.report_key(&c.key));
            } else {
                self.unhandled_below(c, path, out);
            }
            path.pop();
        }
    }
}

fn words(s: &str) -> Vec<&str> {
    s.split_whitespace().collect()
}

/// Reads the handled lines of a running config. `table` decides which
/// options of an interface are unhandled.
pub fn read(doc: &Document, table: &Table) -> Config {
    let mut r = R {
        table,
        read: BTreeSet::new(),
    };
    let mut cfg = Config::default();
    for s in doc.root.children() {
        let w = words(&s.key);
        match w.as_slice() {
            ["interface", name] if name.to_ascii_lowercase().starts_with("nve") => {
                cfg.nve = Some(nve(&mut r, s, name));
            }
            ["interface", name] => {
                let i = interface(&mut r, s, name);
                cfg.interfaces.push(i);
            }
            ["ip", "access-list", name] => {
                r.mark(s);
                let acl = access_list(&mut r, s, name);
                cfg.acls.insert((*name).to_string(), acl);
            }
            ["object-group", "ip", "address", name] => {
                r.mark(s);
                let mut members = Vec::new();
                for c in s.children() {
                    r.mark(c);
                    let cw = words(&c.key);
                    let rest = match cw.first() {
                        Some(x) if x.parse::<u32>().is_ok() => &cw[1..],
                        _ => &cw[..],
                    };
                    let mut i = 0;
                    match addr_spec(rest, &mut i) {
                        Some(a) if i == rest.len() => members.push(a),
                        _ => members.push(AddrSpec::Group(format!(
                            "(unreadable member {})",
                            table.report_key(&c.key)
                        ))),
                    }
                }
                cfg.address_groups.insert((*name).to_string(), members);
            }
            ["object-group", "ip", "port", name] => {
                r.mark(s);
                let mut members = Vec::new();
                for c in s.children() {
                    r.mark(c);
                    let cw = words(&c.key);
                    let rest = match cw.first() {
                        Some(x) if x.parse::<u32>().is_ok() => &cw[1..],
                        _ => &cw[..],
                    };
                    let mut i = 0;
                    let p = port_spec(rest, &mut i);
                    if i == rest.len() && p != PortSpec::Any {
                        members.push(p);
                    } else {
                        members.push(PortSpec::Group(format!(
                            "(unreadable member {})",
                            table.report_key(&c.key)
                        )));
                    }
                }
                cfg.port_groups.insert((*name).to_string(), members);
            }
            ["ip", "route", rest @ ..] => {
                r.mark(s);
                cfg.static_routes
                    .push(static_route("default", rest, Lines::of(s)));
            }
            ["vrf", "context", name] => {
                r.mark(s);
                cfg.vrfs.insert((*name).to_string(), Lines::of(s));
                for c in s.children() {
                    match words(&c.key).as_slice() {
                        ["ip", "route", rest @ ..] => {
                            r.mark(c);
                            cfg.static_routes
                                .push(static_route(name, rest, Lines::of(c)));
                        }
                        ["vni", n] => {
                            if let Ok(vni) = n.parse::<u32>() {
                                r.mark(c);
                                cfg.vrf_vnis
                                    .insert((*name).to_string(), (vni, Lines::of(c)));
                            }
                        }
                        _ => {}
                    }
                }
            }
            ["ip", "nat", "pool", name, start, end, ..] => {
                r.mark(s);
                cfg.nat_pools.insert(
                    (*name).to_string(),
                    NatPool {
                        start: (*start).to_string(),
                        end: (*end).to_string(),
                        lines: Lines::of(s),
                    },
                );
            }
            ["ip", "nat", "translation", ..] => {}
            ["hostname", h] => cfg.hostname = Some((*h).to_string()),
            ["router", "bgp", ..] => {
                fn find(s: &Stanza) -> Option<Lines> {
                    s.children().iter().find_map(|c| {
                        if c.key == "advertise-pip" {
                            Some(Lines::of(c))
                        } else {
                            find(c)
                        }
                    })
                }
                cfg.advertise_pip = find(s);
                cfg.bgp = super::bgp::read(s, &mut r.read, &|k| table.report_key(k));
            }
            ["fabric", "forwarding", "anycast-gateway-mac", m] => {
                r.mark(s);
                cfg.anycast_mac = Some(((*m).to_string(), Lines::of(s)));
            }
            ["vpc", "domain", n] => {
                r.mark(s);
                let mut d = VpcDomain {
                    id: n.parse().unwrap_or(u32::MAX),
                    lines: Lines::of(s),
                    unhandled: r.unhandled_children(s),
                    ..VpcDomain::default()
                };
                for c in s.children() {
                    if c.key == "peer-gateway" {
                        r.mark(c);
                        d.peer_gateway = true;
                    }
                }
                cfg.vpc_domain = Some(d);
            }
            ["vlan", list] => {
                r.mark(s);
                let Some(ranges) = vlan_list(list) else {
                    cfg.unreadable_vlans.push(table.report_key(&s.key));
                    continue;
                };
                let unknown = s
                    .children()
                    .iter()
                    .any(|c| table.state(&[s.key.as_str(), c.key.as_str()]) == State::Unhandled);
                if unknown {
                    cfg.unknown_vlans.extend(ranges.iter().copied());
                }
                for c in s.children() {
                    if let ["vn-segment", n] = words(&c.key).as_slice() {
                        r.mark(c);
                        match (ranges.as_slice(), n.parse::<u32>()) {
                            ([(a, b)], Ok(vni)) if a == b => {
                                cfg.segments.insert(*a, (vni, Lines::of(c)));
                            }
                            _ => cfg.unknown_vlans.extend(ranges.iter().copied()),
                        }
                    }
                }
                cfg.vlans.extend(ranges);
            }
            ["vlan", "filter", rest @ ..] => {
                let ranges = match rest {
                    [_, "vlan-list", list] => vlan_list(list),
                    _ => None,
                }
                .unwrap_or_else(|| vec![(1, 4094)]);
                cfg.unknown_vlans.extend(ranges.iter().copied());
                cfg.vlan_filters.push((table.report_key(&s.key), ranges));
            }
            ["vlan", dot1q, "tag", "native", ..] if dot1q.eq_ignore_ascii_case("dot1q") => {
                cfg.native_tagging = Some(table.report_key(&s.key));
            }
            ["system", "default", "switchport"] => {
                r.mark(s);
                cfg.default_switchport = Some(true);
            }
            ["no", "system", "default", "switchport"] => {
                r.mark(s);
                cfg.default_switchport = Some(false);
            }
            ["ip", "nat", "inside", "source", ..] => {
                r.mark(s);
                cfg.nat_rules.push(NatRule {
                    kind: nat_rule(&w, table),
                    lines: Lines::of(s),
                });
            }
            ["ip", "nat", ..] => {
                cfg.nat_rules.push(NatRule {
                    kind: NatKind::Other(table.report_key(&s.key)),
                    lines: Lines::of(s),
                });
            }
            _ => {}
        }
    }
    cfg.read = r.read;
    cfg.dynamic_vrfs = super::table::dynamic_vrfs(doc);
    cfg
}

/// The text of a `description` line.
pub(crate) fn description_text(line: &str) -> String {
    line.strip_prefix("description")
        .unwrap_or(line)
        .trim()
        .to_string()
}

fn interface(r: &mut R, s: &Stanza, name: &str) -> Interface {
    r.mark(s);
    let mut i = Interface {
        name: name.to_string(),
        lines: Lines::of(s),
        unhandled: r.unhandled_children(s),
        ..Interface::default()
    };
    for c in s.children() {
        let lines = Lines::of(c);
        let handled = match words(&c.key).as_slice() {
            ["shutdown"] => {
                i.admin_up = Some(false);
                true
            }
            ["no", "shutdown"] => {
                i.admin_up = Some(true);
                true
            }
            ["no", "switchport"] => {
                i.switchport = Some(false);
                true
            }
            ["switchport"] => {
                i.switchport = Some(true);
                true
            }
            ["switchport", "mode", m @ ("access" | "trunk")] => {
                i.switchport = Some(true);
                i.mode = Some(if *m == "access" {
                    PortMode::Access
                } else {
                    PortMode::Trunk
                });
                true
            }
            ["switchport", "access", "vlan", v] => {
                i.switchport = Some(true);
                match v.parse() {
                    Ok(v) => i.access_vlan = Some(v),
                    Err(_) => i.unhandled.push(r.table.report_key(&c.key)),
                }
                true
            }
            ["switchport", "trunk", "native", "vlan", v] => {
                i.switchport = Some(true);
                match v.parse() {
                    Ok(v) => i.native_vlan = Some(v),
                    Err(_) => i.unhandled.push(r.table.report_key(&c.key)),
                }
                true
            }
            ["switchport", "trunk", "allowed", "vlan", rest @ ..] => {
                i.switchport = Some(true);
                let list = match rest {
                    ["none"] => Some((false, Vec::new())),
                    ["all"] => Some((false, vec![(1, 4094)])),
                    ["add", l] => vlan_list(l).map(|v| (true, v)),
                    [l] => vlan_list(l).map(|v| (false, v)),
                    _ => None,
                };
                match list {
                    Some((true, v)) => i.allowed.get_or_insert_with(Vec::new).extend(v),
                    Some((false, v)) => i.allowed = Some(v),
                    None => i.unhandled.push(r.table.report_key(&c.key)),
                }
                true
            }
            ["channel-group", n, ..] => {
                match n.parse() {
                    Ok(n) => i.channel_group = Some(n),
                    Err(_) => i.unhandled.push(r.table.report_key(&c.key)),
                }
                true
            }
            ["hsrp", "version", _] => true,
            ["description", ..] => {
                i.description = Some((description_text(&c.key), lines));
                true
            }
            ["vpc", "peer-link"] => {
                i.vpc = Some(VpcPort::PeerLink);
                true
            }
            ["vpc", n] => {
                match n.parse() {
                    Ok(n) => i.vpc = Some(VpcPort::Member(n)),
                    Err(_) => i.unhandled.push(r.table.report_key(&c.key)),
                }
                true
            }
            [kind @ ("hsrp" | "vrrp"), n] => {
                let kind = if *kind == "hsrp" {
                    FhrpKind::Hsrp
                } else {
                    FhrpKind::Vrrp
                };
                let mut g = Fhrp {
                    kind,
                    group: n.parse().unwrap_or(u32::MAX),
                    vip: None,
                    lines,
                };
                for gc in c.children() {
                    if let ["ip" | "address", a] = words(&gc.key).as_slice() {
                        r.mark(gc);
                        g.vip = Some((*a).to_string());
                    }
                }
                i.fhrp.push(g);
                true
            }
            [
                "service-policy",
                "type",
                "qos",
                dir @ ("input" | "output"),
                name,
            ]
            | ["service-policy", dir @ ("input" | "output"), name] => {
                let q = Some(((*name).to_string(), lines));
                if *dir == "input" {
                    i.qos_in = q;
                } else {
                    i.qos_out = q;
                }
                true
            }
            ["vrf", "member", v] => {
                i.vrf = Some((*v).to_string());
                true
            }
            ["ip", "address", "dhcp"] => {
                i.dynamic_address = true;
                true
            }
            ["ip", "address", a, rest @ ..] => {
                let secondary = rest.first() == Some(&"secondary");
                let prefix = if a.contains('/') {
                    Some((*a).to_string())
                } else {
                    rest.first()
                        .and_then(|m| mask_len(m))
                        .map(|l| format!("{a}/{l}"))
                };
                match prefix {
                    Some(prefix) => i.addresses.push(Address {
                        prefix,
                        secondary,
                        lines,
                    }),
                    None => i.dynamic_address = true,
                }
                true
            }
            ["ipv6", "address", a, rest @ ..] => {
                if a.contains(':') && !rest.contains(&"eui64") {
                    i.ipv6.push(((*a).to_string(), lines));
                }
                true
            }
            ["ipv6", "address", ..] | ["ipv6", "link-local", ..] => true,
            ["ip", "access-group", acl, "in"] => {
                i.acl_in = Some(((*acl).to_string(), lines));
                true
            }
            ["ip", "access-group", acl, "out"] => {
                i.acl_out = Some(((*acl).to_string(), lines));
                true
            }
            ["ip", "nat", "inside"] => {
                i.nat = Some((NatRole::Inside, lines));
                true
            }
            ["ip", "forward"] => {
                i.ip_forward = true;
                true
            }
            ["fabric", "forwarding", "mode", "anycast-gateway"] => {
                i.anycast_gateway = true;
                true
            }
            ["ip", "nat", "outside"] => {
                i.nat = Some((NatRole::Outside, lines));
                true
            }
            _ => false,
        };
        if handled {
            r.mark(c);
        }
    }
    i
}

/// The replication of a `member vni` or a `global` line, or `None` for a
/// line that is not a replication line.
fn replication(w: &[&str]) -> Option<Replication> {
    match w {
        ["ingress-replication", "protocol", "bgp"] => Some(Replication::Ingress),
        ["mcast-group", g] | ["mcast-group", g, "L2"] => {
            Some(Replication::Multicast((*g).to_string()))
        }
        _ => None,
    }
}

fn nve(r: &mut R, s: &Stanza, name: &str) -> Nve {
    r.mark(s);
    let mut n = Nve {
        name: name.to_string(),
        lines: Lines::of(s),
        unhandled: r.unhandled_children(s),
        ..Nve::default()
    };
    for c in s.children() {
        let lines = Lines::of(c);
        let w = words(&c.key);
        let handled = match w.as_slice() {
            ["shutdown"] => {
                n.admin_up = Some(false);
                true
            }
            ["no", "shutdown"] => {
                n.admin_up = Some(true);
                true
            }
            ["source-interface", i] => {
                n.source = Some(((*i).to_string(), lines));
                true
            }
            ["host-reachability", "protocol", "bgp"] => {
                n.bgp = true;
                true
            }
            ["global", rest @ ..] => match replication(rest) {
                Some(rep) => {
                    n.global = Some(rep);
                    true
                }
                None => false,
            },
            ["member", "vni", v, rest @ ..] => {
                let l3 = rest == ["associate-vrf"];
                match v.parse::<u32>() {
                    Ok(vni) if rest.is_empty() || l3 => {
                        let mut m = NveMember {
                            vni,
                            l3,
                            replication: Replication::Unstated,
                            lines,
                        };
                        for gc in c.children() {
                            if let Some(rep) = replication(&words(&gc.key)) {
                                r.mark(gc);
                                m.replication = rep;
                            }
                        }
                        n.members.push(m);
                    }
                    _ => n.unhandled.push(r.table.report_key(&c.key)),
                }
                true
            }
            _ => false,
        };
        if handled {
            r.mark(c);
        }
    }
    n
}

/// The VLAN ranges of a list such as `1,10,20-25`, or `None` if a part is
/// not a VLAN or a range.
pub fn vlan_list(text: &str) -> Option<Vec<(u16, u16)>> {
    let mut out = Vec::new();
    for part in text.split(',') {
        let (a, b) = part.split_once('-').unwrap_or((part, part));
        let a: u16 = a.trim().parse().ok()?;
        let b: u16 = b.trim().parse().ok()?;
        if a == 0 || a > b || b > 4094 {
            return None;
        }
        out.push((a, b));
    }
    Some(out)
}

/// The prefix length of a contiguous dotted mask.
pub fn mask_len(mask: &str) -> Option<u8> {
    let m: std::net::Ipv4Addr = mask.parse().ok()?;
    let v = u32::from(m);
    let len = v.leading_ones();
    (v.checked_shl(len).unwrap_or(0) == 0).then(|| u8::try_from(len).unwrap_or(32))
}

fn access_list(r: &mut R, s: &Stanza, name: &str) -> Acl {
    let mut acl = Acl {
        name: name.to_string(),
        entries: Vec::new(),
        unreadable: Vec::new(),
        lines: Lines::of(s),
    };
    for c in s.children() {
        let w = words(&c.key);
        match w.as_slice() {
            ["statistics", ..] => {}
            [seq, "remark", ..] | ["remark", seq, ..] => {
                let _ = seq;
                r.mark(c);
            }
            [seq, action @ ("permit" | "deny"), rest @ ..] => {
                r.mark(c);
                let action = if *action == "permit" {
                    AclAction::Permit
                } else {
                    AclAction::Deny
                };
                match ace(seq, action, rest, Lines::of(c)) {
                    Some(e) => acl.entries.push(e),
                    None => acl.unreadable.push(r.table.report_key(&c.key)),
                }
            }
            _ => {
                r.mark(c);
                acl.unreadable.push(r.table.report_key(&c.key));
            }
        }
    }
    acl
}

/// Reads an address of an ACL entry from the words at `i`, and moves `i`
/// past it.
pub(crate) fn addr_spec(w: &[&str], i: &mut usize) -> Option<AddrSpec> {
    let first = *w.get(*i)?;
    let out = match first {
        "any" => {
            *i += 1;
            AddrSpec::Any
        }
        "host" => {
            let a = w.get(*i + 1)?;
            *i += 2;
            AddrSpec::Prefix(format!("{a}/32"))
        }
        "addrgroup" => {
            let g = w.get(*i + 1)?;
            *i += 2;
            AddrSpec::Group((*g).to_string())
        }
        a if a.contains('/') => {
            *i += 1;
            AddrSpec::Prefix(a.to_string())
        }
        a if a.parse::<std::net::Ipv4Addr>().is_ok() => {
            let wc = w.get(*i + 1)?;
            wc.parse::<std::net::Ipv4Addr>().ok()?;
            *i += 2;
            AddrSpec::Wildcard(a.to_string(), (*wc).to_string())
        }
        _ => return None,
    };
    Some(out)
}

/// Reads a port condition from the words at `i`, and moves `i` past it. No
/// port condition gives `Any`.
fn port_spec(w: &[&str], i: &mut usize) -> PortSpec {
    let at = |k: usize| w.get(*i + k).map(|s| (*s).to_string());
    let (spec, n) = match w.get(*i).copied() {
        Some("eq") => {
            let mut ports = Vec::new();
            let mut k = 1;
            while let Some(p) = at(k) {
                if is_port(&p) {
                    ports.push(p);
                    k += 1;
                } else {
                    break;
                }
            }
            if ports.is_empty() {
                return PortSpec::Any;
            }
            (PortSpec::Eq(ports), k)
        }
        Some("neq") => match at(1) {
            Some(p) => (PortSpec::Neq(p), 2),
            None => return PortSpec::Any,
        },
        Some("lt") => match at(1) {
            Some(p) => (PortSpec::Lt(p), 2),
            None => return PortSpec::Any,
        },
        Some("gt") => match at(1) {
            Some(p) => (PortSpec::Gt(p), 2),
            None => return PortSpec::Any,
        },
        Some("range") => match (at(1), at(2)) {
            (Some(a), Some(b)) => (PortSpec::Range(a, b), 3),
            _ => return PortSpec::Any,
        },
        Some("portgroup") => match at(1) {
            Some(g) => (PortSpec::Group(g), 2),
            None => return PortSpec::Any,
        },
        _ => return PortSpec::Any,
    };
    *i += n;
    spec
}

/// True for a word that can be a port: a number or a known port name.
fn is_port(w: &str) -> bool {
    w.parse::<u16>().is_ok() || super::lower::port_number(w).is_some()
}

/// The protocols whose entries can have ports.
const PORT_PROTOCOLS: &[&str] = &["tcp", "udp", "sctp", "6", "17", "132"];

/// Reads an ACL entry: `<protocol> <source> [<port>] <destination> [<port>]
/// [<options>]`.
pub(crate) fn ace(seq: &str, action: AclAction, w: &[&str], lines: Lines) -> Option<Ace> {
    let protocol = (*w.first()?).to_string();
    let mut i = 1;
    let ports = PORT_PROTOCOLS.contains(&protocol.as_str());
    let source = addr_spec(w, &mut i)?;
    let source_port = if ports {
        port_spec(w, &mut i)
    } else {
        PortSpec::Any
    };
    let destination = addr_spec(w, &mut i)?;
    let destination_port = if ports {
        port_spec(w, &mut i)
    } else {
        PortSpec::Any
    };
    let mut e = Ace {
        seq: seq.to_string(),
        action,
        protocol: protocol.clone(),
        source,
        source_port,
        destination,
        destination_port,
        icmp: None,
        established: false,
        unhandled: Vec::new(),
        lines,
    };
    if protocol == "icmp"
        && let Some(t) = w.get(i)
        && super::lower::icmp_type(t).is_some()
    {
        let code = w
            .get(i + 1)
            .filter(|c| c.parse::<u8>().is_ok())
            .map(|c| (*c).to_string());
        i += 1 + usize::from(code.is_some());
        e.icmp = Some(((*t).to_string(), code));
    }
    while let Some(word) = w.get(i) {
        match *word {
            "log" => {}
            "established" if protocol == "tcp" || protocol == "6" => e.established = true,
            other => e.unhandled.push(other.to_string()),
        }
        i += 1;
    }
    Some(e)
}

pub(crate) fn static_route(vrf: &str, w: &[&str], lines: Lines) -> StaticRoute {
    let mut r = StaticRoute {
        vrf: vrf.to_string(),
        prefix: String::new(),
        interface: None,
        next_hop: None,
        preference: 1,
        unhandled: Vec::new(),
        lines,
    };
    let mut preference = None;
    let mut i = 0;
    match w {
        [p, m, ..] if !p.contains('/') => {
            match mask_len(m) {
                Some(l) => r.prefix = format!("{p}/{l}"),
                None => r.unhandled.push(format!("mask {m}")),
            }
            i = 2;
        }
        [p, ..] => {
            r.prefix = (*p).to_string();
            i = 1;
        }
        [] => r.unhandled.push("no prefix".into()),
    }
    while let Some(word) = w.get(i) {
        match *word {
            "name" | "tag" => i += 1,
            a if a.parse::<std::net::Ipv4Addr>().is_ok() && r.next_hop.is_none() => {
                r.next_hop = Some(a.to_string());
            }
            n if preference.is_none()
                && r.unhandled.is_empty()
                && (r.next_hop.is_some() || r.interface.is_some())
                && n.parse::<u8>().is_ok_and(|v| v > 0) =>
            {
                preference = n.parse::<u8>().ok();
            }
            n if n.chars().next().is_some_and(char::is_alphabetic)
                && n.chars().any(|c| c.is_ascii_digit())
                && r.interface.is_none()
                && r.next_hop.is_none() =>
            {
                r.interface = Some(n.to_string());
            }
            other => r.unhandled.push(other.to_string()),
        }
        i += 1;
    }
    if let Some(p) = preference {
        r.preference = p;
    }
    r
}

pub(crate) fn nat_rule(w: &[&str], table: &Table) -> NatKind {
    let other = || NatKind::Other(table.report_key(&w.join(" ")));
    match w {
        [
            "ip",
            "nat",
            "inside",
            "source",
            "static",
            proto @ ("tcp" | "udp"),
            local,
            lp,
            global,
            gp,
            rest @ ..,
        ] if rest.iter().all(|x| *x == "add-route") => NatKind::Static {
            protocol: Some((*proto).to_string()),
            local: (*local).to_string(),
            local_port: Some((*lp).to_string()),
            global: (*global).to_string(),
            global_port: Some((*gp).to_string()),
            uncertain: None,
        },
        [
            "ip",
            "nat",
            "inside",
            "source",
            "static",
            local,
            global,
            rest @ ..,
        ] if rest.iter().all(|x| *x == "add-route")
            && local.parse::<std::net::Ipv4Addr>().is_ok()
            && global.parse::<std::net::Ipv4Addr>().is_ok() =>
        {
            NatKind::Static {
                protocol: None,
                local: (*local).to_string(),
                local_port: None,
                global: (*global).to_string(),
                global_port: None,
                uncertain: None,
            }
        }
        [
            "ip",
            "nat",
            "inside",
            "source",
            "list",
            acl,
            "pool",
            pool,
            rest @ ..,
        ] if rest.iter().all(|x| *x == "overload" || *x == "add-route") => NatKind::List {
            acl: (*acl).to_string(),
            target: NatTarget::Pool((*pool).to_string()),
            overload: rest.contains(&"overload"),
        },
        [
            "ip",
            "nat",
            "inside",
            "source",
            "list",
            acl,
            "interface",
            iface,
            "overload",
        ] => NatKind::List {
            acl: (*acl).to_string(),
            target: NatTarget::Interface((*iface).to_string()),
            overload: true,
        },
        _ => other(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vlan_list_gives_its_ranges() {
        assert_eq!(
            vlan_list("1,10,20-25"),
            Some(vec![(1, 1), (10, 10), (20, 25)])
        );
        assert_eq!(vlan_list("10,x"), None);
        assert_eq!(vlan_list("30-20"), None);
        assert_eq!(vlan_list("0"), None);
    }

    #[test]
    fn a_mask_gives_its_length() {
        assert_eq!(mask_len("255.255.255.0"), Some(24));
        assert_eq!(mask_len("255.255.255.255"), Some(32));
        assert_eq!(mask_len("0.0.0.0"), Some(0));
        assert_eq!(mask_len("255.0.255.0"), None);
    }

    #[test]
    fn an_entry_gives_its_parts() {
        let w = words("tcp 192.0.2.0/26 any eq 443 log");
        let e = ace("10", AclAction::Permit, &w, Lines::default()).unwrap();
        assert_eq!(e.source, AddrSpec::Prefix("192.0.2.0/26".into()));
        assert_eq!(e.destination, AddrSpec::Any);
        assert_eq!(e.destination_port, PortSpec::Eq(vec!["443".into()]));
        assert!(e.unhandled.is_empty());
        let w = words(
            "tcp host 192.0.2.1 range 1000 2000 addrgroup WEB eq www https established dscp ef",
        );
        let e = ace("20", AclAction::Deny, &w, Lines::default()).unwrap();
        assert_eq!(e.source, AddrSpec::Prefix("192.0.2.1/32".into()));
        assert_eq!(e.source_port, PortSpec::Range("1000".into(), "2000".into()));
        assert_eq!(e.destination, AddrSpec::Group("WEB".into()));
        // A port name that the reader does not know stays an unhandled
        // option.
        assert_eq!(e.destination_port, PortSpec::Eq(vec!["www".into()]));
        assert!(e.established);
        assert_eq!(e.unhandled, ["https", "dscp", "ef"]);
        let w = words("icmp any 192.0.2.0 0.0.0.255 echo");
        let e = ace("30", AclAction::Permit, &w, Lines::default()).unwrap();
        assert_eq!(
            e.destination,
            AddrSpec::Wildcard("192.0.2.0".into(), "0.0.0.255".into())
        );
        assert_eq!(e.icmp, Some(("echo".into(), None)));
        assert!(
            ace(
                "40",
                AclAction::Permit,
                &words("ip bogus any"),
                Lines::default()
            )
            .is_none()
        );
    }

    #[test]
    fn a_static_route_gives_its_parts() {
        let s = Lines::default();
        let r = static_route("default", &words("10.0.0.0/8 192.0.2.9 name core 5"), s);
        assert_eq!(r.prefix, "10.0.0.0/8");
        assert_eq!(r.next_hop.as_deref(), Some("192.0.2.9"));
        assert_eq!(r.preference, 5);
        assert!(r.unhandled.is_empty());
        let r = static_route("default", &words("0.0.0.0/0 Ethernet1/2 198.51.100.2"), s);
        assert_eq!(r.interface.as_deref(), Some("Ethernet1/2"));
        assert_eq!(r.next_hop.as_deref(), Some("198.51.100.2"));
        assert_eq!(r.preference, 1);
        let r = static_route("default", &words("10.0.0.0/8 192.0.2.9 250 7"), s);
        assert_eq!(r.preference, 250);
        assert_eq!(r.unhandled, ["7"]);
        let r = static_route("default", &words("10.0.0.0/8 192.0.2.9 track 5"), s);
        assert_eq!(r.preference, 1);
        assert_eq!(r.unhandled, ["track", "5"]);
        let r = static_route("default", &words("10.0.0.0/8 192.0.2.9 vrf RED"), s);
        assert_eq!(r.unhandled, ["vrf", "RED"]);
        let r = static_route("default", &words("192.0.2.128/25 Null0"), s);
        assert_eq!(r.interface.as_deref(), Some("Null0"));
    }
}
