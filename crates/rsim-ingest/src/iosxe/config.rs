//! The handlers of an IOS-XE running config: the typed structures of the
//! handled lines.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use rsim_core::Mac;

use crate::coverage::{State, Table};
pub use crate::nxos::config::Lines;
use crate::nxos::config::{
    Ace, Acl, AclAction, AddrSpec, Address, FhrpKind, NatKind, NatPool, NatRole, NatRule, PortMode,
    PortSpec, StaticRoute, ace, addr_spec, mask_len, nat_rule, static_route, vlan_list,
};
use crate::stanza::{Document, Stanza};

fn lines_of(s: &Stanza) -> Lines {
    Lines {
        first: s.first_line,
        last: s.last_line,
    }
}

/// An HSRP group (`standby`) or a VRRP group (`vrrp`) of an interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FhrpGroup {
    pub kind: FhrpKind,
    pub group: u32,
    /// The virtual addresses, the primary first.
    pub addresses: Vec<(Ipv4Addr, Lines)>,
    pub priority: Option<(u32, Lines)>,
    pub preempt: Option<Lines>,
    /// The virtual MAC of `standby <group> mac-address`.
    pub mac: Option<(Mac, Lines)>,
    /// The masked handled lines of the group that the handler cannot read.
    pub unhandled: Vec<String>,
    /// The first line and the last line of the group.
    pub lines: Lines,
}

/// An interface, a sub-interface, a port-channel or an SVI.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    /// `Some(false)` with `shutdown`, `Some(true)` with `no shutdown`, and
    /// `None` with neither.
    pub admin_up: Option<bool>,
    /// The VRF of `vrf forwarding` or `ip vrf forwarding`.
    pub vrf: Option<(String, Lines)>,
    pub addresses: Vec<Address>,
    /// The line `no ip address`.
    pub no_address: Option<Lines>,
    /// The line of an address that the config does not state:
    /// `ip address dhcp` or `ip address negotiated`.
    pub dynamic_address: Option<Lines>,
    /// The IPv6 addresses with their prefix lengths, as written.
    pub ipv6: Vec<(String, Lines)>,
    /// The IPv4 ACLs of the `in` and the `out` direction.
    pub acl_in: Option<(String, Lines)>,
    pub acl_out: Option<(String, Lines)>,
    pub nat: Option<(NatRole, Lines)>,
    /// The QoS policies of the input and the output.
    pub qos_in: Option<(String, Lines)>,
    pub qos_out: Option<(String, Lines)>,
    pub mtu: Option<(u32, Lines)>,
    pub ip_mtu: Option<(u32, Lines)>,
    /// The VLAN of `encapsulation dot1Q`, true for a `native` VLAN.
    pub dot1q: Option<(u16, bool, Lines)>,
    /// The port-channel of a member port, from `channel-group`.
    pub channel_group: Option<(u32, Lines)>,
    /// `Some(true)` with a `switchport` line, `Some(false)` with
    /// `no switchport`, and `None` with neither.
    pub switchport: Option<bool>,
    pub mode: Option<PortMode>,
    pub access_vlan: Option<u16>,
    pub native_vlan: Option<u16>,
    /// The allowed VLANs of a trunk as ranges. `None` allows each VLAN.
    pub allowed: Option<Vec<(u16, u16)>>,
    /// The HSRP version of `standby version`.
    pub hsrp_version: Option<(u8, Lines)>,
    /// The HSRP and VRRP groups, in the order of their first lines.
    pub fhrp: Vec<FhrpGroup>,
    /// The text of the `description` line.
    pub description: Option<(String, Lines)>,
    /// The masked lines that the handlers do not read: the unhandled
    /// options and the handled lines with a form that the handler cannot
    /// read.
    pub unhandled: Vec<String>,
    pub lines: Lines,
}

/// A VRF of `vrf definition` or of `ip vrf`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vrf {
    pub name: String,
    /// The lines that turn on IPv4 in the VRF: the `address-family ipv4`
    /// stanza of `vrf definition`, or the whole `ip vrf` stanza, which is
    /// IPv4 only. `None` for a VRF with no IPv4.
    pub ipv4: Option<Lines>,
    pub lines: Lines,
}

/// A `vlan` stanza.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vlan {
    /// The VLANs of the stanza as ranges.
    pub ranges: Vec<(u16, u16)>,
    pub name: Option<(String, Lines)>,
    /// The masked lines of the stanza that no handler reads.
    pub unhandled: Vec<String>,
    pub lines: Lines,
}

/// The typed structures of a running config.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// The name of the line `hostname`.
    pub hostname: Option<String>,
    /// True with `ip routing`, false with `no ip routing`.
    pub ip_routing: Option<(bool, Lines)>,
    pub interfaces: Vec<Interface>,
    pub vrfs: BTreeMap<String, Vrf>,
    /// The IPv4 access lists, named and numbered. An entry of a standard
    /// list is an entry of the protocol `ip` with any destination.
    pub acls: BTreeMap<String, Acl>,
    /// The static routes. The VRF of a route of the global table is
    /// `default`.
    pub static_routes: Vec<StaticRoute>,
    pub nat_rules: Vec<NatRule>,
    pub nat_pools: BTreeMap<String, NatPool>,
    pub vlans: Vec<Vlan>,
    /// The masked `vlan` lines whose list the handler cannot read.
    pub unreadable_vlans: Vec<String>,
    /// The VLANs of the `vlan filter` lines, which the lowering does not
    /// model. A list that the handler cannot read gives each VLAN.
    pub filtered_vlans: Vec<(u16, u16)>,
    /// The masked line `vlan dot1q tag native`, which the lowering does not
    /// model.
    pub native_tagging: Option<String>,
    /// The mode of `vtp mode`.
    pub vtp_mode: Option<(String, Lines)>,
    /// The VRFs with a dynamic routing protocol, with the lines that show
    /// it.
    pub dynamic_vrfs: BTreeMap<String, Vec<(u32, u32)>>,
    /// The BGP processes, neighbours and listen ranges.
    pub bgp: crate::bgp_peers::BgpConfig,
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

    fn state(&self, path: &[&str]) -> State {
        self.table.state(path)
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
/// lines are handled.
pub fn read(doc: &Document, table: &Table) -> Config {
    let mut r = R {
        table,
        read: BTreeSet::new(),
    };
    let mut cfg = Config::default();
    for s in doc.root.children() {
        let w = words(&s.key);
        match w.as_slice() {
            ["hostname", name] => cfg.hostname = Some((*name).to_string()),
            ["router", "bgp", _] => {
                let table = r.table;
                cfg.bgp = super::bgp::read(s, &mut r.read, &|k| table.report_key(k));
            }
            ["interface", name] => {
                let i = interface(&mut r, s, name);
                cfg.interfaces.push(i);
            }
            ["vrf", "definition", name] => {
                r.mark(s);
                let mut v = Vrf {
                    name: (*name).to_string(),
                    ipv4: None,
                    lines: lines_of(s),
                };
                for c in s.children() {
                    if r.state(&[&s.key, &c.key]) == State::Handled {
                        r.mark(c);
                        if c.key == "address-family ipv4" {
                            v.ipv4 = Some(lines_of(c));
                        }
                    }
                }
                cfg.vrfs.insert(v.name.clone(), v);
            }
            ["ip", "vrf", name] => {
                r.mark(s);
                cfg.vrfs.insert(
                    (*name).to_string(),
                    Vrf {
                        name: (*name).to_string(),
                        ipv4: Some(lines_of(s)),
                        lines: lines_of(s),
                    },
                );
            }
            ["ip", "access-list", kind @ ("extended" | "standard"), name] => {
                r.mark(s);
                let acl = named_acl(&mut r, s, name, *kind == "standard");
                cfg.acls.insert((*name).to_string(), acl);
            }
            ["access-list", ..] => {
                r.mark(s);
                numbered_acl_line(&r, s, &w, &mut cfg.acls);
            }
            ["ip", "route", "vrf", vrf, rest @ ..] => {
                r.mark(s);
                cfg.static_routes.push(static_route(vrf, rest, lines_of(s)));
            }
            ["ip", "route", rest @ ..] => {
                r.mark(s);
                cfg.static_routes
                    .push(static_route("default", rest, lines_of(s)));
            }
            ["ip", "routing"] => {
                r.mark(s);
                cfg.ip_routing = Some((true, lines_of(s)));
            }
            ["no", "ip", "routing"] => {
                r.mark(s);
                cfg.ip_routing = Some((false, lines_of(s)));
            }
            ["ip", "nat", "inside", "source", ..] => {
                r.mark(s);
                cfg.nat_rules.push(NatRule {
                    kind: nat_kind(&w, table),
                    lines: lines_of(s),
                });
            }
            ["ip", "nat", "pool", rest @ ..] => {
                r.mark(s);
                match rest {
                    [name, start, end, ..]
                        if start.parse::<Ipv4Addr>().is_ok() && end.parse::<Ipv4Addr>().is_ok() =>
                    {
                        cfg.nat_pools.insert(
                            (*name).to_string(),
                            NatPool {
                                start: (*start).to_string(),
                                end: (*end).to_string(),
                                lines: lines_of(s),
                            },
                        );
                    }
                    _ => cfg.nat_rules.push(NatRule {
                        kind: NatKind::Other(table.report_key(&s.key)),
                        lines: lines_of(s),
                    }),
                }
                for c in s.children() {
                    r.mark(c);
                }
            }
            ["ip", "nat", ..] if r.state(&[&s.key]) == State::Unhandled => {
                cfg.nat_rules.push(NatRule {
                    kind: NatKind::Other(table.report_key(&s.key)),
                    lines: lines_of(s),
                });
            }
            ["vlan", "filter", rest @ ..] if r.state(&[&s.key]) == State::Unhandled => {
                let list = match rest {
                    [_, "vlan-list", list] => vlan_list(list),
                    _ => None,
                };
                cfg.filtered_vlans
                    .extend(list.unwrap_or_else(|| vec![(1, 4094)]));
            }
            ["vlan", "dot1q", "tag", "native"] if r.state(&[&s.key]) == State::Unhandled => {
                cfg.native_tagging = Some(table.report_key(&s.key));
            }
            ["vtp", "mode", m] if r.state(&[&s.key]) == State::Handled => {
                r.mark(s);
                cfg.vtp_mode = Some(((*m).to_string(), lines_of(s)));
            }
            ["vlan", list] if r.state(&[&s.key]) == State::Handled => {
                r.mark(s);
                let Some(ranges) = vlan_list(list) else {
                    cfg.unreadable_vlans.push(table.report_key(&s.key));
                    continue;
                };
                let mut v = Vlan {
                    ranges,
                    name: None,
                    unhandled: r.unhandled_children(s),
                    lines: lines_of(s),
                };
                for c in s.children() {
                    if let ["name", n, ..] = words(&c.key).as_slice() {
                        r.mark(c);
                        v.name = Some(((*n).to_string(), lines_of(c)));
                    }
                }
                cfg.vlans.push(v);
            }
            _ => {}
        }
    }
    cfg.read = r.read;
    cfg.dynamic_vrfs = super::table::dynamic_vrfs(doc);
    cfg
}

/// The kind of an `ip nat inside source` line. A static rule with a final
/// `extendable` is a static rule with that word as its uncertain word; each
/// other line with `extendable` is a form that the lowering does not read.
fn nat_kind(w: &[&str], table: &Table) -> NatKind {
    let Some((&"extendable", rest)) = w.split_last() else {
        return nat_rule(w, table);
    };
    match nat_rule(rest, table) {
        NatKind::Static {
            protocol,
            local,
            local_port,
            global,
            global_port,
            ..
        } => NatKind::Static {
            protocol,
            local,
            local_port,
            global,
            global_port,
            uncertain: Some("extendable".into()),
        },
        _ => NatKind::Other(table.report_key(&w.join(" "))),
    }
}

/// An IPv4 address with a dotted mask, as `address/length`, and the words
/// after it.
fn ipv4_prefix<'a, 'b>(w: &'a [&'b str]) -> Option<(String, &'a [&'b str])> {
    let [a, m, rest @ ..] = w else {
        return None;
    };
    a.parse::<Ipv4Addr>().ok()?;
    let len = mask_len(m)?;
    Some((format!("{a}/{len}"), rest))
}

fn interface(r: &mut R, s: &Stanza, name: &str) -> Interface {
    r.mark(s);
    let mut i = Interface {
        name: name.to_string(),
        lines: lines_of(s),
        unhandled: r.unhandled_children(s),
        ..Interface::default()
    };
    for c in s.children() {
        if r.state(&[&s.key, &c.key]) != State::Handled {
            continue;
        }
        r.mark(c);
        if !interface_line(&mut i, c) {
            i.unhandled.push(r.table.report_key(&c.key));
        }
    }
    i
}

/// Reads a handled line of an interface into the interface. False for a
/// line with a form that the handler cannot read.
fn interface_line(i: &mut Interface, c: &Stanza) -> bool {
    let lines = lines_of(c);
    let vlan = |v: &str| v.parse::<u16>().ok().filter(|v| (1..=4094).contains(v));
    match words(&c.key).as_slice() {
        ["shutdown"] => i.admin_up = Some(false),
        ["no", "shutdown"] => i.admin_up = Some(true),
        ["description", ..] => {
            i.description = Some((crate::nxos::config::description_text(&c.key), lines));
        }
        ["vrf", "forwarding", v] | ["ip", "vrf", "forwarding", v] => {
            i.vrf = Some(((*v).to_string(), lines));
        }
        ["no", "ip", "address"] => i.no_address = Some(lines),
        ["ip", "address", "dhcp", ..] | ["ip", "address", "negotiated", ..] => {
            i.dynamic_address = Some(lines);
        }
        ["ip", "address", rest @ ..] => {
            let secondary = match ipv4_prefix(rest) {
                Some((prefix, [])) => (prefix, false),
                Some((prefix, ["secondary"])) => (prefix, true),
                _ => return false,
            };
            i.addresses.push(Address {
                prefix: secondary.0,
                secondary: secondary.1,
                lines,
            });
        }
        ["ipv6", "address", a, ..] => i.ipv6.push(((*a).to_string(), lines)),
        ["ip", "access-group", acl, dir @ ("in" | "out")] => {
            let a = Some(((*acl).to_string(), lines));
            if *dir == "in" {
                i.acl_in = a;
            } else {
                i.acl_out = a;
            }
        }
        ["ip", "nat", "inside"] => i.nat = Some((NatRole::Inside, lines)),
        ["ip", "nat", "outside"] => i.nat = Some((NatRole::Outside, lines)),
        ["service-policy", dir @ ("input" | "output"), policy] => {
            let q = Some(((*policy).to_string(), lines));
            if *dir == "input" {
                i.qos_in = q;
            } else {
                i.qos_out = q;
            }
        }
        ["mtu", n] => match n.parse() {
            Ok(n) => i.mtu = Some((n, lines)),
            Err(_) => return false,
        },
        ["ip", "mtu", n] => match n.parse() {
            Ok(n) => i.ip_mtu = Some((n, lines)),
            Err(_) => return false,
        },
        ["encapsulation", "dot1Q", v, rest @ ..] => match (vlan(v), rest) {
            (Some(v), []) => i.dot1q = Some((v, false, lines)),
            (Some(v), ["native"]) => i.dot1q = Some((v, true, lines)),
            _ => return false,
        },
        ["channel-group", n, ..] => match n.parse() {
            Ok(n) => i.channel_group = Some((n, lines)),
            Err(_) => return false,
        },
        ["switchport"] => i.switchport = Some(true),
        ["no", "switchport"] => i.switchport = Some(false),
        ["switchport", "mode", m @ ("access" | "trunk")] => {
            i.switchport = Some(true);
            i.mode = Some(if *m == "access" {
                PortMode::Access
            } else {
                PortMode::Trunk
            });
        }
        ["switchport", "access", "vlan", v] => {
            i.switchport = Some(true);
            match vlan(v) {
                Some(v) => i.access_vlan = Some(v),
                None => return false,
            }
        }
        ["switchport", "trunk", "native", "vlan", v] => {
            i.switchport = Some(true);
            match vlan(v) {
                Some(v) => i.native_vlan = Some(v),
                None => return false,
            }
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
                None => return false,
            }
        }
        ["switchport", "trunk", "encapsulation", "dot1q"] => i.switchport = Some(true),
        ["standby", "version", v] => match v.parse() {
            Ok(v @ (1 | 2)) => i.hsrp_version = Some((v, lines)),
            _ => return false,
        },
        [kind @ ("standby" | "vrrp"), n, rest @ ..] => {
            let kind = if *kind == "standby" {
                FhrpKind::Hsrp
            } else {
                FhrpKind::Vrrp
            };
            let Ok(n) = n.parse::<u32>() else {
                return false;
            };
            fhrp_line(i, kind, n, rest, &c.key, lines);
        }
        _ => return false,
    }
    true
}

/// Reads a handled line of an HSRP or a VRRP group into its group. A line
/// with a form that the handler cannot read goes to the unhandled lines of
/// the group, through the mask.
fn fhrp_line(i: &mut Interface, kind: FhrpKind, n: u32, w: &[&str], key: &str, lines: Lines) {
    let at = match i.fhrp.iter().position(|g| g.kind == kind && g.group == n) {
        Some(at) => at,
        None => {
            i.fhrp.push(FhrpGroup {
                kind,
                group: n,
                addresses: Vec::new(),
                priority: None,
                preempt: None,
                mac: None,
                unhandled: Vec::new(),
                lines,
            });
            i.fhrp.len() - 1
        }
    };
    let g = &mut i.fhrp[at];
    g.lines.first = g.lines.first.min(lines.first);
    g.lines.last = g.lines.last.max(lines.last);
    let read = match w {
        ["ip", a] => a.parse().map(|a| g.addresses.insert(0, (a, lines))).is_ok(),
        ["ip", a, "secondary"] => a.parse().map(|a| g.addresses.push((a, lines))).is_ok(),
        ["priority", p] => p.parse().map(|p| g.priority = Some((p, lines))).is_ok(),
        ["preempt", ..] => {
            g.preempt = Some(lines);
            true
        }
        ["mac-address", m] => crate::nxos::state::mac(m)
            .map(|m| g.mac = Some((m, lines)))
            .is_some(),
        _ => false,
    };
    if !read {
        g.unhandled.push(super::mask(key));
    }
}

/// Reads an entry of a standard access list: a source address, with an
/// address alone as a host, and `log`.
fn standard_ace(seq: &str, action: AclAction, w: &[&str], lines: Lines) -> Option<Ace> {
    let mut i = 0;
    let source = match w {
        [a, rest @ ..]
            if a.parse::<Ipv4Addr>().is_ok()
                && rest.first().is_none_or(|m| m.parse::<Ipv4Addr>().is_err()) =>
        {
            i = 1;
            AddrSpec::Prefix(format!("{a}/32"))
        }
        _ => addr_spec(w, &mut i)?,
    };
    let mut unhandled = Vec::new();
    for word in &w[i..] {
        if *word != "log" {
            unhandled.push((*word).to_string());
        }
    }
    Some(Ace {
        seq: seq.to_string(),
        action,
        protocol: "ip".into(),
        source,
        source_port: PortSpec::Any,
        destination: AddrSpec::Any,
        destination_port: PortSpec::Any,
        icmp: None,
        established: false,
        unhandled,
        lines,
    })
}

/// Reads an entry with its action and its words after the action, and adds
/// it to the list. An entry with no sequence number gets the number of the
/// entry before it plus 10, as IOS-XE numbers it.
fn add_entry(
    acl: &mut Acl,
    seq: Option<&str>,
    action: &str,
    rest: &[&str],
    standard: bool,
    lines: Lines,
) -> bool {
    let action = if action == "permit" {
        AclAction::Permit
    } else {
        AclAction::Deny
    };
    let seq = match seq {
        Some(s) => s.to_string(),
        None => {
            let last = acl
                .entries
                .last()
                .and_then(|e| e.seq.parse::<u64>().ok())
                .unwrap_or(0);
            (last + 10).to_string()
        }
    };
    let entry = if standard {
        standard_ace(&seq, action, rest, lines)
    } else {
        ace(&seq, action, rest, lines)
    };
    match entry {
        Some(e) => {
            acl.entries.push(e);
            true
        }
        None => false,
    }
}

fn named_acl(r: &mut R, s: &Stanza, name: &str, standard: bool) -> Acl {
    let mut acl = Acl {
        name: name.to_string(),
        entries: Vec::new(),
        unreadable: Vec::new(),
        lines: lines_of(s),
    };
    for c in s.children() {
        r.mark(c);
        let w = words(&c.key);
        let (seq, rest) = match w.as_slice() {
            [seq, rest @ ..] if seq.parse::<u64>().is_ok() => (Some(*seq), rest),
            rest => (None, rest),
        };
        let ok = match rest {
            ["remark", ..] => true,
            [action @ ("permit" | "deny"), rest @ ..] => {
                add_entry(&mut acl, seq, action, rest, standard, lines_of(c))
            }
            _ => false,
        };
        if !ok {
            acl.unreadable.push(r.table.report_key(&c.key));
        }
    }
    acl
}

/// True for the number of a standard numbered access list.
fn standard_number(n: u32) -> bool {
    (1..=99).contains(&n) || (1300..=1999).contains(&n)
}

/// True for the number of an extended numbered access list.
fn extended_number(n: u32) -> bool {
    (100..=199).contains(&n) || (2000..=2699).contains(&n)
}

/// Reads a line `access-list <number> ..` into the list of its number.
fn numbered_acl_line(r: &R, s: &Stanza, w: &[&str], acls: &mut BTreeMap<String, Acl>) {
    let name = w.get(1).copied().unwrap_or_default();
    let acl = acls.entry(name.to_string()).or_insert_with(|| Acl {
        name: name.to_string(),
        entries: Vec::new(),
        unreadable: Vec::new(),
        lines: lines_of(s),
    });
    acl.lines.last = acl.lines.last.max(s.last_line);
    let number = name.parse::<u32>().ok();
    let ok = match (number, &w[2.min(w.len())..]) {
        (Some(_), ["remark", ..]) => true,
        (Some(n), [action @ ("permit" | "deny"), rest @ ..])
            if standard_number(n) || extended_number(n) =>
        {
            add_entry(acl, None, action, rest, standard_number(n), lines_of(s))
        }
        _ => false,
    };
    if !ok {
        acl.unreadable.push(r.table.report_key(&s.key));
    }
}
