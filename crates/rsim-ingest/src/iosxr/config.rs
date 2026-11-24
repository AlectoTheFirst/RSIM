//! The handlers of an IOS-XR running config: the typed structures of the
//! handled lines.

use std::collections::{BTreeMap, BTreeSet};

use crate::coverage::{State, Table};
pub use crate::nxos::config::Lines;
use crate::nxos::config::{Acl, AclAction, mask_len};
use crate::stanza::{Document, Stanza};

fn lines_of(s: &Stanza) -> Lines {
    Lines {
        first: s.first_line,
        last: s.last_line,
    }
}

/// An IPv4 address of an interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    /// The address with its prefix length, for example `192.0.2.1/24`.
    pub prefix: String,
    pub secondary: bool,
    pub lines: Lines,
}

/// An interface or a sub-interface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    /// True with a `shutdown` line.
    pub shutdown: bool,
    pub vrf: Option<(String, Lines)>,
    pub addresses: Vec<Address>,
    /// The IPv6 addresses with their prefix lengths, as written.
    pub ipv6: Vec<(String, Lines)>,
    /// The IPv4 ACLs of the `ingress` and the `egress` direction.
    pub acl_in: Option<(String, Lines)>,
    pub acl_out: Option<(String, Lines)>,
    /// The QoS policies of the input and the output.
    pub qos_in: Option<(String, Lines)>,
    pub qos_out: Option<(String, Lines)>,
    /// The VLAN of `encapsulation dot1q`.
    pub dot1q: Option<(u16, Lines)>,
    /// The bundle of a member port, from `bundle id`.
    pub bundle: Option<(u32, Lines)>,
    pub mtu: Option<(u32, Lines)>,
    /// The text of the `description` line.
    pub description: Option<(String, Lines)>,
    /// The masked lines of the options that the handlers do not read: the
    /// unhandled options and the handled lines with a form that the handler
    /// cannot read.
    pub unhandled: Vec<String>,
    pub lines: Lines,
}

/// A sub-interface with `l2transport`. The handlers do not lower it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2Transport {
    pub name: String,
    /// The VLAN of an `encapsulation dot1q <vlan>` line with no other word.
    pub dot1q: Option<u16>,
    /// The masked key of the stanza.
    pub key: String,
    pub lines: Lines,
}

/// An IPv4 HSRP group of `router hsrp`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HsrpGroup {
    /// The interface of the `interface` stanza of `router hsrp`.
    pub interface: String,
    pub group: u32,
    /// The version of `hsrp <group> version <n>`.
    pub version: Option<(u8, Lines)>,
    /// The virtual addresses, the primary first.
    pub addresses: Vec<(std::net::Ipv4Addr, Lines)>,
    pub priority: Option<(u32, Lines)>,
    pub preempt: Option<Lines>,
    /// The virtual MAC of `mac-address`.
    pub mac: Option<(rsim_core::Mac, Lines)>,
    /// The masked lines of the group, its interface and `router hsrp` that
    /// the handlers do not read.
    pub unhandled: Vec<String>,
    pub lines: Lines,
}

/// The typed structures of a running config.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// The name of the line `hostname`.
    pub hostname: Option<String>,
    pub interfaces: Vec<Interface>,
    /// The `l2transport` sub-interfaces.
    pub l2transport: Vec<L2Transport>,
    /// The VRFs of the config, with the lines of their `vrf` stanza.
    pub vrfs: BTreeMap<String, Lines>,
    /// The IPv4 access lists.
    pub acls: BTreeMap<String, Acl>,
    /// The IPv4 HSRP groups.
    pub hsrp: Vec<HsrpGroup>,
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

    /// The masked keys of the children of a stanza that the table
    /// classifies as unhandled.
    fn unhandled_children(&self, parent: &Stanza) -> Vec<String> {
        parent
            .children()
            .iter()
            .filter(|c| self.table.state(&[&parent.key, &c.key]) == State::Unhandled)
            .map(|c| self.table.report_key(&c.key))
            .collect()
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
            ["hostname", name] => cfg.hostname = Some((*name).to_string()),
            ["interface", name] => {
                let i = interface(&mut r, s, name);
                cfg.interfaces.push(i);
            }
            ["interface", name, "l2transport"] => {
                cfg.l2transport.push(l2transport(&r, s, name));
            }
            ["vrf", name] => {
                r.mark(s);
                cfg.vrfs.insert((*name).to_string(), lines_of(s));
            }
            ["ipv4", "access-list", name] => {
                r.mark(s);
                let acl = access_list(&mut r, s, name);
                cfg.acls.insert((*name).to_string(), acl);
            }
            ["router", "hsrp"] => {
                r.mark(s);
                cfg.hsrp.extend(router_hsrp(&mut r, s));
            }
            ["router", "bgp", _] => {
                let table = r.table;
                cfg.bgp = super::bgp::read(s, &mut r.read, &|k| table.report_key(k));
            }
            _ => {}
        }
    }
    cfg.read = r.read;
    cfg.dynamic_vrfs = super::table::dynamic_vrfs(doc);
    cfg
}

/// An IPv4 address with a dotted mask or a prefix length, as
/// `address/length`.
fn ipv4_prefix<'a, 'b>(w: &'a [&'b str]) -> Option<(String, &'a [&'b str])> {
    let (first, rest) = w.split_first()?;
    if let Some((a, len)) = first.split_once('/') {
        a.parse::<std::net::Ipv4Addr>().ok()?;
        let len: u8 = len.parse().ok().filter(|l| *l <= 32)?;
        return Some((format!("{a}/{len}"), rest));
    }
    first.parse::<std::net::Ipv4Addr>().ok()?;
    let (m, rest) = rest.split_first()?;
    let len = mask_len(m)?;
    Some((format!("{first}/{len}"), rest))
}

fn l2transport(r: &R, s: &Stanza, name: &str) -> L2Transport {
    let dot1q = s
        .children()
        .iter()
        .find_map(|c| match words(&c.key).as_slice() {
            ["encapsulation", "dot1q", v] => Some(v.parse::<u16>().ok()),
            ["encapsulation", ..] => Some(None),
            _ => None,
        })
        .flatten()
        .filter(|v| (1..=4094).contains(v));
    L2Transport {
        name: name.to_string(),
        dot1q,
        key: r.table.report_key(&s.key),
        lines: lines_of(s),
    }
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
        let lines = lines_of(c);
        let mut unreadable = false;
        let handled = match words(&c.key).as_slice() {
            ["shutdown"] => {
                i.shutdown = true;
                true
            }
            ["description", ..] => {
                i.description = Some((crate::nxos::config::description_text(&c.key), lines));
                true
            }
            ["vrf", v] => {
                i.vrf = Some(((*v).to_string(), lines));
                true
            }
            ["ipv4", "address", rest @ ..] => {
                match ipv4_prefix(rest) {
                    Some((prefix, [])) => i.addresses.push(Address {
                        prefix,
                        secondary: false,
                        lines,
                    }),
                    Some((prefix, ["secondary"])) => i.addresses.push(Address {
                        prefix,
                        secondary: true,
                        lines,
                    }),
                    _ => unreadable = true,
                }
                true
            }
            ["ipv6", "address", a, ..] => {
                i.ipv6.push(((*a).to_string(), lines));
                true
            }
            ["ipv4", "access-group", acl, dir @ ("ingress" | "egress")] => {
                let a = Some(((*acl).to_string(), lines));
                if *dir == "ingress" {
                    i.acl_in = a;
                } else {
                    i.acl_out = a;
                }
                true
            }
            ["service-policy", dir @ ("input" | "output"), policy] => {
                let q = Some(((*policy).to_string(), lines));
                if *dir == "input" {
                    i.qos_in = q;
                } else {
                    i.qos_out = q;
                }
                true
            }
            ["encapsulation", "dot1q", rest @ ..] => {
                match rest {
                    [v] => match v.parse::<u16>() {
                        Ok(v) if (1..=4094).contains(&v) => i.dot1q = Some((v, lines)),
                        _ => unreadable = true,
                    },
                    _ => unreadable = true,
                }
                true
            }
            ["bundle", "id", n, "mode", ..] => {
                match n.parse() {
                    Ok(n) => i.bundle = Some((n, lines)),
                    Err(_) => unreadable = true,
                }
                true
            }
            ["mtu", n] => {
                match n.parse() {
                    Ok(n) => i.mtu = Some((n, lines)),
                    Err(_) => unreadable = true,
                }
                true
            }
            _ => false,
        };
        if handled {
            r.mark(c);
        }
        if unreadable {
            i.unhandled.push(r.table.report_key(&c.key));
        }
    }
    i
}

/// The masked keys of the stanzas below a stanza, at any depth, that the
/// table classifies as unhandled. `path` holds the keys from the root to the
/// stanza.
fn unhandled_below(r: &R, path: &mut Vec<String>, s: &Stanza, out: &mut Vec<String>) {
    for c in s.children() {
        path.push(c.key.clone());
        let keys: Vec<&str> = path.iter().map(String::as_str).collect();
        if r.table.state(&keys) == State::Unhandled {
            out.push(r.table.report_key(&c.key));
        } else {
            unhandled_below(r, path, c, out);
        }
        path.pop();
    }
}

/// The IPv4 groups of `router hsrp`. An unhandled line of a group, of its
/// interface or of `router hsrp` goes to the unhandled lines of the groups
/// that it can change.
fn router_hsrp(r: &mut R, s: &Stanza) -> Vec<HsrpGroup> {
    let mut out = Vec::new();
    let mut top = Vec::new();
    for c in s.children() {
        let mut path = vec![s.key.clone(), c.key.clone()];
        let keys: Vec<&str> = path.iter().map(String::as_str).collect();
        let name = match words(&c.key).as_slice() {
            ["interface", name] if r.table.state(&keys) == State::Handled => (*name).to_string(),
            _ => {
                if r.table.state(&keys) == State::Unhandled {
                    top.push(r.table.report_key(&c.key));
                }
                continue;
            }
        };
        r.mark(c);
        let mut iface_lines = Vec::new();
        let mut groups = Vec::new();
        for af in c.children() {
            path.push(af.key.clone());
            let keys: Vec<&str> = path.iter().map(String::as_str).collect();
            let state = r.table.state(&keys);
            if words(&af.key).as_slice() != ["address-family", "ipv4"] || state != State::Handled {
                if state == State::Unhandled {
                    iface_lines.push(r.table.report_key(&af.key));
                } else {
                    unhandled_below(r, &mut path, af, &mut iface_lines);
                }
                path.pop();
                continue;
            }
            r.mark(af);
            for g in af.children() {
                path.push(g.key.clone());
                let keys: Vec<&str> = path.iter().map(String::as_str).collect();
                let handled = r.table.state(&keys) == State::Handled;
                let w = words(&g.key);
                let parsed = match w.as_slice() {
                    ["hsrp", n] => n.parse::<u32>().ok().map(|n| (n, None)),
                    ["hsrp", n, "version", v] => n
                        .parse::<u32>()
                        .ok()
                        .zip(v.parse::<u8>().ok())
                        .map(|(n, v)| (n, Some(v))),
                    _ => None,
                };
                match (handled, parsed) {
                    (true, Some((n, v))) => {
                        r.mark(g);
                        groups.push(group(r, &mut path, g, &name, n, v));
                    }
                    (true, None) => {
                        r.mark(g);
                        iface_lines.push(r.table.report_key(&g.key));
                    }
                    (false, _) => {
                        if r.table.state(&keys) == State::Unhandled {
                            iface_lines.push(r.table.report_key(&g.key));
                        } else {
                            unhandled_below(r, &mut path, g, &mut iface_lines);
                        }
                    }
                }
                path.pop();
            }
            path.pop();
        }
        for mut g in groups {
            g.unhandled.extend(iface_lines.iter().cloned());
            out.push(g);
        }
    }
    for g in &mut out {
        g.unhandled.extend(top.iter().cloned());
    }
    out
}

fn group(
    r: &mut R,
    path: &mut Vec<String>,
    s: &Stanza,
    iface: &str,
    n: u32,
    v: Option<u8>,
) -> HsrpGroup {
    let mut g = HsrpGroup {
        interface: iface.to_string(),
        group: n,
        version: v.map(|v| (v, lines_of(s))),
        lines: lines_of(s),
        ..HsrpGroup::default()
    };
    for c in s.children() {
        path.push(c.key.clone());
        let keys: Vec<&str> = path.iter().map(String::as_str).collect();
        let state = r.table.state(&keys);
        path.pop();
        if state != State::Handled {
            if state == State::Unhandled {
                g.unhandled.push(r.table.report_key(&c.key));
            }
            continue;
        }
        r.mark(c);
        let lines = lines_of(c);
        let read = match words(&c.key).as_slice() {
            ["address", a] | ["address", a, "secondary"] => match a.parse() {
                Ok(a) => {
                    if words(&c.key).len() == 2 {
                        g.addresses.insert(0, (a, lines));
                    } else {
                        g.addresses.push((a, lines));
                    }
                    true
                }
                Err(_) => false,
            },
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
            g.unhandled.push(r.table.report_key(&c.key));
        }
    }
    g
}

fn access_list(r: &mut R, s: &Stanza, name: &str) -> Acl {
    let mut acl = Acl {
        name: name.to_string(),
        entries: Vec::new(),
        unreadable: Vec::new(),
        lines: lines_of(s),
    };
    for c in s.children() {
        r.mark(c);
        let w = words(&c.key);
        match w.as_slice() {
            [_, "remark", ..] => {}
            [seq, action @ ("permit" | "deny"), rest @ ..] => {
                let action = if *action == "permit" {
                    AclAction::Permit
                } else {
                    AclAction::Deny
                };
                match crate::nxos::config::ace(seq, action, rest, lines_of(c)) {
                    Some(e) => acl.entries.push(e),
                    None => acl.unreadable.push(r.table.report_key(&c.key)),
                }
            }
            _ => acl.unreadable.push(r.table.report_key(&c.key)),
        }
    }
    acl
}
