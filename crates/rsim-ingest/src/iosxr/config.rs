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
    /// The masked lines of the options that the handlers do not read: the
    /// unhandled options and the handled lines with a form that the handler
    /// cannot read.
    pub unhandled: Vec<String>,
    pub lines: Lines,
}

/// The typed structures of a running config.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// The name of the line `hostname`.
    pub hostname: Option<String>,
    pub interfaces: Vec<Interface>,
    /// The VRFs of the config, with the lines of their `vrf` stanza.
    pub vrfs: BTreeMap<String, Lines>,
    /// The IPv4 access lists.
    pub acls: BTreeMap<String, Acl>,
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
            ["vrf", name] => {
                r.mark(s);
                cfg.vrfs.insert((*name).to_string(), lines_of(s));
            }
            ["ipv4", "access-list", name] => {
                r.mark(s);
                let acl = access_list(&mut r, s, name);
                cfg.acls.insert((*name).to_string(), acl);
            }
            _ => {}
        }
    }
    cfg.read = r.read;
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
