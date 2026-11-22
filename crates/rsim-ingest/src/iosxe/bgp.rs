//! The BGP neighbours of an IOS-XE running config: the `neighbor <peer>
//! <keyword>` lines of the global part of `router bgp` and of each
//! `address-family` stanza, the peer groups, the `template peer-session`
//! and `template peer-policy` stanzas, and the listen ranges.
//!
//! A line of the global part belongs to the default VRF, and a line of
//! `address-family <family> vrf <name>` to that VRF. A peer group belongs to
//! the VRF of its lines. A neighbour takes each setting that it does not
//! state from its `inherit` templates in their order, then from the peer
//! group of its VRF. A peer-policy that an address family other than IPv4
//! unicast inherits gives no policy. A neighbour of the default VRF is
//! active in IPv4 unicast by the default of the profile, unless `no bgp
//! default ipv4-unicast` or `no neighbor <peer> activate`, and so is a
//! listen range of the default VRF unless its peer group has `no neighbor
//! <group> activate`; a neighbour of a
//! VRF is active in the family of the stanza that gives its remote AS.

use std::collections::{BTreeMap, BTreeSet};

use super::profile::BGP_DEFAULT_IPV4_UNICAST;
use crate::bgp::IPV4_UNICAST;
use crate::bgp_peers::{
    BgpConfig, Confederation, DEFAULT_VRF, LocalAs, Neighbour, Parent, Process, Settings, Sourced,
    Template, Templates, family, parse_asn, peer_of, remote_as, resolve,
};
use crate::coverage::{Reach, State, Table};
use crate::links::BgpPeer;
use crate::route_tables::{RouteTables, VRF};
use crate::stanza::Stanza;

const PEER_GROUP: &str = "peer-group";
const SESSION_TEMPLATE: &str = "template peer-session";
const POLICY_TEMPLATE: &str = "template peer-policy";

/// The handled `neighbor` lines of the global part and of an address
/// family.
const NEIGHBOR_LINES: &[&str] = &[
    "neighbor * remote-as ..",
    "neighbor * peer-group",
    "neighbor * peer-group *",
    "neighbor * update-source *",
    "neighbor * shutdown",
    "neighbor * local-as ..",
    "neighbor * inherit ..",
    "neighbor * activate",
    "no neighbor * activate",
    "bgp listen range * peer-group *",
];

/// The handled lines of a template.
const TEMPLATE_LINES: &[&str] = &[
    "remote-as ..",
    "update-source *",
    "shutdown",
    "local-as ..",
    "inherit ..",
];

/// The address-family stanzas of a VRF.
const VRF_FAMILIES: &[&str] = &["address-family ipv4", "address-family ipv4 unicast"];

/// Adds the handled BGP lines: the process line, the confederation, the
/// default of IPv4 unicast, the address-family stanzas with the VRF
/// stanzas, the neighbour lines, the listen ranges, the templates with their
/// handled lines and the lines that close a stanza. The other lines of a
/// BGP stanza keep the state of the routing lines of their VRF. Call it
/// before the entries of the routing processes.
pub fn push_entries(t: &mut Table, tables: &RouteTables) {
    let p = "router bgp *";
    let node = |t: &mut Table, levels: &[&str]| t.push_levels(levels, State::Handled, Reach::Node);
    let tree =
        |t: &mut Table, levels: &[&str]| t.push_levels(levels, State::Handled, Reach::Subtree);
    node(t, &[p]);
    for line in [
        "bgp confederation identifier *",
        "bgp confederation peers ..",
        "no bgp default ipv4-unicast",
        "exit-peer-session",
        "exit-peer-policy",
        "exit-address-family",
    ] {
        tree(t, &[p, line]);
    }
    for af in VRF_FAMILIES {
        tables.push_handled_vrfs(t, &["router bgp ..", &format!("{af} vrf {VRF} ..")]);
    }
    node(t, &[p, "address-family .."]);
    for line in NEIGHBOR_LINES {
        tree(t, &[p, line]);
        tree(t, &[p, "address-family ..", line]);
    }
    for template in [SESSION_TEMPLATE, POLICY_TEMPLATE] {
        let stanza = format!("{template} *");
        node(t, &[p, &stanza]);
        for line in TEMPLATE_LINES {
            tree(t, &[p, &stanza, line]);
        }
    }
}

/// The settings of one name of a scope: a neighbour, a listen range or a
/// peer group.
#[derive(Default)]
struct Entry {
    settings: Settings,
    parents: Vec<Parent>,
    /// True for a peer group.
    group: bool,
    /// The lines of the first line of the name.
    lines: Option<(u32, u32)>,
}

/// The reader of one `router bgp` stanza.
struct Reader<'a> {
    read: &'a mut BTreeSet<u32>,
    mask: &'a dyn Fn(&str) -> String,
    /// The entries of each VRF by name.
    entries: BTreeMap<String, BTreeMap<String, Entry>>,
    /// The listen ranges of each VRF with their peer group.
    ranges: Vec<(String, String, String, (u32, u32))>,
    default_ipv4: Option<(u32, u32)>,
    /// The masked words of the address family of the lines that `line`
    /// reads when `family` does not name it.
    unread_family: Option<String>,
}

impl Reader<'_> {
    fn entry(&mut self, vrf: &str, name: &str, lines: (u32, u32)) -> &mut Entry {
        let e = self
            .entries
            .entry(vrf.to_string())
            .or_default()
            .entry(name.to_string())
            .or_default();
        e.lines.get_or_insert(lines);
        e
    }

    /// Reads one `neighbor` line, or a `bgp listen range` line, of the
    /// global part or of an address family of `fam` in `vrf`. `ipv4` is
    /// true for the global part and an address family of IPv4 unicast.
    fn line(&mut self, c: &Stanza, vrf: &str, fam: Option<&str>, ipv4: bool) {
        let w: Vec<&str> = c.key.split_whitespace().collect();
        let lines = (c.first_line, c.last_line);
        let mask = self.mask;
        let unread_family = self.unread_family.clone();
        match w.as_slice() {
            ["bgp", "listen", "range", range, "peer-group", g] => {
                self.read.insert(c.first_line);
                self.ranges.push((
                    vrf.to_string(),
                    (*range).to_string(),
                    (*g).to_string(),
                    lines,
                ));
            }
            ["no", "neighbor", n, "activate"] => {
                if let Some(f) = fam {
                    self.read.insert(c.first_line);
                    let e = self.entry(vrf, n, lines);
                    e.settings
                        .families
                        .insert(f.to_string(), Sourced::new(false, lines));
                }
            }
            ["neighbor", n, rest @ ..] => {
                let e = self.entry(vrf, n, lines);
                let s = &mut e.settings;
                let read = match rest {
                    ["remote-as", r @ ..] => {
                        s.remote_as = Some(Sourced::new(remote_as(r, mask), lines));
                        if let (Some(f), true) = (fam, vrf != DEFAULT_VRF) {
                            s.families
                                .entry(f.to_string())
                                .or_insert(Sourced::new(true, lines));
                        }
                        true
                    }
                    ["peer-group"] => {
                        e.group = true;
                        true
                    }
                    ["peer-group", g] => {
                        e.parents.retain(|p| p.kind != PEER_GROUP);
                        e.parents.push(Parent::new(PEER_GROUP, g, u32::MAX));
                        true
                    }
                    ["update-source", i] => {
                        s.update_source = Some(Sourced::new((*i).to_string(), lines));
                        true
                    }
                    ["shutdown"] => {
                        s.shutdown = Some(Sourced::new(true, lines));
                        true
                    }
                    ["local-as", r @ ..] => {
                        s.local_as = Some(Sourced::new(LocalAs::parse(r, mask(&c.key)), lines));
                        true
                    }
                    ["inherit", kind, name, seq @ ..] => match inherit(kind, name, seq) {
                        Some(p) => {
                            e.parents.push(p.with_ipv4_policy(ipv4));
                            true
                        }
                        None => false,
                    },
                    ["activate"] => match fam {
                        Some(f) => {
                            s.families.insert(f.to_string(), Sourced::new(true, lines));
                            true
                        }
                        None => {
                            s.unread_families.extend(unread_family);
                            false
                        }
                    },
                    ["route-map", m, dir] if fam == Some(IPV4_UNICAST) => {
                        let v = Some(Sourced::new((*m).to_string(), lines));
                        match *dir {
                            "in" => s.policy_in = v,
                            "out" => s.policy_out = v,
                            _ => {}
                        }
                        false
                    }
                    _ => false,
                };
                if read {
                    self.read.insert(c.first_line);
                }
            }
            _ => {}
        }
    }
}

/// The source of an `inherit` line.
fn inherit(kind: &str, name: &str, seq: &[&str]) -> Option<Parent> {
    let order = seq.first().and_then(|x| x.parse().ok()).unwrap_or(0);
    match kind {
        "peer-session" => Some(Parent::new(SESSION_TEMPLATE, name, order)),
        "peer-policy" => Some(Parent::new(POLICY_TEMPLATE, name, order)),
        _ => None,
    }
}

/// The settings of a `template peer-session` or `template peer-policy`
/// stanza.
fn template(c: &Stanza, read: &mut BTreeSet<u32>, mask: &dyn Fn(&str) -> String) -> Template {
    let mut t = Template {
        lines: Some((c.first_line, c.last_line)),
        ..Template::default()
    };
    for l in c.children() {
        let w: Vec<&str> = l.key.split_whitespace().collect();
        let lines = (l.first_line, l.last_line);
        let s = &mut t.settings;
        let handled = match w.as_slice() {
            ["remote-as", r @ ..] => {
                s.remote_as = Some(Sourced::new(remote_as(r, mask), lines));
                true
            }
            ["update-source", i] => {
                s.update_source = Some(Sourced::new((*i).to_string(), lines));
                true
            }
            ["shutdown"] => {
                s.shutdown = Some(Sourced::new(true, lines));
                true
            }
            ["local-as", r @ ..] => {
                s.local_as = Some(Sourced::new(LocalAs::parse(r, mask(&l.key)), lines));
                true
            }
            ["inherit", kind, name, seq @ ..] => match inherit(kind, name, seq) {
                Some(p) => {
                    t.parents.push(p);
                    true
                }
                None => false,
            },
            ["route-map", m, dir] => {
                let v = Some(Sourced::new((*m).to_string(), lines));
                match *dir {
                    "in" => s.policy_in = v,
                    "out" => s.policy_out = v,
                    _ => {}
                }
                false
            }
            _ => false,
        };
        if handled {
            read.insert(l.first_line);
        }
    }
    t
}

/// The VRF and the family of the words after `address-family`, for
/// example `ipv4 vrf RED` or `vpnv4`.
fn af_scope(words: &[&str]) -> (String, Option<String>) {
    let (fam, vrf) = match words.iter().position(|w| *w == "vrf") {
        Some(i) => (&words[..i], words.get(i + 1).copied()),
        None => (words, None),
    };
    (vrf.unwrap_or(DEFAULT_VRF).to_string(), family(fam))
}

/// Reads the BGP config of a `router bgp` stanza. Each line that a handler
/// reads goes into `read`.
pub fn read(s: &Stanza, read: &mut BTreeSet<u32>, mask: &dyn Fn(&str) -> String) -> BgpConfig {
    read.insert(s.first_line);
    let words: Vec<&str> = s.key.split_whitespace().collect();
    let asn_text = words.get(2).copied().unwrap_or_default();
    let asn = Sourced::new(
        parse_asn(asn_text)
            .ok_or_else(|| format!("router bgp {} not an AS number", mask(asn_text))),
        (s.first_line, s.first_line),
    );
    let mut confederation = Confederation::default();
    let mut templates = Templates::new();
    let mut r = Reader {
        read,
        mask,
        entries: BTreeMap::new(),
        ranges: Vec::new(),
        default_ipv4: None,
        unread_family: None,
    };
    for c in s.children() {
        let w: Vec<&str> = c.key.split_whitespace().collect();
        let lines = (c.first_line, c.last_line);
        match w.as_slice() {
            ["bgp", "confederation", "identifier", id] => {
                r.read.insert(c.first_line);
                confederation.identifier = Some(Sourced::new(
                    parse_asn(id).ok_or_else(|| mask(&c.key)),
                    lines,
                ));
            }
            ["bgp", "confederation", "peers", rest @ ..] => {
                r.read.insert(c.first_line);
                let peers: Option<BTreeSet<u32>> = rest.iter().map(|a| parse_asn(a)).collect();
                confederation.peers = Some(Sourced::new(peers.ok_or_else(|| mask(&c.key)), lines));
            }
            ["no", "bgp", "default", "ipv4-unicast"] => {
                r.read.insert(c.first_line);
                r.default_ipv4 = Some(lines);
            }
            ["exit-peer-session" | "exit-peer-policy" | "exit-address-family"] => {
                r.read.insert(c.first_line);
            }
            ["template", kind @ ("peer-session" | "peer-policy"), name] => {
                r.read.insert(c.first_line);
                let k = format!("template {kind}");
                templates.insert((k, (*name).to_string()), template(c, r.read, mask));
            }
            ["address-family", rest @ ..] => {
                r.read.insert(c.first_line);
                let (vrf, fam) = af_scope(rest);
                let ipv4 = fam.as_deref() == Some(IPV4_UNICAST);
                r.unread_family = fam.is_none().then(|| mask(&rest.join(" ")));
                for l in c.children() {
                    r.line(l, &vrf, fam.as_deref(), ipv4);
                }
                r.unread_family = None;
            }
            _ => r.line(c, DEFAULT_VRF, None, true),
        }
    }
    let default_on = BGP_DEFAULT_IPV4_UNICAST && r.default_ipv4.is_none();
    // The templates of each VRF: the session and policy templates and the
    // peer groups of that VRF, as templates of the kind `peer-group`.
    let mut scoped: BTreeMap<String, Templates> = BTreeMap::new();
    for (vrf, names) in &r.entries {
        let t = scoped
            .entry(vrf.clone())
            .or_insert_with(|| templates.clone());
        for (name, e) in names.iter().filter(|(_, e)| e.group) {
            t.insert(
                (PEER_GROUP.to_string(), name.clone()),
                Template {
                    settings: e.settings.clone(),
                    parents: e.parents.clone(),
                    lines: e.lines,
                },
            );
        }
    }
    let of_vrf = |vrf: &str| scoped.get(vrf).unwrap_or(&templates);
    let mut cfg = BgpConfig::default();
    let vrfs: BTreeSet<String> = std::iter::once(DEFAULT_VRF.to_string())
        .chain(r.entries.keys().cloned())
        .chain(r.ranges.iter().map(|x| x.0.clone()))
        .collect();
    for vrf in &vrfs {
        cfg.processes.insert(
            vrf.clone(),
            Process {
                asn: asn.clone(),
                confederation: confederation.clone(),
            },
        );
    }
    for (vrf, names) in &r.entries {
        for (name, e) in names.iter().filter(|(_, e)| !e.group) {
            let Some(peer) = peer_of(name) else {
                continue;
            };
            let mut own = e.settings.clone();
            if vrf == DEFAULT_VRF
                && default_on
                && let Some(l) = e.lines
            {
                own.families
                    .entry(IPV4_UNICAST.to_string())
                    .or_insert(Sourced::new(true, l));
            }
            cfg.neighbours.push(Neighbour {
                vrf: vrf.clone(),
                peer,
                resolved: resolve(&own, &e.parents, of_vrf(vrf)),
                lines: e.lines.unwrap_or((s.first_line, s.first_line)),
            });
        }
    }
    for (vrf, range, group, lines) in &r.ranges {
        let Some(peer @ BgpPeer::Range(_)) = peer_of(range) else {
            continue;
        };
        let mut resolved = resolve(
            &Settings::default(),
            &[Parent::new(PEER_GROUP, group, 0)],
            of_vrf(vrf),
        );
        if vrf == DEFAULT_VRF && default_on {
            resolved
                .settings
                .families
                .entry(IPV4_UNICAST.to_string())
                .or_insert(Sourced::new(true, *lines));
        }
        cfg.neighbours.push(Neighbour {
            vrf: vrf.clone(),
            peer,
            resolved,
            lines: *lines,
        });
    }
    cfg
}
