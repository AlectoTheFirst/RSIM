//! The BGP neighbours of an IOS-XR running config: the process of the
//! default VRF and of each `vrf` stanza, the neighbours and listen ranges,
//! and the `neighbor-group` and `session-group` stanzas that they use.
//!
//! A neighbour takes each setting that it does not state from its
//! neighbor-group, then from its session-group, else from the
//! session-group of its neighbor-group. A session-group takes the settings
//! of the session-group that it uses.

use std::collections::{BTreeMap, BTreeSet};

use crate::bgp_peers::{
    BgpConfig, Confederation, DEFAULT_VRF, Neighbour, Parent, Process, Settings, Sourced, Template,
    Templates, block, parse_asn, peer_of, resolve,
};
use crate::coverage::{Reach, State, Table};
use crate::links::BgpPeer;
use crate::route_tables::{RouteTables, VRF};
use crate::stanza::Stanza;

const NEIGHBOR_GROUP: &str = "neighbor-group";
const SESSION_GROUP: &str = "session-group";

/// The handled lines of a neighbour or a group, below its stanza.
const BODY: &[&str] = &[
    "remote-as *",
    "use neighbor-group *",
    "use session-group *",
    "update-source *",
    "shutdown",
    "shutdown inheritance-disable",
    "local-as ..",
];

/// Adds the handled BGP lines: the process line, the confederation, the
/// address-family stanzas, the VRF stanzas, the neighbours, the listen
/// ranges and the groups with their handled lines. The other lines of a
/// BGP stanza keep the state of the routing lines of their VRF. Call it
/// before the entries of the routing processes.
pub fn push_entries(t: &mut Table, tables: &RouteTables) {
    let p = "router bgp *";
    let node = |t: &mut Table, levels: &[&str]| t.push_levels(levels, State::Handled, Reach::Node);
    let tree =
        |t: &mut Table, levels: &[&str]| t.push_levels(levels, State::Handled, Reach::Subtree);
    node(t, &[p]);
    tree(t, &[p, "bgp confederation identifier *"]);
    tree(t, &[p, "bgp confederation peers .."]);
    tables.push_handled_vrfs(t, &["router bgp ..", &format!("vrf {VRF}")]);
    fn join<'a>(scope: &[&'a str], extra: &[&'a str]) -> Vec<&'a str> {
        scope.iter().chain(extra).copied().collect()
    }
    for scope in [vec![p], vec![p, "vrf *"]] {
        let at = |extra: &[&'static str]| join(&scope, extra);
        node(t, &at(&["address-family .."]));
        let mut stanzas = vec!["neighbor *"];
        if scope.len() == 1 {
            stanzas.extend(["neighbor-group *", "session-group *"]);
        }
        for stanza in stanzas {
            node(t, &at(&[stanza]));
            for line in BODY {
                tree(t, &at(&[stanza, line]));
            }
            node(t, &at(&[stanza, "address-family .."]));
        }
    }
}

/// The source of a `use` line of a neighbour or a group.
fn inherit(words: &[&str]) -> Option<Parent> {
    match words {
        ["use", kind @ ("neighbor-group" | "session-group"), name] => {
            Some(Parent::new(kind, name, 0))
        }
        _ => None,
    }
}

fn body(
    s: &Stanza,
    read: &mut BTreeSet<u32>,
    mask: &dyn Fn(&str) -> String,
    settings: &mut Settings,
    parents: &mut Vec<Parent>,
) {
    block(s, read, mask, settings, parents, &inherit, "route-policy");
}

/// The ASes of the lines below `bgp confederation peers` and of the words
/// after it.
fn confederation_peers(c: &Stanza, read: &mut BTreeSet<u32>) -> Option<BTreeSet<u32>> {
    let mut out = BTreeSet::new();
    let words: Vec<&str> = c.key.split_whitespace().skip(3).collect();
    for w in words {
        out.insert(parse_asn(w)?);
    }
    for m in c.children() {
        read.insert(m.first_line);
        for w in m.key.split_whitespace() {
            out.insert(parse_asn(w)?);
        }
    }
    Some(out)
}

/// Reads the BGP config of a `router bgp` stanza. Each line that a handler
/// reads goes into `read`.
pub fn read(s: &Stanza, read: &mut BTreeSet<u32>, mask: &dyn Fn(&str) -> String) -> BgpConfig {
    read.insert(s.first_line);
    let words: Vec<&str> = s.key.split_whitespace().collect();
    let asn_text = words.get(2).copied().unwrap_or_default();
    let asn = Sourced::new(
        parse_asn(asn_text)
            .ok_or_else(|| format!("router bgp {} is not an AS number", mask(asn_text))),
        (s.first_line, s.first_line),
    );
    let mut confederation = Confederation::default();
    let mut groups = Templates::new();
    let mut group_sessions = BTreeMap::new();
    for c in s.children() {
        let w: Vec<&str> = c.key.split_whitespace().collect();
        let lines = (c.first_line, c.last_line);
        match w.as_slice() {
            ["bgp", "confederation", "identifier", id] => {
                read.insert(c.first_line);
                confederation.identifier = Some(Sourced::new(
                    parse_asn(id).ok_or_else(|| mask(&c.key)),
                    lines,
                ));
            }
            ["bgp", "confederation", "peers", ..] => {
                read.insert(c.first_line);
                confederation.peers = Some(Sourced::new(
                    confederation_peers(c, read).ok_or_else(|| mask(&c.key)),
                    lines,
                ));
            }
            [kind @ ("neighbor-group" | "session-group"), name] => {
                read.insert(c.first_line);
                let mut g = Template {
                    lines: Some(lines),
                    ..Template::default()
                };
                body(c, read, mask, &mut g.settings, &mut g.parents);
                if *kind == NEIGHBOR_GROUP {
                    if let Some(p) = g.parents.iter().find(|p| p.kind == SESSION_GROUP) {
                        group_sessions.insert((*name).to_string(), p.name.clone());
                    }
                    g.parents.retain(|p| p.kind != SESSION_GROUP);
                }
                groups.insert(((*kind).to_string(), (*name).to_string()), g);
            }
            _ => {}
        }
    }
    let mut cfg = BgpConfig::default();
    let process = || Process {
        asn: asn.clone(),
        confederation: confederation.clone(),
    };
    scope(
        s,
        DEFAULT_VRF,
        process(),
        read,
        mask,
        &groups,
        &group_sessions,
        &mut cfg,
    );
    for c in s.children() {
        if let ["vrf", v] = c.key.split_whitespace().collect::<Vec<_>>().as_slice() {
            read.insert(c.first_line);
            scope(
                c,
                v,
                process(),
                read,
                mask,
                &groups,
                &group_sessions,
                &mut cfg,
            );
        }
    }
    cfg
}

/// Reads the address-family lines and the neighbours of the default VRF or
/// of a `vrf` stanza. `sessions` gives the session-group of each
/// neighbor-group that names one.
#[allow(clippy::too_many_arguments)]
fn scope(
    s: &Stanza,
    vrf: &str,
    process: Process,
    read: &mut BTreeSet<u32>,
    mask: &dyn Fn(&str) -> String,
    groups: &Templates,
    sessions: &BTreeMap<String, String>,
    cfg: &mut BgpConfig,
) {
    for c in s.children() {
        let w: Vec<&str> = c.key.split_whitespace().collect();
        match w.as_slice() {
            ["address-family", ..] => {
                read.insert(c.first_line);
            }
            ["neighbor", peer] => {
                read.insert(c.first_line);
                let mut own = Settings::default();
                let mut parents = Vec::new();
                body(c, read, mask, &mut own, &mut parents);
                // The session-group of the neighbour, else the one of its
                // neighbor-group, after the neighbor-group.
                let own_session = parents
                    .iter()
                    .find(|p| p.kind == SESSION_GROUP)
                    .map(|p| p.name.clone());
                parents.retain(|p| p.kind != SESSION_GROUP);
                let group_session = parents.iter().find_map(|p| sessions.get(&p.name).cloned());
                if let Some(sg) = own_session.or(group_session) {
                    parents.push(Parent::new(SESSION_GROUP, &sg, 1));
                }
                let peer = peer_of(peer).unwrap_or_else(|| BgpPeer::Interface(mask(peer)));
                cfg.neighbours.push(Neighbour {
                    vrf: vrf.to_string(),
                    peer,
                    resolved: resolve(&own, &parents, groups),
                    lines: (c.first_line, c.last_line),
                });
            }
            _ => {}
        }
    }
    cfg.processes.insert(vrf.to_string(), process);
}
