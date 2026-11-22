//! The BGP neighbours of an NX-OS running config: the process of the
//! default VRF and of each `vrf` stanza, the neighbours and listen ranges,
//! and the `template peer`, `template peer-session` and `template
//! peer-policy` stanzas that they inherit from.

use std::collections::BTreeSet;

use crate::bgp_peers::{
    BgpConfig, Confederation, DEFAULT_VRF, Neighbour, Parent, Process, Settings, Sourced, Template,
    Templates, block, parse_asn, peer_of, remote_as, resolve,
};
use crate::coverage::{Reach, State, Table};
use crate::links::BgpPeer;
use crate::route_tables::{RouteTables, VRF};
use crate::stanza::Stanza;

/// The kinds of the templates and the words of the lines that inherit
/// from them.
const TEMPLATES: &[(&str, &str)] = &[
    ("peer", "template peer"),
    ("peer-session", "template peer-session"),
    ("peer-policy", "template peer-policy"),
];

/// The handled lines of a neighbour or a template, below its stanza.
const BODY: &[&str] = &[
    "remote-as ..",
    "inherit ..",
    "update-source *",
    "shutdown",
    "local-as ..",
];

/// The handled lines of the process of a VRF and of the default VRF.
const PROCESS: &[&str] = &["local-as *"];

/// Adds the handled BGP lines: the process line, the confederation, the
/// address-family stanzas, the VRF stanzas, the neighbours, the listen
/// ranges and the templates with their handled lines. The other lines of
/// a BGP stanza keep the state of the routing lines of their VRF. Call it
/// before the entries of the routing processes.
pub fn push_entries(t: &mut Table, tables: &RouteTables) {
    let p = "router bgp *";
    let node = |t: &mut Table, levels: &[&str]| t.push_levels(levels, State::Handled, Reach::Node);
    let tree =
        |t: &mut Table, levels: &[&str]| t.push_levels(levels, State::Handled, Reach::Subtree);
    node(t, &[p]);
    tree(t, &[p, "confederation identifier *"]);
    tree(t, &[p, "confederation peers .."]);
    tables.push_handled_vrfs(t, &["router bgp ..", &format!("vrf {VRF}")]);
    for scope in [vec![p], vec![p, "vrf *"]] {
        fn join<'a>(scope: &[&'a str], extra: &[&'a str]) -> Vec<&'a str> {
            scope.iter().chain(extra).copied().collect()
        }
        let at = |extra: &[&'static str]| join(&scope, extra);
        node(t, &at(&["address-family .."]));
        for line in PROCESS {
            tree(t, &at(&[line]));
        }
        let mut stanzas = vec!["neighbor *", "neighbor * remote-as .."];
        if scope.len() == 1 {
            stanzas.extend([
                "template peer *",
                "template peer-session *",
                "template peer-policy *",
            ]);
        }
        for stanza in stanzas {
            node(t, &at(&[stanza]));
            for line in BODY {
                tree(t, &at(&[stanza, line]));
            }
            node(t, &at(&[stanza, "address-family .."]));
            tree(t, &at(&[stanza, "address-family ..", "inherit .."]));
        }
    }
}

/// The source of an `inherit` line of a neighbour, a template or an
/// address family: the template and the sequence number of a peer-policy
/// template as its order.
fn inherit(words: &[&str]) -> Option<Parent> {
    let ["inherit", kind, name, rest @ ..] = words else {
        return None;
    };
    let (_, k) = TEMPLATES.iter().find(|(w, _)| w == kind)?;
    let order = rest.first().and_then(|x| x.parse().ok()).unwrap_or(0);
    Some(Parent::new(k, name, order))
}

fn body(
    s: &Stanza,
    read: &mut BTreeSet<u32>,
    mask: &dyn Fn(&str) -> String,
    settings: &mut Settings,
    parents: &mut Vec<Parent>,
) {
    block(s, read, mask, settings, parents, &inherit, "route-map");
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
    for c in s.children() {
        let w: Vec<&str> = c.key.split_whitespace().collect();
        let lines = (c.first_line, c.last_line);
        match w.as_slice() {
            ["confederation", "identifier", id] => {
                read.insert(c.first_line);
                confederation.identifier = Some(Sourced::new(
                    parse_asn(id).ok_or_else(|| mask(&c.key)),
                    lines,
                ));
            }
            ["confederation", "peers", rest @ ..] => {
                read.insert(c.first_line);
                let peers: Option<BTreeSet<u32>> = rest.iter().map(|a| parse_asn(a)).collect();
                confederation.peers = Some(Sourced::new(peers.ok_or_else(|| mask(&c.key)), lines));
            }
            ["template", kind, name] => {
                if let Some((_, k)) = TEMPLATES.iter().find(|(w, _)| w == kind) {
                    read.insert(c.first_line);
                    let mut t = Template {
                        lines: Some(lines),
                        ..Template::default()
                    };
                    body(c, read, mask, &mut t.settings, &mut t.parents);
                    templates.insert(((*k).to_string(), (*name).to_string()), t);
                }
            }
            _ => {}
        }
    }
    let mut cfg = BgpConfig::default();
    let default = Process {
        asn: asn.clone(),
        confederation: confederation.clone(),
    };
    scope(s, DEFAULT_VRF, default, read, mask, &templates, &mut cfg);
    for c in s.children() {
        if let ["vrf", v] = c.key.split_whitespace().collect::<Vec<_>>().as_slice() {
            read.insert(c.first_line);
            let p = Process {
                asn: asn.clone(),
                confederation: confederation.clone(),
            };
            scope(c, v, p, read, mask, &templates, &mut cfg);
        }
    }
    cfg
}

/// Reads the process lines and the neighbours of the default VRF or of a
/// `vrf` stanza.
fn scope(
    s: &Stanza,
    vrf: &str,
    mut process: Process,
    read: &mut BTreeSet<u32>,
    mask: &dyn Fn(&str) -> String,
    templates: &Templates,
    cfg: &mut BgpConfig,
) {
    for c in s.children() {
        let w: Vec<&str> = c.key.split_whitespace().collect();
        let lines = (c.first_line, c.last_line);
        match w.as_slice() {
            ["address-family", ..] => {
                read.insert(c.first_line);
            }
            ["local-as", a] => {
                read.insert(c.first_line);
                process.asn = Sourced::new(
                    parse_asn(a).ok_or_else(|| format!("{} not an AS number", mask(&c.key))),
                    lines,
                );
            }
            ["neighbor", peer, rest @ ..] => {
                read.insert(c.first_line);
                let mut own = Settings::default();
                let mut parents = Vec::new();
                if let ["remote-as", r @ ..] = rest {
                    own.remote_as = Some(Sourced::new(
                        remote_as(r, mask),
                        (c.first_line, c.first_line),
                    ));
                }
                body(c, read, mask, &mut own, &mut parents);
                let peer = peer_of(peer).unwrap_or_else(|| BgpPeer::Interface(mask(peer)));
                cfg.neighbours.push(Neighbour {
                    vrf: vrf.to_string(),
                    peer,
                    resolved: resolve(&own, &parents, templates),
                    lines,
                });
            }
            _ => {}
        }
    }
    cfg.processes.insert(vrf.to_string(), process);
}
