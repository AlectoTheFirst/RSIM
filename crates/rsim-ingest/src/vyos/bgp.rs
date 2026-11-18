//! The BGP neighbours of a VyOS config: `protocols bgp` of the main VRF and
//! of each `vrf name <name>`, the neighbours, the peer groups and the
//! listen ranges. A neighbour takes each setting that it does not state
//! from its peer group. The process of VyOS 1.3, `protocols bgp <asn>`, is
//! not read: its AS and its neighbours are not known.

use std::collections::BTreeSet;

use crate::bgp::IPV4_UNICAST;
use crate::bgp_peers::{
    BgpConfig, Confederation, DEFAULT_VRF, LocalAs, Neighbour, Parent, Process, RemoteAs, Settings,
    Sourced, Template, Templates, family, parse_asn, peer_of, resolve,
};
use crate::coverage::{Reach, State, Table};
use crate::links::BgpPeer;
use crate::route_tables::{RouteTables, VRF};
use crate::stanza::{Body, Stanza};

const PEER_GROUP: &str = "peer-group";

/// The handled settings of a neighbour and of a peer group.
const SETTINGS: &[&str] = &["remote-as", "update-source", "shutdown", "local-as"];

/// Adds the handled BGP paths of the main VRF and of each VRF: the
/// process, its AS, the confederation, the neighbours, the peer groups and
/// the listen ranges with their handled settings, and the address-family
/// stanzas. The other paths keep the state of the routing paths of their
/// VRF. Call it before the entries of the routing paths.
pub fn push_entries(t: &mut Table, tables: &RouteTables) {
    let node = |t: &mut Table, p: &str| t.push(p, State::Handled, Reach::Node);
    let tree = |t: &mut Table, p: &str| t.push(p, State::Handled, Reach::Subtree);
    node(t, "protocols/bgp");
    for p in ["vrf", "vrf/name", "vrf/name/*", "vrf/name/*/protocols"] {
        node(t, p);
    }
    tables.push_handled_vrfs(t, &["vrf", "name", VRF, "protocols", "bgp"]);
    for base in ["protocols/bgp", "vrf/name/*/protocols/bgp"] {
        tree(t, &format!("{base}/system-as"));
        node(t, &format!("{base}/parameters"));
        tree(t, &format!("{base}/parameters/confederation"));
        node(t, &format!("{base}/address-family"));
        node(t, &format!("{base}/address-family/*"));
        for p in ["listen", "listen/range", "listen/range/*"] {
            node(t, &format!("{base}/{p}"));
        }
        tree(t, &format!("{base}/listen/range/*/peer-group"));
        for kind in ["neighbor", "peer-group"] {
            node(t, &format!("{base}/{kind}"));
            node(t, &format!("{base}/{kind}/*"));
            for s in SETTINGS {
                tree(t, &format!("{base}/{kind}/*/{s}"));
            }
            node(t, &format!("{base}/{kind}/*/address-family"));
            node(t, &format!("{base}/{kind}/*/address-family/*"));
        }
        tree(t, &format!("{base}/neighbor/*/peer-group"));
    }
}

/// Reads the settings of a neighbour or a peer group.
fn settings(s: &Stanza, read: &mut BTreeSet<u32>) -> Settings {
    let mut out = Settings::default();
    let lines = |x: &Stanza| (x.first_line, x.last_line);
    for c in s.children() {
        match c.key.as_str() {
            "remote-as" => {
                read.insert(c.first_line);
                let v = match c.text().unwrap_or_default() {
                    "internal" => RemoteAs::Internal,
                    "external" => RemoteAs::External,
                    "auto" => RemoteAs::Auto,
                    t => parse_asn(t)
                        .map_or_else(|| RemoteAs::Unreadable(t.to_string()), RemoteAs::Asn),
                };
                out.remote_as = Some(Sourced::new(v, lines(c)));
            }
            "update-source" => {
                read.insert(c.first_line);
                if let Some(t) = c.text() {
                    out.update_source = Some(Sourced::new(t.to_string(), lines(c)));
                }
            }
            "shutdown" => {
                read.insert(c.first_line);
                out.shutdown = Some(Sourced::new(true, lines(c)));
            }
            "local-as" => {
                read.insert(c.first_line);
                out.local_as = Some(Sourced::new(local_as(c, read), lines(c)));
            }
            "address-family" => {
                read.insert(c.first_line);
                for f in c.children() {
                    let Some(name) = family(&[f.key.as_str()]) else {
                        out.unread_families.insert(f.key.clone());
                        continue;
                    };
                    read.insert(f.first_line);
                    out.families
                        .insert(name.clone(), Sourced::new(true, lines(f)));
                    if name == IPV4_UNICAST {
                        let map = |dir: &str| {
                            let x = f.at(&["route-map", dir])?;
                            Some(Sourced::new(x.text()?.to_string(), lines(x)))
                        };
                        out.policy_in = map("import");
                        out.policy_out = map("export");
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// The local AS of `local-as <asn> [no-prepend [replace-as]]`, a node
/// with the AS as its key and the options below it. More than one AS is
/// not read.
fn local_as(s: &Stanza, read: &mut BTreeSet<u32>) -> LocalAs {
    let keys: Vec<&Stanza> = s.children().iter().collect();
    let text = keys
        .iter()
        .map(|k| k.key.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let [k] = keys.as_slice() else {
        return LocalAs::parse(&["(more than one AS)"], text);
    };
    read.insert(k.first_line);
    let mut words = vec![k.key.as_str()];
    let mut cur = *k;
    while let Body::Object(c) = &cur.body {
        let [next] = c.as_slice() else {
            break;
        };
        read.insert(next.first_line);
        words.push(next.key.as_str());
        cur = next;
    }
    LocalAs::parse(&words, words.join(" "))
}

/// Reads the BGP config of `protocols bgp` of the main VRF and of each VRF.
/// Each path that a handler reads goes into `read`.
pub fn read(root: &Stanza, read: &mut BTreeSet<u32>) -> BgpConfig {
    let mut cfg = BgpConfig::default();
    if let Some(b) = root.at(&["protocols", "bgp"]) {
        process(b, DEFAULT_VRF, read, &mut cfg);
    }
    if let Some(v) = root.get("vrf") {
        read.insert(v.first_line);
        if let Some(names) = v.get("name") {
            read.insert(names.first_line);
            for n in names.children() {
                read.insert(n.first_line);
                if let Some(p) = n.get("protocols") {
                    read.insert(p.first_line);
                    if let Some(b) = p.get("bgp") {
                        process(b, &n.key, read, &mut cfg);
                    }
                }
            }
        }
    }
    cfg
}

/// Reads one `protocols bgp` stanza of a VRF.
fn process(b: &Stanza, vrf: &str, read: &mut BTreeSet<u32>, cfg: &mut BgpConfig) {
    read.insert(b.first_line);
    let lines = |x: &Stanza| (x.first_line, x.last_line);
    let legacy = b
        .children()
        .iter()
        .find(|c| c.key.bytes().all(|x| x.is_ascii_digit()));
    let asn = match (b.get("system-as"), legacy) {
        (_, Some(l)) => Sourced::new(
            Err(format!(
                "the VyOS 1.3 process protocols bgp {} is not read",
                l.key
            )),
            lines(l),
        ),
        (Some(s), None) => {
            read.insert(s.first_line);
            let t = s.text().unwrap_or_default();
            Sourced::new(
                parse_asn(t).ok_or_else(|| format!("system-as {t} is not an AS number")),
                lines(s),
            )
        }
        (None, None) => Sourced::new(Err("protocols bgp has no system-as".to_string()), lines(b)),
    };
    let mut confederation = Confederation::default();
    if let Some(p) = b.get("parameters") {
        read.insert(p.first_line);
        if let Some(c) = p.get("confederation") {
            read.insert(c.first_line);
            if let Some(id) = c.get("identifier") {
                read.insert(id.first_line);
                let t = id.text().unwrap_or_default();
                confederation.identifier = Some(Sourced::new(
                    parse_asn(t).ok_or_else(|| format!("identifier {t}")),
                    lines(id),
                ));
            }
            if let Some(peers) = c.get("peers") {
                read.insert(peers.first_line);
                for x in peers.children() {
                    read.insert(x.first_line);
                }
                let texts = peers.texts();
                let set: Option<BTreeSet<u32>> = texts.iter().map(|t| parse_asn(t)).collect();
                confederation.peers = Some(Sourced::new(
                    set.ok_or_else(|| format!("peers {}", texts.join(" "))),
                    lines(peers),
                ));
            }
        }
    }
    if let Some(af) = b.get("address-family") {
        read.insert(af.first_line);
        for f in af.children() {
            read.insert(f.first_line);
        }
    }
    let mut groups = Templates::new();
    if let Some(pg) = b.get(PEER_GROUP) {
        read.insert(pg.first_line);
        for g in pg.children() {
            read.insert(g.first_line);
            groups.insert(
                (PEER_GROUP.to_string(), g.key.clone()),
                Template {
                    settings: settings(g, read),
                    parents: Vec::new(),
                    lines: Some(lines(g)),
                },
            );
        }
    }
    if let Some(ns) = b.get("neighbor") {
        read.insert(ns.first_line);
        for n in ns.children() {
            read.insert(n.first_line);
            let own = settings(n, read);
            let parents: Vec<Parent> = match n.get(PEER_GROUP) {
                Some(g) => {
                    read.insert(g.first_line);
                    g.text()
                        .map(|t| vec![Parent::new(PEER_GROUP, t, 0)])
                        .unwrap_or_default()
                }
                None => Vec::new(),
            };
            let peer = peer_of(&n.key).unwrap_or_else(|| BgpPeer::Interface(n.key.clone()));
            cfg.neighbours.push(Neighbour {
                vrf: vrf.to_string(),
                peer,
                resolved: resolve(&own, &parents, &groups),
                lines: lines(n),
            });
        }
    }
    if let Some(l) = b.get("listen") {
        read.insert(l.first_line);
        if let Some(ranges) = l.get("range") {
            read.insert(ranges.first_line);
            for r in ranges.children() {
                read.insert(r.first_line);
                let Some(peer @ BgpPeer::Range(_)) = peer_of(&r.key) else {
                    continue;
                };
                let parents: Vec<Parent> = match r.get(PEER_GROUP) {
                    Some(g) => {
                        read.insert(g.first_line);
                        g.text()
                            .map(|t| vec![Parent::new(PEER_GROUP, t, 0)])
                            .unwrap_or_default()
                    }
                    None => Vec::new(),
                };
                cfg.neighbours.push(Neighbour {
                    vrf: vrf.to_string(),
                    peer,
                    resolved: resolve(&Settings::default(), &parents, &groups),
                    lines: lines(r),
                });
            }
        }
    }
    cfg.processes
        .insert(vrf.to_string(), Process { asn, confederation });
}
