//! The BGP processes of a VyOS config for the BGP calculation: `protocols
//! bgp` of the main VRF and of each `vrf name <name>`, with the router ID,
//! the cluster ID, the `parameters` options, `maximum-paths`, the `network`
//! and `aggregate-address` nodes and the neighbours, and the FRR route maps,
//! prefix lists, community lists and AS-path lists of `policy`.
//!
//! The settings of a neighbour in a unicast family come from its own
//! `address-family` node, then from its peer group. FRR sends the standard
//! and the extended communities unless `disable-send-community` states
//! otherwise. `parameters ebgp-requires-policy` sets the FRR rule of an
//! eBGP neighbour with no policy, and its absence clears it. A neighbour is
//! active only in the families of its `address-family` nodes. A `network`
//! needs the route of its prefix only with `parameters
//! network-import-check`. A node of a process, a neighbour or a peer group
//! that the reader does not lower, other than a node with no effect on the
//! routes, is a gap.
//!
//! The nodes that import or export routes between VRFs or between EVPN and
//! a VRF are gaps of their VRF: the `vni` of a `vrf name`, each node of the
//! `l2vpn-evpn` family of a VRF process, `advertise` and `route-target` of
//! the `l2vpn-evpn` family of the main process, and the nodes of a unicast
//! family that the reader does not lower, for example `import vrf` and
//! `route-target vpn`. `advertise-all-vni` of the main process is a gap of
//! each VRF with a `vni`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use rsim_core::Prefix;
use rsim_routing::Platform;
use rsim_routing::bgp::{
    Aggregate, AsPathLine, AsPathList, Asn, BgpOptions, BgpProcess, Clause, Cmp, Community,
    CommunityLine, CommunityList, Continue, Family, MatchTerm, Network, NextHopMatch, NextHopSelf,
    NextHopSet, PolicyBody, PolicySet, PrefixList, PrefixListEntry, RouteKey, RoutePolicy,
    SetAction,
};

use crate::bgp_build::CollectedBgp;
use crate::bgp_config::{AfSettings, DeviceBgp, UNICAST, neighbor, no_effect, span, unicast_of};
use crate::bgp_peers::{BgpConfig, DEFAULT_VRF};
use crate::coverage::{Reach, State, Table};
use crate::links::BgpPeer;
use crate::stanza::{Body, Stanza};

fn lines(s: &Stanza) -> (u32, u32) {
    (s.first_line, s.last_line)
}

/// Marks a stanza and each stanza below it.
fn mark_all(s: &Stanza, read: &mut BTreeSet<u32>) {
    read.insert(s.first_line);
    for c in s.children() {
        mark_all(c, read);
    }
}

/// The keys of a path of a stanza and of the first child of each object
/// below it with one child, as the text of a gap, for example
/// `redistribute connected`.
fn text_of(s: &Stanza) -> String {
    let mut out = vec![s.key.clone()];
    let mut cur = s;
    loop {
        match &cur.body {
            Body::Object(c) if c.len() == 1 => {
                out.push(c[0].key.clone());
                cur = &c[0];
            }
            Body::Scalar(v) if !v.is_empty() => {
                out.push(v.clone());
                break;
            }
            _ => break,
        }
    }
    out.join(" ")
}

/// The handled options of `parameters`.
const PARAMETERS: &[&str] = &[
    "router-id",
    "cluster-id",
    "ebgp-requires-policy",
    "deterministic-med",
    "always-compare-med",
    "network-import-check",
    "bestpath/compare-routerid",
    "bestpath/as-path/multipath-relax",
    "bestpath/med/missing-as-worst",
    "default/local-pref",
];

/// The handled nodes of a unicast address family of a neighbour or a peer
/// group.
const AF_NODES: &[&str] = &[
    "route-map",
    "route-reflector-client",
    "nexthop-self",
    "disable-send-community",
];

/// Adds the handled paths that the reader lowers. Call it before the
/// entries of the routing paths.
pub fn push_entries(t: &mut Table) {
    let node = |t: &mut Table, p: &str| t.push(p, State::Handled, Reach::Node);
    let tree = |t: &mut Table, p: &str| t.push(p, State::Handled, Reach::Subtree);
    for base in ["protocols/bgp", "vrf/name/*/protocols/bgp"] {
        for p in ["bestpath", "bestpath/as-path", "bestpath/med", "default"] {
            node(t, &format!("{base}/parameters/{p}"));
        }
        for p in PARAMETERS {
            tree(t, &format!("{base}/parameters/{p}"));
        }
        node(t, &format!("{base}/address-family/*/network"));
        node(t, &format!("{base}/address-family/*/aggregate-address"));
        node(t, &format!("{base}/address-family/*/aggregate-address/*"));
        for o in ["summary-only", "as-set"] {
            tree(
                t,
                &format!("{base}/address-family/*/aggregate-address/*/{o}"),
            );
        }
        tree(t, &format!("{base}/address-family/*/maximum-paths"));
        for kind in ["neighbor", "peer-group"] {
            for p in AF_NODES {
                tree(t, &format!("{base}/{kind}/*/address-family/*/{p}"));
            }
            node(
                t,
                &format!("{base}/{kind}/*/address-family/*/remove-private-as"),
            );
        }
    }
    for p in [
        "policy/route-map",
        "policy/prefix-list",
        "policy/prefix-list6",
        "policy/community-list",
        "policy/as-path-list",
    ] {
        tree(t, p);
    }
}

/// The kind of a node of a neighbour, a peer group or a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Line {
    Read,
    /// The reader of the neighbours reads the node.
    Other,
    NoEffect,
    Gap,
}

/// Reads one node of a unicast address family of a neighbour or a peer
/// group into `af`.
fn af_node(s: &Stanza, af: &mut AfSettings, read: &mut BTreeSet<u32>) -> Line {
    match s.key.as_str() {
        "route-map" => {
            for c in s.children() {
                let v = c.text().map(str::to_string);
                match c.key.as_str() {
                    "import" => af.import = v,
                    "export" => af.export = v,
                    _ => return Line::Gap,
                }
            }
            mark_all(s, read);
            Line::Read
        }
        "route-reflector-client" => {
            af.rr_client = Some(true);
            mark_all(s, read);
            Line::Read
        }
        "nexthop-self" => {
            let force = s.get("force").is_some();
            if s.children().len() > usize::from(force) {
                return Line::Gap;
            }
            af.next_hop_self = Some(if force {
                NextHopSelf::All
            } else {
                NextHopSelf::On
            });
            mark_all(s, read);
            Line::Read
        }
        "disable-send-community" => {
            for c in s.children() {
                match c.key.as_str() {
                    "standard" => af.send_community = Some(false),
                    "extended" => af.send_community_extended = Some(false),
                    _ => return Line::Gap,
                }
            }
            mark_all(s, read);
            Line::Read
        }
        "remove-private-as" if s.children().is_empty() => {
            af.remove_private_as = Some(true);
            read.insert(s.first_line);
            Line::Read
        }
        k if no_effect(&[k]) => Line::NoEffect,
        _ => Line::Gap,
    }
}

/// The kind of a node of a neighbour or a peer group outside its address
/// families.
fn session_node(key: &str) -> Line {
    match key {
        "remote-as" | "update-source" | "shutdown" | "local-as" | "peer-group"
        | "address-family" => Line::Other,
        k if no_effect(&[k]) => Line::NoEffect,
        _ => Line::Gap,
    }
}

/// A gap node: the text, the lines and the families.
type GapLine = (String, (u32, u32), Vec<Family>);

/// The settings of a neighbour or a peer group in each unicast family and
/// its gap nodes.
type Settings = (BTreeMap<Family, AfSettings>, Vec<GapLine>);

/// The settings of a neighbour or a peer group in each unicast family and
/// its gap nodes.
fn settings_of(s: &Stanza, read: &mut BTreeSet<u32>) -> Settings {
    let mut af = BTreeMap::new();
    let mut gaps = Vec::new();
    for c in s.children() {
        if session_node(&c.key) == Line::Gap {
            gaps.push((text_of(c), lines(c), UNICAST.to_vec()));
        }
    }
    if let Some(fams) = s.get("address-family") {
        for f in fams.children() {
            let Some(fam) = unicast_of(&f.key) else {
                continue;
            };
            let mut a = AfSettings::default();
            for n in f.children() {
                if af_node(n, &mut a, read) == Line::Gap {
                    gaps.push((
                        format!("address-family {} {}", f.key, text_of(n)),
                        lines(n),
                        vec![fam],
                    ));
                }
            }
            af.insert(fam, a);
        }
    }
    (af, gaps)
}

/// The prefix lists of `prefix-list` as `ip <name>` and of `prefix-list6`
/// as `ipv6 <name>`. A list with a rule that is not read is left out.
fn prefix_lists(policy: &Stanza, set: &mut PolicySet) {
    for (key, v6) in [("prefix-list", false), ("prefix-list6", true)] {
        let Some(lists) = policy.get(key) else {
            continue;
        };
        for list in lists.children() {
            let mut entries = Vec::new();
            let mut ok = true;
            for rule in list.get("rule").map(Stanza::children).unwrap_or_default() {
                let entry = (|| {
                    let seq: u32 = rule.key.parse().ok()?;
                    let permit = match rule.get("action")?.text()? {
                        "permit" => true,
                        "deny" => false,
                        _ => return None,
                    };
                    let prefix: Prefix = rule.get("prefix")?.text()?.parse().ok()?;
                    if prefix.is_ipv4() == v6 {
                        return None;
                    }
                    let num = |k: &str| -> Option<Option<u8>> {
                        match rule.get(k) {
                            None => Some(None),
                            Some(x) => x.text()?.parse().ok().map(Some),
                        }
                    };
                    let known = ["action", "prefix", "ge", "le", "description"];
                    if rule
                        .children()
                        .iter()
                        .any(|c| !known.contains(&c.key.as_str()))
                    {
                        return None;
                    }
                    Some(PrefixListEntry::new(
                        seq,
                        permit,
                        prefix,
                        num("ge")?,
                        num("le")?,
                        None,
                    ))
                })();
                match entry {
                    Some(e) => entries.push(e),
                    None => ok = false,
                }
            }
            if ok {
                let name = if v6 { "ipv6" } else { "ip" };
                set.prefix_lists
                    .insert(format!("{name} {}", list.key), PrefixList::new(entries));
            }
        }
    }
}

/// The action and the regular expression of a rule of a community list or
/// an AS-path list.
fn regex_rule(rule: &Stanza) -> Option<(u32, bool, String)> {
    let seq: u32 = rule.key.parse().ok()?;
    let permit = match rule.get("action")?.text()? {
        "permit" => true,
        "deny" => false,
        _ => return None,
    };
    let known = ["action", "regex", "description"];
    if rule
        .children()
        .iter()
        .any(|c| !known.contains(&c.key.as_str()))
    {
        return None;
    }
    Some((seq, permit, rule.get("regex")?.text()?.to_string()))
}

/// The community lists, which FRR holds as expanded lists, and the AS-path
/// lists. A rule that is not read is an unhandled line.
fn regex_lists(policy: &Stanza, set: &mut PolicySet) {
    for list in policy
        .get("community-list")
        .map(Stanza::children)
        .unwrap_or_default()
    {
        let mut out = Vec::new();
        for rule in list.get("rule").map(Stanza::children).unwrap_or_default() {
            out.push(match regex_rule(rule) {
                Some((seq, permit, re)) => CommunityLine::expanded(seq, permit, &re),
                None => CommunityLine {
                    seq: rule.key.parse().unwrap_or(0),
                    permit: false,
                    term: rsim_routing::bgp::CommunityTerm::Unhandled(format!(
                        "community-list {} rule {}",
                        list.key, rule.key
                    )),
                },
            });
        }
        set.community_lists
            .insert(list.key.clone(), CommunityList::new(out));
    }
    for list in policy
        .get("as-path-list")
        .map(Stanza::children)
        .unwrap_or_default()
    {
        let mut out = Vec::new();
        for rule in list.get("rule").map(Stanza::children).unwrap_or_default() {
            out.push(match regex_rule(rule) {
                Some((seq, permit, re)) => AsPathLine::regex(seq, permit, &re),
                None => AsPathLine {
                    seq: rule.key.parse().unwrap_or(0),
                    permit: false,
                    term: rsim_routing::bgp::AsPathTerm::Unhandled(format!(
                        "as-path-list {} rule {}",
                        list.key, rule.key
                    )),
                },
            });
        }
        set.as_path_lists
            .insert(list.key.clone(), AsPathList::new(out));
    }
}

/// The match terms of the `match` node of a route map rule.
fn match_terms(m: &Stanza, rule: &str) -> Vec<MatchTerm> {
    let mut out = Vec::new();
    let unhandled = |what: &str| MatchTerm::Unhandled(format!("{rule} match {what}"));
    for c in m.children() {
        let term = match c.key.as_str() {
            "ip" | "ipv6" => {
                let family = c.key.as_str();
                for x in c.children() {
                    let name = x.get("prefix-list").and_then(Stanza::text);
                    let one = x.children().len() == 1;
                    out.push(match (x.key.as_str(), name, one) {
                        ("address", Some(n), true) => {
                            MatchTerm::PrefixList(vec![format!("{family} {n}")])
                        }
                        ("nexthop", Some(n), true) => MatchTerm::NextHop(NextHopMatch::PrefixList(
                            vec![format!("{family} {n}")],
                        )),
                        _ => unhandled(&format!("{family} {}", text_of(x))),
                    });
                }
                continue;
            }
            "community" => match (
                c.get("community-list").and_then(Stanza::text),
                c.children().len(),
            ) {
                (Some(n), 1) => MatchTerm::CommunityList {
                    names: vec![n.to_string()],
                    every: false,
                },
                _ => unhandled(&text_of(c)),
            },
            "as-path" => match c.text() {
                Some(n) => MatchTerm::AsPathList(vec![n.to_string()]),
                None => unhandled("as-path"),
            },
            "metric" => match c.text().and_then(|t| t.parse().ok()) {
                Some(v) => MatchTerm::Med(Cmp::Eq, v),
                None => unhandled("metric"),
            },
            "tag" => match c.text().and_then(|t| t.parse().ok()) {
                Some(v) => MatchTerm::Tag(vec![v]),
                None => unhandled("tag"),
            },
            "origin" => match c.text().and_then(crate::nxos::bgp_config::origin) {
                Some(o) => MatchTerm::Origin(o),
                None => unhandled("origin"),
            },
            _ => unhandled(&text_of(c)),
        };
        out.push(term);
    }
    out
}

/// The set actions of the `set` node of a route map rule.
fn set_actions(s: &Stanza, rule: &str) -> Vec<SetAction> {
    let mut out = Vec::new();
    let unhandled = |what: &str| SetAction::Unhandled(format!("{rule} set {what}"));
    let communities = |t: &str| -> Option<Vec<Community>> {
        t.split_whitespace().map(|c| c.parse().ok()).collect()
    };
    for c in s.children() {
        let t = c.text();
        let action = match c.key.as_str() {
            "local-preference" => t.and_then(|v| v.parse().ok()).map(SetAction::LocalPref),
            "metric" => t.and_then(crate::nxos::bgp_config::med).map(SetAction::Med),
            "weight" => t.and_then(|v| v.parse().ok()).map(SetAction::Weight),
            "origin" => t
                .and_then(crate::nxos::bgp_config::origin)
                .map(SetAction::Origin),
            "tag" => t.and_then(|v| v.parse().ok()).map(SetAction::Tag),
            "ip-next-hop" => t
                .and_then(|v| v.parse().ok())
                .map(|a| SetAction::NextHop(NextHopSet::Address(a))),
            "community" => match c.children() {
                [x] => match x.key.as_str() {
                    "none" => Some(SetAction::CommunityReplace(Vec::new())),
                    "add" => x.text().and_then(communities).map(SetAction::CommunityAdd),
                    "replace" => x
                        .text()
                        .and_then(communities)
                        .map(SetAction::CommunityReplace),
                    _ => None,
                },
                _ => None,
            },
            "as-path" => match c.children() {
                [x] if x.key == "prepend" => x
                    .text()
                    .and_then(|v| {
                        v.split_whitespace()
                            .map(|a| a.parse::<Asn>().ok())
                            .collect::<Option<Vec<_>>>()
                    })
                    .map(SetAction::AsPathPrepend),
                [x] if x.key == "prepend-last-as" => x
                    .text()
                    .and_then(|v| v.parse().ok())
                    .map(SetAction::AsPathPrependLastAs),
                _ => None,
            },
            _ => None,
        };
        out.push(action.unwrap_or_else(|| unhandled(&text_of(c))));
    }
    out
}

/// The route maps of `policy route-map`. A node of a rule that is not read
/// is an unknown match term below `match` and an unknown action otherwise.
fn route_maps(policy: &Stanza, file: &str, set: &mut PolicySet) {
    for map in policy
        .get("route-map")
        .map(Stanza::children)
        .unwrap_or_default()
    {
        let mut clauses = Vec::new();
        for rule in map.get("rule").map(Stanza::children).unwrap_or_default() {
            let name = format!("route-map {} rule {}", map.key, rule.key);
            let seq = rule.key.parse().ok();
            let permit = rule.get("action").and_then(Stanza::text) == Some("permit");
            let mut c = Clause::new(seq.unwrap_or(0), permit);
            c.spans.push(span(file, lines(rule)));
            if seq.is_none()
                || !matches!(
                    rule.get("action").and_then(Stanza::text),
                    Some("permit" | "deny")
                )
            {
                c.sets.push(SetAction::Unhandled(format!("{name} action")));
            }
            for x in rule.children() {
                match x.key.as_str() {
                    "action" | "description" => {}
                    "match" => c.matches.extend(match_terms(x, &name)),
                    "set" => c.sets.extend(set_actions(x, &name)),
                    "continue" => match x.text().and_then(|t| t.parse().ok()) {
                        Some(n) => c.continue_to = Some(Continue::Seq(n)),
                        None => c
                            .sets
                            .push(SetAction::Unhandled(format!("{name} continue"))),
                    },
                    "on-match" => match x.children() {
                        [n] if n.key == "next" => c.continue_to = Some(Continue::Next),
                        [n] if n.key == "goto" => match n.text().and_then(|t| t.parse().ok()) {
                            Some(s) => c.continue_to = Some(Continue::Seq(s)),
                            None => c
                                .sets
                                .push(SetAction::Unhandled(format!("{name} on-match"))),
                        },
                        _ => c
                            .sets
                            .push(SetAction::Unhandled(format!("{name} on-match"))),
                    },
                    _ => c
                        .sets
                        .push(SetAction::Unhandled(format!("{name} {}", text_of(x)))),
                }
            }
            clauses.push(c);
        }
        clauses.sort_by_key(|c| c.seq);
        let spans = clauses
            .iter()
            .flat_map(|c| c.spans.iter().cloned())
            .collect();
        set.policies.insert(
            map.key.clone(),
            RoutePolicy {
                name: map.key.clone(),
                body: PolicyBody::RouteMap(clauses),
                spans,
            },
        );
    }
}

/// The route policies and the lists of `policy`. Each node below them goes
/// into `read`.
pub fn policies(root: &Stanza, file: &str, read: &mut BTreeSet<u32>) -> PolicySet {
    let mut set = PolicySet::default();
    let Some(policy) = root.get("policy") else {
        return set;
    };
    for key in [
        "route-map",
        "prefix-list",
        "prefix-list6",
        "community-list",
        "as-path-list",
    ] {
        if let Some(s) = policy.get(key) {
            mark_all(s, read);
        }
    }
    route_maps(policy, file, &mut set);
    prefix_lists(policy, &mut set);
    regex_lists(policy, &mut set);
    set
}

/// The selected BGP routes of the collected route rows of the main VRF by
/// prefix, with the next hops of their rows.
pub fn collected(col: &crate::collected::Collected) -> Vec<CollectedBgp> {
    let mut by: BTreeMap<String, CollectedBgp> = BTreeMap::new();
    for r in col
        .routes
        .iter()
        .filter(|r| r.selected && r.protocol == "bgp" && r.vrf == DEFAULT_VRF)
    {
        let Ok(prefix) = r.prefix.parse::<Prefix>() else {
            continue;
        };
        let e = by.entry(r.prefix.clone()).or_insert_with(|| CollectedBgp {
            vrf: r.vrf.clone(),
            prefix,
            next_hops: Vec::new(),
            spans: Vec::new(),
        });
        if let Some(nh) = r.next_hop.as_deref().and_then(|g| g.parse().ok())
            && !e.next_hops.contains(&nh)
        {
            e.next_hops.push(nh);
        }
        e.spans.push(r.span.clone());
    }
    by.into_values().collect()
}

/// Reads the BGP processes of the config with the policies and the gaps.
/// `bgp` is the BGP config after the inheritance. Each node that the
/// reader lowers goes into `read`.
pub fn read(root: &Stanza, bgp: &BgpConfig, file: &str, read: &mut BTreeSet<u32>) -> DeviceBgp {
    let mut out = DeviceBgp::default();
    let policy = policies(root, file, read);
    vni_gaps(root, file, &mut out);
    if let Some(b) = root.at(&["protocols", "bgp"]) {
        process(b, DEFAULT_VRF, bgp, &policy, file, read, &mut out);
    }
    for v in root
        .at(&["vrf", "name"])
        .map(Stanza::children)
        .unwrap_or_default()
    {
        if let Some(b) = v.at(&["protocols", "bgp"]) {
            process(b, &v.key, bgp, &policy, file, read, &mut out);
        }
    }
    out
}

/// The options of `parameters`, with the router ID and the cluster ID.
struct Parameters {
    options: BgpOptions,
    router_id: Option<Ipv4Addr>,
    cluster_id: Option<Ipv4Addr>,
}

/// Reads `parameters`. A node that is not read and has an effect on the
/// routes is a gap.
fn parameters(p: Option<&Stanza>, read: &mut BTreeSet<u32>, gaps: &mut Vec<GapLine>) -> Parameters {
    let mut out = Parameters {
        options: BgpOptions {
            ebgp_requires_policy: Some(false),
            default_ipv4_unicast: Some(false),
            network_import_check: Some(false),
            ..BgpOptions::default()
        },
        router_id: None,
        cluster_id: None,
    };
    let Some(p) = p else {
        return out;
    };
    let gap = |s: &Stanza, gaps: &mut Vec<GapLine>| {
        gaps.push((
            format!("parameters {}", text_of(s)),
            lines(s),
            UNICAST.to_vec(),
        ));
    };
    for c in p.children() {
        let ok = match c.key.as_str() {
            "router-id" => c
                .text()
                .and_then(|t| t.parse().ok())
                .map(|a| out.router_id = Some(a))
                .is_some(),
            "cluster-id" => c
                .text()
                .and_then(|t| t.parse().ok())
                .map(|a| out.cluster_id = Some(a))
                .is_some(),
            "ebgp-requires-policy" => {
                out.options.ebgp_requires_policy = Some(true);
                true
            }
            "deterministic-med" => {
                out.options.deterministic_med = Some(true);
                true
            }
            "always-compare-med" => {
                out.options.always_compare_med = true;
                true
            }
            "network-import-check" => {
                out.options.network_import_check = Some(true);
                true
            }
            "bestpath" => {
                for b in c.children() {
                    let fine = match (b.key.as_str(), b.children()) {
                        ("compare-routerid", []) => {
                            out.options.compare_routerid = true;
                            true
                        }
                        ("as-path", [x]) if x.key == "multipath-relax" => {
                            out.options.multipath_relax = true;
                            true
                        }
                        ("med", [x]) if x.key == "missing-as-worst" => {
                            out.options.missing_as_worst = Some(true);
                            true
                        }
                        _ => false,
                    };
                    if fine {
                        mark_all(b, read);
                    } else {
                        gap(b, gaps);
                    }
                }
                read.insert(c.first_line);
                continue;
            }
            "default" => {
                for d in c.children() {
                    match (d.key.as_str(), d.text().and_then(|t| t.parse().ok())) {
                        ("local-pref", Some(v)) => {
                            out.options.default_local_pref = Some(v);
                            read.insert(d.first_line);
                        }
                        ("no-ipv4-unicast", _) => {
                            read.insert(d.first_line);
                        }
                        _ => gap(d, gaps),
                    }
                }
                read.insert(c.first_line);
                continue;
            }
            "confederation" => continue,
            k if no_effect(&[k]) => continue,
            _ => false,
        };
        if ok {
            mark_all(c, read);
        } else {
            gap(c, gaps);
        }
    }
    out
}

/// The gaps of the `l2vpn-evpn` family `f` of a process. In the main
/// process, `main` is true, and only `advertise` and `route-target` are
/// gaps. In a VRF process, each node is a gap, and so is an empty family.
fn evpn_gaps(f: &Stanza, main: bool, gaps: &mut Vec<GapLine>) {
    if !main && f.children().is_empty() {
        gaps.push((
            "address-family l2vpn-evpn".to_string(),
            lines(f),
            UNICAST.to_vec(),
        ));
    }
    let mut push = |s: &Stanza, text: String| {
        let fams = match text.as_str() {
            "advertise ipv4 unicast" => vec![Family::Ipv4Unicast],
            "advertise ipv6 unicast" => vec![Family::Ipv6Unicast],
            _ => UNICAST.to_vec(),
        };
        gaps.push((format!("address-family l2vpn-evpn {text}"), lines(s), fams));
    };
    for n in f.children() {
        if main && !matches!(n.key.as_str(), "advertise" | "route-target") {
            continue;
        }
        match &n.body {
            Body::Object(c) if c.len() > 1 => {
                for x in c {
                    push(x, format!("{} {}", n.key, text_of(x)));
                }
            }
            _ => push(n, text_of(n)),
        }
    }
}

/// The gaps of the VRFs of `vrf name` with a `vni`: the `vni` node, and
/// `advertise-all-vni` of the `l2vpn-evpn` family of the main process.
fn vni_gaps(root: &Stanza, file: &str, out: &mut DeviceBgp) {
    let all_vni = root.at(&[
        "protocols",
        "bgp",
        "address-family",
        "l2vpn-evpn",
        "advertise-all-vni",
    ]);
    for v in root
        .at(&["vrf", "name"])
        .map(Stanza::children)
        .unwrap_or_default()
    {
        let Some(vni) = v.get("vni") else {
            continue;
        };
        out.gap(&v.key, &UNICAST, text_of(vni), vec![span(file, lines(vni))]);
        if let Some(a) = all_vni {
            out.gap(
                &v.key,
                &UNICAST,
                "address-family l2vpn-evpn advertise-all-vni",
                vec![span(file, lines(a))],
            );
        }
    }
}

/// The prefix of a key of `network` or `aggregate-address` in the family.
fn key_of(text: &str, f: Family) -> Option<RouteKey> {
    let p: Prefix = text.parse().ok()?;
    let k = RouteKey::unicast(p);
    (k.family == f).then_some(k)
}

/// Reads one `protocols bgp` of a VRF.
fn process(
    b: &Stanza,
    vrf: &str,
    bgp: &BgpConfig,
    policy: &PolicySet,
    file: &str,
    read: &mut BTreeSet<u32>,
    out: &mut DeviceBgp,
) {
    let mut gaps: Vec<GapLine> = Vec::new();
    let params = parameters(b.get("parameters"), read, &mut gaps);
    let mut networks = Vec::new();
    let mut aggregates = Vec::new();
    let (mut ebgp, mut ibgp): (Option<u32>, Option<u32>) = (None, None);
    for c in b.children() {
        match c.key.as_str() {
            "system-as" | "parameters" | "neighbor" | "peer-group" | "listen" => {}
            "address-family" => {
                for f in c.children() {
                    let Some(fam) = unicast_of(&f.key) else {
                        if f.key == "l2vpn-evpn" {
                            evpn_gaps(f, vrf == DEFAULT_VRF, &mut gaps);
                        }
                        continue;
                    };
                    for n in f.children() {
                        let mut ok = true;
                        match n.key.as_str() {
                            "network" => {
                                for x in n.children() {
                                    let policy = x.get("route-map").and_then(Stanza::text);
                                    let known = x.children().iter().all(|y| y.key == "route-map");
                                    match key_of(&x.key, fam) {
                                        Some(k) if known => {
                                            networks.push(Network {
                                                key: k,
                                                policy: policy.map(str::to_string),
                                                spans: vec![span(file, lines(x))],
                                            });
                                            mark_all(x, read);
                                        }
                                        _ => gaps.push((
                                            format!("address-family {} network {}", f.key, x.key),
                                            lines(x),
                                            vec![fam],
                                        )),
                                    }
                                }
                                read.insert(n.first_line);
                                continue;
                            }
                            "aggregate-address" => {
                                for x in n.children() {
                                    read.insert(x.first_line);
                                    let opts: Vec<&str> =
                                        x.children().iter().map(|y| y.key.as_str()).collect();
                                    let known = opts
                                        .iter()
                                        .all(|o| matches!(*o, "summary-only" | "as-set"));
                                    match key_of(&x.key, fam) {
                                        Some(k) if known => {
                                            aggregates.push(Aggregate {
                                                key: k,
                                                summary_only: opts.contains(&"summary-only"),
                                                as_set: opts.contains(&"as-set"),
                                                spans: vec![span(file, lines(x))],
                                            });
                                            mark_all(x, read);
                                        }
                                        _ => gaps.push((
                                            format!(
                                                "address-family {} aggregate-address {}",
                                                f.key,
                                                text_of(x)
                                            ),
                                            lines(x),
                                            vec![fam],
                                        )),
                                    }
                                }
                                read.insert(n.first_line);
                                continue;
                            }
                            "maximum-paths" => {
                                for x in n.children() {
                                    let v: Option<u32> = x.text().and_then(|t| t.parse().ok());
                                    let slot = match x.key.as_str() {
                                        "ebgp" => &mut ebgp,
                                        "ibgp" => &mut ibgp,
                                        _ => {
                                            ok = false;
                                            continue;
                                        }
                                    };
                                    match v {
                                        Some(v) if slot.is_none_or(|s| s == v) => *slot = Some(v),
                                        _ => ok = false,
                                    }
                                }
                            }
                            k if no_effect(&[k]) => continue,
                            _ => ok = false,
                        }
                        if ok {
                            mark_all(n, read);
                        } else {
                            gaps.push((
                                format!("address-family {} {}", f.key, text_of(n)),
                                lines(n),
                                vec![fam],
                            ));
                        }
                    }
                }
            }
            k if no_effect(&[k]) => {}
            _ => gaps.push((text_of(c), lines(c), UNICAST.to_vec())),
        }
    }
    let mut groups: BTreeMap<String, Settings> = BTreeMap::new();
    for g in b
        .get("peer-group")
        .map(Stanza::children)
        .unwrap_or_default()
    {
        groups.insert(g.key.clone(), settings_of(g, read));
    }
    let mut own: BTreeMap<String, (Settings, Option<String>)> = BTreeMap::new();
    for n in b.get("neighbor").map(Stanza::children).unwrap_or_default() {
        let x = settings_of(n, read);
        let group = n
            .get("peer-group")
            .and_then(Stanza::text)
            .map(str::to_string);
        own.insert(n.key.clone(), (x, group));
    }
    let process = bgp.processes.get(vrf);
    let asn = match process.map(|p| &p.asn.value) {
        Some(Ok(a)) => *a,
        Some(Err(e)) => {
            out.gap(vrf, &UNICAST, e.clone(), vec![span(file, lines(b))]);
            return;
        }
        None => return,
    };
    for (text, l, fams) in &gaps {
        out.gap(vrf, fams, text.clone(), vec![span(file, *l)]);
    }
    let mut p = BgpProcess::new(
        "",
        vrf,
        Some(Platform::FrrTraditional),
        Asn(asn),
        params.router_id,
    );
    p.cluster_id = params.cluster_id;
    p.options = params.options;
    p.options.maximum_paths_ebgp = ebgp;
    p.options.maximum_paths_ibgp = ibgp;
    p.networks = networks;
    p.aggregates = aggregates;
    p.policy = policy.clone();
    p.spans = vec![span(file, (b.first_line, b.first_line))];
    if let Some(c) = process.map(|x| &x.confederation) {
        if let Some(id) = &c.identifier {
            match &id.value {
                Ok(a) => p.confederation_id = Some(Asn(*a)),
                Err(t) => out.gap(vrf, &UNICAST, t.clone(), vec![span(file, id.lines)]),
            }
        }
        if let Some(peers) = &c.peers {
            match &peers.value {
                Ok(m) => p.confederation_peers = m.iter().map(|a| Asn(*a)).collect(),
                Err(t) => out.gap(vrf, &UNICAST, t.clone(), vec![span(file, peers.lines)]),
            }
        }
    }
    for n in bgp.neighbours.iter().filter(|n| n.vrf == vrf) {
        let BgpPeer::Address(a) = &n.peer else {
            if let Err(why) = neighbor(n, asn, &BTreeMap::new(), file) {
                out.gap(vrf, &UNICAST, why, vec![span(file, n.lines)]);
            }
            continue;
        };
        let Some(((af, own_gaps), group)) = own
            .iter()
            .find(|(k, _)| k.parse::<std::net::IpAddr>().ok() == Some(*a))
            .map(|(_, v)| v)
        else {
            continue;
        };
        let mut gaps = own_gaps.clone();
        let mut af = af.clone();
        if let Some((gaf, ggaps)) = group.as_ref().and_then(|g| groups.get(g)) {
            gaps.extend(ggaps.iter().cloned());
            for (f, s) in gaf {
                af.entry(*f).or_default().fill(s);
            }
        }
        for s in af.values_mut() {
            s.send_community.get_or_insert(true);
            s.send_community_extended.get_or_insert(true);
        }
        for (text, l, fams) in gaps {
            out.gap(
                vrf,
                &fams,
                format!("neighbor {a} {text}"),
                vec![span(file, l)],
            );
        }
        match neighbor(n, asn, &af, file) {
            Ok(nb) => {
                p.neighbors.insert(nb.address, nb);
            }
            Err(why) => out.gap(vrf, &UNICAST, why, vec![span(file, n.lines)]),
        }
    }
    out.processes.push(p);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsim_routing::bgp::{
        AsPath, BgpPath, Direction, Peer, PolicyContext, PolicyResult, SessionKind, evaluate,
    };
    use std::net::IpAddr;

    const CONFIG: &str = r#"{
  "policy": {
    "as-path-list": {"FROM-64501": {"rule": {"10": {"action": "permit", "regex": "^64501_"}}}},
    "community-list": {"KEEP": {"rule": {"10": {"action": "permit", "regex": "64500:100"}}}},
    "prefix-list": {"LAN": {"rule": {"10": {"action": "permit", "prefix": "203.0.113.0/24", "le": "26"}}}},
    "prefix-list6": {"V6": {"rule": {"10": {"action": "permit", "prefix": "2001:db8::/32", "le": "64"}}}},
    "route-map": {
      "IN": {"rule": {
        "10": {"action": "permit", "match": {"ip": {"address": {"prefix-list": "LAN"}}}, "set": {"local-preference": "200"}, "on-match": {"next": {}}},
        "20": {"action": "deny", "match": {"as-path": "FROM-64501"}},
        "30": {"action": "permit", "match": {"community": {"community-list": "KEEP"}}, "set": {"community": {"add": "64500:200"}}}
      }},
      "ODD": {"rule": {"10": {"action": "permit", "set": {"large-community": {"add": "64500:1:1"}}}}}
    }
  },
  "protocols": {"bgp": {
    "system-as": "64500",
    "parameters": {
      "router-id": "192.0.2.1",
      "deterministic-med": {},
      "always-compare-med": {},
      "ebgp-requires-policy": {},
      "log-neighbor-changes": {},
      "bestpath": {"as-path": {"multipath-relax": {}}}
    },
    "address-family": {"ipv4-unicast": {
      "network": {"203.0.113.0/26": {}},
      "aggregate-address": {"203.0.113.0/24": {"summary-only": {}}},
      "maximum-paths": {"ebgp": "4"},
      "redistribute": {"connected": {}}
    }},
    "neighbor": {
      "192.0.2.2": {
        "remote-as": "64500",
        "update-source": "dum0",
        "peer-group": "IBGP",
        "address-family": {"ipv4-unicast": {"nexthop-self": {}}}
      },
      "198.51.100.2": {
        "remote-as": "64501",
        "description": "isp",
        "address-family": {"ipv4-unicast": {
          "route-map": {"import": "IN", "export": "IN"},
          "disable-send-community": {"extended": {}},
          "allowas-in": {"number": "2"},
          "soft-reconfiguration": {"inbound": {}}
        }}
      }
    },
    "peer-group": {"IBGP": {"address-family": {"ipv4-unicast": {"route-reflector-client": {}}}}}
  }}
}"#;

    fn lowered() -> (DeviceBgp, BTreeSet<u32>) {
        let doc = crate::stanza::read_json(CONFIG.as_bytes()).unwrap();
        let mut read = BTreeSet::new();
        let bgp = super::super::bgp::read(&doc.root, &mut read);
        let out = super::read(&doc.root, &bgp, "v1/config", &mut read);
        (out, read)
    }

    fn run(set: &PolicySet, name: &str, prefix: &str, as_path: &[u32]) -> PolicyResult {
        let peer = Peer {
            address: Some("198.51.100.2".parse::<IpAddr>().unwrap()),
            router_id: Some("198.51.100.2".parse().unwrap()),
            asn: Asn(64501),
            kind: SessionKind::Ebgp,
        };
        let key = RouteKey::unicast(prefix.parse().unwrap());
        let p = BgpPath::new(peer, None, AsPath::sequence(as_path));
        let ctx = PolicyContext {
            set,
            direction: Direction::Import,
            local_address: None,
            peer_address: None,
            default_local_pref: 100,
            match_reads: rsim_routing::bgp::MatchReads::Output,
        };
        evaluate(&set.policies[name], &key, &p, &ctx)
    }

    #[test]
    fn a_route_map_with_on_match_next_sets_the_local_preference() {
        let (d, _) = lowered();
        let set = &d.processes[0].policy;
        match run(set, "IN", "203.0.113.64/26", &[64502]) {
            PolicyResult::Permit(p) => assert_eq!(p.local_pref, Some(200)),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            run(set, "IN", "198.51.100.0/24", &[64501]),
            PolicyResult::Deny
        );
        assert!(set.prefix_lists.contains_key("ip LAN"));
        assert!(set.prefix_lists.contains_key("ipv6 V6"));
        match &set.policies["ODD"].body {
            PolicyBody::RouteMap(c) => assert!(matches!(c[0].sets[0], SetAction::Unhandled(_))),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_process_takes_the_parameters_and_the_neighbour_settings() {
        let (d, _) = lowered();
        let p = &d.processes[0];
        assert_eq!(p.platform, Some(Platform::FrrTraditional));
        assert_eq!(p.options.ebgp_requires_policy, Some(true));
        assert_eq!(p.options.deterministic_med, Some(true));
        assert!(p.options.always_compare_med && p.options.multipath_relax);
        assert_eq!(p.options.maximum_paths_ebgp, Some(4));
        assert_eq!(p.options.default_ipv4_unicast, Some(false));
        assert_eq!(p.networks.len(), 1);
        assert_eq!(p.options.network_import_check, Some(false));
        assert!(p.aggregates[0].summary_only);
        let ibgp = &p.neighbors[&"192.0.2.2".parse::<IpAddr>().unwrap()];
        assert!(ibgp.route_reflector_client);
        assert_eq!(ibgp.next_hop_self, NextHopSelf::On);
        assert!(ibgp.send_community && ibgp.send_community_extended);
        let ebgp = &p.neighbors[&"198.51.100.2".parse::<IpAddr>().unwrap()];
        assert_eq!(ebgp.import_policy.as_deref(), Some("IN"));
        assert!(ebgp.send_community && !ebgp.send_community_extended);
        assert!(ebgp.activated.contains(&Family::Ipv4Unicast));
    }

    #[test]
    fn the_nodes_that_are_not_lowered_are_gaps() {
        let (d, _) = lowered();
        let texts: Vec<&str> = d.gaps.iter().map(|g| g.text.as_str()).collect();
        for want in [
            "address-family ipv4-unicast redistribute connected",
            "neighbor 198.51.100.2 address-family ipv4-unicast allowas-in number 2",
        ] {
            assert!(texts.contains(&want), "{want:?} not in {texts:?}");
        }
    }

    fn lowered_from(config: &str) -> DeviceBgp {
        let doc = crate::stanza::read_json(config.as_bytes()).unwrap();
        let mut read = BTreeSet::new();
        let bgp = super::super::bgp::read(&doc.root, &mut read);
        super::read(&doc.root, &bgp, "v1/config", &mut read)
    }

    #[test]
    fn a_network_with_no_import_check_is_lowered_with_no_gap() {
        let d = lowered_from(
            r#"{"protocols": {"bgp": {"system-as": "64500",
              "address-family": {"ipv4-unicast": {"network": {"203.0.113.0/26": {}}}}}}}"#,
        );
        let p = &d.processes[0];
        assert_eq!(p.options.network_import_check, Some(false));
        assert_eq!(p.networks[0].key.prefix.to_string(), "203.0.113.0/26");
        assert!(d.gaps.is_empty(), "{:?}", d.gaps);
    }

    #[test]
    fn a_network_with_the_import_check_is_lowered_with_the_option() {
        let d = lowered_from(
            r#"{"protocols": {"bgp": {"system-as": "64500",
              "parameters": {"network-import-check": {}},
              "address-family": {"ipv4-unicast": {"network": {"203.0.113.0/26": {}}}}}}}"#,
        );
        let p = &d.processes[0];
        assert_eq!(p.options.network_import_check, Some(true));
        assert_eq!(p.networks.len(), 1);
        assert!(d.gaps.is_empty(), "{:?}", d.gaps);
    }

    #[test]
    fn the_nodes_that_import_routes_into_a_vrf_are_gaps_of_the_vrf() {
        let d = lowered_from(
            r#"{
  "protocols": {"bgp": {
    "system-as": "64500",
    "address-family": {"l2vpn-evpn": {"advertise-all-vni": {}, "advertise-svi-ip": {}}}
  }},
  "vrf": {"name": {
    "RED": {
      "table": "100",
      "vni": "10010",
      "protocols": {"bgp": {
        "system-as": "64500",
        "address-family": {
          "ipv4-unicast": {"import": {"vrf": "BLUE"}},
          "l2vpn-evpn": {
            "advertise": {"ipv4": {"unicast": {}}},
            "route-target": {"import": "64500:10", "export": "64500:11"}
          }
        }
      }}
    },
    "BLUE": {"table": "101"}
  }}
}"#,
        );
        let texts: Vec<(&str, &str)> = d
            .gaps
            .iter()
            .map(|g| (g.vrf.as_str(), g.text.as_str()))
            .collect();
        for want in [
            ("RED", "vni 10010"),
            ("RED", "address-family l2vpn-evpn advertise-all-vni"),
            ("RED", "address-family l2vpn-evpn advertise ipv4 unicast"),
            (
                "RED",
                "address-family l2vpn-evpn route-target import 64500:10",
            ),
            (
                "RED",
                "address-family l2vpn-evpn route-target export 64500:11",
            ),
            ("RED", "address-family ipv4-unicast import vrf BLUE"),
        ] {
            assert!(texts.contains(&want), "{want:?} not in {texts:?}");
        }
        assert!(texts.iter().all(|(v, _)| *v == "RED"), "{texts:?}");
        let advertise = d
            .gaps
            .iter()
            .find(|g| g.text.ends_with("advertise ipv4 unicast"))
            .unwrap();
        assert_eq!(advertise.families, BTreeSet::from([Family::Ipv4Unicast]));
    }

    #[test]
    fn with_no_ebgp_requires_policy_an_ebgp_neighbour_needs_no_policy() {
        let doc = crate::stanza::read_json(
            br#"{"protocols": {"bgp": {"system-as": "64500", "parameters": {"router-id": "192.0.2.1"}}}}"#,
        )
        .unwrap();
        let mut read = BTreeSet::new();
        let bgp = super::super::bgp::read(&doc.root, &mut read);
        let d = super::read(&doc.root, &bgp, "v1/config", &mut read);
        assert_eq!(d.processes[0].options.ebgp_requires_policy, Some(false));
    }

    #[test]
    fn each_handled_node_is_read() {
        let doc = crate::stanza::read_json(CONFIG.as_bytes()).unwrap();
        let tables = crate::route_tables::RouteTables::uniform(true, Default::default());
        let table = super::super::table(&tables);
        let cfg = super::super::read(&doc);
        assert_eq!(
            super::super::unread(&doc, &table, &cfg.read),
            Vec::<String>::new()
        );
        assert_eq!(cfg.bgp_routing.processes.len(), 1);
    }
}
