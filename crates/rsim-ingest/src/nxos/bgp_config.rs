//! The BGP processes of an NX-OS running config for the BGP calculation:
//! the process of the default VRF and of each `vrf` stanza with its router
//! ID, cluster ID, `bestpath` options, `maximum-paths`, `network` and
//! `aggregate-address` lines and neighbours, and the route maps, the prefix
//! lists, the community lists and the AS-path lists.
//!
//! The settings of a neighbour in a unicast family come from its own
//! address-family lines, then from the `template peer-policy` stanzas that
//! the family inherits in the order of their sequence numbers, then from
//! the `template peer` stanzas that the neighbour inherits. A line of a
//! process, a neighbour or a template that the reader does not lower, other
//! than a line with no effect on the routes, is a gap, and so is an import
//! route target of a `vrf context`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use rsim_core::{Prefix, SourceSpan};
use rsim_routing::Platform;
use rsim_routing::bgp::{
    AdminValue, Aggregate, AsPathLine, AsPathList, AsPathTerm, Asn, BgpOptions, BgpOrigin,
    BgpProcess, Clause, Cmp, Community, CommunityLine, CommunityList, CommunityTerm, Continue,
    Family, MatchTerm, MedSet, Network, NextHopMatch, NextHopSelf, NextHopSet, PolicyBody,
    PolicySet, PrefixList, PrefixListEntry, RouteKey, RoutePolicy, RouteTypeMatch, SetAction,
};

use crate::bgp_build::CollectedBgp;
use crate::bgp_config::{AfSettings, DeviceBgp, UNICAST, neighbor, no_effect, span, unicast_words};
use crate::bgp_peers::{BgpConfig, DEFAULT_VRF};
use crate::coverage::{Reach, State, Table};
use crate::stanza::{Document, Stanza};

fn words(s: &Stanza) -> Vec<&str> {
    s.key.split_whitespace().collect()
}

fn lines(s: &Stanza) -> (u32, u32) {
    (s.first_line, s.last_line)
}

/// The handled lines of an address family of a neighbour, of a `template
/// peer` and of a `template peer-policy`.
const AF_LINES: &[&str] = &[
    "route-map * in",
    "route-map * out",
    "route-reflector-client",
    "next-hop-self",
    "next-hop-self all",
    "send-community",
    "send-community standard",
    "send-community extended",
    "send-community both",
];

/// The handled lines of a unicast address family of a process.
const PROCESS_AF_LINES: &[&str] = &[
    "network *",
    "network * route-map *",
    "aggregate-address *",
    "aggregate-address * summary-only",
    "aggregate-address * as-set",
    "aggregate-address * as-set summary-only",
    "aggregate-address * summary-only as-set",
    "maximum-paths *",
    "maximum-paths ibgp *",
];

/// The handled lines of a process.
const PROCESS_LINES: &[&str] = &[
    "router-id *",
    "cluster-id *",
    "bestpath always-compare-med",
    "bestpath compare-routerid",
    "bestpath med missing-as-worst",
    "bestpath med non-deterministic",
    "bestpath as-path multipath-relax",
];

const UNICAST_AFS: [&str; 2] = ["address-family ipv4 unicast", "address-family ipv6 unicast"];

/// Adds the handled lines that the reader lowers. Call it before the
/// entries of the routing processes and of the route maps and lists.
pub fn push_entries(t: &mut Table) {
    let tree =
        |t: &mut Table, levels: &[&str]| t.push_levels(levels, State::Handled, Reach::Subtree);
    let p = "router bgp *";
    for scope in [vec![p], vec![p, "vrf *"]] {
        let at = |extra: &[&str]| -> Vec<String> {
            scope
                .iter()
                .chain(extra)
                .map(|s| (*s).to_string())
                .collect()
        };
        let push = |t: &mut Table, v: Vec<String>| {
            tree(t, &v.iter().map(String::as_str).collect::<Vec<_>>());
        };
        for line in PROCESS_LINES {
            push(t, at(&[line]));
        }
        for af in UNICAST_AFS {
            for line in PROCESS_AF_LINES {
                push(t, at(&[af, line]));
            }
        }
        let mut stanzas = vec!["neighbor *", "neighbor * remote-as .."];
        if scope.len() == 1 {
            stanzas.push("template peer *");
        }
        for stanza in stanzas {
            push(t, at(&[stanza, "remove-private-as"]));
            for af in UNICAST_AFS {
                for line in AF_LINES {
                    push(t, at(&[stanza, af, line]));
                }
            }
        }
        if scope.len() == 1 {
            for line in AF_LINES {
                push(t, at(&["template peer-policy *", line]));
            }
        }
    }
    for object in [
        "route-map * permit *",
        "route-map * deny *",
        "route-map * permit",
        "route-map * deny",
        "ip prefix-list ..",
        "ipv6 prefix-list ..",
        "ip community-list ..",
        "ip as-path access-list ..",
    ] {
        tree(t, &[object]);
    }
}

/// The route policies and the lists of the config, also of an IOS-XE
/// config. The prefix lists are held as `ip <name>` and `ipv6 <name>`. A
/// community list with a number from 1 to 99 is a standard list, and from
/// 100 an expanded list. A prefix list with a line that is
/// not read is left out, so each match on it is unknown. A route map line
/// that is not read is an unknown match term after `match` and an unknown
/// action otherwise. Each line goes into `read`.
pub fn policies(
    doc: &Document,
    file: &str,
    mask: &dyn Fn(&str) -> String,
    read: &mut BTreeSet<u32>,
) -> PolicySet {
    let mut clauses: BTreeMap<String, Vec<Clause>> = BTreeMap::new();
    let mut prefixes: BTreeMap<String, (Vec<PrefixListEntry>, bool)> = BTreeMap::new();
    let mut communities: BTreeMap<String, Vec<CommunityLine>> = BTreeMap::new();
    let mut paths: BTreeMap<String, Vec<AsPathLine>> = BTreeMap::new();
    for s in doc.root.children() {
        let w = words(s);
        match w.as_slice() {
            ["route-map", name, action @ ("permit" | "deny"), rest @ ..] => {
                read.insert(s.first_line);
                let seq = match rest {
                    [] => Some(10),
                    [n] => n.parse().ok(),
                    _ => None,
                };
                let mut c = Clause::new(seq.unwrap_or(0), *action == "permit");
                if seq.is_none() {
                    c.sets.push(SetAction::Unhandled(mask(&s.key)));
                }
                c.spans.push(span(file, lines(s)));
                for l in s.children() {
                    read.insert(l.first_line);
                    clause_line(&mut c, &words(l), &mask(&l.key));
                }
                clauses.entry((*name).to_string()).or_default().push(c);
            }
            [ip @ ("ip" | "ipv6"), "prefix-list", name, rest @ ..] => {
                read.insert(s.first_line);
                let e = prefixes
                    .entry(format!("{ip} {name}"))
                    .or_insert((Vec::new(), true));
                if let ["description", ..] = rest {
                    continue;
                }
                let next = e.0.last().map_or(5, |x| x.seq + 5);
                match prefix_entry(rest, next, *ip == "ipv6") {
                    Some(x) => e.0.push(x),
                    None => e.1 = false,
                }
            }
            [
                "ip",
                "community-list",
                kind @ ("standard" | "expanded"),
                name,
                rest @ ..,
            ] => {
                read.insert(s.first_line);
                let list = communities.entry((*name).to_string()).or_default();
                let next = list.last().map_or(5, |x| x.seq + 5);
                list.push(community_line(
                    rest,
                    next,
                    *kind == "expanded",
                    &mask(&s.key),
                ));
            }
            ["ip", "community-list", number, rest @ ..] if number.parse::<u16>().is_ok() => {
                read.insert(s.first_line);
                let expanded = number.parse::<u16>().is_ok_and(|n| n >= 100);
                let list = communities.entry((*number).to_string()).or_default();
                let next = list.last().map_or(5, |x| x.seq + 5);
                list.push(community_line(rest, next, expanded, &mask(&s.key)));
            }
            ["ip", "as-path", "access-list", name, rest @ ..] => {
                read.insert(s.first_line);
                let list = paths.entry((*name).to_string()).or_default();
                let next = list.last().map_or(5, |x| x.seq + 5);
                list.push(as_path_line(rest, next, &mask(&s.key)));
            }
            _ => {}
        }
    }
    let mut set = PolicySet::default();
    for (name, mut list) in clauses {
        list.sort_by_key(|c| c.seq);
        let spans = list.iter().flat_map(|c| c.spans.iter().cloned()).collect();
        set.policies.insert(
            name.clone(),
            RoutePolicy {
                name,
                body: PolicyBody::RouteMap(list),
                spans,
            },
        );
    }
    for (name, (entries, ok)) in prefixes {
        if ok {
            set.prefix_lists.insert(name, PrefixList::new(entries));
        }
    }
    for (name, list) in communities {
        set.community_lists.insert(name, CommunityList::new(list));
    }
    for (name, list) in paths {
        set.as_path_lists.insert(name, AsPathList::new(list));
    }
    set
}

/// Reads one line of a route map clause into the clause.
fn clause_line(c: &mut Clause, w: &[&str], text: &str) {
    match w {
        ["description", ..] => {}
        ["continue"] => c.continue_to = Some(Continue::Next),
        ["continue", n] => match n.parse() {
            Ok(n) => c.continue_to = Some(Continue::Seq(n)),
            Err(_) => c.sets.push(SetAction::Unhandled(text.to_string())),
        },
        ["match", rest @ ..] => c
            .matches
            .push(match_term(rest).unwrap_or_else(|| MatchTerm::Unhandled(text.to_string()))),
        ["set", rest @ ..] => c
            .sets
            .push(set_action(rest).unwrap_or_else(|| SetAction::Unhandled(text.to_string()))),
        _ => c.sets.push(SetAction::Unhandled(text.to_string())),
    }
}

fn names(v: &[&str], prefix: &str) -> Vec<String> {
    v.iter().map(|n| format!("{prefix} {n}")).collect()
}

/// The match term of the words after `match`.
fn match_term(w: &[&str]) -> Option<MatchTerm> {
    let plain = |v: &[&str]| v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
    Some(match w {
        ["ip", "address", "prefix-list", n @ ..] if !n.is_empty() => {
            MatchTerm::PrefixList(names(n, "ip"))
        }
        ["ipv6", "address", "prefix-list", n @ ..] if !n.is_empty() => {
            MatchTerm::PrefixList(names(n, "ipv6"))
        }
        ["ip", "next-hop", "prefix-list", n @ ..] if !n.is_empty() => {
            MatchTerm::NextHop(NextHopMatch::PrefixList(names(n, "ip")))
        }
        ["ipv6", "next-hop", "prefix-list", n @ ..] if !n.is_empty() => {
            MatchTerm::NextHop(NextHopMatch::PrefixList(names(n, "ipv6")))
        }
        ["community", n @ ..] if !n.is_empty() && !n.contains(&"exact-match") => {
            MatchTerm::CommunityList {
                names: plain(n),
                every: false,
            }
        }
        ["as-path", n @ ..] if !n.is_empty() => MatchTerm::AsPathList(plain(n)),
        ["route-type", k] => MatchTerm::RouteType(match *k {
            "internal" => RouteTypeMatch::Internal,
            "external" => RouteTypeMatch::External,
            "local" => RouteTypeMatch::Local,
            _ => return None,
        }),
        ["tag", v @ ..] if !v.is_empty() => MatchTerm::Tag(
            v.iter()
                .map(|x| x.parse().ok())
                .collect::<Option<Vec<u32>>>()?,
        ),
        ["metric", v] => MatchTerm::Med(Cmp::Eq, v.parse().ok()?),
        _ => return None,
    })
}

/// The MED of `set metric`: a value, `+<n>` or `-<n>`.
pub(crate) fn med(v: &str) -> Option<MedSet> {
    if let Some(x) = v.strip_prefix('+') {
        return x.parse().ok().map(MedSet::Add);
    }
    if let Some(x) = v.strip_prefix('-') {
        return x.parse().ok().map(MedSet::Subtract);
    }
    v.parse().ok().map(MedSet::Value)
}

/// The origin of a word.
pub(crate) fn origin(w: &str) -> Option<BgpOrigin> {
    match w {
        "igp" => Some(BgpOrigin::Igp),
        "egp" => Some(BgpOrigin::Egp),
        "incomplete" => Some(BgpOrigin::Incomplete),
        _ => None,
    }
}

/// The set action of the words after `set`.
fn set_action(w: &[&str]) -> Option<SetAction> {
    Some(match w {
        ["local-preference", v] => SetAction::LocalPref(v.parse().ok()?),
        ["metric", v] => SetAction::Med(med(v)?),
        ["weight", v] => SetAction::Weight(v.parse().ok()?),
        ["origin", o] => SetAction::Origin(origin(o)?),
        ["community", "none"] => SetAction::CommunityReplace(Vec::new()),
        ["community", rest @ ..] => {
            let (vals, additive) = match rest.split_last() {
                Some((&"additive", v)) => (v, true),
                _ => (rest, false),
            };
            if vals.is_empty() {
                return None;
            }
            let cs = vals
                .iter()
                .map(|v| v.parse::<Community>().ok())
                .collect::<Option<Vec<_>>>()?;
            if additive {
                SetAction::CommunityAdd(cs)
            } else {
                SetAction::CommunityReplace(cs)
            }
        }
        ["comm-list", name, "delete"] => SetAction::CommunityDelete((*name).to_string()),
        ["extcommunity", "rt", rest @ .., "additive"] if !rest.is_empty() => {
            SetAction::RouteTargetAdd(
                rest.iter()
                    .map(|v| v.parse::<AdminValue>().ok())
                    .collect::<Option<Vec<_>>>()?,
            )
        }
        ["as-path", "prepend", "last-as", n] => SetAction::AsPathPrependLastAs(n.parse().ok()?),
        ["as-path", "prepend", asns @ ..] if !asns.is_empty() => SetAction::AsPathPrepend(
            asns.iter()
                .map(|a| a.parse::<Asn>().ok())
                .collect::<Option<Vec<_>>>()?,
        ),
        ["ip" | "ipv6", "next-hop", "peer-address"] => SetAction::NextHop(NextHopSet::PeerAddress),
        ["ip" | "ipv6", "next-hop", a] => SetAction::NextHop(NextHopSet::Address(a.parse().ok()?)),
        ["tag", v] => SetAction::Tag(v.parse().ok()?),
        _ => return None,
    })
}

/// One line of a prefix list after its name: `[seq <n>] permit|deny
/// <prefix> [ge <n>] [le <n>] [eq <n>]`. `next` is the sequence number of a
/// line with none.
pub(crate) fn prefix_entry(w: &[&str], next: u32, v6: bool) -> Option<PrefixListEntry> {
    let (seq, rest): (u32, &[&str]) = match w {
        ["seq", n, rest @ ..] => (n.parse().ok()?, rest),
        _ => (next, w),
    };
    let [action, p, opts @ ..] = rest else {
        return None;
    };
    let permit = match *action {
        "permit" => true,
        "deny" => false,
        _ => return None,
    };
    let prefix: Prefix = p.parse().ok()?;
    if prefix.is_ipv4() == v6 {
        return None;
    }
    let (mut ge, mut le, mut eq) = (None, None, None);
    let mut i = 0;
    while i < opts.len() {
        let v: u8 = opts.get(i + 1)?.parse().ok()?;
        match opts[i] {
            "ge" => ge = Some(v),
            "le" => le = Some(v),
            "eq" => eq = Some(v),
            _ => return None,
        }
        i += 2;
    }
    Some(PrefixListEntry::new(seq, permit, prefix, ge, le, eq))
}

/// The sequence number, the action and the rest of a list line after its
/// name: `[seq <n>] permit|deny <rest>`.
fn seq_action<'a>(w: &'a [&'a str], next: u32) -> Option<(u32, bool, &'a [&'a str])> {
    let (seq, rest): (u32, &[&str]) = match w {
        ["seq", n, rest @ ..] => (n.parse().ok()?, rest),
        _ => (next, w),
    };
    match rest {
        ["permit", r @ ..] => Some((seq, true, r)),
        ["deny", r @ ..] => Some((seq, false, r)),
        _ => None,
    }
}

/// A quoted or plain pattern of the words of a list line.
fn pattern(w: &[&str]) -> String {
    let t = w.join(" ");
    t.strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .map_or(t.clone(), str::to_string)
}

/// One line of a community list after its name.
fn community_line(w: &[&str], next: u32, expanded: bool, text: &str) -> CommunityLine {
    let unhandled = |seq| CommunityLine {
        seq,
        permit: false,
        term: CommunityTerm::Unhandled(text.to_string()),
    };
    let Some((seq, permit, rest)) = seq_action(w, next) else {
        return unhandled(next);
    };
    if rest.is_empty() {
        return unhandled(seq);
    }
    if expanded {
        return CommunityLine::expanded(seq, permit, &pattern(rest));
    }
    if rest == ["internet"] {
        return CommunityLine {
            seq,
            permit,
            term: CommunityTerm::Internet,
        };
    }
    match rest
        .iter()
        .map(|v| v.parse::<Community>().ok())
        .collect::<Option<Vec<_>>>()
    {
        Some(cs) => CommunityLine {
            seq,
            permit,
            term: CommunityTerm::All(cs),
        },
        None => CommunityLine {
            seq,
            permit,
            term: CommunityTerm::Unhandled(text.to_string()),
        },
    }
}

/// One line of an AS-path access list after its name.
fn as_path_line(w: &[&str], next: u32, text: &str) -> AsPathLine {
    match seq_action(w, next) {
        Some((seq, permit, rest)) if !rest.is_empty() => {
            AsPathLine::regex(seq, permit, &pattern(rest))
        }
        _ => AsPathLine {
            seq: next,
            permit: false,
            term: AsPathTerm::Unhandled(text.to_string()),
        },
    }
}

/// The kind of a line of a neighbour, a template or an address family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Line {
    /// The reader of this module reads the line.
    Read,
    /// Another reader reads the line: the session settings, the
    /// inheritance or a stanza.
    Other,
    NoEffect,
    Gap,
}

/// Reads one line of a unicast address family of a neighbour, a `template
/// peer` or a `template peer-policy` into `af`.
fn af_line(w: &[&str], af: &mut AfSettings) -> Line {
    match w {
        ["route-map", m, "in"] => af.import = Some((*m).to_string()),
        ["route-map", m, "out"] => af.export = Some((*m).to_string()),
        ["route-reflector-client"] => af.rr_client = Some(true),
        ["next-hop-self"] => af.next_hop_self = Some(NextHopSelf::On),
        ["next-hop-self", "all"] => af.next_hop_self = Some(NextHopSelf::All),
        ["send-community"] | ["send-community", "standard"] => af.send_community = Some(true),
        ["send-community", "extended"] => af.send_community_extended = Some(true),
        ["send-community", "both"] => {
            af.send_community = Some(true);
            af.send_community_extended = Some(true);
        }
        ["inherit", ..] => return Line::Other,
        w if no_effect(w) => return Line::NoEffect,
        _ => return Line::Gap,
    }
    Line::Read
}

/// The kind of a line of a neighbour or a template outside its address
/// families.
fn session_line(w: &[&str]) -> Line {
    match w {
        ["remove-private-as"] => Line::Read,
        ["remote-as", ..]
        | ["inherit", ..]
        | ["update-source", _]
        | ["shutdown"]
        | ["shutdown", "inheritance-disable"]
        | ["local-as", ..]
        | ["address-family", ..] => Line::Other,
        w if no_effect(w) => Line::NoEffect,
        _ => Line::Gap,
    }
}

/// The templates of a `router bgp` stanza by kind and name, for example
/// `peer-policy` and its name.
type Templates<'a> = BTreeMap<(String, String), &'a Stanza>;

/// A line that is a gap, with its lines.
type GapLine = (String, (u32, u32));

struct Reader<'a> {
    templates: Templates<'a>,
    mask: &'a dyn Fn(&str) -> String,
}

impl Reader<'_> {
    /// The settings of the family `f` of a neighbour or a `template peer`
    /// stanza: its own lines, then its peer-policy templates, then its peer
    /// templates. A gap line of a source goes into `gaps`.
    fn af_of(
        &self,
        s: &Stanza,
        f: Family,
        path: &mut Vec<String>,
        gaps: &mut Vec<GapLine>,
    ) -> AfSettings {
        let mut own = AfSettings::default();
        let mut policies: Vec<(u32, String)> = Vec::new();
        for c in s.children() {
            let w = words(c);
            match w.as_slice() {
                ["address-family", fam @ ..] if unicast_words(fam) == Some(f) => {
                    for a in c.children() {
                        let aw = words(a);
                        if let ["inherit", "peer-policy", name, rest @ ..] = aw.as_slice() {
                            let seq = rest.first().and_then(|x| x.parse().ok()).unwrap_or(0);
                            policies.push((seq, (*name).to_string()));
                        } else if af_line(&aw, &mut own) == Line::Gap {
                            gaps.push(((self.mask)(&a.key), lines(a)));
                        }
                    }
                }
                ["remove-private-as"] => own.remove_private_as = Some(true),
                _ => {}
            }
        }
        policies.sort();
        for (_, name) in &policies {
            let p = self.policy_template(name, path, gaps);
            own.fill(&p);
        }
        for c in s.children() {
            if let ["inherit", "peer", name] = words(c).as_slice() {
                let key = format!("peer {name}");
                if let Some(t) = self
                    .templates
                    .get(&("peer".to_string(), (*name).to_string()))
                    && !path.contains(&key)
                {
                    path.push(key);
                    let x = self.af_of(t, f, path, gaps);
                    path.pop();
                    own.fill(&x);
                }
            }
        }
        own
    }

    /// The settings of a `template peer-policy` and of the peer-policy
    /// templates that it inherits.
    fn policy_template(
        &self,
        name: &str,
        path: &mut Vec<String>,
        gaps: &mut Vec<GapLine>,
    ) -> AfSettings {
        let key = format!("peer-policy {name}");
        let Some(t) = self
            .templates
            .get(&("peer-policy".to_string(), name.to_string()))
        else {
            return AfSettings::default();
        };
        if path.contains(&key) {
            return AfSettings::default();
        }
        path.push(key);
        let mut own = AfSettings::default();
        let mut more: Vec<(u32, String)> = Vec::new();
        for c in t.children() {
            let w = words(c);
            if let ["inherit", "peer-policy", n, rest @ ..] = w.as_slice() {
                let seq = rest.first().and_then(|x| x.parse().ok()).unwrap_or(0);
                more.push((seq, (*n).to_string()));
            } else if af_line(&w, &mut own) == Line::Gap {
                gaps.push(((self.mask)(&c.key), lines(c)));
            }
        }
        more.sort();
        for (_, n) in &more {
            let p = self.policy_template(n, path, gaps);
            own.fill(&p);
        }
        path.pop();
        own
    }

    /// The gap lines outside the address families of a neighbour or a
    /// template and of the peer and peer-session templates that it
    /// inherits.
    fn session_gaps(&self, s: &Stanza, path: &mut Vec<String>, gaps: &mut Vec<GapLine>) {
        for c in s.children() {
            let w = words(c);
            if session_line(&w) == Line::Gap {
                gaps.push(((self.mask)(&c.key), lines(c)));
            }
            if let ["inherit", kind @ ("peer" | "peer-session"), name, ..] = w.as_slice() {
                let key = format!("{kind} {name}");
                if let Some(t) = self
                    .templates
                    .get(&((*kind).to_string(), (*name).to_string()))
                    && !path.contains(&key)
                {
                    path.push(key);
                    self.session_gaps(t, path, gaps);
                    path.pop();
                }
            }
        }
    }
}

/// Marks the lines of a stanza that [`af_line`] reads, and the
/// `remove-private-as` line.
fn mark_af(s: &Stanza, read: &mut BTreeSet<u32>) {
    for c in s.children() {
        let w = words(c);
        match w.as_slice() {
            ["address-family", fam @ ..] if unicast_words(fam).is_some() => {
                for a in c.children() {
                    if af_line(&words(a), &mut AfSettings::default()) == Line::Read {
                        read.insert(a.first_line);
                    }
                }
            }
            ["remove-private-as"] => {
                read.insert(c.first_line);
            }
            _ => {}
        }
    }
}

/// The selected BGP routes of the collected route rows by VRF and prefix,
/// with the next hops of their rows. A next hop with a `%vrf` suffix gives
/// its address.
pub fn collected(col: &crate::collected::Collected) -> Vec<CollectedBgp> {
    let mut by: BTreeMap<(String, String), (Vec<IpAddr>, Vec<SourceSpan>)> = BTreeMap::new();
    for r in col
        .routes
        .iter()
        .filter(|r| r.selected && super::profile::protocol_word(&r.protocol) == "bgp")
    {
        let e = by.entry((r.vrf.clone(), r.prefix.clone())).or_default();
        let hop = r
            .next_hop
            .as_deref()
            .and_then(|g| g.split('%').next()?.parse::<IpAddr>().ok());
        if let Some(nh) = hop
            && !e.0.contains(&nh)
        {
            e.0.push(nh);
        }
        e.1.push(r.span.clone());
    }
    by.into_iter()
        .filter_map(|((vrf, p), (next_hops, spans))| {
            Some(CollectedBgp {
                vrf,
                prefix: p.parse().ok()?,
                next_hops,
                spans,
            })
        })
        .collect()
}

/// Reads the BGP processes of the config with the policies and the gaps.
/// `bgp` is the BGP config after the inheritance. Each line that the reader
/// lowers goes into `read`.
pub fn read(
    doc: &Document,
    bgp: &BgpConfig,
    file: &str,
    mask: &dyn Fn(&str) -> String,
    read: &mut BTreeSet<u32>,
) -> DeviceBgp {
    let mut out = DeviceBgp::default();
    let policy = policies(doc, file, mask, read);
    route_targets(doc, file, mask, &mut out);
    let Some(rb) = doc
        .root
        .children()
        .iter()
        .find(|s| words(s).starts_with(&["router", "bgp"]))
    else {
        return out;
    };
    let mut templates = Templates::new();
    for c in rb.children() {
        if let ["template", kind, name] = words(c).as_slice() {
            templates.insert(((*kind).to_string(), (*name).to_string()), c);
            mark_af(c, read);
            if *kind == "peer-policy" {
                for l in c.children() {
                    if af_line(&words(l), &mut AfSettings::default()) == Line::Read {
                        read.insert(l.first_line);
                    }
                }
            }
        }
    }
    let r = Reader { templates, mask };
    let global_id = rb
        .children()
        .iter()
        .find_map(|c| match words(c).as_slice() {
            ["router-id", a] => a.parse::<Ipv4Addr>().ok(),
            _ => None,
        });
    let ctx = Scope {
        r: &r,
        bgp,
        policy: &policy,
        file,
    };
    ctx.scope(rb, DEFAULT_VRF, global_id, read, &mut out);
    for c in rb.children() {
        if let ["vrf", v] = words(c).as_slice() {
            ctx.scope(c, v, None, read, &mut out);
        }
    }
    out
}

/// Each import route target of a `vrf context` is a gap of its VRF and
/// family.
fn route_targets(doc: &Document, file: &str, mask: &dyn Fn(&str) -> String, out: &mut DeviceBgp) {
    for s in doc.root.children() {
        let w = words(s);
        let ["vrf", "context", vrf] = w.as_slice() else {
            continue;
        };
        for af in s.children() {
            let w = words(af);
            let ["address-family", fam @ ..] = w.as_slice() else {
                continue;
            };
            let Some(f) = unicast_words(fam) else {
                continue;
            };
            for c in af.children() {
                if let ["route-target", "import" | "both", ..] = words(c).as_slice() {
                    out.gap(vrf, &[f], mask(&c.key), vec![span(file, lines(c))]);
                }
            }
        }
    }
}

struct Scope<'a, 'b> {
    r: &'a Reader<'b>,
    bgp: &'a BgpConfig,
    policy: &'a PolicySet,
    file: &'a str,
}

impl Scope<'_, '_> {
    /// Reads the process of the default VRF or of a `vrf` stanza.
    /// `default_id` is the router ID of a VRF with no `router-id` line.
    fn scope(
        &self,
        sc: &Stanza,
        vrf: &str,
        default_id: Option<Ipv4Addr>,
        read: &mut BTreeSet<u32>,
        out: &mut DeviceBgp,
    ) {
        let file = self.file;
        let mask = self.r.mask;
        let mut options = BgpOptions::default();
        let mut router_id = default_id;
        let mut cluster_id = None;
        let mut networks = Vec::new();
        let mut aggregates = Vec::new();
        let mut ebgp_paths: Option<u32> = None;
        let mut ibgp_paths: Option<u32> = None;
        let top = vrf == DEFAULT_VRF;
        for c in sc.children() {
            if c.key.starts_with("neighbor ") {
                mark_af(c, read);
            }
        }
        for c in sc.children() {
            let w = words(c);
            let gap = |out: &mut DeviceBgp, fams: &[Family]| {
                out.gap(vrf, fams, mask(&c.key), vec![span(file, lines(c))]);
            };
            match w.as_slice() {
                ["router-id", a] => match a.parse::<Ipv4Addr>() {
                    Ok(x) => {
                        read.insert(c.first_line);
                        router_id = Some(x);
                    }
                    Err(_) => gap(out, &UNICAST),
                },
                ["cluster-id", a] => match a.parse::<Ipv4Addr>() {
                    Ok(x) => {
                        read.insert(c.first_line);
                        cluster_id = Some(x);
                    }
                    Err(_) => gap(out, &UNICAST),
                },
                ["bestpath", rest @ ..] => {
                    match rest {
                        ["always-compare-med"] => options.always_compare_med = true,
                        ["compare-routerid"] => options.compare_routerid = true,
                        ["med", "missing-as-worst"] => options.missing_as_worst = Some(true),
                        ["med", "non-deterministic"] => options.deterministic_med = Some(false),
                        ["as-path", "multipath-relax"] => options.multipath_relax = true,
                        _ => {
                            gap(out, &UNICAST);
                            continue;
                        }
                    }
                    read.insert(c.first_line);
                }
                ["address-family", fam @ ..] => {
                    let Some(f) = unicast_words(fam) else {
                        continue;
                    };
                    for a in c.children() {
                        let aw = words(a);
                        let agap = |out: &mut DeviceBgp| {
                            out.gap(vrf, &[f], mask(&a.key), vec![span(file, lines(a))]);
                        };
                        let key = |p: &str| -> Option<RouteKey> {
                            let p: Prefix = p.parse().ok()?;
                            let k = RouteKey::unicast(p);
                            (k.family == f).then_some(k)
                        };
                        let spans = vec![span(file, lines(a))];
                        let ok = match aw.as_slice() {
                            ["network", p] => key(p).map(|k| {
                                networks.push(Network {
                                    key: k,
                                    policy: None,
                                    spans,
                                })
                            }),
                            ["network", p, "route-map", m] => key(p).map(|k| {
                                networks.push(Network {
                                    key: k,
                                    policy: Some((*m).to_string()),
                                    spans,
                                })
                            }),
                            ["aggregate-address", p, opts @ ..]
                                if opts.iter().all(|o| matches!(*o, "summary-only" | "as-set")) =>
                            {
                                key(p).map(|k| {
                                    aggregates.push(Aggregate {
                                        key: k,
                                        summary_only: opts.contains(&"summary-only"),
                                        as_set: opts.contains(&"as-set"),
                                        spans,
                                    })
                                })
                            }
                            ["maximum-paths", n] => n.parse::<u32>().ok().and_then(|n| {
                                (ebgp_paths.is_none_or(|x| x == n)).then(|| ebgp_paths = Some(n))
                            }),
                            ["maximum-paths", "ibgp", n] => n.parse::<u32>().ok().and_then(|n| {
                                (ibgp_paths.is_none_or(|x| x == n)).then(|| ibgp_paths = Some(n))
                            }),
                            w if no_effect(w) => {
                                continue;
                            }
                            _ => None,
                        };
                        match ok {
                            Some(()) => {
                                read.insert(a.first_line);
                            }
                            None => agap(out),
                        }
                    }
                }
                ["neighbor", ..] | ["confederation", ..] | ["local-as", _] => {}
                ["template", ..] | ["vrf", _] if top => {}
                w if no_effect(w) => {}
                _ => gap(out, &UNICAST),
            }
        }
        options.maximum_paths_ebgp = ebgp_paths;
        options.maximum_paths_ibgp = ibgp_paths;
        let process = self.bgp.processes.get(vrf);
        let asn = match process.map(|p| &p.asn.value) {
            Some(Ok(a)) => *a,
            Some(Err(e)) => {
                out.gap(vrf, &UNICAST, e.clone(), vec![span(file, lines(sc))]);
                return;
            }
            None => return,
        };
        let Some(id) = router_id else {
            out.gap(
                vrf,
                &UNICAST,
                "router-id not configured",
                vec![span(file, lines(sc))],
            );
            return;
        };
        let mut p = BgpProcess::new("", vrf, Some(Platform::Nxos), Asn(asn), id);
        p.cluster_id = cluster_id;
        p.options = options;
        p.networks = networks;
        p.aggregates = aggregates;
        p.policy = self.policy.clone();
        p.spans = vec![span(file, (sc.first_line, sc.first_line))];
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
        for n in self.bgp.neighbours.iter().filter(|n| n.vrf == vrf) {
            let Some(ns) = sc.children().iter().find(|c| c.first_line == n.lines.0) else {
                continue;
            };
            let mut gaps = Vec::new();
            let mut path = Vec::new();
            self.r.session_gaps(ns, &mut path, &mut gaps);
            let mut af = BTreeMap::new();
            for f in UNICAST {
                let mut path = Vec::new();
                af.insert(f, self.r.af_of(ns, f, &mut path, &mut gaps));
            }
            for (text, l) in gaps {
                out.gap(vrf, &UNICAST, text, vec![span(file, l)]);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsim_routing::bgp::{
        AsPath, BgpPath, Direction, Peer, PolicyContext, PolicyResult, SessionKind, evaluate,
    };
    use std::net::IpAddr;

    const CONFIG: &str = "\
ip prefix-list LAN seq 5 permit 203.0.113.0/24 le 26
ip prefix-list BAD seq 5 permit 203.0.113.0/24 le
ipv6 prefix-list V6 seq 5 permit 2001:db8::/32 le 64
ip community-list standard KEEP seq 10 permit 64496:100
ip community-list expanded ANY seq 10 permit \"^64496:.*\"
ip as-path access-list FROM-64496 seq 10 permit \"^64496_\"
route-map IN permit 10
  match ip address prefix-list LAN
  set local-preference 200
  continue 30
route-map IN deny 20
  match as-path FROM-64496
route-map IN permit 30
  match community KEEP
  set community 64496:200 additive
route-map IN permit 40
  match ip address prefix-list BAD
route-map ODD permit 10
  set extcommunity color 7
router bgp 64500
  router-id 192.0.2.11
  bestpath as-path multipath-relax
  bestpath med non-deterministic
  log-neighbor-changes
  template peer-policy RR
    route-reflector-client
    route-map IN in
  template peer IBGP
    remote-as 64500
    update-source loopback0
    address-family ipv4 unicast
      next-hop-self
      inherit peer-policy RR 10
  address-family ipv4 unicast
    network 203.0.113.64/26
    aggregate-address 203.0.113.0/24 summary-only
    maximum-paths 4
    redistribute direct route-map IN
  neighbor 192.0.2.12
    inherit peer IBGP
  neighbor 198.51.100.2
    remote-as 64501
    allowas-in 2
    address-family ipv4 unicast
      route-map IN out
      send-community both
  vrf RED
    address-family ipv4 unicast
      advertise l2vpn evpn
vrf context RED
  address-family ipv4 unicast
    route-target both auto evpn
";

    fn lowered() -> (DeviceBgp, BTreeSet<u32>) {
        let doc = crate::stanza::read_indented(CONFIG);
        let mut read = BTreeSet::new();
        let bgp = crate::nxos::bgp::read(
            doc.root
                .children()
                .iter()
                .find(|s| s.key.starts_with("router bgp"))
                .unwrap(),
            &mut read,
            &|k| k.to_string(),
        );
        let out = super::read(&doc, &bgp, "n1/config", &|k| k.to_string(), &mut read);
        (out, read)
    }

    fn path(prefix: &str) -> (RouteKey, BgpPath) {
        let peer = Peer {
            address: Some("198.51.100.2".parse::<IpAddr>().unwrap()),
            router_id: "198.51.100.2".parse().unwrap(),
            asn: Asn(64501),
            kind: SessionKind::Ebgp,
        };
        (
            RouteKey::unicast(prefix.parse().unwrap()),
            BgpPath::new(peer, None, AsPath::sequence(&[64501])),
        )
    }

    fn run(set: &PolicySet, name: &str, prefix: &str, as_path: &[u32]) -> PolicyResult {
        let (key, mut p) = path(prefix);
        p.as_path = AsPath::sequence(as_path);
        let ctx = PolicyContext {
            set,
            direction: Direction::Import,
            local_address: None,
            peer_address: None,
            default_local_pref: 100,
            match_reads: rsim_routing::bgp::MatchReads::Input,
        };
        evaluate(&set.policies[name], &key, &p, &ctx)
    }

    #[test]
    fn a_route_map_with_continue_sets_the_local_preference_and_reaches_its_target() {
        let (d, _) = lowered();
        let set = &d.processes[0].policy;
        match run(set, "IN", "203.0.113.64/26", &[64501]) {
            PolicyResult::Permit(p) => assert_eq!(p.local_pref, Some(200)),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            run(set, "IN", "198.51.100.0/24", &[64496, 64501]),
            PolicyResult::Deny
        );
        assert!(set.prefix_lists.contains_key("ip LAN"));
        assert!(set.prefix_lists.contains_key("ipv6 V6"));
        assert!(!set.prefix_lists.contains_key("ip BAD"));
        // The clause 40 refers to a prefix list that is left out.
        assert!(matches!(
            run(set, "IN", "198.51.100.0/24", &[64501]),
            PolicyResult::Unknown(_)
        ));
        assert!(set.community_lists.contains_key("ANY"));
        match &set.policies["ODD"].body {
            PolicyBody::RouteMap(c) => {
                assert!(matches!(c[0].sets[0], SetAction::Unhandled(_)));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_processes_take_the_options_the_originations_and_the_inherited_family_settings() {
        let (d, _) = lowered();
        let p = &d.processes[0];
        assert_eq!(p.vrf, "default");
        assert_eq!(p.router_id, "192.0.2.11".parse::<Ipv4Addr>().unwrap());
        assert!(p.options.multipath_relax);
        assert_eq!(p.options.deterministic_med, Some(false));
        assert_eq!(p.options.maximum_paths_ebgp, Some(4));
        assert_eq!(p.networks.len(), 1);
        assert!(p.aggregates[0].summary_only);
        let ibgp = &p.neighbors[&"192.0.2.12".parse::<IpAddr>().unwrap()];
        assert_eq!(ibgp.remote_as, Asn(64500));
        assert!(ibgp.route_reflector_client);
        assert_eq!(ibgp.next_hop_self, NextHopSelf::On);
        assert_eq!(ibgp.import_policy.as_deref(), Some("IN"));
        assert!(ibgp.activated.contains(&Family::Ipv4Unicast));
        let ebgp = &p.neighbors[&"198.51.100.2".parse::<IpAddr>().unwrap()];
        assert_eq!(ebgp.export_policy.as_deref(), Some("IN"));
        assert!(ebgp.send_community && ebgp.send_community_extended);
    }

    #[test]
    fn the_lines_that_are_not_lowered_are_gaps() {
        let (d, _) = lowered();
        let texts: Vec<(&str, &str)> = d
            .gaps
            .iter()
            .map(|g| (g.vrf.as_str(), g.text.as_str()))
            .collect();
        for want in [
            ("default", "redistribute direct route-map IN"),
            ("default", "allowas-in 2"),
            ("RED", "advertise l2vpn evpn"),
            ("RED", "route-target both auto evpn"),
            ("RED", "router-id not configured"),
        ] {
            assert!(texts.contains(&want), "{want:?} not in {texts:?}");
        }
        assert_eq!(d.processes.len(), 1);
    }

    #[test]
    fn each_handled_line_is_read() {
        let doc = crate::stanza::read_indented(CONFIG);
        let tables = crate::route_tables::RouteTables::uniform(true, Default::default());
        let table = crate::nxos::table(&tables);
        let cfg = crate::nxos::read(&doc, &table);
        assert_eq!(
            crate::nxos::unread(&doc, &table, &cfg.read),
            Vec::<String>::new()
        );
        let (_, read) = lowered();
        assert!(!read.is_empty());
    }
}
