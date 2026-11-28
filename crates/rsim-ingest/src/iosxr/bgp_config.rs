//! The BGP processes of an IOS-XR running config for the BGP calculation:
//! the process of the default VRF and of each `vrf` stanza with its router
//! ID, cluster ID, `bgp bestpath` options, `maximum-paths`, `network` and
//! `aggregate-address` lines and neighbours, and the route policies, the
//! prefix sets, the community sets and the AS-path sets.
//!
//! The settings of a neighbour in a unicast family come from its own
//! address-family lines, then from the af-group that the family uses, then
//! from the address family of its neighbor-group and the af-group of that
//! family. A line of a process, a neighbour or a group that the reader does
//! not lower, other than a line with no effect on the routes, is a gap, and
//! so is an `import` line of a VRF. A session to an iBGP or a
//! confederation peer sends the standard and the extended communities, and
//! a session to an eBGP peer sends them with `send-community-ebgp` and
//! `send-extended-community-ebgp`.
//!
//! The policy statements are read from the lines of the policy in order:
//! `if`, `elseif`, `else` and `endif`, `pass`, `drop`, `done`, `apply`, the
//! `set` actions, `prepend as-path` and `delete community in`. A condition
//! is a boolean expression of `and`, `or`, `not` and parentheses over the
//! terms `destination in`, `community matches-any` and `matches-every`,
//! `as-path in`, `neighbor-is`, `originates-from`, `passes-through` and
//! `length`, `local-preference`, `med`, `origin is`, `tag` and `next-hop
//! in`, with a named or an inline set. A condition with another part is an
//! unknown term, and another statement is an unknown statement.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use rsim_core::{Prefix, SourceSpan};
use rsim_routing::Platform;
use rsim_routing::bgp::{
    Aggregate, AsPathLine, AsPathList, AsPathTerm, Asn, BgpOptions, BgpProcess, Cmp, Community,
    CommunityLine, CommunityList, CommunityTerm, Family, Guard, Half, MatchTerm, Network,
    NextHopMatch, NextHopSelf, NextHopSet, Pattern, PolicyBody, PolicySet, PrefixList,
    PrefixListEntry, RouteKey, RoutePolicy, SetAction, Statement,
};

use crate::bgp_build::CollectedBgp;
use crate::bgp_config::{AfSettings, DeviceBgp, UNICAST, neighbor, no_effect, span, unicast_words};
use crate::bgp_peers::{BgpConfig, DEFAULT_VRF};
use crate::coverage::{Reach, State, Table};
use crate::nxos::bgp_config::{med, origin};
use crate::stanza::{Document, Stanza};

fn words(s: &Stanza) -> Vec<&str> {
    s.key.split_whitespace().collect()
}

fn lines(s: &Stanza) -> (u32, u32) {
    (s.first_line, s.last_line)
}

/// The handled lines of an address family of a neighbour, of a
/// neighbor-group and of an af-group.
const AF_LINES: &[&str] = &[
    "route-policy * in",
    "route-policy * out",
    "route-reflector-client",
    "route-reflector-client inheritance-disable",
    "next-hop-self",
    "next-hop-self inheritance-disable",
    "send-community-ebgp",
    "send-extended-community-ebgp",
    "remove-private-AS",
    "use af-group *",
];

/// The handled lines of a unicast address family of a process.
const PROCESS_AF_LINES: &[&str] = &[
    "network *",
    "network * route-policy *",
    "aggregate-address *",
    "aggregate-address * summary-only",
    "aggregate-address * as-set",
    "aggregate-address * as-set summary-only",
    "aggregate-address * summary-only as-set",
    "maximum-paths ebgp *",
    "maximum-paths ibgp *",
];

/// The handled lines of a process.
const PROCESS_LINES: &[&str] = &[
    "bgp router-id *",
    "bgp cluster-id *",
    "bgp bestpath med always",
    "bgp bestpath med missing-as-worst",
    "bgp bestpath compare-routerid",
    "bgp bestpath as-path multipath-relax",
    "bgp default local-preference *",
];

const UNICAST_AFS: [&str; 2] = ["address-family ipv4 unicast", "address-family ipv6 unicast"];

/// Adds the handled lines that the reader lowers. Call it before the
/// entries of the routing processes and of the policies and sets.
pub fn push_entries(t: &mut Table) {
    let p = "router bgp *";
    let push = |t: &mut Table, v: &[&str]| t.push_levels(v, State::Handled, Reach::Subtree);
    for scope in [vec![p], vec![p, "vrf *"]] {
        let at = |extra: &[&str]| -> Vec<String> {
            scope
                .iter()
                .chain(extra)
                .map(|s| (*s).to_string())
                .collect()
        };
        let mut all: Vec<Vec<String>> = Vec::new();
        for line in PROCESS_LINES {
            all.push(at(&[line]));
        }
        for af in UNICAST_AFS {
            for line in PROCESS_AF_LINES {
                all.push(at(&[af, line]));
            }
        }
        let mut stanzas = vec!["neighbor *"];
        if scope.len() == 1 {
            stanzas.push("neighbor-group *");
        }
        for stanza in stanzas {
            for af in UNICAST_AFS {
                for line in AF_LINES {
                    all.push(at(&[stanza, af, line]));
                }
            }
        }
        if scope.len() == 1 {
            for af in UNICAST_AFS {
                let head = format!("af-group * {af}");
                for line in AF_LINES {
                    all.push(at(&[&head, line]));
                }
            }
        }
        for v in &all {
            push(t, &v.iter().map(String::as_str).collect::<Vec<_>>());
        }
    }
    for object in [
        "route-policy *",
        "prefix-set *",
        "community-set *",
        "as-path-set *",
        "end-policy",
        "end-set",
    ] {
        push(t, &[object]);
    }
}

/// A token of a condition or of an inline set.
fn tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars();
    let flush = |cur: &mut String, out: &mut Vec<String>| {
        if !cur.is_empty() {
            out.push(std::mem::take(cur));
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                flush(&mut cur, &mut out);
                let mut q = String::from("'");
                for d in chars.by_ref() {
                    q.push(d);
                    if d == '\'' {
                        break;
                    }
                }
                out.push(q);
            }
            '(' | ')' | ',' => {
                flush(&mut cur, &mut out);
                out.push(c.to_string());
            }
            c if c.is_whitespace() => flush(&mut cur, &mut out),
            _ => cur.push(c),
        }
    }
    flush(&mut cur, &mut out);
    out
}

/// The text of a quoted token, `'<text>'`.
fn unquote(t: &str) -> Option<&str> {
    t.strip_prefix('\'')?.strip_suffix('\'')
}

/// The elements of the lines of a set, each as its tokens. A comment line
/// is left out.
fn elements(lines: &[String]) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for l in lines {
        if l.trim_start().starts_with('#') {
            continue;
        }
        for t in tokens(l) {
            if t == "," {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            } else {
                cur.push(t);
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// A prefix set element: `<prefix> [ge <n>] [le <n>] [eq <n>]`.
fn prefix_element(e: &[String], seq: u32) -> Option<PrefixListEntry> {
    let (p, opts) = e.split_first()?;
    let prefix: Prefix = p.parse().ok()?;
    let (mut ge, mut le, mut eq) = (None, None, None);
    let mut i = 0;
    while i < opts.len() {
        let v: u8 = opts.get(i + 1)?.parse().ok()?;
        match opts[i].as_str() {
            "ge" => ge = Some(v),
            "le" => le = Some(v),
            "eq" => eq = Some(v),
            _ => return None,
        }
        i += 2;
    }
    Some(PrefixListEntry::new(seq, true, prefix, ge, le, eq))
}

/// A prefix set of its elements, `None` if an element is not read.
fn prefix_set(es: &[Vec<String>]) -> Option<PrefixList> {
    es.iter()
        .enumerate()
        .map(|(i, e)| prefix_element(e, i as u32))
        .collect::<Option<Vec<_>>>()
        .map(PrefixList::new)
}

/// One half of a community set element: a number, `*` or `[<a>..<b>]`.
fn half(t: &str) -> Option<Half> {
    if t == "*" {
        return Some(Half::Any);
    }
    if let Some(r) = t.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        let (a, b) = r.split_once("..")?;
        return Some(Half::Range(a.parse().ok()?, b.parse().ok()?));
    }
    t.parse().ok().map(Half::Value)
}

/// A community set element as a list line.
fn community_element(e: &[String], seq: u32, text: &str) -> CommunityLine {
    let line = |term| CommunityLine {
        seq,
        permit: true,
        term,
    };
    let unhandled = || line(CommunityTerm::Unhandled(text.to_string()));
    match e {
        [kind, q] if kind == "ios-regex" => match unquote(q) {
            Some(p) => CommunityLine::expanded(seq, true, p),
            None => unhandled(),
        },
        [v] => {
            if let Ok(c) = v.parse::<Community>() {
                return line(CommunityTerm::All(vec![c]));
            }
            match v
                .split_once(':')
                .and_then(|(a, b)| Some((half(a)?, half(b)?)))
            {
                Some((a, b)) => line(CommunityTerm::Wildcard(a, b)),
                None => unhandled(),
            }
        }
        _ => unhandled(),
    }
}

/// The ASes of a quoted AS list.
fn quoted_asns(q: &str) -> Option<Vec<Asn>> {
    unquote(q)?
        .split_whitespace()
        .map(|a| a.parse::<Asn>().ok())
        .collect()
}

/// The comparison of an RPL word.
fn cmp(w: &str) -> Option<Cmp> {
    match w {
        "eq" | "is" => Some(Cmp::Eq),
        "ge" => Some(Cmp::Ge),
        "le" => Some(Cmp::Le),
        _ => None,
    }
}

/// An AS-path set element as a list line.
fn as_path_element(e: &[String], seq: u32, text: &str) -> AsPathLine {
    let term = match e {
        [kind, q] if kind == "ios-regex" => match unquote(q).map(Pattern::parse) {
            Some(Ok(p)) => Some(AsPathTerm::Pattern(p)),
            _ => None,
        },
        [kind, q] if kind == "neighbor-is" => quoted_asns(q).map(AsPathTerm::NeighborIs),
        [kind, q] if kind == "originates-from" => quoted_asns(q).map(AsPathTerm::OriginatesFrom),
        [kind, q] if kind == "passes-through" => quoted_asns(q).map(AsPathTerm::PassesThrough),
        [kind, c, n] if kind == "length" => match (cmp(c), n.parse()) {
            (Some(c), Ok(n)) => Some(AsPathTerm::Length(c, n)),
            _ => None,
        },
        _ => None,
    };
    AsPathLine {
        seq,
        permit: true,
        term: term.unwrap_or_else(|| AsPathTerm::Unhandled(text.to_string())),
    }
}

/// The token at `j`.
fn word_at(t: &[String], j: usize) -> Option<&str> {
    t.get(j).map(String::as_str)
}

/// The number at `j`.
fn number_at(t: &[String], j: usize) -> Option<u32> {
    t.get(j).and_then(|x| x.parse().ok())
}

/// The text lines of the children of a stanza and of their children, in
/// line order, each with its first line.
fn flat(s: &Stanza, out: &mut Vec<(String, u32)>) {
    for c in s.children() {
        out.push((c.key.clone(), c.first_line));
        flat(c, out);
    }
}

/// The policies of a config and the parser of their statements. Inline
/// sets are added to `set` under the name `inline <n>`.
struct Policies<'a> {
    set: PolicySet,
    mask: &'a dyn Fn(&str) -> String,
    inline: usize,
}

/// The parser of the statements of one policy.
struct Body<'a> {
    lines: &'a [(String, u32)],
    i: usize,
}

impl Body<'_> {
    fn first_word(&self) -> Option<&str> {
        self.lines
            .get(self.i)
            .and_then(|(t, _)| t.split_whitespace().next())
    }
}

impl Policies<'_> {
    /// Adds an inline set of the tokens between the parentheses and gives
    /// its name.
    fn add_inline(&mut self, kind: &str, items: &[String], text: &str) -> Option<String> {
        let mut es: Vec<Vec<String>> = Vec::new();
        let mut cur = Vec::new();
        for t in items {
            if t == "," {
                es.push(std::mem::take(&mut cur));
            } else {
                cur.push(t.clone());
            }
        }
        es.push(cur);
        if es.iter().any(Vec::is_empty) {
            return None;
        }
        self.inline += 1;
        let name = format!("inline {}", self.inline);
        match kind {
            "prefix" => {
                let l = prefix_set(&es)?;
                self.set.prefix_lists.insert(name.clone(), l);
            }
            "community" => {
                let l = es
                    .iter()
                    .enumerate()
                    .map(|(i, e)| community_element(e, i as u32, text))
                    .collect();
                self.set
                    .community_lists
                    .insert(name.clone(), CommunityList::new(l));
            }
            _ => {
                let l = es
                    .iter()
                    .enumerate()
                    .map(|(i, e)| as_path_element(e, i as u32, text))
                    .collect();
                self.set
                    .as_path_lists
                    .insert(name.clone(), AsPathList::new(l));
            }
        }
        Some(name)
    }

    /// The name of a named or an inline set at `t[*i]`, after it.
    fn set_ref(&mut self, kind: &str, t: &[String], i: &mut usize, text: &str) -> Option<String> {
        let first = t.get(*i)?;
        if first != "(" {
            *i += 1;
            return Some(first.clone());
        }
        let close = t[*i..].iter().position(|x| x == ")")? + *i;
        let items = t[*i + 1..close].to_vec();
        *i = close + 1;
        self.add_inline(kind, &items, text)
    }

    /// One term of a condition at `t[*i]`.
    fn term(&mut self, t: &[String], i: &mut usize, text: &str) -> Option<MatchTerm> {
        let j = *i;
        let a = word_at(t, j)?;
        let b = word_at(t, j + 1)?;
        let term = match (a, b) {
            ("destination", "in") => {
                *i = j + 2;
                MatchTerm::PrefixList(vec![self.set_ref("prefix", t, i, text)?])
            }
            ("next-hop", "in") => {
                *i = j + 2;
                MatchTerm::NextHop(NextHopMatch::PrefixList(vec![
                    self.set_ref("prefix", t, i, text)?,
                ]))
            }
            ("community", "matches-any" | "matches-every") => {
                let every = b == "matches-every";
                *i = j + 2;
                MatchTerm::CommunityList {
                    names: vec![self.set_ref("community", t, i, text)?],
                    every,
                }
            }
            ("as-path", "in") => {
                *i = j + 2;
                MatchTerm::AsPathList(vec![self.set_ref("as-path", t, i, text)?])
            }
            ("as-path", "neighbor-is" | "originates-from" | "passes-through") => {
                let asns = quoted_asns(word_at(t, j + 2)?)?;
                let term = match b {
                    "neighbor-is" => AsPathTerm::NeighborIs(asns),
                    "originates-from" => AsPathTerm::OriginatesFrom(asns),
                    _ => AsPathTerm::PassesThrough(asns),
                };
                *i = j + 3;
                self.inline += 1;
                let name = format!("inline {}", self.inline);
                self.set.as_path_lists.insert(
                    name.clone(),
                    AsPathList::new(vec![AsPathLine {
                        seq: 0,
                        permit: true,
                        term,
                    }]),
                );
                MatchTerm::AsPathList(vec![name])
            }
            ("as-path", "length") => {
                let c = cmp(word_at(t, j + 2)?)?;
                let n = number_at(t, j + 3)?;
                *i = j + 4;
                MatchTerm::AsPathLength(c, n)
            }
            ("local-preference" | "med", c) => {
                let c = cmp(c)?;
                let n = number_at(t, j + 2)?;
                *i = j + 3;
                if a == "med" {
                    MatchTerm::Med(c, n)
                } else {
                    MatchTerm::LocalPref(c, n)
                }
            }
            ("origin", "is") => {
                let o = origin(word_at(t, j + 2)?)?;
                *i = j + 3;
                MatchTerm::Origin(o)
            }
            ("tag", c) if cmp(c) == Some(Cmp::Eq) => {
                let n = number_at(t, j + 2)?;
                *i = j + 3;
                MatchTerm::Tag(vec![n])
            }
            _ => return None,
        };
        Some(term)
    }

    fn unary(&mut self, t: &[String], i: &mut usize, text: &str) -> Option<Guard> {
        match t.get(*i).map(String::as_str)? {
            "not" => {
                *i += 1;
                Some(Guard::Not(Box::new(self.unary(t, i, text)?)))
            }
            "(" => {
                *i += 1;
                let g = self.or(t, i, text)?;
                if t.get(*i).map(String::as_str) != Some(")") {
                    return None;
                }
                *i += 1;
                Some(g)
            }
            _ => self.term(t, i, text).map(Guard::Term),
        }
    }

    fn and(&mut self, t: &[String], i: &mut usize, text: &str) -> Option<Guard> {
        let mut parts = vec![self.unary(t, i, text)?];
        while t.get(*i).map(String::as_str) == Some("and") {
            *i += 1;
            parts.push(self.unary(t, i, text)?);
        }
        Some(if parts.len() == 1 {
            parts.remove(0)
        } else {
            Guard::And(parts)
        })
    }

    fn or(&mut self, t: &[String], i: &mut usize, text: &str) -> Option<Guard> {
        let mut parts = vec![self.and(t, i, text)?];
        while t.get(*i).map(String::as_str) == Some("or") {
            *i += 1;
            parts.push(self.and(t, i, text)?);
        }
        Some(if parts.len() == 1 {
            parts.remove(0)
        } else {
            Guard::Or(parts)
        })
    }

    /// The guard of the condition of an `if` or `elseif` line. A condition
    /// that is not read is an unknown term with the masked line.
    fn guard(&mut self, line: &str) -> Guard {
        let text = (self.mask)(line);
        let t = tokens(line);
        let body = match t.as_slice() {
            [first, rest @ .., last] if (first == "if" || first == "elseif") && last == "then" => {
                rest
            }
            _ => return Guard::Term(MatchTerm::Unhandled(text)),
        };
        let mut i = 0;
        match self.or(body, &mut i, &text) {
            Some(g) if i == body.len() => g,
            _ => Guard::Term(MatchTerm::Unhandled(text)),
        }
    }

    /// The communities of a named or inline set of plain values for a
    /// `set community` statement.
    fn communities(&self, t: &[String]) -> Option<Vec<Community>> {
        match t {
            [name] => {
                let l = self.set.community_lists.get(name)?;
                l.lines
                    .iter()
                    .map(|x| match &x.term {
                        CommunityTerm::All(v) if v.len() == 1 => Some(v[0]),
                        _ => None,
                    })
                    .collect()
            }
            [open, items @ .., close] if open == "(" && close == ")" => items
                .iter()
                .filter(|x| *x != ",")
                .map(|x| x.parse::<Community>().ok())
                .collect(),
            _ => None,
        }
    }

    /// The statement of a line that is not `if`, `elseif`, `else` or
    /// `endif`. `None` for a comment.
    fn statement(&mut self, line: &str) -> Option<Statement> {
        let text = (self.mask)(line);
        let w: Vec<&str> = line.split_whitespace().collect();
        let set =
            |a: Option<SetAction>| Statement::Set(a.unwrap_or(SetAction::Unhandled(text.clone())));
        Some(match w.as_slice() {
            [first, ..] if first.starts_with('#') => return None,
            ["pass"] => Statement::Pass,
            ["drop"] => Statement::Drop,
            ["done"] => Statement::Done,
            ["apply", name] if !name.contains('(') => Statement::Apply((*name).to_string()),
            ["set", "local-preference", v] => set(v.parse().ok().map(SetAction::LocalPref)),
            ["set", "med", v] => set(med(v).map(SetAction::Med)),
            ["set", "weight", v] => set(v.parse().ok().map(SetAction::Weight)),
            ["set", "origin", o] => set(origin(o).map(SetAction::Origin)),
            ["set", "next-hop", "self"] => {
                Statement::Set(SetAction::NextHop(NextHopSet::SelfAddress))
            }
            ["set", "next-hop", "peer-address"] => {
                Statement::Set(SetAction::NextHop(NextHopSet::PeerAddress))
            }
            ["set", "next-hop", a] => set(a
                .parse()
                .ok()
                .map(|x| SetAction::NextHop(NextHopSet::Address(x)))),
            ["set", "tag", v] => set(v.parse().ok().map(SetAction::Tag)),
            ["set", "community", ..] => {
                let t = tokens(line);
                let (vals, additive) = match t[2..].split_last() {
                    Some((last, v)) if last == "additive" => (v, true),
                    _ => (&t[2..], false),
                };
                set(self.communities(vals).map(|cs| {
                    if additive {
                        SetAction::CommunityAdd(cs)
                    } else {
                        SetAction::CommunityReplace(cs)
                    }
                }))
            }
            ["delete", "community", "in", name] if !name.starts_with('(') => {
                Statement::Set(SetAction::CommunityDelete((*name).to_string()))
            }
            ["prepend", "as-path", "most-recent", n] => {
                set(n.parse().ok().map(SetAction::AsPathPrependLastAs))
            }
            ["prepend", "as-path", a] => set(a
                .parse::<Asn>()
                .ok()
                .map(|a| SetAction::AsPathPrepend(vec![a]))),
            ["prepend", "as-path", a, n] => set(match (a.parse::<Asn>(), n.parse::<usize>()) {
                (Ok(a), Ok(n)) if n > 0 => Some(SetAction::AsPathPrepend(vec![a; n])),
                _ => None,
            }),
            _ => Statement::Unhandled(text.clone()),
        })
    }

    /// The statements up to an `elseif`, an `else`, an `endif` or the end.
    fn block(&mut self, b: &mut Body<'_>) -> Vec<Statement> {
        let mut out = Vec::new();
        while let Some(first) = b.first_word() {
            match first {
                "elseif" | "else" | "endif" => break,
                "if" => out.push(self.if_statement(b)),
                _ => {
                    let line = b.lines[b.i].0.clone();
                    b.i += 1;
                    out.extend(self.statement(&line));
                }
            }
        }
        out
    }

    /// An `if` statement with its `elseif` and `else` branches and its
    /// `endif`. An `if` with no `endif` is an unknown statement.
    fn if_statement(&mut self, b: &mut Body<'_>) -> Statement {
        let head = b.lines[b.i].0.clone();
        b.i += 1;
        let guard = self.guard(&head);
        let body = self.block(b);
        let mut branches = vec![(guard, body)];
        let mut otherwise = Vec::new();
        loop {
            match b.first_word() {
                Some("elseif") => {
                    let line = b.lines[b.i].0.clone();
                    b.i += 1;
                    let g = self.guard(&line);
                    let body = self.block(b);
                    branches.push((g, body));
                }
                Some("else") => {
                    b.i += 1;
                    otherwise = self.block(b);
                }
                Some("endif") => {
                    b.i += 1;
                    return Statement::If {
                        branches,
                        otherwise,
                    };
                }
                _ => return Statement::Unhandled((self.mask)(&head)),
            }
        }
    }
}

/// The route policies and the sets of the config. A prefix set with an
/// element that is not read is left out, so each match on it is unknown.
/// A policy with parameters is one unknown statement. Each line goes into
/// `read`.
pub fn policies(
    doc: &Document,
    file: &str,
    mask: &dyn Fn(&str) -> String,
    read: &mut BTreeSet<u32>,
) -> PolicySet {
    let mut p = Policies {
        set: PolicySet::default(),
        mask,
        inline: 0,
    };
    let mut bodies = Vec::new();
    for s in doc.root.children() {
        let w = words(s);
        let mut all = Vec::new();
        flat(s, &mut all);
        let texts: Vec<String> = all.iter().map(|(t, _)| t.clone()).collect();
        let marked = matches!(
            w.as_slice(),
            [
                "prefix-set" | "community-set" | "as-path-set" | "route-policy",
                _
            ]
        );
        if marked {
            read.insert(s.first_line);
            for (_, l) in &all {
                read.insert(*l);
            }
        }
        match w.as_slice() {
            ["end-policy"] | ["end-set"] => {
                read.insert(s.first_line);
            }
            ["prefix-set", name] => {
                if let Some(l) = prefix_set(&elements(&texts)) {
                    p.set.prefix_lists.insert((*name).to_string(), l);
                }
            }
            ["community-set", name] => {
                let text = mask(&s.key);
                let l = elements(&texts)
                    .iter()
                    .enumerate()
                    .map(|(i, e)| community_element(e, i as u32, &text))
                    .collect();
                p.set
                    .community_lists
                    .insert((*name).to_string(), CommunityList::new(l));
            }
            ["as-path-set", name] => {
                let text = mask(&s.key);
                let l = elements(&texts)
                    .iter()
                    .enumerate()
                    .map(|(i, e)| as_path_element(e, i as u32, &text))
                    .collect();
                p.set
                    .as_path_lists
                    .insert((*name).to_string(), AsPathList::new(l));
            }
            ["route-policy", name] => {
                bodies.push(((*name).to_string(), s, all));
            }
            _ => {}
        }
    }
    for (name, s, all) in bodies {
        let spans = vec![span(file, lines(s))];
        let stmts = if name.contains('(') {
            vec![Statement::Unhandled(mask(&s.key))]
        } else {
            let mut b = Body { lines: &all, i: 0 };
            let mut out = p.block(&mut b);
            while b.i < all.len() {
                // An `elseif`, `else` or `endif` with no `if`.
                out.push(Statement::Unhandled(mask(&all[b.i].0)));
                b.i += 1;
                out.extend(p.block(&mut b));
            }
            out
        };
        let key = name.split('(').next().unwrap_or_default().to_string();
        p.set.policies.insert(
            key.clone(),
            RoutePolicy {
                name: key,
                body: PolicyBody::Rpl(stmts),
                spans,
            },
        );
    }
    p.set
}

/// The kind of a line of a neighbour, a group or an address family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Line {
    Read,
    Other,
    NoEffect,
    Gap,
}

/// Reads one line of a unicast address family of a neighbour, a
/// neighbor-group or an af-group into `af`.
fn af_line(w: &[&str], af: &mut AfSettings) -> Line {
    match w {
        ["route-policy", m, "in"] => af.import = Some((*m).to_string()),
        ["route-policy", m, "out"] => af.export = Some((*m).to_string()),
        ["route-reflector-client"] => af.rr_client = Some(true),
        ["route-reflector-client", "inheritance-disable"] => af.rr_client = Some(false),
        ["next-hop-self"] => af.next_hop_self = Some(NextHopSelf::On),
        ["next-hop-self", "inheritance-disable"] => af.next_hop_self = Some(NextHopSelf::Off),
        ["send-community-ebgp"] => af.send_community = Some(true),
        ["send-extended-community-ebgp"] => af.send_community_extended = Some(true),
        ["remove-private-AS"] => af.remove_private_as = Some(true),
        ["use", "af-group", _] => {}
        w if no_effect(w) => return Line::NoEffect,
        _ => return Line::Gap,
    }
    Line::Read
}

/// The kind of a line of a neighbour or a group outside its address
/// families.
fn session_line(w: &[&str]) -> Line {
    match w {
        ["remote-as", ..]
        | ["use", ..]
        | ["update-source", _]
        | ["shutdown"]
        | ["shutdown", "inheritance-disable"]
        | ["local-as", ..]
        | ["address-family", ..] => Line::Other,
        w if no_effect(w) => Line::NoEffect,
        _ => Line::Gap,
    }
}

/// A line that is a gap, with its lines.
type GapLine = (String, (u32, u32));

struct Groups<'a> {
    /// The neighbor-groups and the session-groups by kind and name.
    groups: BTreeMap<(String, String), &'a Stanza>,
    /// The af-groups by name and family.
    af_groups: BTreeMap<(String, Family), &'a Stanza>,
    mask: &'a dyn Fn(&str) -> String,
}

impl Groups<'_> {
    /// The lines of the address family `f` of a stanza, with the af-group
    /// that the family uses after them.
    fn family(&self, s: &Stanza, f: Family, gaps: &mut Vec<GapLine>) -> AfSettings {
        let mut own = AfSettings::default();
        let mut group = None;
        for c in s.children() {
            let w = words(c);
            let ["address-family", fam @ ..] = w.as_slice() else {
                continue;
            };
            if unicast_words(fam) != Some(f) {
                continue;
            }
            for a in c.children() {
                let aw = words(a);
                if let ["use", "af-group", g] = aw.as_slice() {
                    group = Some((*g).to_string());
                }
                if af_line(&aw, &mut own) == Line::Gap {
                    gaps.push(((self.mask)(&a.key), lines(a)));
                }
            }
        }
        if let Some(g) = group
            && let Some(t) = self.af_groups.get(&(g, f))
        {
            let mut x = AfSettings::default();
            for a in t.children() {
                if af_line(&words(a), &mut x) == Line::Gap {
                    gaps.push(((self.mask)(&a.key), lines(a)));
                }
            }
            own.fill(&x);
        }
        own
    }

    /// The settings of the family `f` of a neighbour: its own, then of its
    /// neighbor-group.
    fn af_of(&self, s: &Stanza, f: Family, gaps: &mut Vec<GapLine>) -> AfSettings {
        let mut own = self.family(s, f, gaps);
        for c in s.children() {
            if let ["use", "neighbor-group", g] = words(c).as_slice()
                && let Some(t) = self
                    .groups
                    .get(&("neighbor-group".to_string(), (*g).to_string()))
            {
                let x = self.family(t, f, gaps);
                own.fill(&x);
            }
        }
        own
    }

    /// The gap lines outside the address families of a neighbour and of
    /// the groups that it uses, and of the session-group of a group.
    fn session_gaps(&self, s: &Stanza, depth: usize, gaps: &mut Vec<GapLine>) {
        for c in s.children() {
            let w = words(c);
            if session_line(&w) == Line::Gap {
                gaps.push(((self.mask)(&c.key), lines(c)));
            }
            if let ["use", kind @ ("neighbor-group" | "session-group"), g] = w.as_slice()
                && depth < 2
                && let Some(t) = self.groups.get(&((*kind).to_string(), (*g).to_string()))
            {
                self.session_gaps(t, depth + 1, gaps);
            }
        }
    }
}

/// Marks the lines of the unicast families of a stanza that [`af_line`]
/// reads.
fn mark_af(s: &Stanza, read: &mut BTreeSet<u32>) {
    for c in s.children() {
        let w = words(c);
        if let ["address-family", fam @ ..] = w.as_slice()
            && unicast_words(fam).is_some()
        {
            for a in c.children() {
                if af_line(&words(a), &mut AfSettings::default()) == Line::Read {
                    read.insert(a.first_line);
                }
            }
        }
    }
}

/// The BGP routes of the route table section by VRF and prefix, with the
/// next hops of their paths that are not backup paths.
pub fn collected(
    cfg: &super::Config,
    sections: &BTreeMap<String, (Vec<u8>, String)>,
) -> Vec<CollectedBgp> {
    let st = super::state::read(sections, &super::names(cfg));
    let Some(Ok(rib)) = &st.rib else {
        return Vec::new();
    };
    let mut by: BTreeMap<(String, Prefix), (Vec<IpAddr>, Vec<SourceSpan>)> = BTreeMap::new();
    for p in rib.paths.iter().filter(|p| !p.backup) {
        let first = p.protocol.split_whitespace().next().unwrap_or_default();
        if first.split('*').next() != Some("B") {
            continue;
        }
        let e = by.entry((p.vrf.clone(), p.prefix)).or_default();
        if let Some(g) = p.gateway
            && !e.0.contains(&g)
        {
            e.0.push(g);
        }
        e.1.push(p.span.clone());
    }
    by.into_iter()
        .map(|((vrf, prefix), (next_hops, spans))| CollectedBgp {
            vrf,
            prefix,
            next_hops,
            spans,
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
    vrf_imports(doc, file, mask, &mut out);
    let Some(rb) = doc
        .root
        .children()
        .iter()
        .find(|s| words(s).starts_with(&["router", "bgp"]))
    else {
        return out;
    };
    let mut groups = Groups {
        groups: BTreeMap::new(),
        af_groups: BTreeMap::new(),
        mask,
    };
    for c in rb.children() {
        match words(c).as_slice() {
            [kind @ ("neighbor-group" | "session-group"), name] => {
                groups
                    .groups
                    .insert(((*kind).to_string(), (*name).to_string()), c);
                mark_af(c, read);
            }
            ["af-group", name, "address-family", fam @ ..] => {
                if let Some(f) = unicast_words(fam) {
                    read.insert(c.first_line);
                    for a in c.children() {
                        if af_line(&words(a), &mut AfSettings::default()) == Line::Read {
                            read.insert(a.first_line);
                        }
                    }
                    groups.af_groups.insert(((*name).to_string(), f), c);
                }
            }
            _ => {}
        }
    }
    let ctx = Scope {
        g: &groups,
        bgp,
        policy: &policy,
        file,
    };
    ctx.scope(rb, DEFAULT_VRF, read, &mut out);
    for c in rb.children() {
        if let ["vrf", v] = words(c).as_slice() {
            ctx.scope(c, v, read, &mut out);
        }
    }
    out
}

/// Each `import` line of a unicast family of a VRF is a gap of its VRF and
/// family.
fn vrf_imports(doc: &Document, file: &str, mask: &dyn Fn(&str) -> String, out: &mut DeviceBgp) {
    for s in doc.root.children() {
        let ["vrf", vrf] = words(s).as_slice() else {
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
                if words(c).first() == Some(&"import") {
                    out.gap(vrf, &[f], mask(&c.key), vec![span(file, lines(c))]);
                }
            }
        }
    }
}

struct Scope<'a, 'b> {
    g: &'a Groups<'b>,
    bgp: &'a BgpConfig,
    policy: &'a PolicySet,
    file: &'a str,
}

impl Scope<'_, '_> {
    /// Reads the process of the default VRF or of a `vrf` stanza.
    fn scope(&self, sc: &Stanza, vrf: &str, read: &mut BTreeSet<u32>, out: &mut DeviceBgp) {
        let file = self.file;
        let mask = self.g.mask;
        let mut options = BgpOptions::default();
        let mut router_id = None;
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
            let gap = |out: &mut DeviceBgp| {
                out.gap(vrf, &UNICAST, mask(&c.key), vec![span(file, lines(c))]);
            };
            match w.as_slice() {
                ["bgp", "router-id", a] => match a.parse::<Ipv4Addr>() {
                    Ok(x) => {
                        read.insert(c.first_line);
                        router_id = Some(x);
                    }
                    Err(_) => gap(out),
                },
                ["bgp", "cluster-id", a] => match a.parse::<Ipv4Addr>() {
                    Ok(x) => {
                        read.insert(c.first_line);
                        cluster_id = Some(x);
                    }
                    Err(_) => gap(out),
                },
                ["bgp", "default", "local-preference", v] => match v.parse::<u32>() {
                    Ok(x) => {
                        read.insert(c.first_line);
                        options.default_local_pref = Some(x);
                    }
                    Err(_) => gap(out),
                },
                ["bgp", "bestpath", rest @ ..] => {
                    match rest {
                        ["med", "always"] => options.always_compare_med = true,
                        ["med", "missing-as-worst"] => options.missing_as_worst = Some(true),
                        ["compare-routerid"] => options.compare_routerid = true,
                        ["as-path", "multipath-relax"] => options.multipath_relax = true,
                        _ => {
                            gap(out);
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
                            ["network", p, "route-policy", m] if !m.contains('(') => {
                                key(p).map(|k| {
                                    networks.push(Network {
                                        key: k,
                                        policy: Some((*m).to_string()),
                                        spans,
                                    })
                                })
                            }
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
                            ["maximum-paths", "ebgp", n] => n.parse::<u32>().ok().and_then(|n| {
                                (ebgp_paths.is_none_or(|x| x == n)).then(|| ebgp_paths = Some(n))
                            }),
                            ["maximum-paths", "ibgp", n] => n.parse::<u32>().ok().and_then(|n| {
                                (ibgp_paths.is_none_or(|x| x == n)).then(|| ibgp_paths = Some(n))
                            }),
                            w if no_effect(w) => continue,
                            _ => None,
                        };
                        match ok {
                            Some(()) => {
                                read.insert(a.first_line);
                            }
                            None => out.gap(vrf, &[f], mask(&a.key), vec![span(file, lines(a))]),
                        }
                    }
                }
                ["neighbor", _] | ["bgp", "confederation", ..] | ["rd", ..] => {}
                ["neighbor-group", _] | ["session-group", _] | ["af-group", ..] | ["vrf", _]
                    if top => {}
                ["nsr", ..] | ["bgp", "log", ..] => {}
                w if no_effect(w) => {}
                _ => gap(out),
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
        let mut p = BgpProcess::new("", vrf, Some(Platform::Iosxr), Asn(asn), id);
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
            self.g.session_gaps(ns, 0, &mut gaps);
            let mut af = BTreeMap::new();
            for f in UNICAST {
                af.insert(f, self.g.af_of(ns, f, &mut gaps));
            }
            for (text, l) in gaps {
                out.gap(vrf, &UNICAST, text, vec![span(file, l)]);
            }
            let policies = af.values().flat_map(|a| a.import.iter().chain(&a.export));
            if let Some(m) = policies.into_iter().find(|m| m.contains('(')) {
                out.gap(
                    vrf,
                    &UNICAST,
                    format!("route-policy {m} with parameters"),
                    vec![span(file, n.lines)],
                );
            }
            match neighbor(n, asn, &af, file) {
                Ok(mut nb) => {
                    if p.session_kind(&nb).is_internal() {
                        nb.send_community = true;
                        nb.send_community_extended = true;
                    }
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
        AsPath, BgpPath, Direction, MatchReads, Peer, PolicyContext, PolicyResult, SessionKind,
        evaluate,
    };
    use std::net::IpAddr;

    const CONFIG: &str = "\
prefix-set LAN
  203.0.113.0/24 le 26,
  2001:db8::/32 le 64
end-set
!
prefix-set ODD
  203.0.113.0/24 between 25
end-set
!
community-set KEEP
  64496:100,
  64496:[200..299],
  ios-regex '^64497:'
end-set
!
as-path-set FROM-64496
  ios-regex '^64496_',
  length ge 10
end-set
!
route-policy FROM-PEER
  if destination in LAN and not as-path in FROM-64496 then
    set local-preference 200
    set community (64496:300) additive
    pass
  elseif community matches-any KEEP then
    prepend as-path 64502 2
    done
  elseif destination in ODD then
    pass
  else
    drop
  endif
end-policy
!
route-policy PASS
  pass
end-policy
!
route-policy ODD-ACTION
  set extcommunity color COLOR
  pass
end-policy
!
vrf RED
 address-family ipv4 unicast
  import route-target
   64496:100
  !
 !
!
router bgp 64502
 bgp router-id 192.0.2.1
 bgp cluster-id 192.0.2.100
 bgp bestpath med always
 address-family ipv4 unicast
  network 192.0.2.64/27
  maximum-paths ibgp 2
  redistribute connected
 !
 af-group RR-AF address-family ipv4 unicast
  route-reflector-client
 !
 neighbor-group CLIENTS
  remote-as 64502
  update-source Loopback0
  address-family ipv4 unicast
   use af-group RR-AF
   next-hop-self
  !
 !
 neighbor 192.0.2.2
  use neighbor-group CLIENTS
 !
 neighbor 198.51.100.1
  remote-as 64501
  as-override
  address-family ipv4 unicast
   route-policy FROM-PEER in
   route-policy PASS out
  !
 !
 vrf RED
  rd 64502:1
  address-family ipv4 unicast
  !
 !
!
";

    fn lowered() -> (DeviceBgp, BTreeSet<u32>) {
        let doc = crate::stanza::read_indented(CONFIG);
        let mut read = BTreeSet::new();
        let bgp = crate::iosxr::bgp::read(
            doc.root
                .children()
                .iter()
                .find(|s| s.key.starts_with("router bgp"))
                .unwrap(),
            &mut read,
            &|k| k.to_string(),
        );
        let out = super::read(&doc, &bgp, "x1/config", &|k| k.to_string(), &mut read);
        (out, read)
    }

    fn run(
        set: &PolicySet,
        name: &str,
        prefix: &str,
        as_path: &[u32],
        comms: &[&str],
    ) -> PolicyResult {
        let peer = Peer {
            address: Some("198.51.100.1".parse::<IpAddr>().unwrap()),
            router_id: "198.51.100.1".parse().unwrap(),
            asn: Asn(64501),
            kind: SessionKind::Ebgp,
        };
        let key = RouteKey::unicast(prefix.parse().unwrap());
        let mut p = BgpPath::new(peer, None, AsPath::sequence(as_path));
        p.communities = comms.iter().map(|c| c.parse().unwrap()).collect();
        let ctx = PolicyContext {
            set,
            direction: Direction::Import,
            local_address: None,
            peer_address: None,
            default_local_pref: 100,
            match_reads: MatchReads::Input,
        };
        evaluate(&set.policies[name], &key, &p, &ctx)
    }

    #[test]
    fn an_rpl_policy_gives_its_branches() {
        let (d, _) = lowered();
        let set = &d.processes[0].policy;
        match run(set, "FROM-PEER", "203.0.113.64/26", &[64501], &[]) {
            PolicyResult::Permit(p) => {
                assert_eq!(p.local_pref, Some(200));
                assert!(p.communities.contains(&Community::new(64496, 300)));
            }
            other => panic!("{other:?}"),
        }
        match run(
            set,
            "FROM-PEER",
            "198.51.100.0/24",
            &[64501],
            &["64496:250"],
        ) {
            PolicyResult::Permit(p) => {
                assert_eq!(p.as_path, AsPath::sequence(&[64502, 64502, 64501]));
            }
            other => panic!("{other:?}"),
        }
        // The prefix set ODD has an element that is not read.
        assert!(!set.prefix_lists.contains_key("ODD"));
        assert!(matches!(
            run(set, "FROM-PEER", "198.51.100.0/24", &[64501], &[]),
            PolicyResult::Unknown(_)
        ));
        match &set.policies["ODD-ACTION"].body {
            PolicyBody::Rpl(s) => {
                assert!(matches!(s[0], Statement::Set(SetAction::Unhandled(_))));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_process_takes_the_options_and_the_group_settings() {
        let (d, _) = lowered();
        assert_eq!(d.processes.len(), 1);
        let p = &d.processes[0];
        assert_eq!(p.cluster_id, Some("192.0.2.100".parse().unwrap()));
        assert!(p.options.always_compare_med);
        assert_eq!(p.options.maximum_paths_ibgp, Some(2));
        let client = &p.neighbors[&"192.0.2.2".parse::<IpAddr>().unwrap()];
        assert!(client.route_reflector_client);
        assert_eq!(client.next_hop_self, NextHopSelf::On);
        assert!(client.send_community && client.send_community_extended);
        let ebgp = &p.neighbors[&"198.51.100.1".parse::<IpAddr>().unwrap()];
        assert_eq!(ebgp.import_policy.as_deref(), Some("FROM-PEER"));
        assert!(!ebgp.send_community);
        let texts: Vec<(&str, &str)> = d
            .gaps
            .iter()
            .map(|g| (g.vrf.as_str(), g.text.as_str()))
            .collect();
        for want in [
            ("default", "redistribute connected"),
            ("default", "as-override"),
            ("RED", "import route-target"),
            ("RED", "router-id not configured"),
        ] {
            assert!(texts.contains(&want), "{want:?} not in {texts:?}");
        }
    }

    #[test]
    fn each_handled_line_is_read() {
        let doc = crate::stanza::read_indented(CONFIG);
        let tables = crate::route_tables::RouteTables::uniform(true, Default::default());
        let table = crate::iosxr::table(&tables);
        let cfg = crate::iosxr::read(&doc, &table);
        assert_eq!(
            crate::iosxr::unread(&doc, &table, &cfg.read),
            Vec::<String>::new()
        );
    }
}
