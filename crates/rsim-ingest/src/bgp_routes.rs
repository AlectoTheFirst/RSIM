//! The section `bgp_routes`: the received table, the accepted table and
//! the advertised table of each neighbour, with the outcome of the read of
//! each table.
//!
//! NX-OS and VyOS store one JSON object of VRF, address and direction,
//! where each direction is `{"answer": <answer>}` or `{"failed": <error>}`.
//! An NX-OS answer is the `TABLE_vrf` tree of HST `collectors/nxos.py`
//! `parse_bgp_paths`, and `{}` is an empty table. A VyOS answer is the FRR
//! form of HST `collectors/vyos.py`: the key `receivedRoutes`, `routes` or
//! `advertisedRoutes` with an object for each prefix (the received and the
//! advertised tables) or a list of paths (the accepted table). An FRR
//! answer with no table key, a key that is not an IPv4 prefix, or a prefix
//! counter (`totalPrefixCounter`, `numRoutes`) that does not agree with the
//! table is `Failed`.
//!
//! IOS-XE and IOS-XR store text with the line `NEIGHBOR: <vrf> <address>
//! <direction>` before each answer, or the same line with ` failed`. The
//! answer is read by the columns of its header (`bgp_table.rs`). A blank
//! answer, and an answer with no path row and no row-shaped line, is
//! `CompleteEmpty`. A line that starts with `%` makes the table `Failed`,
//! and so does a prefix counter (`Total number of prefixes <n>`,
//! `Processed <n> prefixes, <m> paths`) that does not agree with the
//! prefixes of the rows, and an answer with row-shaped lines of which none
//! is read. The text tables hold no communities.

use std::collections::BTreeSet;
use std::net::IpAddr;

use rsim_core::{Prefix, SourceSpan};
use rsim_routing::bgp::{AsPath, AsSegment, Asn, BgpOrigin, Community, SegmentKind};
use serde_json::Value;

use crate::bgp::{Answer, Outcome};

/// The section of the tables of the neighbours.
pub const ROUTES: &str = "bgp_routes";

/// The line before each answer of a text section.
pub const NEIGHBOR_LINE: &str = "NEIGHBOR: ";

/// The table of a neighbour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// The paths from the neighbour before the import policy.
    Received,
    /// The paths from the neighbour after the import policy.
    Accepted,
    /// The paths to the neighbour.
    Advertised,
}

impl Direction {
    pub const ALL: [Direction; 3] = [
        Direction::Received,
        Direction::Accepted,
        Direction::Advertised,
    ];

    /// The name of the direction in the section: `received-routes`,
    /// `routes` or `advertised-routes`.
    pub fn word(self) -> &'static str {
        match self {
            Direction::Received => "received-routes",
            Direction::Accepted => "routes",
            Direction::Advertised => "advertised-routes",
        }
    }

    pub fn of(word: &str) -> Option<Direction> {
        Direction::ALL.into_iter().find(|d| d.word() == word)
    }

    /// The FRR key of the table and the key of its prefix counter.
    fn frr_keys(self) -> (&'static str, &'static str) {
        match self {
            Direction::Received => ("receivedRoutes", "totalPrefixCounter"),
            Direction::Accepted => ("routes", "numRoutes"),
            Direction::Advertised => ("advertisedRoutes", "totalPrefixCounter"),
        }
    }
}

/// One path of a table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathRow {
    pub prefix: Prefix,
    pub next_hop: Option<IpAddr>,
    /// `None` when a token of the AS path is not read.
    pub as_path: Option<AsPath>,
    pub origin: Option<BgpOrigin>,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    pub weight: Option<u32>,
    /// `None` when the table holds no communities.
    pub communities: Option<BTreeSet<Community>>,
    /// True if the device marks the path best.
    pub best: bool,
    pub span: SourceSpan,
}

/// One table of a neighbour with the outcome of its read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    pub vrf: String,
    pub peer: IpAddr,
    pub direction: Direction,
    pub outcome: Outcome,
    /// The reason of an outcome other than `Complete` and `CompleteEmpty`.
    pub detail: Option<String>,
    pub rows: Vec<PathRow>,
}

impl Table {
    /// True if the table is read whole.
    pub fn complete(&self) -> bool {
        matches!(self.outcome, Outcome::Complete | Outcome::CompleteEmpty)
    }
}

/// The tables of the section of a device of a vendor. A section that is not
/// fresh gives no table.
pub fn read(vendor: &str, a: Answer<'_>) -> Vec<Table> {
    let Answer::Fresh(bytes, file) = a else {
        return Vec::new();
    };
    match vendor {
        "nxos" | "vyos" => json_tables(vendor, bytes, file),
        "iosxe" | "iosxr" => text_tables(&String::from_utf8_lossy(bytes), file),
        _ => Vec::new(),
    }
}

/// The table of an outcome with no row.
fn failed(vrf: &str, peer: IpAddr, d: Direction, detail: impl Into<String>) -> Table {
    Table {
        vrf: vrf.to_string(),
        peer,
        direction: d,
        outcome: Outcome::Failed,
        detail: Some(detail.into()),
        rows: Vec::new(),
    }
}

/// The outcome of a table with `rows` read rows and `unread` row-shaped
/// parts that are not read.
fn outcome(rows: usize, unread: usize) -> (Outcome, Option<String>) {
    let detail = (unread > 0).then(|| format!("{unread} paths not read"));
    match (rows, unread) {
        (0, 0) => (Outcome::CompleteEmpty, None),
        (_, 0) => (Outcome::Complete, None),
        (0, _) => (Outcome::Failed, detail),
        _ => (Outcome::Partial, detail),
    }
}

/// An AS path of the tokens of a table: AS numbers, `{a,b}` for an
/// AS_SET and `(a b)` for an AS_CONFED_SEQUENCE.
pub fn as_path(text: &str) -> Option<AsPath> {
    fn push(segments: &mut Vec<AsSegment>, kind: SegmentKind, asn: Asn) {
        let same = kind != SegmentKind::Set && segments.last().is_some_and(|s| s.kind == kind);
        match segments.last_mut() {
            Some(s) if same => s.asns.push(asn),
            _ => segments.push(AsSegment {
                kind,
                asns: vec![asn],
            }),
        }
    }
    let mut segments: Vec<AsSegment> = Vec::new();
    let mut confed = false;
    for token in text.split_whitespace() {
        if let Some(set) = token.strip_prefix('{') {
            let set = set.strip_suffix('}')?;
            let asns = set
                .split(',')
                .map(|a| crate::bgp_peers::parse_asn(a).map(Asn))
                .collect::<Option<Vec<_>>>()?;
            segments.push(AsSegment {
                kind: SegmentKind::Set,
                asns,
            });
            continue;
        }
        let mut t = token;
        if let Some(x) = t.strip_prefix('(') {
            confed = true;
            t = x;
        }
        let close = t.ends_with(')');
        let t = t.strip_suffix(')').unwrap_or(t);
        let a = Asn(crate::bgp_peers::parse_asn(t)?);
        let kind = if confed {
            SegmentKind::ConfedSequence
        } else {
            SegmentKind::Sequence
        };
        push(&mut segments, kind, a);
        if close {
            if !confed {
                return None;
            }
            confed = false;
        }
    }
    if confed {
        return None;
    }
    Some(AsPath { segments })
}

/// The origin of a word of a table.
fn origin(w: &str) -> Option<BgpOrigin> {
    match w {
        "i" | "igp" | "IGP" => Some(BgpOrigin::Igp),
        "e" | "egp" | "EGP" => Some(BgpOrigin::Egp),
        "?" | "incomplete" | "INCOMPLETE" | "Incomplete" => Some(BgpOrigin::Incomplete),
        _ => None,
    }
}

/// The communities of a text of `a:b` words.
fn communities(text: &str) -> Option<BTreeSet<Community>> {
    text.split_whitespace()
        .map(|c| c.parse::<Community>().ok())
        .collect()
}

// The text tables of IOS-XE and IOS-XR.

/// The tables of a text section.
fn text_tables(text: &str, file: &str) -> Vec<Table> {
    let lines: Vec<&str> = text.lines().collect();
    let heads: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.starts_with(NEIGHBOR_LINE))
        .map(|(i, _)| i)
        .collect();
    let mut out = Vec::new();
    for (k, &h) in heads.iter().enumerate() {
        let end = heads.get(k + 1).copied().unwrap_or(lines.len());
        let words: Vec<&str> = lines[h][NEIGHBOR_LINE.len()..].split_whitespace().collect();
        let (vrf, peer, d, is_failed) = match words.as_slice() {
            [v, a, d] => (*v, *a, *d, false),
            [v, a, d, "failed"] => (*v, *a, *d, true),
            _ => continue,
        };
        let (Ok(peer), Some(d)) = (peer.parse::<IpAddr>(), Direction::of(d)) else {
            continue;
        };
        if is_failed {
            out.push(failed(vrf, peer, d, "the command failed"));
            continue;
        }
        let body = lines[h + 1..end].join("\n");
        let offset = u32::try_from(h + 1).unwrap_or(u32::MAX);
        out.push(text_table(vrf, peer, d, &body, file, offset));
    }
    out
}

/// The number of a counter line: `Total number of prefixes <n>` or
/// `Processed <n> prefixes, <m> paths`.
fn counter(body: &str) -> Option<usize> {
    body.lines().find_map(|l| {
        let w: Vec<&str> = l.split_whitespace().collect();
        match w.as_slice() {
            ["Total", "number", "of", "prefixes", n, ..] => n.parse().ok(),
            ["Processed", n, "prefixes,", ..] | ["Processed", n, "prefix,", ..] => n.parse().ok(),
            _ => None,
        }
    })
}

/// One text answer. `offset` is the line of the section before the first
/// line of `body`.
fn text_table(vrf: &str, peer: IpAddr, d: Direction, body: &str, file: &str, offset: u32) -> Table {
    if let Some(l) = body.lines().find(|l| l.trim_start().starts_with('%')) {
        return failed(vrf, peer, d, l.trim());
    }
    let mut rows = Vec::new();
    let mut unread = 0;
    for r in crate::bgp_table::path_rows(body) {
        let Ok(prefix) = r.network.parse::<Prefix>() else {
            unread += 1;
            continue;
        };
        let status = r.status.clone().unwrap_or_default();
        rows.push(PathRow {
            prefix,
            next_hop: crate::bgp_table::next_hop_of(&r.next_hop),
            as_path: as_path(&r.as_path),
            origin: origin(&r.origin.to_string()),
            med: r.metric,
            local_pref: r.local_pref,
            weight: r.weight,
            communities: None,
            best: r.status.is_none() || status.contains('>'),
            span: SourceSpan::new(file, offset + r.lines.0, offset + r.lines.1),
        });
    }
    if rows.is_empty() && unread == 0 && crate::bgp_table::holds_path_rows(body) {
        return failed(vrf, peer, d, "no path row of the answer is read");
    }
    let prefixes: BTreeSet<Prefix> = rows.iter().map(|r| r.prefix).collect();
    if let Some(n) = counter(body)
        && n != prefixes.len() + unread
    {
        return failed(
            vrf,
            peer,
            d,
            format!(
                "the answer states {n} prefixes and its table has {}",
                prefixes.len() + unread
            ),
        );
    }
    let (outcome, detail) = outcome(rows.len(), unread);
    Table {
        vrf: vrf.to_string(),
        peer,
        direction: d,
        outcome,
        detail,
        rows,
    }
}

// The JSON tables of NX-OS and VyOS.

/// The tables of a JSON section.
fn json_tables(vendor: &str, bytes: &[u8], file: &str) -> Vec<Table> {
    let Ok(Value::Object(top)) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut index: u32 = 0;
    for (vrf, peers) in &top {
        let Some(peers) = peers.as_object() else {
            continue;
        };
        for (addr, dirs) in peers {
            let Ok(peer) = addr.parse::<IpAddr>() else {
                continue;
            };
            let Some(dirs) = dirs.as_object() else {
                continue;
            };
            for d in Direction::ALL {
                let Some(entry) = dirs.get(d.word()) else {
                    continue;
                };
                if let Some(e) = entry.get("failed") {
                    let why = e.as_str().unwrap_or("the command failed");
                    out.push(failed(vrf, peer, d, why));
                    continue;
                }
                let Some(answer) = entry.get("answer") else {
                    out.push(failed(vrf, peer, d, "the entry has no answer"));
                    continue;
                };
                let t = match vendor {
                    "nxos" => nxos_table(vrf, peer, d, answer, file, &mut index),
                    _ => frr_table(vrf, peer, d, answer, file, &mut index),
                };
                out.push(t);
            }
        }
    }
    out
}

/// The answer of a command that is not a JSON object: the first line of a
/// `%` text, else a reason.
fn text_answer(v: &Value) -> Option<String> {
    let s = v.as_str()?;
    let t = s.trim();
    if t.starts_with('%') {
        return Some(t.lines().next().unwrap_or_default().to_string());
    }
    Some("the answer is not a JSON object".to_string())
}

/// The rows of `TABLE_<name>`, one object or a list.
fn rows<'a>(v: &'a Value, name: &str) -> Vec<&'a Value> {
    match v
        .get(format!("TABLE_{name}"))
        .and_then(|t| t.get(format!("ROW_{name}")))
    {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(o @ Value::Object(_)) => vec![o],
        _ => Vec::new(),
    }
}

/// A number as a JSON number or a string of digits.
fn num(v: Option<&Value>) -> Option<u32> {
    match v? {
        Value::Number(n) => n.as_u64().and_then(|x| u32::try_from(x).ok()),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn text(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str)
}

fn truth(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        Some(Value::Object(o)) => truth(o.get("overall")),
        _ => false,
    }
}

fn next_row(index: &mut u32) -> u32 {
    *index = index.saturating_add(1);
    *index
}

/// One NX-OS answer: vrf, address family, sub-family, route
/// distinguisher, prefix and path. A sub-family with its prefixes and no
/// route distinguisher level is read too.
fn nxos_table(
    vrf: &str,
    peer: IpAddr,
    d: Direction,
    answer: &Value,
    file: &str,
    index: &mut u32,
) -> Table {
    if let Some(why) = text_answer(answer) {
        return failed(vrf, peer, d, why);
    }
    let Some(o) = answer.as_object() else {
        return failed(vrf, peer, d, "the answer is not a JSON object");
    };
    if !o.is_empty() && !o.contains_key("TABLE_vrf") {
        return failed(vrf, peer, d, "the answer has no TABLE_vrf");
    }
    let mut out = Vec::new();
    let mut unread = 0;
    for v in rows(answer, "vrf") {
        for afi in rows(v, "afi") {
            for safi in rows(afi, "safi") {
                let rds = rows(safi, "rd");
                let holders = if rds.is_empty() { vec![safi] } else { rds };
                for h in holders {
                    for p in rows(h, "prefix") {
                        let prefix = text(p.get("ipprefix")).and_then(|x| x.parse::<Prefix>().ok());
                        for path in rows(p, "path") {
                            let n = next_row(index);
                            let Some(prefix) = prefix else {
                                unread += 1;
                                continue;
                            };
                            let hop = text(path.get("ipnexthop"));
                            let next_hop = hop.and_then(|h| h.parse().ok());
                            if hop.is_some_and(|h| !h.is_empty()) && next_hop.is_none() {
                                unread += 1;
                                continue;
                            }
                            out.push(PathRow {
                                prefix,
                                next_hop,
                                as_path: as_path(text(path.get("aspath")).unwrap_or_default()),
                                origin: text(path.get("origin")).and_then(origin),
                                med: num(path.get("metric")),
                                local_pref: num(path.get("localpref")),
                                weight: num(path.get("weight")),
                                communities: Some(
                                    text(path.get("community"))
                                        .and_then(communities)
                                        .unwrap_or_default(),
                                ),
                                best: truth(path.get("best")),
                                span: SourceSpan::row(file, n),
                            });
                        }
                    }
                }
            }
        }
    }
    let (outcome, detail) = outcome(out.len(), unread);
    Table {
        vrf: vrf.to_string(),
        peer,
        direction: d,
        outcome,
        detail,
        rows: out,
    }
}

/// The reason why an FRR answer is not a table that the reader reads
/// whole, after HST `_route_table_problem`: the table key of the direction
/// is an object, each key is an IPv4 prefix, each value is a path object or
/// a list of path objects with one path or more, and the prefix counter, if
/// the answer states one, is the number of prefixes. An empty received or
/// advertised table states the counter 0.
fn frr_problem(o: &serde_json::Map<String, Value>, d: Direction) -> Option<String> {
    let (key, counter) = d.frr_keys();
    let Some(table) = o.get(key) else {
        if o.is_empty() {
            return Some(format!(
                "the answer is an empty JSON object, with no {key} table"
            ));
        }
        return Some(format!("the answer has no {key} table"));
    };
    let Some(table) = table.as_object() else {
        return Some(format!(
            "the {key} table of the answer is not a JSON object"
        ));
    };
    let unread = table
        .iter()
        .filter(|(p, v)| {
            let v4 = p.parse::<Prefix>().is_ok_and(|x| x.is_ipv4());
            let ok = match v {
                Value::Object(_) => true,
                Value::Array(a) => !a.is_empty() && a.iter().all(Value::is_object),
                _ => false,
            };
            !(v4 && ok)
        })
        .count();
    if unread > 0 {
        return Some(format!(
            "{unread} of the {} prefixes of the {key} table are not read",
            table.len()
        ));
    }
    match num(o.get(counter)) {
        None if table.is_empty() && d != Direction::Accepted => Some(format!(
            "the {key} table is empty and the answer states no {counter}"
        )),
        Some(n) if usize::try_from(n).ok() != Some(table.len()) => Some(format!(
            "the answer states {counter} {n} and its {key} table has {} prefixes",
            table.len()
        )),
        _ => None,
    }
}

/// The next hop of an FRR path: the used entry of `nexthops`, else its
/// first entry, else the `nextHop` of the received and advertised forms.
fn frr_next_hop(path: &Value) -> Option<&str> {
    if let Some(Value::Array(hops)) = path.get("nexthops") {
        let hops: Vec<&Value> = hops.iter().filter(|h| h.is_object()).collect();
        if !hops.is_empty() {
            return hops
                .iter()
                .find(|h| truth(h.get("used")))
                .or(hops.first())
                .and_then(|h| text(h.get("ip")));
        }
    }
    text(path.get("nextHop")).filter(|s| !s.is_empty())
}

/// The AS path of an FRR path: `aspath.string`, `aspath` as a string, else
/// `path`.
fn frr_as_path(path: &Value) -> &str {
    match path.get("aspath") {
        Some(Value::Object(o)) => text(o.get("string")),
        Some(Value::String(s)) => Some(s.as_str()),
        _ => None,
    }
    .or_else(|| text(path.get("path")))
    .unwrap_or_default()
}

fn frr_communities(path: &Value) -> Option<BTreeSet<Community>> {
    match path.get("community") {
        Some(Value::Object(o)) => text(o.get("string")).and_then(communities),
        Some(Value::String(s)) => communities(s),
        None => Some(BTreeSet::new()),
        _ => None,
    }
}

/// One FRR answer.
fn frr_table(
    vrf: &str,
    peer: IpAddr,
    d: Direction,
    answer: &Value,
    file: &str,
    index: &mut u32,
) -> Table {
    if let Some(why) = text_answer(answer) {
        return failed(vrf, peer, d, why);
    }
    let Some(o) = answer.as_object() else {
        return failed(vrf, peer, d, "the answer is not a JSON object");
    };
    if let Some(why) = frr_problem(o, d) {
        return failed(vrf, peer, d, why);
    }
    let (key, _) = d.frr_keys();
    let mut out = Vec::new();
    let mut unread = 0;
    for (p, v) in o.get(key).and_then(Value::as_object).into_iter().flatten() {
        let Ok(prefix) = p.parse::<Prefix>() else {
            continue;
        };
        let paths: Vec<&Value> = match v {
            Value::Array(a) => a.iter().collect(),
            other => vec![other],
        };
        for path in paths {
            let n = next_row(index);
            let hop = frr_next_hop(path);
            let next_hop = hop.and_then(|h| h.parse().ok());
            if hop.is_some() && next_hop.is_none() {
                unread += 1;
                continue;
            }
            out.push(PathRow {
                prefix,
                next_hop,
                as_path: as_path(frr_as_path(path)),
                origin: text(path.get("origin")).and_then(origin),
                med: num(path.get("metric")),
                local_pref: num(path.get("locPrf")),
                weight: num(path.get("weight")),
                communities: frr_communities(path),
                best: d == Direction::Advertised
                    || truth(path.get("bestpath"))
                    || truth(path.get("best")),
                span: SourceSpan::row(file, n),
            });
        }
    }
    let (outcome, detail) = outcome(out.len(), unread);
    Table {
        vrf: vrf.to_string(),
        peer,
        direction: d,
        outcome,
        detail,
        rows: out,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_as_path_with_a_set_and_a_confederation_segment() {
        let p = as_path("(64512 64513) 64500 {64501,64502}").unwrap();
        assert_eq!(p.segments.len(), 3);
        assert_eq!(p.segments[0].kind, SegmentKind::ConfedSequence);
        assert_eq!(p.segments[2].kind, SegmentKind::Set);
        assert_eq!(p.len(), 2);
        assert_eq!(as_path("").unwrap(), AsPath::default());
        assert_eq!(as_path("64500 x"), None);
    }

    #[test]
    fn a_text_section_gives_a_table_for_each_head() {
        use crate::bgp_table::{HEADER, print_row};
        let row = print_row(" *>", "10.0.0.0", "192.0.2.1", "0", "", "0", "64500 i");
        let text = format!(
            "NEIGHBOR: default 192.0.2.1 received-routes\n\
             % Inbound soft reconfiguration not enabled on 192.0.2.1\n\
             NEIGHBOR: default 192.0.2.1 routes\n\
             BGP table version is 4, local router ID is 192.0.2.9\n\
             {HEADER}\n\
             {row}\n\
             \n\
             Total number of prefixes 1 \n\
             NEIGHBOR: default 192.0.2.1 advertised-routes\n\
             \n\
             Total number of prefixes 0 \n\
             NEIGHBOR: RED 192.0.2.5 routes failed\n\
             NEIGHBOR: RED 192.0.2.5 advertised-routes\n\
             {HEADER}\n\
             {row}\n\
             \n\
             Total number of prefixes 2 \n"
        );
        let t = read("iosxe", Answer::Fresh(text.as_bytes(), "r1/bgp_routes"));
        let got: Vec<(&str, Direction, Outcome, usize)> = t
            .iter()
            .map(|x| (x.vrf.as_str(), x.direction, x.outcome, x.rows.len()))
            .collect();
        assert_eq!(
            got,
            [
                ("default", Direction::Received, Outcome::Failed, 0),
                ("default", Direction::Accepted, Outcome::Complete, 1),
                ("default", Direction::Advertised, Outcome::CompleteEmpty, 0),
                ("RED", Direction::Accepted, Outcome::Failed, 0),
                ("RED", Direction::Advertised, Outcome::Failed, 0),
            ]
        );
        let r = &t[1].rows[0];
        assert_eq!(r.prefix, "10.0.0.0/8".parse::<Prefix>().unwrap());
        assert_eq!(r.next_hop, Some(ip("192.0.2.1")));
        assert_eq!(r.as_path, Some(AsPath::sequence(&[64500])));
        assert!(r.best);
        assert_eq!(r.span, SourceSpan::new("r1/bgp_routes", 6, 6));
        assert!(
            t[4].detail
                .as_deref()
                .unwrap()
                .contains("states 2 prefixes")
        );
    }

    #[test]
    fn an_nxos_section_with_2_paths_an_empty_table_and_a_failed_command() {
        let json = r#"{"default":{"192.0.2.1":{
            "received-routes":{"answer":{}},
            "routes":{"answer":{"TABLE_vrf":{"ROW_vrf":[{"vrf-name-out":"default","TABLE_afi":{"ROW_afi":[{"afi":"1","TABLE_safi":{"ROW_safi":[{"safi":"1","TABLE_prefix":{"ROW_prefix":[{"ipprefix":"198.51.100.0/24","TABLE_path":{"ROW_path":[
                {"pathnr":"0","ipnexthop":"192.0.2.1","aspath":"64500 64501","localpref":"100","metric":"5","origin":"i","weight":"0","best":"true","community":"64500:1"},
                {"pathnr":"1","ipnexthop":"192.0.2.2","aspath":"64502","localpref":"100","metric":"","origin":"e","weight":"0","best":"false"}]}}]}}]}}]}}]}}},
            "advertised-routes":{"failed":"timeout"}}}}"#;
        let t = read("nxos", Answer::Fresh(json.as_bytes(), "n1/bgp_routes"));
        assert_eq!(t.len(), 3);
        assert_eq!(t[0].outcome, Outcome::CompleteEmpty);
        assert_eq!(t[1].outcome, Outcome::Complete);
        assert_eq!(t[1].rows.len(), 2);
        assert_eq!(t[1].rows[0].med, Some(5));
        assert_eq!(t[1].rows[1].med, None);
        assert_eq!(t[1].rows[1].origin, Some(BgpOrigin::Egp));
        assert!(t[1].rows[0].best && !t[1].rows[1].best);
        assert_eq!(
            t[1].rows[0].communities,
            Some(BTreeSet::from([Community::new(64500, 1)]))
        );
        assert_eq!(t[2].outcome, Outcome::Failed);
    }

    #[test]
    fn an_frr_section_checks_the_table_and_the_prefix_counter() {
        let json = r#"{"default":{"192.0.2.1":{
            "received-routes":{"answer":{"receivedRoutes":{"10.1.0.0/16":{"network":"10.1.0.0/16","nextHop":"192.0.2.1","metric":0,"weight":0,"path":"64500","origin":"IGP"}},"totalPrefixCounter":1}},
            "routes":{"answer":{"routes":{"10.1.0.0/16":[{"valid":true,"bestpath":true,"path":"64500","origin":"IGP","nexthops":[{"ip":"192.0.2.1","used":true}]},{"valid":true,"path":"64501 64500","origin":"IGP","nexthops":[{"ip":"192.0.2.3"}]}]},"numRoutes":2}},
            "advertised-routes":{"answer":{"advertisedRoutes":{},"totalPrefixCounter":0}}},
          "192.0.2.5":{"received-routes":{"answer":{}},"routes":{"answer":{"routes":{}}},"advertised-routes":{"answer":{"advertisedRoutes":{}}}}}}"#;
        let t = read("vyos", Answer::Fresh(json.as_bytes(), "v1/bgp_routes"));
        let got: Vec<(&str, Direction, Outcome, usize)> = t
            .iter()
            .map(|x| (x.vrf.as_str(), x.direction, x.outcome, x.rows.len()))
            .collect();
        assert_eq!(
            got,
            [
                ("default", Direction::Received, Outcome::Complete, 1),
                ("default", Direction::Accepted, Outcome::Failed, 0),
                ("default", Direction::Advertised, Outcome::CompleteEmpty, 0),
                ("default", Direction::Received, Outcome::Failed, 0),
                ("default", Direction::Accepted, Outcome::CompleteEmpty, 0),
                ("default", Direction::Advertised, Outcome::Failed, 0),
            ]
        );
        assert!(t[1].detail.as_deref().unwrap().contains("numRoutes 2"));
        assert_eq!(t[0].rows[0].next_hop, Some(ip("192.0.2.1")));
        assert_eq!(t[0].rows[0].origin, Some(BgpOrigin::Igp));
    }
}
