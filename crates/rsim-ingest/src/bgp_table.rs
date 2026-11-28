//! The BGP path tables of IOS-XE and IOS-XR, read by the column positions
//! of the header line, after HST `collectors/cisco_bgp_table.py`.
//!
//! The header line `Network  Next Hop  Metric LocPrf Weight Path` gives the
//! columns. Metric, LocPrf and Weight are right-aligned under the last
//! letter of their header word, and a blank value is spaces. A row at most
//! 2 columns right of the header is read by position, and each other row
//! by its tokens when the tokens fit the columns. A network longer than its
//! column is alone on its line, and the rest of its first path is on the
//! next line. A further path of a network has a blank network column and
//! takes the network of the row above it. A network with no length gets
//! its classful length. The IOS-XR table of the advertised routes has the
//! header `Network  Next Hop  From  AS Path`, with rows from column 0 and no
//! status, metric, local preference or weight.
//!
//! A line is a path row only when its network and its next hop are
//! well-formed addresses and its numbers fit the columns. Each other line
//! after a header ends the carry of a network into the rows below it. The
//! layouts come from the Cisco documents and the ntc-templates of these
//! commands, and no capture of a device confirms them.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One path of a table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The status codes with no space, `None` in a table with no status
    /// column.
    pub status: Option<String>,
    /// The network with its length, except a class D or E network with no
    /// length.
    pub network: String,
    pub next_hop: String,
    pub metric: Option<u32>,
    pub local_pref: Option<u32>,
    pub weight: Option<u32>,
    /// The AS path tokens joined by one space, empty for no AS.
    pub as_path: String,
    /// `i`, `e` or `?`.
    pub origin: char,
    /// The lines of the row from 1: the line of the network of a wrapped
    /// network to the line of the path.
    pub lines: (u32, u32),
}

/// The characters of the status area: the status codes, the RPKI codes
/// and the space.
const STATUS_CHARS: &str = " *>sdhirSmbfxacVINDtL-";
/// The width of the metric column, which ends under `Metric`.
const METRIC_WIDTH: usize = 10;
/// The largest difference between the first and the last distance of a
/// line read by its tokens.
const MAX_SPREAD: i64 = 4;
/// The largest offset from the header at which a row is read by position.
const MAX_OFFSET: i64 = 2;
/// The columns that the leading numbers of a line fill, with 0 for Metric,
/// 1 for LocPrf and 2 for Weight, in the order of the tries.
const NUMBER_LAYOUTS: [&[usize]; 4] = [&[0, 1, 2], &[0, 2], &[1, 2], &[2]];

/// The columns of a standard header: the start of the network, the start
/// of the next hop, the ends of Metric, LocPrf and Weight, and the start of
/// the AS path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Geometry {
    n: usize,
    hop: usize,
    metric_end: usize,
    local_pref_end: usize,
    weight_end: usize,
    path: usize,
}

/// The tokens of a line from `from`: the start, the last index and the
/// text of each.
fn tokens(line: &str, from: usize) -> Vec<(usize, usize, &str)> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    let mut i = from;
    while i < b.len() {
        if b[i] == b' ' || b[i] == b'\t' {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && b[i] != b' ' && b[i] != b'\t' {
            i += 1;
        }
        out.push((start, i - 1, &line[start..i]));
    }
    out
}

fn is_next_hop_word(w: &[&str]) -> Option<usize> {
    match w {
        [x, ..] if x.eq_ignore_ascii_case("next-hop") => Some(1),
        [a, h, ..] if *a == "Next" && (*h == "Hop" || *h == "hop") => Some(2),
        _ => None,
    }
}

/// The geometry of a standard header line.
fn header(line: &str) -> Option<Geometry> {
    let t = tokens(line, 0);
    let words: Vec<&str> = t.iter().map(|x| x.2).collect();
    if words.first() != Some(&"Network") {
        return None;
    }
    let k = is_next_hop_word(&words[1..])?;
    if k == 2 && t[2].0 != t[1].1 + 2 {
        return None;
    }
    if words[1 + k..] != ["Metric", "LocPrf", "Weight", "Path"] {
        return None;
    }
    let at = |i: usize| t[1 + k + i];
    Some(Geometry {
        n: t[0].0,
        hop: t[1].0,
        metric_end: at(0).1,
        local_pref_end: at(1).1,
        weight_end: at(2).1,
        path: at(3).0,
    })
}

/// True for the header `Network  Next Hop  From  AS Path`.
fn from_header(line: &str) -> bool {
    let t = tokens(line, 0);
    let words: Vec<&str> = t.iter().map(|x| x.2).collect();
    if words.first() != Some(&"Network") {
        return false;
    }
    let Some(k) = is_next_hop_word(&words[1..]) else {
        return false;
    };
    let rest = &words[1 + k..];
    rest == ["From", "AS", "Path"] || rest == ["From", "AS-Path"]
}

/// An IPv4 address in dotted form with no leading zero.
fn ipv4(s: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    for p in &parts {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if p.len() > 1 && p.starts_with('0') {
            return None;
        }
        if p.parse::<u16>().ok()? > 255 {
            return None;
        }
    }
    s.parse().ok()
}

fn ipv6(s: &str) -> Option<Ipv6Addr> {
    if !s.contains(':')
        || !s
            .bytes()
            .all(|c| c.is_ascii_hexdigit() || c == b':' || c == b'.')
    {
        return None;
    }
    s.parse().ok()
}

fn length(s: &str, max: u8) -> bool {
    !s.is_empty()
        && s.len() <= 3
        && s.bytes().all(|c| c.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'))
        && s.parse::<u8>().is_ok_and(|l| l <= max)
}

/// An IPv4 network with an optional length, or an IPv6 network with a
/// length.
pub fn network_ok(s: &str) -> bool {
    match s.split_once('/') {
        Some((a, l)) => {
            (ipv4(a).is_some() && length(l, 32)) || (ipv6(a).is_some() && length(l, 128))
        }
        None => ipv4(s).is_some(),
    }
}

/// An IPv4 or IPv6 address.
pub fn next_hop_ok(s: &str) -> bool {
    ipv4(s).is_some() || ipv6(s).is_some()
}

/// The address of a next hop of a row.
pub fn next_hop_of(s: &str) -> Option<IpAddr> {
    ipv4(s).map(IpAddr::V4).or_else(|| ipv6(s).map(IpAddr::V6))
}

/// The network with its classful length when it has no length: /8, /16 or
/// /24 by the first octet, and /0 for 0.0.0.0. A network with a length, an
/// IPv6 network and a class D or E network stay. `network` has passed
/// [`network_ok`].
pub fn classful(network: &str) -> String {
    if network.contains('/') || network.contains(':') {
        return network.to_string();
    }
    if network == "0.0.0.0" {
        return "0.0.0.0/0".to_string();
    }
    let first: u32 = network
        .split('.')
        .next()
        .and_then(|x| x.parse().ok())
        .unwrap_or(255);
    match first {
        0..=127 => format!("{network}/8"),
        128..=191 => format!("{network}/16"),
        192..=223 => format!("{network}/24"),
        _ => network.to_string(),
    }
}

/// True if a line of `text` starts with a status area and an IPv4
/// address. The reader cannot read an answer with such a line that gives
/// no row.
pub fn holds_path_rows(text: &str) -> bool {
    text.lines().any(|l| {
        let b = l.as_bytes();
        let mut i = 0;
        while i < b.len() && i < 6 && STATUS_CHARS.as_bytes().contains(&b[i]) {
            i += 1;
        }
        let rest = &l[i..];
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let word = &rest[..end];
        let parts: Vec<&str> = word.split('.').collect();
        parts.len() >= 4
            && parts[..4]
                .iter()
                .all(|p| (1..=3).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_digit()))
    })
}

/// The tokens before the origin and the origin. The origin is the last
/// token, or is printed against the last AS path token.
fn split_origin<'a>(words: &[&'a str]) -> Option<(Vec<&'a str>, char)> {
    let last = *words.last()?;
    if matches!(last, "i" | "e" | "?") {
        return Some((words[..words.len() - 1].to_vec(), last.chars().next()?));
    }
    let o = last.chars().last()?;
    if !matches!(o, 'i' | 'e' | '?') || last.len() < 2 {
        return None;
    }
    let head = &last[..last.len() - 1];
    if !head
        .bytes()
        .all(|c| c.is_ascii_digit() || b"{}(),.".contains(&c))
    {
        return None;
    }
    let mut out = words[..words.len() - 1].to_vec();
    out.push(head);
    Some((out, o))
}

/// The score, the layout and the distances of a layout that fits a line.
type Fit = ((i64, i64), &'static [usize], Vec<i64>);

/// The fields of one line read by its tokens: the network, empty when the
/// column is blank, the next hop, empty for a wrapped network, the metric,
/// the local preference, the weight, the AS path and the origin.
struct Fields {
    network: String,
    next_hop: String,
    numbers: [String; 3],
    as_path: String,
    origin: char,
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

/// One line of a table with the header `g`, read by its tokens. A first
/// token left of the next-hop column is the network, and a network alone
/// on its line is a wrapped network. The next token is the next hop. Of
/// the rest, up to 3 leading numbers fill Metric, LocPrf and Weight in one
/// of [`NUMBER_LAYOUTS`]. Each number sits some distance right of the end
/// of its column, and the AS path some distance right of the Path column.
/// A layout fits when no distance is negative or smaller than the distance
/// before it, and the last distance exceeds the first by at most
/// [`MAX_SPREAD`]. Of the layouts that fit, the one with the smallest
/// excess wins, then the one with the smallest first distance, then the
/// earlier one. The offset is the distance when each distance of the
/// winner is the same and is at most [`MAX_OFFSET`].
fn by_tokens(line: &str, g: &Geometry) -> Option<(Fields, Option<usize>)> {
    let mut t = tokens(line, g.n);
    if t.is_empty() {
        return None;
    }
    let mut network = String::new();
    if t[0].0 < g.hop {
        network = t[0].2.to_string();
        if t.len() == 1 {
            return Some((
                Fields {
                    network,
                    next_hop: String::new(),
                    numbers: Default::default(),
                    as_path: String::new(),
                    origin: 'i',
                },
                None,
            ));
        }
        t.remove(0);
    }
    let next_hop = t[0].2.to_string();
    let rest = &t[1..];
    if rest.is_empty() {
        return None;
    }
    let texts: Vec<&str> = rest.iter().map(|x| x.2).collect();
    let (words, origin) = split_origin(&texts)?;
    if words.is_empty() {
        return None;
    }
    let mut spans: Vec<(i64, i64)> = rest[..words.len()]
        .iter()
        .map(|x| (x.0 as i64, x.1 as i64))
        .collect();
    if words.len() == rest.len() {
        let last = spans.len() - 1;
        spans[last].1 -= 1;
    }
    let numbers = words.iter().take(3).take_while(|w| digits(w)).count();
    let ends = [
        g.metric_end as i64,
        g.local_pref_end as i64,
        g.weight_end as i64,
    ];
    let mut best: Option<Fit> = None;
    for layout in NUMBER_LAYOUTS {
        let count = layout.len();
        if count > numbers {
            continue;
        }
        let mut shifts: Vec<i64> = layout
            .iter()
            .enumerate()
            .map(|(i, col)| spans[i].1 - ends[*col])
            .collect();
        let after = if count < spans.len() {
            spans[count].0
        } else {
            rest[rest.len() - 1].0 as i64
        };
        shifts.push(after - g.path as i64);
        if shifts[0] < 0 || shifts.windows(2).any(|w| w[1] < w[0]) {
            continue;
        }
        let spread = shifts[shifts.len() - 1] - shifts[0];
        if spread > MAX_SPREAD {
            continue;
        }
        let score = (spread, shifts[0]);
        if best.as_ref().is_none_or(|b| score < b.0) {
            best = Some((score, layout, shifts));
        }
    }
    let (_, layout, shifts) = best?;
    let mut values: [String; 3] = Default::default();
    for (i, col) in layout.iter().enumerate() {
        values[*col] = words[i].to_string();
    }
    let offset = (shifts[shifts.len() - 1] == shifts[0] && shifts[0] <= MAX_OFFSET)
        .then(|| usize::try_from(shifts[0]).unwrap_or(0));
    Some((
        Fields {
            network,
            next_hop,
            numbers: values,
            as_path: words[layout.len()..].join(" "),
            origin,
        },
        offset,
    ))
}

/// One line of the IOS-XR table `Network  Next Hop  From  AS Path`, from
/// column 0.
fn from_row(line: &str) -> Option<(String, String, String, char)> {
    if line.is_empty() || line.starts_with(' ') {
        return None;
    }
    let t: Vec<&str> = line.split_whitespace().collect();
    if t.len() < 4 {
        return None;
    }
    let (words, origin) = split_origin(&t[3..])?;
    if !network_ok(t[0]) || !next_hop_ok(t[1]) {
        return None;
    }
    Some((classful(t[0]), t[1].to_string(), words.join(" "), origin))
}

fn number(s: &str) -> Option<u32> {
    if s.is_empty() { None } else { s.parse().ok() }
}

/// The text of `line` from `a` to `b` inclusive, empty when out of range.
fn cut(line: &str, a: usize, b: usize) -> &str {
    let end = (b + 1).min(line.len());
    if a >= end { "" } else { &line[a..end] }
}

fn byte(line: &str, i: usize) -> u8 {
    line.as_bytes().get(i).copied().unwrap_or(0)
}

/// Each path row of one answer, in order. No line before the first header
/// line is a row. A standard header sets the columns. A row is read by
/// position when it fits the columns of the header, or the columns at the
/// offset that a row read by its tokens set; each other line is read by
/// its tokens.
pub fn path_rows(text: &str) -> Vec<Row> {
    let mut out = Vec::new();
    let (mut table, mut from_table) = (false, false);
    let mut g = Geometry::default();
    let mut cur = Geometry::default();
    let mut carried: Option<(String, u32)> = None;
    let mut pending: Option<String> = None;
    for (i, line) in text.lines().enumerate() {
        let no = u32::try_from(i + 1).unwrap_or(u32::MAX);
        if !line.is_ascii() {
            carried = None;
            pending = None;
            continue;
        }
        if line.contains("Network") {
            if let Some(h) = header(line) {
                table = true;
                from_table = false;
                g = h;
                cur = h;
                carried = None;
                pending = None;
                continue;
            }
            if from_header(line) {
                table = false;
                from_table = true;
                carried = None;
                pending = None;
                continue;
            }
        }
        if from_table {
            if let Some((network, next_hop, as_path, origin)) = from_row(line) {
                out.push(Row {
                    status: None,
                    network,
                    next_hop,
                    metric: None,
                    local_pref: None,
                    weight: None,
                    as_path,
                    origin,
                    lines: (no, no),
                });
            }
            continue;
        }
        if !table {
            continue;
        }
        let status_area = cut(line, 0, g.n.saturating_sub(1));
        let status_area = if g.n == 0 { "" } else { status_area };
        if !status_area.chars().all(|c| STATUS_CHARS.contains(c)) {
            carried = None;
            pending = None;
            continue;
        }
        let metric = cur.metric_end + 1 - METRIC_WIDTH.min(cur.metric_end + 1);
        let mut fields: Option<Fields> = None;
        if line.len() > cur.path
            && cur.hop >= 1
            && metric >= 1
            && byte(line, cur.hop - 1) == b' '
            && byte(line, metric - 1) == b' '
            && byte(line, cur.metric_end + 1) == b' '
            && byte(line, cur.local_pref_end + 1) == b' '
            && byte(line, cur.weight_end + 1) == b' '
            && byte(line, cur.path) != b' '
            && cut(line, cur.weight_end + 2, cur.path.saturating_sub(1))
                .trim()
                .is_empty()
        {
            let tail = line[cur.path..].trim_end();
            let origin = tail.chars().last().unwrap_or(' ');
            let weight = cut(line, cur.local_pref_end + 2, cur.weight_end).trim_start();
            let metric_text = cut(line, metric, cur.metric_end).trim_start();
            let local_pref = cut(line, cur.metric_end + 2, cur.local_pref_end).trim_start();
            let network = cut(line, g.n, cur.hop - 1).trim();
            let next_hop = cut(line, cur.hop, metric - 1).trim();
            let spaced = tail.len() == 1 || tail.as_bytes()[tail.len() - 2] == b' ';
            if matches!(origin, 'i' | 'e' | '?')
                && spaced
                && digits(weight)
                && (metric_text.is_empty() || digits(metric_text))
                && (local_pref.is_empty() || digits(local_pref))
                && (network.is_empty() || network_ok(network))
                && !next_hop.is_empty()
                && next_hop_ok(next_hop)
            {
                let as_path = tail[..tail.len() - 1]
                    .split_whitespace()
                    .collect::<Vec<_>>();
                fields = Some(Fields {
                    network: network.to_string(),
                    next_hop: next_hop.to_string(),
                    numbers: [
                        metric_text.to_string(),
                        local_pref.to_string(),
                        weight.to_string(),
                    ],
                    as_path: as_path.join(" "),
                    origin,
                });
            }
        }
        let f = match fields {
            Some(f) => f,
            None => {
                let Some((f, offset)) = by_tokens(line, &g) else {
                    carried = None;
                    pending = None;
                    continue;
                };
                if let Some(o) = offset {
                    cur = Geometry {
                        n: g.n,
                        hop: g.hop + o,
                        metric_end: g.metric_end + o,
                        local_pref_end: g.local_pref_end + o,
                        weight_end: g.weight_end + o,
                        path: g.path + o,
                    };
                }
                if f.next_hop.is_empty() {
                    if !network_ok(&f.network) {
                        carried = None;
                        pending = None;
                        continue;
                    }
                    carried = Some((classful(&f.network), no));
                    pending = Some(status_area.replace(' ', ""));
                    continue;
                }
                if (!f.network.is_empty() && !network_ok(&f.network)) || !next_hop_ok(&f.next_hop) {
                    carried = None;
                    pending = None;
                    continue;
                }
                f
            }
        };
        let mut status = status_area.replace(' ', "");
        let first = if !f.network.is_empty() {
            carried = Some((classful(&f.network), no));
            no
        } else {
            match &carried {
                None => {
                    pending = None;
                    continue;
                }
                Some((_, l)) => {
                    if let Some(p) = &pending
                        && status.is_empty()
                    {
                        status.clone_from(p);
                    }
                    if pending.is_some() { *l } else { no }
                }
            }
        };
        pending = None;
        let network = carried.as_ref().map(|c| c.0.clone()).unwrap_or_default();
        out.push(Row {
            status: Some(status),
            network,
            next_hop: f.next_hop,
            metric: number(&f.numbers[0]),
            local_pref: number(&f.numbers[1]),
            weight: number(&f.numbers[2]),
            as_path: f.as_path,
            origin: f.origin,
            lines: (first, no),
        });
    }
    out
}

/// The header line of the IOS-XE tables.
#[cfg(test)]
pub(crate) const HEADER: &str =
    "     Network          Next Hop            Metric LocPrf Weight Path";

/// A row of the IOS-XE layout of [`HEADER`].
#[cfg(test)]
pub(crate) fn print_row(
    status: &str,
    network: &str,
    hop: &str,
    m: &str,
    lp: &str,
    w: &str,
    path: &str,
) -> String {
    let mut net = format!("{status:<5}{network}");
    if net.len() > 21 {
        net.push('\n');
        net.push_str(&" ".repeat(22));
    } else {
        net = format!("{net:<22}");
    }
    format!("{net}{hop:<16}{m:>10}{lp:>7}{w:>7} {path}")
}

#[cfg(test)]
mod tests {
    use super::print_row as row;
    use super::*;

    #[test]
    fn the_rows_of_a_table_with_a_wrapped_network_and_a_second_path() {
        let text = [
            "BGP table version is 14, local router ID is 192.0.2.1".to_string(),
            "Status codes: s suppressed, d damped, h history, * valid, > best, i - internal".into(),
            String::new(),
            HEADER.into(),
            row(" *>", "10.0.0.0", "192.0.2.2", "0", "", "0", "64500 ?"),
            row(" *>i", "198.51.100.0/24", "10.0.0.3", "0", "100", "0", "i"),
            row(" *mi", "", "10.0.0.4", "0", "100", "0", "i"),
            row(
                " *>",
                "100.100.100.128/25",
                "192.0.2.2",
                "0",
                "",
                "0",
                "64500 64511 i",
            ),
            String::new(),
            "Total number of prefixes 3".into(),
        ]
        .join("\n");
        let rows = path_rows(&text);
        let short: Vec<(String, String, String, String)> = rows
            .iter()
            .map(|r| {
                (
                    r.status.clone().unwrap(),
                    r.network.clone(),
                    r.next_hop.clone(),
                    r.as_path.clone(),
                )
            })
            .collect();
        assert_eq!(
            short,
            [
                (
                    "*>".into(),
                    "10.0.0.0/8".into(),
                    "192.0.2.2".into(),
                    "64500".into()
                ),
                (
                    "*>i".into(),
                    "198.51.100.0/24".into(),
                    "10.0.0.3".into(),
                    String::new()
                ),
                (
                    "*mi".into(),
                    "198.51.100.0/24".into(),
                    "10.0.0.4".into(),
                    String::new()
                ),
                (
                    "*>".into(),
                    "100.100.100.128/25".into(),
                    "192.0.2.2".into(),
                    "64500 64511".into()
                ),
            ]
        );
        assert_eq!(rows[1].local_pref, Some(100));
        assert_eq!(rows[0].local_pref, None);
        assert_eq!(rows[0].origin, '?');
        assert_eq!(rows[3].lines, (8, 9));
    }

    #[test]
    fn a_row_one_column_right_of_the_header_is_read_by_its_tokens() {
        let text = format!(
            "{HEADER}\n{}",
            " ".to_string() + &row(" *>", "10.1.0.0/16", "192.0.2.9", "5", "", "0", "64501 i")
        );
        let rows = path_rows(&text);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].metric, Some(5));
        assert_eq!(rows[0].weight, Some(0));
        assert_eq!(rows[0].as_path, "64501");
    }

    #[test]
    fn the_ios_xr_table_of_the_advertised_routes() {
        let text = "Network            Next Hop        From            AS Path\n\
                    10.1.0.0/16        192.0.2.1       Local           i\n\
                    198.51.100.0/24    192.0.2.1       192.0.2.5       64510 64511?\n\
                    \n\
                    Processed 2 prefixes, 2 paths\n";
        let rows = path_rows(text);
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[1].as_path, "64510 64511");
        assert_eq!(rows[1].origin, '?');
        assert_eq!(rows[0].status, None);
    }

    #[test]
    fn a_line_that_is_not_a_row_gives_no_row_and_ends_the_carry() {
        let text = format!(
            "{HEADER}\n{}\nRoute Distinguisher: 64500:1\n{}",
            row(" *>", "10.2.0.0/16", "192.0.2.2", "0", "", "0", "i"),
            row(" *", "", "192.0.2.3", "0", "", "0", "i"),
        );
        let rows = path_rows(&text);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert!(holds_path_rows(" *>  10.2.0.0/16  192.0.2.2"));
        assert!(!holds_path_rows("Total number of prefixes 0"));
    }

    /// A generator of the test, with no dependency: a linear congruential
    /// generator with a fixed seed.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self, n: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) % n
        }
    }

    /// The status, the network, the next hop, the metric, the local
    /// preference, the weight, the AS path and the origin of a row.
    type Want = (
        String,
        String,
        String,
        Option<u32>,
        Option<u32>,
        u32,
        String,
        char,
    );

    #[test]
    fn random_tables_read_back_as_they_are_printed() {
        let mut r = Lcg(0x5eed);
        for _ in 0..200 {
            let mut want: Vec<Want> = Vec::new();
            let mut lines = vec![HEADER.to_string()];
            for k in 0..(1 + r.next(6)) {
                let len = [8, 16, 24, 25, 28, 32][r.next(6) as usize];
                let network = format!(
                    "{}.{}.{}.{}/{len}",
                    [10, 100, 172, 198, 203][r.next(5) as usize],
                    r.next(256),
                    r.next(256),
                    r.next(256)
                );
                for p in 0..(1 + r.next(3)) {
                    let hop = format!("192.0.2.{}", 1 + r.next(254));
                    let metric = (r.next(2) == 0).then(|| r.next(100_000) as u32);
                    let lp = (r.next(2) == 0).then(|| r.next(1000) as u32);
                    let weight = if r.next(3) == 0 { 32_768 } else { 0 };
                    let path: Vec<String> = (0..r.next(4))
                        .map(|_| (64_496 + r.next(16)).to_string())
                        .collect();
                    let origin = ['i', 'e', '?'][r.next(3) as usize];
                    let status = if p == 0 { " *>" } else { " *" };
                    let path_text = if path.is_empty() {
                        origin.to_string()
                    } else {
                        format!("{} {origin}", path.join(" "))
                    };
                    lines.push(row(
                        status,
                        if p == 0 { &network } else { "" },
                        &hop,
                        &metric.map(|m| m.to_string()).unwrap_or_default(),
                        &lp.map(|m| m.to_string()).unwrap_or_default(),
                        &weight.to_string(),
                        &path_text,
                    ));
                    want.push((
                        status.trim().to_string(),
                        network.clone(),
                        hop,
                        metric,
                        lp,
                        weight,
                        path.join(" "),
                        origin,
                    ));
                }
                if k % 3 == 2 {
                    lines.push(String::new());
                    lines.push(HEADER.to_string());
                }
            }
            let text = lines.join("\n");
            let got: Vec<Want> = path_rows(&text)
                .into_iter()
                .map(|x| {
                    (
                        x.status.unwrap_or_default(),
                        x.network,
                        x.next_hop,
                        x.metric,
                        x.local_pref,
                        x.weight.unwrap_or(u32::MAX),
                        x.as_path,
                        x.origin,
                    )
                })
                .collect();
            assert_eq!(got, want, "{text}");
        }
    }
}
