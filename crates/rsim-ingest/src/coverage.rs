//! The classification of stanzas and the coverage report.

use std::collections::{BTreeMap, BTreeSet};

use crate::stanza::{Document, Stanza};

/// The state of a stanza.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum State {
    /// A handler reads the stanza.
    Handled,
    /// The stanza has no effect on the twin.
    Irrelevant,
    /// No handler reads the stanza. The functions that it can change give
    /// `Unknown`.
    Unhandled,
}

/// How far an entry of a classification table reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// The stanza and all stanzas below it.
    Subtree,
    /// The stanza only. Each child needs its own entry.
    Node,
}

/// An entry of a classification table. The path is a list of segments,
/// separated by `/`, one for each level. A segment matches a key:
///
/// - `*` matches each key, for example the name of an interface or the
///   number of a rule.
/// - A segment with a space, or that ends with `..`, is a word pattern for
///   the line of an indented config. Its words match the words of the key in
///   order: `*` matches 1 word, a literal matches the same word, and a final
///   `..` matches the rest of the words, also none. Example:
///   `interface */ip address ..`.
/// - Each other segment matches the same key.
///
/// A segment cannot hold `/`. [`Table::push_levels`] takes the segments as
/// a list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: &'static str,
    pub state: State,
    pub reach: Reach,
}

/// A check of the key of a stanza.
pub type Check = fn(&str) -> bool;

/// A classification table. For each stanza, the entry with the longest path
/// that matches the stanza decides. A stanza with no entry is unhandled. An
/// entry with a check matches only a stanza whose key passes the check.
///
/// The mask of a table changes each key that a report prints in full, for
/// example to hide a secret.
#[derive(Clone, Debug)]
pub struct Table {
    entries: Vec<(Vec<String>, State, Reach, Option<Check>)>,
    mask: Option<fn(&str) -> String>,
}

impl Table {
    pub fn new(entries: &[Entry]) -> Table {
        let mut t = Table {
            entries: Vec::with_capacity(entries.len()),
            mask: None,
        };
        for e in entries {
            t.push(e.path, e.state, e.reach);
        }
        t
    }

    /// Sets the mask of the keys that a report prints in full.
    pub fn with_mask(mut self, mask: fn(&str) -> String) -> Table {
        self.mask = Some(mask);
        self
    }

    /// The report form of a key: the key through the mask of the table.
    pub fn report_key(&self, key: &str) -> String {
        match self.mask {
            Some(m) => m(key),
            None => key.to_string(),
        }
    }

    /// Adds an entry.
    pub fn push(&mut self, path: &str, state: State, reach: Reach) {
        self.entries.push((
            path.split('/').map(str::to_string).collect(),
            state,
            reach,
            None,
        ));
    }

    /// Adds an entry with its segments as a list.
    pub fn push_levels(&mut self, levels: &[&str], state: State, reach: Reach) {
        self.entries.push((
            levels.iter().map(|l| (*l).to_string()).collect(),
            state,
            reach,
            None,
        ));
    }

    /// Adds an entry with its segments as a list. The entry matches only a
    /// stanza whose key at the last segment gives true from `check`.
    pub fn push_checked(&mut self, levels: &[&str], state: State, reach: Reach, check: Check) {
        self.entries.push((
            levels.iter().map(|l| (*l).to_string()).collect(),
            state,
            reach,
            Some(check),
        ));
    }

    /// The state of the stanza at `path`.
    pub fn state(&self, path: &[&str]) -> State {
        let mut best: Option<(usize, usize, State)> = None;
        for (pattern, state, reach, check) in &self.entries {
            let fits = match reach {
                Reach::Node => pattern.len() == path.len(),
                Reach::Subtree => pattern.len() <= path.len(),
            };
            if !fits || !pattern.iter().zip(path).all(|(p, k)| matches(p, k)) {
                continue;
            }
            if check.is_some_and(|c| !c(path[pattern.len() - 1])) {
                continue;
            }
            let exact = pattern.iter().map(|p| literal_words(p)).sum();
            let rank = (pattern.len(), exact);
            if best.is_none_or(|(l, e, _)| rank > (l, e)) {
                best = Some((rank.0, rank.1, *state));
            }
        }
        best.map_or(State::Unhandled, |b| b.2)
    }
}

/// True if the segment of an entry matches a key.
fn matches(segment: &str, key: &str) -> bool {
    if segment == "*" || segment == key {
        return true;
    }
    if !is_words(segment) {
        return false;
    }
    let mut keys = key.split_whitespace();
    let mut words = segment.split_whitespace().peekable();
    while let Some(w) = words.next() {
        if w == ".." && words.peek().is_none() {
            return true;
        }
        match keys.next() {
            Some(k) if w == "*" || w == k => {}
            _ => return false,
        }
    }
    keys.next().is_none()
}

/// True if a segment is a word pattern.
fn is_words(segment: &str) -> bool {
    segment.contains(' ') || segment.ends_with("..")
}

/// The number of literal words of a segment. A more literal entry wins over
/// a less literal entry of the same length.
fn literal_words(segment: &str) -> usize {
    if is_words(segment) {
        segment
            .split_whitespace()
            .filter(|w| *w != "*" && *w != "..")
            .count()
    } else {
        usize::from(segment != "*")
    }
}

/// The coverage of one section.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Coverage {
    /// The lines of each state. The first and the last line of the root are
    /// not counted.
    pub lines: BTreeMap<State, u32>,
    /// The paths of the unhandled stanzas with the number of stanzas and
    /// lines of each. A path has `*` in place of each key that a `*` of the
    /// table matches.
    pub unhandled: BTreeMap<String, (u32, u32)>,
}

impl Coverage {
    /// The share of the lines in a state, from 0 to 1.
    pub fn share(&self, state: State) -> f64 {
        let total: u32 = self.lines.values().sum();
        if total == 0 {
            return 1.0;
        }
        f64::from(self.lines.get(&state).copied().unwrap_or(0)) / f64::from(total)
    }

    /// The unhandled paths, the most frequent first, then by path.
    pub fn ranked(&self) -> Vec<(&str, u32, u32)> {
        let mut v: Vec<(&str, u32, u32)> = self
            .unhandled
            .iter()
            .map(|(p, (n, l))| (p.as_str(), *n, *l))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)).then(a.0.cmp(b.0)));
        v
    }
}

/// Classifies each stanza of a document.
///
/// Each line belongs to the deepest stanza that contains it. An unhandled
/// stanza is reported once, at the top of its unhandled part.
pub fn classify(doc: &Document, table: &Table) -> Coverage {
    let mut cov = Coverage::default();
    let mut path = Vec::new();
    for child in doc.root.children() {
        walk(child, table, &mut path, &mut cov, false);
    }
    cov
}

fn walk<'a>(
    s: &'a Stanza,
    table: &Table,
    path: &mut Vec<&'a str>,
    cov: &mut Coverage,
    inside_unhandled: bool,
) {
    path.push(&s.key);
    let state = table.state(path);
    if state == State::Unhandled && !inside_unhandled {
        let pattern = generalize(path, table);
        let e = cov.unhandled.entry(pattern).or_default();
        e.0 += 1;
        e.1 += s.last_line - s.first_line + 1;
    }
    let child_lines: u32 = s
        .children()
        .iter()
        .map(|c| c.last_line - c.first_line + 1)
        .sum();
    let own = s.last_line - s.first_line + 1 - child_lines;
    *cov.lines.entry(state).or_default() += own;
    for c in s.children() {
        walk(c, table, path, cov, state == State::Unhandled);
    }
    path.pop();
}

/// The path of an unhandled stanza for the report. At each level, the
/// most literal segment of the table that matches the key with the same
/// levels before it takes the place of the key, so that `*` stands for each
/// name and number. The last segment of an entry with a check matches only
/// a key that passes the check. A level that no segment matches keeps its
/// key.
fn generalize(path: &[&str], table: &Table) -> String {
    let mut out: Vec<String> = Vec::with_capacity(path.len());
    for (i, key) in path.iter().enumerate() {
        let best = table
            .entries
            .iter()
            .filter(|(p, _, _, check)| {
                p.len() > i
                    && matches(&p[i], key)
                    && p[..i].iter().zip(path).all(|(a, b)| matches(a, b))
                    && (p.len() > i + 1 || check.is_none_or(|c| c(key)))
            })
            .map(|(p, _, _, _)| &p[i])
            .max_by_key(|seg| (literal_words(seg), std::cmp::Reverse(seg.as_str())));
        out.push(match best {
            Some(seg) if seg == "*" || is_words(seg) => seg.clone(),
            _ => table.report_key(key),
        });
    }
    out.join("/")
}

/// The paths of the handled stanzas that no handler read, each key through
/// the mask of the table. `read` holds the first line of each stanza that a
/// handler read. A correct handler set gives an empty list.
pub fn unread(doc: &Document, table: &Table, read: &BTreeSet<u32>) -> Vec<String> {
    let mut out = Vec::new();
    let mut path = Vec::new();
    for c in doc.root.children() {
        unread_walk(c, table, read, &mut path, &mut out);
    }
    out
}

fn unread_walk<'a>(
    s: &'a Stanza,
    table: &Table,
    read: &BTreeSet<u32>,
    path: &mut Vec<&'a str>,
    out: &mut Vec<String>,
) {
    path.push(&s.key);
    let state = table.state(path);
    if state == State::Handled && !read.contains(&s.first_line) {
        let keys: Vec<String> = path.iter().map(|k| table.report_key(k)).collect();
        out.push(keys.join("/"));
    }
    if state != State::Unhandled {
        for c in s.children() {
            unread_walk(c, table, read, path, out);
        }
    }
    path.pop();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stanza::read_json;
    use Reach::{Node, Subtree};
    use State::{Handled, Irrelevant, Unhandled};

    const fn e(path: &'static str, state: State, reach: Reach) -> Entry {
        Entry { path, state, reach }
    }

    fn table() -> Table {
        Table::new(&[
            e("firewall/ipv4/name/*", Handled, Node),
            e("firewall/ipv4/name/*/default-action", Handled, Subtree),
            e("firewall/ipv4/name/*/rule", Handled, Node),
            e("firewall/ipv4/name/*/rule/*", Handled, Node),
            e("firewall/ipv4/name/*/rule/*/action", Handled, Subtree),
            e("firewall/ipv4/name/*/rule/*/source", Handled, Subtree),
            e("service", Irrelevant, Subtree),
            e("firewall", Handled, Node),
            e("firewall/ipv4", Handled, Node),
            e("firewall/ipv4/name", Handled, Node),
        ])
    }

    #[test]
    fn the_longest_entry_decides_and_a_node_entry_does_not_reach_children() {
        let t = table();
        assert_eq!(t.state(&["firewall", "ipv4", "name", "IN"]), Handled);
        let rule = ["firewall", "ipv4", "name", "IN", "rule", "10"];
        assert_eq!(t.state(&rule), Handled);
        let mut opt = rule.to_vec();
        opt.push("log");
        assert_eq!(t.state(&opt), Unhandled);
        opt[6] = "source";
        opt.push("address");
        assert_eq!(t.state(&opt), Handled);
        assert_eq!(t.state(&["service", "ssh", "port"]), Irrelevant);
        assert_eq!(t.state(&["system"]), Unhandled);
    }

    #[test]
    fn word_patterns_match_the_lines_of_an_indented_config() {
        assert!(matches("interface *", "interface Ethernet1/1"));
        assert!(!matches("interface *", "interface Ethernet1/1 extra"));
        assert!(matches(
            "ip address ..",
            "ip address 192.0.2.1/24 secondary"
        ));
        assert!(matches("shutdown ..", "shutdown"));
        assert!(!matches("ip address ..", "ip route 0.0.0.0/0 192.0.2.9"));
        assert!(matches("feature", "feature"));
        let mut t = Table::new(&[
            e("feature *", Handled, Node),
            e("interface *", Handled, Node),
            e("interface */description ..", Irrelevant, Node),
            e("interface */ip ..", Unhandled, Subtree),
            e("interface */ip address ..", Handled, Node),
            e("line ..", Irrelevant, Subtree),
        ]);
        t.push_levels(
            &["interface mgmt0", "vrf member management"],
            Irrelevant,
            Node,
        );
        let doc = crate::stanza::read_indented(
            "feature ospf\nfeature bfd\ninterface Ethernet1/1\n  description up\n  ip address 192.0.2.1/24\n  ip ospf cost 10\n  service-policy input Q1\ninterface Ethernet1/2\n  service-policy input Q2\ninterface mgmt0\n  vrf member management\nline vty\n  exec-timeout 5\nhostname n1\n",
        );
        assert_eq!(
            t.state(&["interface Ethernet1/1", "ip address 192.0.2.1/24"]),
            Handled
        );
        assert_eq!(
            t.state(&["interface Ethernet1/1", "ip ospf cost 10"]),
            Unhandled
        );
        assert_eq!(
            t.state(&["interface mgmt0", "vrf member management"]),
            Irrelevant
        );
        let cov = classify(&doc, &t);
        assert_eq!(
            cov.ranked(),
            [
                ("hostname n1", 1, 1),
                ("interface */ip ..", 1, 1),
                ("interface */service-policy input Q1", 1, 1),
                ("interface */service-policy input Q2", 1, 1),
            ]
        );
        assert_eq!(cov.lines[&Irrelevant], 4);
        assert_eq!(cov.lines.values().sum::<u32>(), doc.lines);
    }

    #[test]
    fn an_entry_with_a_check_matches_only_a_key_that_passes_the_check() {
        let mut t = Table::new(&[e("router ..", Irrelevant, Subtree)]);
        t.push_checked(&["router ..", "cost *"], Handled, Subtree, |k| {
            k != "cost 0"
        });
        assert_eq!(t.state(&["router 1", "cost 5"]), Handled);
        assert_eq!(t.state(&["router 1", "cost 0"]), Irrelevant);
        assert_eq!(generalize(&["router 1", "cost 0"], &t), "router ../cost 0");
        assert_eq!(generalize(&["router 1", "cost 5"], &t), "router ../cost *");
    }

    #[test]
    fn the_coverage_counts_each_line_once() {
        let doc = read_json(
            br#"{"firewall": {"ipv4": {"name": {"IN": {"default-action": "drop",
                "rule": {"10": {"action": "accept", "log": {}, "state": ["established"]},
                         "20": {"action": "drop", "log": {}}}}}}},
                "service": {"ssh": {"port": "22"}}}"#,
        )
        .unwrap();
        let cov = classify(&doc, &table());
        let total: u32 = cov.lines.values().sum();
        assert_eq!(total + 2, doc.lines);
        assert_eq!(cov.lines[&Irrelevant], 5);
        let ranked = cov.ranked();
        assert_eq!(ranked[0], ("firewall/ipv4/name/*/rule/*/log", 2, 2));
        assert_eq!(ranked[1], ("firewall/ipv4/name/*/rule/*/state", 1, 3));
        assert_eq!(cov.lines[&Unhandled], 5);
        assert!(cov.share(Handled) > 0.5);
    }
}
