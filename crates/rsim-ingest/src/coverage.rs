//! The classification of stanzas and the coverage report.

use std::collections::BTreeMap;

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

/// An entry of a classification table. The path is a list of keys, separated
/// by `/`. The segment `*` matches each key, for example the name of an
/// interface or the number of a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: &'static str,
    pub state: State,
    pub reach: Reach,
}

/// A classification table. For each stanza, the entry with the longest path
/// that matches the stanza decides. A stanza with no entry is unhandled.
#[derive(Clone, Debug)]
pub struct Table {
    entries: Vec<(Vec<String>, State, Reach)>,
}

impl Table {
    pub fn new(entries: &[Entry]) -> Table {
        let mut t = Table {
            entries: Vec::with_capacity(entries.len()),
        };
        for e in entries {
            t.push(e.path, e.state, e.reach);
        }
        t
    }

    /// Adds an entry.
    pub fn push(&mut self, path: &str, state: State, reach: Reach) {
        self.entries
            .push((path.split('/').map(str::to_string).collect(), state, reach));
    }

    /// The state of the stanza at `path`.
    pub fn state(&self, path: &[&str]) -> State {
        let mut best: Option<(usize, usize, State)> = None;
        for (pattern, state, reach) in &self.entries {
            let fits = match reach {
                Reach::Node => pattern.len() == path.len(),
                Reach::Subtree => pattern.len() <= path.len(),
            };
            if !fits || !pattern.iter().zip(path).all(|(p, k)| p == "*" || p == k) {
                continue;
            }
            let exact = pattern.iter().filter(|p| *p != "*").count();
            let rank = (pattern.len(), exact);
            if best.is_none_or(|(l, e, _)| rank > (l, e)) {
                best = Some((rank.0, rank.1, *state));
            }
        }
        best.map_or(State::Unhandled, |b| b.2)
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

/// The path with `*` in place of each key that is a number or that only a
/// `*` of the table can match.
fn generalize(path: &[&str], table: &Table) -> String {
    let named: std::collections::BTreeSet<(usize, &str)> = table
        .entries
        .iter()
        .flat_map(|(p, _, _)| p.iter().enumerate().map(|(i, k)| (i, k.as_str())))
        .filter(|(_, k)| *k != "*")
        .collect();
    path.iter()
        .enumerate()
        .map(|(i, k)| {
            if named.contains(&(i, k)) || !table_has_star_at(table, path, i) {
                (*k).to_string()
            } else {
                "*".to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// True if an entry of the table with the same keys before `i` has `*` at
/// `i`.
fn table_has_star_at(table: &Table, path: &[&str], i: usize) -> bool {
    table.entries.iter().any(|(p, _, _)| {
        p.len() > i && p[i] == "*" && p[..i].iter().zip(path).all(|(a, b)| a == "*" || a == b)
    })
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
