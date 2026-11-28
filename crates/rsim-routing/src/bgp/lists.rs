//! Prefix lists, prefix sets, community lists and AS-path lists.
//!
//! Each list is walked in ascending sequence number, the action of the
//! first line that matches is the result, and a route that no line matches
//! is denied. A line with an unhandled construct has an unknown match. A
//! list result is `None` when it depends on an unknown match: the result
//! with the line matching differs from the result with the line not
//! matching.

use std::collections::BTreeSet;

use rsim_core::Prefix;

use super::pattern::Pattern;
use super::{AsPath, Asn, Community};

/// A numeric comparison of a match term or a list line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cmp {
    Eq,
    Ge,
    Le,
}

impl Cmp {
    /// True if `actual` compares to `value` by the operator.
    pub fn holds(self, actual: u32, value: u32) -> bool {
        match self {
            Cmp::Eq => actual == value,
            Cmp::Ge => actual >= value,
            Cmp::Le => actual <= value,
        }
    }
}

/// The result of the first matching line of `lines`, each line as its
/// action and its match. `None` if an unknown match decides the result.
fn first_match(lines: impl Iterator<Item = (bool, Option<bool>)> + Clone) -> Option<bool> {
    let mut rest = lines;
    loop {
        let Some((permit, matched)) = rest.next() else {
            return Some(false);
        };
        match matched {
            Some(true) => return Some(permit),
            Some(false) => {}
            None => {
                let without = first_match(rest);
                return if without == Some(permit) {
                    without
                } else {
                    None
                };
            }
        }
    }
}

/// One line of a prefix list with its resolved length range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrefixListEntry {
    pub seq: u32,
    pub permit: bool,
    pub prefix: Prefix,
    pub min_len: u8,
    pub max_len: u8,
}

impl PrefixListEntry {
    /// A line from its vendor qualifiers. With no qualifier the range is
    /// the length of the prefix. `ge` alone runs to 32 for IPv4 and 128 for
    /// IPv6. `le` alone starts at the length of the prefix. `eq` overrides
    /// `ge` and `le`.
    pub fn new(
        seq: u32,
        permit: bool,
        prefix: Prefix,
        ge: Option<u8>,
        le: Option<u8>,
        eq: Option<u8>,
    ) -> PrefixListEntry {
        let max = if prefix.is_ipv4() { 32 } else { 128 };
        let base = prefix.len();
        let (mut lo, mut hi) = (base, base);
        if let Some(ge) = ge {
            (lo, hi) = (ge, max);
        }
        if let Some(le) = le {
            hi = le;
        }
        if let Some(eq) = eq {
            (lo, hi) = (eq, eq);
        }
        PrefixListEntry {
            seq,
            permit,
            prefix,
            min_len: lo,
            max_len: hi,
        }
    }

    /// True if the first bits of `candidate` are the prefix of the line and
    /// its length is in the range. A line of the other address family
    /// matches nothing.
    pub fn matches(&self, candidate: Prefix) -> bool {
        candidate.is_ipv4() == self.prefix.is_ipv4()
            && candidate.len() >= self.prefix.len()
            && self.prefix.contains(candidate.addr())
            && (self.min_len..=self.max_len).contains(&candidate.len())
    }
}

/// A prefix list, or an IOS-XR prefix set as a list of permit lines.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrefixList {
    /// The lines in ascending sequence number.
    pub entries: Vec<PrefixListEntry>,
}

impl PrefixList {
    pub fn new(mut entries: Vec<PrefixListEntry>) -> PrefixList {
        entries.sort_by_key(|e| e.seq);
        PrefixList { entries }
    }

    /// A prefix set: each element is a prefix with its length range.
    pub fn set(elements: &[(Prefix, u8, u8)]) -> PrefixList {
        PrefixList {
            entries: elements
                .iter()
                .enumerate()
                .map(|(i, &(prefix, min_len, max_len))| PrefixListEntry {
                    seq: i as u32,
                    permit: true,
                    prefix,
                    min_len,
                    max_len,
                })
                .collect(),
        }
    }

    /// True if the list permits `candidate`.
    pub fn permits(&self, candidate: Prefix) -> bool {
        self.entries
            .iter()
            .find(|e| e.matches(candidate))
            .is_some_and(|e| e.permit)
    }
}

/// One half of an IOS-XR community wildcard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Half {
    Any,
    Value(u16),
    Range(u16, u16),
}

impl Half {
    fn matches(self, v: u16) -> bool {
        match self {
            Half::Any => true,
            Half::Value(x) => x == v,
            Half::Range(lo, hi) => lo <= v && v <= hi,
        }
    }
}

/// The match of one community list line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommunityTerm {
    /// A standard line: the route holds each of the communities.
    All(Vec<Community>),
    /// `internet`: each route.
    Internet,
    /// An expanded line: the pattern matches the communities of the route
    /// in ascending order, joined by a space.
    Expanded(Pattern),
    /// An IOS-XR wildcard: one community of the route matches both halves.
    Wildcard(Half, Half),
    /// A line with an unhandled construct, with its text.
    Unhandled(String),
}

/// One line of a community list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommunityLine {
    pub seq: u32,
    pub permit: bool,
    pub term: CommunityTerm,
}

impl CommunityLine {
    /// An expanded line. A pattern outside the subset of
    /// [`Pattern`] gives an unhandled line.
    pub fn expanded(seq: u32, permit: bool, text: &str) -> CommunityLine {
        let term = match Pattern::parse(text) {
            Ok(p) => CommunityTerm::Expanded(p),
            Err(_) => CommunityTerm::Unhandled(text.to_string()),
        };
        CommunityLine { seq, permit, term }
    }

    /// The match of the line on a set of communities, `None` if unknown.
    pub fn matches(&self, held: &BTreeSet<Community>) -> Option<bool> {
        match &self.term {
            CommunityTerm::All(wanted) => {
                Some(!wanted.is_empty() && wanted.iter().all(|c| held.contains(c)))
            }
            CommunityTerm::Internet => Some(true),
            CommunityTerm::Expanded(p) => {
                let text = held
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                Some(p.is_match(&text))
            }
            CommunityTerm::Wildcard(high, low) => Some(
                held.iter()
                    .any(|c| high.matches((c.0 >> 16) as u16) && low.matches(c.0 as u16)),
            ),
            CommunityTerm::Unhandled(_) => None,
        }
    }
}

/// A community list, or an IOS-XR community set as a list of permit lines.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommunityList {
    /// The lines in ascending sequence number.
    pub lines: Vec<CommunityLine>,
}

impl CommunityList {
    pub fn new(mut lines: Vec<CommunityLine>) -> CommunityList {
        lines.sort_by_key(|l| l.seq);
        CommunityList { lines }
    }

    /// The result of the first matching line on the communities of a
    /// route.
    pub fn permits(&self, held: &BTreeSet<Community>) -> Option<bool> {
        first_match(self.lines.iter().map(|l| (l.permit, l.matches(held))))
    }

    /// The IOS-XR test `matches-every`: each line matches. A list with no
    /// line matches nothing.
    pub fn matches_every(&self, held: &BTreeSet<Community>) -> Option<bool> {
        if self.lines.is_empty() {
            return Some(false);
        }
        let mut unknown = false;
        for l in &self.lines {
            match l.matches(held) {
                Some(false) => return Some(false),
                None => unknown = true,
                Some(true) => {}
            }
        }
        if unknown { None } else { Some(true) }
    }

    /// True if a delete by this list removes `c`: the first line that
    /// matches `c` alone is a permit line.
    pub fn deletes(&self, c: Community) -> Option<bool> {
        self.permits(&BTreeSet::from([c]))
    }

    /// The text of each unhandled line.
    pub fn unhandled(&self) -> impl Iterator<Item = &str> {
        self.lines.iter().filter_map(|l| match &l.term {
            CommunityTerm::Unhandled(t) => Some(t.as_str()),
            _ => None,
        })
    }
}

/// The match of one AS-path list line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsPathTerm {
    /// The pattern matches the text form of the path (`AsPath` `Display`).
    Pattern(Pattern),
    /// The path starts with the ASNs.
    NeighborIs(Vec<Asn>),
    /// The path ends with the ASNs.
    OriginatesFrom(Vec<Asn>),
    /// The path holds the ASNs in a row.
    PassesThrough(Vec<Asn>),
    /// The decision length of the path compares to the number.
    Length(Cmp, u32),
    /// A line with an unhandled construct, with its text.
    Unhandled(String),
}

/// One line of an AS-path list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsPathLine {
    pub seq: u32,
    pub permit: bool,
    pub term: AsPathTerm,
}

impl AsPathLine {
    /// A pattern line. A pattern outside the subset of [`Pattern`] gives an
    /// unhandled line.
    pub fn regex(seq: u32, permit: bool, text: &str) -> AsPathLine {
        let term = match Pattern::parse(text) {
            Ok(p) => AsPathTerm::Pattern(p),
            Err(_) => AsPathTerm::Unhandled(text.to_string()),
        };
        AsPathLine { seq, permit, term }
    }

    /// The match of the line on a path, `None` if unknown.
    pub fn matches(&self, path: &AsPath) -> Option<bool> {
        let flat = || path.flat();
        let run_at = |asns: &[Asn], f: &[Asn], i: usize| f[i..].starts_with(asns);
        match &self.term {
            AsPathTerm::Pattern(p) => Some(p.is_match(&path.to_string())),
            AsPathTerm::NeighborIs(asns) => Some(!asns.is_empty() && flat().starts_with(asns)),
            AsPathTerm::OriginatesFrom(asns) => Some(!asns.is_empty() && flat().ends_with(asns)),
            AsPathTerm::PassesThrough(asns) => {
                let f = flat();
                Some(
                    !asns.is_empty()
                        && asns.len() <= f.len()
                        && (0..=f.len() - asns.len()).any(|i| run_at(asns, &f, i)),
                )
            }
            AsPathTerm::Length(cmp, n) => Some(cmp.holds(path.len(), *n)),
            AsPathTerm::Unhandled(_) => None,
        }
    }
}

/// An AS-path list, or an IOS-XR AS-path set as a list of permit lines.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AsPathList {
    /// The lines in ascending sequence number.
    pub lines: Vec<AsPathLine>,
}

impl AsPathList {
    pub fn new(mut lines: Vec<AsPathLine>) -> AsPathList {
        lines.sort_by_key(|l| l.seq);
        AsPathList { lines }
    }

    /// The result of the first matching line on a path.
    pub fn permits(&self, path: &AsPath) -> Option<bool> {
        first_match(self.lines.iter().map(|l| (l.permit, l.matches(path))))
    }
}
