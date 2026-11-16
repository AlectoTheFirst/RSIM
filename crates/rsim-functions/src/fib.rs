//! A forwarding table: a prefix trie with interned next-hop groups and
//! compact provenance.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use rsim_core::{
    AddrField, GroupPartition, PacketSet, Prefix, PrefixTable, SourceSpan, TriePrefixTable,
};

use crate::routing::{Route, RouteKind, RouteNextHop};

/// The forwarding result of a route: its kind and its next hops in the
/// fixed order of the alternatives. Routes with the same group forward the
/// same packets the same way.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NextHopGroup {
    pub kind: RouteKind,
    pub next_hops: Vec<RouteNextHop>,
}

const NONE: u32 = u32::MAX;

/// The provenance of a route: an interned file and a line range. A route
/// with more spans keeps the others in a side map.
#[derive(Clone, Copy, Debug)]
struct Span {
    file: u32,
    first: u32,
    last: u32,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    group: u32,
    span: Span,
}

/// The summary of a trie node: the number of entries in its subtree and
/// the group of each of them, if they all have one group.
#[derive(Clone, Copy, Debug)]
struct Summary {
    count: u32,
    uniform: u32,
}

/// A forwarding table. Each route holds the number of its next-hop group
/// and its provenance, so a full internet table stays small.
#[derive(Debug, Default)]
pub struct Fib {
    trie: TriePrefixTable<u32>,
    entries: Vec<Entry>,
    groups: Vec<NextHopGroup>,
    group_ids: BTreeMap<NextHopGroup, u32>,
    files: Vec<Arc<str>>,
    file_ids: BTreeMap<Arc<str>, u32>,
    extra_spans: BTreeMap<u32, Vec<SourceSpan>>,
    summary: OnceLock<BTreeMap<u32, Summary>>,
}

impl Clone for Fib {
    fn clone(&self) -> Self {
        Fib {
            trie: self.trie.clone(),
            entries: self.entries.clone(),
            groups: self.groups.clone(),
            group_ids: self.group_ids.clone(),
            files: self.files.clone(),
            file_ids: self.file_ids.clone(),
            extra_spans: self.extra_spans.clone(),
            summary: OnceLock::new(),
        }
    }
}

impl FromIterator<(Prefix, Route)> for Fib {
    fn from_iter<I: IntoIterator<Item = (Prefix, Route)>>(iter: I) -> Self {
        let mut f = Fib::new();
        for (p, r) in iter {
            f.insert(p, r);
        }
        f
    }
}

/// The routes of one group in a split of a packet set.
#[derive(Clone, Debug)]
pub struct GroupRoutes<'a> {
    pub group: &'a NextHopGroup,
    /// The number of routes that the packets of the group matched.
    pub count: usize,
    /// The first routes, in prefix order, at most the asked number.
    pub sample: Vec<Prefix>,
    /// The provenance of the routes of the sample.
    pub spans: Vec<SourceSpan>,
    pub packets: PacketSet,
}

impl Fib {
    pub fn new() -> Self {
        Fib::default()
    }

    fn intern_file(&mut self, file: &Arc<str>) -> u32 {
        if let Some(i) = self.file_ids.get(file) {
            return *i;
        }
        let i = u32::try_from(self.files.len()).expect("too many files");
        self.files.push(file.clone());
        self.file_ids.insert(file.clone(), i);
        i
    }

    fn intern_group(&mut self, g: NextHopGroup) -> u32 {
        if let Some(i) = self.group_ids.get(&g) {
            return *i;
        }
        let i = u32::try_from(self.groups.len()).expect("too many groups");
        self.groups.push(g.clone());
        self.group_ids.insert(g, i);
        i
    }

    /// Inserts a route. A route of the same prefix is replaced.
    pub fn insert(&mut self, prefix: Prefix, route: Route) {
        self.summary = OnceLock::new();
        let group = self.intern_group(NextHopGroup {
            kind: route.kind,
            next_hops: route.next_hops().to_vec(),
        });
        let mut spans = route.spans.into_iter();
        let span = match spans.next() {
            Some(s) => Span {
                file: self.intern_file(&s.file),
                first: s.first_line,
                last: s.last_line,
            },
            None => Span {
                file: NONE,
                first: 0,
                last: 0,
            },
        };
        let entry = Entry { group, span };
        let id = match self.trie.get(&prefix) {
            Some(i) => {
                self.entries[*i as usize] = entry;
                *i
            }
            None => {
                let i = u32::try_from(self.entries.len()).expect("too many routes");
                self.entries.push(entry);
                self.trie.insert(prefix, i);
                i
            }
        };
        let rest: Vec<SourceSpan> = spans.collect();
        if rest.is_empty() {
            self.extra_spans.remove(&id);
        } else {
            self.extra_spans.insert(id, rest);
        }
    }

    pub fn len(&self) -> usize {
        self.trie.len()
    }

    pub fn is_empty(&self) -> bool {
        self.trie.is_empty()
    }

    /// The next-hop groups, in the order of their first use.
    pub fn groups(&self) -> &[NextHopGroup] {
        &self.groups
    }

    fn spans_of(&self, id: u32) -> Vec<SourceSpan> {
        let e = self.entries[id as usize];
        let mut v = Vec::new();
        if e.span.file != NONE {
            v.push(SourceSpan {
                file: self.files[e.span.file as usize].clone(),
                first_line: e.span.first,
                last_line: e.span.last,
            });
        }
        if let Some(x) = self.extra_spans.get(&id) {
            v.extend(x.iter().cloned());
        }
        v
    }

    /// The route of exactly a prefix.
    pub fn get(&self, prefix: &Prefix) -> Option<Route> {
        let id = *self.trie.get(prefix)?;
        Some(self.route(id))
    }

    fn route(&self, id: u32) -> Route {
        let g = &self.groups[self.entries[id as usize].group as usize];
        Route::new(g.kind, g.next_hops.clone(), self.spans_of(id))
    }

    /// All routes in prefix order.
    pub fn entries(&self) -> Vec<(Prefix, Route)> {
        self.trie
            .entries()
            .into_iter()
            .map(|(p, id)| (p, self.route(*id)))
            .collect()
    }

    /// The bytes that the table holds, for the memory benchmark.
    pub fn heap_bytes(&self) -> usize {
        self.trie.heap_bytes()
            + self.entries.capacity() * std::mem::size_of::<Entry>()
            + self
                .groups
                .iter()
                .map(|g| g.next_hops.capacity() * 64)
                .sum::<usize>()
    }

    fn summary(&self) -> &BTreeMap<u32, Summary> {
        self.summary.get_or_init(|| {
            let mut out = BTreeMap::new();
            for v6 in [false, true] {
                if let Some(r) = self.trie.walk_root(v6) {
                    self.summarize(r, &mut out);
                }
            }
            out
        })
    }

    /// The summary of a node, from its children. The walk is iterative, so
    /// a deep trie does not use the stack.
    fn summarize(&self, root: u32, out: &mut BTreeMap<u32, Summary>) {
        let mut stack = vec![(root, false)];
        while let Some((n, done)) = stack.pop() {
            let node = self.trie.walk_node(n);
            if !done {
                stack.push((n, true));
                for c in node.children.into_iter().flatten() {
                    stack.push((c, false));
                }
                continue;
            }
            let mut count = 0u32;
            // The groups of the subtree: the entry, then the children. NONE
            // stands for a child with mixed groups.
            let mut seen: Vec<u32> = Vec::new();
            if let Some((_, _, id)) = node.entry {
                count += 1;
                seen.push(self.entries[*id as usize].group);
            }
            for c in node.children.into_iter().flatten() {
                let s = out[&c];
                count += s.count;
                seen.push(s.uniform);
            }
            let mixed = seen.contains(&NONE) || seen.windows(2).any(|w| w[0] != w[1]);
            let uniform = seen.first().copied();
            let uniform = match (mixed, uniform) {
                (false, Some(u)) => u,
                _ => NONE,
            };
            out.insert(n, Summary { count, uniform });
        }
    }

    /// The prefixes of the subtree of a node, in prefix order, at most `max`.
    fn subtree_prefixes(&self, root: u32, max: usize, out: &mut Vec<(Prefix, u32)>) {
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            if out.len() >= max {
                return;
            }
            let node = self.trie.walk_node(n);
            if let Some((_, p, id)) = node.entry {
                out.push((p, *id));
            }
            for c in node.children.into_iter().rev().flatten() {
                stack.push(c);
            }
        }
    }

    /// Splits a packet set by the next-hop group of its longest-prefix
    /// match on the destination. Each group has the number of its routes and
    /// the first `sample` of them in prefix order.
    pub fn split(
        &self,
        input: &PacketSet,
        sample: usize,
    ) -> (Vec<GroupRoutes<'_>>, PacketSet, PacketSet) {
        let summary = self.summary();
        let key = |id: &u32| self.entries[*id as usize].group;
        let uniform = |n: u32| {
            summary
                .get(&n)
                .and_then(|s| (s.uniform != NONE).then_some(s.uniform))
        };
        let part: GroupPartition<u32> =
            input.partition_by_group(AddrField::Dst, &self.trie, &key, &uniform);
        let groups = part
            .groups
            .into_iter()
            .map(|g| {
                let mut routes: Vec<(Prefix, u32)> = g
                    .entries
                    .iter()
                    .map(|i| {
                        let (p, id) = self.trie.entry(*i);
                        (p, *id)
                    })
                    .collect();
                let mut count = routes.len();
                for n in &g.subtrees {
                    count += summary.get(n).map_or(0, |s| s.count as usize);
                    self.subtree_prefixes(*n, sample, &mut routes);
                }
                routes.sort_by_key(|(p, _)| *p);
                routes.dedup_by_key(|(p, _)| *p);
                routes.truncate(sample);
                GroupRoutes {
                    group: &self.groups[g.key as usize],
                    count,
                    spans: routes
                        .iter()
                        .flat_map(|(_, id)| self.spans_of(*id))
                        .collect(),
                    sample: routes.into_iter().map(|(p, _)| p).collect(),
                    packets: g.packets,
                }
            })
            .collect();
        (groups, part.unmatched, part.uncertain)
    }
}
