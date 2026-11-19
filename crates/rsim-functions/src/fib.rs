//! A forwarding table: a prefix trie with interned next-hop groups and
//! compact provenance.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use rsim_core::{
    AddrField, GroupPartition, PacketSet, Prefix, PrefixTable, ReasonCode, SetSpec, SourceSpan,
    TriePrefixTable,
};

use crate::routing::{Route, RouteKind, RouteNextHop, RouteProtocol};

/// The forwarding result of a route: its forwarding kind, its next hops in
/// the fixed order of the alternatives, and for a route with no next hop
/// the reason that its packets are unknown. Routes with the same group
/// forward the same packets the same way. A learned route has the kind
/// `Static`, so it shares the group of a static route with the same next
/// hops; its protocol is a column of its entry.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NextHopGroup {
    pub kind: RouteKind,
    pub next_hops: Vec<RouteNextHop>,
    pub unknown: Option<(ReasonCode, String)>,
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
    protocol: Option<RouteProtocol>,
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
    summary: OnceLock<Vec<Summary>>,
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
    /// The number of routes that the packets of the group matched. If
    /// `exact` is false, it is an upper bound: the split gave a whole
    /// subtree to the group, and the packets can touch fewer routes of it.
    pub count: usize,
    pub exact: bool,
    /// The first routes, in prefix order, at most the asked number.
    pub sample: Vec<Prefix>,
    /// The protocol of each route of the sample that a routing protocol
    /// gave.
    pub protocols: Vec<Option<RouteProtocol>>,
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
            kind: route.kind.forwarding(),
            next_hops: route.next_hops().to_vec(),
            unknown: route.unknown_code().map(|(c, why)| (c, why.to_string())),
        });
        let protocol = route.kind.protocol();
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
        let entry = Entry {
            group,
            span,
            protocol,
        };
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

    /// Calls `f` with the provenance of each route.
    pub fn each_span(&self, f: &mut dyn FnMut(&SourceSpan)) {
        for e in &self.entries {
            if e.span.file != NONE {
                f(&SourceSpan {
                    file: self.files[e.span.file as usize].clone(),
                    first_line: e.span.first,
                    last_line: e.span.last,
                });
            }
        }
        for s in self.extra_spans.values().flatten() {
            f(s);
        }
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
        let e = self.entries[id as usize];
        let g = &self.groups[e.group as usize];
        let kind = match e.protocol {
            Some(p) => RouteKind::Learned(p),
            None => g.kind,
        };
        match &g.unknown {
            Some((code, why)) => Route::unknown_with(kind, *code, why.clone(), self.spans_of(id)),
            None => Route::new(kind, g.next_hops.clone(), self.spans_of(id)),
        }
    }

    /// The longest-prefix match of one address: the prefix and its group.
    pub fn lookup(&self, addr: std::net::IpAddr) -> Option<(Prefix, &NextHopGroup)> {
        let (p, id) = self.trie.longest_match(addr)?;
        Some((p, &self.groups[self.entries[*id as usize].group as usize]))
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

    /// The summary of each node, built at the first split of a set with
    /// more than one destination. A path query does not build it.
    fn summary(&self) -> &[Summary] {
        self.summary.get_or_init(|| {
            let mut out = vec![
                Summary {
                    count: 0,
                    uniform: NONE
                };
                self.trie.node_count()
            ];
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
    fn summarize(&self, root: u32, out: &mut [Summary]) {
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
                let s = out[c as usize];
                count += s.count;
                seen.push(s.uniform);
            }
            let mixed = seen.contains(&NONE) || seen.windows(2).any(|w| w[0] != w[1]);
            let uniform = seen.first().copied();
            let uniform = match (mixed, uniform) {
                (false, Some(u)) => u,
                _ => NONE,
            };
            out[n as usize] = Summary { count, uniform };
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
        let key = |id: &u32| self.entries[*id as usize].group;
        let uniform = |n: u32| {
            let s = self.summary()[n as usize];
            (s.uniform != NONE).then_some(s.uniform)
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
                let exact = g.subtrees.is_empty();
                let mut count = routes.len();
                for n in &g.subtrees {
                    count += self.summary()[*n as usize].count as usize;
                    self.subtree_prefixes(*n, 4 * sample, &mut routes);
                }
                routes.sort_by_key(|(p, _)| *p);
                routes.dedup_by_key(|(p, _)| *p);
                if !exact {
                    // A whole subtree went to the group: name only routes
                    // that the packets touch.
                    let arena = g.packets.arena().clone();
                    routes.retain(|(p, _)| {
                        let spec = SetSpec {
                            dst_ip: Some(vec![*p]),
                            ..SetSpec::default()
                        };
                        !PacketSet::from_spec(&arena, &spec)
                            .intersect(&g.packets)
                            .is_empty()
                    });
                }
                routes.truncate(sample);
                GroupRoutes {
                    group: &self.groups[g.key as usize],
                    count,
                    exact,
                    spans: routes
                        .iter()
                        .flat_map(|(_, id)| self.spans_of(*id))
                        .collect(),
                    protocols: routes
                        .iter()
                        .map(|(_, id)| self.entries[*id as usize].protocol)
                        .collect(),
                    sample: routes.into_iter().map(|(p, _)| p).collect(),
                    packets: g.packets,
                }
            })
            .collect();
        (groups, part.unmatched, part.uncertain)
    }
}

#[cfg(test)]
mod tests {
    use rsim_core::{FunctionId, InterfaceId, SetArena};

    use super::*;

    fn route(iface: &str) -> Route {
        Route::new(
            RouteKind::Static,
            vec![RouteNextHop {
                interface: InterfaceId::new(iface),
                gateway: None,
                next: FunctionId::new(format!("r1/out/{iface}")),
            }],
            vec![SourceSpan::line("r1/routes", 1)],
        )
    }

    fn set(dst: &str) -> PacketSet {
        let spec = SetSpec {
            src_ip: Some(vec!["192.0.2.1/32".parse().unwrap()]),
            dst_ip: Some(vec![dst.parse().unwrap()]),
            ..SetSpec::default()
        };
        PacketSet::from_spec(&SetArena::standalone(), &spec)
    }

    #[test]
    fn a_whole_subtree_gives_an_upper_bound_and_names_only_touched_routes() {
        let f: Fib = [
            ("10.0.0.0/8", "eth1"),
            ("10.1.0.0/16", "eth1"),
            ("10.2.0.0/16", "eth1"),
            ("10.3.0.0/16", "eth2"),
        ]
        .into_iter()
        .map(|(p, i)| (p.parse().unwrap(), route(i)))
        .collect();
        let (groups, _, _) = f.split(&set("10.1.0.0/16"), 5);
        assert_eq!(groups.len(), 1);
        let g = &groups[0];
        let names: Vec<String> = g.sample.iter().map(ToString::to_string).collect();
        assert!(!names.contains(&"10.2.0.0/16".to_string()), "{names:?}");
        assert!(names.contains(&"10.1.0.0/16".to_string()), "{names:?}");
        assert!(g.exact || g.count >= names.len());

        // All of 10/8: both groups, each with its own routes.
        let (groups, unmatched, _) = f.split(&set("10.0.0.0/8"), 5);
        assert!(unmatched.is_empty());
        assert_eq!(groups.len(), 2);
        let total: usize = groups.iter().map(|g| g.count).sum();
        assert!(total >= 4, "{total}");
    }

    #[test]
    fn a_learned_route_shares_the_group_of_a_static_route_and_keeps_its_protocol() {
        let learned = |iface: &str, p: RouteProtocol| {
            let r = route(iface);
            Route::new(RouteKind::Learned(p), r.next_hops().to_vec(), r.spans)
        };
        let f: Fib = [
            ("10.1.0.0/16", route("eth1")),
            ("10.2.0.0/16", learned("eth1", RouteProtocol::Bgp)),
            ("10.3.0.0/16", learned("eth2", RouteProtocol::Ospf)),
        ]
        .into_iter()
        .map(|(p, r)| (p.parse().unwrap(), r))
        .collect();
        assert_eq!(f.groups().len(), 2);
        let kinds: Vec<&str> = f.entries().iter().map(|(_, r)| r.kind.name()).collect();
        assert_eq!(kinds, ["static", "bgp", "ospf"]);
        let (groups, _, _) = f.split(&set("10.0.0.0/8"), 5);
        assert_eq!(groups.len(), 2);
        let eth1 = groups
            .iter()
            .find(|g| g.group.next_hops[0].interface == InterfaceId::new("eth1"))
            .unwrap();
        assert_eq!(eth1.protocols, [None, Some(RouteProtocol::Bgp)]);
    }

    #[test]
    fn the_reason_of_an_unknown_route_is_part_of_its_group() {
        let why = |w: &str| Route::unknown(RouteKind::Static, w, Vec::new());
        let f: Fib = [
            ("10.1.0.0/16", why("a")),
            ("10.2.0.0/16", why("a")),
            ("10.3.0.0/16", why("b")),
            (
                "10.4.0.0/16",
                Route::new(RouteKind::Static, Vec::new(), Vec::new()),
            ),
        ]
        .into_iter()
        .map(|(p, r)| (p.parse().unwrap(), r))
        .collect();
        assert_eq!(f.groups().len(), 3);
        let p: Prefix = "10.3.0.0/16".parse().unwrap();
        assert_eq!(f.get(&p).unwrap().unknown_reason(), Some("b"));
    }

    #[test]
    fn a_path_query_names_its_exact_route_without_the_summary() {
        let f: Fib = [("0.0.0.0/0", "eth0"), ("10.0.0.0/8", "eth1")]
            .into_iter()
            .map(|(p, i)| (p.parse().unwrap(), route(i)))
            .collect();
        let (groups, _, _) = f.split(&set("10.9.9.9/32"), 5);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].count, 1);
        assert!(groups[0].exact);
        assert_eq!(groups[0].sample[0].to_string(), "10.0.0.0/8");
        assert!(f.summary.get().is_none(), "a path query built the summary");
    }
}
