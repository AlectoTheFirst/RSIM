//! A prefix table with longest-prefix match, behind a trait.

use std::net::IpAddr;

use crate::addr::{Prefix, addr_bit};

/// A node of the read-only walk of a prefix table. The node stands for the
/// first `depth` bits of `key`; the bits after `depth` in `key` mean
/// nothing. A child has a greater depth, and the bits between the 2 depths
/// are the bits of the key of the child.
#[derive(Clone, Copy, Debug)]
pub struct WalkNode<'a, V> {
    pub depth: u8,
    pub key: IpAddr,
    /// The entry of exactly this node, with its index in the table.
    pub entry: Option<(usize, Prefix, &'a V)>,
    pub children: [Option<u32>; 2],
}

/// A table keyed by prefix with longest-prefix match.
pub trait PrefixTable<V> {
    /// Inserts a value. Returns the old value of the same prefix.
    fn insert(&mut self, prefix: Prefix, value: V) -> Option<V>;
    /// The value of exactly this prefix.
    fn get(&self, prefix: &Prefix) -> Option<&V>;
    /// The longest prefix that contains `addr`, with its value.
    fn longest_match(&self, addr: IpAddr) -> Option<(Prefix, &V)>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// All entries, in prefix order.
    fn entries(&self) -> Vec<(Prefix, &V)>;
    /// The entry with an index of the walk.
    fn entry(&self, index: usize) -> (Prefix, &V);
    /// The root node of the walk of a family, if the family has an entry.
    fn walk_root(&self, ipv6: bool) -> Option<u32>;
    /// A node of the walk.
    fn walk_node(&self, node: u32) -> WalkNode<'_, V>;
}

const NONE: u32 = u32::MAX;

/// A node of the trie. Its key is the first `len` bits of the prefix of the
/// entry `rep`, which is an entry at or below the node.
#[derive(Clone, Copy, Debug)]
struct Node {
    child: [u32; 2],
    value: u32,
    rep: u32,
    len: u8,
}

/// A path-compressed binary trie in one arena. Node 0 is the IPv4 root and
/// node 1 is the IPv6 root. A node exists only where 2 prefixes branch or
/// where a prefix ends, so the trie has at most 2 nodes for each entry
/// besides the roots. The structure has no hashing, so its behaviour is
/// deterministic.
#[derive(Clone, Debug)]
pub struct TriePrefixTable<V> {
    nodes: Vec<Node>,
    values: Vec<(Prefix, V)>,
}

impl<V> Default for TriePrefixTable<V> {
    fn default() -> Self {
        Self::new()
    }
}

/// True if the first `len` bits of 2 addresses of one family are equal.
fn same_bits(a: IpAddr, b: IpAddr, len: u8) -> bool {
    Prefix::new(a, len) == Prefix::new(b, len)
}

/// The first bit from `from` where 2 addresses differ, or `to` if they are
/// equal up to `to`.
fn first_difference(a: IpAddr, b: IpAddr, from: u8, to: u8) -> u8 {
    (from..to)
        .find(|&i| addr_bit(a, i) != addr_bit(b, i))
        .unwrap_or(to)
}

impl<V> TriePrefixTable<V> {
    pub fn new() -> Self {
        TriePrefixTable {
            nodes: vec![
                Node {
                    child: [NONE, NONE],
                    value: NONE,
                    rep: NONE,
                    len: 0,
                },
                Node {
                    child: [NONE, NONE],
                    value: NONE,
                    rep: NONE,
                    len: 0,
                },
            ],
            values: Vec::new(),
        }
    }

    fn root(ipv4: bool) -> usize {
        if ipv4 { 0 } else { 1 }
    }

    /// The bytes that the table holds, for the memory benchmark.
    pub fn heap_bytes(&self) -> usize {
        self.nodes.capacity() * std::mem::size_of::<Node>()
            + self.values.capacity() * std::mem::size_of::<(Prefix, V)>()
    }

    /// The key address of a node. A root with no entry below has none.
    fn key(&self, n: usize) -> Option<IpAddr> {
        let r = self.nodes[n].rep;
        (r != NONE).then(|| self.values[r as usize].0.addr())
    }

    fn push_node(&mut self, len: u8, value: u32, rep: u32) -> u32 {
        self.nodes.push(Node {
            child: [NONE, NONE],
            value,
            rep,
            len,
        });
        u32::try_from(self.nodes.len() - 1).expect("trie too large")
    }

    fn push_value(&mut self, prefix: Prefix, value: V) -> u32 {
        self.values.push((prefix, value));
        u32::try_from(self.values.len() - 1).expect("trie too large")
    }

    /// The node of exactly `prefix`, if it exists.
    fn find(&self, prefix: &Prefix) -> Option<usize> {
        let a = prefix.addr();
        let mut n = Self::root(prefix.is_ipv4());
        loop {
            let len = self.nodes[n].len;
            if len == prefix.len() {
                return Some(n);
            }
            let c = self.nodes[n].child[usize::from(addr_bit(a, len))];
            if c == NONE {
                return None;
            }
            let c = c as usize;
            let cl = self.nodes[c].len;
            if cl > prefix.len() || !same_bits(self.key(c)?, a, cl) {
                return None;
            }
            n = c;
        }
    }
}

impl<V> FromIterator<(Prefix, V)> for TriePrefixTable<V> {
    fn from_iter<I: IntoIterator<Item = (Prefix, V)>>(iter: I) -> Self {
        let mut t = TriePrefixTable::new();
        for (p, v) in iter {
            t.insert(p, v);
        }
        t
    }
}

impl<V> PrefixTable<V> for TriePrefixTable<V> {
    fn insert(&mut self, prefix: Prefix, value: V) -> Option<V> {
        let a = prefix.addr();
        let plen = prefix.len();
        let mut n = Self::root(prefix.is_ipv4());
        loop {
            let len = self.nodes[n].len;
            if len == plen {
                let vi = self.nodes[n].value;
                if vi != NONE {
                    return Some(std::mem::replace(&mut self.values[vi as usize].1, value));
                }
                let vi = self.push_value(prefix, value);
                self.nodes[n].value = vi;
                if self.nodes[n].rep == NONE {
                    self.nodes[n].rep = vi;
                }
                return None;
            }
            if self.nodes[n].rep == NONE {
                // An empty root takes its first entry as its key.
                let vi = u32::try_from(self.values.len()).expect("trie too large");
                self.nodes[n].rep = vi;
            }
            let b = usize::from(addr_bit(a, len));
            let c = self.nodes[n].child[b];
            if c == NONE {
                let vi = self.push_value(prefix, value);
                let leaf = self.push_node(plen, vi, vi);
                self.nodes[n].child[b] = leaf;
                return None;
            }
            let ci = c as usize;
            let cl = self.nodes[ci].len;
            let ck = self.key(ci).expect("a child has an entry below it");
            let d = first_difference(a, ck, len + 1, cl.min(plen));
            if d == cl {
                // The key of the child is a prefix of the new prefix.
                n = ci;
                continue;
            }
            if d == plen {
                // The new prefix is a prefix of the key of the child.
                let vi = self.push_value(prefix, value);
                let mid = self.push_node(plen, vi, vi);
                self.nodes[mid as usize].child[usize::from(addr_bit(ck, plen))] = c;
                self.nodes[n].child[b] = mid;
                return None;
            }
            // The new prefix and the key of the child branch at bit `d`.
            let vi = self.push_value(prefix, value);
            let leaf = self.push_node(plen, vi, vi);
            let fork = self.push_node(d, NONE, vi);
            let f = fork as usize;
            self.nodes[f].child[usize::from(addr_bit(ck, d))] = c;
            self.nodes[f].child[usize::from(addr_bit(a, d))] = leaf;
            self.nodes[n].child[b] = fork;
            return None;
        }
    }

    fn get(&self, prefix: &Prefix) -> Option<&V> {
        let n = self.find(prefix)?;
        let vi = self.nodes[n].value;
        (vi != NONE).then(|| &self.values[vi as usize].1)
    }

    fn longest_match(&self, addr: IpAddr) -> Option<(Prefix, &V)> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let mut n = Self::root(addr.is_ipv4());
        let mut best = self.nodes[n].value;
        loop {
            let len = self.nodes[n].len;
            if len == max {
                break;
            }
            let c = self.nodes[n].child[usize::from(addr_bit(addr, len))];
            if c == NONE {
                break;
            }
            let ci = c as usize;
            let Some(k) = self.key(ci) else {
                break;
            };
            if !same_bits(k, addr, self.nodes[ci].len) {
                break;
            }
            n = ci;
            if self.nodes[n].value != NONE {
                best = self.nodes[n].value;
            }
        }
        (best != NONE).then(|| {
            let (p, v) = &self.values[best as usize];
            (*p, v)
        })
    }

    fn len(&self) -> usize {
        self.values.len()
    }

    fn entries(&self) -> Vec<(Prefix, &V)> {
        let mut e: Vec<(Prefix, &V)> = self.values.iter().map(|(p, v)| (*p, v)).collect();
        e.sort_by_key(|(p, _)| *p);
        e
    }

    fn entry(&self, index: usize) -> (Prefix, &V) {
        let (p, v) = &self.values[index];
        (*p, v)
    }

    fn walk_root(&self, ipv6: bool) -> Option<u32> {
        let r = Self::root(!ipv6);
        (self.nodes[r].rep != NONE).then_some(r as u32)
    }

    fn walk_node(&self, node: u32) -> WalkNode<'_, V> {
        let n = &self.nodes[node as usize];
        let opt = |x: u32| (x != NONE).then_some(x);
        WalkNode {
            depth: n.len,
            key: self.values[n.rep as usize].0.addr(),
            entry: opt(n.value).map(|v| {
                let (p, val) = &self.values[v as usize];
                (v as usize, *p, val)
            }),
            children: [opt(n.child[0]), opt(n.child[1])],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_match_prefers_longer() {
        let mut t = TriePrefixTable::new();
        t.insert("0.0.0.0/0".parse().unwrap(), "default");
        t.insert("10.0.0.0/8".parse().unwrap(), "ten");
        t.insert("10.20.0.0/24".parse().unwrap(), "users");
        t.insert("2001:db8::/32".parse().unwrap(), "v6");
        let lm = |s: &str| t.longest_match(s.parse().unwrap()).map(|(_, v)| *v);
        assert_eq!(lm("10.20.0.53"), Some("users"));
        assert_eq!(lm("10.21.0.1"), Some("ten"));
        assert_eq!(lm("8.8.8.8"), Some("default"));
        assert_eq!(lm("2001:db8::5"), Some("v6"));
        assert_eq!(lm("2001:db9::5"), None);
        assert_eq!(t.get(&"10.0.0.0/8".parse().unwrap()), Some(&"ten"));
        assert_eq!(t.get(&"10.0.0.0/9".parse().unwrap()), None);
        assert_eq!(t.insert("10.0.0.0/8".parse().unwrap(), "ten2"), Some("ten"));
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn the_trie_has_at_most_2_nodes_for_each_entry() {
        let mut t = TriePrefixTable::new();
        for i in 0..1000u32 {
            let a = IpAddr::from(std::net::Ipv4Addr::from(i.wrapping_mul(2_654_435_761)));
            t.insert(Prefix::new(a, 24), i);
        }
        assert!(t.nodes.len() <= 2 * t.len() + 2, "{} nodes", t.nodes.len());
    }
}
