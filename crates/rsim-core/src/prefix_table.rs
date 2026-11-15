//! The prefix table: self-written, behind a trait (section 15, item 4).

use std::net::IpAddr;

use crate::addr::{Prefix, addr_bit};

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
}

const NONE: u32 = u32::MAX;

#[derive(Clone, Debug)]
struct Node {
    child: [u32; 2],
    value: u32,
}

impl Node {
    fn empty() -> Self {
        Node {
            child: [NONE, NONE],
            value: NONE,
        }
    }
}

/// A binary trie in one arena. Node 0 is the IPv4 root and node 1 is the IPv6
/// root. The structure has no hashing, so its behaviour is deterministic.
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

impl<V> TriePrefixTable<V> {
    pub fn new() -> Self {
        TriePrefixTable {
            nodes: vec![Node::empty(), Node::empty()],
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
        let mut n = Self::root(prefix.is_ipv4());
        for i in 0..prefix.len() {
            let b = usize::from(prefix.bit(i));
            if self.nodes[n].child[b] == NONE {
                self.nodes.push(Node::empty());
                let idx = u32::try_from(self.nodes.len() - 1).expect("trie too large");
                self.nodes[n].child[b] = idx;
            }
            n = self.nodes[n].child[b] as usize;
        }
        let vi = self.nodes[n].value;
        if vi == NONE {
            self.values.push((prefix, value));
            self.nodes[n].value = u32::try_from(self.values.len() - 1).expect("trie too large");
            None
        } else {
            Some(std::mem::replace(&mut self.values[vi as usize].1, value))
        }
    }

    fn get(&self, prefix: &Prefix) -> Option<&V> {
        let mut n = Self::root(prefix.is_ipv4());
        for i in 0..prefix.len() {
            let c = self.nodes[n].child[usize::from(prefix.bit(i))];
            if c == NONE {
                return None;
            }
            n = c as usize;
        }
        let vi = self.nodes[n].value;
        (vi != NONE).then(|| &self.values[vi as usize].1)
    }

    fn longest_match(&self, addr: IpAddr) -> Option<(Prefix, &V)> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let mut n = Self::root(addr.is_ipv4());
        let mut best = self.nodes[n].value;
        for i in 0..max {
            let c = self.nodes[n].child[usize::from(addr_bit(addr, i))];
            if c == NONE {
                break;
            }
            n = c as usize;
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
        assert_eq!(t.insert("10.0.0.0/8".parse().unwrap(), "ten2"), Some("ten"));
        assert_eq!(t.len(), 4);
    }
}
