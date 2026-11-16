//! The path-compressed prefix table and the prefix partition of a packet set
//! agree with a brute-force longest-prefix match.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use rsim_core::{
    AddrField, Header, PROTO_TCP, PacketSet, Prefix, PrefixTable, SetArena, TriePrefixTable,
};

/// The longest prefix of the list that contains `a`, with its index.
fn brute(prefixes: &[Prefix], a: IpAddr) -> Option<usize> {
    prefixes
        .iter()
        .enumerate()
        .filter(|(_, p)| p.contains(a))
        .max_by_key(|(_, p)| p.len())
        .map(|(i, _)| i)
}

/// Prefixes in a small space, so that they nest and share bits.
fn prefix() -> impl Strategy<Value = Prefix> {
    prop_oneof![
        (0u32..65_536, 0u8..=32).prop_map(|(x, l)| {
            Prefix::new(
                IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | (x << 8) | (x & 0xff))),
                l,
            )
        }),
        (0u128..65_536, 0u8..=128).prop_map(|(x, l)| {
            Prefix::new(
                IpAddr::V6(Ipv6Addr::from((0x2001_0db8u128 << 96) | (x << 64) | x)),
                l,
            )
        }),
    ]
}

fn address() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        (0u32..65_536)
            .prop_map(|x| IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | (x << 8) | (x & 0xff)))),
        any::<u32>().prop_map(|x| IpAddr::V4(Ipv4Addr::from(x))),
        (0u128..65_536)
            .prop_map(|x| IpAddr::V6(Ipv6Addr::from((0x2001_0db8u128 << 96) | (x << 64) | x))),
    ]
}

fn unique(mut v: Vec<Prefix>) -> Vec<Prefix> {
    v.sort();
    v.dedup();
    v
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn lookups_agree_with_brute_force(
        prefixes in prop::collection::vec(prefix(), 0..60),
        addrs in prop::collection::vec(address(), 1..40),
    ) {
        let prefixes = unique(prefixes);
        let t: TriePrefixTable<usize> =
            prefixes.iter().enumerate().map(|(i, p)| (*p, i)).collect();
        prop_assert_eq!(t.len(), prefixes.len());
        for (i, p) in prefixes.iter().enumerate() {
            prop_assert_eq!(t.get(p), Some(&i));
        }
        for a in addrs {
            prop_assert_eq!(t.longest_match(a).map(|(_, v)| *v), brute(&prefixes, a), "{}", a);
        }
    }

    #[test]
    fn the_prefix_partition_agrees_with_brute_force(
        prefixes in prop::collection::vec(prefix(), 0..40),
        addrs in prop::collection::vec(address(), 2..12),
    ) {
        let prefixes = unique(prefixes);
        let t: TriePrefixTable<usize> =
            prefixes.iter().enumerate().map(|(i, p)| (*p, i)).collect();
        let arena = SetArena::standalone();
        let one = |a: IpAddr| {
            let src = if a.is_ipv4() { "192.0.2.1" } else { "2001:db8:ffff::1" };
            PacketSet::single(&arena, &Header::request(src.parse().unwrap(), a, PROTO_TCP))
        };
        let mut all = one(addrs[0]);
        for a in &addrs[1..] {
            all = all.union(&one(*a));
        }
        let part = all.partition_by_prefix(AddrField::Dst, &t);
        prop_assert!(part.uncertain.is_empty());
        for a in &addrs {
            let s = one(*a);
            let want = brute(&prefixes, *a);
            let got: Vec<usize> = part
                .matched
                .iter()
                .filter(|(_, _, set)| !s.intersect(set).is_empty())
                .map(|(_, v, _)| **v)
                .collect();
            match want {
                Some(i) => prop_assert_eq!(got, vec![i], "{}", a),
                None => {
                    prop_assert!(got.is_empty(), "{}", a);
                    prop_assert!(s.is_subset(&part.unmatched), "{}", a);
                }
            }
        }
    }
}

/// The uniform group of each trie node: the group of each entry of its
/// subtree, or `None`.
fn uniform_of(t: &TriePrefixTable<usize>, groups: usize) -> std::collections::BTreeMap<u32, usize> {
    fn walk(
        t: &TriePrefixTable<usize>,
        n: u32,
        g: usize,
        out: &mut std::collections::BTreeMap<u32, usize>,
    ) -> Option<Option<usize>> {
        // None: mixed. Some(None): no entry. Some(Some(k)): all k.
        let node = t.walk_node(n);
        let mut acc: Option<usize> = node.entry.map(|e| *e.2 % g);
        for c in node.children.into_iter().flatten() {
            match walk(t, c, g, out)? {
                None => {}
                Some(k) => match acc {
                    None => acc = Some(k),
                    Some(a) if a == k => {}
                    Some(_) => return None,
                },
            }
        }
        if let Some(k) = acc {
            out.insert(n, k);
        }
        Some(acc)
    }
    let mut out = std::collections::BTreeMap::new();
    for v6 in [false, true] {
        if let Some(r) = t.walk_root(v6) {
            walk(t, r, groups, &mut out);
        }
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    #[test]
    fn the_group_partition_agrees_with_brute_force(
        prefixes in prop::collection::vec(prefix(), 0..40),
        addrs in prop::collection::vec(address(), 2..12),
        groups in 1usize..4,
        shortcut in any::<bool>(),
    ) {
        let prefixes = unique(prefixes);
        let t: TriePrefixTable<usize> =
            prefixes.iter().enumerate().map(|(i, p)| (*p, i)).collect();
        let uniform = uniform_of(&t, groups);
        let arena = SetArena::standalone();
        let one = |a: IpAddr| {
            let src = if a.is_ipv4() { "192.0.2.1" } else { "2001:db8:ffff::1" };
            PacketSet::single(&arena, &Header::request(src.parse().unwrap(), a, PROTO_TCP))
        };
        let mut all = one(addrs[0]);
        for a in &addrs[1..] {
            all = all.union(&one(*a));
        }
        let key = |v: &usize| *v % groups;
        let uni = |n: u32| if shortcut { uniform.get(&n).copied() } else { None };
        let part = all.partition_by_group(AddrField::Dst, &t, &key, &uni);
        prop_assert!(part.uncertain.is_empty());
        let mut keys: Vec<usize> = part.groups.iter().map(|g| g.key).collect();
        keys.dedup();
        prop_assert_eq!(keys.len(), part.groups.len());
        for a in &addrs {
            let s = one(*a);
            let got: Vec<usize> = part
                .groups
                .iter()
                .filter(|g| !s.intersect(&g.packets).is_empty())
                .map(|g| g.key)
                .collect();
            match brute(&prefixes, *a) {
                Some(i) => prop_assert_eq!(got, vec![i % groups], "{}", a),
                None => prop_assert!(got.is_empty() && s.is_subset(&part.unmatched), "{}", a),
            }
        }
    }
}
