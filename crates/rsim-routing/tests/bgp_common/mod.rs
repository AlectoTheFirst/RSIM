//! Builders and a fixed-seed generator for the BGP tests.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};

use rsim_core::Prefix;
use rsim_routing::bgp::{AsPath, Asn, BgpPath, Peer, RouteKey, SessionKind};

pub fn pfx(s: &str) -> Prefix {
    s.parse().unwrap()
}

pub fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

pub fn v4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

pub fn key(s: &str) -> RouteKey {
    RouteKey::unicast(pfx(s))
}

/// A path from the peer `addr` of `kind`, with the router ID `addr` and
/// the next hop `addr`.
pub fn path(kind: SessionKind, addr: &str, as_path: &[u32]) -> BgpPath {
    let asn = as_path.first().copied().unwrap_or(65000);
    let peer = Peer {
        address: Some(ip(addr)),
        router_id: v4(addr),
        asn: Asn(asn),
        kind,
    };
    BgpPath::new(peer, Some(ip(addr)), AsPath::sequence(as_path))
}

pub fn ebgp(addr: &str, as_path: &[u32]) -> BgpPath {
    path(SessionKind::Ebgp, addr, as_path)
}

pub fn ibgp(addr: &str, as_path: &[u32]) -> BgpPath {
    path(SessionKind::Ibgp, addr, as_path)
}

/// A xorshift64 generator with a fixed seed.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// A number in `0..n`.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize]
    }
}

/// Each permutation of `0..n`, in lexicographic order.
pub fn permutations(n: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut cur: Vec<usize> = (0..n).collect();
    loop {
        out.push(cur.clone());
        let Some(i) = (0..n.saturating_sub(1))
            .rev()
            .find(|&i| cur[i] < cur[i + 1])
        else {
            return out;
        };
        let j = (i + 1..n).rev().find(|&j| cur[j] > cur[i]).unwrap();
        cur.swap(i, j);
        cur[i + 1..].reverse();
    }
}
