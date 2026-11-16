//! The forwarding table at internet scale: a synthetic table of 1,000,000
//! IPv4 and 200,000 IPv6 routes. A counting allocator measures the heap
//! bytes of the table. The benchmark prints the build time, the time of a
//! point lookup and of a grouped split of one destination, and the time and
//! the diagram nodes of a split of all destinations at 2, 16 and 256
//! next-hop groups.

// The global allocator needs `unsafe`. It is only in this benchmark binary.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Instant;

use rsim_core::{
    FunctionId, Header, InterfaceId, PROTO_TCP, PacketSet, Prefix, SetArena, SetSpec, SourceSpan,
};
use rsim_functions::{Fib, Route, RouteKind, RouteNextHop};

struct Counting;
static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as isize, Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_add(n as isize - l.size() as isize, Ordering::Relaxed);
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static A: Counting = Counting;

/// A fixed pseudo-random sequence, so each run builds the same table.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }
}

/// Prefix lengths in about the proportions of an internet table.
fn v4_len(r: u64) -> u8 {
    match r % 100 {
        0..60 => 24,
        60..70 => 23,
        70..80 => 22,
        80..85 => 21,
        85..90 => 20,
        90..93 => 19,
        93..95 => 18,
        95..98 => 16,
        _ => 8 + (r % 8) as u8,
    }
}

fn v6_len(r: u64) -> u8 {
    match r % 100 {
        0..50 => 48,
        50..65 => 32,
        65..75 => 40,
        75..85 => 44,
        85..92 => 36,
        _ => 29,
    }
}

/// The number of IPv4 and IPv6 routes: 1,000,000 and 200,000, or the
/// values of `RSIM_FIB_V4` and `RSIM_FIB_V6`.
fn sizes() -> (usize, usize) {
    let get = |k: &str, d: usize| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    (get("RSIM_FIB_V4", 1_000_000), get("RSIM_FIB_V6", 200_000))
}

fn prefixes(seed: u64) -> Vec<Prefix> {
    let (v4, v6) = sizes();
    let mut g = Lcg(seed);
    let mut out = Vec::with_capacity(v4 + v6);
    for _ in 0..v4 {
        let a = Ipv4Addr::from(g.next() as u32);
        out.push(Prefix::new(IpAddr::V4(a), v4_len(g.next())));
    }
    for _ in 0..v6 {
        let hi = (0x2000u128 << 112) | (u128::from(g.next()) << 48);
        out.push(Prefix::new(
            IpAddr::V6(Ipv6Addr::from(hi)),
            v6_len(g.next()),
        ));
    }
    out
}

fn build(prefixes: &[Prefix], groups: usize) -> Fib {
    let mut f = Fib::new();
    for (i, p) in prefixes.iter().enumerate() {
        let g = i % groups;
        let hop = RouteNextHop {
            interface: InterfaceId::new(format!("eth{g}")),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(10, (g >> 8) as u8, g as u8, 1))),
            next: FunctionId::new(format!("r1/out/eth{g}")),
        };
        let span = SourceSpan::line("r1/routes@0123456789ab", u32::try_from(i + 1).unwrap());
        f.insert(*p, Route::new(RouteKind::Static, vec![hop], vec![span]));
    }
    f
}

fn kib(b: isize) -> f64 {
    b as f64 / 1024.0
}

fn main() {
    let ps = prefixes(7);
    for groups in [2usize, 16, 256] {
        let before = LIVE.load(Ordering::Relaxed);
        let t0 = Instant::now();
        let fib = build(&ps, groups);
        let built = t0.elapsed();
        let bytes = LIVE.load(Ordering::Relaxed) - before;
        println!(
            "{groups:>3} groups: {} routes, heap {:.1} MiB ({:.1} B per route), build {:.2} s",
            fib.len(),
            kib(bytes) / 1024.0,
            bytes as f64 / fib.len() as f64,
            built.as_secs_f64()
        );

        // Point lookups in the trie.
        let mut g = Lcg(99);
        let n = 1_000_000;
        let t0 = Instant::now();
        let mut hits = 0usize;
        for _ in 0..n {
            let a = IpAddr::V4(Ipv4Addr::from(g.next() as u32));
            hits += usize::from(fib.lookup(a).is_some());
        }
        let per = t0.elapsed().as_nanos() as f64 / n as f64;
        println!("    point lookup {per:.0} ns ({hits} of {n} matched)");

        // The grouped split of one destination, as a path query does it.
        let arena = SetArena::standalone();
        let t0 = Instant::now();
        let k = 1_000;
        for i in 0..k {
            let h = Header::request(
                "192.0.2.1".parse().unwrap(),
                IpAddr::V4(Ipv4Addr::from((i as u32).wrapping_mul(2_654_435_761))),
                PROTO_TCP,
            );
            let s = PacketSet::single(&arena, &h);
            std::hint::black_box(fib.split(&s, 5));
        }
        let per = t0.elapsed().as_micros() as f64 / k as f64;
        println!("    split of one destination {per:.1} us");

        // The grouped split of all destinations of each family. With
        // `RSIM_FIB_SKIP_ALL` set, this part does not run.
        let skip = std::env::var("RSIM_FIB_SKIP_ALL").is_ok();
        for dst in ["0.0.0.0/0", "::/0"].into_iter().filter(|_| !skip) {
            let arena = SetArena::standalone();
            let src = if dst.contains(':') {
                "2001:db8::1/128"
            } else {
                "192.0.2.1/32"
            };
            let spec = SetSpec {
                src_ip: Some(vec![src.parse().unwrap()]),
                dst_ip: Some(vec![dst.parse().unwrap()]),
                protocol: Some(vec![(PROTO_TCP, PROTO_TCP)]),
                ..SetSpec::default()
            };
            let s = PacketSet::from_spec(&arena, &spec);
            let t0 = Instant::now();
            let (parts, unmatched, _) = fib.split(&s, 5);
            let took = t0.elapsed();
            let max = parts.iter().map(|p| p.count).max().unwrap_or(0);
            println!(
                "    split of {dst}: {} branches, largest {} routes, unmatched {}, {:.2} s, {} nodes",
                parts.len(),
                max,
                !unmatched.is_empty(),
                took.as_secs_f64(),
                arena.local_nodes()
            );
        }
        drop(fib);
    }
}
