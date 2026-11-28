//! Builds the twin of the newest snapshot of a store and measures the
//! routing calculation: the time and the peak heap of the estate build with
//! its routing rounds, the rounds, the count of processes, the count of
//! prefix groups, the size of the largest group, the count of groups that
//! reached the search, the count of groups of each convergence result, the
//! time of one more BGP calculation in milliseconds, and the rows of the
//! route guard and of the database guard by category. The clock of this
//! example is the only clock of the crate. A counting allocator measures
//! the heap.
//!
//! Arguments: the data folder of `rsim-collect`.

// The global allocator needs `unsafe`. It is only in this example binary.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Instant;

use rsim_ingest::bgp_build::Igp;
use rsim_ingest::estate;
use rsim_routing::bgp::{Event, compute};
use rsim_store::{Keys, Store};

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let now = LIVE.fetch_add(l.size() as isize, Ordering::Relaxed) + l.size() as isize;
        PEAK.fetch_max(now, Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let by = n as isize - l.size() as isize;
        let now = LIVE.fetch_add(by, Ordering::Relaxed) + by;
        PEAK.fetch_max(now, Ordering::Relaxed);
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static A: Counting = Counting;

fn mib(b: isize) -> f64 {
    b as f64 / (1024.0 * 1024.0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let data = &args[1];
    let keys = std::fs::read_to_string(format!("{data}/keys")).expect("the key file is readable");
    let store = Store::open_read(
        format!("{data}/store"),
        Keys::from_hex(&keys).expect("valid keys"),
    )
    .expect("the store opens");
    let snap = store
        .latest()
        .expect("the store reads")
        .expect("a snapshot exists");
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let started = Instant::now();
    let e = estate::build(&store, &snap).expect("the snapshot reads");
    let estate_ms = started.elapsed().as_millis();
    println!(
        "estate build peak heap MiB {:.1}, held MiB {:.1}",
        mib(PEAK.load(Ordering::Relaxed) - before),
        mib(LIVE.load(Ordering::Relaxed) - before)
    );
    for n in e.notes.get("estate").into_iter().flatten() {
        if n.starts_with("routing rounds") {
            println!("{n}");
        }
    }
    let mut lsas: BTreeMap<&str, usize> = BTreeMap::new();
    for rows in e.ospf_guard.values() {
        for r in rows.iter().filter(|r| r.area.is_none()) {
            *lsas.entry(r.category.name()).or_default() += 1;
        }
    }
    for (c, n) in &lsas {
        println!("external lsa rows {c} {n}");
    }
    let Some(b) = &e.bgp_routing else {
        println!("no BGP process");
        return;
    };
    let started = Instant::now();
    let result = compute(&b.input, &Igp { tables: &b.igp });
    let ms = started.elapsed().as_millis();
    println!("estate build ms {estate_ms}");
    println!("processes {}", b.input.processes.len());
    println!("sessions {}", b.input.sessions.len());
    println!("seeds {}", b.input.seeds.len());
    let gaps: usize = b.gaps.values().map(Vec::len).sum();
    println!("gaps {gaps}");
    match result {
        Ok(r) => {
            println!("prefix groups {}", r.groups.len());
            let largest = r.groups.iter().map(|g| g.keys.len()).max().unwrap_or(0);
            println!("largest group keys {largest}");
            let searched: BTreeSet<usize> = r
                .events
                .iter()
                .filter_map(|e| match e {
                    Event::Search { group, .. } => Some(*group),
                    Event::Round { .. } => None,
                })
                .collect();
            println!("groups with a search {}", searched.len());
            let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
            for g in &r.groups {
                *kinds
                    .entry(format!("{:?}", g.convergence.kind()))
                    .or_default() += 1;
            }
            for (k, n) in kinds {
                println!("groups {k} {n}");
            }
            println!("routes {}", r.routes.len());
        }
        Err(err) => println!("calculation not run: {err}"),
    }
    println!("bgp calculation ms {ms}");
    let mut categories: BTreeMap<(String, String), usize> = BTreeMap::new();
    for rows in e.guard.values() {
        for r in rows {
            let bgp = r.protocol.starts_with("bgp") || r.protocol.starts_with('B');
            if bgp {
                *categories
                    .entry((r.category.name().to_string(), r.reason.clone()))
                    .or_default() += 1;
            }
        }
    }
    let mut by_category: BTreeMap<&str, usize> = BTreeMap::new();
    for ((c, _), n) in &categories {
        *by_category.entry(c.as_str()).or_default() += n;
    }
    for (c, n) in &by_category {
        println!("bgp rows {c} {n}");
    }
    let mut reasons: Vec<(&(String, String), &usize)> = categories.iter().collect();
    reasons.sort_by(|a, b| b.1.cmp(a.1));
    for ((c, r), n) in reasons.into_iter().take(12) {
        println!("bgp rows {c} {n}: {r}");
    }
}
