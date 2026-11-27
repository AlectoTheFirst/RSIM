//! The scale benchmark: a generated estate of `RSIM_SCALE_PERCENT` % of
//! 10,000 routers, 1,000 firewalls with 60,000 rules and 60,000 endpoints
//! (default 1 %). A counting allocator measures the live heap bytes and the
//! peak above the start of each measure.
//!
//! The benchmark prints the generation and build times and the heap of the
//! twin, the time of a path query and of a set query, and the time and
//! peak heap of requests of the table `fib`: a first page of 100 rows with
//! the build of the columns and the heap that the columns hold, a page of
//! 100 rows, a page of the rows of one device, a page sorted by prefix, and
//! all rows as JSON. `RSIM_SCALE_PHASES` selects the parts, a list of `twin`,
//! `path`, `set`, `table` and `fulltable` (the heap of one full table
//! alone); the default is all. `RSIM_SCALE_FILL=0` builds the route tables
//! with only the routes of the estate. When the live heap passes
//! `RSIM_SCALE_CAP_GIB` GiB (default 12), the process stops.

// The global allocator needs `unsafe`. It is only in this benchmark binary.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::{Duration, Instant};

use rsim_cli::commands::Loaded;
use rsim_cli::tables;
use rsim_contract::table::Selection;
use rsim_contract::twin::TwinJson;
use rsim_core::{Header, PROTO_TCP, PROTO_UDP, PacketSet, SetSpec, VerdictKind};
use rsim_engine::{Answer, ExecOptions, Executor, Query, Twin};
use rsim_topologies::{ScaleOpts, dmz_network, scale_estate, server, user, user_network};

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);
static CAP: AtomicIsize = AtomicIsize::new(isize::MAX);

fn grew(by: isize) {
    let now = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(now, Ordering::Relaxed);
    if now > CAP.load(Ordering::Relaxed) {
        let _ = std::io::stderr().write_all(b"the live heap passed the cap; stop\n");
        std::process::abort();
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        grew(l.size() as isize);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        grew(n as isize - l.size() as isize);
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static A: Counting = Counting;

fn live() -> isize {
    LIVE.load(Ordering::Relaxed)
}

/// Sets the peak to the live heap, and gives the live heap.
fn reset_peak() -> isize {
    let now = live();
    PEAK.store(now, Ordering::Relaxed);
    now
}

fn mib(b: isize) -> f64 {
    b as f64 / (1024.0 * 1024.0)
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

fn out(line: String) {
    let mut o = std::io::stdout().lock();
    let _ = writeln!(o, "{line}");
    let _ = o.flush();
}

/// The median time of `n` runs after one warm-up run.
fn median(n: usize, mut f: impl FnMut()) -> Duration {
    f();
    let mut v: Vec<Duration> = (0..n)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed()
        })
        .collect();
    v.sort();
    v[n / 2]
}

fn kinds(a: &Answer) -> Vec<String> {
    a.summary
        .iter()
        .map(|p| match p.summary.kind() {
            Some(VerdictKind::Deliver) => "deliver".to_string(),
            Some(VerdictKind::Exit) => "exit".to_string(),
            Some(VerdictKind::Drop) => "drop".to_string(),
            Some(VerdictKind::Unknown) => "unknown".to_string(),
            None => "depends on the path".to_string(),
        })
        .collect()
}

fn main() {
    let percent: f64 = env("RSIM_SCALE_PERCENT")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1.0);
    let phases: Vec<String> = env("RSIM_SCALE_PHASES")
        .unwrap_or_else(|| "twin,path,set,table,fulltable".into())
        .split(',')
        .map(str::to_string)
        .collect();
    let on = |p: &str| phases.iter().any(|x| x == p);
    let cap_gib: f64 = env("RSIM_SCALE_CAP_GIB")
        .and_then(|v| v.parse().ok())
        .unwrap_or(12.0);
    CAP.store(
        (cap_gib * 1024.0 * 1024.0 * 1024.0) as isize,
        Ordering::Relaxed,
    );
    let mut opts = ScaleOpts::percent(percent);
    opts.fill_tables = env("RSIM_SCALE_FILL").as_deref() != Some("0");
    out(format!("scale {percent} %: {opts:?}"));

    if on("fulltable") {
        let before = reset_peak();
        let t = Instant::now();
        let one = scale_estate(ScaleOpts {
            sites: 2,
            fill_tables: true,
            full_table_routers: 1,
            ..opts
        });
        let twin = one.builder.build().unwrap();
        let bytes = live() - before;
        out(format!(
            "estate of 2 sites with 1 full table: {} routes, {} in the full table, heap {:.1} MiB, {:.2} s",
            one.counts.routes,
            one.counts.full_table_routes,
            mib(bytes),
            t.elapsed().as_secs_f64()
        ));
        drop(twin);
        let none = scale_estate(ScaleOpts {
            sites: 2,
            fill_tables: true,
            full_table_routers: 0,
            ..opts
        });
        let before = live();
        let twin = none.builder.build().unwrap();
        let rest = live() - before;
        drop(twin);
        out(format!(
            "estate of 2 sites with no full table: heap {:.1} MiB; one full table {:.1} MiB, {:.0} B per route",
            mib(rest),
            mib(bytes - rest),
            (bytes - rest) as f64 / one.counts.full_table_routes as f64
        ));
    }

    let start = reset_peak();
    let t = Instant::now();
    let estate = scale_estate(opts);
    let generated = t.elapsed();
    let builder_bytes = live() - start;
    let c = estate.counts;
    let t = Instant::now();
    let twin: Twin = estate.builder.build().unwrap();
    let built = t.elapsed();
    let twin_bytes = live() - start;
    let build_peak = PEAK.load(Ordering::Relaxed) - start;
    let devices = twin.device_count();
    out(format!(
        "estate: {} sites, {} hubs, {} routers, {} firewalls, {} rules, {} endpoints, {} routes ({} in {} full tables), {:.0} routes per router without the full tables",
        c.sites,
        c.hubs,
        c.routers,
        c.firewalls,
        c.rules,
        c.endpoints,
        c.routes,
        c.full_table_routes,
        c.full_table_routers,
        (c.routes - c.full_table_routes) as f64 / (c.routers + c.firewalls) as f64
    ));
    out(format!(
        "twin: {} devices, {} functions; generation {:.2} s, builder heap {:.1} MiB; build {:.2} s; twin heap {:.1} MiB ({:.1} KiB per device), peak {:.1} MiB",
        devices,
        twin.function_count(),
        generated.as_secs_f64(),
        mib(builder_bytes),
        built.as_secs_f64(),
        mib(twin_bytes),
        twin_bytes as f64 / 1024.0 / devices as f64,
        mib(build_peak)
    ));
    if !on("twin") && !on("path") && !on("set") && !on("table") {
        return;
    }

    let opts_exec = ExecOptions {
        check_contract: false,
        ..ExecOptions::default()
    };
    let ex = Executor::with_options(&twin, opts_exec);
    let (src_site, dst_site) = (c.sites - 1, c.sites / 2);
    let (src_access, src_vlan, src) = user(src_site, 5);
    let dst = server(dst_site, 1);

    if on("path") {
        let h = Header::request(src, dst, PROTO_TCP)
            .with_src_port(40000)
            .with_dst_port(443);
        for reply in [false, true] {
            let mut q = Query::path(&twin, &h);
            q.reply = reply;
            let a = ex.run(&q).unwrap();
            let branches = a.branches();
            let steps: usize = branches.iter().map(|b| b.steps.len()).max().unwrap_or(0);
            let took = median(20, || {
                let mut q = Query::path(&twin, &h);
                q.reply = reply;
                std::hint::black_box(ex.run(&q).unwrap());
            });
            out(format!(
                "path query {src} -> {dst} tcp 443{}: {:?}, {} branches, {} replies, at most {steps} steps in a branch, median {:.3} ms",
                if reply { " with the reply" } else { "" },
                kinds(&a),
                branches.len(),
                a.replies.len(),
                took.as_secs_f64() * 1e3
            ));
        }
    }

    if on("set") {
        let spec = SetSpec {
            src_ip: Some(vec![user_network(src_site, src_access, src_vlan)]),
            dst_ip: Some(vec![dmz_network(dst_site)]),
            protocol: Some(vec![(PROTO_TCP, PROTO_TCP), (PROTO_UDP, PROTO_UDP)]),
            ..SetSpec::default()
        };
        let query = || {
            let arena = twin.arena(None);
            Query::set(PacketSet::from_spec(&arena, &spec))
        };
        let a = ex.run(&query()).unwrap();
        let nodes: usize = a.runs.iter().map(|r| r.input.arena().local_nodes()).sum();
        let before = reset_peak();
        let took = median(5, || {
            std::hint::black_box(ex.run(&query()).unwrap());
        });
        out(format!(
            "set query {} -> {} tcp and udp: {} parts {:?}, {} branches, {nodes} nodes, median {:.3} ms, peak heap {:.1} MiB",
            user_network(src_site, src_access, src_vlan),
            dmz_network(dst_site),
            a.summary.len(),
            kinds(&a),
            a.branches().len(),
            took.as_secs_f64() * 1e3,
            mib(PEAK.load(Ordering::Relaxed) - before)
        ));
    }

    if on("table") {
        let loaded = Loaded {
            twin,
            identity: TwinJson::builtin("scale").unwrap(),
            coverage: BTreeMap::new(),
            bgp: BTreeMap::new(),
            facts: BTreeMap::new(),
            seen: Vec::new(),
            fabric: BTreeMap::new(),
            mtu: BTreeMap::new(),
            guard: BTreeMap::new(),
            tables: Default::default(),
            source: None,
        };
        let page = Selection {
            limit: Some(100),
            ..Selection::default()
        };
        let before = reset_peak();
        let t = Instant::now();
        let r = tables::show("scale", &loaded, "fib", &page).unwrap();
        let took = t.elapsed();
        let peak = PEAK.load(Ordering::Relaxed) - before;
        let held = live() - before;
        out(format!(
            "fib table, a first page of 100 rows with the build of the columns: {} rows of {}, {:.2} s, peak heap {:.1} MiB ({:.0} B per row of the table), columns held {:.1} MiB ({:.0} B per row)",
            r.rows.len(),
            r.total,
            took.as_secs_f64(),
            mib(peak),
            peak as f64 / r.total as f64,
            mib(held),
            held as f64 / r.total as f64
        ));
        let device = r.rows[0][0].as_str().unwrap_or_default().to_string();
        drop(r);
        let mut device_page = page.clone();
        device_page
            .filters
            .insert("device".into(), vec![device.clone()]);
        let sorted = Selection {
            sort: Some(vec!["-prefix".into()]),
            ..page.clone()
        };
        for (what, sel) in [
            ("a page of 100 rows".to_string(), &page),
            (
                format!("a page of 100 rows of the device {device}"),
                &device_page,
            ),
            ("a page of 100 rows sorted by -prefix".to_string(), &sorted),
        ] {
            let before = reset_peak();
            let t = Instant::now();
            let r = tables::show("scale", &loaded, "fib", sel).unwrap();
            let took = t.elapsed();
            out(format!(
                "fib table, {what}: {} rows of {}, {:.3} s, peak heap {:.1} MiB",
                r.rows.len(),
                r.total,
                took.as_secs_f64(),
                mib(PEAK.load(Ordering::Relaxed) - before)
            ));
        }
        let before = reset_peak();
        let t = Instant::now();
        let r = tables::show("scale", &loaded, "fib", &Selection::default()).unwrap();
        let rows_took = t.elapsed();
        let rows_peak = PEAK.load(Ordering::Relaxed) - before;
        let held = live() - before;
        let json = serde_json::to_vec(&r).unwrap();
        let took = t.elapsed();
        let peak = PEAK.load(Ordering::Relaxed) - before;
        out(format!(
            "fib table, all rows as JSON: {} rows, {:.1} MiB of JSON; rows {:.2} s, peak heap {:.1} MiB, answer held {:.1} MiB; with the JSON {:.2} s, peak heap {:.1} MiB ({:.0} B per row)",
            r.total,
            mib(json.len() as isize),
            rows_took.as_secs_f64(),
            mib(rows_peak),
            mib(held),
            took.as_secs_f64(),
            mib(peak),
            peak as f64 / r.total as f64
        ));
    }
}
