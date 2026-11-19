//! The classify and hash stage of one VyOS router, and a cycle of 10,000
//! routers with no change on a fake transport with no delay.

use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use rsim_collect::fake::FakeTransport;
use rsim_collect::vyos::{VyosSource, sections};
use rsim_collect::*;
use rsim_store::{Keys, Store};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/vyos/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn file(section: &str) -> &'static str {
    match section {
        "config" => "config.json",
        "version" => "version.txt",
        "links" => "links.json",
        "addresses" => "addresses.json",
        "neighbours" => "neighbours.json",
        "link_speeds" => "speeds.txt",
        "routes_ipv4" => "routes_ipv4.json",
        "bgp_sessions" => "bgp_sessions.json",
        _ => "routes_ipv6.json",
    }
}

fn device(id: &str) -> Device {
    Device {
        id: id.into(),
        vendor: Vendor::Vyos,
        address: "192.0.2.1".into(),
        credential: "lab".into(),
        site: None,
        capture_bgp: Default::default(),
        route: Default::default(),
    }
}

fn capture(id: &str) -> Capture {
    Capture {
        device: device(id),
        collected_at: 1,
        sections: sections()
            .into_iter()
            .map(|spec| RawSection {
                result: Ok(fixture(file(spec.name))),
                spec,
            })
            .collect(),
    }
}

fn classify_bench(c: &mut Criterion) {
    let keys = Keys::new([1; 32], [2; 32]);
    let cap = capture("r1");
    let none = |_: &rsim_store::Hash| None;
    let first = classify(&keys, &cap, None, false, &none);
    let prev = rsim_store::DeviceManifest {
        device: "r1".into(),
        vendor: "vyos".into(),
        collected_at: 1,
        sections: first.sections.clone(),
        tables: Default::default(),
        management_address: None,
    };
    c.bench_function("classify_unchanged", |b| {
        b.iter(|| classify(&keys, &cap, Some(&prev), false, &none))
    });
    c.bench_function("classify_new", |b| {
        b.iter(|| classify(&keys, &cap, None, false, &none))
    });
}

fn cycle_bench(c: &mut Criterion) {
    const N: usize = 10_000;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let t = Arc::new(FakeTransport::new(Duration::ZERO));
    let devices: Vec<Device> = (0..N).map(|i| device(&format!("r{i:05}"))).collect();
    for d in &devices {
        for s in sections() {
            t.reply(&d.id, &s.command, Ok(fixture(file(s.name))));
        }
    }
    let store = Store::open(dir.path(), Keys::new([1; 32], [2; 32])).unwrap();
    let schedule = Schedule {
        interval: Duration::ZERO,
        full_interval: Duration::from_secs(1 << 30),
        ..Schedule::default()
    };
    let mut col = Collector::new(
        store,
        Box::new(devices),
        schedule,
        Limits::default(),
        Arc::new(TokioClock::system()),
    )
    .unwrap()
    .with_source(Arc::new(VyosSource::new(t)));
    let start = Instant::now();
    let first = rt.block_on(col.run_cycle()).unwrap();
    assert_eq!(first.changed.len(), N);
    eprintln!("first cycle of {N} routers: {:?}", start.elapsed());
    let mut g = c.benchmark_group("cycle");
    g.sample_size(10);
    g.bench_function("10k_unchanged", |b| {
        b.iter(|| {
            let r = rt.block_on(col.run_cycle()).unwrap();
            assert_eq!((r.due, r.snapshot), (N, None));
        })
    });
    g.finish();
}

criterion_group!(benches, classify_bench, cycle_bench);
criterion_main!(benches);
