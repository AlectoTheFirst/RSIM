//! Collection cycles of an IOS XR router on the fake transport, with the
//! synthetic answers in `tests/fixtures/iosxr/`.

#![cfg(feature = "iosxr")]

use std::sync::Arc;
use std::time::Duration;

use rsim_collect::fake::FakeTransport;
use rsim_collect::iosxr::{IosxrSource, sections};
use rsim_collect::*;
use rsim_store::{Keys, SectionStatus, Snapshot, Store};

const T0: u64 = 1_700_000_000_000;

fn fixture(name: &str) -> String {
    let p = format!("{}/tests/fixtures/iosxr/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn router() -> Device {
    Device {
        id: "x1".into(),
        vendor: Vendor::Iosxr,
        address: "192.0.2.10".into(),
        credential: "lab".into(),
        site: None,
        route: Default::default(),
    }
}

/// The fixture of each section that has one. The other commands are
/// refused as on a router with no such feature.
fn file(section: &str) -> Option<&'static str> {
    Some(match section {
        "config" => "config.txt",
        "version" => "version.txt",
        "interfaces" => "interfaces.txt",
        "lldp" => "lldp.txt",
        "vrfs" => "vrfs.txt",
        "rib" => "rib.txt",
        _ => return None,
    })
}

fn command(section: &str) -> String {
    sections()
        .into_iter()
        .find(|s| s.name == section)
        .unwrap()
        .command
}

fn set(t: &FakeTransport, section: &str, text: &str) {
    t.reply("x1", &command(section), Ok(text.as_bytes().to_vec()));
}

fn load(t: &FakeTransport) {
    for s in sections() {
        match file(s.name) {
            Some(f) => set(t, s.name, &fixture(f).replace("HOST", "x1")),
            None => t.reply(
                "x1",
                &s.command,
                Err(TransportError::Command(
                    "% Invalid input detected at '^' marker.".into(),
                )),
            ),
        }
    }
}

struct Env {
    _dir: tempfile::TempDir,
    t: Arc<FakeTransport>,
    c: Collector,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let t = Arc::new(FakeTransport::new(Duration::from_millis(1)));
    load(&t);
    let store = Store::open(dir.path(), Keys::new([1; 32], [2; 32])).unwrap();
    let c = Collector::new(
        store,
        Box::new(vec![router()]),
        Schedule {
            spread: false,
            ..Schedule::default()
        },
        Limits::default(),
        Arc::new(TokioClock::new(T0)),
    )
    .unwrap()
    .with_source(Arc::new(IosxrSource::new(t.clone())));
    Env { _dir: dir, t, c }
}

fn latest(e: &Env) -> Snapshot {
    e.c.store().latest().unwrap().unwrap()
}

fn status(e: &Env, section: &str) -> SectionStatus {
    latest(e).devices["x1"]
        .sections
        .iter()
        .find(|s| s.name == section)
        .unwrap()
        .status
        .clone()
}

#[tokio::test(start_paused = true)]
async fn the_first_cycle_keeps_each_text_answer() {
    let mut e = env();
    let r = e.c.run_cycle().await.unwrap();
    assert!(r.snapshot.is_some() && r.failed.is_empty(), "{r:?}");
    for s in ["config", "version", "interfaces", "lldp", "vrfs", "rib"] {
        assert_eq!(status(&e, s), SectionStatus::Fresh, "{s}");
    }
    for s in ["cdp", "arp", "inventory", "hsrp"] {
        assert!(matches!(status(&e, s), SectionStatus::Absent { .. }), "{s}");
    }
}

#[tokio::test(start_paused = true)]
async fn the_time_lines_make_no_snapshot_and_a_config_change_makes_one() {
    let mut e = env();
    let first = e.c.run_cycle().await.unwrap().snapshot.unwrap();
    let swap = |f: &str, a: &str, b: &str| fixture(f).replace("HOST", "x1").replace(a, b);
    for (s, f) in [
        ("config", "config.txt"),
        ("version", "version.txt"),
        ("rib", "rib.txt"),
        ("interfaces", "interfaces.txt"),
    ] {
        set(&e.t, s, &swap(f, "10:00:00.000", "10:01:00.000"));
    }
    set(
        &e.t,
        "config",
        &swap("config.txt", "10:00:00.000", "10:01:00.000").replace("09:58:12", "10:00:59"),
    );
    tokio::time::advance(Duration::from_secs(60)).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.snapshot, None, "{r:?}");
    assert_eq!(latest(&e).manifest.cycle, first);

    set(
        &e.t,
        "config",
        &swap("config.txt", "description to-core", "description to-core-2"),
    );
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(e.c.run_cycle().await.unwrap().snapshot.is_some());
}
