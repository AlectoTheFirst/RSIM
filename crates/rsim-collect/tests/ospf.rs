//! The OSPF sections of NX-OS, IOS XE and VyOS on the fake transport, with
//! the synthetic answers of `rsim-ingest/tests/fixtures/ospf/`.

#![cfg(all(feature = "nxos", feature = "iosxe", feature = "vyos"))]

use std::sync::Arc;
use std::time::Duration;

use rsim_collect::fake::FakeTransport;
use rsim_collect::*;
use rsim_ingest::bgp::Outcome;
use rsim_ingest::ospf as reader;
use rsim_routing::ospf::Version;
use rsim_store::{SectionStatus, Snapshot, Store};

#[path = "support/keys.rs"]
mod keys;

const T0: u64 = 1_700_000_000_000;

fn fixture(vendor: &str, name: &str) -> String {
    let ext = if vendor == "iosxe" { "txt" } else { "json" };
    let p = format!(
        "{}/../rsim-ingest/tests/fixtures/ospf/{vendor}/{name}.{ext}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn device(vendor: Vendor) -> Device {
    Device {
        id: "r1".into(),
        vendor,
        address: "192.0.2.10".into(),
        credential: "lab".into(),
        site: None,
        capture_bgp: CaptureBgp::Off,
        route: Default::default(),
        interval: DEFAULT_INTERVAL,
    }
}

fn specs(vendor: Vendor) -> Vec<SectionSpec> {
    match vendor {
        Vendor::Nxos => rsim_collect::nxos::sections_with(false, CaptureBgp::Off),
        Vendor::Iosxe => rsim_collect::iosxe::sections_with(CaptureBgp::Off),
        _ => rsim_collect::vyos::sections_with(CaptureBgp::Off),
    }
}

fn command(vendor: Vendor, section: &str) -> String {
    specs(vendor)
        .into_iter()
        .find(|s| s.name == section)
        .unwrap_or_else(|| panic!("no section {section}"))
        .command
}

/// The VyOS config with OSPFv2 in the main table and OSPFv3.
const VYOS_CONFIG: &str = r#"{"protocols":{"ospf":{"area":{"0":{}}},"ospfv3":{"area":{"0":{}}}}}"#;

/// The answer of each section: the OSPF fixtures and an empty answer of
/// each other section.
fn load(t: &FakeTransport, vendor: Vendor, name: &str) {
    for s in specs(vendor) {
        let answer = if rsim_collect::ospf::is_ospf(s.name) {
            continue;
        } else if s.name == "config" && vendor == Vendor::Vyos {
            VYOS_CONFIG.to_string()
        } else if matches!(s.name, "links" | "addresses" | "neighbours") {
            "[]".to_string()
        } else if s.format == rsim_store::Format::Json {
            "{}".to_string()
        } else {
            String::new()
        };
        t.reply("r1", &s.command, Ok(answer.into_bytes()));
    }
    for n in rsim_collect::ospf::V2
        .iter()
        .chain(rsim_collect::ospf::V3.iter())
    {
        set(t, vendor, n, &fixture(name, n));
    }
}

/// Sets the answer of an OSPF section. A VyOS OSPFv2 fixture holds the
/// answer of the default VRF, which the command of that VRF gives.
fn set(t: &FakeTransport, vendor: Vendor, section: &str, text: &str) {
    if vendor == Vendor::Vyos && rsim_collect::ospf::V2.contains(&section) {
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        let answer = v["default"]["answer"].to_string();
        let c = rsim_collect::ospf::frr_v2_command(section, "default").unwrap();
        t.reply("r1", &c, Ok(answer.into_bytes()));
    } else {
        t.reply(
            "r1",
            &command(vendor, section),
            Ok(text.as_bytes().to_vec()),
        );
    }
}

struct Env {
    _dir: tempfile::TempDir,
    t: Arc<FakeTransport>,
    c: Collector,
}

fn env(vendor: Vendor, name: &str) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let t = Arc::new(FakeTransport::new(Duration::from_millis(1)));
    load(&t, vendor, name);
    let store = Store::open(dir.path(), keys::keys()).unwrap();
    let source: Arc<dyn Source> = match vendor {
        Vendor::Nxos => Arc::new(rsim_collect::nxos::NxosSource::new(t.clone())),
        Vendor::Iosxe => Arc::new(rsim_collect::iosxe::IosxeSource::new(t.clone())),
        _ => Arc::new(rsim_collect::vyos::VyosSource::new(t.clone())),
    };
    let c = Collector::new(
        store,
        Box::new(vec![device(vendor)]),
        Schedule {
            spread: false,
            ..Schedule::default()
        },
        Limits::default(),
        Arc::new(TokioClock::new(T0)),
    )
    .unwrap()
    .with_source(source);
    Env { _dir: dir, t, c }
}

fn latest(e: &Env) -> Snapshot {
    e.c.store().latest().unwrap().unwrap()
}

fn status(e: &Env, section: &str) -> SectionStatus {
    latest(e).devices["r1"]
        .sections
        .iter()
        .find(|s| s.name == section)
        .unwrap()
        .status
        .clone()
}

fn read(e: &Env, vendor: &str) -> reader::DeviceOspf {
    let snap = latest(e);
    let inputs = reader::inputs(e.c.store(), &snap).unwrap();
    reader::read(vendor, &inputs["r1"])
}

/// The fixture of a section with each change of `pairs`.
fn swap(vendor: &str, section: &str, pairs: &[(&str, &str)]) -> String {
    let mut t = fixture(vendor, section);
    for (a, b) in pairs {
        assert!(t.contains(a), "{section}: {a}");
        t = t.replace(a, b);
    }
    t
}

#[tokio::test(start_paused = true)]
async fn ios_xe_stores_each_lsa_type_and_an_lsa_refresh_makes_no_snapshot() {
    let mut e = env(Vendor::Iosxe, "iosxe");
    let first = e.c.run_cycle().await.unwrap().snapshot.unwrap();
    for n in rsim_collect::ospf::V2
        .iter()
        .chain(rsim_collect::ospf::V3.iter())
    {
        assert_eq!(status(&e, n), SectionStatus::Fresh, "{n}");
    }
    let d = read(&e, "iosxe");
    assert_eq!(d.outcomes[&Version::V2].outcome, Outcome::Complete);
    assert_eq!(d.outcomes[&Version::V3].outcome, Outcome::Complete);
    assert_eq!(d.of(Version::V2, "default").next().unwrap().lsas.len(), 11);
    assert_eq!(d.of(Version::V3, "default").next().unwrap().lsas.len(), 21);

    let refresh = [
        ("LS age: 100", "LS age: 1799"),
        ("LS Seq Number: 80000001", "LS Seq Number: 80000002"),
        ("Checksum: 0x1A2B", "Checksum: 0x3C4D"),
    ];
    for n in rsim_collect::ospf::V2
        .iter()
        .chain(rsim_collect::ospf::V3.iter())
    {
        if n.contains("_lsdb_") {
            set(&e.t, Vendor::Iosxe, n, &swap("iosxe", n, &refresh));
        }
    }
    set(
        &e.t,
        Vendor::Iosxe,
        "ospf_neighbors",
        &swap("iosxe", "ospf_neighbors", &[("00:00:35", "00:00:31")]),
    );
    tokio::time::advance(Duration::from_secs(60)).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.snapshot, None, "{r:?}");
    assert_eq!(latest(&e).manifest.cycle, first);

    let router =
        fixture("iosxe", "ospf_lsdb_router").replacen("TOS 0 Metrics: 10", "TOS 0 Metrics: 30", 1);
    set(&e.t, Vendor::Iosxe, "ospf_lsdb_router", &router);
    tokio::time::advance(Duration::from_secs(60)).await;
    let r = e.c.run_cycle().await.unwrap();
    assert!(r.snapshot.is_some(), "a metric change is a change: {r:?}");
}

#[tokio::test(start_paused = true)]
async fn a_refused_command_fails_and_a_missing_feature_is_not_captured() {
    let mut e = env(Vendor::Iosxe, "iosxe");
    set(
        &e.t,
        Vendor::Iosxe,
        "ospf_lsdb_router",
        "% Permission denied\n",
    );
    for n in rsim_collect::ospf::V3 {
        e.t.reply(
            "r1",
            &command(Vendor::Iosxe, n),
            Ok(b"% Invalid input detected at '^' marker.\n".to_vec()),
        );
    }
    e.c.run_cycle().await.unwrap();
    assert!(!matches!(
        status(&e, "ospf_lsdb_router"),
        SectionStatus::Fresh
    ));
    assert!(matches!(
        status(&e, "ospfv3_lsdb_router"),
        SectionStatus::Absent { .. }
    ));
    let d = read(&e, "iosxe");
    assert_eq!(d.outcomes[&Version::V2].outcome, Outcome::Failed);
    assert_eq!(d.outcomes[&Version::V3].outcome, Outcome::NotCaptured);
}

#[tokio::test(start_paused = true)]
async fn nx_os_json_ages_and_sequence_numbers_make_no_snapshot() {
    let mut e = env(Vendor::Nxos, "nxos");
    let first = e.c.run_cycle().await.unwrap().snapshot.unwrap();
    let d = read(&e, "nxos");
    assert_eq!(d.outcomes[&Version::V2].outcome, Outcome::Complete);
    assert_eq!(d.outcomes[&Version::V3].outcome, Outcome::Complete);
    for n in rsim_collect::ospf::V2
        .iter()
        .chain(rsim_collect::ospf::V3.iter())
    {
        if n.contains("_lsdb_") {
            let t = swap(
                "nxos",
                n,
                &[
                    ("\"age\": \"100\"", "\"age\": \"1799\""),
                    ("\"seqno\": \"0x80000001\"", "\"seqno\": \"0x80000002\""),
                ],
            );
            set(&e.t, Vendor::Nxos, n, &t);
        }
    }
    tokio::time::advance(Duration::from_secs(60)).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.snapshot, None, "{r:?}");
    assert_eq!(latest(&e).manifest.cycle, first);
}

#[tokio::test(start_paused = true)]
async fn vyos_combines_the_vrfs_of_the_config_and_reads_ospfv3() {
    let mut e = env(Vendor::Vyos, "vyos");
    e.c.run_cycle().await.unwrap().snapshot.unwrap();
    let d = read(&e, "vyos");
    assert_eq!(
        d.outcomes[&Version::V2].outcome,
        Outcome::Complete,
        "{:?}",
        d.outcomes
    );
    assert_eq!(
        d.outcomes[&Version::V3].outcome,
        Outcome::Complete,
        "{:?}",
        d.outcomes
    );
    assert_eq!(d.of(Version::V2, "default").next().unwrap().lsas.len(), 11);
    assert_eq!(d.of(Version::V3, "default").next().unwrap().lsas.len(), 21);
}

#[tokio::test(start_paused = true)]
async fn vyos_ages_and_sequence_numbers_make_no_snapshot() {
    let mut e = env(Vendor::Vyos, "vyos");
    let first = e.c.run_cycle().await.unwrap().snapshot.unwrap();
    for n in rsim_collect::ospf::V2 {
        if n.contains("_lsdb_") {
            let t = swap(
                "vyos",
                n,
                &[
                    ("\"lsaAge\": 100", "\"lsaAge\": 1799"),
                    (
                        "\"lsaSeqNumber\": \"80000001\"",
                        "\"lsaSeqNumber\": \"80000002\"",
                    ),
                    ("\"checksum\": \"1a2b\"", "\"checksum\": \"3c4d\""),
                ],
            );
            set(&e.t, Vendor::Vyos, n, &t);
        }
    }
    for n in rsim_collect::ospf::V3 {
        if n.contains("_lsdb_") {
            let t = swap(
                "vyos",
                n,
                &[
                    ("\"age\": 100", "\"age\": 1799"),
                    (
                        "\"lsSequenceNumber\": 2147483649",
                        "\"lsSequenceNumber\": 2147483650",
                    ),
                    ("\"checksum\": 6699", "\"checksum\": 7000"),
                ],
            );
            set(&e.t, Vendor::Vyos, n, &t);
        }
    }
    tokio::time::advance(Duration::from_secs(60)).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.snapshot, None, "{r:?}");
    assert_eq!(latest(&e).manifest.cycle, first);
}
