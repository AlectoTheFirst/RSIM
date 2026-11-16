//! Collection cycles on fake transports: the first snapshot, a cycle with
//! no change, volatile changes, the forced full collection, the change of
//! each class, failed reads, a failed half of a table, an extract error,
//! the limits of concurrency and the sink.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use arrow_array::{Array, BooleanArray, RecordBatch, StringArray, UInt64Array};
use rsim_collect::fake::FakeTransport;
use rsim_collect::unifi::UnifiSource;
use rsim_collect::vyos::VyosSource;
use rsim_collect::*;
use rsim_store::{Class, Keys, SectionStatus, Snapshot, Store, TableSchema, table};

const T0: u64 = 1_700_000_000_000;
const MINUTE: Duration = Duration::from_secs(60);

fn fixture(path: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/{path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn vyos(id: &str) -> Device {
    Device {
        id: id.into(),
        vendor: Vendor::Vyos,
        address: "192.0.2.1".into(),
        credential: "lab".into(),
        site: None,
        route: Default::default(),
    }
}

fn site(id: &str) -> Device {
    Device {
        id: id.into(),
        vendor: Vendor::Unifi,
        address: "192.0.2.5".into(),
        credential: "lab".into(),
        site: Some("default".into()),
        route: Default::default(),
    }
}

fn vyos_file(section: &str) -> &'static str {
    match section {
        "config" => "vyos/config.json",
        "version" => "vyos/version.txt",
        "links" => "vyos/links.json",
        "addresses" => "vyos/addresses.json",
        "neighbours" => "vyos/neighbours.json",
        "link_speeds" => "vyos/speeds.txt",
        "routes_ipv4" => "vyos/routes_ipv4.json",
        "routes_ipv6" => "vyos/routes_ipv6.json",
        s => panic!("no fixture for {s}"),
    }
}

fn command(d: &Device, section: &str) -> String {
    let specs = match d.vendor {
        Vendor::Vyos => rsim_collect::vyos::sections(),
        Vendor::Unifi => rsim_collect::unifi::sections(d.site.as_deref().unwrap()),
        Vendor::Nxos => unreachable!("the NX-OS cycles are in tests/nxos.rs"),
    };
    specs
        .into_iter()
        .find(|s| s.name == section)
        .unwrap()
        .command
}

fn set(t: &FakeTransport, d: &Device, section: &str, bytes: Vec<u8>) {
    t.reply(&d.id, &command(d, section), Ok(bytes));
}

fn load(t: &FakeTransport, d: &Device) {
    match d.vendor {
        Vendor::Vyos => {
            for s in rsim_collect::vyos::sections() {
                let mut b = fixture(vyos_file(s.name));
                if s.name == "config" {
                    b = String::from_utf8(b)
                        .unwrap()
                        .replace("HOST", &d.id)
                        .into_bytes();
                }
                set(t, d, s.name, b);
            }
        }
        Vendor::Unifi => {
            let files = [
                ("devices", "unifi/stat_device.json"),
                ("networks", "unifi/networkconf.json"),
                ("port_profiles", "unifi/portconf.json"),
                ("wlans", "unifi/wlanconf.json"),
                ("clients", "unifi/stat_sta.json"),
                ("firewall_rules", "unifi/firewallrule.json"),
                ("firewall_groups", "unifi/firewallgroup.json"),
            ];
            for (s, f) in files {
                set(t, d, s, fixture(f));
            }
            for s in ["firewall_zones", "firewall_policies"] {
                t.reply(
                    &d.id,
                    &command(d, s),
                    Err(TransportError::NotFound("HTTP 404".into())),
                );
            }
        }
        Vendor::Nxos => unreachable!("the NX-OS cycles are in tests/nxos.rs"),
    }
}

type Changes = Vec<(String, Vec<Class>)>;

#[derive(Default)]
struct Recorder(Mutex<Vec<(u64, Changes)>>);

impl Sink for Recorder {
    fn changed(&self, snapshot: u64, devices: &[(String, Vec<Class>)]) {
        self.0.lock().unwrap().push((snapshot, devices.to_vec()));
    }
}

struct Env {
    dir: tempfile::TempDir,
    t: Arc<FakeTransport>,
    sink: Arc<Recorder>,
    c: Collector,
    devices: Vec<Device>,
}

fn keys() -> Keys {
    Keys::new([1; 32], [2; 32])
}

fn env(devices: Vec<Device>, limits: Limits) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let t = Arc::new(FakeTransport::new(Duration::from_millis(5)));
    for d in &devices {
        load(&t, d);
    }
    let sink = Arc::new(Recorder::default());
    let store = Store::open(dir.path(), keys()).unwrap();
    let c = Collector::new(
        store,
        Box::new(devices.clone()),
        Schedule {
            spread: false,
            ..Schedule::default()
        },
        limits,
        Arc::new(TokioClock::new(T0)),
    )
    .unwrap()
    .with_source(Arc::new(VyosSource::new(t.clone())))
    .with_source(Arc::new(UnifiSource::new(t.clone())))
    .with_sink(sink.clone());
    Env {
        dir,
        t,
        sink,
        c,
        devices,
    }
}

fn files(e: &Env) -> usize {
    fn walk(p: &std::path::Path) -> usize {
        std::fs::read_dir(p)
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                if p.is_dir() { walk(&p) } else { 1 }
            })
            .sum()
    }
    walk(e.dir.path())
}

fn latest(e: &Env) -> Snapshot {
    e.c.store().latest().unwrap().unwrap()
}

/// The cells of the rows of one device in a table, as text.
fn rows(e: &Env, t: &TableSchema, device: &str) -> Vec<Vec<String>> {
    let s = latest(e);
    let all = e.c.store().read_table(&s, t).unwrap();
    let Some((_, b)) = all.into_iter().find(|(d, _)| d == device) else {
        return Vec::new();
    };
    text(&b, t)
}

fn text(b: &RecordBatch, t: &TableSchema) -> Vec<Vec<String>> {
    (0..b.num_rows())
        .map(|i| {
            t.columns
                .iter()
                .map(|c| {
                    let a = b.column_by_name(c.name).unwrap();
                    if a.is_null(i) {
                        return "-".to_string();
                    }
                    let any = a.as_any();
                    if let Some(x) = any.downcast_ref::<StringArray>() {
                        x.value(i).to_string()
                    } else if let Some(x) = any.downcast_ref::<UInt64Array>() {
                        x.value(i).to_string()
                    } else {
                        any.downcast_ref::<BooleanArray>()
                            .unwrap()
                            .value(i)
                            .to_string()
                    }
                })
                .collect()
        })
        .collect()
}

fn row(cells: &[&str]) -> Vec<String> {
    cells.iter().map(|s| s.to_string()).collect()
}

#[tokio::test(start_paused = true)]
async fn the_first_cycle_stores_all_devices_and_their_tables() {
    let mut e = env(
        vec![vyos("r1"), vyos("r2"), site("site-a")],
        Limits::default(),
    );
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!((r.due, r.snapshot), (3, Some(0)));
    assert!(r.failed.is_empty() && r.extract_errors.is_empty(), "{r:?}");
    let all = vec![Class::Configuration, Class::Observation];
    let want: Vec<(String, Vec<Class>)> = ["r1", "r2", "site-a"]
        .iter()
        .map(|d| (d.to_string(), all.clone()))
        .collect();
    assert_eq!(r.changed, want);
    assert_eq!(e.sink.0.lock().unwrap().clone(), vec![(0, want)]);

    let s = latest(&e);
    assert!(s.manifest.checkpoint);
    let site = &s.devices["site-a"];
    let zones = site.section("firewall_zones").unwrap();
    assert!(matches!(zones.status, SectionStatus::Absent { .. }));
    assert!(zones.blob.is_none());
    let cfg = s.devices["r1"].section("config").unwrap();
    let raw = e.c.store().read_blob(&cfg.blob.unwrap()).unwrap();
    assert!(
        String::from_utf8(raw)
            .unwrap()
            .contains("\"host-name\":\"r1\"")
    );

    let t = |n| table(n).unwrap();
    assert_eq!(
        rows(&e, t("neighbours"), "r1"),
        vec![
            row(&["eth0", "192.0.2.10", "00:00:5e:00:53:10", "REACHABLE"]),
            row(&["eth1", "198.51.100.254", "00:00:5e:00:53:fe", "STALE"]),
            row(&["eth0", "2001:db8:1::10", "00:00:5e:00:53:10", "DELAY"]),
            row(&["eth0", "192.0.2.99", "-", "FAILED"]),
        ]
    );
    assert_eq!(
        rows(&e, t("routes"), "r2"),
        vec![
            row(&[
                "blue",
                "203.0.113.0/26",
                "connected",
                "true",
                "0",
                "0",
                "-",
                "eth1.10"
            ]),
            row(&[
                "default",
                "0.0.0.0/0",
                "static",
                "true",
                "1",
                "0",
                "198.51.100.254",
                "eth1"
            ]),
            row(&[
                "default",
                "192.0.2.0/24",
                "connected",
                "true",
                "0",
                "0",
                "-",
                "eth0"
            ]),
            row(&[
                "default",
                "2001:db8:1::/64",
                "connected",
                "true",
                "0",
                "0",
                "-",
                "eth0"
            ]),
        ]
    );
    assert_eq!(
        rows(&e, t("links"), "r1")[3],
        row(&[
            "eth1.10",
            "00:00:5e:00:53:02",
            "1500",
            "true",
            "UP",
            "eth1",
            "10"
        ])
    );
    assert_eq!(
        rows(&e, t("link_speeds"), "r1")[0],
        row(&["eth0", "1000", "full"])
    );
    assert_eq!(rows(&e, t("link_speeds"), "r1")[3], row(&["lo", "-", "-"]));
    assert_eq!(rows(&e, t("addresses"), "r1").len(), 4);
    assert_eq!(
        rows(&e, t("clients"), "site-a"),
        vec![
            row(&[
                "00:00:5e:00:53:c1",
                "192.0.2.50",
                "laptop-1",
                "Default",
                "-",
                "false",
                "00:00:5e:00:53:b1",
                "-",
                "-"
            ]),
            row(&[
                "00:00:5e:00:53:c2",
                "192.0.2.51",
                "printer",
                "Default",
                "-",
                "true",
                "-",
                "00:00:5e:00:53:a1",
                "1"
            ]),
            row(&[
                "00:00:5e:00:53:c3",
                "-",
                "-",
                "Guest",
                "10",
                "false",
                "00:00:5e:00:53:b1",
                "-",
                "-"
            ]),
        ]
    );
    assert_eq!(e.devices.len(), 3);
}

#[tokio::test(start_paused = true)]
async fn volatile_changes_write_nothing_until_the_forced_full_collection() {
    let mut e = env(vec![vyos("r1"), site("site-a")], Limits::default());
    e.c.run_cycle().await.unwrap();
    let before = files(&e);
    // A cycle before the interval has no due device.
    assert_eq!(e.c.run_cycle().await.unwrap().due, 0);

    // Only volatile fields and lines change.
    let r1 = vyos("r1");
    let st = site("site-a");
    let version = String::from_utf8(fixture("vyos/version.txt")).unwrap();
    set(
        &e.t,
        &r1,
        "version",
        version.replace("1 day", "2 days").into_bytes(),
    );
    let sta = String::from_utf8(fixture("unifi/stat_sta.json")).unwrap();
    let sta = sta
        .replace("\"signal\":-50", "\"signal\":-71")
        .replace("\"uptime\":100", "\"uptime\":160");
    set(&e.t, &st, "clients", sta.into_bytes());
    let neigh = String::from_utf8(fixture("vyos/neighbours.json")).unwrap();
    set(
        &e.t,
        &r1,
        "neighbours",
        neigh.replace("REACHABLE", "STALE").into_bytes(),
    );
    for _ in 0..14 {
        tokio::time::advance(MINUTE).await;
        let r = e.c.run_cycle().await.unwrap();
        assert_eq!((r.due, r.snapshot), (2, None), "{r:?}");
        assert_eq!(files(&e), before);
    }
    // 15 minutes after the first collection, the collection is forced.
    tokio::time::advance(MINUTE).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.snapshot, Some(1));
    // The new content is stored, and it causes no work.
    assert!(r.changed.is_empty(), "{r:?}");
    assert!(e.sink.0.lock().unwrap().len() == 1);
    let s = latest(&e);
    let v = s.devices["r1"].section("version").unwrap();
    let raw = String::from_utf8(e.c.store().read_blob(&v.blob.unwrap()).unwrap()).unwrap();
    assert!(raw.contains("2 days"));
    assert_eq!(rows(&e, table("neighbours").unwrap(), "r1")[0][3], "STALE");
    assert_eq!(e.t.calls(), 16 * (8 + 9));
}

#[tokio::test(start_paused = true)]
async fn a_change_of_each_class_is_reported_with_its_class() {
    let mut e = env(vec![vyos("r1"), vyos("r2")], Limits::default());
    e.c.run_cycle().await.unwrap();
    let cfg = String::from_utf8(fixture("vyos/config.json")).unwrap();
    set(
        &e.t,
        &vyos("r1"),
        "config",
        cfg.replace("HOST", "r1-new").into_bytes(),
    );
    let neigh = String::from_utf8(fixture("vyos/neighbours.json")).unwrap();
    set(
        &e.t,
        &vyos("r2"),
        "neighbours",
        neigh.replace("192.0.2.10", "192.0.2.11").into_bytes(),
    );
    tokio::time::advance(MINUTE).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(
        r.changed,
        vec![
            ("r1".into(), vec![Class::Configuration]),
            ("r2".into(), vec![Class::Observation])
        ]
    );
    let s = latest(&e);
    assert!(!s.manifest.checkpoint);
    assert_eq!(s.manifest.devices.len(), 2);
    // The rows of r1 stay in the first file, and r2 has new rows.
    assert_eq!(s.devices["r1"].tables["neighbours"].cycle, 0);
    assert_eq!(s.devices["r2"].tables["neighbours"].cycle, 1);
    assert_eq!(
        rows(&e, table("neighbours").unwrap(), "r2")[0][1],
        "192.0.2.11"
    );
}

#[tokio::test(start_paused = true)]
async fn a_failed_device_keeps_its_data_and_backs_off() {
    let mut e = env(vec![vyos("r1"), vyos("r2")], Limits::default());
    e.c.run_cycle().await.unwrap();
    let neigh_before = rows(&e, table("neighbours").unwrap(), "r1");
    e.t.clear("r1");
    tokio::time::advance(MINUTE).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.failed, vec!["r1".to_string()]);
    assert_eq!(r.snapshot, Some(1));
    assert!(r.changed.is_empty());
    let s = latest(&e);
    for sec in &s.devices["r1"].sections {
        assert!(matches!(sec.status, SectionStatus::Old { .. }), "{sec:?}");
        assert!(sec.blob.is_some());
    }
    assert_eq!(rows(&e, table("neighbours").unwrap(), "r1"), neigh_before);
    assert_eq!(e.c.scheduler().failures("r1"), 1);

    // r1 waits for its backoff. A second failure writes nothing.
    tokio::time::advance(MINUTE).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!((r.due, r.snapshot), (2, None));
    assert_eq!(e.c.scheduler().failures("r1"), 2);
    tokio::time::advance(MINUTE).await;
    assert_eq!(e.c.run_cycle().await.unwrap().due, 1);

    // After a recovery, the sections are fresh again with their old blobs.
    load(&e.t, &vyos("r1"));
    tokio::time::advance(MINUTE).await;
    let r = e.c.run_cycle().await.unwrap();
    assert!(r.failed.is_empty() && r.changed.is_empty(), "{r:?}");
    let s = latest(&e);
    assert!(
        s.devices["r1"]
            .sections
            .iter()
            .all(|x| x.status == SectionStatus::Fresh)
    );
}

#[tokio::test(start_paused = true)]
async fn a_table_with_a_failed_section_keeps_the_rows_of_its_old_blob() {
    let mut e = env(vec![vyos("r1")], Limits::default());
    e.c.run_cycle().await.unwrap();
    let d = vyos("r1");
    e.t.reply(
        &d.id,
        &command(&d, "routes_ipv6"),
        Err(TransportError::Timeout),
    );
    let v4 = String::from_utf8(fixture("vyos/routes_ipv4.json")).unwrap();
    set(
        &e.t,
        &d,
        "routes_ipv4",
        v4.replace(
            "\"metric\":0,\"uptime\":\"01:02:03\",\"nexthops\":[{\"ip\"",
            "\"metric\":5,\"uptime\":\"01:02:03\",\"nexthops\":[{\"ip\"",
        )
        .into_bytes(),
    );
    tokio::time::advance(MINUTE).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.changed, vec![("r1".into(), vec![Class::Observation])]);
    let routes = rows(&e, table("routes").unwrap(), "r1");
    assert_eq!(routes.len(), 4);
    let default = routes.iter().find(|r| r[1] == "0.0.0.0/0").unwrap();
    assert_eq!(default[5], "5");
    assert_eq!(routes[3][1], "2001:db8:1::/64");
}

#[tokio::test(start_paused = true)]
async fn an_extract_error_is_reported_and_the_table_keeps_its_rows() {
    let mut e = env(vec![vyos("r1")], Limits::default());
    e.c.run_cycle().await.unwrap();
    let before = rows(&e, table("neighbours").unwrap(), "r1");
    set(
        &e.t,
        &vyos("r1"),
        "neighbours",
        br#"{"not": "an array"}"#.to_vec(),
    );
    tokio::time::advance(MINUTE).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.extract_errors.len(), 1, "{r:?}");
    assert_eq!(r.extract_errors[0].1, "neighbours");
    assert_eq!(rows(&e, table("neighbours").unwrap(), "r1"), before);
}

#[tokio::test(start_paused = true)]
async fn the_limits_bound_the_devices_in_flight() {
    let devices: Vec<Device> = (0..40).map(|i| vyos(&format!("r{i:02}"))).collect();
    let limits = Limits {
        devices: 4,
        per_vendor: 3,
        channel: 2,
        ..Limits::default()
    };
    let mut e = env(devices, limits);
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!((r.due, r.changed.len()), (40, 40));
    assert_eq!(e.t.max_devices(), 3);
    assert_eq!(e.t.max_per_device(), 8);
}

#[tokio::test(start_paused = true)]
async fn a_collector_continues_from_the_store() {
    let mut e = env(vec![vyos("r1")], Limits::default());
    e.c.run_cycle().await.unwrap();
    let store = Store::open(e.dir.path(), keys()).unwrap();
    let mut c = Collector::new(
        store,
        Box::new(vec![vyos("r1")]),
        Schedule::default(),
        Limits::default(),
        Arc::new(TokioClock::new(T0 + 60_000)),
    )
    .unwrap()
    .with_source(Arc::new(VyosSource::new(e.t.clone())));
    // The new collector forces its first collection. The content is the
    // same, so only the device manifest is new.
    let r = c.run_cycle().await.unwrap();
    assert_eq!(r.snapshot, Some(1));
    assert!(r.changed.is_empty(), "{r:?}");
}

/// This test uses real time. With paused time, the runtime moves the time
/// to the stop timer while a cycle waits for the store thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_collects_at_each_interval_until_it_stops() {
    let dir = tempfile::tempdir().unwrap();
    let t = Arc::new(FakeTransport::new(Duration::ZERO));
    load(&t, &vyos("r1"));
    let interval = Duration::from_millis(300);
    let mut c = Collector::new(
        Store::open(dir.path(), keys()).unwrap(),
        Box::new(vec![vyos("r1")]),
        Schedule {
            interval,
            ..Schedule::default()
        },
        Limits::default(),
        Arc::new(TokioClock::new(T0)),
    )
    .unwrap()
    .with_source(Arc::new(VyosSource::new(t.clone())));
    // Stop after 4 cycles that each read the 8 sections.
    let calls = t.clone();
    let stop = async move {
        while calls.calls() < 4 * 8 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    let start = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(60), c.run(stop))
        .await
        .expect("4 cycles run in 60 s")
        .unwrap();
    // The 4th cycle starts no earlier than 3 intervals after the first.
    assert!(start.elapsed() >= 3 * interval, "{:?}", start.elapsed());
    assert_eq!(c.store().head().unwrap(), Some(0));
}
