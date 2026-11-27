//! Collection cycles on fake transports: the first snapshot, a cycle with
//! no change, volatile changes, the forced full collection, the change of
//! each class, failed reads, a failed half of a table, an extract error,
//! the limits of concurrency, the time limits of a device, the sink, a
//! device that leaves the inventory and the inventory version of a
//! reconfigured collector.

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
        capture_bgp: Default::default(),
        route: Default::default(),
        interval: DEFAULT_INTERVAL,
    }
}

fn site(id: &str) -> Device {
    Device {
        id: id.into(),
        vendor: Vendor::Unifi,
        address: "192.0.2.5".into(),
        credential: "lab".into(),
        site: Some("default".into()),
        capture_bgp: Default::default(),
        route: Default::default(),
        interval: DEFAULT_INTERVAL,
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
        "bgp_sessions" => "vyos/bgp_sessions.json",
        s => panic!("no fixture for {s}"),
    }
}

fn command(d: &Device, section: &str) -> String {
    let specs = match d.vendor {
        Vendor::Vyos => rsim_collect::vyos::sections(),
        Vendor::Unifi => rsim_collect::unifi::sections(d.site.as_deref().unwrap()),
        Vendor::Nxos | Vendor::Iosxr | Vendor::Iosxe | Vendor::Velocloud | Vendor::Equinix => {
            unreachable!("these vendors have their own cycle tests")
        }
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
                if rsim_collect::ospf::is_ospf(s.name) {
                    continue;
                }
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
        Vendor::Nxos | Vendor::Iosxr | Vendor::Iosxe | Vendor::Velocloud | Vendor::Equinix => {
            unreachable!("these vendors have their own cycle tests")
        }
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

/// The store keys of the tests, made one time in each test process.
fn keys() -> Keys {
    static KEYS: std::sync::OnceLock<([u8; 32], [u8; 32])> = std::sync::OnceLock::new();
    let (hash, wrap) = KEYS.get_or_init(|| {
        let mut bytes = [[0u8; 32]; 2];
        for b in &mut bytes {
            getrandom::fill(b).unwrap();
        }
        (bytes[0], bytes[1])
    });
    Keys::new(*hash, *wrap)
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
    // Each manifest records the address to which the collector connected.
    assert_eq!(
        s.devices["r1"].management_address.as_deref(),
        Some("192.0.2.1")
    );
    assert_eq!(site.management_address.as_deref(), Some("192.0.2.5"));
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
    assert_eq!(e.t.calls(), 16 * (9 + 9));
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
async fn a_device_that_the_collector_does_not_reach_keeps_its_previous_address() {
    // With no previous manifest, a failed device records no address.
    let mut e = env(vec![vyos("r1"), vyos("r2")], Limits::default());
    e.t.clear("r1");
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.failed, vec!["r1".to_string()]);
    let s = latest(&e);
    assert_eq!(s.devices["r1"].management_address, None);
    assert_eq!(
        s.devices["r2"].management_address.as_deref(),
        Some("192.0.2.1")
    );

    // A device that fails after a good cycle keeps the address of its
    // previous manifest.
    let mut e = env(vec![vyos("r1"), vyos("r2")], Limits::default());
    e.c.run_cycle().await.unwrap();
    e.t.clear("r1");
    tokio::time::advance(MINUTE).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.failed, vec!["r1".to_string()]);
    assert_eq!(r.snapshot, Some(1));
    let s = latest(&e);
    assert!(
        s.devices["r1"]
            .sections
            .iter()
            .all(|sec| matches!(sec.status, SectionStatus::Old { .. }))
    );
    assert_eq!(
        s.devices["r1"].management_address.as_deref(),
        Some("192.0.2.1")
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
    assert_eq!(e.t.max_per_device(), 9);
}

#[tokio::test(start_paused = true)]
async fn the_time_limits_of_a_device_replace_the_limits_of_the_cycle() {
    let devices = vec![vyos("r1"), vyos("r2"), vyos("r3")];
    let dir = tempfile::tempdir().unwrap();
    let t = Arc::new(FakeTransport::new(Duration::from_secs(15)));
    for d in &devices {
        load(&t, d);
    }
    let store = Store::open(dir.path(), keys()).unwrap();
    let mut c = Collector::new(
        store,
        Box::new(devices),
        Schedule {
            spread: false,
            ..Schedule::default()
        },
        Limits::default(),
        Arc::new(TokioClock::new(T0)),
    )
    .unwrap()
    .with_source(Arc::new(VyosSource::new(t.clone())))
    .with_time_limits(
        "r1",
        TimeLimits {
            section: Duration::from_secs(10),
            device: Duration::from_secs(45),
        },
    )
    .with_time_limits(
        "r2",
        TimeLimits {
            section: Duration::from_secs(20),
            device: Duration::from_secs(10),
        },
    );
    let start = tokio::time::Instant::now();
    let r = c.run_cycle().await.unwrap();
    assert_eq!(start.elapsed(), Duration::from_secs(15));
    assert_eq!(r.failed, ["r1", "r2"]);
    let s = c.store().latest().unwrap().unwrap();
    for d in ["r1", "r2"] {
        assert!(
            s.devices[d]
                .sections
                .iter()
                .all(|x| matches!(x.status, SectionStatus::Missing { .. })),
            "{d}"
        );
    }
    assert!(
        s.devices["r3"]
            .sections
            .iter()
            .all(|x| x.status == SectionStatus::Fresh)
    );
}

#[tokio::test(start_paused = true)]
async fn two_devices_with_one_id_stop_the_cycle_before_a_fetch() {
    let other = Device {
        address: "192.0.2.2".into(),
        ..vyos("r1")
    };
    let mut e = env(vec![vyos("r1"), other], Limits::default());
    let err = e.c.run_cycle().await.unwrap_err();
    assert!(matches!(err, CollectError::Inventory(_)), "{err}");
    assert!(err.to_string().contains("r1"), "{err}");
    assert_eq!(e.t.max_devices(), 0);
    assert!(e.c.store().latest().unwrap().is_none());
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

/// An inventory that the test changes between cycles.
#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<Device>>>);

impl Inventory for Shared {
    fn devices(&self) -> Vec<Device> {
        self.0.lock().unwrap().clone()
    }
}

fn table_devices(store: &Store, s: &Snapshot, t: &str) -> Vec<String> {
    store
        .read_table(s, table(t).unwrap())
        .unwrap()
        .into_iter()
        .map(|(d, _)| d)
        .collect()
}

#[tokio::test(start_paused = true)]
async fn a_device_that_leaves_the_inventory_leaves_the_store_and_can_come_back() {
    let dir = tempfile::tempdir().unwrap();
    let t = Arc::new(FakeTransport::new(Duration::from_millis(5)));
    load(&t, &vyos("r1"));
    load(&t, &vyos("r2"));
    let inv = Shared::default();
    *inv.0.lock().unwrap() = vec![vyos("r1"), vyos("r2")];
    let sink = Arc::new(Recorder::default());
    let mut c = Collector::new(
        Store::open(dir.path(), keys()).unwrap(),
        Box::new(inv.clone()),
        Schedule {
            spread: false,
            ..Schedule::default()
        },
        Limits::default(),
        Arc::new(TokioClock::new(T0)),
    )
    .unwrap()
    .with_source(Arc::new(VyosSource::new(t.clone())))
    .with_sink(sink.clone());
    let r = c.run_cycle().await.unwrap();
    assert_eq!(r.snapshot, Some(0));
    assert!(r.removed.is_empty());

    // r2 leaves the inventory. No device is due, and the cycle removes r2
    // with no fetch.
    inv.0.lock().unwrap().retain(|d| d.id != "r2");
    let calls = t.calls();
    let r = c.run_cycle().await.unwrap();
    assert_eq!((r.due, r.snapshot), (0, Some(1)), "{r:?}");
    assert_eq!(r.removed, ["r2"]);
    assert!(r.changed.is_empty());
    assert_eq!(t.calls(), calls);
    let store = c.store();
    let s1 = store.latest().unwrap().unwrap();
    assert_eq!(s1.devices.keys().collect::<Vec<_>>(), ["r1"]);
    assert_eq!(s1.manifest.removed.iter().collect::<Vec<_>>(), ["r2"]);
    assert_eq!(table_devices(store, &s1, "links"), ["r1"]);
    let s0 = store.snapshot(0).unwrap();
    assert_eq!(s0.devices.keys().collect::<Vec<_>>(), ["r1", "r2"]);
    assert_eq!(table_devices(store, &s0, "links"), ["r1", "r2"]);

    // The removal is in one snapshot only.
    tokio::time::advance(Duration::from_secs(10)).await;
    let r = c.run_cycle().await.unwrap();
    assert_eq!((r.due, r.snapshot), (0, None), "{r:?}");
    assert!(r.removed.is_empty());

    // r2 comes back before the end of its interval. It is due at once, and
    // the store has it again with its new state.
    tokio::time::advance(Duration::from_secs(10)).await;
    inv.0.lock().unwrap().push(vyos("r2"));
    let r = c.run_cycle().await.unwrap();
    assert_eq!((r.due, r.snapshot), (1, Some(2)), "{r:?}");
    assert!(r.removed.is_empty());
    let all = vec![Class::Configuration, Class::Observation];
    assert_eq!(r.changed, [("r2".to_string(), all)]);
    let s2 = c.store().latest().unwrap().unwrap();
    assert_eq!(s2.devices.keys().collect::<Vec<_>>(), ["r1", "r2"]);
    assert_eq!(s2.devices["r2"].tables["links"].cycle, 2);
    assert_eq!(table_devices(c.store(), &s2, "links"), ["r1", "r2"]);
    assert_eq!(
        sink.0
            .lock()
            .unwrap()
            .iter()
            .map(|(s, _)| *s)
            .collect::<Vec<_>>(),
        [0, 2]
    );
}

#[tokio::test(start_paused = true)]
async fn a_reconfigured_collector_records_the_inventory_version_and_keeps_its_schedule() {
    let dir = tempfile::tempdir().unwrap();
    let t = Arc::new(FakeTransport::new(Duration::from_millis(5)));
    load(&t, &vyos("r1"));
    load(&t, &vyos("r2"));
    let mut c = Collector::new(
        Store::open(dir.path(), keys()).unwrap(),
        Box::new(Vec::<Device>::new()),
        Schedule {
            spread: false,
            ..Schedule::default()
        },
        Limits::default(),
        Arc::new(TokioClock::new(T0)),
    )
    .unwrap();
    let source =
        || -> Vec<Arc<dyn rsim_collect::Source>> { vec![Arc::new(VyosSource::new(t.clone()))] };
    c.reconfigure(
        Box::new(InventoryList {
            devices: vec![vyos("r1")],
            version: Some(4),
        }),
        source(),
        Default::default(),
    );
    let r = c.run_cycle().await.unwrap();
    assert_eq!(r.snapshot, Some(0));
    let s0 = c.store().latest().unwrap().unwrap();
    assert_eq!(s0.manifest.inventory_version, Some(4));

    // A new version adds r2. r1 is not due again, so only r2 is fetched.
    tokio::time::advance(Duration::from_secs(10)).await;
    c.reconfigure(
        Box::new(InventoryList {
            devices: vec![vyos("r1"), vyos("r2")],
            version: Some(5),
        }),
        source(),
        Default::default(),
    );
    let r = c.run_cycle().await.unwrap();
    assert_eq!((r.due, r.snapshot), (1, Some(1)), "{r:?}");
    let s1 = c.store().latest().unwrap().unwrap();
    assert_eq!(s1.manifest.inventory_version, Some(5));
    assert_eq!(s1.devices.keys().collect::<Vec<_>>(), ["r1", "r2"]);
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
        Box::new(vec![Device {
            interval,
            ..vyos("r1")
        }]),
        Schedule::default(),
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
    tokio::time::timeout(Duration::from_secs(60), c.run(stop, |_| {}))
        .await
        .expect("4 cycles run in 60 s")
        .unwrap();
    // The 4th cycle starts no earlier than 3 intervals after the first.
    assert!(start.elapsed() >= 3 * interval, "{:?}", start.elapsed());
    assert_eq!(c.store().head().unwrap(), Some(0));
}

/// A bridge and one bridge port in the form of `ip -d -j link show`.
fn bridge_links(gc: &str, hold: &str, mtu: u32) -> Vec<u8> {
    format!(
        r#"[{{"ifindex":3,"ifname":"br0","flags":["UP"],"mtu":{mtu},"operstate":"UP",
"address":"00:00:5e:00:53:10",
"linkinfo":{{"info_kind":"bridge","info_data":{{"forward_delay":1500,"hello_time":200,
"hello_timer":0.00,"tcn_timer":0.00,"topology_change_timer":0.00,"gc_timer":{gc}}}}}}},
{{"ifindex":4,"ifname":"eth1","flags":["UP"],"mtu":1500,"operstate":"UP","master":"br0",
"address":"00:00:5e:00:53:11",
"linkinfo":{{"info_slave_kind":"bridge","info_slave_data":{{"state":"forwarding",
"message_age_timer":0.00,"forward_delay_timer":0.00,"hold_timer":{hold}}}}}}}]"#
    )
    .into_bytes()
}

#[test]
fn the_timers_of_a_bridge_do_not_change_the_hash_of_the_links() {
    let keys = Keys::new([1; 32], [2; 32]);
    let spec = rsim_collect::vyos::sections()
        .into_iter()
        .find(|s| s.name == "links")
        .unwrap();
    let hash = |b: &[u8]| {
        rsim_store::change_hash_kept(&keys, spec.format, b, spec.volatile, spec.keep).unwrap()
    };
    let a = hash(&bridge_links("287.31", "0.00", 1500));
    assert_eq!(a, hash(&bridge_links("12.04", "0.76", 1500)));
    assert_ne!(a, hash(&bridge_links("287.31", "0.00", 9000)));
}

#[tokio::test(start_paused = true)]
async fn the_collector_wakes_for_each_device_at_its_own_interval() {
    let dir = tempfile::tempdir().unwrap();
    let t = Arc::new(FakeTransport::new(Duration::from_millis(5)));
    let every = |id: &str, s: u64| Device {
        interval: Duration::from_secs(s),
        ..vyos(id)
    };
    load(&t, &vyos("r1"));
    load(&t, &vyos("r2"));
    let mut c = Collector::new(
        Store::open(dir.path(), keys()).unwrap(),
        Box::new(Vec::<Device>::new()),
        Schedule {
            spread: false,
            ..Schedule::default()
        },
        Limits::default(),
        Arc::new(TokioClock::new(T0)),
    )
    .unwrap();
    let configure = |c: &mut Collector, r2: u64| {
        c.reconfigure(
            Box::new(vec![every("r1", 60), every("r2", r2)]),
            vec![Arc::new(VyosSource::new(t.clone()))],
            Default::default(),
        )
    };
    let both = |cycles: &[(u64, usize)]| -> Vec<u64> {
        cycles
            .iter()
            .filter(|(_, n)| *n == 2)
            .map(|(s, _)| *s)
            .collect()
    };
    configure(&mut c, 300);
    let cycles = wake_and_run(&mut c, 600).await;
    let minutes: Vec<u64> = (0..=10).map(|m| m * 60).collect();
    let at: Vec<u64> = cycles.iter().map(|(s, _)| *s).collect();
    assert_eq!(at, minutes, "{cycles:?}");
    assert_eq!(both(&cycles), [0, 300, 600]);

    // An interval of 120 s for r2 applies from its last collection.
    configure(&mut c, 120);
    let cycles = wake_and_run(&mut c, 900).await;
    assert_eq!(both(&cycles), [720, 840], "{cycles:?}");

    // With no device, the collector wakes after the wake limit.
    let empty_dir = tempfile::tempdir().unwrap();
    let empty = Collector::new(
        Store::open(empty_dir.path(), keys()).unwrap(),
        Box::new(Vec::<Device>::new()),
        Schedule::default(),
        Limits::default(),
        Arc::new(TokioClock::new(T0)),
    )
    .unwrap();
    assert_eq!(empty.next_wake(T0), T0 + WAKE_LIMIT.as_millis() as u64);
}

/// Runs a cycle at each wake time of the collector up to the second `until`
/// after `T0`, and gives the second after `T0` and the due devices of each
/// cycle.
async fn wake_and_run(c: &mut Collector, until: u64) -> Vec<(u64, usize)> {
    let mut cycles = Vec::new();
    loop {
        let now = c.now_ms();
        let wake = c.next_wake(now);
        if wake > T0 + until * 1000 {
            return cycles;
        }
        tokio::time::advance(Duration::from_millis(wake.saturating_sub(now))).await;
        let r = c.run_cycle().await.unwrap();
        cycles.push(((r.time - T0) / 1000, r.due));
    }
}

/// The config of r1 with a host name, so each name is a change.
fn rename(e: &Env, name: &str) {
    let text = String::from_utf8(fixture("vyos/config.json"))
        .unwrap()
        .replace("HOST", name);
    set(&e.t, &e.devices[0], "config", text.into_bytes());
}

#[tokio::test(start_paused = true)]
async fn a_cycle_prunes_the_snapshots_older_than_the_history() {
    let mut e = env(vec![vyos("r1")], Limits::default());
    e.c.set_history(Duration::from_secs(86_400));
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.snapshot, Some(0));
    assert_eq!(r.pruned, Some(Default::default()));

    // 2 days later the first snapshot is older than the history.
    tokio::time::advance(Duration::from_secs(2 * 86_400)).await;
    rename(&e, "two-days");
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.snapshot, Some(1), "{r:?}");
    let p = r.pruned.clone().unwrap();
    assert_eq!((p.snapshots, p.checkpoint), (1, Some(1)), "{r:?}");
    assert_eq!(r.prune_error, None);
    let store = e.c.store();
    assert!(store.snapshot(0).is_err());
    assert!(store.snapshot(1).unwrap().manifest.checkpoint);
    assert_eq!(latest(&e).devices.keys().collect::<Vec<_>>(), ["r1"]);

    // No prune runs in the hour after a prune.
    tokio::time::advance(MINUTE).await;
    rename(&e, "later");
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!((r.snapshot, &r.pruned), (Some(2), &None), "{r:?}");
}

#[tokio::test(start_paused = true)]
async fn a_cycle_in_the_second_of_the_newest_snapshot_waits_for_the_next_second() {
    let dir = tempfile::tempdir().unwrap();
    let t = Arc::new(FakeTransport::new(Duration::from_millis(5)));
    load(&t, &vyos("r1"));
    load(&t, &vyos("r2"));
    let inv = Shared::default();
    *inv.0.lock().unwrap() = vec![vyos("r1"), vyos("r2")];
    let mut c = Collector::new(
        Store::open(dir.path(), keys()).unwrap(),
        Box::new(inv.clone()),
        Schedule::default(),
        Limits::default(),
        Arc::new(TokioClock::new(T0 + 250)),
    )
    .unwrap()
    .with_source(Arc::new(VyosSource::new(t.clone())));
    let r = c.run_cycle().await.unwrap();
    assert_eq!((r.time, r.snapshot), (T0 + 250, Some(0)));
    // The removal of r2 at once is a snapshot of the next second.
    inv.0.lock().unwrap().retain(|d| d.id != "r2");
    let r = c.run_cycle().await.unwrap();
    assert_eq!((r.time, r.snapshot), (T0 + 1_000, Some(1)), "{r:?}");
    let times: Vec<u64> = [0, 1]
        .iter()
        .map(|n| c.store().snapshot(*n).unwrap().manifest.time)
        .collect();
    assert_eq!(times, [T0 + 250, T0 + 1_000]);
}
