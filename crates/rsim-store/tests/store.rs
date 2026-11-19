//! The snapshot store: content addressing, the cycle that writes nothing,
//! the load of a table across parents and a checkpoint, the removal of a
//! device, a stopped cycle, the keys and the determinism of the files.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use arrow_array::{Array, StringArray};
use rsim_store::*;

struct Counter(u8);

impl Entropy for Counter {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            self.0 = self.0.wrapping_add(1);
            *b = self.0;
        }
    }
}

fn keys() -> Keys {
    Keys::new([7; 32], [9; 32])
}

fn files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p.strip_prefix(dir).unwrap().display().to_string());
            }
        }
    }
    out.sort();
    out
}

fn section(name: &str, blob: Hash, class: Class) -> SectionEntry {
    SectionEntry {
        name: name.into(),
        command: format!("show {name}"),
        class,
        format: Format::Json,
        change_hash: Some(blob),
        blob: Some(blob),
        status: SectionStatus::Fresh,
        collected_at: Some(1),
    }
}

fn speed_row(iface: &str, mbps: u64) -> Row {
    vec![
        Cell::Str(iface.into()),
        Cell::U64(mbps),
        Cell::Str("full".into()),
    ]
}

/// The update of a device with one config section and its link speeds.
fn update(
    store: &Store,
    device: &str,
    config: &str,
    speeds: Option<&[(&str, u64)]>,
) -> DeviceUpdate {
    let mut e = Counter(0);
    let cfg = store.put_blob(config.as_bytes(), &mut e).unwrap();
    let mut sections = vec![section("config", cfg, Class::Configuration)];
    let mut tables = BTreeMap::new();
    if let Some(s) = speeds {
        let text: String = s.iter().map(|(i, m)| format!("{i} {m}\n")).collect();
        let b = store.put_blob(text.as_bytes(), &mut e).unwrap();
        sections.push(section("speeds", b, Class::Observation));
        let rows = s.iter().map(|(i, m)| speed_row(i, *m)).collect();
        tables.insert("link_speeds".to_string(), vec![(b, rows)]);
    }
    DeviceUpdate {
        device: device.into(),
        vendor: "vyos".into(),
        collected_at: 1,
        sections,
        tables,
        management_address: None,
    }
}

fn commit(store: &Store, time: u64, updates: Vec<DeviceUpdate>) -> Option<Snapshot> {
    let mut c = store.begin(time).unwrap();
    for u in updates {
        c.add(u).unwrap();
    }
    c.prepare().unwrap().map(|p| p.publish().unwrap())
}

/// The link speeds of each device at a snapshot.
fn speeds(store: &Store, s: &Snapshot) -> Vec<(String, Vec<String>)> {
    store
        .read_table(s, &LINK_SPEEDS)
        .unwrap()
        .into_iter()
        .map(|(d, b)| {
            let iface = b
                .column_by_name("interface")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap()
                .clone();
            let dev = b.column_by_name("device").unwrap();
            assert_eq!(dev.len(), b.num_rows());
            (
                d,
                (0..iface.len())
                    .map(|i| iface.value(i).to_string())
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn equal_bytes_are_stored_once() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), keys()).unwrap();
    let a = store.put_blob(b"same", &mut Counter(0)).unwrap();
    let b = store.put_blob(b"same", &mut Counter(50)).unwrap();
    assert_eq!(a, b);
    assert_eq!(files(&dir.path().join("blobs")).len(), 1);
    assert_eq!(store.read_blob(&a).unwrap(), b"same");
}

#[test]
fn a_cycle_with_no_change_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), keys()).unwrap();
    let first = commit(
        &store,
        10,
        vec![update(&store, "r1", "a", Some(&[("eth0", 1000)]))],
    )
    .unwrap();
    assert!(first.manifest.checkpoint);
    let before = files(dir.path());
    // The same sections at a later time, with no new table rows.
    let mut same = update(&store, "r1", "a", None);
    same.sections = first.devices["r1"].sections.clone();
    same.collected_at = 99;
    assert!(commit(&store, 20, vec![same]).is_none());
    assert_eq!(files(dir.path()), before);
    assert_eq!(store.head().unwrap(), Some(0));
}

#[test]
fn the_snapshot_manifest_has_the_schema_version_of_each_table() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), keys()).unwrap();
    let s = commit(&store, 10, vec![update(&store, "r1", "a", None)]).unwrap();
    let want: BTreeMap<String, u32> = TABLES
        .iter()
        .map(|t| (t.name.to_string(), t.version))
        .collect();
    assert_eq!(s.manifest.schemas, want);
    let r = &store.snapshot(0).unwrap();
    assert_eq!(r, &s);
}

#[test]
fn a_table_loads_across_parents_and_checkpoints() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), keys()).unwrap();
    commit(
        &store,
        0,
        vec![
            update(&store, "r1", "a", Some(&[("eth0", 1000)])),
            update(&store, "r2", "b", Some(&[("eth0", 100), ("eth1", 100)])),
        ],
    );
    // Cycle 1 changes only the config of r1. Its rows stay in cycle 0.
    let s1 = commit(&store, 1, vec![update(&store, "r1", "a2", None)]).unwrap();
    assert!(!s1.manifest.checkpoint);
    assert_eq!(s1.manifest.devices.len(), 1);
    // Cycle 2 changes the rows of r2.
    let s2 = commit(
        &store,
        2,
        vec![update(&store, "r2", "b", Some(&[("eth9", 10)]))],
    )
    .unwrap();
    assert_eq!(s2.devices["r1"].tables["link_speeds"].cycle, 0);
    assert_eq!(s2.devices["r2"].tables["link_speeds"].cycle, 2);
    let at = |c| speeds(&store, &store.snapshot(c).unwrap());
    let r1 = ("r1".to_string(), vec!["eth0".to_string()]);
    assert_eq!(
        at(1),
        vec![
            r1.clone(),
            ("r2".into(), vec!["eth0".into(), "eth1".into()])
        ]
    );
    assert_eq!(at(2), vec![r1.clone(), ("r2".into(), vec!["eth9".into()])]);

    // Up to the next checkpoint, each cycle changes the config of r1.
    for c in 3..=CHECKPOINT_INTERVAL + 1 {
        let s = commit(
            &store,
            c,
            vec![update(&store, "r1", &format!("a{c}"), None)],
        )
        .unwrap();
        assert_eq!(s.manifest.cycle, c);
        assert_eq!(s.manifest.checkpoint, c == CHECKPOINT_INTERVAL);
    }
    let cp = store.snapshot(CHECKPOINT_INTERVAL).unwrap();
    assert_eq!(cp.manifest.devices.len(), 2);
    // The checkpoint stops the walk: the snapshot after it loads with the
    // older snapshot manifests removed.
    for c in 0..CHECKPOINT_INTERVAL {
        fs::remove_file(dir.path().join("snapshots").join(format!("{c:020}"))).unwrap();
    }
    let last = store.latest().unwrap().unwrap();
    assert_eq!(
        speeds(&store, &last),
        vec![r1, ("r2".into(), vec!["eth9".into()])]
    );
}

#[test]
fn a_cycle_that_stops_before_head_is_not_visible() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), keys()).unwrap();
    let s0 = commit(
        &store,
        0,
        vec![update(&store, "r1", "a", Some(&[("eth0", 1)]))],
    )
    .unwrap();
    let mut c = store.begin(1).unwrap();
    assert_eq!(c.number(), 1);
    c.add(update(&store, "r1", "b", Some(&[("eth0", 2)])))
        .unwrap();
    let stopped = c.prepare().unwrap().unwrap();
    drop(stopped);
    assert_eq!(store.head().unwrap(), Some(0));
    assert_eq!(store.latest().unwrap().unwrap(), s0);
    let orphan = files(dir.path());
    // The next cycle takes a number that the stopped cycle did not use and
    // changes none of its files.
    let s = commit(
        &store,
        2,
        vec![update(&store, "r1", "c", Some(&[("eth0", 3)]))],
    )
    .unwrap();
    assert_eq!(s.manifest.cycle, 2);
    assert_eq!(s.manifest.parent, Some(0));
    let after = files(dir.path());
    assert!(orphan.iter().all(|f| f == "HEAD" || after.contains(f)));
    assert_eq!(speeds(&store, &s)[0].1, vec!["eth0".to_string()]);
}

#[test]
fn other_keys_do_not_read_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), keys()).unwrap();
    let s = commit(&store, 0, vec![update(&store, "r1", "secret config", None)]).unwrap();
    let blob = s.devices["r1"].sections[0].blob.unwrap();
    let raw = fs::read(dir.path().join("blobs").join(blob.to_string())).unwrap();
    assert!(!raw.windows(6).any(|w| w == b"secret"));
    let other_wrap = Store::open(dir.path(), Keys::new([7; 32], [8; 32])).unwrap();
    assert!(matches!(
        other_wrap.read_blob(&blob),
        Err(StoreError::Integrity(_))
    ));
    let other_hash = Store::open(dir.path(), Keys::new([6; 32], [9; 32])).unwrap();
    assert!(matches!(other_hash.latest(), Err(StoreError::Integrity(_))));
}

#[test]
fn the_same_input_gives_the_same_files() {
    let make = || {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), keys()).unwrap();
        commit(
            &store,
            5,
            vec![
                update(&store, "r2", "b", Some(&[("eth1", 10), ("eth0", 20)])),
                update(&store, "r1", "a", Some(&[("eth0", 1000)])),
            ],
        );
        let mut out = BTreeMap::new();
        for f in files(dir.path()) {
            out.insert(f.clone(), fs::read(dir.path().join(&f)).unwrap());
        }
        out
    };
    assert_eq!(make(), make());
}

#[test]
fn a_second_writer_of_the_same_cycle_fails_and_publishes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let a = Store::open(dir.path(), keys()).unwrap();
    let b = Store::open(dir.path(), keys()).unwrap();
    commit(&a, 0, vec![update(&a, "r1", "a", Some(&[("eth0", 1)]))]).unwrap();
    // All 3 cycles take the number 1.
    let mut ca = a.begin(1).unwrap();
    let mut cb = b.begin(1).unwrap();
    let mut cc = b.begin(1).unwrap();
    assert_eq!((ca.number(), cb.number(), cc.number()), (1, 1, 1));
    ca.add(update(&a, "r1", "b", Some(&[("eth0", 2)]))).unwrap();
    cb.add(update(&b, "r2", "x", Some(&[("eth9", 9)]))).unwrap();
    cc.add(update(&b, "r3", "y", None)).unwrap();
    let sa = ca.prepare().unwrap().unwrap().publish().unwrap();
    // The table file of the cycle exists.
    assert!(matches!(cb.prepare(), Err(StoreError::Conflict(_))));
    // The snapshot manifest of the cycle exists.
    assert!(matches!(cc.prepare(), Err(StoreError::Conflict(_))));
    assert_eq!(a.head().unwrap(), Some(1));
    let latest = a.latest().unwrap().unwrap();
    assert_eq!(latest, sa);
    assert_eq!(
        speeds(&a, &latest),
        vec![("r1".to_string(), vec!["eth0".to_string()])]
    );
}

fn commit_removing(
    store: &Store,
    time: u64,
    remove: &[&str],
    updates: Vec<DeviceUpdate>,
) -> Option<Snapshot> {
    let mut c = store.begin(time).unwrap();
    for d in remove {
        c.remove(d);
    }
    for u in updates {
        c.add(u).unwrap();
    }
    c.prepare().unwrap().map(|p| p.publish().unwrap())
}

fn names(s: &Snapshot) -> Vec<&str> {
    s.devices.keys().map(String::as_str).collect()
}

#[test]
fn a_removed_device_leaves_the_later_snapshots_and_the_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), keys()).unwrap();
    commit(
        &store,
        0,
        vec![
            update(&store, "r1", "a", Some(&[("eth0", 1000)])),
            update(&store, "r2", "b", Some(&[("eth1", 100)])),
        ],
    );
    // A cycle with only a removal publishes a snapshot.
    let s1 = commit_removing(&store, 1, &["r2"], vec![]).unwrap();
    assert_eq!(s1.manifest.cycle, 1);
    assert!(s1.manifest.devices.is_empty());
    assert_eq!(s1.manifest.removed, ["r2".to_string()].into());
    assert_eq!(names(&s1), ["r1"]);
    assert_eq!(store.snapshot(1).unwrap(), s1);
    assert_eq!(names(&store.snapshot(0).unwrap()), ["r1", "r2"]);
    let r1 = ("r1".to_string(), vec!["eth0".to_string()]);
    assert_eq!(speeds(&store, &s1), vec![r1.clone()]);
    assert_eq!(
        speeds(&store, &store.snapshot(0).unwrap()),
        vec![r1.clone(), ("r2".into(), vec!["eth1".into()])]
    );

    // The removal of a device that the base does not have writes nothing.
    let before = files(dir.path());
    assert!(commit_removing(&store, 2, &["r2", "r9"], vec![]).is_none());
    assert_eq!(files(dir.path()), before);

    for c in 2..=CHECKPOINT_INTERVAL {
        let s = commit(
            &store,
            c,
            vec![update(&store, "r1", &format!("a{c}"), None)],
        )
        .unwrap();
        assert_eq!(names(&s), ["r1"]);
        assert!(s.manifest.removed.is_empty());
    }
    let cp = store.snapshot(CHECKPOINT_INTERVAL).unwrap();
    assert!(cp.manifest.checkpoint);
    assert_eq!(cp.manifest.devices.keys().collect::<Vec<_>>(), ["r1"]);
    for c in 0..CHECKPOINT_INTERVAL {
        fs::remove_file(dir.path().join("snapshots").join(format!("{c:020}"))).unwrap();
    }
    let last = store.latest().unwrap().unwrap();
    assert_eq!(names(&last), ["r1"]);
    assert_eq!(speeds(&store, &last), vec![r1]);
}

#[test]
fn a_removed_device_that_comes_back_has_only_its_new_state() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), keys()).unwrap();
    commit(
        &store,
        0,
        vec![
            update(&store, "r1", "a", None),
            update(&store, "r2", "b", Some(&[("eth1", 100)])),
        ],
    );
    commit_removing(&store, 1, &["r2"], vec![]).unwrap();
    // The device comes back with the same config and no table rows.
    let s2 = commit(&store, 2, vec![update(&store, "r2", "b", None)]).unwrap();
    assert!(s2.manifest.removed.is_empty());
    assert_eq!(names(&s2), ["r1", "r2"]);
    assert!(s2.devices["r2"].tables.is_empty());
    assert!(speeds(&store, &s2).is_empty());
    assert_eq!(names(&store.snapshot(1).unwrap()), ["r1"]);
    assert_eq!(store.snapshot(2).unwrap(), s2);

    // A removal and an update of one device in one cycle: the last call
    // wins.
    let s3 = commit_removing(&store, 3, &["r2"], vec![update(&store, "r2", "b3", None)]).unwrap();
    assert!(s3.manifest.removed.is_empty());
    assert_eq!(names(&s3), ["r1", "r2"]);
    let mut c = store.begin(4).unwrap();
    c.add(update(&store, "r2", "b4", None)).unwrap();
    c.remove("r2");
    let s4 = c.prepare().unwrap().unwrap().publish().unwrap();
    assert_eq!(s4.manifest.removed, ["r2".to_string()].into());
    assert!(s4.manifest.devices.is_empty());
    assert_eq!(names(&store.snapshot(4).unwrap()), ["r1"]);
}

#[test]
fn a_snapshot_manifest_without_removed_devices_reads() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), keys()).unwrap();
    commit(&store, 0, vec![update(&store, "r1", "a", None)]);
    let s1 = commit(&store, 1, vec![update(&store, "r1", "a1", None)]).unwrap();
    // A manifest with no removed device has no field `removed`.
    for c in 0..2u64 {
        let path = dir.path().join("snapshots").join(format!("{c:020}"));
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("removed"), "{text}");
    }
    assert_eq!(store.snapshot(1).unwrap(), s1);
    // A manifest with no field `removed` removes no device.
    let plain = r#"{"cycle":1,"time":1,"parent":0,"checkpoint":false,"schemas":{},"devices":{}}"#;
    let m: SnapshotManifest = serde_json::from_str(plain).unwrap();
    assert!(m.removed.is_empty());
}

#[test]
fn a_snapshot_records_the_inventory_version_and_an_older_manifest_has_none() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), keys()).unwrap();
    commit(&store, 0, vec![update(&store, "r1", "a", None)]);
    let mut c = store.begin(1).unwrap();
    c.set_inventory_version(Some(7));
    c.add(update(&store, "r1", "a1", None)).unwrap();
    let s1 = c.prepare().unwrap().unwrap().publish().unwrap();
    assert_eq!(s1.manifest.inventory_version, Some(7));
    assert_eq!(
        store.snapshot(1).unwrap().manifest.inventory_version,
        Some(7)
    );
    let path = |c: u64| dir.path().join("snapshots").join(format!("{c:020}"));
    let text = fs::read_to_string(path(1)).unwrap();
    assert!(text.contains("\"inventory_version\": 7"), "{text}");
    // A cycle with no inventory database writes no field.
    let text = fs::read_to_string(path(0)).unwrap();
    assert!(!text.contains("inventory_version"), "{text}");
    assert_eq!(store.snapshot(0).unwrap().manifest.inventory_version, None);
    let plain = r#"{"cycle":1,"time":1,"parent":0,"checkpoint":false,"schemas":{},"devices":{}}"#;
    let m: SnapshotManifest = serde_json::from_str(plain).unwrap();
    assert_eq!(m.inventory_version, None);
}

#[test]
fn a_device_manifest_records_the_management_address_and_an_older_manifest_has_none() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), keys()).unwrap();
    let with = |a: Option<&str>| {
        let mut u = update(&store, "r1", "a", None);
        u.management_address = a.map(str::to_string);
        u
    };
    let s0 = commit(&store, 0, vec![with(None)]).unwrap();
    assert_eq!(s0.devices["r1"].management_address, None);
    // A change of only the address writes a new manifest.
    let s1 = commit(&store, 1, vec![with(Some("192.0.2.1"))]).unwrap();
    assert_eq!(
        s1.devices["r1"].management_address.as_deref(),
        Some("192.0.2.1")
    );
    assert_eq!(
        store.snapshot(1).unwrap().devices["r1"].management_address,
        s1.devices["r1"].management_address
    );
    // The same address again writes nothing.
    assert!(commit(&store, 2, vec![with(Some("192.0.2.1"))]).is_none());
    // A manifest with no field `management_address` has none.
    let plain = r#"{"device":"r1","vendor":"vyos","collected_at":1,"sections":[],"tables":{}}"#;
    let m: DeviceManifest = serde_json::from_str(plain).unwrap();
    assert_eq!(m.management_address, None);
    assert!(
        !serde_json::to_string(&m)
            .unwrap()
            .contains("management_address")
    );
}

fn snapshot_file(dir: &Path, cycle: u64) -> std::path::PathBuf {
    dir.join("snapshots").join(format!("{cycle:020}"))
}

#[test]
fn a_snapshot_whose_parent_is_not_older_is_an_integrity_error() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), keys()).unwrap();
    commit(&store, 0, vec![update(&store, "r1", "a", None)]);
    commit(&store, 1, vec![update(&store, "r1", "a1", None)]).unwrap();
    commit(&store, 2, vec![update(&store, "r1", "a2", None)]).unwrap();
    let set_parent = |cycle: u64, parent: u64| {
        let path = snapshot_file(dir.path(), cycle);
        let mut m: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        m["parent"] = parent.into();
        fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
    };
    // A manifest that names itself as its parent.
    set_parent(1, 1);
    assert!(matches!(store.snapshot(1), Err(StoreError::Integrity(_))));
    // Two manifests that name each other.
    set_parent(1, 2);
    assert!(matches!(store.snapshot(2), Err(StoreError::Integrity(_))));
    assert!(matches!(store.latest(), Err(StoreError::Integrity(_))));
}

#[test]
fn a_table_range_that_overflows_is_an_integrity_error() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), keys()).unwrap();
    let s0 = commit(
        &store,
        0,
        vec![update(&store, "r1", "a", Some(&[("eth0", 1000)]))],
    )
    .unwrap();
    // A device manifest whose row range does not fit in a u64.
    let mut d: serde_json::Value = serde_json::to_value(&s0.devices["r1"]).unwrap();
    d["tables"]["link_speeds"]["first_row"] = u64::MAX.into();
    let bytes = serde_json::to_vec(&d).unwrap();
    let name = keys().hash(&bytes);
    fs::write(dir.path().join("devices").join(name.to_string()), &bytes).unwrap();
    let path = snapshot_file(dir.path(), 0);
    let mut m: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    m["devices"]["r1"] = name.to_string().into();
    fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
    let s = store.snapshot(0).unwrap();
    assert!(matches!(
        store.read_table(&s, &LINK_SPEEDS),
        Err(StoreError::Integrity(_))
    ));
}
