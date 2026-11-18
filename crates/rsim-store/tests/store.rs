//! The snapshot store: content addressing, the cycle that writes nothing,
//! the load of a table across parents and a checkpoint, a stopped cycle,
//! the keys and the determinism of the files.

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
