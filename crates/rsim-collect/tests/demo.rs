//! The demo estate: the committed folder `demo/` is the output of the
//! generator, the seed writes its cycles into a new store, and the twin of
//! the newest snapshot answers the planned path queries between the sites.

#![cfg(all(feature = "nxos", feature = "iosxe", feature = "iosxr"))]

#[path = "../examples/demo_enterprise/mod.rs"]
mod demo_enterprise;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rsim_core::{Header, PROTO_TCP, PROTO_UDP, VerdictKind};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::estate;
use rsim_store::{Keys, Store};

/// The committed demo folder.
fn committed() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo")
}

/// The files below a folder, by their path in the folder.
fn files(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for entry in std::fs::read_dir(&d).unwrap_or_else(|e| panic!("{}: {e}", d.display())) {
            let p = entry.unwrap().path();
            if p.is_dir() {
                todo.push(p);
            } else {
                let rel = p.strip_prefix(dir).unwrap().to_path_buf();
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    out
}

#[test]
fn the_committed_demo_folder_is_the_output_of_the_generator() {
    let tmp = tempfile::tempdir().unwrap();
    demo_enterprise::generate(tmp.path()).unwrap();
    let fresh = files(tmp.path());
    let old = files(&committed());
    let missing: Vec<&PathBuf> = fresh.keys().filter(|k| !old.contains_key(*k)).collect();
    let extra: Vec<&PathBuf> = old.keys().filter(|k| !fresh.contains_key(*k)).collect();
    let changed: Vec<&PathBuf> = fresh
        .iter()
        .filter(|(k, v)| old.get(*k).is_some_and(|o| o != *v))
        .map(|(k, _)| k)
        .collect();
    assert!(
        missing.is_empty() && extra.is_empty() && changed.is_empty(),
        "demo/ is not current; run `cargo run -p rsim-collect --example demo_enterprise -- demo`. \
         missing {missing:?}, extra {extra:?}, changed {changed:?}"
    );
}

/// A new store in a temporary folder.
fn new_store(dir: &Path) -> Store {
    Store::open(dir.join("store"), Keys::new([3; 32], [4; 32])).unwrap()
}

#[tokio::test]
async fn the_seed_refuses_a_store_with_a_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    let reports = rsim_collect::demo::seed(new_store(tmp.path()), &committed())
        .await
        .unwrap();
    assert_eq!(reports.len(), demo_enterprise::CYCLES);
    for r in &reports {
        assert!(r.snapshot.is_some(), "{r:?}");
        assert!(!r.changed.is_empty(), "{r:?}");
    }
    let e = rsim_collect::demo::seed(new_store(tmp.path()), &committed())
        .await
        .unwrap_err();
    assert!(e.contains("the store has a snapshot"), "{e}");
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn run(t: &Twin, src: &str, dst: &str, proto: u8, port: u16) -> Answer {
    let h = Header::request(ip(src), ip(dst), proto)
        .with_src_port(40000)
        .with_dst_port(port);
    Executor::new(t)
        .run(&Query::path(t, &h))
        .expect("the query runs")
}

/// The kind and the text of the verdict of each branch.
fn verdicts(a: &Answer) -> Vec<(VerdictKind, String)> {
    a.branches()
        .iter()
        .map(|b| (b.verdict.kind(), format!("{:?}", b.verdict)))
        .collect()
}

/// Checks that each branch of a query ends in `kind` with `text` in its
/// verdict, and that each reply of a delivered branch is delivered.
fn expect(t: &Twin, (src, dst, proto, port): (&str, &str, u8, u16), kind: VerdictKind, text: &str) {
    let a = run(t, src, dst, proto, port);
    let v = verdicts(&a);
    assert!(!v.is_empty(), "{src} -> {dst}: no branch");
    for (k, s) in &v {
        assert_eq!(*k, kind, "{src} -> {dst}:{port}: {v:#?}");
        assert!(s.contains(text), "{src} -> {dst}:{port}: {text} not in {s}");
    }
    if kind == VerdictKind::Deliver {
        for b in 0..v.len() {
            let r = a.reply_of(b).expect("the reply ran");
            for (k, s) in verdicts(r) {
                assert_eq!(k, VerdictKind::Deliver, "the reply of {src} -> {dst}: {s}");
            }
        }
    }
}

#[tokio::test]
async fn the_twin_of_the_newest_snapshot_answers_the_planned_queries() {
    let tmp = tempfile::tempdir().unwrap();
    rsim_collect::demo::seed(new_store(tmp.path()), &committed())
        .await
        .unwrap();
    let store = new_store(tmp.path());
    let snap = store.latest().unwrap().expect("a snapshot");
    assert_eq!(snap.devices.len(), 40);
    let e = estate::build(&store, &snap).unwrap();
    for (device, cov) in &e.coverage {
        let unhandled: Vec<&String> = cov.unhandled.keys().collect();
        assert!(unhandled.is_empty(), "{device}: {unhandled:?}");
        let unread = e.unread.get(device).cloned().unwrap_or_default();
        assert!(unread.is_empty(), "{device}: {unread:?}");
    }
    let t = e.builder.build().expect("the twin builds");
    let tcp = PROTO_TCP;
    // A Paris user reaches the web shop in Frankfurt over the WAN and the
    // fabric of Frankfurt.
    expect(
        &t,
        ("10.22.110.21", "10.11.10.11", tcp, 443),
        VerdictKind::Deliver,
        "fra-dc-leaf1/vlan10/",
    );
    // A Frankfurt user reaches the name server of the data centre.
    expect(
        &t,
        ("10.12.110.20", "10.11.40.53", PROTO_UDP, 53),
        VerdictKind::Deliver,
        "fra-dc-leaf3/vlan40/",
    );
    // The access list of the border leaves blocks the database port and,
    // from cycle 2, SSH to the web servers.
    expect(
        &t,
        ("10.12.110.20", "10.11.30.11", tcp, 1433),
        VerdictKind::Drop,
        "DC-IN/10",
    );
    expect(
        &t,
        ("10.12.110.20", "10.11.10.11", tcp, 22),
        VerdictKind::Drop,
        "DC-IN/30",
    );
    // Inside the fabric the database port is open.
    expect(
        &t,
        ("10.11.50.11", "10.11.30.11", tcp, 1433),
        VerdictKind::Deliver,
        "fra-dc-leaf3/vlan30/",
    );
    // A web server in Frankfurt reaches the database in Paris over the
    // interconnect of the fabrics.
    expect(
        &t,
        ("10.11.10.11", "10.21.30.11", tcp, 5432),
        VerdictKind::Deliver,
        "par-dc-leaf3/vlan30/",
    );
    // A Paris user reaches a printer of the Frankfurt campus.
    expect(
        &t,
        ("10.22.110.21", "10.12.120.20", tcp, 9100),
        VerdictKind::Deliver,
        "fra-acc1/vlan120/",
    );
    // A host on the internet is past the egress of the internet edge,
    // which has no link.
    expect(
        &t,
        ("10.12.110.20", "192.0.2.80", tcp, 443),
        VerdictKind::Unknown,
        "no link · interface GigabitEthernet0/0/0",
    );
}
