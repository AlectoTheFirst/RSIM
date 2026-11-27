#![cfg(all(feature = "nxos", feature = "iosxe", feature = "iosxr"))]
#[path = "../examples/demo_enterprise/mod.rs"]
mod demo_enterprise;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use rsim_routing::Platform;
use rsim_routing::ospf::{OspfProfile, Version, compute};

#[path = "support/keys.rs"]
mod keys;

#[tokio::test]
async fn probe() {
    let tmp = tempfile::tempdir().unwrap();
    let store = rsim_store::Store::open(tmp.path().join("s"), keys::keys()).unwrap();
    let folder = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo");
    rsim_collect::demo::seed(store, &folder).await.unwrap();
    let store = rsim_store::Store::open(tmp.path().join("s"), keys::keys()).unwrap();
    let snap = store.latest().unwrap().unwrap();
    let all = rsim_ingest::ospf::of_snapshot(&store, &snap).unwrap();
    let e = demo_enterprise::build::estate(demo_enterprise::CYCLES);
    let t = demo_enterprise::route::tables(&e);
    let (mut m, mut m1, mut d, mut oc, mut od) = (0, 0, 0, 0, 0);
    for (i, dev) in e.devs.iter().enumerate() {
        let Some(o) = all.get(&dev.name) else {
            continue;
        };
        let out = &o.outcomes[&Version::V2];
        let Some(db) = o.of(Version::V2, "default").next() else {
            println!("PROBE {} {:?} no db", dev.name, out.outcome);
            continue;
        };
        let p = match dev.os {
            demo_enterprise::model::Os::Nxos => Platform::Nxos,
            demo_enterprise::model::Os::Iosxe => Platform::Iosxe,
            demo_enterprise::model::Os::Iosxr => Platform::Iosxr,
        };
        let c = compute(db, db.router_id.unwrap(), &OspfProfile::of(p));
        let mine: BTreeMap<String, (u32, BTreeSet<String>)> = c
            .routes
            .iter()
            .map(|r| {
                (
                    r.prefix.to_string(),
                    (
                        r.metric,
                        r.next_hops.iter().map(|h| h.gateway.to_string()).collect(),
                    ),
                )
            })
            .collect();
        let theirs: BTreeMap<String, (u32, BTreeSet<String>)> = t.ribs[i]
            .iter()
            .filter(|r| r.vrf == "default" && r.kind == demo_enterprise::route::Kind::Ospf)
            .map(|r| {
                (
                    format!("{}/{}", r.prefix.0, r.prefix.1),
                    (
                        r.metric,
                        r.paths
                            .iter()
                            .filter_map(|p| p.next_hop.map(|x| x.to_string()))
                            .collect(),
                    ),
                )
            })
            .collect();
        let mut ex = Vec::new();
        for (k, v) in &theirs {
            match mine.get(k) {
                Some(x) if x == v => m += 1,
                Some(x) if x.1 == v.1 && x.0 == v.0 + 1 => m1 += 1,
                Some(x) => {
                    d += 1;
                    if ex.len() < 3 {
                        ex.push(format!("{k} demo {v:?} ospf {x:?}"));
                    }
                }
                None => {
                    od += 1;
                    if ex.len() < 3 {
                        ex.push(format!("{k} demo only {v:?}"));
                    }
                }
            }
        }
        for k in mine.keys() {
            if !theirs.contains_key(k) {
                oc += 1;
                if ex.len() < 5 {
                    ex.push(format!("{k} ospf only {:?}", mine[k]));
                }
            }
        }
        println!(
            "PROBE {} {:?} gaps {} notes {} ospf {} demo {} {:?}",
            dev.name,
            out.outcome,
            c.gaps.len(),
            c.notes.len(),
            mine.len(),
            theirs.len(),
            ex
        );
    }
    println!("PROBE-SUM same {m} plus-one {m1} differ {d} demo-only {od} ospf-only {oc}");
}
