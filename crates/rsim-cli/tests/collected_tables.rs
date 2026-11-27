//! The tables of the collected state and the table `links`: the registry
//! rows against the store schemas, the rows of a store twin and of a
//! hand-built twin, and the claim `path-mtu`.

use rsim_cli::claims::{end_mtu, path_mtu};
use rsim_cli::commands;
use rsim_cli::tables::{Mtus, OpenEnd, TwinLink};
use rsim_contract::claim::{ClaimArgs, ClaimResult};
use rsim_contract::table::{self, ColumnType, Selection};
use rsim_core::FunctionId;
use rsim_store::ColType;
use serde_json::{Value, json};

#[path = "support/fixture_store.rs"]
mod fixture_store;

/// Each column of a table of the collected state, other than `device`,
/// `provenance` and the join columns, is a column of 1 of its store tables
/// with a matching type. Each join column is a column of its table.
/// With 2 or more store tables, each store table has each key column.
#[test]
fn each_collected_column_is_a_store_column() {
    let collected: Vec<_> = table::TABLES
        .iter()
        .filter(|d| !d.collected.is_empty())
        .collect();
    assert_eq!(
        collected.iter().map(|d| d.name).collect::<Vec<_>>(),
        ["interfaces", "routes", "mac", "arp"]
    );
    for d in collected {
        let schemas: Vec<_> = d
            .collected
            .iter()
            .map(|n| rsim_store::table(n).unwrap_or_else(|| panic!("{} names {n}", d.name)))
            .collect();
        let joined = rsim_cli::tables::JOINED
            .iter()
            .find(|(n, _)| *n == d.name)
            .map_or(&[][..], |(_, c)| c);
        for j in joined {
            assert!(d.column(j).is_some(), "{} has no join column {j}", d.name);
        }
        for c in d.columns {
            if c.name == "device" || c.name == "provenance" || joined.contains(&c.name) {
                continue;
            }
            let found = schemas
                .iter()
                .flat_map(|s| s.columns.iter())
                .find(|x| x.name == c.name)
                .unwrap_or_else(|| panic!("{} {} is in no store table", d.name, c.name));
            let fits = match found.ty {
                ColType::Str => matches!(
                    c.kind,
                    ColumnType::Text | ColumnType::Address | ColumnType::Prefix | ColumnType::List
                ),
                ColType::U64 => c.kind == ColumnType::Integer,
                ColType::Bool => c.kind == ColumnType::Boolean,
            };
            assert!(fits, "{} {} {:?}", d.name, c.name, c.kind);
        }
        if schemas.len() > 1 {
            for k in d.key.iter().filter(|k| **k != "device") {
                for s in &schemas {
                    assert!(
                        s.columns.iter().any(|x| x.name == *k),
                        "{} key {k} is not in {}",
                        d.name,
                        s.name
                    );
                }
            }
        }
    }
}

fn rows(topology: &str, t: &commands::Loaded, name: &str) -> Vec<Value> {
    rsim_cli::tables::show(topology, t, name, &Selection::default())
        .unwrap()
        .rows
        .iter()
        .map(|r| json!(r))
        .collect()
}

#[test]
#[allow(clippy::disallowed_methods)]
fn the_collected_tables_of_a_store_twin() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("rsim-cli-collected");
    let _ = std::fs::remove_dir_all(&dir);
    fixture_store::write(&dir);
    let topology = format!("store:{}", dir.display());
    let t = commands::load(&topology).unwrap();

    // The interfaces of r1: the 3 rows of `links` and the interface of the
    // row of `addresses`.
    let interfaces = rows(&topology, &t, "interfaces");
    let names: Vec<&Value> = interfaces.iter().map(|r| &r[1]).collect();
    assert_eq!(names, ["eth0", "eth0.10", "eth0.110", "pppoe0"]);
    for r in &interfaces {
        assert_eq!(r[0], "r1");
    }
    assert_eq!(interfaces[0][2], "00:00:5e:00:53:01");
    assert_eq!(interfaces[0][3], 1500);
    assert_eq!(interfaces[0][4], true);
    assert_eq!(interfaces[1][6], "eth0");
    assert_eq!(interfaces[3][2], Value::Null);
    assert_eq!(interfaces[3][10], json!(["203.0.113.10/32"]));
    let span = interfaces[3][14][0].as_str().unwrap();
    assert!(span.starts_with("r1/addresses@"), "{span}");
    let span = interfaces[0][14][0].as_str().unwrap();
    assert!(span.starts_with("r1/links@"), "{span}");
    // Each interface has a far end or the reason that it has none.
    for r in &interfaces {
        assert_ne!(r[11].is_null(), r[13].is_null(), "{r}");
    }

    // The routes of r1 in the numeric order of the prefixes.
    let routes = rows(&topology, &t, "routes");
    let prefixes: Vec<&Value> = routes.iter().map(|r| &r[2]).collect();
    assert_eq!(
        prefixes,
        [
            "0.0.0.0/0",
            "192.0.2.0/26",
            "192.0.2.64/26",
            "192.0.2.192/27"
        ]
    );
    assert_eq!(routes[0][3], "kernel");
    assert_eq!(routes[0][4], true);
    assert_eq!(routes[0][8], "pppoe0");
    // A route with no next hop has no next hop device and no reason.
    assert_eq!(
        (&routes[0][9], &routes[0][10]),
        (&Value::Null, &Value::Null)
    );

    // The store has no MAC table and no ARP table.
    assert!(rows(&topology, &t, "mac").is_empty());
    assert!(rows(&topology, &t, "arp").is_empty());
}

#[test]
fn a_hand_built_twin_has_no_collected_rows() {
    let t = commands::load("mini-enterprise").unwrap();
    for name in ["interfaces", "routes", "mac", "arp"] {
        assert!(rows("mini-enterprise", &t, name).is_empty(), "{name}");
    }
}

#[test]
fn the_links_of_a_hand_built_twin_have_both_ends() {
    let t = commands::load("leaf-spine").unwrap();
    let links = rows("leaf-spine", &t, "links");
    let row = links
        .iter()
        .find(|r| r[0] == "leaf1" && r[1] == "eth1")
        .expect("the link leaf1 eth1");
    assert_eq!(row[2], "spine1");
    assert_eq!(row[3], "eth1");
    assert_eq!(row[4], Value::Null);
    assert_eq!(row[5], Value::Null);
}

fn link(device: &str, interface: &str, peer: &str, peer_interface: &str) -> TwinLink {
    TwinLink {
        function: FunctionId::new(format!("{device}/out/{interface}")),
        device: Some(device.into()),
        interface: interface.into(),
        peer: FunctionId::new(format!("{peer}/in/{peer_interface}")),
        peer_device: Some(peer.into()),
        peer_interface: Some(peer_interface.into()),
        facts: None,
        spans: Vec::new(),
    }
}

fn mtus(rows: &[(&str, &str, Option<u64>)]) -> Mtus {
    rows.iter()
        .map(|(d, i, m)| {
            (
                (d.to_string(), i.to_string()),
                (*m, format!("{d}/links@b:1-1")),
            )
        })
        .collect()
}

#[test]
fn path_mtu_refutes_a_mismatch_and_an_end_below_the_minimum() {
    let l = link("r1", "eth0", "r2", "eth1");
    let e = path_mtu(
        &l,
        &mtus(&[("r1", "eth0", Some(1500)), ("r2", "eth1", Some(9000))]),
        None,
    );
    assert_eq!(
        (e.result, e.reason.as_str()),
        (ClaimResult::Refuted, "mismatch")
    );
    assert_eq!(e.detail, "MTU 1500 and 9000");
    assert_eq!(e.subject, "r1/out/eth0 to r2/in/eth1");

    let both = mtus(&[("r1", "eth0", Some(1500)), ("r2", "eth1", Some(1500))]);
    let e = path_mtu(&l, &both, Some(9000));
    assert_eq!(
        (e.result, e.reason.as_str()),
        (ClaimResult::Refuted, "below_minimum")
    );
    assert_eq!(e.detail, "MTU 1500 is below 9000");
    assert_eq!(
        path_mtu(&l, &both, Some(1500)).result,
        ClaimResult::Confirmed
    );
    assert_eq!(path_mtu(&l, &both, None).result, ClaimResult::Confirmed);

    let one = mtus(&[("r1", "eth0", Some(9000)), ("r2", "eth1", None)]);
    let e = path_mtu(&l, &one, Some(1500));
    assert_eq!(
        (e.result, e.reason.as_str()),
        (ClaimResult::Unknown, "not_collected")
    );
    let e = path_mtu(&l, &one, Some(9216));
    assert_eq!(e.result, ClaimResult::Refuted);
    assert_eq!(e.provenance, ["r1/links@b:1-1", "r2/links@b:1-1"]);
}

/// The MTU of an interface of r1 comes from the collected `links` row of
/// the interface. The far ends of r1 have no collected MTU.
#[test]
fn path_mtu_on_a_store_twin_reads_the_collected_mtu() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("rsim-cli-path-mtu");
    #[allow(clippy::disallowed_methods)]
    let _ = std::fs::remove_dir_all(&dir);
    fixture_store::write(&dir);
    let topology = format!("store:{}", dir.display());
    let t = commands::load(&topology).unwrap();
    let a = ClaimArgs {
        topology: topology.clone(),
        claim: "path-mtu".into(),
        devices: None,
        query: None,
        min: Some(1500),
    };
    let o = rsim_cli::claims::run(&topology, &t, &a).unwrap();
    assert_eq!(o.result, ClaimResult::Unknown);
    let r1 = o
        .evidence
        .iter()
        .find(|e| e.provenance.iter().any(|p| p.starts_with("r1/links@")))
        .expect("a row with the collected MTU of an interface of r1");
    assert!(
        r1.expected.as_ref().is_some_and(|x| x["mtu"] == 1500)
            || r1.observed.as_ref().is_some_and(|x| x["mtu"] == 1500),
        "{r1:?}"
    );
}

#[test]
fn path_mtu_compares_an_egress_with_no_far_end_with_the_minimum() {
    let e = OpenEnd {
        function: FunctionId::new("r1/out/pppoe0"),
        device: Some("r1".into()),
        interface: "pppoe0".into(),
        spans: Vec::new(),
    };
    let m = mtus(&[("r1", "pppoe0", Some(1492))]);
    let r = end_mtu(&e, &m, 1500);
    assert_eq!(
        (r.result, r.reason.as_str()),
        (ClaimResult::Refuted, "below_minimum")
    );
    assert_eq!(r.detail, "MTU 1492 is below 1500");
    assert_eq!(end_mtu(&e, &m, 1492).result, ClaimResult::Confirmed);
    assert_eq!(end_mtu(&e, &mtus(&[]), 1500).result, ClaimResult::Unknown);
}

/// The value of the column `name` of a row of a table answer.
fn cell<'a>(columns: &[String], row: &'a [Value], name: &str) -> &'a Value {
    &row[columns.iter().position(|c| c == name).unwrap()]
}

#[test]
#[allow(clippy::disallowed_methods)]
fn the_join_columns_of_a_store_twin_resolve_the_host_the_addresses_and_the_vlan() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("rsim-cli-joins");
    let _ = std::fs::remove_dir_all(&dir);
    fixture_store::write_l2(&dir);
    let topology = format!("store:{}", dir.display());
    let t = commands::load(&topology).unwrap();

    let mac = rsim_cli::tables::show(&topology, &t, "mac", &Selection::default()).unwrap();
    assert_eq!(mac.rows.len(), 2);
    for r in &mac.rows {
        let c = |n: &str| cell(&mac.columns, r, n);
        // Each join has a value or the reason that it has none.
        for (v, why) in [
            ("host", "host_reason"),
            ("peer_device", "peer_device_reason"),
            ("bridge_domain", "bridge_domain_reason"),
        ] {
            assert_ne!(c(v).is_null(), c(why).is_null(), "{v} {r:?}");
        }
        match c("mac").as_str().unwrap() {
            // The MAC address of the interface eth0 of r1.
            "00:00:5e:00:53:01" => {
                assert_eq!(*c("host"), "r1");
                assert_eq!(c("ip"), &Value::Null);
                assert_eq!(*c("ip_reason"), "not_found");
            }
            "02:00:00:00:00:10" => {
                assert_eq!(c("ip"), &json!(["198.51.100.10"]));
                assert_eq!(c("ip_reason"), &Value::Null);
            }
            m => panic!("{m}"),
        }
    }

    let arp = rsim_cli::tables::show(&topology, &t, "arp", &Selection::default()).unwrap();
    assert_eq!(arp.rows.len(), 1);
    let r = &arp.rows[0];
    let c = |n: &str| cell(&arp.columns, r, n);
    // The links row of eth0.10 has no VLAN.
    assert_eq!(
        (c("vlan"), c("vlan_reason")),
        (&Value::Null, &json!("not_found"))
    );
    assert_ne!(c("host").is_null(), c("host_reason").is_null());
    assert_ne!(
        c("access_device").is_null(),
        c("access_device_reason").is_null()
    );
    assert_eq!(c("access_device").is_null(), c("access_port").is_null());
}

#[test]
#[allow(clippy::disallowed_methods)]
fn two_twins_of_the_same_rows_share_the_frame_of_each_device() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("rsim-cli-parts");
    let _ = std::fs::remove_dir_all(&dir);
    fixture_store::write_l2(&dir);
    let topology = format!("store:{}", dir.display());
    let a = commands::load(&topology).unwrap();
    let b = commands::load(&topology).unwrap();
    for name in ["interfaces", "routes", "mac", "arp"] {
        let pa = rsim_cli::tables::parts(&a, name).unwrap();
        let pb = rsim_cli::tables::parts(&b, name).unwrap();
        assert_eq!(pa.len(), 1, "{name}");
        assert!(std::sync::Arc::ptr_eq(&pa[0], &pb[0]), "{name}");
        assert_eq!(
            rows(&topology, &a, name),
            rows(&topology, &b, name),
            "{name}"
        );
    }
}
