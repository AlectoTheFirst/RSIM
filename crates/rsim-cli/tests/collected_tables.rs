//! The tables of the collected state: the registry rows against the store
//! schemas, and the rows of a store twin.

use rsim_cli::commands;
use rsim_contract::table::{self, ColumnType, Selection};
use rsim_store::ColType;
use serde_json::{Value, json};

#[path = "support/fixture_store.rs"]
mod fixture_store;

/// Each column of a table of the collected state, other than `device` and
/// `provenance`, is a column of 1 of its store tables with a matching type.
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
        for c in d.columns {
            if c.name == "device" || c.name == "provenance" {
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
    assert_eq!(interfaces[0][4], true);
    assert_eq!(interfaces[1][6], "eth0");
    assert_eq!(interfaces[3][2], Value::Null);
    assert_eq!(interfaces[3][10], json!(["203.0.113.10/32"]));
    let span = interfaces[3][11][0].as_str().unwrap();
    assert!(span.starts_with("r1/addresses@"), "{span}");
    let span = interfaces[0][11][0].as_str().unwrap();
    assert!(span.starts_with("r1/links@"), "{span}");

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
