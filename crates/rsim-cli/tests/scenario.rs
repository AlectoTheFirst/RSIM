//! The link-down layers of `--down` on a store twin of the OSPF triangle of
//! the NX-OS switches r1, r2 and r3.

use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

#[path = "support/fixture_store.rs"]
mod fixture_store;

const LAYER: &str = "layer 1: link-down r1:Ethernet1/1";

/// The data folder of the triangle, written once for each test.
#[allow(clippy::disallowed_methods)]
fn store(name: &str) -> String {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    fixture_store::write_triangle(&dir);
    format!("store:{}", dir.display())
}

fn rsim(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rsim"))
        .args(args)
        .output()
        .expect("rsim runs")
}

fn json_of(o: &Output) -> Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: {}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    })
}

/// The flags of a path query from the LAN host of r1 to `dst`.
fn query(dst: &str) -> Vec<String> {
    [
        "--ingress",
        "r1/Ethernet1/3",
        "--source.ip",
        "203.0.113.10",
        "--destination.ip",
        dst,
        "--network.transport",
        "tcp",
        "--source.port",
        "40000",
        "--destination.port",
        "22",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn path(topology: &str, dst: &str, down: &[&str]) -> Output {
    let mut a: Vec<String> = vec!["path".into(), topology.into()];
    a.extend(query(dst));
    a.extend(["--no-reply", "--format", "json"].map(String::from));
    for d in down {
        a.extend(["--down".to_string(), d.to_string()]);
    }
    let args: Vec<&str> = a.iter().map(String::as_str).collect();
    rsim(&args)
}

/// The devices of the steps of the one branch of a path answer, each once
/// in order.
fn devices(v: &Value) -> Vec<String> {
    let branches = v["answer"]["branches"].as_array().unwrap();
    assert_eq!(branches.len(), 1, "{v:#}");
    let mut out: Vec<String> = Vec::new();
    for s in branches[0]["steps"].as_array().unwrap() {
        let f = s["function"].as_str().unwrap();
        let d = f.split('/').next().unwrap().to_string();
        if out.last() != Some(&d) {
            out.push(d);
        }
    }
    out
}

#[test]
fn a_link_down_moves_the_path_and_the_twin_has_the_layer() {
    let topology = store("rsim-cli-scenario-path");
    let base = path(&topology, "203.0.113.74", &[]);
    assert_eq!(base.status.code(), Some(0), "{base:?}");
    let v = json_of(&base);
    assert_eq!(devices(&v), ["r1", "r2"]);
    assert_eq!(v["twin"]["layers"], serde_json::json!([]));
    assert!(!v.to_string().contains(LAYER));

    let o = path(&topology, "203.0.113.74", &["r1:Ethernet1/1"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let v = json_of(&o);
    assert_eq!(devices(&v), ["r1", "r3", "r2"]);
    assert_eq!(
        v["twin"]["layers"],
        serde_json::json!(["link-down r1:Ethernet1/1"])
    );
    let id = v["twin"]["id"].as_str().unwrap();
    let snapshot = json_of(&base)["twin"]["id"].as_str().unwrap().to_string();
    assert_eq!(id.len(), snapshot.len() + 2 + 12);
    assert!(id.starts_with(&format!("{snapshot}~~")), "{id}");
    assert_eq!(v["twin"]["base"], snapshot.as_str());
    assert!(v.to_string().contains(LAYER), "{v:#}");

    // The same scenario gives the same bytes.
    let again = path(&topology, "203.0.113.74", &["r1:Ethernet1/1"]);
    assert_eq!(again.stdout, o.stdout);
}

#[test]
fn a_bgp_route_is_unknown_with_a_layer_and_the_claim_and_the_table_take_the_layer() {
    let topology = store("rsim-cli-scenario-claim");
    let o = path(&topology, "192.0.2.130", &["r2:Ethernet1/2"]);
    let v = json_of(&o);
    assert_eq!(devices(&v), ["r1"]);
    let text = v.to_string();
    assert!(text.contains("routing not recomputed"), "{v:#}");

    let claim = |down: &[&str]| {
        let mut a: Vec<String> = [topology.as_str(), "claim", "run", "no-unknown"]
            .map(String::from)
            .to_vec();
        a.extend(query("192.0.2.130"));
        for d in down {
            a.extend(["--down".to_string(), d.to_string()]);
        }
        a.extend(["--format", "json"].map(String::from));
        let args: Vec<&str> = a.iter().map(String::as_str).collect();
        rsim(&args)
    };
    let base = claim(&[]);
    assert_eq!(base.status.code(), Some(0), "{base:?}");
    let o = claim(&["r2:Ethernet1/2"]);
    let v = json_of(&o);
    assert_ne!(v["result"], "confirmed", "{v:#}");
    assert_eq!(
        v["twin"]["layers"],
        serde_json::json!(["link-down r2:Ethernet1/2"])
    );

    // The row of 203.0.113.64/26 of r1 in the table `fib`.
    let fib = |down: &[&str]| {
        let mut a = vec![
            topology.as_str(),
            "fib",
            "show",
            "--device",
            "r1",
            "--format",
            "json",
        ];
        for d in down {
            a.extend(["--down", *d]);
        }
        let v = json_of(&rsim(&a));
        let columns: Vec<&str> = v["columns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        let at = columns.iter().position(|c| *c == "prefix").unwrap();
        let rows: Vec<&Value> = v["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r[at] == "203.0.113.64/26")
            .collect();
        assert_eq!(rows.len(), 1, "{v:#}");
        (rows[0].to_string(), v["twin"]["layers"].clone())
    };
    let (row, layers) = fib(&[]);
    assert!(row.contains("198.51.100.2@Ethernet1/1"), "{row}");
    assert_eq!(layers, serde_json::json!([]));
    let (row, layers) = fib(&["r1:Ethernet1/1"]);
    assert!(row.contains("198.51.100.6@Ethernet1/2"), "{row}");
    assert!(!row.contains("@Ethernet1/1"), "{row}");
    assert!(row.contains(LAYER), "{row}");
    assert_eq!(layers, serde_json::json!(["link-down r1:Ethernet1/1"]));
}

#[test]
fn a_layer_is_refused_on_a_missing_interface_and_on_a_hand_built_twin() {
    let topology = store("rsim-cli-scenario-refused");
    let o = path(&topology, "203.0.113.74", &["r1:Ethernet1/9"]);
    assert_eq!(o.status.code(), Some(1));
    let v = json_of(&o);
    assert_eq!(v["error"]["code"], "invalid_query", "{v:#}");
    assert!(
        v["error"]["detail"]
            .as_str()
            .unwrap()
            .contains("no interface Ethernet1/9 in the config of r1"),
        "{v:#}"
    );
    let o = path("leaf-spine", "203.0.113.74", &["r1:Ethernet1/1"]);
    assert_eq!(json_of(&o)["error"]["code"], "invalid_query");
    let o = path(&topology, "203.0.113.74", &["r1-Ethernet1/1"]);
    assert_eq!(json_of(&o)["error"]["code"], "invalid_query");
}
