//! The topology layers, the table `sdwan-paths` and the device facts of a
//! twin of VeloCloud edges, on the synthetic sections of `rsim-ingest`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rsim_cli::commands::Loaded;
use rsim_contract::args::TopologyViewArgs;
use rsim_contract::table::{Selection, TableOut};
use rsim_contract::twin::TwinJson;
use rsim_core::{Header, PROTO_TCP};
use rsim_engine::{Executor, Query};
use rsim_ingest::estate::{Input, assemble};
use rsim_ingest::facts::{self, Sections};
use serde_json::{Value, json};

const STORE: &str = "vco-orch1-ent-1";
const BR: &str = "vco-orch1-ent-1/edge/e-br";
const HUB: &str = "vco-orch1-ent-1/edge/e-hub";
const SELECT: &str = "vco-orch1-ent-1/edge/e-br/sdwan/select/1/e-hub";
const PUBLIC: &str = "vco-orch1-ent-1/transport/public";
const PRIVATE: &str = "vco-orch1-ent-1/transport/private/MPLS-A";

const SECTIONS: &[&str] = &[
    "aggregates",
    "bgp_sessions",
    "edge_modules",
    "edges",
    "object_groups",
    "profiles",
    "route_table",
    "sdwan_peers",
];

fn fixture(name: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rsim-ingest/tests/fixtures/velocloud")
        .join(format!("{name}.json"));
    let bytes = std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    serde_json::from_slice(&bytes).unwrap()
}

/// The sections of the fixtures, with the firewall of the branch open and
/// no LAN BGP neighbour; `edge_state` has the bytes of `edges`.
fn base() -> BTreeMap<String, Value> {
    let mut m: BTreeMap<String, Value> = SECTIONS
        .iter()
        .map(|s| (s.to_string(), fixture(s)))
        .collect();
    let edges = m.get_mut("edges").unwrap();
    edges[0]["configuration"]["enterprise"]["modules"][3]["edgeSpecificData"]["segments"][0]["outbound"] = json!([
        {"name": "allow-all", "ruleLogicalId": "fw-all", "match": {},
         "action": {"allow_or_deny": "allow"}}
    ]);
    for e in edges.as_array_mut().unwrap() {
        e["configuration"]["enterprise"]["modules"][0]["edgeSpecificData"]["segments"][0]["bgp"]
            ["neighbors"] = json!([]);
    }
    let edges = m["edges"].clone();
    m.insert("edge_state".into(), edges);
    m
}

fn sections(m: &BTreeMap<String, Value>) -> Sections {
    m.iter()
        .map(|(k, v)| {
            (
                k.clone(),
                (
                    serde_json::to_vec_pretty(v).unwrap(),
                    format!("{STORE}/{k}@b1"),
                ),
            )
        })
        .collect()
}

/// The twin of the sections, with the facts of the enterprise device.
fn loaded(m: &BTreeMap<String, Value>) -> Loaded {
    let s = sections(m);
    let estate = assemble(vec![Input::Velocloud {
        name: STORE.to_string(),
        sections: s.clone(),
    }]);
    let facts = facts::device(STORE, "velocloud", 1_700_000_000_000, None, &s)
        .into_iter()
        .collect();
    Loaded {
        twin: estate.builder.build().expect("the twin builds"),
        identity: TwinJson::builtin("velocloud").unwrap(),
        coverage: estate.coverage,
        bgp: estate.bgp,
        facts,
        seen: estate.seen,
        tables: Default::default(),
        source: None,
    }
}

fn table(t: &Loaded, name: &str) -> TableOut {
    rsim_cli::tables::show("velocloud", t, name, &Selection::default()).unwrap()
}

/// The value of a column of a row.
fn cell<'a>(out: &TableOut, row: &'a [Value], column: &str) -> &'a Value {
    let i = out
        .columns
        .iter()
        .position(|c| c == column)
        .unwrap_or_else(|| panic!("{column} is not a column"));
    &row[i]
}

#[test]
fn each_tunnel_of_the_branch_to_the_hub_is_a_row_with_its_transport_and_its_state() {
    let t = loaded(&base());
    let out = table(&t, "sdwan-paths");
    let rows: Vec<&Vec<Value>> = out
        .rows
        .iter()
        .filter(|r| cell(&out, r, "function") == SELECT)
        .collect();
    let got: Vec<Vec<&Value>> = rows
        .iter()
        .map(|r| {
            [
                "device",
                "segment",
                "tunnel",
                "interface",
                "transport",
                "peer",
                "far",
                "state",
                "state_reason",
                "paths",
            ]
            .iter()
            .map(|c| cell(&out, r, c))
            .collect()
        })
        .collect();
    let want = [
        json!([
            BR,
            1,
            "l-br-dia~e-hub:l-hub-dia",
            "GE2",
            "public",
            "203.0.113.2",
            HUB,
            "up",
            null,
            2
        ]),
        json!([
            BR,
            1,
            "l-br-mpls~e-hub:l-hub-mpls",
            "GE1",
            "MPLS-A",
            "172.16.9.2",
            HUB,
            "up",
            null,
            2
        ]),
    ];
    let got: Vec<Value> = got.into_iter().map(|r| json!(r)).collect();
    assert_eq!(got, want);
    for r in &rows {
        let spans = cell(&out, r, "provenance").as_array().unwrap();
        assert!(!spans.is_empty());
    }
    for r in &out.rows {
        let state = cell(&out, r, "state");
        let reason = cell(&out, r, "state_reason");
        assert!(state.is_null() != reason.is_null(), "{r:?}");
    }
}

#[test]
fn each_edge_has_its_facts_under_its_twin_device_with_the_enterprise_as_its_store_device() {
    let mut m = base();
    m.get_mut("edges").unwrap()[1]["serialNumber"] = json!("0000");
    let t = loaded(&m);
    let devices: Vec<String> = t.devices().iter().map(ToString::to_string).collect();
    for d in t.facts.keys() {
        assert!(devices.contains(d), "{d} is not a device of the twin");
    }
    let out = table(&t, "devices");
    let row = |d: &str| {
        out.rows
            .iter()
            .find(|r| cell(&out, r, "device") == d)
            .unwrap_or_else(|| panic!("no row of {d}"))
    };
    let br = row(BR);
    assert_eq!(cell(&out, br, "vendor"), "velocloud");
    assert_eq!(cell(&out, br, "platform"), "edge610");
    assert_eq!(cell(&out, br, "os_version"), "6.4.0");
    assert_eq!(cell(&out, br, "serial"), "S-e-br");
    assert_eq!(cell(&out, br, "store_device"), STORE);
    assert_eq!(cell(&out, br, "management_address_reason"), "not_collected");
    let spans = cell(&out, br, "provenance").as_array().unwrap();
    assert_eq!(spans.len(), 3);
    assert!(spans.iter().all(|s| {
        s.as_str()
            .unwrap()
            .starts_with(&format!("{STORE}/edges@b1:"))
    }));
    let hub = row(HUB);
    assert_eq!(cell(&out, hub, "platform"), "edge3400");
    assert!(cell(&out, hub, "serial").is_null());
    assert_eq!(cell(&out, hub, "serial_reason"), "not_read");
    assert_eq!(cell(&out, hub, "store_device"), STORE);
    assert!(out.rows.iter().all(|r| cell(&out, r, "device") != STORE));
}

#[test]
fn a_transport_network_is_a_network_node_with_a_link_to_each_wan_interface() {
    let t = loaded(&base());
    let out = rsim_cli::topology::topology("velocloud", &t, &TopologyViewArgs::default()).unwrap();
    let kind = |id: &str| {
        out.nodes
            .iter()
            .find(|n| n.id == id)
            .map(|n| n.kind.as_str())
            .unwrap_or_else(|| panic!("no node {id}"))
    };
    assert_eq!(kind(PUBLIC), "network");
    assert_eq!(kind(PRIVATE), "network");
    assert_eq!(kind(BR), "device");
    assert_eq!(kind(HUB), "device");
    let physical: Vec<(&str, &str)> = out
        .edges
        .iter()
        .filter(|e| e.layer == "physical")
        .map(|e| (e.from.as_str(), e.to.as_str()))
        .collect();
    for pair in [(BR, PUBLIC), (BR, PRIVATE), (HUB, PUBLIC), (HUB, PRIVATE)] {
        assert!(
            physical.contains(&pair) || physical.contains(&(pair.1, pair.0)),
            "{pair:?} is not in {physical:?}"
        );
    }
    let tunnel = out
        .edges
        .iter()
        .find(|e| e.id == format!("overlay:{BR}>{HUB}"))
        .expect("the overlay edge of the branch to the hub");
    let facts: Vec<(&str, &str, &str)> = tunnel.facts["tunnels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["interface"].as_str().unwrap(),
                x["peer"].as_str().unwrap(),
                x["state"].as_str().unwrap(),
            )
        })
        .collect();
    assert!(facts.contains(&("GE2", "203.0.113.2", "up")), "{facts:?}");
    assert!(facts.contains(&("GE1", "172.16.9.2", "up")), "{facts:?}");
}

#[test]
fn the_drawing_of_a_path_to_the_hub_has_the_tunnel_through_each_transport_network() {
    let t = loaded(&base());
    let h = Header::request(
        "10.10.10.20".parse().unwrap(),
        "10.20.20.10".parse().unwrap(),
        PROTO_TCP,
    )
    .with_src_port(40000)
    .with_dst_port(443);
    let a = Executor::new(&t.twin)
        .run(&Query::path(&t.twin, &h).with_ingress(BR, "users"))
        .expect("the query runs");
    let out = rsim_cli::topology::drawing("velocloud", &t, &a);
    let over = format!("overlay:{BR}>{HUB}");
    let tunnel = out
        .edges
        .iter()
        .find(|e| e.id == over)
        .expect("the overlay edge");
    assert_eq!(tunnel.branches, [0, 1]);
    let underlay: Vec<(&str, &str, Option<&str>)> = out
        .edges
        .iter()
        .filter(|e| e.layer == "underlay")
        .map(|e| (e.from.as_str(), e.to.as_str(), e.overlay.as_deref()))
        .collect();
    for hop in [(BR, PUBLIC), (PUBLIC, HUB), (BR, PRIVATE), (PRIVATE, HUB)] {
        let want = (hop.0, hop.1, Some(over.as_str()));
        assert!(underlay.contains(&want), "{want:?} is not in {underlay:?}");
    }
    let kinds: BTreeMap<&str, &str> = out
        .nodes
        .iter()
        .map(|n| (n.id.as_str(), n.kind.as_str()))
        .collect();
    assert_eq!(kinds.get(PUBLIC), Some(&"network"));
}
