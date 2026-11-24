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
use rsim_ingest::collected::{Collected, LinkRow, row_span};
use rsim_ingest::estate::{Input, assemble};
use rsim_ingest::facts::{self, Sections};
use serde_json::{Value, json};

const STORE: &str = "vco-orch1-ent-1";
const BR: &str = "vco-orch1-ent-1/edge/e-br";
const HUB: &str = "vco-orch1-ent-1/edge/e-hub";
const SELECT: &str = "vco-orch1-ent-1/edge/e-br/sdwan/select/1/e-hub";
const HUB_SELECT: &str = "vco-orch1-ent-1/edge/e-hub/sdwan/select/1/e-br";
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

/// Gives `edge_state` the content of `edges`.
fn sync_state(m: &mut BTreeMap<String, Value>) {
    let edges = m["edges"].clone();
    m.insert("edge_state".into(), edges);
}

/// The twin of the sections, with the facts of the enterprise device.
fn loaded(m: &BTreeMap<String, Value>) -> Loaded {
    loaded_with(m, Vec::new())
}

/// The twin of the sections and of the devices `estate`, with the facts of
/// the enterprise device.
fn loaded_with(m: &BTreeMap<String, Value>, estate: Vec<Input>) -> Loaded {
    let s = sections(m);
    let mut inputs = vec![Input::Velocloud {
        name: STORE.to_string(),
        sections: s.clone(),
    }];
    inputs.extend(estate);
    let estate = assemble(inputs);
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
        fabric: estate.fabric,
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

/// The values of `columns` of each row of the tunnel selection `select`.
fn select_rows(out: &TableOut, select: &str, columns: &[&str]) -> Vec<Value> {
    out.rows
        .iter()
        .filter(|r| cell(out, r, "function") == select)
        .map(|r| json!(columns.iter().map(|c| cell(out, r, c)).collect::<Vec<_>>()))
        .collect()
}

/// The source spans of the WAN link of a listing row: the listing row, the
/// row of the WAN module and the row of `edge_state`.
fn link_spans(edges: (u32, u32), module: (u32, u32)) -> [String; 3] {
    [
        format!("{STORE}/edges@b1:{}-{}", edges.0, edges.1),
        format!("{STORE}/edge_modules@b1:{}-{}", module.0, module.1),
        format!("{STORE}/edge_state@b1:{}-{}", edges.0, edges.1),
    ]
}

/// The state, the reason and the far end paths of the tunnels of the
/// branch to the hub.
fn states(m: &BTreeMap<String, Value>) -> Vec<Value> {
    let out = table(&loaded(m), "sdwan-paths");
    select_rows(&out, SELECT, &["state", "state_reason", "far_paths"])
}

/// The router r1 with the address 203.0.113.129/25 on eth1.
fn router() -> Input {
    Input::Vyos {
        name: "r1".into(),
        config: include_bytes!("../../rsim-ingest/tests/fixtures/vyos/r1-config.json").to_vec(),
        file: "r1/config".into(),
        collected: Collected {
            links: vec![LinkRow {
                interface: "eth1".into(),
                mac: Some("00:00:5e:00:53:21".into()),
                parent: None,
                vlan: None,
                span: row_span("r1", "links", "b4", 0),
            }],
            ..Collected::default()
        },
    }
}

#[test]
fn each_tunnel_of_the_branch_to_the_hub_is_a_row_with_its_transport_and_its_state() {
    let t = loaded(&base());
    let out = table(&t, "sdwan-paths");
    let got = select_rows(
        &out,
        SELECT,
        &[
            "device",
            "segment",
            "tunnel",
            "interface",
            "transport",
            "peer",
            "far",
            "far_interface",
            "state",
            "state_reason",
            "far_paths",
            "provenance",
        ],
    );
    let peer = format!("{STORE}/sdwan_peers@b1:3-18");
    let spans = |near: [String; 3], far: [String; 3]| {
        let mut v: Vec<String> = near.into_iter().chain(far).collect();
        v.push(peer.clone());
        v
    };
    let want = [
        json!([
            BR,
            1,
            "l-br-dia~e-hub:l-hub-dia",
            "GE2",
            "public",
            "203.0.113.2",
            HUB,
            "GE2",
            "up",
            null,
            2,
            spans(
                link_spans((253, 268), (23, 38)),
                link_spans((426, 441), (172, 187))
            )
        ]),
        json!([
            BR,
            1,
            "l-br-mpls~e-hub:l-hub-mpls",
            "GE1",
            "MPLS-A",
            "172.16.9.2",
            HUB,
            "GE1",
            "up",
            null,
            2,
            spans(
                link_spans((237, 252), (6, 22)),
                link_spans((410, 425), (155, 171))
            )
        ]),
    ];
    assert_eq!(got, want);
    let hub = select_rows(&out, HUB_SELECT, &["state", "state_reason", "far_paths"]);
    assert_eq!(hub.len(), 2);
    for r in &hub {
        assert_eq!(r, &json!([null, "not_collected", null]));
    }
    for r in &out.rows {
        let state = cell(&out, r, "state");
        let reason = cell(&out, r, "state_reason");
        assert!(state.is_null() != reason.is_null(), "{r:?}");
    }
}

#[test]
fn a_path_count_of_the_hub_that_differs_from_the_links_that_are_up_makes_each_state_not_known() {
    let mut m = base();
    m.get_mut("sdwan_peers").unwrap()["e-br"][0]["pathStatusCount"]["stable"] = json!(1);
    let want = json!([null, "paths_differ", 1]);
    assert_eq!(states(&m), [want.clone(), want]);
}

#[test]
fn a_link_state_that_is_not_known_makes_each_state_not_known() {
    let mut m = base();
    m.get_mut("edges").unwrap()[0]["links"][1]["state"] = json!("WAITING");
    sync_state(&mut m);
    let want = json!([null, "link_state_not_known", 2]);
    assert_eq!(states(&m), [want.clone(), want]);
}

#[test]
fn a_hub_with_no_peer_row_has_each_tunnel_down_with_no_path() {
    let mut m = base();
    m.get_mut("sdwan_peers").unwrap()["e-br"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    let want = json!(["down", null, 0]);
    assert_eq!(states(&m), [want.clone(), want]);
}

#[test]
fn peers_that_are_not_collected_make_each_state_not_known() {
    let mut m = base();
    m.remove("sdwan_peers");
    let want = json!([null, "not_collected", null]);
    assert_eq!(states(&m), [want.clone(), want]);
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
    let facts: Vec<(&str, &str, &str, &Value)> = tunnel.facts["tunnels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["interface"].as_str().unwrap(),
                x["peer"].as_str().unwrap(),
                x["state"].as_str().unwrap(),
                &x["segments"],
            )
        })
        .collect();
    let segments = json!([0, 1]);
    assert!(
        facts.contains(&("GE2", "203.0.113.2", "up", &segments)),
        "{facts:?}"
    );
    assert!(
        facts.contains(&("GE1", "172.16.9.2", "up", &segments)),
        "{facts:?}"
    );
}

#[test]
fn a_wan_interface_with_a_link_of_the_join_has_a_physical_edge_to_the_estate_device() {
    let mut m = base();
    m.get_mut("edges").unwrap()[0]["configuration"]["enterprise"]["modules"][0]["edgeSpecificData"]
        ["routedInterfaces"][0]["addressing"] = json!({
        "type": "STATIC", "cidrIp": "203.0.113.130", "cidrPrefix": 25, "gateway": "203.0.113.129"
    });
    m.get_mut("edges").unwrap()[0]["links"][0]["ipAddress"] = json!("203.0.113.130");
    m.get_mut("edge_modules").unwrap()["e-br"]["WAN"]["data"]["links"][0]["nextHopIpAddress"] =
        json!("203.0.113.129");
    sync_state(&mut m);
    let t = loaded_with(&m, vec![router()]);
    let out = rsim_cli::topology::topology("velocloud", &t, &TopologyViewArgs::default()).unwrap();
    let physical: Vec<(&str, &str)> = out
        .edges
        .iter()
        .filter(|e| e.layer == "physical")
        .map(|e| (e.from.as_str(), e.to.as_str()))
        .collect();
    let has =
        |a: &'static str, b: &'static str| physical.contains(&(a, b)) || physical.contains(&(b, a));
    assert!(has(BR, "r1"), "{physical:?}");
    assert!(!has(BR, PRIVATE), "{physical:?}");
    assert!(has(BR, PUBLIC), "{physical:?}");
    assert!(has(HUB, PRIVATE), "{physical:?}");
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
