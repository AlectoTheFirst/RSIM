//! The lowering of the VeloCloud edges of an enterprise on synthetic
//! sections: the tunnels of a path, the firewall, the business policy, the
//! route order, the link steering, the hub of a cluster, 2 enterprises and
//! the determinism of the twin.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{AlternativeKind, ExitPoint, Header, PROTO_TCP, ReasonCode, Verdict};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::estate::{Estate, Input, assemble};
use serde_json::{Value, json};

const STORE: &str = "vco-orch1-ent-1";
const BR: &str = "vco-orch1-ent-1/edge/e-br";
const HUB: &str = "vco-orch1-ent-1/edge/e-hub";
const SELECT: &str = "vco-orch1-ent-1/edge/e-br/sdwan/select/1/e-hub";

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
    let path = format!(
        "{}/tests/fixtures/velocloud/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_slice(&bytes).unwrap()
}

/// The sections of the fixtures; `edge_state` has the bytes of `edges`.
fn base() -> BTreeMap<String, Value> {
    let mut m: BTreeMap<String, Value> = SECTIONS
        .iter()
        .map(|s| (s.to_string(), fixture(s)))
        .collect();
    m.insert("edge_state".into(), fixture("edges"));
    m
}

/// Gives `edge_state` the content of `edges`.
fn sync_state(m: &mut BTreeMap<String, Value>) {
    let edges = m["edges"].clone();
    m.insert("edge_state".into(), edges);
}

fn input(store: &str, m: &BTreeMap<String, Value>) -> Input {
    Input::Velocloud {
        name: store.to_string(),
        sections: m
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    (
                        serde_json::to_vec_pretty(v).unwrap(),
                        format!("{store}/{k}@b1"),
                    ),
                )
            })
            .collect(),
    }
}

fn estate(m: &BTreeMap<String, Value>) -> Estate {
    assemble(vec![input(STORE, m)])
}

fn twin(m: &BTreeMap<String, Value>) -> Twin {
    estate(m).builder.build().expect("the twin builds")
}

/// The edge-specific data of the module `index` of the branch edge.
fn branch_module(m: &mut BTreeMap<String, Value>, index: usize) -> &mut Value {
    &mut m.get_mut("edges").unwrap()[0]["configuration"]["enterprise"]["modules"][index]["edgeSpecificData"]
}

/// The outbound firewall rules of the branch edge permit each packet.
fn open_firewall(m: &mut BTreeMap<String, Value>) {
    branch_module(m, 3)["segments"][0]["outbound"] = json!([
        {"name": "allow-all", "ruleLogicalId": "fw-all", "match": {},
         "action": {"allow_or_deny": "allow"}}
    ]);
    sync_state(m);
}

/// The business rules of the branch edge in the segment `corp`.
fn edge_rules(m: &mut BTreeMap<String, Value>, rules: Value) {
    branch_module(m, 1)["segments"][0]["rules"] = rules;
    sync_state(m);
}

/// The state of the WAN link `index` of the branch edge, and the path
/// counts of its peer `e-hub`.
fn link_state(m: &mut BTreeMap<String, Value>, index: usize, state: &str, stable: i64, dead: i64) {
    m.get_mut("edges").unwrap()[0]["links"][index]["state"] = json!(state);
    sync_state(m);
    let count = &mut m.get_mut("sdwan_peers").unwrap()["e-br"][0]["pathStatusCount"];
    count["stable"] = json!(stable);
    count["dead"] = json!(dead);
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn run_from(t: &Twin, iface: &str, src: &str, dst: &str) -> Answer {
    let h = Header::request(ip(src), ip(dst), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(443);
    Executor::new(t)
        .run(&Query::path(t, &h).with_ingress(BR, iface))
        .expect("the query runs")
}

fn run(t: &Twin, dst: &str) -> Answer {
    run_from(t, "users", "10.10.10.20", dst)
}

fn functions(a: &Answer, branch: usize) -> Vec<String> {
    a.branches()[branch]
        .steps
        .iter()
        .map(|s| s.function.to_string())
        .collect()
}

fn has(f: &[String], name: &str) {
    assert!(f.iter().any(|x| x == name), "{name} is not in {f:?}");
}

fn code(v: &Verdict) -> Option<ReasonCode> {
    match v {
        Verdict::Drop(r) | Verdict::Unknown(r) => Some(r.code),
        Verdict::Deliver(_) | Verdict::Exit(_) => None,
    }
}

#[test]
fn a_path_to_a_host_behind_the_hub_has_one_candidate_for_each_tunnel_that_is_up() {
    let mut m = base();
    open_firewall(&mut m);
    let t = twin(&m);
    let a = run(&t, "10.20.20.10");
    let b = a.branches();
    assert_eq!(b.len(), 2);
    for (i, transport) in ["public", "private/MPLS-A"].iter().enumerate() {
        let f = functions(&a, i);
        let at = |name: &str| {
            f.iter()
                .position(|x| x == name)
                .unwrap_or_else(|| panic!("{name} is not in {f:?}"))
        };
        let route = format!("{STORE}/transport/{transport}/route");
        assert!(at(&format!("{BR}/firewall/1")) < at(SELECT));
        assert!(at(SELECT) < at(&route));
        assert!(at(&route) < at(&format!("{HUB}/vcmp/decap")));
        has(&f, &format!("{HUB}/route"));
        let step = b[i]
            .steps
            .iter()
            .find(|s| s.function.as_str() == SELECT)
            .unwrap();
        let alt = step.alternative.as_ref().expect("a candidate");
        assert_eq!(alt.kind, AlternativeKind::Candidate);
        assert_eq!((alt.index, alt.count), (i as u32, 2));
        let carried = b[i]
            .steps
            .iter()
            .find(|s| s.function.as_str() == route)
            .unwrap();
        let text = carried.assumption.as_deref().unwrap_or_default();
        assert!(text.contains("carries UDP 2426"), "{text}");
    }
}

#[test]
fn a_tunnel_that_is_down_is_no_candidate() {
    let mut m = base();
    open_firewall(&mut m);
    link_state(&mut m, 1, "DISCONNECTED", 1, 1);
    let t = twin(&m);
    let a = run(&t, "10.20.20.10");
    assert_eq!(a.branches().len(), 1);
    let f = functions(&a, 0);
    has(&f, &format!("{STORE}/transport/private/MPLS-A/route"));
    has(&f, &format!("{HUB}/vcmp/decap"));
    let step = a.branches()[0]
        .steps
        .iter()
        .find(|s| s.function.as_str() == SELECT)
        .copied()
        .unwrap();
    assert!(step.alternative.is_none(), "{:?}", step.alternative);
}

#[test]
fn the_firewall_of_the_branch_drops_the_packets_of_a_rule() {
    let t = twin(&base());
    let a = run(&t, "10.20.20.10");
    let v = a.verdict().expect("one result");
    assert!(matches!(v, Verdict::Drop(_)), "{v:?}");
    assert_eq!(code(v), Some(ReasonCode::Denied));
    let f = functions(&a, 0);
    assert_eq!(
        f.last().map(String::as_str),
        Some(&*format!("{BR}/firewall/1"))
    );
}

#[test]
fn a_packet_that_reaches_the_firewall_default_is_unknown() {
    let mut m = base();
    m.get_mut("profiles").unwrap()[0]["modules"][3]["data"]["segments"][0]["outbound"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["ruleLogicalId"] != "fw-chat");
    let t = twin(&m);
    let a = run_from(&t, "GE3:10", "10.9.10.20", "10.20.20.10");
    let v = a.verdict().expect("one result");
    assert!(matches!(v, Verdict::Unknown(_)), "{v:?}");
    assert_eq!(code(v), Some(ReasonCode::UnhandledStanza));
    let f = functions(&a, 0);
    assert_eq!(
        f.last().map(String::as_str),
        Some(&*format!("{BR}/firewall/1"))
    );
}

#[test]
fn the_business_policy_sends_the_packets_of_a_backhaul_rule_to_the_hub() {
    let mut m = base();
    open_firewall(&mut m);
    edge_rules(
        &mut m,
        json!([{
            "name": "backhaul", "ruleLogicalId": "rule-bh",
            "match": {"dip": "198.51.100.200", "proto": 6},
            "action": {"edge2CloudRouteAction": {
                "routePolicy": "backhaul", "linkPolicy": "auto",
                "routeCfg": {"backhaulEdges": [
                    {"logicalId": "e-hub", "name": "hub-1", "type": "edgeHub"}
                ]}
            }}
        }]),
    );
    let t = twin(&m);
    let a = run(&t, "198.51.100.200");
    assert_eq!(a.branches().len(), 2);
    for i in 0..2 {
        let f = functions(&a, i);
        let at = |name: &str| {
            f.iter()
                .position(|x| x == name)
                .unwrap_or_else(|| panic!("{name} is not in {f:?}"))
        };
        assert!(at(&format!("{BR}/policy/1")) < at(SELECT));
        assert!(at(SELECT) < at(&format!("{HUB}/vcmp/decap")));
        assert!(at(&format!("{HUB}/vcmp/decap")) < at(&format!("{HUB}/policy/1")));
    }
}

#[test]
fn a_direct_rule_leaves_the_twin_at_the_wan_interface() {
    let mut m = base();
    open_firewall(&mut m);
    edge_rules(
        &mut m,
        json!([{
            "name": "direct", "ruleLogicalId": "rule-direct",
            "match": {"dip": "198.51.100.200"},
            "action": {"edge2CloudRouteAction": {"routePolicy": "direct", "linkPolicy": "auto"}}
        }]),
    );
    branch_module(&mut m, 0)["routedInterfaces"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "name": "GE2", "wanOverlay": "AUTO_DISCOVERED", "segmentId": -1, "natDirect": true,
            "addressing": {"type": "STATIC", "cidrIp": "198.51.100.2", "cidrPrefix": 30,
                           "gateway": "198.51.100.1"}
        }));
    sync_state(&mut m);
    let t = twin(&m);
    let a = run(&t, "198.51.100.200");
    assert_eq!(
        a.verdict(),
        Some(&Verdict::Exit(ExitPoint {
            device: BR.into(),
            interface: "GE2".into(),
        }))
    );
    let f = functions(&a, 0);
    for want in ["policy/1", "direct/1", "snat", "nexthop/direct", "exit/GE2"] {
        has(&f, &format!("{BR}/{want}"));
    }
    let snat = a.branches()[0]
        .steps
        .iter()
        .find(|s| s.function.as_str() == format!("{BR}/snat"))
        .copied()
        .unwrap();
    let w = snat.output.witness().unwrap().current;
    assert_eq!(w.src_ip, rsim_core::FieldValue::Known(ip("198.51.100.2")));
}

#[test]
fn the_route_order_of_2_prefixes_of_the_administration_guide() {
    let mut m = base();
    open_firewall(&mut m);
    let subnets = m.get_mut("route_table").unwrap()["subnets"]
        .as_array_mut()
        .unwrap();
    for p in ["10.50.0.0/16", "10.60.0.0/16"] {
        subnets.push(json!({
            "subnet": format!("{p}:1"),
            "preferredExits": [{"type": "CONNECTED", "exitType": "EDGE",
                                "edgeLogicalId": "e-hub", "segmentId": 1}],
            "eligableExits": []
        }));
    }
    let t = twin(&m);
    let a = run(&t, "10.50.1.1");
    let f = functions(&a, 0);
    has(&f, &format!("{BR}/nexthop"));
    assert!(!f.iter().any(|x| x == SELECT), "{f:?}");
    let a = run(&t, "10.60.1.1");
    let f = functions(&a, 0);
    has(&f, SELECT);
}

#[test]
fn mandatory_steering_to_a_link_that_is_down_drops_the_packets() {
    let mut m = base();
    open_firewall(&mut m);
    edge_rules(
        &mut m,
        json!([{
            "name": "pin", "ruleLogicalId": "rule-pin",
            "match": {"dip": "10.20.20.0", "dsm": "255.255.255.0", "proto": 6},
            "action": {"edge2EdgeRouteAction": {"linkPolicy": "fixed", "wanlink": "l-br-mpls"}}
        }]),
    );
    link_state(&mut m, 0, "DISCONNECTED", 1, 1);
    let t = twin(&m);
    let a = run(&t, "10.20.20.10");
    let v = a.verdict().expect("one result");
    assert!(matches!(v, Verdict::Drop(_)), "{v:?}");
    assert_eq!(code(v), Some(ReasonCode::NoNeighbour));
    let f = functions(&a, 0);
    assert_eq!(f.last().map(String::as_str), Some(SELECT));
}

#[test]
fn a_hub_of_a_cluster_with_no_sdwan_peers_data_is_unknown() {
    let mut m = base();
    open_firewall(&mut m);
    m.remove("sdwan_peers");
    edge_rules(
        &mut m,
        json!([{
            "name": "backhaul", "ruleLogicalId": "rule-bh",
            "match": {"dip": "198.51.100.200"},
            "action": {"edge2CloudRouteAction": {
                "routePolicy": "backhaul", "linkPolicy": "auto",
                "routeCfg": {"backhaulEdges": [{"name": "DC-CLUSTER", "type": "edgeHubCluster"}]}
            }}
        }]),
    );
    let t = twin(&m);
    let a = run(&t, "198.51.100.200");
    let v = a.verdict().expect("one result");
    assert!(matches!(v, Verdict::Unknown(_)), "{v:?}");
    assert_eq!(code(v), Some(ReasonCode::NotCollected));
    let f = functions(&a, 0);
    assert_eq!(f.last().map(String::as_str), Some(SELECT));
}

#[test]
fn the_edges_and_the_transports_of_2_enterprises_stay_apart() {
    let mut m = base();
    open_firewall(&mut m);
    let e = assemble(vec![input(STORE, &m), input("vco-orch1-ent-2", &m)]);
    let t = e.builder.build().expect("the twin builds");
    let h = Header::request(ip("10.10.10.20"), ip("10.20.20.10"), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(443);
    let a = Executor::new(&t)
        .run(&Query::path(&t, &h).with_ingress("vco-orch1-ent-2/edge/e-br", "users"))
        .expect("the query runs");
    assert_eq!(a.branches().len(), 2);
    for b in a.branches() {
        for s in &b.steps {
            assert!(
                s.function.as_str().starts_with("vco-orch1-ent-2/"),
                "{}",
                s.function
            );
        }
    }
}

#[test]
fn each_edge_has_its_coverage_and_the_same_sections_give_the_same_twin() {
    let mut m = base();
    open_firewall(&mut m);
    let one = estate(&m);
    let two = estate(&m);
    for d in [STORE, BR, HUB] {
        assert!(one.coverage.contains_key(d), "{d}");
    }
    assert_eq!(one.coverage, two.coverage);
    assert_eq!(one.notes, two.notes);
    let t1 = one.builder.build().expect("the twin builds");
    let t2 = two.builder.build().expect("the twin builds");
    for dst in ["10.20.20.10", "10.50.1.1", "198.51.100.200"] {
        let a = run(&t1, dst);
        let b = run(&t2, dst);
        assert_eq!(format!("{:?}", a.verdict()), format!("{:?}", b.verdict()));
        assert_eq!(a.branches().len(), b.branches().len());
        for i in 0..a.branches().len() {
            assert_eq!(functions(&a, i), functions(&b, i));
        }
    }
}
