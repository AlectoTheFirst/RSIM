//! The lowering of the VeloCloud edges of an enterprise on synthetic
//! sections: the tunnels of a path and the results of their candidates, the
//! firewall, the business policy, the route order, the LAN BGP of a
//! segment, the link steering, the hub of a cluster, 2 enterprises, the
//! determinism of the twin, the links of the join to a switch on the LAN
//! side and to a router on the WAN side, and a WAN gateway on an SVI with no
//! link.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{AlternativeKind, ExitPoint, Header, PROTO_TCP, ReasonCode, Verdict, VerdictKind};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::collected::{Collected, LinkRow, MacRow, NeighbourRow, row_span};
use rsim_ingest::estate::{Estate, Input, assemble};
use serde_json::{Value, json};

const STORE: &str = "vco-orch1-ent-1";
const BR: &str = "vco-orch1-ent-1/edge/e-br";
const HUB: &str = "vco-orch1-ent-1/edge/e-hub";
const SELECT: &str = "vco-orch1-ent-1/edge/e-br/sdwan/select/1/e-hub";
const BACKHAUL: &str = "vco-orch1-ent-1/edge/e-br/sdwan/select/1/e-hub/backhaul";

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

/// The segment `corp` of each edge has no LAN BGP neighbour.
fn no_lan_bgp(m: &mut BTreeMap<String, Value>) {
    for e in m.get_mut("edges").unwrap().as_array_mut().unwrap() {
        e["configuration"]["enterprise"]["modules"][0]["edgeSpecificData"]["segments"][0]["bgp"]
            ["neighbors"] = json!([]);
    }
    sync_state(m);
}

/// The hub edge `e-hub2`, with no WAN link and no LAN, is the second
/// member of the cluster `cl-dc` of `e-hub`.
fn second_hub(m: &mut BTreeMap<String, Value>) {
    let edges = m.get_mut("edges").unwrap().as_array_mut().unwrap();
    let mut hub = edges[1].clone();
    hub["_href"] = json!("/api/sdwan/v2/enterprises/ent-1/edges/e-hub2");
    hub["id"] = json!(3);
    hub["logicalId"] = json!("e-hub2");
    hub["name"] = json!("hub-2");
    hub["serialNumber"] = json!("S-e-hub2");
    hub["links"] = json!([]);
    hub["configuration"]["enterprise"]["modules"][0]["edgeSpecificData"] = json!({});
    edges.push(hub);
    sync_state(m);
    m.get_mut("edge_modules").unwrap()["e-br"]["controlPlane"]["data"]["segments"][0]["vpn"]
        ["dataCenterEdges"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "logicalId": "e-hub2", "clusterLogicalId": "cl-dc", "clusterName": " DC-CLUSTER",
            "name": "hub-2", "type": "edgeHubCluster"
        }));
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

fn detail(v: &Verdict) -> &str {
    match v {
        Verdict::Drop(r) | Verdict::Unknown(r) => &r.detail,
        Verdict::Deliver(_) | Verdict::Exit(_) => "",
    }
}

#[test]
fn a_path_to_a_host_behind_the_hub_has_one_candidate_for_each_tunnel_that_is_up() {
    let mut m = base();
    open_firewall(&mut m);
    no_lan_bgp(&mut m);
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
        assert!(at(&format!("{BR}/firewall/1")) < at(&format!("{SELECT}/qos")));
        assert!(at(&format!("{SELECT}/qos")) < at(SELECT));
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
        assert!(
            matches!(b[i].verdict, Verdict::Unknown(_)),
            "{:?}",
            b[i].verdict
        );
        assert_eq!(code(b[i].verdict), Some(ReasonCode::IncompleteTable));
        assert_eq!(
            f.last().map(String::as_str),
            Some(&*format!("{HUB}/nexthop"))
        );
    }
    let summary = a.single_summary().expect("one part");
    assert_eq!(summary.kind(), Some(VerdictKind::Unknown));
}

#[test]
fn candidates_with_the_same_result_give_that_result() {
    let mut m = base();
    open_firewall(&mut m);
    no_lan_bgp(&mut m);
    let t = twin(&m);
    let a = run(&t, "10.20.20.1");
    assert_eq!(a.branches().len(), 2);
    let v = a.verdict().expect("one result");
    assert!(matches!(v, Verdict::Deliver(_)), "{v:?}");
}

#[test]
fn candidates_with_different_results_are_unknown() {
    let mut m = base();
    open_firewall(&mut m);
    no_lan_bgp(&mut m);
    m.get_mut("edges").unwrap()[1]["links"][1]["ipAddress"] = json!("198.51.100.2");
    sync_state(&mut m);
    let t = twin(&m);
    let a = run(&t, "10.20.20.1");
    let b = a.branches();
    assert_eq!(b.len(), 2);
    let kinds: Vec<VerdictKind> = b.iter().map(|x| x.verdict.kind()).collect();
    assert!(kinds.contains(&VerdictKind::Deliver), "{kinds:?}");
    assert!(kinds.contains(&VerdictKind::Unknown), "{kinds:?}");
    let v = a.verdict().expect("one result");
    assert!(matches!(v, Verdict::Unknown(_)), "{v:?}");
    assert_eq!(code(v), Some(ReasonCode::SelectionNotCollected));
}

#[test]
fn a_segment_with_a_lan_bgp_neighbour_answers_only_for_its_connected_routes() {
    let mut m = base();
    open_firewall(&mut m);
    let t = twin(&m);
    for dst in ["10.20.20.10", "10.50.1.1", "198.51.100.200"] {
        let a = run(&t, dst);
        let v = a.verdict().expect("one result");
        assert!(matches!(v, Verdict::Unknown(_)), "{dst}: {v:?}");
        assert_eq!(code(v), Some(ReasonCode::NotCollected), "{dst}");
        assert!(
            detail(v).ends_with("lan learned routes not collected"),
            "{dst}: {v:?}"
        );
        let f = functions(&a, 0);
        assert_eq!(f.last().map(String::as_str), Some(&*format!("{BR}/route")));
    }
    let a = run(&t, "10.9.9.50");
    has(&functions(&a, 0), &format!("{BR}/nexthop"));
}

#[test]
fn a_tunnel_that_is_down_is_no_candidate() {
    let mut m = base();
    open_firewall(&mut m);
    no_lan_bgp(&mut m);
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
    no_lan_bgp(&mut m);
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
        assert!(at(&format!("{BR}/policy/1")) < at(BACKHAUL));
        assert!(at(BACKHAUL) < at(&format!("{HUB}/vcmp/decap")));
        assert!(at(&format!("{HUB}/vcmp/decap")) < at(&format!("{HUB}/policy/1")));
    }
}

#[test]
fn a_direct_rule_leaves_the_twin_at_the_wan_interface() {
    let mut m = base();
    open_firewall(&mut m);
    no_lan_bgp(&mut m);
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
    no_lan_bgp(&mut m);
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
fn a_pinned_link_that_is_down_makes_the_packets_unknown() {
    let mut m = base();
    open_firewall(&mut m);
    no_lan_bgp(&mut m);
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
    assert!(matches!(v, Verdict::Unknown(_)), "{v:?}");
    assert_eq!(code(v), Some(ReasonCode::NotCollected));
    assert!(detail(v).contains("steering rule rule-pin"), "{v:?}");
    let f = functions(&a, 0);
    assert_eq!(f.last().map(String::as_str), Some(SELECT));
}

/// The business rules of the branch edge send the packets to
/// 198.51.100.200 to the cluster `DC-CLUSTER`.
fn backhaul_to_the_cluster(m: &mut BTreeMap<String, Value>) {
    edge_rules(
        m,
        json!([{
            "name": "backhaul", "ruleLogicalId": "rule-bh",
            "match": {"dip": "198.51.100.200"},
            "action": {"edge2CloudRouteAction": {
                "routePolicy": "backhaul", "linkPolicy": "auto",
                "routeCfg": {"backhaulEdges": [{"name": "DC-CLUSTER", "type": "edgeHubCluster"}]}
            }}
        }]),
    );
}

#[test]
fn a_hub_of_a_cluster_with_no_sdwan_peers_data_is_unknown() {
    let mut m = base();
    open_firewall(&mut m);
    no_lan_bgp(&mut m);
    second_hub(&mut m);
    m.remove("sdwan_peers");
    backhaul_to_the_cluster(&mut m);
    let t = twin(&m);
    let a = run(&t, "198.51.100.200");
    let v = a.verdict().expect("one result");
    assert!(matches!(v, Verdict::Unknown(_)), "{v:?}");
    assert_eq!(code(v), Some(ReasonCode::NotCollected));
    assert!(
        detail(v).ends_with("hub of cluster cl-dc not collected"),
        "{v:?}"
    );
    let f = functions(&a, 0);
    let last = f.last().map(String::as_str).unwrap_or_default();
    assert!(last.starts_with(&format!("{BR}/unknown/1/")), "{f:?}");
}

#[test]
fn the_hub_of_a_cluster_with_a_path_in_sdwan_peers_is_the_far_end() {
    let mut m = base();
    open_firewall(&mut m);
    no_lan_bgp(&mut m);
    second_hub(&mut m);
    backhaul_to_the_cluster(&mut m);
    let t = twin(&m);
    let a = run(&t, "198.51.100.200");
    assert_eq!(a.branches().len(), 2);
    for i in 0..2 {
        let f = functions(&a, i);
        has(&f, BACKHAUL);
        has(&f, &format!("{HUB}/vcmp/decap"));
    }
}

#[test]
fn the_edges_and_the_transports_of_2_enterprises_stay_apart() {
    let mut m = base();
    open_firewall(&mut m);
    no_lan_bgp(&mut m);
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

const SWITCH: &str = "sw1";

fn arp_row(iface: &str, ip: &str, mac: &str, i: u64) -> NeighbourRow {
    NeighbourRow {
        interface: iface.into(),
        ip: ip.into(),
        mac: Some(mac.into()),
        state: None,
        span: row_span(SWITCH, "neighbours", "b2", i),
    }
}

fn mac_row(vlan: u64, mac: &str, port: &str, i: u64) -> MacRow {
    MacRow {
        vlan,
        mac: mac.into(),
        port: Some(port.into()),
        kind: Some("dynamic".into()),
        span: row_span(SWITCH, "mac_table", "b3", i),
    }
}

fn link_row(device: &str, iface: &str, mac: &str) -> LinkRow {
    LinkRow {
        interface: iface.into(),
        mac: Some(mac.into()),
        parent: None,
        vlan: None,
        span: row_span(device, "links", "b4", 0),
    }
}

/// An NX-OS switch with the host 192.0.2.130 on the access port
/// Ethernet1/5 in VLAN 30, the branch address 192.0.2.40 on the access port
/// Ethernet1/6 in VLAN 10, and a route to the LAN of the hub through the
/// branch.
fn switch() -> Input {
    let config = "hostname sw1
feature interface-vlan
vlan 10,30
interface Vlan10
  no shutdown
  ip address 192.0.2.2/26
interface Vlan30
  no shutdown
  ip address 192.0.2.129/26
interface Ethernet1/5
  switchport
  switchport access vlan 30
  no shutdown
interface Ethernet1/6
  switchport
  switchport access vlan 10
  no shutdown
ip route 10.20.0.0/16 192.0.2.40
";
    let interfaces = json!({"TABLE_interface": {"ROW_interface": [
        {"interface": "Ethernet1/5", "admin_state": "up", "state": "up"},
        {"interface": "Ethernet1/6", "admin_state": "up", "state": "up"},
        {"interface": "Vlan10", "svi_admin_state": "up", "svi_line_proto": "up"},
        {"interface": "Vlan30", "svi_admin_state": "up", "svi_line_proto": "up"}
    ]}});
    Input::Nxos {
        name: SWITCH.into(),
        config: config.as_bytes().to_vec(),
        file: format!("{SWITCH}/config"),
        collected: Collected {
            neighbours: vec![
                arp_row("Vlan10", "192.0.2.40", "00:00:5e:00:53:40", 0),
                arp_row("Vlan30", "192.0.2.130", "00:00:5e:00:53:a1", 1),
            ],
            macs: vec![
                mac_row(10, "00:00:5e:00:53:40", "Eth1/6", 0),
                mac_row(30, "00:00:5e:00:53:a1", "Eth1/5", 1),
            ],
            links: vec![
                link_row(SWITCH, "Vlan10", "00:00:5e:00:53:10"),
                link_row(SWITCH, "Vlan30", "00:00:5e:00:53:30"),
            ],
            ..Collected::default()
        },
        sections: BTreeMap::from([(
            "interfaces".to_string(),
            (
                serde_json::to_vec(&interfaces).unwrap(),
                format!("{SWITCH}/interfaces"),
            ),
        )]),
    }
}

/// The router r1 of the VyOS fixture, with the collected MAC of eth1,
/// 203.0.113.129/25.
fn router() -> Input {
    Input::Vyos {
        name: "r1".into(),
        config: include_bytes!("fixtures/vyos/r1-config.json").to_vec(),
        file: "r1/config".into(),
        collected: Collected {
            links: vec![link_row("r1", "eth1", "00:00:5e:00:53:21")],
            ..Collected::default()
        },
    }
}

/// The next hop of the link `l-br-mpls` in the WAN module of the branch.
fn wan_next_hop(m: &mut BTreeMap<String, Value>, gateway: &str) {
    m.get_mut("edge_modules").unwrap()["e-br"]["WAN"]["data"]["links"][0]["nextHopIpAddress"] =
        json!(gateway);
}

/// The position of the step of the function `name` in a path.
fn position(f: &[String], name: &str) -> usize {
    f.iter()
        .position(|x| x == name)
        .unwrap_or_else(|| panic!("{name} is not in {f:?}"))
}

#[test]
fn a_host_behind_an_estate_switch_reaches_a_host_behind_the_hub_through_the_branch_lan() {
    let mut m = base();
    open_firewall(&mut m);
    no_lan_bgp(&mut m);
    let lan = &mut branch_module(&mut m, 0)["lan"]["networks"][0];
    lan["cidrIp"] = json!("192.0.2.40");
    lan["cidrPrefix"] = json!(26);
    sync_state(&mut m);
    let e = assemble(vec![input(STORE, &m), switch()]);
    let notes = e.notes.clone();
    let t = e.builder.build().expect("the twin builds");
    let h = Header::request(ip("192.0.2.130"), ip("10.20.20.10"), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(443);
    let a = Executor::new(&t)
        .run(&Query::path(&t, &h).without_reply())
        .expect("the query runs");
    let b = a.branches();
    assert_eq!(b.len(), 2, "{notes:#?}");
    for (i, branch) in b.iter().enumerate() {
        let f = functions(&a, i);
        let port = position(&f, &format!("{SWITCH}/port/Ethernet1/6/out"));
        let lan = position(&f, &format!("{BR}/in/users"));
        assert!(port < lan, "{f:?}");
        assert!(lan < position(&f, SELECT), "{f:?}");
        assert!(position(&f, SELECT) < position(&f, &format!("{HUB}/vcmp/decap")));
        let step = branch
            .steps
            .iter()
            .find(|s| s.function.as_str() == SELECT)
            .unwrap();
        let alt = step.alternative.as_ref().expect("a candidate");
        assert_eq!(alt.kind, AlternativeKind::Candidate);
        assert_eq!((alt.index, alt.count), (i as u32, 2));
    }
    assert!(
        notes[SWITCH]
            .iter()
            .any(|n| n.ends_with("an address of a device of the twin, not an endpoint")),
        "{notes:#?}"
    );
}

#[test]
fn the_outer_packet_of_a_tunnel_goes_through_the_estate_router_of_the_wan_gateway() {
    let mut m = base();
    open_firewall(&mut m);
    no_lan_bgp(&mut m);
    branch_module(&mut m, 0)["routedInterfaces"][0]["addressing"] = json!({
        "type": "STATIC", "cidrIp": "203.0.113.130", "cidrPrefix": 25, "gateway": "203.0.113.129"
    });
    m.get_mut("edges").unwrap()[0]["links"][0]["ipAddress"] = json!("203.0.113.130");
    wan_next_hop(&mut m, "203.0.113.129");
    sync_state(&mut m);
    let e = assemble(vec![input(STORE, &m), router()]);
    let notes = e.notes.clone();
    let t = e.builder.build().expect("the twin builds");
    let a = run(&t, "10.20.20.10");
    let b = a.branches();
    assert_eq!(b.len(), 2, "{notes:#?}");
    let wan = format!("{BR}/out/GE1");
    let i = (0..b.len())
        .find(|i| functions(&a, *i).contains(&wan))
        .unwrap_or_else(|| panic!("no path leaves on GE1: {notes:#?}"));
    let f = functions(&a, i);
    let handoff = position(&f, "r1/handoff/eth1");
    assert!(position(&f, &wan) < handoff, "{f:?}");
    assert!(handoff < position(&f, "r1/in/eth1"), "{f:?}");
    assert!(
        !f.iter()
            .any(|x| x.starts_with(&format!("{STORE}/transport/"))),
        "{f:?}"
    );
}

#[test]
fn the_outer_packet_of_a_tunnel_to_a_wan_gateway_on_an_svi_is_unknown() {
    let mut m = base();
    open_firewall(&mut m);
    no_lan_bgp(&mut m);
    branch_module(&mut m, 0)["routedInterfaces"][0]["addressing"] = json!({
        "type": "STATIC", "cidrIp": "192.0.2.3", "cidrPrefix": 26, "gateway": "192.0.2.2"
    });
    m.get_mut("edges").unwrap()[0]["links"][0]["ipAddress"] = json!("192.0.2.3");
    wan_next_hop(&mut m, "192.0.2.2");
    sync_state(&mut m);
    let e = assemble(vec![input(STORE, &m), switch()]);
    let notes = e.notes.clone();
    assert!(
        notes[BR].contains(&format!("GE1: 192.0.2.2 on VLAN 10 of {SWITCH}, no link")),
        "{notes:#?}"
    );
    let t = e.builder.build().expect("the twin builds");
    let a = run(&t, "10.20.20.10");
    let b = a.branches();
    let unknown = format!("{BR}/wan/unknown/GE1");
    let i = (0..b.len())
        .find(|i| functions(&a, *i).contains(&unknown))
        .unwrap_or_else(|| panic!("no path reaches {unknown}: {notes:#?}"));
    assert_eq!(code(b[i].verdict), Some(ReasonCode::NotCollected));
    assert!(
        detail(b[i].verdict).contains("gateway 192.0.2.2"),
        "{:?}",
        b[i].verdict
    );
    let f = functions(&a, i);
    assert!(
        !f.iter()
            .any(|x| x.starts_with(&format!("{STORE}/transport/"))),
        "{f:?}"
    );
}
