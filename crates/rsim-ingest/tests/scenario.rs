//! The link-down scenarios on the synthetic OSPF triangle of the NX-OS
//! switches r1, r2 and r3.

#[path = "support/triangle.rs"]
mod triangle;

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{Header, PROTO_TCP, VerdictKind};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::collected::{Collected, LinkRow, NeighbourRow, RouteRow, row_span};
use rsim_ingest::estate::{Estate, Input, assemble, assemble_scenario};
use rsim_ingest::scenario::{GUARD_MISMATCH, Layer, NOT_RECOMPUTED};

fn inputs(mismatch: bool) -> Vec<Input> {
    triangle::devices(mismatch)
        .into_iter()
        .map(|d| {
            let name = d.name.clone();
            let routes = d
                .routes
                .iter()
                .enumerate()
                .map(|(i, (prefix, protocol, hop, iface))| RouteRow {
                    vrf: "default".into(),
                    prefix: prefix.clone(),
                    protocol: protocol.clone(),
                    selected: true,
                    next_hop: hop.clone(),
                    interface: iface.clone(),
                    span: row_span(&name, "routes", "b1", i as u64),
                })
                .collect();
            let links = d
                .links
                .iter()
                .enumerate()
                .map(|(i, (iface, mac))| LinkRow {
                    interface: iface.clone(),
                    mac: Some(mac.clone()),
                    parent: None,
                    vlan: None,
                    span: row_span(&name, "links", "b2", i as u64),
                })
                .collect();
            let neighbours = d
                .arp
                .iter()
                .enumerate()
                .map(|(i, (iface, ip, mac))| NeighbourRow {
                    interface: iface.clone(),
                    ip: ip.clone(),
                    mac: Some(mac.clone()),
                    state: Some("REACHABLE".into()),
                    span: row_span(&name, "neighbours", "b3", i as u64),
                })
                .collect();
            Input::Nxos {
                name: name.clone(),
                config: d.config.into_bytes(),
                file: format!("{name}/config"),
                collected: Collected {
                    routes,
                    links,
                    neighbours,
                    ..Collected::default()
                },
                sections: BTreeMap::from([(
                    "lldp".to_string(),
                    (d.lldp.into_bytes(), format!("{name}/lldp")),
                )]),
            }
        })
        .collect()
}

fn layers(down: &[&str]) -> Vec<Layer> {
    down.iter().map(|d| Layer::link_down(d).unwrap()).collect()
}

fn scenario(mismatch: bool, down: &[&str]) -> Estate {
    assemble_scenario(inputs(mismatch), &BTreeMap::new(), &layers(down))
        .expect("the scenario builds")
}

fn twin(e: Estate) -> Twin {
    e.builder.build().expect("the twin builds")
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// The answer for TCP port 22 from `src` that enters `device` on its LAN
/// port, with no reply.
fn run_from(t: &Twin, device: &str, src: &str, dst: &str) -> Answer {
    let h = Header::request(ip(src), ip(dst), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(22);
    let q = Query::path(t, &h)
        .with_ingress(device, "Ethernet1/3")
        .without_reply();
    Executor::new(t).run(&q).expect("the query runs")
}

/// The answer from the host of the LAN of r1.
fn run(t: &Twin, dst: &str) -> Answer {
    run_from(t, "r1", "203.0.113.10", dst)
}

/// The devices of the steps of the one branch, each once in order, and
/// the verdict.
fn path(a: &Answer) -> (Vec<String>, VerdictKind) {
    let branches = a.branches();
    assert_eq!(branches.len(), 1, "{:#?}", text(a));
    let mut devices: Vec<String> = Vec::new();
    for s in &branches[0].steps {
        let d = s.function.to_string();
        let d = d.split('/').next().unwrap_or_default().to_string();
        if devices.last() != Some(&d) {
            devices.push(d);
        }
    }
    (devices, branches[0].verdict.kind())
}

/// The reason of the last step of a path that leaves on the LAN port of a
/// switch, which has no link.
const LAN_EGRESS: &str = "no link on interface Ethernet1/3";

/// The reason of the last step of the one branch.
fn last_reason(a: &Answer) -> String {
    let branches = a.branches();
    branches[0].steps.last().unwrap().reason.detail.clone()
}

/// Each branch with its verdict, and each step with its function, its
/// reason and its provenance.
fn text(a: &Answer) -> Vec<String> {
    let mut out = Vec::new();
    for b in a.branches() {
        out.push(format!("{:?}", b.verdict.kind()));
        for s in &b.steps {
            let spans: Vec<String> = s
                .provenance
                .iter()
                .map(|p| format!("{}:{}-{}", p.file, p.first_line, p.last_line))
                .collect();
            out.push(format!(
                "{} {} [{}]",
                s.function,
                s.reason.detail,
                spans.join(", ")
            ));
        }
    }
    out
}

fn names_layer(a: &Answer, layer: &str) -> bool {
    a.branches()
        .iter()
        .flat_map(|b| &b.steps)
        .flat_map(|s| &s.provenance)
        .any(|p| &*p.file == layer)
}

#[test]
fn the_base_guard_matches_each_collected_route_but_the_bgp_route() {
    let e = assemble(inputs(false));
    for d in ["r1", "r2", "r3"] {
        let rows = &e.guard[d];
        let other: Vec<String> = rows
            .iter()
            .filter(|r| r.category != rsim_guard::Category::Match)
            .map(|r| {
                format!(
                    "{} {:?} {:?} {:?}",
                    r.prefix, r.category, r.computed, r.collected
                )
            })
            .collect();
        let expected: Vec<String> = if d == "r1" {
            vec!["192.0.2.128/25".into()]
        } else {
            Vec::new()
        };
        let got: Vec<String> = other
            .iter()
            .map(|x| x.split(' ').next().unwrap().to_string())
            .collect();
        assert_eq!(got, expected, "{d}: {other:#?}");
    }
    assert_eq!(
        e.links.get(&("r1".to_string(), "Ethernet1/1".to_string())),
        Some(&vec![("r2".to_string(), "Ethernet1/1".to_string())])
    );
}

#[test]
fn a_link_down_moves_the_path_to_the_other_link_and_the_trace_names_the_layer() {
    let base = twin(assemble(inputs(false)));
    let a = run(&base, "203.0.113.74");
    let (devices, verdict) = path(&a);
    assert_eq!(devices, ["r1", "r2"]);
    assert_eq!(last_reason(&a), LAN_EGRESS, "{:#?}", text(&a));

    let t = twin(scenario(false, &["r1:Ethernet1/1"]));
    let a = run(&t, "203.0.113.74");
    let (devices, after) = path(&a);
    assert_eq!(devices, ["r1", "r3", "r2"], "{:#?}", text(&a));
    assert_eq!(after, verdict);
    assert_eq!(last_reason(&a), LAN_EGRESS, "{:#?}", text(&a));
    assert!(
        names_layer(&a, "layer 1: link-down r1:Ethernet1/1"),
        "{:#?}",
        text(&a)
    );
    // The far end r2 goes down too, so its path back to r1 goes through r3.
    let back = run_from(&t, "r2", "203.0.113.74", "203.0.113.10");
    assert_eq!(path(&back).0, ["r2", "r3", "r1"], "{:#?}", text(&back));
    // A path that the layer does not change keeps the collected route.
    let other = run(&t, "203.0.113.138");
    assert_eq!(path(&other).0, ["r1", "r3"]);
    assert!(!names_layer(&other, "layer 1: link-down r1:Ethernet1/1"));
}

#[test]
fn a_prefix_whose_base_differs_from_the_collected_route_is_unknown() {
    let base = twin(assemble(inputs(true)));
    let a = run(&base, "203.0.113.74");
    assert_eq!(path(&a).0, ["r1", "r3", "r2"]);
    assert_eq!(last_reason(&a), LAN_EGRESS, "{:#?}", text(&a));
    let t = twin(scenario(true, &["r1:Ethernet1/1"]));
    let a = run(&t, "203.0.113.74");
    assert_eq!(path(&a), (vec!["r1".to_string()], VerdictKind::Unknown));
    assert!(last_reason(&a).contains(GUARD_MISMATCH), "{:#?}", text(&a));
}

#[test]
fn a_bgp_route_is_unknown_in_a_scenario_and_definite_in_the_base() {
    let base = twin(assemble(inputs(false)));
    let a = run(&base, "192.0.2.130");
    let (devices, verdict) = path(&a);
    assert_eq!(devices[..2], ["r1", "r2"], "{:#?}", text(&a));
    assert_ne!(verdict, VerdictKind::Unknown);
    let t = twin(scenario(false, &["r2:Ethernet1/2"]));
    let a = run(&t, "192.0.2.130");
    assert_eq!(path(&a), (vec!["r1".to_string()], VerdictKind::Unknown));
    assert!(last_reason(&a).contains(NOT_RECOMPUTED), "{:#?}", text(&a));
}

#[test]
fn a_scenario_with_no_layer_is_the_snapshot_twin_and_a_scenario_is_the_same_in_2_builds() {
    let dsts = ["203.0.113.74", "203.0.113.138", "192.0.2.130"];
    let answers =
        |t: &Twin| -> Vec<Vec<String>> { dsts.iter().map(|d| text(&run(t, d))).collect() };
    let snapshot = answers(&twin(assemble(inputs(false))));
    let none = answers(&twin(scenario(false, &[])));
    assert_eq!(none, snapshot);
    let one = answers(&twin(scenario(false, &["r1:Ethernet1/1"])));
    let two = answers(&twin(scenario(false, &["r1:Ethernet1/1"])));
    assert_eq!(one, two);
    assert_ne!(one, snapshot);
}

#[test]
fn a_layer_on_an_interface_or_a_device_that_does_not_exist_is_refused() {
    let err = |down: &str| {
        assemble_scenario(inputs(false), &BTreeMap::new(), &layers(&[down]))
            .err()
            .expect("the layer is refused")
    };
    assert_eq!(
        err("r1:Ethernet1/9"),
        "no interface Ethernet1/9 in the config of r1"
    );
    assert_eq!(
        err("r9:Ethernet1/1"),
        "link-down r9:Ethernet1/1: no device r9 in the twin"
    );
}

#[test]
fn the_guard_rows_of_a_scenario_are_the_rows_of_the_base() {
    let base = assemble(inputs(false));
    let e = scenario(false, &["r1:Ethernet1/1"]);
    assert_eq!(e.guard, base.guard);
}
