//! A UniFi site joined to a VyOS router, on synthetic sections.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{Destination, EndpointId, FieldValue, Header, PROTO_TCP, ReasonCode, Verdict};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::State;
use rsim_ingest::collected::{AddressRow, Collected, LinkRow, RouteRow, row_span};
use rsim_ingest::estate::{Estate, Input, assemble};

const VYOS: &[u8] = include_bytes!("fixtures/vyos/r1-config.json");

fn section(name: &str) -> (String, (Vec<u8>, String)) {
    let path = format!(
        "{}/tests/fixtures/unifi/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = std::fs::read(path).unwrap();
    (name.to_string(), (bytes, format!("site1/{name}")))
}

fn route(prefix: &str, protocol: &str, iface: &str) -> RouteRow {
    RouteRow {
        vrf: "default".into(),
        prefix: prefix.into(),
        protocol: protocol.into(),
        selected: true,
        next_hop: None,
        interface: Some(iface.into()),
        span: row_span("r1", "routes", "b1", 0),
    }
}

fn link(iface: &str, parent: Option<&str>) -> LinkRow {
    LinkRow {
        interface: iface.into(),
        mac: Some("00:00:5e:00:53:01".into()),
        parent: parent.map(str::to_string),
        vlan: None,
        span: row_span("r1", "links", "b4", 0),
    }
}

fn estate() -> Estate {
    let collected = Collected {
        addresses: vec![AddressRow {
            interface: "pppoe0".into(),
            prefix: "203.0.113.10/32".into(),
            span: row_span("r1", "addresses", "b2", 0),
        }],
        routes: vec![
            route("0.0.0.0/0", "kernel", "pppoe0"),
            route("192.0.2.0/26", "connected", "eth0.10"),
            route("192.0.2.64/26", "connected", "eth0.110"),
            route("192.0.2.192/27", "connected", "eth0"),
        ],
        neighbours: Vec::new(),
        links: vec![
            link("eth0", None),
            link("eth0.10", Some("eth0")),
            link("eth0.110", Some("eth0")),
        ],
    };
    let sections: BTreeMap<String, (Vec<u8>, String)> =
        ["networks", "wlans", "devices", "clients", "port_profiles"]
            .into_iter()
            .map(section)
            .collect();
    assemble(vec![
        Input::Vyos {
            name: "r1".into(),
            config: VYOS.to_vec(),
            file: "r1/config".into(),
            collected,
        },
        Input::Unifi {
            name: "site1".into(),
            sections,
        },
    ])
}

fn twin() -> Twin {
    estate().builder.build().expect("the twin builds")
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn run(t: &Twin, src: &str, dst: &str, port: u16) -> Answer {
    let h = Header::request(ip(src), ip(dst), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(port);
    Executor::new(t)
        .run(&Query::path(t, &h))
        .expect("the query runs")
}

#[test]
fn a_guest_reaches_a_lan_host_through_the_access_point_the_switch_and_the_router() {
    let t = twin();
    let a = run(&t, "192.0.2.70", "192.0.2.50", 8123);
    assert_eq!(
        a.verdict(),
        Some(&Verdict::Deliver(Destination::Endpoint(EndpointId::new(
            "h1-005351"
        ))))
    );
    let b = &a.branches()[0];
    let f: Vec<&str> = b.steps.iter().map(|s| s.function.as_str()).collect();
    for want in [
        "ap1/host/wlan/guest",
        "ap1/wlan/guest/in",
        "ap1/port/1/out",
        "sw1/port/3/in",
        "sw1/port/1/out",
        "r1/handoff/eth0",
        "r1/in/eth0.110",
        "r1/policy",
        "r1/out/eth0.10",
        "sw1/port/1/in",
        "sw1/port/2/out",
    ] {
        assert!(f.contains(&want), "{want} not in {f:?}");
    }
    let tag = |name: &str| {
        let s = b
            .steps
            .iter()
            .find(|s| s.function.as_str() == name)
            .unwrap();
        s.output.witness().unwrap().current.vlan
    };
    assert_eq!(tag("ap1/port/1/out"), FieldValue::Known(110));
    assert_eq!(tag("r1/out/eth0.10"), FieldValue::Known(10));
    assert_eq!(tag("sw1/port/2/out"), FieldValue::Absent);
}

#[test]
fn the_router_policy_decides_between_the_vlans() {
    let t = twin();
    let a = run(&t, "192.0.2.70", "192.0.2.50", 22);
    match a.verdict() {
        Some(Verdict::Drop(r)) => assert_eq!(r.code, ReasonCode::Denied),
        v => panic!("{v:?}"),
    }
}

#[test]
fn the_router_reaches_a_client_from_the_client_list() {
    let t = twin();
    // The router has no ARP entry for g1; the client list gives its MAC.
    let a = run(&t, "192.0.2.50", "192.0.2.70", 443);
    assert_eq!(
        a.verdict(),
        Some(&Verdict::Deliver(Destination::Endpoint(EndpointId::new(
            "g1-005352"
        ))))
    );
}

#[test]
fn the_coverage_and_the_notes_name_what_is_not_lowered() {
    let e = estate();
    let cov = &e.coverage["site1"];
    let ranked: Vec<&str> = cov.ranked().iter().map(|r| r.0).collect();
    assert_eq!(ranked, ["networks/*/is_nat"]);
    assert!(cov.share(State::Unhandled) < 0.1);
    let notes = &e.notes["site1"];
    assert!(notes.iter().any(|n| n.contains("gw1")), "{notes:?}");
    assert_eq!(e.unread["r1"], Vec::<String>::new());
}

#[test]
fn two_builds_give_the_same_answers() {
    let (a, b) = (twin(), twin());
    assert_eq!(
        format!("{:?}", run(&a, "192.0.2.70", "192.0.2.50", 8123).summary),
        format!("{:?}", run(&b, "192.0.2.70", "192.0.2.50", 8123).summary)
    );
}
