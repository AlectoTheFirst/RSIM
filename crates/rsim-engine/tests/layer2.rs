//! Layer 2 on a hand-built switched site: host resolution, port ingress,
//! MAC lookup, flood, port egress, wireless attachment and the hand-off to
//! the router.

use rsim_core::{Destination, EndpointId, FieldValue, Header, PROTO_TCP, ReasonCode, Verdict};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_topologies::*;

fn twin() -> Twin {
    layer2_site().build().expect("the site builds")
}

fn run(t: &Twin, h: Header) -> Answer {
    Executor::new(t)
        .run(&Query::path(t, &h))
        .expect("the query runs")
}

fn tcp_to(src: &str, dst: &str) -> Header {
    Header::request(ip(src), ip(dst), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(443)
}

fn functions(a: &Answer, i: usize) -> Vec<String> {
    a.branches()[i]
        .steps
        .iter()
        .map(|s| s.function.to_string())
        .collect()
}

fn deliver(e: &str) -> Verdict {
    Verdict::Deliver(Destination::Endpoint(EndpointId::new(e)))
}

#[test]
fn a_wired_host_reaches_a_host_of_another_vlan_through_the_router() {
    let t = twin();
    let a = run(&t, tcp_to("192.0.2.10", "198.51.100.20"));
    assert_eq!(a.verdict(), Some(&deliver("h2")));
    assert_eq!(
        functions(&a, 0),
        [
            "sw1/host/port/2",
            "sw1/port/2/in",
            "sw1/mac",
            "sw1/port/1/out",
            "r1/handoff",
            "r1/in/eth0",
            "r1/vrf",
            "r1/route",
            "r1/nexthop",
            "r1/out/eth0.20",
            "sw1/port/1/in",
            "sw1/mac",
            "sw1/port/4/out",
        ]
    );
    let b = &a.branches()[0];
    let tag = |f: &str| {
        let s = b
            .steps
            .iter()
            .rev()
            .find(|s| s.function.as_str() == f)
            .unwrap();
        s.output.witness().unwrap().current.vlan
    };
    assert_eq!(tag("sw1/port/1/out"), FieldValue::Absent);
    assert_eq!(tag("r1/out/eth0.20"), FieldValue::Known(20));
    assert_eq!(tag("sw1/port/4/out"), FieldValue::Absent);
    let last = b.steps.last().unwrap().output.witness().unwrap().current;
    assert_eq!(last.dst_mac, FieldValue::Known(H2_MAC));
    assert_eq!(last.src_mac, FieldValue::Known(R1_MAC));
}

#[test]
fn a_wireless_host_reaches_a_wired_host_of_its_vlan_without_the_router() {
    let t = twin();
    let a = run(&t, tcp_to("198.51.100.30", "198.51.100.20"));
    assert_eq!(a.verdict(), Some(&deliver("h2")));
    let f = functions(&a, 0);
    assert_eq!(
        f[..3],
        ["ap1/host/wlan/office", "ap1/wlan/office/in", "ap1/mac"]
    );
    assert!(!f.iter().any(|x| x.starts_with("r1/")), "{f:?}");
    let b = &a.branches()[0];
    let trunk = b
        .steps
        .iter()
        .find(|s| s.function.as_str() == "ap1/port/1/out")
        .unwrap();
    assert_eq!(
        trunk.output.witness().unwrap().current.vlan,
        FieldValue::Known(20)
    );
}

#[test]
fn the_router_reaches_a_wireless_host() {
    let t = twin();
    let a = run(&t, tcp_to("192.0.2.10", "198.51.100.30"));
    assert_eq!(a.verdict(), Some(&deliver("w1")));
    let f = functions(&a, 0);
    assert!(
        f.ends_with(&[
            "ap1/port/1/in".into(),
            "ap1/mac".into(),
            "ap1/wlan/office/out".into()
        ]),
        "{f:?}"
    );
}

#[test]
fn an_unknown_mac_floods_to_the_other_forwarding_ports_only() {
    let t = twin();
    // h3 is in no MAC table, so a frame from h1 to h3 floods in `lan`.
    let a = run(&t, tcp_to("192.0.2.10", "192.0.2.13"));
    let copies: Vec<String> = a
        .branches()
        .iter()
        .filter_map(|b| b.steps.iter().find_map(|s| s.flood_copy.as_ref()))
        .map(|c| c.port.to_string())
        .collect();
    assert!(copies.contains(&"port/6".to_string()), "{copies:?}");
    assert!(!copies.contains(&"port/2".to_string()), "{copies:?}");
    assert!(!copies.contains(&"port/5".to_string()), "{copies:?}");
    // The copy to port 6 reaches h3, so the flood delivers.
    assert_eq!(a.verdict(), Some(&deliver("h3")));
    let to_router = a
        .branches()
        .into_iter()
        .find(|b| b.steps.iter().any(|s| s.function.as_str() == "r1/handoff"))
        .unwrap();
    match to_router.verdict {
        Verdict::Drop(r) => assert_eq!(r.code, ReasonCode::Denied),
        v => panic!("{v:?}"),
    }
}

#[test]
fn a_host_on_a_local_network_with_no_mac_is_unknown() {
    let t = twin();
    let a = run(&t, tcp_to("192.0.2.10", "192.0.2.40"));
    assert!(
        matches!(a.verdict(), Some(Verdict::Unknown(_))),
        "{:?}",
        a.verdict()
    );
}
