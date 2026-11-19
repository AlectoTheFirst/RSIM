//! The VXLAN fabric: encapsulation at the ingress leaf, the underlay with
//! equal-cost paths over 2 spines, a spine ACL on the outer header, a spine
//! with no route, decapsulation at the egress leaf, and the reply.

use rsim_core::{
    Destination, DeviceId, EndpointId, FieldValue, FunctionId, Header, InterfaceId, PROTO_TCP,
    PROTO_UDP, PacketSet, ReasonCode, SetSpec, Verdict, VerdictKind,
};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_topologies::*;

fn twin() -> Twin {
    leaf_spine().build().expect("twin builds")
}

fn run(twin: &Twin, h: &Header) -> Answer {
    Executor::new(twin)
        .run(&Query::path(twin, h))
        .expect("query runs")
}

fn deliver(e: &str) -> Verdict {
    Verdict::Deliver(Destination::Endpoint(EndpointId::new(e)))
}

fn code(v: &Verdict) -> Option<ReasonCode> {
    match v {
        Verdict::Drop(r) | Verdict::Unknown(r) => Some(r.code),
        Verdict::Deliver(_) | Verdict::Exit(_) => None,
    }
}

fn functions(a: &Answer, branch: usize) -> Vec<String> {
    a.branches()[branch]
        .steps
        .iter()
        .map(|s| s.function.to_string())
        .collect()
}

#[test]
fn the_tunnel_crosses_each_spine_and_the_reply_comes_back() {
    let twin = twin();
    let a = run(&twin, &tcp("10.1.0.10", 40000, "10.2.0.10", 22));
    let b = a.branches();
    assert_eq!(b.len(), 2);
    for (i, spine) in ["spine1", "spine2"].iter().enumerate() {
        assert_eq!(b[i].verdict, &deliver("host2"));
        let f = functions(&a, i);
        assert!(f.contains(&format!("{spine}/route")), "{f:?}");
        let at = |name: &str| f.iter().position(|x| x == name).unwrap();
        assert!(at("leaf1/vxlan-encap") < at(&format!("{spine}/route")));
        assert!(at(&format!("{spine}/route")) < at("leaf2/vxlan-decap"));
        let alt = b[i].steps[4]
            .alternative
            .as_ref()
            .expect("a forwarding choice");
        assert_eq!((alt.index, alt.count), (i as u32, 2));
        let reply = a.reply_of(i).expect("the reply ran");
        assert_eq!(reply.verdict(), Some(&deliver("host1")));
    }
}

#[test]
fn the_packets_on_the_spine_have_the_outer_header_and_the_inner_header() {
    let twin = twin();
    let a = run(&twin, &tcp("10.1.0.10", 40000, "10.2.0.10", 22));
    let b = &a.branches()[0];
    let spine = b
        .steps
        .iter()
        .find(|s| s.function.as_str() == "spine1/route")
        .unwrap();
    let w = spine.input.witness().unwrap().current;
    assert_eq!(w.dst_ip, FieldValue::Known(ip("192.0.2.2")));
    assert_eq!(w.protocol, FieldValue::Known(PROTO_UDP));
    assert_eq!(w.dst_port, FieldValue::Known(4789));
    assert_eq!(w.src_port, FieldValue::Unknown);
    let inner = w.inner.expect("the inner header");
    assert_eq!(inner.dst_ip, FieldValue::Known(ip("10.2.0.10")));
    assert_eq!(inner.dst_port, FieldValue::Known(22));
    let end = b.packets.witness().unwrap().current;
    assert!(end.encap.is_empty() && end.inner.is_none());
}

#[test]
fn the_spine_acl_on_the_outer_header_drops_one_path() {
    let twin = twin();
    let a = run(&twin, &udp("10.1.0.10", 40000, "10.3.0.10", 53));
    let b = a.branches();
    assert_eq!(b[0].verdict, &deliver("host3"));
    assert_eq!(code(b[1].verdict), Some(ReasonCode::Denied));
    assert_eq!(b[1].steps.last().unwrap().function.as_str(), "spine2/acl");
    assert_eq!(a.verdict(), None);
}

#[test]
fn a_spine_with_no_route_to_the_tunnel_end_drops_its_path() {
    let twin = twin();
    let a = run(&twin, &udp("10.1.0.10", 40000, "10.4.0.10", 53));
    let b = a.branches();
    assert_eq!(code(b[0].verdict), Some(ReasonCode::NoRoute));
    assert_eq!(b[0].steps.last().unwrap().function.as_str(), "spine1/route");
    assert_eq!(b[1].verdict, &deliver("host4"));
}

#[test]
fn a_set_query_to_two_hosts_drops_only_the_tunnel_to_leaf3_on_spine2() {
    let twin = twin();
    let arena = twin.arena(None);
    let spec = SetSpec {
        src_ip: Some(vec![pfx("10.1.0.10/32")]),
        dst_ip: Some(vec![pfx("10.2.0.10/32"), pfx("10.3.0.10/32")]),
        protocol: Some(vec![(PROTO_TCP, PROTO_TCP), (PROTO_UDP, PROTO_UDP)]),
        ..SetSpec::default()
    };
    let set = PacketSet::from_spec(&arena, &spec);
    let q = Query::set(set).with_ingress(DeviceId::new("leaf1"), InterfaceId::new("eth9"));
    let a = Executor::new(&twin).run(&q).expect("query runs");
    let kinds: Vec<VerdictKind> = a.branches().iter().map(|b| b.verdict.kind()).collect();
    assert!(kinds.contains(&VerdictKind::Deliver));
    assert!(kinds.contains(&VerdictKind::Drop));
    for b in a.branches() {
        if b.verdict.kind() == VerdictKind::Drop {
            assert_eq!(code(b.verdict), Some(ReasonCode::Denied));
            let w = b.packets.witness().unwrap().current;
            assert_eq!(w.dst_ip, FieldValue::Known(ip("192.0.2.3")));
        }
    }
}

#[test]
fn a_packet_that_is_encapsulated_already_is_unknown_at_the_tunnel_end() {
    let twin = twin();
    let arena = twin.arena(None);
    let inner = tcp("10.1.0.10", 40000, "10.2.0.10", 22);
    let gre = {
        let mut o = Header::request(ip("198.51.100.1"), ip("10.2.0.10"), 47);
        for f in [&mut o.dscp, &mut o.ecn] {
            *f = FieldValue::Known(0);
        }
        o.src_mac = FieldValue::Unknown;
        o.dst_mac = FieldValue::Unknown;
        o = o.untagged();
        o.encap = vec![rsim_core::Encap::Gre {
            src: ip("198.51.100.1"),
            dst: ip("10.2.0.10"),
        }];
        o
    };
    let set = PacketSet::single(&arena, &inner).encapsulate(&gre).done;
    let q = Query::set(set)
        .with_ingress(DeviceId::new("leaf1"), InterfaceId::new("eth9"))
        .without_reply();
    let a = Executor::new(&twin).run(&q).expect("query runs");
    let b = a.branches();
    assert_eq!(b.len(), 1);
    assert_eq!(code(b[0].verdict), Some(ReasonCode::Nested));
    assert_eq!(
        b[0].steps.last().unwrap().function,
        FunctionId::new("leaf1/vxlan-encap")
    );
}
