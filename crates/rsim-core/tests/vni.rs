//! The selection of packets by VXLAN network identifier.

use rsim_core::{Encap, FieldValue, Header, PROTO_TCP, PROTO_UDP, PacketSet, SetArena};

fn ip(s: &str) -> std::net::IpAddr {
    s.parse().unwrap()
}

fn inner() -> Header {
    Header::request(ip("10.1.0.10"), ip("10.2.0.10"), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(22)
}

fn outer(vni: u32) -> Header {
    let mut o = Header::request(ip("192.0.2.1"), ip("192.0.2.2"), PROTO_UDP).with_dst_port(4789);
    o.src_port = FieldValue::Unknown;
    o.dscp = FieldValue::Unknown;
    o.ecn = FieldValue::Unknown;
    o.src_mac = FieldValue::Unknown;
    o.dst_mac = FieldValue::Unknown;
    o = o.untagged();
    o.encap = vec![Encap::Vxlan {
        src: ip("192.0.2.1"),
        dst: ip("192.0.2.2"),
        vni,
    }];
    o
}

#[test]
fn a_vni_selects_only_the_packets_of_its_segment() {
    let a = SetArena::standalone();
    let plain = PacketSet::single(&a, &inner());
    let e10 = plain.encapsulate(&outer(10)).done;
    let e20 = plain.encapsulate(&outer(20)).done;
    let both = e10.union(&e20).union(&plain);
    assert_eq!(both.vxlan_vni(10), e10);
    assert_eq!(both.vxlan_vni(20), e20);
    assert!(both.vxlan_vni(30).is_empty());
    assert!(plain.vxlan_vni(0).is_empty());
    assert!(both.vxlan_vni(10).has_free_levels());
    assert!(both.vxlan_vni(10).has_valid_tags());
}

#[test]
fn an_outer_header_with_unknown_fields_decapsulates_to_the_inner_header() {
    let a = SetArena::standalone();
    let plain = PacketSet::single(&a, &inner());
    let e = plain.encapsulate(&outer(10)).done;
    let w = e.witness().unwrap().current;
    assert_eq!(w.src_port, FieldValue::Unknown);
    assert_eq!(w.dst_port, FieldValue::Known(4789));
    assert_eq!(e.decapsulate().done, plain);
}
