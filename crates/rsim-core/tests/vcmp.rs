//! The VCMP encapsulation and the selection of packets by its segment.

use rsim_core::{Encap, FieldValue, Header, PROTO_TCP, PROTO_UDP, PacketSet, SetArena, bits};

fn ip(s: &str) -> std::net::IpAddr {
    s.parse().unwrap()
}

fn inner() -> Header {
    Header::request(ip("10.1.0.10"), ip("10.2.0.10"), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(443)
}

fn outer(segment: u32) -> Header {
    let mut o = Header::request(ip("192.0.2.1"), ip("198.51.100.2"), PROTO_UDP)
        .with_src_port(2426)
        .with_dst_port(2426);
    o.dscp = FieldValue::Known(0);
    o.ecn = FieldValue::Known(0);
    o.src_mac = FieldValue::Unknown;
    o.dst_mac = FieldValue::Unknown;
    o = o.untagged();
    o.encap = vec![Encap::Vcmp {
        src: ip("192.0.2.1"),
        dst: ip("198.51.100.2"),
        segment,
    }];
    o
}

#[test]
fn a_segment_selects_only_the_packets_of_its_segment() {
    let a = SetArena::standalone();
    let plain = PacketSet::single(&a, &inner());
    let s0 = plain.encapsulate(&outer(0)).done;
    let s7 = plain.encapsulate(&outer(7)).done;
    let all = s0.union(&s7).union(&plain);
    assert_eq!(all.vcmp(), s0.union(&s7));
    assert_eq!(all.vcmp_segment(0), s0);
    assert_eq!(all.vcmp_segment(7), s7);
    assert!(all.vcmp_segment(1).is_empty());
    assert!(plain.vcmp().is_empty());
    assert!(all.vcmp_segment(7).has_free_levels());
    assert!(all.vcmp_segment(7).has_valid_tags());
}

#[test]
fn a_vcmp_packet_is_not_a_vxlan_packet_of_the_same_number() {
    let a = SetArena::standalone();
    let e = PacketSet::single(&a, &inner()).encapsulate(&outer(7)).done;
    assert!(e.vxlan_vni(7).is_empty());
    assert!(e.wireguard().is_empty());
}

#[test]
fn a_vcmp_packet_has_its_kind_its_addresses_and_its_segment() {
    let a = SetArena::standalone();
    let plain = PacketSet::single(&a, &inner());
    let e = plain.encapsulate(&outer(7)).done;
    let w = e.witness().unwrap().current;
    assert_eq!(
        w.encap,
        vec![Encap::Vcmp {
            src: ip("192.0.2.1"),
            dst: ip("198.51.100.2"),
            segment: 7,
        }]
    );
    assert_eq!(w.dst_port, FieldValue::Known(2426));
    let members = e.describe();
    let d = members[0].current.encap.as_ref().unwrap();
    assert_eq!(d.kind, bits::ENCAP_VCMP);
    assert_eq!(d.vni.single(), Some(7));
    assert_eq!(e.decapsulate().done, plain);
}
