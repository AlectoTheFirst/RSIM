//! The push and the pop of the 802.1Q tag.

use rsim_core::{FieldValue, Header, PROTO_TCP, PacketSet, SetArena};

fn untagged() -> Header {
    Header::request(
        "192.0.2.1".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        PROTO_TCP,
    )
    .with_src_port(1)
    .with_dst_port(2)
}

#[test]
fn a_push_tags_an_untagged_frame_with_an_unknown_priority() {
    let s = PacketSet::single(&SetArena::standalone(), &untagged());
    let w = s.witness().unwrap().current;
    assert_eq!(w.vlan, FieldValue::Absent);
    let t = s.set_vlan(Some(20));
    let w = t.witness().unwrap().current;
    assert_eq!(w.vlan, FieldValue::Known(20));
    assert_eq!(w.l2_priority, FieldValue::Unknown);
    let w = t.set_vlan(Some(30)).witness().unwrap().current;
    assert_eq!(w.vlan, FieldValue::Known(30));
    assert_eq!(w.l2_priority, FieldValue::Unknown);
}

#[test]
fn a_pop_removes_the_tag_and_the_priority() {
    let s = PacketSet::single(&SetArena::standalone(), &untagged()).set_vlan(Some(20));
    let p = s.set_vlan(None);
    let w = p.witness().unwrap().current;
    assert_eq!(w.vlan, FieldValue::Absent);
    assert_eq!(w.l2_priority, FieldValue::Absent);
    assert_eq!(p.witness().unwrap().original.vlan, FieldValue::Absent);
    assert_eq!(
        p.set_vlan(None).witness().unwrap().current.vlan,
        FieldValue::Absent
    );
}
