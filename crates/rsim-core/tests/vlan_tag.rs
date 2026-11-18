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

fn with_tag(vlan: FieldValue<u16>, l2_priority: FieldValue<u8>) -> Header {
    let mut h = untagged();
    h.vlan = vlan;
    h.l2_priority = l2_priority;
    h
}

#[test]
fn a_request_for_vlan_0_holds_no_untagged_frame() {
    let arena = SetArena::standalone();
    let vlan0 = PacketSet::single(
        &arena,
        &with_tag(FieldValue::Known(0), FieldValue::Unstated),
    );
    let plain = PacketSet::single(&arena, &with_tag(FieldValue::Absent, FieldValue::Absent));
    assert!(vlan0.intersect(&plain).is_empty());
    let tagged = PacketSet::single(
        &arena,
        &with_tag(FieldValue::Known(0), FieldValue::Known(5)),
    );
    assert!(tagged.is_subset(&vlan0));
}

#[test]
fn an_untagged_request_holds_no_frame_of_vlan_0() {
    let arena = SetArena::standalone();
    let plain = PacketSet::single(&arena, &with_tag(FieldValue::Absent, FieldValue::Unstated));
    let vlan0 = PacketSet::single(
        &arena,
        &with_tag(FieldValue::Known(0), FieldValue::Known(0)),
    );
    assert!(plain.intersect(&vlan0).is_empty());
    let untagged = PacketSet::single(&arena, &with_tag(FieldValue::Absent, FieldValue::Absent));
    assert_eq!(plain, untagged);
}

#[test]
fn an_unstated_tag_holds_tagged_and_untagged_frames() {
    let arena = SetArena::standalone();
    let unstated = PacketSet::single(&arena, &untagged());
    let plain = PacketSet::single(&arena, &with_tag(FieldValue::Absent, FieldValue::Absent));
    let tagged = PacketSet::single(
        &arena,
        &with_tag(FieldValue::Known(7), FieldValue::Known(1)),
    );
    assert!(plain.is_subset(&unstated));
    assert!(tagged.is_subset(&unstated));
}
