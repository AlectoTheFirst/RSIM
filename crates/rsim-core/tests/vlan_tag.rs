//! The push and the pop of the VLAN tags.

use rsim_core::{Encap, FieldValue, Header, PROTO_TCP, PROTO_UDP, PacketSet, SetArena, SetSpec};

/// A request that does not state its VLAN tags.
fn request() -> Header {
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
    let s = PacketSet::single(&SetArena::standalone(), &request());
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
    let s = PacketSet::single(&SetArena::standalone(), &request()).set_vlan(Some(20));
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
    let mut h = request();
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
    let unstated = PacketSet::single(&arena, &request());
    let plain = PacketSet::single(&arena, &with_tag(FieldValue::Absent, FieldValue::Absent));
    let tagged = PacketSet::single(
        &arena,
        &with_tag(FieldValue::Known(7), FieldValue::Known(1)),
    );
    assert!(plain.is_subset(&unstated));
    assert!(tagged.is_subset(&unstated));
}

fn ip(s: &str) -> std::net::IpAddr {
    s.parse().unwrap()
}

/// A frame with the outer tag `outer` and the inner tag `inner`: VLAN,
/// priority and TPID.
fn frame(outer: Option<(u16, u8, u16)>, inner: Option<(u16, u8, u16)>) -> Header {
    let mut h = request().untagged();
    if let Some((v, p, t)) = outer {
        h.vlan = FieldValue::Known(v);
        h.l2_priority = FieldValue::Known(p);
        h.vlan_tpid = FieldValue::Known(t);
    }
    if let Some((v, p, t)) = inner {
        h.inner_vlan = FieldValue::Known(v);
        h.inner_l2_priority = FieldValue::Known(p);
        h.inner_vlan_tpid = FieldValue::Known(t);
    }
    h
}

fn current(s: &PacketSet) -> Header {
    s.witness().unwrap().current
}

fn checked(s: &PacketSet) -> &PacketSet {
    assert!(s.has_free_levels() && s.has_valid_tags());
    s
}

#[test]
fn a_set_vlan_keeps_the_inner_tag_and_sets_the_tpid_of_802_1q() {
    let a = SetArena::standalone();
    let s = PacketSet::single(&a, &frame(Some((10, 3, 0x88a8)), Some((20, 5, 0x8100))));
    let w = current(checked(&s.set_vlan(Some(30))));
    assert_eq!(w.vlan, FieldValue::Known(30));
    assert_eq!(w.l2_priority, FieldValue::Known(3));
    assert_eq!(w.vlan_tpid, FieldValue::Known(0x8100));
    assert_eq!(w.inner_vlan, FieldValue::Known(20));
    assert_eq!(w.inner_l2_priority, FieldValue::Known(5));
    let w = current(checked(&s.set_vlan(None)));
    assert_eq!(w.vlan, FieldValue::Absent);
    assert_eq!(w.vlan_tpid, FieldValue::Absent);
    assert_eq!(w.inner_vlan, FieldValue::Absent);
    let w = current(checked(&s.clear_inner_vlan()));
    assert_eq!(w.vlan, FieldValue::Known(10));
    assert_eq!(w.vlan_tpid, FieldValue::Known(0x88a8));
    assert_eq!(w.inner_vlan, FieldValue::Absent);
}

#[test]
fn a_push_on_0_1_and_2_tags() {
    let a = SetArena::standalone();
    let none = PacketSet::single(&a, &frame(None, None));
    let one = PacketSet::single(&a, &frame(Some((20, 5, 0x8100)), None));
    let two = PacketSet::single(&a, &frame(Some((20, 5, 0x8100)), Some((30, 1, 0x8100))));

    let p = none.push_vlan(100, 0x88a8);
    assert!(p.full.is_empty());
    let w = current(checked(&p.done));
    assert_eq!(w.vlan, FieldValue::Known(100));
    assert_eq!(w.vlan_tpid, FieldValue::Known(0x88a8));
    assert_eq!(w.l2_priority, FieldValue::Unknown);
    assert_eq!(w.inner_vlan, FieldValue::Absent);

    let p = one.push_vlan(100, 0x9100);
    assert!(p.full.is_empty());
    let w = current(checked(&p.done));
    assert_eq!(w.vlan, FieldValue::Known(100));
    assert_eq!(w.vlan_tpid, FieldValue::Known(0x9100));
    assert_eq!(w.inner_vlan, FieldValue::Known(20));
    assert_eq!(w.inner_l2_priority, FieldValue::Known(5));
    assert_eq!(w.inner_vlan_tpid, FieldValue::Known(0x8100));
    assert_eq!(
        p.done.witness().unwrap().original.vlan,
        FieldValue::Known(20)
    );

    // A third tag is not pushed.
    let p = two.push_vlan(100, 0x88a8);
    assert!(p.done.is_empty());
    assert_eq!(p.full, two);
}

#[test]
fn a_pop_on_0_1_and_2_tags() {
    let a = SetArena::standalone();
    let none = PacketSet::single(&a, &frame(None, None));
    let one = PacketSet::single(&a, &frame(Some((20, 5, 0x8100)), None));
    let two = PacketSet::single(&a, &frame(Some((20, 5, 0x88a8)), Some((30, 1, 0x8100))));
    assert_eq!(checked(&none.pop_vlan()), &none);
    let w = current(checked(&one.pop_vlan()));
    assert_eq!(w.vlan, FieldValue::Absent);
    assert_eq!(w.l2_priority, FieldValue::Absent);
    assert_eq!(w.vlan_tpid, FieldValue::Absent);
    let w = current(checked(&two.pop_vlan()));
    assert_eq!(w.vlan, FieldValue::Known(30));
    assert_eq!(w.l2_priority, FieldValue::Known(1));
    assert_eq!(w.vlan_tpid, FieldValue::Known(0x8100));
    assert_eq!(w.inner_vlan, FieldValue::Absent);
    assert_eq!(w.inner_l2_priority, FieldValue::Absent);
    assert_eq!(w.inner_vlan_tpid, FieldValue::Absent);
}

#[test]
fn a_push_and_then_a_pop_give_the_frame_again() {
    let a = SetArena::standalone();
    for h in [
        frame(None, None),
        frame(Some((20, 5, 0x8100)), None),
        frame(Some((4095, 7, 0x9100)), None),
        request(),
    ] {
        let s = PacketSet::single(&a, &h);
        let (s, rest) = s.split_inner_vlan();
        assert!(s.is_empty());
        let p = rest.push_vlan(100, 0x88a8);
        assert_eq!(checked(&p.done.pop_vlan()), &rest.difference(&p.full));
    }
}

#[test]
fn an_inner_tag_needs_an_outer_tag() {
    let a = SetArena::standalone();
    // A stated inner tag makes the outer tag present.
    let mut h = request();
    h.inner_vlan = FieldValue::Known(30);
    let w = current(checked(&PacketSet::single(&a, &h)));
    assert!(w.vlan.is_present() && w.inner_vlan == FieldValue::Known(30));
    // An absent outer tag makes the inner tag absent.
    let mut h = request();
    h.vlan = FieldValue::Absent;
    h.inner_vlan = FieldValue::Known(30);
    let w = current(checked(&PacketSet::single(&a, &h)));
    assert_eq!(w.inner_vlan, FieldValue::Absent);
    // An unstated request holds no frame with an inner tag and no outer tag.
    let s = PacketSet::single(&a, &request());
    assert!(checked(&s).has_valid_tags());
    assert!(checked(&s.set_vlan(Some(10))).has_valid_tags());
}

#[test]
fn a_request_that_does_not_state_the_inner_tag_has_no_inner_tag() {
    let a = SetArena::standalone();
    let unstated = PacketSet::single(&a, &request());
    let (inner, rest) = unstated.split_inner_vlan();
    assert!(inner.is_empty());
    assert_eq!(rest, unstated);
    // A tagged frame that the request does not state has the TPID 0x8100.
    let tagged = PacketSet::single(&a, &frame(Some((7, 1, 0x8100)), None));
    assert!(tagged.is_subset(&unstated));
    let other = PacketSet::single(&a, &frame(Some((7, 1, 0x88a8)), None));
    assert!(other.intersect(&unstated).is_empty());
    let mut h = request();
    h.vlan = FieldValue::Known(7);
    let w = current(checked(&PacketSet::single(&a, &h)));
    assert_eq!(w.vlan_tpid, FieldValue::Known(0x8100));
    assert_eq!(w.inner_vlan, FieldValue::Absent);
    // A stated inner tag and a pushed tag are present.
    let stated = PacketSet::single(&a, &frame(Some((20, 5, 0x88a8)), Some((30, 1, 0x8100))));
    let (inner, rest) = stated.split_inner_vlan();
    assert_eq!(inner, stated);
    assert!(rest.is_empty());
    let (inner, _) = tagged.push_vlan(100, 0x88a8).done.split_inner_vlan();
    assert!(!inner.is_empty());
}

#[test]
fn the_tags_move_with_the_header_through_an_encapsulation() {
    let a = SetArena::standalone();
    let mut o = Header::request(ip("192.0.2.1"), ip("192.0.2.2"), PROTO_UDP)
        .with_src_port(49152)
        .with_dst_port(4789)
        .untagged();
    o.dscp = FieldValue::Known(0);
    o.ecn = FieldValue::Known(0);
    o.src_mac = FieldValue::Unknown;
    o.dst_mac = FieldValue::Unknown;
    o.encap = vec![Encap::Vxlan {
        src: ip("192.0.2.1"),
        dst: ip("192.0.2.2"),
        vni: 10,
    }];
    let s = PacketSet::single(&a, &frame(Some((20, 5, 0x88a8)), Some((30, 1, 0x8100))));
    let e = s.encapsulate(&o).done;
    let w = current(checked(&e));
    assert_eq!(w.vlan, FieldValue::Absent);
    assert_eq!(w.inner_vlan, FieldValue::Absent);
    let i = w.inner.unwrap();
    assert_eq!(i.vlan_tpid, FieldValue::Known(0x88a8));
    assert_eq!(i.inner_vlan, FieldValue::Known(30));
    assert_eq!(checked(&e.decapsulate().done), &s);
}

#[test]
fn a_set_input_has_no_inner_tag_and_the_tpid_of_802_1q() {
    let a = SetArena::standalone();
    for vlan in [Some(vec![(7, 7)]), None] {
        let spec = SetSpec {
            protocol: Some(vec![(PROTO_TCP, PROTO_TCP)]),
            vlan: vlan.clone(),
            ..SetSpec::default()
        };
        let s = PacketSet::from_spec(&a, &spec);
        assert!(checked(&s).split_inner_vlan().0.is_empty());
        let tagged = PacketSet::single(&a, &frame(Some((7, 1, 0x8100)), None));
        assert!(tagged.is_subset(&s), "{vlan:?}");
        let other = PacketSet::single(&a, &frame(Some((7, 1, 0x88a8)), None));
        assert!(other.intersect(&s).is_empty(), "{vlan:?}");
        let two = PacketSet::single(&a, &frame(Some((7, 1, 0x8100)), Some((8, 0, 0x8100))));
        assert!(two.intersect(&s).is_empty(), "{vlan:?}");
    }
}
