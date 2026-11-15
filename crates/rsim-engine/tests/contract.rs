//! Checks of the function contract and of edge cases of the functions.

mod common;

use std::collections::BTreeMap;

use common::*;
use rsim_core::{
    Alternative, Attr, Branch, Context, Delay, EndpointId, FieldValue, FlowKey, FlowState,
    InterfaceId, NetFunction, NextHop, Outcome, PacketSet, Prefix, PrefixTable, Reason, ReasonCode,
    Tri, TriePrefixTable, Verdict, ZoneId,
};
use rsim_engine::{Executor, Query, Summary, check_partition};
use rsim_functions::{Neighbour, NextHopResolution, UnzonedInterface, ZoneLookup, ZoneRole};

fn branch(p: PacketSet) -> Branch {
    Branch::new(
        p,
        Outcome::Drop,
        Reason::new(ReasonCode::Denied, "test"),
        Context::default(),
        FlowState::new(),
        Delay::zero(),
    )
}

fn alt(b: Branch, i: u32) -> Branch {
    b.with_alternative(Alternative {
        choice: fid("f"),
        key: "k".into(),
        index: i,
        count: 2,
        label: format!("alt {i}"),
    })
}

#[test]
fn the_partition_check_finds_lost_duplicated_and_unequal_packets() {
    let a = PacketSet::single(udp("10.0.0.1", 1, "10.0.0.2", 53));
    let b = PacketSet::single(udp("10.0.0.1", 2, "10.0.0.2", 53));
    let input = a.union(&b);
    assert!(check_partition(&input, &[branch(a.clone()), branch(b.clone())]).is_ok());
    // A lost packet.
    assert!(check_partition(&input, &[branch(a.clone())]).is_err());
    // A duplicated packet.
    assert!(check_partition(&input, &[branch(input.clone()), branch(a.clone())]).is_err());
    // Alternatives of one choice with different packets.
    assert!(
        check_partition(
            &input,
            &[alt(branch(input.clone()), 0), alt(branch(a.clone()), 1)]
        )
        .is_err()
    );
    // Alternatives of one choice with the same packets.
    assert!(
        check_partition(
            &input,
            &[alt(branch(input.clone()), 0), alt(branch(input.clone()), 1)]
        )
        .is_ok()
    );
}

#[test]
fn two_owners_behind_one_link_are_two_owners() {
    let dev = Dev::new("r1", nxos());
    let mut table: TriePrefixTable<Vec<Neighbour>> = TriePrefixTable::new();
    let n = |owner: &str| Neighbour {
        interface: InterfaceId::new("eth1"),
        target: rsim_core::NeighbourTarget::Link,
        owner: owner.into(),
        spans: Vec::new(),
    };
    table.insert(
        Prefix::host(ip("10.0.0.9")),
        vec![n("router-a"), n("router-b")],
    );
    let f = NextHopResolution {
        meta: dev.meta("nexthop", 1, 1),
        neighbours: table,
        complete: true,
        egress: BTreeMap::from([(InterfaceId::new("eth1"), fid("r1/out/eth1"))]),
    };
    let ctx = Context {
        egress_interface: Attr::Known(InterfaceId::new("eth1")),
        next_hop: Attr::Known(NextHop::Gateway(ip("10.0.0.9"))),
        ..Context::default()
    };
    let out = f.apply(
        &PacketSet::single(udp("10.0.0.1", 1, "10.5.0.1", 53)),
        &ctx,
        &FlowState::new(),
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].outcome, Outcome::Unknown);
    assert_eq!(out[0].reason.code, ReasonCode::AmbiguousOwner);
    assert!(out[0].reason.detail.contains("router-a, router-b"));
}

#[test]
fn an_unstated_field_against_a_known_session_field_is_uncertain() {
    let known = udp("10.0.0.1", 40000, "10.0.0.2", 53);
    let key = FlowKey::of(&known);
    let mut unstated = known.clone();
    unstated.src_port = FieldValue::Unstated;
    assert_eq!(key.matches(&known), Tri::True);
    assert_eq!(key.matches(&unstated), Tri::Unknown);
    assert_eq!(FlowKey::of(&unstated).matches(&known), Tri::Unknown);
    assert_eq!(FlowKey::of(&unstated).matches(&unstated), Tri::True);
}

#[test]
fn an_interface_in_no_zone_follows_the_profile() {
    let dev = Dev::new("fw", fortios());
    let mk = |unzoned| ZoneLookup {
        meta: dev.meta("zone", 1, 1),
        role: ZoneRole::Source,
        by_interface: BTreeMap::from([(InterfaceId::new("port1"), ZoneId::new("corp"))]),
        unzoned,
        next: fid("fw/next"),
    };
    let ctx = Context {
        ingress_interface: Attr::Known(InterfaceId::new("port9")),
        ..Context::default()
    };
    let p = PacketSet::single(udp("10.0.0.1", 1, "10.0.0.2", 53));
    let drop = mk(UnzonedInterface::Drop).apply(&p, &ctx, &FlowState::new());
    assert_eq!(drop[0].outcome, Outcome::Drop);
    let ind = mk(UnzonedInterface::Unknown).apply(&p, &ctx, &FlowState::new());
    assert_eq!(ind[0].outcome, Outcome::Unknown);
}

#[test]
fn a_long_path_does_not_exhaust_the_stack() {
    // 200 routers, 6 steps each: 1,200 nested function applications, run in
    // a thread with the default test stack of 2 MiB.
    let twin = chain(200, 2, 2).build().unwrap();
    let q = Query::from_endpoint(
        &twin,
        &EndpointId::new("client"),
        tcp("10.254.0.10", 40000, "10.255.0.10", 443),
    )
    .unwrap();
    let a = std::thread::spawn(move || Executor::new(&twin).run(&q).map(|a| a.summary))
        .join()
        .expect("no stack overflow")
        .unwrap();
    assert_eq!(
        a,
        Summary::Same(Verdict::Deliver(rsim_core::Destination::Endpoint(
            EndpointId::new("server")
        )))
    );
}
