//! The export and receipt rules of a session, the originations, the
//! multipath and the install form of the BGP calculation.

mod bgp_common;

use std::collections::BTreeSet;

use bgp_common::*;
use rsim_functions::{RouteKind, RouteProtocol};
use rsim_routing::Platform;
use rsim_routing::bgp::converge::NOT_CHECKED;
use rsim_routing::bgp::{
    AdminValue, Aggregate, AsPath, Asn, Clause, Community, Convergence, Event, ExtCommunity,
    Family, MatchTerm, Network, NextHopSelf, Offer, PolicyBody, Reason, RouteDistinguisher,
    RouteKey, RoutePolicy, RouteState, Session, SessionEnd, SessionKind, SessionStage, SetAction,
    compute, export, install_candidates, receive,
};
use rsim_routing::bgp::{Note, RouteAt, RoutingStage};

const P: &str = "203.0.113.0/24";

fn end(device: &str, neighbor: &str) -> SessionEnd {
    SessionEnd {
        device: device.to_string(),
        vrf: "default".to_string(),
        neighbor: ip(neighbor),
    }
}

/// r1 (AS 65001, 10.0.0.1) and r2 (AS `r2_as`, 10.0.0.2) with one session.
fn pair(r2_as: u32) -> Lab {
    let mut lab = Lab::default();
    lab.router("r1", Platform::Iosxe, 65001, "10.255.0.1");
    lab.router("r2", Platform::Iosxe, r2_as, "10.255.0.2");
    lab.peer("r1", "10.0.0.1", "r2", "10.0.0.2");
    lab
}

fn transfer(lab: &Lab, path: &rsim_routing::bgp::BgpPath) -> (Offer, Offer) {
    let s = Session {
        a: end("r1", "10.0.0.2"),
        b: end("r2", "10.0.0.1"),
    };
    SessionStage {
        sender: lab.get("r1"),
        receiver: lab.get("r2"),
        session: &s,
    }
    .run(&(key(P), path.clone()))
}

fn sent(o: &Offer) -> &rsim_routing::bgp::BgpPath {
    match o {
        Offer::Path(p) => p,
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_ebgp_export_prepends_the_as_sets_the_next_hop_and_drops_the_internal_attributes() {
    let lab = pair(65002);
    let mut p = ibgp("10.9.9.9", &[65010]);
    p.local_pref = Some(200);
    p.med = Some(50);
    p.weight = 7;
    p.originator_id = Some(v4("10.255.0.9"));
    p.cluster_list = vec![v4("10.255.0.8")];
    let (out, accepted) = transfer(&lab, &p);
    let out = sent(&out);
    assert_eq!(out.as_path, AsPath::sequence(&[65001, 65010]));
    assert_eq!(out.next_hop, Some(ip("10.0.0.1")));
    assert_eq!(
        (out.local_pref, out.med, out.weight, out.originator_id),
        (None, None, 0, None)
    );
    assert!(out.cluster_list.is_empty());
    let a = sent(&accepted);
    assert_eq!(a.peer.address, Some(ip("10.0.0.1")));
    assert_eq!(a.peer.kind, SessionKind::Ebgp);
    assert_eq!(a.peer.asn, Asn(65001));
    assert_eq!(a.peer.router_id, Some(v4("10.255.0.1")));
}

#[test]
fn an_ebgp_path_with_the_as_of_the_receiver_is_rejected() {
    let lab = pair(65002);
    let (out, accepted) = transfer(&lab, &ibgp("10.9.9.9", &[65020, 65002]));
    assert!(matches!(out, Offer::Path(_)));
    assert_eq!(accepted, Offer::None);
}

#[test]
fn a_path_is_not_sent_back_to_its_peer() {
    let lab = pair(65002);
    let p = ebgp("10.0.0.2", &[65002]);
    assert_eq!(transfer(&lab, &p).0, Offer::None);
}

#[test]
fn a_local_path_keeps_its_med_to_an_ebgp_peer() {
    let lab = pair(65002);
    let mut path = rsim_routing::bgp::BgpPath::new(
        rsim_routing::bgp::Peer {
            address: None,
            router_id: Some(v4("10.255.0.1")),
            asn: Asn(65001),
            kind: SessionKind::Local(rsim_routing::bgp::LocalOrigin::Network),
        },
        None,
        AsPath::default(),
    );
    path.med = Some(30);
    let out = transfer(&lab, &path).0;
    assert_eq!(sent(&out).med, Some(30));
    assert_eq!(sent(&out).as_path, AsPath::sequence(&[65001]));
}

#[test]
fn no_export_stops_at_an_ebgp_peer_and_passes_an_ibgp_peer() {
    let mut p = ebgp("192.0.2.9", &[65010]);
    p.communities.insert(Community::NO_EXPORT);
    assert_eq!(transfer(&pair(65002), &p).0, Offer::None);
    assert!(matches!(transfer(&pair(65001), &p).0, Offer::Path(_)));
    p.communities = BTreeSet::from([Community::NO_ADVERTISE]);
    assert_eq!(transfer(&pair(65001), &p).0, Offer::None);
}

#[test]
fn the_communities_are_sent_only_with_send_community() {
    let mut lab = pair(65002);
    let mut p = ibgp("10.9.9.9", &[65010]);
    p.communities.insert(Community::new(65010, 1));
    p.ext_communities.insert(ExtCommunity::RouteTarget(
        "65010:7".parse::<AdminValue>().unwrap(),
    ));
    let out = transfer(&lab, &p).0;
    assert_eq!(sent(&out).communities.len(), 1);
    assert_eq!(sent(&out).ext_communities.len(), 1);
    let n = lab.neighbor_mut("r1", "10.0.0.2");
    n.send_community = false;
    n.send_community_extended = false;
    let out = transfer(&lab, &p).0;
    assert!(sent(&out).communities.is_empty());
    assert!(sent(&out).ext_communities.is_empty());
}

#[test]
fn an_ibgp_export_keeps_the_next_hop_unless_next_hop_self() {
    let mut lab = pair(65001);
    let p = ebgp("192.0.2.1", &[64500]);
    let out = transfer(&lab, &p).0;
    assert_eq!(sent(&out).next_hop, Some(ip("192.0.2.1")));
    assert_eq!(sent(&out).local_pref, Some(100));
    assert_eq!(sent(&out).as_path, AsPath::sequence(&[64500]));
    lab.neighbor_mut("r1", "10.0.0.2").next_hop_self = NextHopSelf::On;
    let out = transfer(&lab, &p).0;
    assert_eq!(sent(&out).next_hop, Some(ip("10.0.0.1")));
}

#[test]
fn an_ibgp_path_goes_to_an_ibgp_peer_only_through_a_reflector() {
    let mut lab = pair(65001);
    let p = ibgp("10.9.9.9", &[64500]);
    assert_eq!(transfer(&lab, &p).0, Offer::None);
    lab.neighbor_mut("r1", "10.0.0.2").route_reflector_client = true;
    let out = transfer(&lab, &p).0;
    let out = sent(&out);
    assert_eq!(out.originator_id, Some(v4("10.9.9.9")));
    assert_eq!(out.cluster_list, vec![v4("10.255.0.1")]);
    assert_eq!(out.next_hop, Some(ip("10.9.9.9")));
}

#[test]
fn a_reflected_path_needs_a_known_originator_id_and_cluster_id() {
    let mut lab = pair(65001);
    lab.neighbor_mut("r1", "10.0.0.2").route_reflector_client = true;
    let mut p = ibgp("10.9.9.9", &[64500]);
    p.peer.router_id = None;
    assert!(matches!(
        transfer(&lab, &p).0,
        Offer::Unknown(u) if u.reason == Reason::RouterIdNotKnown
    ));
    let p = ibgp("10.9.9.9", &[64500]);
    lab.proc("r1").router_id = None;
    assert!(matches!(
        transfer(&lab, &p).0,
        Offer::Unknown(u) if u.reason == Reason::RouterIdNotKnown
    ));
    lab.proc("r1").cluster_id = Some(v4("10.255.0.100"));
    assert!(matches!(transfer(&lab, &p).0, Offer::Path(_)));
    let r2 = lab.get("r2").clone();
    let n = &r2.neighbors[&ip("10.0.0.1")];
    let mut r2 = r2.clone();
    r2.router_id = None;
    let mut q = ibgp("10.0.0.1", &[64500]);
    q.originator_id = Some(v4("10.255.0.9"));
    assert!(matches!(
        receive(&r2, n, Some(v4("10.255.0.1")), &key(P), &q),
        Offer::Unknown(u) if u.reason == Reason::RouterIdNotKnown
    ));
}

#[test]
fn a_reflected_path_is_rejected_by_its_originator_and_by_a_router_of_its_cluster() {
    let lab = pair(65001);
    let r2 = lab.get("r2");
    let n = &r2.neighbors[&ip("10.0.0.1")];
    let mut p = ibgp("10.0.0.1", &[64500]);
    p.originator_id = Some(v4("10.255.0.2"));
    assert_eq!(
        receive(r2, n, Some(v4("10.255.0.1")), &key(P), &p),
        Offer::None
    );
    p.originator_id = Some(v4("10.255.0.9"));
    p.cluster_list = vec![v4("10.255.0.2")];
    assert_eq!(
        receive(r2, n, Some(v4("10.255.0.1")), &key(P), &p),
        Offer::None
    );
    p.cluster_list = vec![v4("10.255.0.3")];
    assert!(matches!(
        receive(r2, n, Some(v4("10.255.0.1")), &key(P), &p),
        Offer::Path(_)
    ));
}

#[test]
fn a_reflector_sends_a_client_path_to_the_other_client_with_the_originator_and_the_cluster() {
    let mut lab = Lab::default();
    lab.router("rr", Platform::Iosxe, 65001, "10.255.0.1");
    lab.router("c1", Platform::Iosxe, 65001, "10.255.0.11");
    lab.router("c2", Platform::Iosxe, 65001, "10.255.0.12");
    lab.peer("rr", "10.1.11.1", "c1", "10.1.11.11");
    lab.peer("rr", "10.1.12.1", "c2", "10.1.12.12");
    lab.neighbor_mut("rr", "10.1.11.11").route_reflector_client = true;
    lab.neighbor_mut("rr", "10.1.12.12").route_reflector_client = true;
    lab.seed("c1", "192.0.2.1", 64500, P, &[64500], None);
    let r = lab.run();
    let c2 = best(&r, "c2", P).unwrap();
    assert_eq!(c2.best.originator_id, Some(v4("10.255.0.11")));
    assert_eq!(c2.best.cluster_list, vec![v4("10.255.0.1")]);
    assert_eq!(c2.best.next_hop, Some(ip("192.0.2.1")));
    assert_eq!(c2.best.peer.kind, SessionKind::Ibgp);
    assert_eq!(best(&r, "c1", P).unwrap().best.peer.kind, SessionKind::Ebgp);
    assert!(matches!(
        r.groups[0].convergence,
        Convergence::Converged { .. }
    ));
}

#[test]
fn a_confederation_export_prepends_the_member_as_and_keeps_the_med_and_the_next_hop() {
    let mut lab = pair(65102);
    for (d, own, other) in [("r1", 65101, 65102), ("r2", 65102, 65101)] {
        let p = lab.proc(d);
        p.asn = Asn(own);
        p.confederation_id = Some(Asn(65000));
        p.confederation_peers = [Asn(other)].into();
    }
    lab.neighbor_mut("r2", "10.0.0.1").remote_as = Asn(65101);
    let mut p = ebgp("192.0.2.1", &[64500]);
    p.med = Some(5);
    let (out, accepted) = transfer(&lab, &p);
    let out = sent(&out);
    assert_eq!(out.as_path.to_string(), "(65101) 64500");
    assert_eq!(out.as_path.len(), 1);
    assert_eq!(out.med, Some(5));
    assert_eq!(out.next_hop, Some(ip("192.0.2.1")));
    assert_eq!(sent(&accepted).peer.kind, SessionKind::ConfedEbgp);
    let mut to_outside = pair(65002);
    let r1 = to_outside.proc("r1");
    r1.confederation_id = Some(Asn(65000));
    let mut q = ibgp("10.9.9.9", &[64500]);
    q.as_path = q.as_path.prepend_confed(Asn(65103));
    let out = transfer(&to_outside, &q).0;
    assert_eq!(sent(&out).as_path, AsPath::sequence(&[65000, 64500]));
}

/// r1 (member AS 65101) and r2 (member AS 65102) of the confederation
/// 65000 with one session.
fn confederation_pair() -> Lab {
    let mut lab = pair(65102);
    for (d, own, other) in [("r1", 65101, 65102), ("r2", 65102, 65101)] {
        let p = lab.proc(d);
        p.asn = Asn(own);
        p.confederation_id = Some(Asn(65000));
        p.confederation_peers = [Asn(other)].into();
    }
    lab.neighbor_mut("r2", "10.0.0.1").remote_as = Asn(65101);
    lab
}

#[test]
fn next_hop_self_sets_the_next_hop_on_a_confederation_ebgp_session() {
    let mut lab = confederation_pair();
    let p = ebgp("192.0.2.1", &[64500]);
    assert_eq!(sent(&transfer(&lab, &p).0).next_hop, Some(ip("192.0.2.1")));
    lab.neighbor_mut("r1", "10.0.0.2").next_hop_self = NextHopSelf::On;
    let out = transfer(&lab, &p).0;
    assert_eq!(sent(&out).next_hop, Some(ip("10.0.0.1")));
    assert_eq!(sent(&out).peer.kind, SessionKind::ConfedEbgp);
}

#[test]
fn an_export_policy_that_sets_the_present_next_hop_keeps_it_on_an_ebgp_session() {
    use rsim_routing::bgp::NextHopSet;
    let mut lab = pair(65002);
    let mut c = Clause::new(10, true);
    c.sets
        .push(SetAction::NextHop(NextHopSet::Address(ip("10.9.9.9"))));
    lab.proc("r1").policy.policies.insert(
        "nh".to_string(),
        RoutePolicy {
            name: "nh".to_string(),
            body: PolicyBody::RouteMap(vec![c]),
            spans: Vec::new(),
        },
    );
    let p = ibgp("10.9.9.9", &[65010]);
    assert_eq!(sent(&transfer(&lab, &p).0).next_hop, Some(ip("10.0.0.1")));
    lab.neighbor_mut("r1", "10.0.0.2").export_policy = Some("nh".to_string());
    assert_eq!(sent(&transfer(&lab, &p).0).next_hop, Some(ip("10.9.9.9")));
}

#[test]
fn a_full_mesh_picks_the_exit_with_the_lower_igp_cost() {
    let mut lab = Lab::default();
    for (d, rid) in [
        ("r1", "10.255.0.1"),
        ("r2", "10.255.0.2"),
        ("r3", "10.255.0.3"),
    ] {
        lab.router(d, Platform::Iosxe, 65001, rid);
    }
    lab.peer("r1", "10.1.2.1", "r2", "10.1.2.2");
    lab.peer("r1", "10.1.3.1", "r3", "10.1.3.3");
    lab.peer("r2", "10.2.3.2", "r3", "10.2.3.3");
    lab.seed("r2", "192.0.2.2", 64500, P, &[64500], None);
    lab.seed("r3", "192.0.2.3", 64500, P, &[64500], None);
    lab.cost("r1", "192.0.2.2", 10);
    lab.cost("r1", "192.0.2.3", 20);
    lab.cost("r2", "192.0.2.3", 15);
    lab.cost("r3", "192.0.2.2", 15);
    let r = lab.run();
    assert_eq!(
        r.groups[0].convergence,
        Convergence::Converged {
            note: Some(Note {
                text: NOT_CHECKED,
                wheel: Vec::new(),
            })
        }
    );
    let b = best(&r, "r1", P).unwrap();
    assert_eq!(b.best.next_hop, Some(ip("192.0.2.2")));
    assert_eq!(b.best.igp_cost, 10);
    assert_eq!(
        best(&r, "r2", P).unwrap().best.next_hop,
        Some(ip("192.0.2.2"))
    );
    assert_eq!(
        best(&r, "r3", P).unwrap().best.next_hop,
        Some(ip("192.0.2.3"))
    );
    let inst = install_candidates(&r, &lab.input.processes);
    let c = &inst[&("r1".to_string(), "default".to_string())][0];
    assert_eq!(c.distance, 200);
    assert_eq!(c.route.kind, RouteKind::Learned(RouteProtocol::Bgp));
    assert_eq!(c.gateways, vec![ip("192.0.2.2")]);
}

fn dual_homed(maximum_paths: Option<u32>) -> Lab {
    let mut lab = Lab::default();
    lab.router("r1", Platform::Iosxe, 65001, "10.255.0.1")
        .options
        .maximum_paths_ebgp = maximum_paths;
    lab.seed("r1", "192.0.2.1", 64500, P, &[64500], None);
    lab.seed("r1", "192.0.2.5", 64500, P, &[64500], None);
    lab
}

#[test]
fn a_dual_homed_ebgp_prefix_under_maximum_paths_converges_with_2_paths() {
    let lab = dual_homed(Some(2));
    let r = lab.run();
    assert_eq!(
        r.groups[0].convergence,
        Convergence::Converged {
            note: Some(Note {
                text: NOT_CHECKED,
                wheel: Vec::new(),
            })
        }
    );
    let b = best(&r, "r1", P).unwrap();
    assert_eq!(b.multipath.len(), 2);
    let inst = install_candidates(&r, &lab.input.processes);
    let c = &inst[&("r1".to_string(), "default".to_string())][0];
    assert_eq!(c.distance, 20);
    let gws: BTreeSet<_> = c.gateways.iter().copied().collect();
    assert_eq!(gws, BTreeSet::from([ip("192.0.2.1"), ip("192.0.2.5")]));
}

#[test]
fn a_tie_with_one_installed_path_gives_one_outcome_for_each_tied_path() {
    let r = dual_homed(Some(1)).run();
    let Convergence::MultipleStableOutcomes { outcomes } = &r.groups[0].convergence else {
        panic!("{:?}", r.groups[0].convergence);
    };
    assert_eq!(outcomes.len(), 2);
}

#[test]
fn a_summary_only_aggregate_holds_its_contributors_back() {
    let mut lab = pair(65002);
    lab.originate("r1", "192.0.2.0/25");
    lab.originate("r1", "192.0.2.128/25");
    lab.proc("r1").aggregates.push(Aggregate {
        key: key("192.0.2.0/24"),
        summary_only: true,
        as_set: false,
        spans: Vec::new(),
    });
    let r = lab.run();
    assert_eq!(r.groups.len(), 1);
    assert_eq!(as_path_of(&r, "r2", "192.0.2.0/24"), Some(vec![65001]));
    assert!(state(&r, "r2", "192.0.2.0/25").is_none());
    assert!(best(&r, "r1", "192.0.2.0/25").is_some());
    let inst = install_candidates(&r, &lab.input.processes);
    let r1 = &inst[&("r1".to_string(), "default".to_string())];
    assert_eq!(r1.len(), 1);
    assert_eq!(r1[0].prefix, pfx("192.0.2.0/24"));
    assert_eq!(r1[0].route.kind, RouteKind::Null);
    assert_eq!(r1[0].distance, 200);
}

#[test]
fn an_as_set_aggregate_holds_the_ases_and_the_worst_origin_of_its_contributors() {
    let mut lab = pair(65002);
    lab.router("r0", Platform::Iosxe, 64500, "10.255.0.9");
    lab.peer("r0", "10.0.9.9", "r1", "10.0.9.1");
    lab.originate("r0", "192.0.2.0/25");
    lab.originate("r1", "192.0.2.128/25");
    lab.proc("r1").aggregates.push(Aggregate {
        key: key("192.0.2.0/24"),
        summary_only: false,
        as_set: true,
        spans: Vec::new(),
    });
    let r = lab.run();
    let agg = best(&r, "r2", "192.0.2.0/24").unwrap();
    assert_eq!(agg.best.as_path.to_string(), "65001 {64500}");
    assert!(best(&r, "r2", "192.0.2.0/25").is_some());
}

#[test]
fn an_as_set_aggregate_keeps_the_common_leading_sequence_and_sets_the_other_ases() {
    use rsim_routing::bgp::{AsSegment, SegmentKind, aggregate_as_path};
    let text = |paths: &[AsPath]| {
        let refs: Vec<&AsPath> = paths.iter().collect();
        aggregate_as_path(&refs).to_string()
    };
    let a = AsPath::sequence(&[100, 200]);
    let b = AsPath::sequence(&[100, 300]);
    assert_eq!(text(&[a.clone(), b.clone()]), "100 {200,300}");
    assert_eq!(aggregate_as_path(&[&a, &b]).len(), 2);
    assert_eq!(text(std::slice::from_ref(&a)), "100 200");
    assert_eq!(
        text(&[a.clone(), AsPath::sequence(&[200, 100])]),
        "{100,200}"
    );
    assert_eq!(
        text(&[a.clone(), AsPath::sequence(&[100, 200, 300])]),
        "100 200 {300}"
    );
    assert_eq!(
        text(&[AsPath::sequence(&[64500]), AsPath::default()]),
        "{64500}"
    );
    let confed = AsPath::sequence(&[100, 200]).prepend_confed(Asn(65101));
    let mut with_set = AsPath::sequence(&[100]);
    with_set.segments.push(AsSegment {
        kind: SegmentKind::Set,
        asns: vec![Asn(400), Asn(100)],
    });
    assert_eq!(text(&[confed, with_set]), "[65101] 100 {200,400}");
}

#[test]
fn an_evpn_ip_prefix_route_carries_its_route_target_over_an_evpn_session_only() {
    let mut lab = pair(65002);
    lab.router("r3", Platform::Iosxe, 65003, "10.255.0.3");
    lab.peer("r1", "10.0.1.1", "r3", "10.0.1.3");
    for (d, n) in [("r1", "10.0.0.2"), ("r2", "10.0.0.1")] {
        lab.neighbor_mut(d, n)
            .activated
            .insert(Family::EvpnIpPrefix);
    }
    let rd = RouteDistinguisher("10.255.0.1:5".parse().unwrap());
    let rt: AdminValue = "65001:5".parse().unwrap();
    let k = RouteKey::evpn_ip_prefix(rd, pfx("198.51.100.0/24"));
    let mut c = Clause::new(10, true);
    c.sets.push(SetAction::RouteTargetAdd(vec![rt]));
    let r1 = lab.proc("r1");
    r1.policy.policies.insert(
        "rt".to_string(),
        RoutePolicy {
            name: "rt".to_string(),
            body: PolicyBody::RouteMap(vec![c]),
            spans: Vec::new(),
        },
    );
    r1.networks.push(Network {
        key: k,
        policy: Some("rt".to_string()),
        spans: Vec::new(),
    });
    lab.igp
        .routes
        .insert(("r1".to_string(), pfx("198.51.100.0/24")));
    let at = |d: &str| RouteAt {
        device: d.to_string(),
        vrf: "default".to_string(),
        key: k,
    };
    let r = lab.run();
    let Some(RouteState::Selected(s)) = r.routes.get(&at("r2")) else {
        panic!("{:?}", r.routes);
    };
    assert_eq!(s.best.route_targets().collect::<Vec<_>>(), vec![rt]);
    assert!(!r.routes.contains_key(&at("r3")));
    assert!(install_candidates(&r, &lab.input.processes).is_empty());
    lab.neighbor_mut("r1", "10.0.0.2").send_community_extended = false;
    let r = lab.run();
    let Some(RouteState::Selected(s)) = r.routes.get(&at("r2")) else {
        panic!("{:?}", r.routes);
    };
    assert_eq!(s.best.route_targets().count(), 0);
}

#[test]
fn a_platform_with_no_profile_makes_its_routes_and_the_routes_after_it_unknown() {
    let mut lab = pair(65002);
    lab.proc("r1").platform = None;
    lab.originate("r1", P);
    let r = lab.run();
    for d in ["r1", "r2"] {
        let Some(RouteState::Unknown(u)) = state(&r, d, P) else {
            panic!("{d}: {:?}", state(&r, d, P));
        };
        assert_cause(u, Reason::NoBgpProfile);
    }
    let inst = install_candidates(&r, &lab.input.processes);
    let c = &inst[&("r2".to_string(), "default".to_string())][0];
    assert_eq!(c.distance, 20);
    assert!(
        c.route
            .unknown_reason()
            .unwrap()
            .starts_with("convergence not determined: no bgp profile")
    );
}

#[test]
fn an_unhandled_import_term_makes_the_route_unknown_only_where_it_decides() {
    let mut lab = pair(65002);
    lab.originate("r1", P);
    lab.originate("r1", "198.51.100.0/24");
    let mut deny = Clause::new(10, false);
    deny.matches
        .push(MatchTerm::PrefixSet(rsim_routing::bgp::PrefixList::set(&[
            (pfx("198.51.100.0/24"), 24, 24),
        ])));
    let mut odd = Clause::new(20, true);
    odd.matches
        .push(MatchTerm::Unhandled("match rpki valid".to_string()));
    let r2 = lab.proc("r2");
    r2.policy.policies.insert(
        "in".to_string(),
        RoutePolicy {
            name: "in".to_string(),
            body: PolicyBody::RouteMap(vec![deny, odd]),
            spans: Vec::new(),
        },
    );
    lab.neighbor_mut("r2", "10.0.0.1").import_policy = Some("in".to_string());
    let r = lab.run();
    let Some(RouteState::Unknown(u)) = state(&r, "r2", P) else {
        panic!("{:?}", state(&r, "r2", P));
    };
    assert_cause(u, Reason::PolicyClauseNotEvaluated);
    assert!(state(&r, "r2", "198.51.100.0/24").is_none());
    let g = r.groups.iter().find(|g| g.keys.contains(&key(P))).unwrap();
    assert!(
        matches!(
            &g.convergence,
            Convergence::Unknown { reason } if reason.reason == Reason::ConvergenceNotDetermined
        ),
        "{:?}",
        g.convergence
    );
    assert!(r.affected.contains(&key(P)));
}

#[test]
fn a_next_hop_that_does_not_resolve_gives_no_candidate_and_an_unknown_one_an_unknown_route() {
    let mut lab = Lab::default();
    lab.router("r1", Platform::Iosxe, 65001, "10.255.0.1");
    lab.seed("r1", "192.0.2.1", 64500, P, &[64500], None);
    lab.igp
        .unresolved
        .insert(("r1".to_string(), ip("192.0.2.1")));
    assert!(state(&lab.run(), "r1", P).is_none());
    lab.igp.unresolved.clear();
    lab.igp.unknown.insert(("r1".to_string(), ip("192.0.2.1")));
    let r = lab.run();
    let Some(RouteState::Unknown(u)) = state(&r, "r1", P) else {
        panic!("{:?}", state(&r, "r1", P));
    };
    assert_cause(u, Reason::NextHopNotResolved);
}

#[test]
fn each_round_of_a_chain_records_the_routes_that_it_changes() {
    let mut lab = Lab::default();
    for (i, d) in ["r0", "r1", "r2"].iter().enumerate() {
        lab.router(
            d,
            Platform::Iosxe,
            65000 + i as u32,
            &format!("10.255.0.{i}"),
        );
    }
    lab.peer("r0", "10.0.1.0", "r1", "10.0.1.1");
    lab.peer("r1", "10.1.2.1", "r2", "10.1.2.2");
    lab.originate("r0", P);
    let r = lab.run();
    let rounds: Vec<Vec<String>> = r
        .events
        .iter()
        .map(|e| match e {
            Event::Round { changed, .. } => changed.iter().map(|c| c.device.clone()).collect(),
            Event::Search { .. } => panic!("no search: {e:?}"),
        })
        .collect();
    assert_eq!(rounds[..3], [vec!["r0"], vec!["r1"], vec!["r2"]]);
    assert!(rounds[3..].iter().all(|r| r.is_empty()));
    assert_eq!(as_path_of(&r, "r2", P), Some(vec![65001, 65000]));
}

#[test]
fn a_session_to_a_process_that_the_input_does_not_hold_is_an_input_error() {
    let mut lab = pair(65002);
    lab.input.sessions.push(Session {
        a: end("r1", "10.0.0.2"),
        b: end("r9", "10.0.0.1"),
    });
    assert!(compute(&lab.input, &lab.igp).is_err());
    let mut lab = pair(65002);
    lab.input.sessions[0].a.neighbor = ip("10.0.0.99");
    assert!(compute(&lab.input, &lab.igp).is_err());
}

#[test]
fn an_export_from_a_process_with_no_profile_is_unknown() {
    let lab = pair(65002);
    let mut r1 = lab.get("r1").clone();
    r1.platform = None;
    let n = &r1.neighbors[&ip("10.0.0.2")];
    let out = export(&r1, n, ip("10.0.0.1"), &key(P), &ibgp("10.9.9.9", &[1]));
    assert!(matches!(out, Offer::Unknown(u) if u.reason == Reason::NoBgpProfile));
}

fn transfer_back(lab: &Lab, path: &rsim_routing::bgp::BgpPath) -> (Offer, Offer) {
    let s = Session {
        a: end("r2", "10.0.0.1"),
        b: end("r1", "10.0.0.2"),
    };
    SessionStage {
        sender: lab.get("r2"),
        receiver: lab.get("r1"),
        session: &s,
    }
    .run(&(key(P), path.clone()))
}

/// The pair with the `local-as` 64999 at r1 towards r2.
fn local_as(no_prepend: bool, replace_as: bool) -> Lab {
    let mut lab = pair(65002);
    lab.neighbor_mut("r1", "10.0.0.2").local_as = Some(rsim_routing::bgp::LocalAs {
        asn: Asn(64999),
        no_prepend,
        replace_as,
        dual_as: false,
    });
    lab.neighbor_mut("r2", "10.0.0.1").remote_as = Asn(64999);
    lab
}

#[test]
fn a_local_as_is_prepended_before_the_as_of_the_process_unless_replace_as() {
    let p = ibgp("10.9.9.9", &[65010]);
    let out = transfer(&local_as(false, false), &p).0;
    assert_eq!(sent(&out).as_path, AsPath::sequence(&[64999, 65001, 65010]));
    let out = transfer(&local_as(false, true), &p).0;
    assert_eq!(sent(&out).as_path, AsPath::sequence(&[64999, 65010]));
}

#[test]
fn a_received_path_gets_the_local_as_unless_no_prepend_and_a_path_with_it_is_rejected() {
    let p = ibgp("10.9.9.9", &[65020]);
    let got = transfer_back(&local_as(false, false), &p).1;
    assert_eq!(sent(&got).as_path, AsPath::sequence(&[64999, 65002, 65020]));
    assert_eq!(sent(&got).peer.asn, Asn(65002));
    let got = transfer_back(&local_as(true, false), &p).1;
    assert_eq!(sent(&got).as_path, AsPath::sequence(&[65002, 65020]));
    let looped = ibgp("10.9.9.9", &[65020, 64999]);
    assert_eq!(
        transfer_back(&local_as(false, false), &looped).1,
        Offer::None
    );
}

#[test]
fn a_key_that_holds_a_session_address_joins_the_group_of_each_key() {
    let mut lab = pair(65002);
    lab.originate("r1", P);
    lab.originate("r1", "198.51.100.0/24");
    assert_eq!(lab.run().groups.len(), 2);
    lab.originate("r1", "10.0.0.0/24");
    let r = lab.run();
    assert_eq!(r.groups.len(), 1);
    assert_eq!(r.groups[0].keys.len(), 3);
}

#[test]
fn a_sole_seed_with_attributes_not_collected_propagates_and_a_contested_one_is_unknown() {
    let mut lab = pair(65002);
    lab.seed("r1", "192.0.2.1", 64500, P, &[64500], None);
    lab.input.seeds[0].path.attributes_collected = false;
    let r = lab.run();
    assert!(!best(&r, "r2", P).unwrap().best.attributes_collected);
    lab.seed("r1", "192.0.2.5", 64501, P, &[64501], None);
    let r = lab.run();
    let Some(RouteState::Unknown(u)) = state(&r, "r1", P) else {
        panic!("{:?}", state(&r, "r1", P));
    };
    assert_cause(u, Reason::PathAttributesNotCollected);
}

#[test]
fn an_accepted_seed_skips_the_import_policy_and_a_received_seed_runs_it() {
    let mut lab = pair(65002);
    lab.seed("r1", "192.0.2.1", 64500, P, &[64500], None);
    lab.proc("r1").policy.policies.insert(
        "deny".to_string(),
        RoutePolicy {
            name: "deny".to_string(),
            body: PolicyBody::RouteMap(Vec::new()),
            spans: Vec::new(),
        },
    );
    lab.neighbor_mut("r1", "192.0.2.1").import_policy = Some("deny".to_string());
    assert!(state(&lab.run(), "r1", P).is_none());
    lab.input.seeds[0].received = false;
    let r = lab.run();
    let b = best(&r, "r1", P).unwrap();
    assert_eq!(b.best.peer.address, Some(ip("192.0.2.1")));
    assert_eq!(b.best.peer.kind, SessionKind::Ebgp);
}

#[test]
fn two_outside_ibgp_seeds_that_tie_to_the_router_id_step_need_their_router_ids() {
    let run = |ids: [Option<&str>; 2]| {
        let mut lab = Lab::default();
        lab.router("r1", Platform::Iosxe, 65001, "10.255.0.1");
        lab.seed("r1", "192.0.2.1", 65001, P, &[64500], None);
        lab.seed("r1", "192.0.2.5", 65001, P, &[64500], None);
        for (s, id) in lab.input.seeds.iter_mut().zip(ids) {
            s.path.peer.router_id = id.map(v4);
        }
        lab.run()
    };
    let r = run([None, None]);
    let Some(RouteState::Unknown(u)) = state(&r, "r1", P) else {
        panic!("{:?}", state(&r, "r1", P));
    };
    assert_cause(u, Reason::RouterIdNotKnown);
    let r = run([Some("198.51.100.9"), Some("198.51.100.2")]);
    assert_eq!(
        best(&r, "r1", P).unwrap().best.next_hop,
        Some(ip("192.0.2.5"))
    );
}

#[test]
fn a_network_with_no_import_check_is_originated_with_no_route_of_its_prefix() {
    use rsim_routing::bgp::{Network, network_offer};
    let mut lab = Lab::default();
    lab.router("r1", Platform::FrrTraditional, 65001, "10.255.0.1");
    let n = Network {
        key: key(P),
        policy: None,
        spans: Vec::new(),
    };
    for (check, originated) in [(Some(false), true), (Some(true), false), (None, false)] {
        lab.proc("r1").options.network_import_check = check;
        let out = network_offer(lab.get("r1"), &n, Some(false));
        assert_eq!(
            matches!(out, Offer::Path(_)),
            originated,
            "{check:?}: {out:?}"
        );
        assert!(matches!(
            network_offer(lab.get("r1"), &n, Some(true)),
            Offer::Path(_)
        ));
    }
    lab.proc("r1").options.network_import_check = Some(false);
    lab.proc("r1").networks.push(n);
    let r = lab.run();
    assert!(best(&r, "r1", P).is_some());
}

/// Asserts that `u` is an unknown convergence whose details hold an
/// unknown route with the reason `cause`.
fn assert_cause(u: &rsim_routing::bgp::Unknown, cause: Reason) {
    assert_eq!(u.reason, Reason::ConvergenceNotDetermined, "{u}");
    assert!(u.details.iter().any(|d| d.starts_with(cause.text())), "{u}");
}
