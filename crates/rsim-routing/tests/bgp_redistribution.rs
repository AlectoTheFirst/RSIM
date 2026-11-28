//! The redistribution into BGP, the EVPN IP prefix routes of the VRFs, the
//! VRF leaks by route target, and the rounds over a mutual redistribution
//! of OSPF and BGP.

mod bgp_common;

use std::collections::BTreeSet;
use std::net::IpAddr;

use bgp_common::*;
use rsim_core::Prefix;
use rsim_routing::Platform;
use rsim_routing::bgp::{
    AdminValue, Asn, BgpInput, BgpOrigin, BgpProcess, BgpResult, Clause, ExtCommunity, Family,
    IgpRoute, IgpSource, IgpView, Leaked, LocalOrigin, MatchTerm, OspfRouteType, PolicyBody,
    PrefixList, Reason, RedistSource, Redistribution, Resolution, RouteAt, RouteDistinguisher,
    RouteKey, RoutePolicy, RouteState, Session, SessionEnd, SessionKind, compute,
    install_candidates, overlay_candidates,
};
use rsim_routing::rounds::{self, Rounds};

/// An IGP view by device, VRF and next hop. A next hop resolves with the
/// cost 0 unless it is in `unknown`.
#[derive(Clone, Debug, Default)]
struct View {
    unknown: BTreeSet<(String, String, IpAddr)>,
}

impl IgpView for View {
    fn resolve(&self, device: &str, vrf: &str, nh: IpAddr) -> Resolution {
        if self
            .unknown
            .contains(&(device.to_string(), vrf.to_string(), nh))
        {
            Resolution::Unknown("not in the test view".to_string())
        } else {
            Resolution::Resolved { cost: 0 }
        }
    }

    fn has_route(&self, _device: &str, _vrf: &str, _prefix: Prefix) -> Option<bool> {
        Some(false)
    }
}

fn route(device: &str, vrf: &str, prefix: &str, source: IgpSource, metric: u32) -> IgpRoute {
    IgpRoute {
        device: device.to_string(),
        vrf: vrf.to_string(),
        prefix: pfx(prefix),
        source,
        metric,
        tag: None,
        next_hop: None,
        unknown: None,
        spans: Vec::new(),
    }
}

fn redistribute(source: RedistSource, policy: Option<&str>) -> Redistribution {
    Redistribution {
        family: Family::Ipv4Unicast,
        source,
        ospf_match: None,
        policy: policy.map(str::to_string),
        metric: None,
        spans: Vec::new(),
    }
}

fn at(device: &str, vrf: &str, prefix: &str) -> RouteAt {
    RouteAt {
        device: device.to_string(),
        vrf: vrf.to_string(),
        key: key(prefix),
    }
}

fn selected<'a>(
    r: &'a BgpResult,
    device: &str,
    vrf: &str,
    prefix: &str,
) -> Option<&'a rsim_routing::bgp::Selection> {
    match r.routes.get(&at(device, vrf, prefix))? {
        RouteState::Selected(s) => Some(s),
        RouteState::Unknown(_) => None,
    }
}

fn rt(s: &str) -> AdminValue {
    s.parse().unwrap()
}

const OSPF: IgpSource = IgpSource::Ospf {
    process: String::new(),
    route_type: OspfRouteType::Internal,
};

#[test]
fn a_route_map_filters_the_connected_routes_and_a_default_route_needs_default_information() {
    let mut lab = Lab::default();
    lab.router("r1", Platform::Iosxe, 65001, "10.255.0.1");
    lab.router("r2", Platform::Iosxe, 65002, "10.255.0.2");
    lab.peer("r1", "10.0.0.1", "r2", "10.0.0.2");
    let mut c = Clause::new(10, true);
    c.matches.push(MatchTerm::PrefixSet(PrefixList::set(&[(
        pfx("10.10.0.0/16"),
        16,
        24,
    )])));
    let r1 = lab.proc("r1");
    r1.policy.policies.insert(
        "C".to_string(),
        RoutePolicy {
            name: "C".to_string(),
            body: PolicyBody::RouteMap(vec![c]),
            spans: Vec::new(),
        },
    );
    r1.redistributions = vec![
        redistribute(RedistSource::Connected, Some("C")),
        redistribute(RedistSource::Static, None),
    ];
    lab.input.igp_routes = vec![
        route("r1", "default", "10.10.1.0/24", IgpSource::Connected, 0),
        route("r1", "default", "10.20.1.0/24", IgpSource::Connected, 0),
        route("r1", "default", "0.0.0.0/0", IgpSource::Static, 0),
    ];
    let r = lab.run();
    let s = best(&r, "r1", "10.10.1.0/24").expect("the permitted connected route");
    assert_eq!(
        s.best.peer.kind,
        SessionKind::Local(LocalOrigin::Redistribute)
    );
    assert_eq!(s.best.origin, BgpOrigin::Incomplete);
    assert_eq!(s.best.weight, 32_768);
    assert_eq!(s.best.next_hop, None);
    let s = best(&r, "r2", "10.10.1.0/24").expect("the route at the eBGP peer");
    assert_eq!(as_path_of(&r, "r2", "10.10.1.0/24"), Some(vec![65001]));
    assert_eq!(s.best.med, Some(0));
    assert!(state(&r, "r1", "10.20.1.0/24").is_none());
    assert!(state(&r, "r1", "0.0.0.0/0").is_none());
    assert!(
        install_candidates(&r, &lab.input.processes)
            .get(&("r1".to_string(), "default".to_string()))
            .is_none()
    );
    lab.proc("r1").default_originate = true;
    let r = lab.run();
    assert!(best(&r, "r2", "0.0.0.0/0").is_some());
}

#[test]
fn ios_xe_offers_only_internal_ospf_routes_and_a_match_clause_or_ios_xr_offers_externals() {
    let ext = IgpSource::Ospf {
        process: "1".to_string(),
        route_type: OspfRouteType::External2,
    };
    let int = IgpSource::Ospf {
        process: "1".to_string(),
        route_type: OspfRouteType::Internal,
    };
    let mut lab = Lab::default();
    lab.router("r1", Platform::Iosxe, 65001, "10.255.0.1");
    lab.proc("r1").redistributions = vec![redistribute(RedistSource::Ospf(Some("1".into())), None)];
    lab.input.igp_routes = vec![
        route("r1", "default", "10.1.0.0/24", int, 30),
        route("r1", "default", "10.2.0.0/24", ext, 20),
    ];
    let r = lab.run();
    assert_eq!(best(&r, "r1", "10.1.0.0/24").unwrap().best.med, Some(30));
    assert!(state(&r, "r1", "10.2.0.0/24").is_none());
    let mut types = BTreeSet::from([OspfRouteType::Internal, OspfRouteType::External2]);
    lab.proc("r1").redistributions[0].ospf_match = Some(types.clone());
    assert!(best(&lab.run(), "r1", "10.2.0.0/24").is_some());
    types.remove(&OspfRouteType::External2);
    lab.proc("r1").redistributions[0].ospf_match = None;
    lab.proc("r1").platform = Some(Platform::Iosxr);
    assert!(best(&lab.run(), "r1", "10.2.0.0/24").is_some());
    // Another OSPF process is not redistributed.
    lab.proc("r1").redistributions[0].source = RedistSource::Ospf(Some("2".into()));
    assert!(state(&lab.run(), "r1", "10.1.0.0/24").is_none());
}

#[test]
fn an_unknown_route_of_the_route_table_makes_its_redistributed_route_unknown() {
    let mut lab = Lab::default();
    lab.router("r1", Platform::Nxos, 65001, "10.255.0.1");
    lab.proc("r1").redistributions = vec![redistribute(RedistSource::Ospf(None), None)];
    let mut r = route("r1", "default", "10.3.0.0/24", OSPF, 10);
    r.unknown = Some("database gap".to_string());
    lab.input.igp_routes = vec![r];
    let out = lab.run();
    let Some(RouteState::Unknown(u)) = state(&out, "r1", "10.3.0.0/24") else {
        panic!("{:?}", out.routes);
    };
    assert_eq!(u.reason, Reason::RedistributedRouteNotKnown);
}

/// A process of a VRF of a leaf with the EVPN targets of the VNI
/// `rt_value`, its route distinguisher and its tunnel end.
fn tenant(device: &str, router_id: &str, rt_value: &str, tunnel_end: &str) -> BgpProcess {
    let mut p = BgpProcess::new(device, "A", Some(Platform::Nxos), Asn(65100), v4(router_id));
    p.targets.rd = Some(RouteDistinguisher(
        format!("{router_id}:3").parse().unwrap(),
    ));
    p.targets.evpn_export = BTreeSet::from([rt(rt_value)]);
    p.targets.evpn_import = BTreeSet::from([rt(rt_value)]);
    p.targets.advertise_evpn = true;
    p.targets.evpn_next_hop = Some(ip(tunnel_end));
    p.redistributions = vec![redistribute(RedistSource::Connected, None)];
    p
}

/// The EVPN fabric: the spine s1 reflects the EVPN routes of the leaves l1,
/// l2 and l3 of AS 65100. l1 and l2 import the target 65100:50001, and l3
/// imports 65100:99 only.
fn fabric() -> BgpInput {
    let mut input = BgpInput::default();
    let mut s1 = BgpProcess::new(
        "s1",
        "default",
        Some(Platform::Nxos),
        Asn(65100),
        v4("10.0.0.1"),
    );
    for (leaf, addr) in [
        ("l1", "10.0.0.11"),
        ("l2", "10.0.0.12"),
        ("l3", "10.0.0.13"),
    ] {
        let mut d = BgpProcess::new(leaf, "default", Some(Platform::Nxos), Asn(65100), v4(addr));
        let mut n = neighbor("10.0.0.1", 65100, addr);
        n.activated = BTreeSet::from([Family::EvpnIpPrefix]);
        d.neighbors.insert(ip("10.0.0.1"), n);
        let mut n = neighbor(addr, 65100, "10.0.0.1");
        n.activated = BTreeSet::from([Family::EvpnIpPrefix]);
        n.route_reflector_client = true;
        s1.neighbors.insert(ip(addr), n);
        input.processes.push(d);
        input.sessions.push(Session {
            a: SessionEnd {
                device: "s1".to_string(),
                vrf: "default".to_string(),
                neighbor: ip(addr),
            },
            b: SessionEnd {
                device: leaf.to_string(),
                vrf: "default".to_string(),
                neighbor: ip("10.0.0.1"),
            },
        });
    }
    input.processes.push(s1);
    input
        .processes
        .push(tenant("l1", "10.0.0.11", "65100:50001", "192.0.2.11"));
    input
        .processes
        .push(tenant("l2", "10.0.0.12", "65100:50001", "192.0.2.12"));
    let mut l3 = tenant("l3", "10.0.0.13", "65100:99", "192.0.2.13");
    l3.targets.evpn_export.clear();
    l3.targets.advertise_evpn = false;
    l3.redistributions.clear();
    input.processes.push(l3);
    input.igp_routes = vec![
        route("l1", "A", "10.1.1.0/24", IgpSource::Connected, 0),
        route("l2", "A", "10.1.2.0/24", IgpSource::Connected, 0),
    ];
    input
}

#[test]
fn a_vrf_imports_the_evpn_routes_of_its_target_with_the_tunnel_end_of_the_far_leaf() {
    let input = fabric();
    let view = View::default();
    let r = compute(&input, &view).unwrap();
    let s = selected(&r, "l2", "A", "10.1.1.0/24").expect("the route of l1 at l2");
    assert_eq!(
        s.best.leaked,
        Some(Box::new(Leaked {
            vrf: "default".to_string(),
            evpn: true
        }))
    );
    assert_eq!(s.best.next_hop, Some(ip("192.0.2.11")));
    assert_eq!(s.best.peer.kind, SessionKind::Ibgp);
    assert_eq!(s.best.peer.address, Some(ip("10.0.0.1")));
    assert!(
        s.best
            .ext_communities
            .contains(&ExtCommunity::RouteTarget(rt("65100:50001")))
    );
    // The EVPN route at the spine has the route distinguisher of the VRF of
    // l1.
    let rd = RouteDistinguisher("10.0.0.11:3".parse().unwrap());
    let evpn = RouteAt {
        device: "s1".to_string(),
        vrf: "default".to_string(),
        key: RouteKey::evpn_ip_prefix(rd, pfx("10.1.1.0/24")),
    };
    assert!(matches!(r.routes.get(&evpn), Some(RouteState::Selected(_))));
    // l1 holds its own route, and l3 imports no route of another target.
    let own = selected(&r, "l1", "A", "10.1.1.0/24").unwrap();
    assert_eq!(
        own.best.peer.kind,
        SessionKind::Local(LocalOrigin::Redistribute)
    );
    assert!(r.routes.get(&at("l3", "A", "10.1.1.0/24")).is_none());
    // The VRF installs the imported route through the tunnel end, with the
    // iBGP distance.
    let overlay = overlay_candidates(&r, &input.processes);
    let c = &overlay[&("l2".to_string(), "A".to_string())];
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].prefix, pfx("10.1.1.0/24"));
    assert_eq!(c[0].tunnel_ends, vec![ip("192.0.2.11")]);
    assert_eq!(c[0].distance, 200);
    let plain = install_candidates(&r, &input.processes);
    assert!(
        plain
            .get(&("l2".to_string(), "A".to_string()))
            .is_none_or(|v| v.iter().all(|c| c.prefix != pfx("10.1.1.0/24")))
    );
}

#[test]
fn the_tunnel_end_of_an_imported_route_resolves_in_the_default_vrf() {
    let input = fabric();
    let mut view = View::default();
    view.unknown
        .insert(("l2".to_string(), "A".to_string(), ip("192.0.2.11")));
    let r = compute(&input, &view).unwrap();
    assert!(selected(&r, "l2", "A", "10.1.1.0/24").is_some());
    let mut view = View::default();
    view.unknown
        .insert(("l2".to_string(), "default".to_string(), ip("192.0.2.11")));
    let r = compute(&input, &view).unwrap();
    let Some(RouteState::Unknown(u)) = r.routes.get(&at("l2", "A", "10.1.1.0/24")) else {
        panic!("{:?}", r.routes.get(&at("l2", "A", "10.1.1.0/24")));
    };
    assert_eq!(u.reason, Reason::NextHopNotResolved, "{u}");
}

#[test]
fn a_vrf_with_no_tunnel_end_gives_unknown_evpn_routes() {
    let mut input = fabric();
    for p in input.processes.iter_mut().filter(|p| p.device == "l1") {
        p.targets.evpn_next_hop = None;
    }
    let r = compute(&input, &View::default()).unwrap();
    let Some(RouteState::Unknown(u)) = r.routes.get(&at("l2", "A", "10.1.1.0/24")) else {
        panic!("{:?}", r.routes.get(&at("l2", "A", "10.1.1.0/24")));
    };
    assert_eq!(u.reason, Reason::TunnelEndNotKnown, "{u}");
}

#[test]
fn a_vrf_leak_by_route_target_copies_the_selection_with_weight_0_and_once() {
    let mut input = BgpInput::default();
    let mut a = BgpProcess::new("d1", "A", Some(Platform::Iosxe), Asn(65000), v4("10.0.0.1"));
    a.targets.export = BTreeSet::from([rt("65000:1")]);
    a.redistributions = vec![redistribute(RedistSource::Connected, None)];
    let mut b = BgpProcess::new("d1", "B", Some(Platform::Iosxe), Asn(65000), v4("10.0.0.1"));
    b.targets.import = BTreeSet::from([rt("65000:1")]);
    b.targets.export = BTreeSet::from([rt("65000:2")]);
    let mut c = BgpProcess::new("d1", "C", Some(Platform::Iosxe), Asn(65000), v4("10.0.0.1"));
    c.targets.import = BTreeSet::from([rt("65000:2")]);
    input.processes = vec![a, b, c];
    input.igp_routes = vec![route("d1", "A", "10.5.0.0/24", IgpSource::Connected, 0)];
    let r = compute(&input, &View::default()).unwrap();
    let s = selected(&r, "d1", "B", "10.5.0.0/24").expect("the leaked route");
    assert_eq!(s.best.weight, 0);
    assert_eq!(
        s.best.leaked,
        Some(Box::new(Leaked {
            vrf: "A".to_string(),
            evpn: false
        }))
    );
    assert!(
        s.best
            .ext_communities
            .contains(&ExtCommunity::RouteTarget(rt("65000:1")))
    );
    assert!(r.routes.get(&at("d1", "C", "10.5.0.0/24")).is_none());
    let inst = install_candidates(&r, &input.processes);
    let b = &inst[&("d1".to_string(), "B".to_string())][0];
    assert!(
        b.route
            .unknown_reason()
            .unwrap()
            .contains("next hop in vrf A not installed")
    );
}

/// The state of one round of the mutual redistribution: whether r1
/// redistributes P from BGP into OSPF, and whether r2 has the OSPF route of
/// P.
type Redist = (bool, bool);

/// One round. r1 has P from the eBGP peer 198.51.100.1 of AS 64999 and
/// redistributes its eBGP routes into OSPF. r2 has the OSPF route of P when
/// r1 redistributed P in the round before. r2 installs the OSPF route,
/// distance 110, over the iBGP route, distance 200, and redistributes its
/// OSPF routes into BGP through the route-map `R`, which denies each route
/// when `deny` is true.
fn redistribution_round(state: &Redist, deny: bool) -> Redist {
    let mut lab = Lab::default();
    lab.router("r1", Platform::Iosxe, 65000, "10.255.0.1");
    lab.router("r2", Platform::Iosxe, 65000, "10.255.0.2");
    lab.peer("r1", "10.0.0.1", "r2", "10.0.0.2");
    lab.seed(
        "r1",
        "198.51.100.1",
        64999,
        "203.0.113.0/24",
        &[64999],
        None,
    );
    let r2 = lab.proc("r2");
    r2.redistributions = vec![redistribute(RedistSource::Ospf(None), Some("R"))];
    r2.policy.policies.insert(
        "R".to_string(),
        RoutePolicy {
            name: "R".to_string(),
            body: PolicyBody::RouteMap(vec![Clause::new(10, !deny)]),
            spans: Vec::new(),
        },
    );
    if state.1 {
        lab.input.igp_routes = vec![route("r2", "default", "203.0.113.0/24", OSPF, 20)];
    }
    let r = lab.run();
    let r1_ebgp =
        best(&r, "r1", "203.0.113.0/24").is_some_and(|s| s.best.peer.kind == SessionKind::Ebgp);
    (r1_ebgp, r1_ebgp)
}

#[test]
fn a_mutual_redistribution_that_withdraws_its_own_source_is_a_cycle_of_the_rounds() {
    // The oracle: the local path of r2 has an empty AS path, so r1 prefers
    // it over the eBGP path and stops its redistribution, which withdraws
    // the OSPF route of r2.
    assert_eq!(redistribution_round(&(false, false), false), (true, true));
    assert_eq!(redistribution_round(&(true, true), false), (false, false));
    match rounds::run((false, false), |s, _| redistribution_round(s, false)) {
        Rounds::Cycle { first, states } => {
            assert_eq!(first, 0);
            assert_eq!(states, vec![(false, false), (true, true)]);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        rounds::run((false, false), |s, _| redistribution_round(s, true)),
        Rounds::Converged {
            state: (true, true),
            rounds: 2
        }
    );
}
