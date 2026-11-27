use super::*;
use rsim_core::{FunctionId, InterfaceId};
use rsim_functions::{RouteNextHop, RouteProtocol};

fn p(s: &str) -> Prefix {
    s.parse().unwrap()
}

fn hop(iface: &str, gw: &str) -> RouteNextHop {
    RouteNextHop {
        interface: InterfaceId::new(iface),
        gateway: Some(gw.parse().unwrap()),
        next: FunctionId::new("r1/nexthop"),
    }
}

fn span(file: &str) -> Vec<SourceSpan> {
    vec![SourceSpan::line(file, 1)]
}

const OSPF: RouteKind = RouteKind::Learned(RouteProtocol::Ospf);
const BGP: RouteKind = RouteKind::Learned(RouteProtocol::Bgp);

fn via(kind: RouteKind, iface: &str, gw: &str, file: &str) -> Route {
    Route::new(kind, vec![hop(iface, gw)], span(file))
}

fn fib(routes: &[(&str, Route)]) -> Fib {
    let mut t = Fib::new();
    for (prefix, r) in routes {
        t.insert(p(prefix), r.clone());
    }
    t
}

fn class(protocol: &str, class: Class) -> CollectedRoute {
    CollectedRoute {
        protocol: protocol.into(),
        class,
    }
}

fn layers() -> Vec<SourceSpan> {
    vec![Layer::link_down("r1:eth1").unwrap().span(1)]
}

/// The scenario table of the collected table `col`, the computed table of
/// the base `was` and the computed table of the scenario `now`, with the
/// interface `eth1` down.
fn run(
    col: &[(&str, Route)],
    routes: &[(&str, CollectedRoute)],
    was: &[(&str, Route)],
    now: &[(&str, Route)],
) -> Fib {
    let routes: BTreeMap<Prefix, CollectedRoute> =
        routes.iter().map(|(x, c)| (p(x), c.clone())).collect();
    let mut collected = fib(col);
    let computed = fib(was);
    let rows = rsim_guard::compare("default", &computed, &collected, &routes);
    rsim_guard::mark(&mut collected, &rows);
    let base = BaseVrf {
        computed,
        collected: collected.clone(),
        rows,
    };
    let down = BTreeSet::from(["eth1".to_string()]);
    forward(&collected, &routes, &base, &fib(now), &down, &layers())
}

fn files(r: &Route) -> Vec<String> {
    r.spans.iter().map(|s| s.file.to_string()).collect()
}

#[test]
fn a_prefix_whose_computed_route_does_not_change_keeps_its_collected_route() {
    let t = run(
        &[(
            "192.0.2.0/24",
            via(OSPF, "eth2", "198.51.100.2", "collected"),
        )],
        &[("192.0.2.0/24", class("ospf", Class::Compared))],
        &[("192.0.2.0/24", via(OSPF, "eth2", "198.51.100.2", "base"))],
        &[(
            "192.0.2.0/24",
            via(OSPF, "eth2", "198.51.100.2", "scenario"),
        )],
    );
    let r = t.get(&p("192.0.2.0/24")).unwrap();
    assert_eq!(files(&r), ["collected"]);
    assert_eq!(
        t.guard(&p("192.0.2.0/24")),
        Some(RibGuardFlag::MatchesCollected)
    );
}

#[test]
fn a_changed_prefix_with_a_matching_base_takes_the_route_of_the_scenario_with_the_layer() {
    let t = run(
        &[(
            "192.0.2.0/24",
            via(OSPF, "eth1", "198.51.100.1", "collected"),
        )],
        &[("192.0.2.0/24", class("ospf", Class::Compared))],
        &[("192.0.2.0/24", via(OSPF, "eth1", "198.51.100.1", "base"))],
        &[(
            "192.0.2.0/24",
            via(OSPF, "eth2", "198.51.100.2", "scenario"),
        )],
    );
    let r = t.get(&p("192.0.2.0/24")).unwrap();
    assert_eq!(r.next_hops(), [hop("eth2", "198.51.100.2")]);
    assert_eq!(files(&r), ["scenario", "layer 1: link-down r1:eth1"]);
}

#[test]
fn a_changed_prefix_whose_base_differs_from_the_collected_route_is_unknown() {
    let t = run(
        &[(
            "192.0.2.0/24",
            via(OSPF, "eth3", "198.51.100.3", "collected"),
        )],
        &[("192.0.2.0/24", class("ospf", Class::Compared))],
        &[("192.0.2.0/24", via(OSPF, "eth1", "198.51.100.1", "base"))],
        &[(
            "192.0.2.0/24",
            via(OSPF, "eth2", "198.51.100.2", "scenario"),
        )],
    );
    let r = t.get(&p("192.0.2.0/24")).unwrap();
    assert!(r.next_hops().is_empty());
    assert_eq!(r.unknown_reason(), Some(GUARD_MISMATCH));
    assert_eq!(files(&r), ["collected", "layer 1: link-down r1:eth1"]);
    assert_eq!(
        t.guard(&p("192.0.2.0/24")),
        Some(RibGuardFlag::DiffersFromCollected)
    );
}

#[test]
fn a_prefix_that_the_scenario_removes_is_removed_if_the_base_matches() {
    let t = run(
        &[
            (
                "198.51.100.0/30",
                Route::new(
                    RouteKind::Connected,
                    vec![RouteNextHop {
                        gateway: None,
                        ..hop("eth1", "198.51.100.1")
                    }],
                    span("collected"),
                ),
            ),
            (
                "192.0.2.0/24",
                via(OSPF, "eth1", "198.51.100.1", "collected"),
            ),
        ],
        &[
            ("198.51.100.0/30", class("direct", Class::Compared)),
            ("192.0.2.0/24", class("ospf", Class::Compared)),
        ],
        &[
            (
                "198.51.100.0/30",
                Route::new(
                    RouteKind::Connected,
                    vec![RouteNextHop {
                        gateway: None,
                        ..hop("eth1", "198.51.100.1")
                    }],
                    span("base"),
                ),
            ),
            ("192.0.2.0/24", via(OSPF, "eth1", "198.51.100.1", "base")),
        ],
        &[],
    );
    assert!(t.get(&p("198.51.100.0/30")).is_none());
    assert!(t.get(&p("192.0.2.0/24")).is_none());
    assert!(t.is_empty());
}

#[test]
fn a_prefix_that_only_the_scenario_computes_is_added() {
    let t = run(
        &[],
        &[],
        &[],
        &[(
            "203.0.113.0/24",
            via(OSPF, "eth2", "198.51.100.2", "scenario"),
        )],
    );
    let r = t.get(&p("203.0.113.0/24")).unwrap();
    assert_eq!(r.next_hops(), [hop("eth2", "198.51.100.2")]);
}

#[test]
fn a_collected_route_that_is_not_computed_is_unknown_and_a_seeded_route_stays() {
    let t = run(
        &[
            (
                "203.0.113.0/24",
                via(BGP, "eth2", "198.51.100.2", "collected"),
            ),
            (
                "0.0.0.0/0",
                via(RouteKind::Static, "eth2", "198.51.100.9", "collected"),
            ),
        ],
        &[
            (
                "203.0.113.0/24",
                class("bgp", Class::NotComputed("bgp not computed".into())),
            ),
            ("0.0.0.0/0", class("static", Class::Seeded)),
        ],
        &[
            (
                "203.0.113.0/24",
                Route::unknown(BGP, "bgp not computed", span("base")),
            ),
            (
                "0.0.0.0/0",
                via(RouteKind::Static, "eth2", "198.51.100.9", "base"),
            ),
        ],
        &[
            (
                "203.0.113.0/24",
                Route::unknown(BGP, "bgp not computed", span("scenario")),
            ),
            (
                "0.0.0.0/0",
                via(RouteKind::Static, "eth2", "198.51.100.9", "scenario"),
            ),
        ],
    );
    let bgp = t.get(&p("203.0.113.0/24")).unwrap();
    assert_eq!(bgp.kind, BGP);
    assert_eq!(bgp.unknown_reason(), Some(NOT_RECOMPUTED));
    assert_eq!(files(&bgp), ["collected", "layer 1: link-down r1:eth1"]);
    let seeded = t.get(&p("0.0.0.0/0")).unwrap();
    assert_eq!(seeded.next_hops(), [hop("eth2", "198.51.100.9")]);
    assert_eq!(files(&seeded), ["collected"]);
}

#[test]
fn a_kept_route_through_a_down_interface_is_unknown() {
    let t = run(
        &[(
            "192.0.2.0/24",
            via(RouteKind::Static, "eth1.10", "198.51.100.1", "collected"),
        )],
        &[("192.0.2.0/24", class("static", Class::Seeded))],
        &[(
            "192.0.2.0/24",
            via(RouteKind::Static, "eth1.10", "198.51.100.1", "base"),
        )],
        &[],
    );
    let r = t.get(&p("192.0.2.0/24")).unwrap();
    assert_eq!(r.unknown_reason(), Some(GUARD_MISMATCH));
}

#[test]
fn an_unknown_computed_route_of_the_base_is_not_a_match() {
    let t = run(
        &[(
            "192.0.2.0/24",
            via(RouteKind::Static, "eth2", "198.51.100.2", "collected"),
        )],
        &[("192.0.2.0/24", class("static", Class::Compared))],
        &[(
            "192.0.2.0/24",
            Route::unknown(RouteKind::Static, "next hop not resolved", span("base")),
        )],
        &[(
            "192.0.2.0/24",
            Route::unknown(RouteKind::Static, "next hop not resolved", span("scenario")),
        )],
    );
    let r = t.get(&p("192.0.2.0/24")).unwrap();
    assert_eq!(r.unknown_reason(), Some(GUARD_MISMATCH));
}

#[test]
fn the_fallback_makes_each_learned_route_unknown_and_keeps_the_others_that_are_up() {
    let t = fib(&[
        (
            "192.0.2.0/24",
            via(OSPF, "eth2", "198.51.100.2", "collected"),
        ),
        (
            "198.51.100.0/24",
            via(RouteKind::Static, "eth1", "198.51.100.1", "collected"),
        ),
        (
            "203.0.113.0/24",
            via(RouteKind::Static, "eth2", "198.51.100.2", "collected"),
        ),
    ]);
    let down = BTreeSet::from(["eth1".to_string()]);
    let out = fallback(&t, &down, &layers());
    let reason = |x: &str| out.get(&p(x)).unwrap().unknown_reason().map(str::to_string);
    assert_eq!(reason("192.0.2.0/24").as_deref(), Some(NOT_RECOMPUTED));
    assert_eq!(reason("198.51.100.0/24").as_deref(), Some(GUARD_MISMATCH));
    assert_eq!(reason("203.0.113.0/24"), None);
}

#[test]
fn a_layer_reads_back_from_its_text() {
    let l = Layer::link_down("core1:Ethernet1/1").unwrap();
    assert_eq!(l.text(), "link-down core1:Ethernet1/1");
    assert_eq!(Layer::parse(&l.text()), Ok(l.clone()));
    assert_eq!(&*l.span(2).file, "layer 2: link-down core1:Ethernet1/1");
    for bad in ["core1", ":eth1", "core1:", "core 1:eth1", ""] {
        assert!(Layer::link_down(bad).is_err(), "{bad:?}");
    }
    for bad in ["link-up r1:eth1", "link-down", "r1:eth1"] {
        assert!(Layer::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_sub_interface_of_a_down_interface_is_down() {
    let down = BTreeSet::from(["eth1".to_string()]);
    assert!(is_down(&down, "eth1"));
    assert!(is_down(&down, "eth1.10"));
    assert!(!is_down(&down, "eth10"));
    assert!(!is_down(&down, "eth2.1"));
}
