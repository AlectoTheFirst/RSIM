use super::*;
use rsim_core::{FunctionId, InterfaceId};
use rsim_functions::RouteNextHop;

fn hop(i: &str, gw: Option<&str>) -> RouteNextHop {
    RouteNextHop {
        interface: InterfaceId::new(i),
        gateway: gw.map(|g| g.parse().unwrap()),
        next: FunctionId::new("r/next"),
    }
}

fn p(s: &str) -> Prefix {
    s.parse().unwrap()
}

fn route(kind: RouteKind, hops: Vec<RouteNextHop>, line: u32) -> Route {
    Route::new(kind, hops, vec![SourceSpan::new("r/config", line, line)])
}

fn compared(word: &str) -> CollectedRoute {
    CollectedRoute {
        protocol: word.into(),
        class: Class::Compared,
    }
}

#[test]
fn each_route_gets_one_category_and_the_rate_leaves_out_the_routes_that_are_not_computed() {
    let computed: Fib = [
        (
            p("192.0.2.0/24"),
            route(RouteKind::Connected, vec![hop("eth0", None)], 1),
        ),
        (
            p("198.51.100.0/24"),
            route(RouteKind::Static, vec![hop("eth0", Some("192.0.2.9"))], 2),
        ),
        (
            p("203.0.113.0/24"),
            route(RouteKind::Static, vec![hop("eth1", None)], 3),
        ),
    ]
    .into_iter()
    .collect();
    let collected: Fib = [
        (
            p("192.0.2.0/24"),
            route(RouteKind::Connected, vec![hop("eth0", None)], 10),
        ),
        (
            p("198.51.100.0/24"),
            route(RouteKind::Static, vec![hop("eth0", Some("192.0.2.8"))], 11),
        ),
        (
            p("0.0.0.0/0"),
            route(RouteKind::Static, vec![hop("eth0", Some("192.0.2.1"))], 12),
        ),
        (
            p("10.0.0.0/8"),
            route(
                RouteKind::Learned(rsim_functions::RouteProtocol::Bgp),
                vec![hop("eth0", Some("192.0.2.1"))],
                13,
            ),
        ),
    ]
    .into_iter()
    .collect();
    let routes = BTreeMap::from([
        (p("192.0.2.0/24"), compared("connected")),
        (p("198.51.100.0/24"), compared("static")),
        (p("0.0.0.0/0"), compared("static")),
        (
            p("10.0.0.0/8"),
            CollectedRoute {
                protocol: "bgp".into(),
                class: Class::NotComputed("bgp not computed".into()),
            },
        ),
    ]);
    let rows = compare("default", &computed, &collected, &routes);
    let got: Vec<(String, Category, Vec<&str>)> = rows
        .iter()
        .map(|r| (r.prefix.to_string(), r.category, r.fields.clone()))
        .collect();
    assert_eq!(
        got,
        [
            ("0.0.0.0/0".to_string(), Category::OnlyCollected, vec![]),
            ("10.0.0.0/8".to_string(), Category::NotComputed, vec![]),
            ("192.0.2.0/24".to_string(), Category::Match, vec![]),
            (
                "198.51.100.0/24".to_string(),
                Category::Differ,
                vec!["next_hops"]
            ),
            ("203.0.113.0/24".to_string(), Category::OnlyComputed, vec![]),
        ]
    );
    let c = Counts::of(&rows);
    assert_eq!(c.compared(), 4);
    assert_eq!(c.not_computed, 1);
    assert_eq!(c.rate(), Some(25.0));
    assert_eq!(
        rows[3].collected.as_ref().unwrap().next_hops,
        ["192.0.2.8@eth0"]
    );
}

#[test]
fn the_mark_flags_the_matching_and_the_differing_collected_routes() {
    let mut fib: Fib = [
        (
            p("192.0.2.0/24"),
            route(RouteKind::Connected, vec![hop("eth0", None)], 1),
        ),
        (
            p("0.0.0.0/0"),
            route(RouteKind::Static, vec![hop("eth0", Some("192.0.2.1"))], 2),
        ),
        (
            p("10.0.0.0/8"),
            route(RouteKind::Static, vec![hop("eth0", Some("192.0.2.1"))], 3),
        ),
    ]
    .into_iter()
    .collect();
    let computed: Fib = [(
        p("192.0.2.0/24"),
        route(RouteKind::Connected, vec![hop("eth0", None)], 1),
    )]
    .into_iter()
    .collect();
    let routes = BTreeMap::from([
        (p("192.0.2.0/24"), compared("connected")),
        (p("0.0.0.0/0"), compared("static")),
        (
            p("10.0.0.0/8"),
            CollectedRoute {
                protocol: "kernel".into(),
                class: Class::NotComputed("kernel route".into()),
            },
        ),
    ]);
    let rows = compare("default", &computed, &fib, &routes);
    mark(&mut fib, &rows);
    assert_eq!(
        fib.guard(&p("192.0.2.0/24")),
        Some(RibGuardFlag::MatchesCollected)
    );
    assert_eq!(
        fib.guard(&p("0.0.0.0/0")),
        Some(RibGuardFlag::DiffersFromCollected)
    );
    assert_eq!(fib.guard(&p("10.0.0.0/8")), Some(RibGuardFlag::NotChecked));
}

#[test]
fn an_unknown_collected_route_is_not_computed_and_no_compared_row_gives_no_rate() {
    let computed = Fib::new();
    let collected: Fib = [(
        p("0.0.0.0/0"),
        Route::unknown(
            RouteKind::Static,
            "next hop not resolved: 192.0.2.1",
            Vec::new(),
        ),
    )]
    .into_iter()
    .collect();
    let routes = BTreeMap::from([(p("0.0.0.0/0"), compared("static"))]);
    let rows = compare("default", &computed, &collected, &routes);
    assert_eq!(rows[0].category, Category::NotComputed);
    assert_eq!(
        rows[0].reason,
        "collected route unknown: next hop not resolved: 192.0.2.1"
    );
    assert_eq!(Counts::of(&rows).rate(), None);
}

#[test]
fn the_loopback_and_link_local_prefixes_are_left_out() {
    let computed: Fib = [
        (
            p("127.0.0.0/8"),
            route(RouteKind::Connected, vec![hop("lo", None)], 1),
        ),
        (
            p("fe80::/64"),
            route(RouteKind::Connected, vec![hop("eth0", None)], 2),
        ),
        (
            p("2001:db8::/64"),
            route(RouteKind::Connected, vec![hop("eth0", None)], 3),
        ),
    ]
    .into_iter()
    .collect();
    let rows = compare("default", &computed, &Fib::new(), &BTreeMap::new());
    let got: Vec<String> = rows.iter().map(|r| r.prefix.to_string()).collect();
    assert_eq!(got, ["2001:db8::/64"]);
}
