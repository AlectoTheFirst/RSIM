//! The OSPF calculation over hand-built link-state databases. The OSPFv2
//! cases are the cases of HST `tests/test_simul_ospf.py` with documentation
//! addresses. The expected outputs are hand-built and are not confirmed
//! against a device.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rsim_core::{Prefix, SourceSpan};
use rsim_routing::Platform;
use rsim_routing::ospf::{
    AreaType, Body, Calculation, Database, GapReach, Interface, LinkKind, Lsa, LsaType,
    OspfProfile, PathType, Reference, RouterLink, Version, compute,
};

const AREA_0: &str = "0.0.0.0";
const AREA_1: &str = "0.0.0.1";
const ZERO: &str = "0.0.0.0";
const R1: &str = "198.51.100.1";
const R2: &str = "198.51.100.2";
const R3: &str = "198.51.100.3";
const R4: &str = "198.51.100.4";
const ASBR: &str = "198.51.100.9";
const MASK_26: &str = "255.255.255.192";
const MASK_27: &str = "255.255.255.224";
const MASK_30: &str = "255.255.255.252";
const MASK_32: &str = "255.255.255.255";

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn pfx(s: &str) -> Prefix {
    s.parse().unwrap()
}

fn lsa(lsa_type: LsaType, lsid: &str, adv: &str, area: Option<&str>, body: Body) -> Lsa {
    Lsa {
        lsa_type,
        area: area.map(ip),
        lsid: ip(lsid),
        adv_router: ip(adv),
        seq: Some(0x8000_0001),
        age: Some(100),
        body,
        span: SourceSpan::line("lsdb", 1),
    }
}

fn link(kind: LinkKind, id: &str, data: &str, metric: u32) -> RouterLink {
    RouterLink {
        kind,
        id: ip(id),
        data: Some(ip(data)),
        metric,
        interface_id: None,
        neighbor_interface_id: None,
    }
}

fn p2p(neighbor: &str, own: &str, metric: u32) -> RouterLink {
    link(LinkKind::PointToPoint, neighbor, own, metric)
}

fn stub(network: &str, mask: &str, metric: u32) -> RouterLink {
    link(LinkKind::Stub, network, mask, metric)
}

fn transit(dr: &str, own: &str, metric: u32) -> RouterLink {
    link(LinkKind::Transit, dr, own, metric)
}

fn router(rid: &str, links: Vec<RouterLink>, area: &str) -> Lsa {
    lsa(
        LsaType::Router,
        rid,
        rid,
        Some(area),
        Body::Router { links },
    )
}

fn network(dr: &str, dr_rid: &str, mask: &str, attached: &[&str], area: &str) -> Lsa {
    lsa(
        LsaType::Network,
        dr,
        dr_rid,
        Some(area),
        Body::Network {
            mask: Some(ip(mask)),
            attached: attached.iter().map(|a| ip(a)).collect(),
        },
    )
}

fn summary(prefix: &str, metric: u32, adv: &str, area: &str) -> Lsa {
    let p = pfx(prefix);
    let IpAddr::V4(id) = p.addr() else {
        unreachable!()
    };
    lsa(
        LsaType::Summary,
        &id.to_string(),
        adv,
        Some(area),
        Body::Summary { prefix: p, metric },
    )
}

fn asbr_summary(asbr: &str, metric: u32, adv: &str, area: &str) -> Lsa {
    lsa(
        LsaType::AsbrSummary,
        asbr,
        adv,
        Some(area),
        Body::AsbrSummary {
            router: ip(asbr),
            metric,
        },
    )
}

fn external(prefix: &str, metric: u32, adv: &str, metric_type: u8, fa: Option<&str>) -> Lsa {
    let p = pfx(prefix);
    let IpAddr::V4(id) = p.addr() else {
        unreachable!()
    };
    lsa(
        LsaType::External,
        &id.to_string(),
        adv,
        None,
        Body::External {
            prefix: p,
            metric,
            metric_type: Some(metric_type),
            forwarding: fa.map(|a| IpAddr::V4(ip(a))),
        },
    )
}

fn nssa(prefix: &str, metric: u32, adv: &str, fa: Option<&str>, area: &str) -> Lsa {
    Lsa {
        lsa_type: LsaType::NssaExternal,
        area: Some(ip(area)),
        ..external(prefix, metric, adv, 2, fa)
    }
}

/// The database of the LSAs, with the span of each LSA at its place.
fn db(lsas: Vec<Lsa>) -> Database {
    let mut d = Database::new(Version::V2, "default", "1");
    for (i, mut l) in lsas.into_iter().enumerate() {
        l.span = SourceSpan::line("lsdb", i as u32 + 1);
        d.insert(l);
    }
    d
}

fn run(d: &Database, root: &str, platform: Platform) -> Calculation {
    compute(d, ip(root), &OspfProfile::of(platform))
}

fn calc(lsas: Vec<Lsa>, root: &str) -> Calculation {
    run(&db(lsas), root, Platform::Nxos)
}

/// Each route as its prefix, path type, metric and gateways.
fn rows(c: &Calculation) -> Vec<(String, &'static str, u32, Vec<String>)> {
    c.routes
        .iter()
        .map(|r| {
            (
                r.prefix.to_string(),
                r.path_type.name(),
                r.metric,
                r.next_hops.iter().map(|h| h.gateway.to_string()).collect(),
            )
        })
        .collect()
}

fn row(
    prefix: &str,
    path: &'static str,
    metric: u32,
    hops: &[&str],
) -> (String, &'static str, u32, Vec<String>) {
    (
        prefix.to_string(),
        path,
        metric,
        hops.iter().map(|h| h.to_string()).collect(),
    )
}

fn route<'c>(c: &'c Calculation, prefix: &str) -> &'c rsim_routing::ospf::Route {
    c.route(pfx(prefix))
        .unwrap_or_else(|| panic!("no route of {prefix}"))
}

fn gateways(c: &Calculation, prefix: &str) -> Vec<String> {
    route(c, prefix)
        .next_hops
        .iter()
        .map(|h| h.gateway.to_string())
        .collect()
}

/// R1 has point-to-point links to R2 and R3, and R2 and R3 share a LAN on
/// which R3 is the designated router. R3 has a stub LAN.
fn single_area() -> Vec<Lsa> {
    vec![
        router(
            R1,
            vec![
                p2p(R2, "192.0.2.1", 10),
                stub("192.0.2.0", MASK_30, 10),
                p2p(R3, "192.0.2.5", 20),
                stub("192.0.2.4", MASK_30, 20),
                stub(R1, MASK_32, 1),
            ],
            AREA_0,
        ),
        router(
            R2,
            vec![
                p2p(R1, "192.0.2.2", 10),
                stub("192.0.2.0", MASK_30, 10),
                transit("192.0.2.67", "192.0.2.66", 10),
                stub(R2, MASK_32, 1),
            ],
            AREA_0,
        ),
        router(
            R3,
            vec![
                p2p(R1, "192.0.2.6", 20),
                stub("192.0.2.4", MASK_30, 20),
                transit("192.0.2.67", "192.0.2.67", 10),
                stub(R3, MASK_32, 1),
                stub("198.51.100.128", MASK_26, 5),
            ],
            AREA_0,
        ),
        network("192.0.2.67", R3, MASK_26, &[R2, R3], AREA_0),
    ]
}

#[test]
fn a_single_area_gives_the_intra_area_routes() {
    let c = calc(single_area(), R1);
    assert!(c.notes.is_empty(), "{:?}", c.notes);
    assert!(c.gaps.is_empty());
    assert!(!c.area_border_router);
    assert_eq!(
        rows(&c),
        [
            row("192.0.2.64/26", "intra-area", 20, &["192.0.2.2"]),
            row("198.51.100.2/32", "intra-area", 11, &["192.0.2.2"]),
            row(
                "198.51.100.3/32",
                "intra-area",
                21,
                &["192.0.2.2", "192.0.2.6"]
            ),
            row(
                "198.51.100.128/26",
                "intra-area",
                25,
                &["192.0.2.2", "192.0.2.6"]
            ),
        ]
    );
    assert_eq!(
        c.router_costs.into_iter().collect::<Vec<_>>(),
        [((ip(AREA_0), ip(R2)), 10), ((ip(AREA_0), ip(R3)), 20)]
    );
    assert!(c.routes.iter().all(|r| r.unknown.is_none()));
}

#[test]
fn the_subnets_of_the_calculating_router_are_not_ospf_routes() {
    let c = calc(single_area(), R1);
    for own in ["192.0.2.0/30", "192.0.2.4/30", "198.51.100.1/32"] {
        assert!(c.route(pfx(own)).is_none(), "{own}");
    }
}

#[test]
fn a_route_keeps_the_spans_of_its_lsas_and_the_interface_of_its_next_hop() {
    let mut d = db(single_area());
    for (name, addr) in [("Ethernet1/1", "192.0.2.1"), ("Ethernet1/2", "192.0.2.5")] {
        d.interfaces.push(Interface {
            name: name.into(),
            area: Some(ip(AREA_0)),
            address: Some((IpAddr::V4(ip(addr)), Some(30))),
            interface_id: None,
            cost: None,
            span: SourceSpan::line("interfaces", 1),
        });
    }
    let c = run(&d, R1, Platform::Nxos);
    let r = route(&c, "198.51.100.3/32");
    let hops: Vec<String> = r.next_hops.iter().map(ToString::to_string).collect();
    assert_eq!(
        hops,
        ["192.0.2.2 on Ethernet1/1", "192.0.2.6 on Ethernet1/2"]
    );
    assert_eq!(r.spans, [SourceSpan::line("lsdb", 3)]);
    assert_eq!(
        route(&c, "192.0.2.64/26").spans,
        [SourceSpan::line("lsdb", 4)]
    );
}

/// R1 reaches the LAN of R1 and R3 at cost 10 on its own link and through
/// R2. R3 has the next hops of both paths, and the LAN is not a route.
#[test]
fn a_network_at_equal_cost_on_the_own_link_and_through_a_router_keeps_both_next_hops() {
    let c = calc(
        vec![
            router(
                R1,
                vec![
                    p2p(R2, "192.0.2.1", 5),
                    transit("192.0.2.67", "192.0.2.65", 10),
                ],
                AREA_0,
            ),
            router(
                R2,
                vec![
                    p2p(R1, "192.0.2.2", 5),
                    transit("192.0.2.67", "192.0.2.66", 5),
                ],
                AREA_0,
            ),
            router(
                R3,
                vec![transit("192.0.2.67", "192.0.2.67", 5), stub(R3, MASK_32, 1)],
                AREA_0,
            ),
            network("192.0.2.67", R3, MASK_26, &[R1, R2, R3], AREA_0),
        ],
        R1,
    );
    assert_eq!(
        rows(&c),
        [row(
            "198.51.100.3/32",
            "intra-area",
            11,
            &["192.0.2.2", "192.0.2.67"]
        )]
    );
}

/// R2 is the area border router: it has a second router LSA in area 1,
/// where R4 is, and originates summary LSAs into both areas.
fn two_areas() -> Vec<Lsa> {
    let mut out = single_area();
    out.extend([
        router(
            R2,
            vec![
                p2p(R4, "192.0.2.9", 10),
                stub("192.0.2.8", MASK_30, 10),
                stub("192.0.2.32", MASK_27, 10),
            ],
            AREA_1,
        ),
        router(
            R4,
            vec![
                p2p(R2, "192.0.2.10", 10),
                stub("192.0.2.8", MASK_30, 10),
                stub(R4, MASK_32, 1),
            ],
            AREA_1,
        ),
        summary("192.0.2.32/27", 10, R2, AREA_0),
        summary("192.0.2.8/30", 10, R2, AREA_0),
        summary("198.51.100.4/32", 11, R2, AREA_0),
        summary("198.51.100.128/26", 1, R2, AREA_0),
        summary("198.51.100.1/32", 11, R2, AREA_1),
        summary("192.0.2.64/26", 10, R2, AREA_1),
        summary("198.51.100.192/27", 5, R4, AREA_1),
    ]);
    out
}

#[test]
fn two_areas_give_inter_area_routes_with_summed_metrics() {
    let c = calc(two_areas(), R1);
    assert!(c.notes.is_empty() && c.gaps.is_empty());
    let r = route(&c, "192.0.2.32/27");
    assert_eq!((r.path_type, r.metric), (PathType::InterArea, 20));
    assert_eq!(gateways(&c, "192.0.2.32/27"), ["192.0.2.2"]);
    assert_eq!(r.advertising_router, Some(ip(R2)));
    assert_eq!(route(&c, "192.0.2.8/30").metric, 20);
    assert_eq!(route(&c, "198.51.100.4/32").metric, 21);
    let lan = route(&c, "198.51.100.128/26");
    assert_eq!(
        (lan.path_type, lan.metric),
        (PathType::IntraArea, 25),
        "an intra-area path ranks before an inter-area path"
    );
    assert!(
        c.route(pfx("198.51.100.192/27")).is_none(),
        "R1 is only in the backbone and does not read the summaries of area 1"
    );
}

#[test]
fn the_border_router_reads_only_the_summaries_of_the_backbone() {
    let c = calc(two_areas(), R2);
    assert!(c.notes.is_empty());
    assert!(c.area_border_router);
    assert!(c.route(pfx("198.51.100.192/27")).is_none());
    assert_eq!(route(&c, "198.51.100.1/32").metric, 11);
    assert_eq!(gateways(&c, "198.51.100.1/32"), ["192.0.2.1"]);
    assert_eq!(route(&c, "198.51.100.4/32").area, Some(ip(AREA_1)));
    assert_eq!(gateways(&c, "198.51.100.4/32"), ["192.0.2.10"]);
    assert_eq!(route(&c, "192.0.2.4/30").metric, 30);
    assert_eq!(
        gateways(&c, "192.0.2.4/30"),
        ["192.0.2.1", "192.0.2.67"],
        "2 equal-cost paths at 30"
    );
}

#[test]
fn the_default_route_of_a_stub_area_comes_from_the_summary_of_the_border_router() {
    let mut d = db(vec![
        router(
            R4,
            vec![
                p2p(R2, "192.0.2.10", 10),
                stub("192.0.2.8", MASK_30, 10),
                stub(R4, MASK_32, 1),
            ],
            AREA_1,
        ),
        router(
            R2,
            vec![p2p(R4, "192.0.2.9", 10), stub("192.0.2.8", MASK_30, 10)],
            AREA_1,
        ),
        summary("0.0.0.0/0", 1, R2, AREA_1),
        summary("198.51.100.1/32", 11, R2, AREA_1),
    ]);
    d.area_types.insert(ip(AREA_1), AreaType::Stub);
    let c = run(&d, R4, Platform::Nxos);
    assert!(c.notes.is_empty());
    assert_eq!(
        rows(&c),
        [
            row("0.0.0.0/0", "inter-area", 11, &["192.0.2.9"]),
            row("198.51.100.1/32", "inter-area", 21, &["192.0.2.9"]),
        ]
    );
}

#[test]
fn a_type_1_external_ranks_before_a_type_2_external_at_any_cost() {
    let mut lsas = single_area();
    lsas.push(external("203.0.113.0/26", 20, R3, 2, None));
    lsas.push(external("203.0.113.0/26", 100, R2, 1, None));
    let c = calc(lsas, R1);
    let r = route(&c, "203.0.113.0/26");
    assert_eq!(
        (r.path_type, r.metric, r.forward_metric),
        (PathType::External1, 110, Some(10))
    );
    assert_eq!(r.advertising_router, Some(ip(R2)));
    assert_eq!(gateways(&c, "203.0.113.0/26"), ["192.0.2.2"]);
}

#[test]
fn type_2_externals_tie_on_the_lsa_metric_and_break_on_the_forward_metric() {
    let mut lsas = single_area();
    lsas.push(external("203.0.113.0/26", 20, R3, 2, None));
    lsas.push(external("203.0.113.0/26", 20, R2, 2, None));
    let c = calc(lsas.clone(), R1);
    let r = route(&c, "203.0.113.0/26");
    assert_eq!(
        (r.path_type, r.metric, r.forward_metric),
        (PathType::External2, 20, Some(10))
    );
    assert_eq!(r.advertising_router, Some(ip(R2)));

    let last = lsas.len() - 1;
    lsas[last] = external("203.0.113.0/26", 30, R2, 2, None);
    let c = calc(lsas, R1);
    let r = route(&c, "203.0.113.0/26");
    assert_eq!(
        (r.metric, r.forward_metric, r.advertising_router),
        (20, Some(20), Some(ip(R3)))
    );
    assert_eq!(
        gateways(&c, "203.0.113.0/26"),
        ["192.0.2.2", "192.0.2.6"],
        "the path to R3 is the equal-cost pair"
    );
}

#[test]
fn a_forwarding_address_resolves_through_the_computed_routes() {
    let mut lsas = single_area();
    lsas.push(external(
        "203.0.113.64/26",
        20,
        R2,
        2,
        Some("198.51.100.138"),
    ));
    lsas.push(external("203.0.113.128/26", 20, R3, 2, Some("192.0.2.2")));
    lsas.push(external(
        "203.0.113.192/26",
        20,
        R2,
        2,
        Some("198.51.100.250"),
    ));
    let c = calc(lsas, R1);
    let lan = route(&c, "203.0.113.64/26");
    assert_eq!((lan.metric, lan.forward_metric), (20, Some(25)));
    assert_eq!(gateways(&c, "203.0.113.64/26"), ["192.0.2.2", "192.0.2.6"]);
    let on_link = route(&c, "203.0.113.128/26");
    assert_eq!(on_link.forward_metric, Some(10));
    assert_eq!(gateways(&c, "203.0.113.128/26"), ["192.0.2.2"]);
    assert!(
        c.route(pfx("203.0.113.192/26")).is_none(),
        "no intra-area or inter-area route covers the forwarding address"
    );
    assert!(c.gaps.is_empty());
    assert!(c.absent_gap(pfx("203.0.113.192/26")).is_none());
}

#[test]
fn a_gap_that_can_give_the_route_of_a_forwarding_address_makes_the_external_route_unknown() {
    let mut lsas = single_area();
    lsas.extend([
        summary("198.51.100.160/27", 5, "198.51.100.8", AREA_0),
        summary("198.51.100.192/27", 5, "198.51.100.8", AREA_0),
        summary("198.51.100.224/27", 5, "198.51.100.8", AREA_0),
        summary("198.51.100.224/27", 5, R2, AREA_0),
        external("203.0.113.0/26", 20, R2, 2, Some("198.51.100.138")),
        external("203.0.113.64/26", 20, R2, 2, Some("198.51.100.170")),
        external("203.0.113.128/26", 20, R2, 2, Some("198.51.100.200")),
        external("203.0.113.192/26", 20, R2, 2, Some("198.51.100.230")),
    ]);
    let c = calc(lsas, R1);
    assert_eq!(c.gaps.len(), 1);
    assert_eq!(
        c.gaps[0].reach,
        GapReach::Prefixes(
            [
                "198.51.100.160/27",
                "198.51.100.192/27",
                "198.51.100.224/27",
                "203.0.113.64/26",
                "203.0.113.128/26",
                "203.0.113.192/26",
            ]
            .map(pfx)
            .to_vec()
        )
    );
    assert!(
        route(&c, "203.0.113.0/26").unknown.is_none(),
        "the gap has no prefix that holds the forwarding address"
    );
    assert!(
        route(&c, "203.0.113.64/26").unknown.is_some(),
        "the gap has a longer prefix than the intra-area route of the forwarding address"
    );
    assert!(c.route(pfx("203.0.113.128/26")).is_none());
    assert!(
        c.absent_gap(pfx("203.0.113.128/26")).is_some(),
        "only the gap has a prefix that holds the forwarding address"
    );
    assert_eq!(
        route(&c, "198.51.100.224/27").path_type,
        PathType::InterArea
    );
    assert!(
        route(&c, "203.0.113.192/26").unknown.is_some(),
        "the gap has the prefix of the inter-area route of the forwarding address"
    );
}

#[test]
fn an_unreachable_asbr_with_a_router_lsa_is_ignored_and_is_not_a_gap() {
    let mut lsas = single_area();
    lsas.extend([
        router(ASBR, vec![p2p(R2, "192.0.2.13", 1)], AREA_0),
        external("203.0.113.0/26", 1, ASBR, 2, None),
        external("203.0.113.0/26", 30, R3, 2, None),
        external("203.0.113.64/26", 1, ASBR, 2, None),
    ]);
    let c = calc(lsas, R1);
    assert!(c.gaps.is_empty());
    let r = route(&c, "203.0.113.0/26");
    assert_eq!(
        (r.metric, r.advertising_router, r.unknown.is_none()),
        (30, Some(ip(R3)), true)
    );
    assert!(c.route(pfx("203.0.113.64/26")).is_none());
    assert!(c.absent_gap(pfx("203.0.113.64/26")).is_none());
}

#[test]
fn a_virtual_link_of_the_calculating_router_is_a_gap_of_the_backbone() {
    let c = calc(
        vec![
            router(
                R1,
                vec![
                    link(LinkKind::Virtual, R2, "192.0.2.1", 20),
                    stub(R1, MASK_32, 1),
                ],
                AREA_0,
            ),
            router(
                R2,
                vec![
                    link(LinkKind::Virtual, R1, "192.0.2.2", 20),
                    stub("198.51.100.128", MASK_26, 1),
                ],
                AREA_0,
            ),
            router(
                R1,
                vec![p2p(R2, "192.0.2.1", 10), stub("192.0.2.0", MASK_30, 10)],
                AREA_1,
            ),
            router(
                R2,
                vec![
                    p2p(R1, "192.0.2.2", 10),
                    stub("192.0.2.0", MASK_30, 10),
                    stub(R2, MASK_32, 1),
                    stub("192.0.2.32", MASK_27, 15),
                ],
                AREA_1,
            ),
            summary("203.0.113.0/26", 5, R2, AREA_1),
        ],
        R1,
    );
    assert_eq!(c.gaps.len(), 1);
    let g = &c.gaps[0];
    assert_eq!(
        (g.lsa_type, g.lsid, g.area, &g.reach),
        (
            LsaType::Router,
            ip(R1),
            Some(ip(AREA_0)),
            &GapReach::FromCost(20)
        )
    );
    assert_eq!(
        g.detail,
        format!("router LSA {R1} in area {AREA_0}, the virtual link to {R2} is not computed")
    );
    assert!(
        c.notes
            .iter()
            .any(|n| n.kind == "ospf-virtual-link-not-modeled")
    );
    let got: Vec<(String, bool)> = c
        .routes
        .iter()
        .map(|r| (r.prefix.to_string(), r.unknown.is_some()))
        .collect();
    assert_eq!(
        got,
        [
            ("192.0.2.32/27".to_string(), true),
            ("198.51.100.2/32".to_string(), false),
            ("203.0.113.0/26".to_string(), true),
        ]
    );
    assert!(c.absent_gap(pfx("198.51.100.128/26")).is_some());
}

#[test]
fn rfc_1583_compatibility_selects_the_path_to_the_asbr() {
    let mut lsas: Vec<Lsa> = two_areas()
        .into_iter()
        .filter(|l| {
            !(l.lsa_type == LsaType::Router && l.lsid == ip(R2) && l.area == Some(ip(AREA_1)))
        })
        .collect();
    lsas.extend([
        router(
            R2,
            vec![
                p2p(R4, "192.0.2.9", 10),
                stub("192.0.2.8", MASK_30, 10),
                p2p(ASBR, "192.0.2.13", 50),
                stub("192.0.2.12", MASK_30, 50),
            ],
            AREA_1,
        ),
        router(
            ASBR,
            vec![p2p(R2, "192.0.2.14", 50), stub("192.0.2.12", MASK_30, 50)],
            AREA_1,
        ),
        asbr_summary(ASBR, 5, R1, AREA_0),
        external("203.0.113.0/26", 20, ASBR, 2, None),
    ]);
    let d = db(lsas);
    let rfc2328 = run(&d, R2, Platform::Nxos);
    let r = route(&rfc2328, "203.0.113.0/26");
    assert_eq!((r.metric, r.forward_metric), (20, Some(50)));
    assert_eq!(gateways(&rfc2328, "203.0.113.0/26"), ["192.0.2.14"]);
    let rfc1583 = run(&d, R2, Platform::Iosxe);
    let r = route(&rfc1583, "203.0.113.0/26");
    assert_eq!((r.metric, r.forward_metric), (20, Some(15)));
    assert_eq!(gateways(&rfc1583, "203.0.113.0/26"), ["192.0.2.1"]);
}

#[test]
fn nssa_externals_and_the_nssa_default_route() {
    let d = db(vec![
        router(
            R4,
            vec![
                p2p(R2, "192.0.2.10", 10),
                stub("192.0.2.8", MASK_30, 10),
                stub(R4, MASK_32, 1),
            ],
            AREA_1,
        ),
        router(
            R2,
            vec![p2p(R4, "192.0.2.9", 10), stub("192.0.2.8", MASK_30, 10)],
            AREA_1,
        ),
        summary("198.51.100.1/32", 11, R2, AREA_1),
        nssa("0.0.0.0/0", 1, R2, None, AREA_1),
        nssa("203.0.113.64/26", 30, R2, Some(ZERO), AREA_1),
        nssa("203.0.113.0/26", 20, R4, Some("192.0.2.10"), AREA_1),
    ]);
    assert_eq!(d.area_type(ip(AREA_1)), AreaType::Nssa);
    let c = run(&d, R4, Platform::Nxos);
    assert!(c.notes.is_empty());
    let got: Vec<_> = c
        .routes
        .iter()
        .map(|r| {
            (
                r.prefix.to_string(),
                r.path_type,
                r.metric,
                r.forward_metric,
                r.lsa_type,
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (
                "0.0.0.0/0".to_string(),
                PathType::External2,
                1,
                Some(10),
                Some(LsaType::NssaExternal)
            ),
            (
                "198.51.100.1/32".to_string(),
                PathType::InterArea,
                21,
                None,
                Some(LsaType::Summary)
            ),
            (
                "203.0.113.64/26".to_string(),
                PathType::External2,
                30,
                Some(10),
                Some(LsaType::NssaExternal)
            ),
        ]
    );
    assert!(
        c.routes.iter().all(
            |r| r.next_hops.len() == 1 && r.next_hops[0].gateway == IpAddr::V4(ip("192.0.2.9"))
        )
    );
}

#[test]
fn a_cost_change_moves_the_next_hop_and_keeps_the_database() {
    let observed = db(single_area());
    let (changed, touched) = observed.with_interface_cost(ip(R1), ip("192.0.2.1"), 40);
    assert!(touched);
    let c = run(&changed, R1, Platform::Nxos);
    assert_eq!(route(&c, "198.51.100.2/32").metric, 31);
    assert_eq!(gateways(&c, "198.51.100.2/32"), ["192.0.2.6"]);
    let c = run(&observed, R1, Platform::Nxos);
    assert_eq!(gateways(&c, "198.51.100.2/32"), ["192.0.2.2"]);
    assert_eq!(observed, db(single_area()));
}

#[test]
fn an_adjacency_loss_removes_the_routes_through_it() {
    let (changed, touched) = db(single_area()).without_adjacency(ip(R1), ip(R2));
    assert!(touched);
    let c = run(&changed, R1, Platform::Nxos);
    assert!(c.gaps.is_empty());
    assert_eq!(
        rows(&c),
        [
            row("192.0.2.64/26", "intra-area", 30, &["192.0.2.6"]),
            row("198.51.100.2/32", "intra-area", 31, &["192.0.2.6"]),
            row("198.51.100.3/32", "intra-area", 21, &["192.0.2.6"]),
            row("198.51.100.128/26", "intra-area", 25, &["192.0.2.6"]),
        ]
    );
}

#[test]
fn an_adjacency_loss_on_a_transit_network_leaves_the_segment_as_stub_links() {
    let (changed, touched) = db(single_area()).without_adjacency(ip(R2), ip(R3));
    assert!(touched);
    let c = run(&changed, R1, Platform::Nxos);
    let lan = route(&c, "192.0.2.64/26");
    assert_eq!(lan.metric, 20);
    assert_eq!(gateways(&c, "192.0.2.64/26"), ["192.0.2.2"]);
    assert_eq!(gateways(&c, "198.51.100.3/32"), ["192.0.2.6"]);
    assert_eq!(gateways(&c, "198.51.100.128/26"), ["192.0.2.6"]);
}

#[test]
fn an_interface_in_another_area_takes_its_prefix_out_of_the_old_area() {
    let (moved, touched) =
        db(single_area()).with_interface_in_area(ip(R3), ip("198.51.100.129"), ip(AREA_1));
    assert!(touched);
    let c = run(&moved, R1, Platform::Nxos);
    assert!(c.gaps.is_empty());
    assert!(c.route(pfx("198.51.100.128/26")).is_none());
    assert_eq!(gateways(&c, "198.51.100.3/32"), ["192.0.2.2", "192.0.2.6"]);
}

#[test]
fn a_change_that_touches_nothing_gives_false() {
    let (_, touched) = db(single_area()).with_interface_cost(ip(R1), ip("192.0.2.200"), 5);
    assert!(!touched);
}

#[test]
fn a_missing_lsa_is_a_gap_and_the_routes_beyond_it_are_unknown() {
    let lsas: Vec<Lsa> = single_area()
        .into_iter()
        .filter(|l| !(l.lsa_type == LsaType::Router && l.lsid == ip(R3)))
        .collect();
    let c = calc(lsas, R1);
    assert!(c.notes.is_empty());
    assert_eq!(c.gaps.len(), 1);
    let g = &c.gaps[0];
    assert_eq!(
        (g.lsa_type, g.lsid, g.area),
        (LsaType::Router, ip(R3), Some(ip(AREA_0)))
    );
    assert_eq!(
        g.detail,
        format!("router LSA {R3} in area {AREA_0}, named by a point-to-point link of router {R1}")
    );
    assert_eq!(g.reach, GapReach::FromCost(20));
    let got: Vec<(String, bool)> = c
        .routes
        .iter()
        .map(|r| (r.prefix.to_string(), r.unknown.is_some()))
        .collect();
    assert_eq!(
        got,
        [
            ("192.0.2.64/26".to_string(), true),
            ("198.51.100.2/32".to_string(), false),
        ]
    );
    assert!(c.absent_gap(pfx("198.51.100.3/32")).is_some());
}

#[test]
fn a_database_with_no_lsa_of_the_calculating_router_gives_only_a_gap() {
    let c = calc(single_area(), "198.51.100.99");
    assert!(c.routes.is_empty());
    assert_eq!(c.gaps.len(), 1);
    assert_eq!(
        (
            c.gaps[0].lsa_type,
            c.gaps[0].lsid,
            c.gaps[0].area,
            &c.gaps[0].reach
        ),
        (LsaType::Router, ip("198.51.100.99"), None, &GapReach::All)
    );
}

#[test]
fn a_summary_of_a_border_router_with_no_lsa_makes_its_prefix_unknown() {
    let mut lsas = single_area();
    lsas.push(summary("198.51.100.192/27", 5, "198.51.100.8", AREA_0));
    let c = calc(lsas, R1);
    assert!(c.route(pfx("198.51.100.192/27")).is_none());
    assert_eq!(
        c.gaps[0].reach,
        GapReach::Prefixes(vec![pfx("198.51.100.192/27")])
    );
    assert!(c.absent_gap(pfx("198.51.100.192/27")).is_some());
    assert!(c.absent_gap(pfx("203.0.113.0/26")).is_none());
    assert!(c.routes.iter().all(|r| r.unknown.is_none()));
}

#[test]
fn the_same_database_in_any_order_gives_the_same_calculation() {
    let mut lsas = two_areas();
    lsas.extend([
        external("203.0.113.0/26", 20, R3, 2, None),
        external("203.0.113.0/26", 20, R2, 2, None),
        external("203.0.113.64/26", 20, R2, 2, Some("198.51.100.138")),
    ]);
    let reference = calc(lsas.clone(), R1);
    for shift in 1..lsas.len() {
        let mut turned = lsas.clone();
        turned.rotate_left(shift);
        turned.reverse();
        let mut d = Database::new(Version::V2, "default", "1");
        for l in turned {
            let span = SourceSpan::line(
                "lsdb",
                lsas.iter().position(|x| x == &l).unwrap() as u32 + 1,
            );
            d.insert(Lsa { span, ..l });
        }
        assert_eq!(run(&d, R1, Platform::Nxos), reference);
    }
}

#[test]
fn the_newer_instance_of_an_lsa_stays_in_the_database() {
    let old = router(R2, vec![p2p(R1, "192.0.2.2", 99)], AREA_0);
    let new = Lsa {
        seq: Some(0x8000_0002),
        ..router(R2, vec![p2p(R1, "192.0.2.2", 10)], AREA_0)
    };
    let mut d = Database::new(Version::V2, "default", "1");
    d.insert(new.clone());
    d.insert(old);
    assert_eq!(d.lsas.values().next(), Some(&new));
}

#[test]
fn the_ospf_defaults_of_each_platform() {
    for p in [
        Platform::Iosxe,
        Platform::Nxos,
        Platform::Iosxr,
        Platform::FrrTraditional,
        Platform::FrrDatacenter,
    ] {
        assert_eq!(OspfProfile::of(p).distance(), 110);
    }
    let of = |p| {
        let o = OspfProfile::of(p);
        (o.reference_bandwidth_mbps, o.rfc1583_compatible)
    };
    assert_eq!(of(Platform::Iosxe), (100, true));
    assert_eq!(of(Platform::Nxos), (40_000, false));
    assert_eq!(of(Platform::Iosxr), (100, false));
    assert_eq!(of(Platform::FrrTraditional), (100, false));
    assert_eq!(of(Platform::FrrDatacenter), (100, false));
}

#[test]
fn the_interface_cost_from_the_bandwidth() {
    let cost = |p, kbps| OspfProfile::of(p).interface_cost(kbps);
    assert_eq!(cost(Platform::Iosxe, 1_544), 64);
    assert_eq!(cost(Platform::Iosxe, 1_000_000), 1);
    assert_eq!(cost(Platform::Nxos, 10_000_000), 4);
    assert_eq!(cost(Platform::Iosxe, 60_000), 1);
    assert_eq!(cost(Platform::FrrTraditional, 60_000), 2);
    assert_eq!(cost(Platform::Iosxe, 1), 65_535);
}

// OSPFv3: the topology of `single_area` with link-local next hops.

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn v3_link(kind: LinkKind, neighbor: &str, own: u32, far: u32, metric: u32) -> RouterLink {
    RouterLink {
        kind,
        id: ip(neighbor),
        data: None,
        metric,
        interface_id: Some(own),
        neighbor_interface_id: Some(far),
    }
}

fn v3_router(rid: &str, links: Vec<RouterLink>) -> Lsa {
    lsa(
        LsaType::Router,
        ZERO,
        rid,
        Some(AREA_0),
        Body::Router { links },
    )
}

fn v3_prefixes(adv: &str, reference: Reference, prefixes: &[(&str, u32)]) -> Lsa {
    let lsid = match reference {
        Reference::Router => 0,
        Reference::Network(id) => 1000 + id,
    };
    lsa(
        LsaType::IntraAreaPrefix,
        &Ipv4Addr::from(lsid).to_string(),
        adv,
        Some(AREA_0),
        Body::IntraAreaPrefix {
            reference,
            router: ip(adv),
            prefixes: prefixes.iter().map(|(p, m)| (pfx(p), *m)).collect(),
        },
    )
}

fn v3_link_lsa(adv: &str, interface_id: u32, address: &str) -> Lsa {
    lsa(
        LsaType::Link,
        &Ipv4Addr::from(interface_id).to_string(),
        adv,
        Some(AREA_0),
        Body::Link {
            address: Some(v6(address)),
            prefixes: Vec::new(),
            interface: None,
        },
    )
}

fn v3_single_area() -> Vec<Lsa> {
    use LinkKind::{PointToPoint, Transit};
    vec![
        v3_router(
            R1,
            vec![
                v3_link(PointToPoint, R2, 1, 1, 10),
                v3_link(PointToPoint, R3, 2, 1, 20),
            ],
        ),
        v3_router(
            R2,
            vec![
                v3_link(PointToPoint, R1, 1, 1, 10),
                v3_link(Transit, R3, 2, 2, 10),
            ],
        ),
        v3_router(
            R3,
            vec![
                v3_link(PointToPoint, R1, 1, 2, 20),
                v3_link(Transit, R3, 2, 2, 10),
            ],
        ),
        lsa(
            LsaType::Network,
            "0.0.0.2",
            R3,
            Some(AREA_0),
            Body::Network {
                mask: None,
                attached: vec![ip(R2), ip(R3)],
            },
        ),
        v3_link_lsa(R2, 1, "fe80::2"),
        v3_link_lsa(R3, 1, "fe80::3"),
        v3_prefixes(
            R1,
            Reference::Router,
            &[
                ("2001:db8:12::/64", 10),
                ("2001:db8:13::/64", 20),
                ("2001:db8:ff::1/128", 1),
            ],
        ),
        v3_prefixes(
            R2,
            Reference::Router,
            &[("2001:db8:12::/64", 10), ("2001:db8:ff::2/128", 1)],
        ),
        v3_prefixes(
            R3,
            Reference::Router,
            &[
                ("2001:db8:13::/64", 20),
                ("2001:db8:ff::3/128", 1),
                ("2001:db8:3::/64", 5),
            ],
        ),
        v3_prefixes(R3, Reference::Network(2), &[("2001:db8:23::/64", 0)]),
    ]
}

fn v3_db(lsas: Vec<Lsa>) -> Database {
    let mut d = Database::new(Version::V3, "default", "1");
    for (i, mut l) in lsas.into_iter().enumerate() {
        l.span = SourceSpan::line("lsdb", i as u32 + 1);
        d.insert(l);
    }
    d
}

#[test]
fn ospfv3_gives_the_graph_of_ospfv2_with_link_local_next_hops() {
    let c = run(&v3_db(v3_single_area()), R1, Platform::Iosxr);
    assert!(
        c.notes.is_empty() && c.gaps.is_empty(),
        "{:?} {:?}",
        c.notes,
        c.gaps
    );
    assert_eq!(
        rows(&c),
        [
            row("2001:db8:3::/64", "intra-area", 25, &["fe80::2", "fe80::3"]),
            row("2001:db8:23::/64", "intra-area", 20, &["fe80::2"]),
            row("2001:db8:ff::2/128", "intra-area", 11, &["fe80::2"]),
            row(
                "2001:db8:ff::3/128",
                "intra-area",
                21,
                &["fe80::2", "fe80::3"]
            ),
        ]
    );
    let v2 = calc(single_area(), R1);
    assert_eq!(c.router_costs, v2.router_costs);
    let shape = |c: &Calculation| {
        let mut s: Vec<(u32, usize)> = c
            .routes
            .iter()
            .map(|r| (r.metric, r.next_hops.len()))
            .collect();
        s.sort();
        s
    };
    assert_eq!(shape(&c), shape(&v2));
}

#[test]
fn ospfv3_externals_and_inter_area_prefixes() {
    let mut lsas = v3_single_area();
    lsas.push(lsa(
        LsaType::External,
        "0.0.0.0",
        R3,
        None,
        Body::External {
            prefix: pfx("2001:db8:99::/64"),
            metric: 20,
            metric_type: Some(2),
            forwarding: None,
        },
    ));
    lsas.push(lsa(
        LsaType::Summary,
        "0.0.0.0",
        R2,
        Some(AREA_0),
        Body::Summary {
            prefix: pfx("2001:db8:44::/64"),
            metric: 10,
        },
    ));
    let c = run(&v3_db(lsas), R1, Platform::Iosxe);
    assert_eq!(
        rows(&c)[..2],
        [
            row("2001:db8:3::/64", "intra-area", 25, &["fe80::2", "fe80::3"]),
            row("2001:db8:23::/64", "intra-area", 20, &["fe80::2"]),
        ]
    );
    let r = route(&c, "2001:db8:44::/64");
    assert_eq!((r.path_type, r.metric), (PathType::InterArea, 20));
    let r = route(&c, "2001:db8:99::/64");
    assert_eq!(
        (r.path_type, r.metric, r.forward_metric),
        (PathType::External2, 20, Some(20))
    );
    assert_eq!(gateways(&c, "2001:db8:99::/64"), ["fe80::2", "fe80::3"]);
}

#[test]
fn ospfv3_with_no_link_lsa_of_a_neighbour_gives_a_gap() {
    let lsas: Vec<Lsa> = v3_single_area()
        .into_iter()
        .filter(|l| !(l.lsa_type == LsaType::Link && l.adv_router == ip(R3)))
        .collect();
    let c = run(&v3_db(lsas), R1, Platform::Iosxr);
    assert_eq!(c.gaps.len(), 1);
    assert_eq!(
        (c.gaps[0].lsa_type, c.gaps[0].lsid, &c.gaps[0].reach),
        (LsaType::Link, ip("0.0.0.1"), &GapReach::FromCost(20))
    );
    let got: Vec<(String, bool, Vec<String>)> = c
        .routes
        .iter()
        .map(|r| {
            (
                r.prefix.to_string(),
                r.unknown.is_some(),
                r.next_hops.iter().map(|h| h.gateway.to_string()).collect(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (
                "2001:db8:3::/64".to_string(),
                true,
                vec!["fe80::2".to_string()]
            ),
            (
                "2001:db8:23::/64".to_string(),
                true,
                vec!["fe80::2".to_string()]
            ),
            (
                "2001:db8:ff::2/128".to_string(),
                false,
                vec!["fe80::2".to_string()]
            ),
            (
                "2001:db8:ff::3/128".to_string(),
                true,
                vec!["fe80::2".to_string()]
            ),
        ]
    );
}
