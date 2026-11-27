//! The OSPF database builder on hand-built configs.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rsim_core::{Prefix, SourceSpan};
use rsim_routing::Platform;
use rsim_routing::ospf::build::{Address, Built, RouterInput, build, default_router_id};
use rsim_routing::ospf::config::{
    Area, DefaultOriginate, NetworkType, OspfInterface, Process, Redistribute, RouterConfig, Source,
};
use rsim_routing::ospf::{
    AreaId, AreaType, BACKBONE, Body, Calculation, Database, GapReach, LinkKind, Lsa, LsaType,
    NextHop, OspfProfile, PathType, Reference, RouterLink, Version, compute,
};

const AREA1: AreaId = Ipv4Addr::new(0, 0, 0, 1);
const AREA2: AreaId = Ipv4Addr::new(0, 0, 0, 2);

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn pfx(s: &str) -> Prefix {
    s.parse().unwrap()
}

fn iface(name: &str, area: AreaId, addr: &str, network: NetworkType) -> OspfInterface {
    secondaries: Vec::new(),
    let (a, len) = addr.split_once('/').unwrap();
    OspfInterface {
        secondaries: Vec::new(),
        name: name.to_string(),
        area,
        address: Some((a.parse::<IpAddr>().unwrap(), len.parse().unwrap())),
        cost: Some(10),
        bandwidth_kbps: None,
        network,
        passive: false,
        priority: 1,
        up: true,
        span: SourceSpan::line(name, 1),
    }
}

fn p2p(name: &str, area: AreaId, addr: &str) -> OspfInterface {
    secondaries: Vec::new(),
    iface(name, area, addr, NetworkType::PointToPoint)
}

fn lan(name: &str, area: AreaId, addr: &str) -> OspfInterface {
    secondaries: Vec::new(),
    iface(name, area, addr, NetworkType::Broadcast)
}

fn lo(area: AreaId, addr: &str) -> OspfInterface {
    secondaries: Vec::new(),
    let mut f = iface("lo0", area, addr, NetworkType::Loopback);
    f.cost = None;
    f
}

fn process(version: Version, rid: Option<&str>, interfaces: Vec<OspfInterface>) -> Process {
    let mut areas = BTreeMap::new();
    for f in &interfaces {
        areas.entry(f.area).or_insert(Area {
            kind: AreaType::Normal,
            no_summary: false,
            default_cost: None,
            span: SourceSpan::line("area", 1),
        });
    }
    Process {
        version,
        vrf: "default".to_string(),
        process: "1".to_string(),
        router_id: rid.map(ip),
        reference_bandwidth_mbps: None,
        areas,
        interfaces,
        redistribute: Vec::new(),
        default_originate: None,
        passive_default: false,
        unhandled: Vec::new(),
        span: SourceSpan::line("process", 1),
    }
}

fn router(platform: Platform, processes: Vec<Process>) -> RouterInput {
    RouterInput::new(RouterConfig { processes }, platform)
}

fn v2(rid: &str, interfaces: Vec<OspfInterface>) -> RouterInput {
    router(
        Platform::Iosxe,
        vec![process(Version::V2, Some(rid), interfaces)],
    )
}

fn twin(routers: Vec<(&str, RouterInput)>) -> Built {
    let map: BTreeMap<String, RouterInput> = routers
        .into_iter()
        .map(|(n, r)| (n.to_string(), r))
        .collect();
    build(&map)
}

fn db<'a>(built: &'a Built, device: &str, version: Version) -> &'a Database {
    &built.databases[&(
        device.to_string(),
        "default".to_string(),
        version,
        "1".to_string(),
    )]
}

fn find<'a>(db: &'a Database, lsa_type: LsaType, adv: &str) -> Vec<&'a Lsa> {
    db.lsas
        .values()
        .filter(|l| l.lsa_type == lsa_type && l.adv_router == ip(adv))
        .collect()
}

fn router_links(db: &Database, area: AreaId, adv: &str) -> Vec<RouterLink> {
    let l = find(db, LsaType::Router, adv)
        .into_iter()
        .find(|l| l.area == Some(area))
        .unwrap_or_else(|| panic!("no router LSA of {adv} in area {area}"));
    match &l.body {
        Body::Router { links } => links.clone(),
        _ => unreachable!(),
    }
}

fn v2_link(kind: LinkKind, id: &str, data: &str, metric: u32) -> RouterLink {
    RouterLink {
        kind,
        id: ip(id),
        data: Some(ip(data)),
        metric,
        interface_id: None,
        neighbor_interface_id: None,
    }
}

fn calc(built: &Built, device: &str, rid: &str) -> Calculation {
    compute(
        db(built, device, Version::V2),
        ip(rid),
        &OspfProfile::of(Platform::Iosxe),
    )
}

fn route(c: &Calculation, prefix: &str) -> (PathType, u32, Vec<String>) {
    let r = c
        .route(pfx(prefix))
        .unwrap_or_else(|| panic!("no route of {prefix}"));
    assert_eq!(r.unknown, None, "the route of {prefix} is unknown");
    (
        r.path_type,
        r.metric,
        r.next_hops.iter().map(|h| h.to_string()).collect(),
    )
}

fn kinds(built: &Built, device: &str) -> Vec<String> {
    built
        .notes
        .iter()
        .filter(|(d, _)| d == device)
        .map(|(_, n)| n.kind.clone())
        .collect()
}

#[test]
fn a_point_to_point_pair_gives_a_point_to_point_link_and_a_stub_link_on_each_router() {
    let mut r1 = p2p("eth0", BACKBONE, "192.0.2.1/30");
    r1.cost = Some(7);
    let built = twin(vec![
        ("r1", v2("203.0.113.1", vec![r1])),
        (
            "r2",
            v2(
                "203.0.113.2",
                vec![
                    p2p("eth0", BACKBONE, "192.0.2.2/30"),
                    lo(BACKBONE, "203.0.113.2/32"),
                ],
            ),
        ),
    ]);
    let d1 = db(&built, "r1", Version::V2);
    assert_eq!(
        router_links(d1, BACKBONE, "203.0.113.1"),
        vec![
            v2_link(LinkKind::PointToPoint, "203.0.113.2", "192.0.2.1", 7),
            v2_link(LinkKind::Stub, "192.0.2.0", "255.255.255.252", 7),
        ]
    );
    assert_eq!(
        router_links(d1, BACKBONE, "203.0.113.2"),
        vec![
            v2_link(LinkKind::PointToPoint, "203.0.113.1", "192.0.2.2", 10),
            v2_link(LinkKind::Stub, "192.0.2.0", "255.255.255.252", 10),
            v2_link(LinkKind::Stub, "203.0.113.2", "255.255.255.255", 1),
        ]
    );
    assert_eq!(d1.neighbors.len(), 1);
    assert_eq!(d1.neighbors[0].router_id, ip("203.0.113.2"));
    assert_eq!(
        find(d1, LsaType::Router, "203.0.113.1")[0].span,
        SourceSpan::line("process", 1)
    );
    let c = calc(&built, "r1", "203.0.113.1");
    assert_eq!(
        route(&c, "203.0.113.2/32"),
        (
            PathType::IntraArea,
            8,
            vec!["192.0.2.2 on eth0".to_string()]
        )
    );
    assert!(c.route(pfx("192.0.2.0/30")).is_none());
}

#[test]
fn a_broadcast_segment_elects_the_highest_priority_then_the_highest_router_id() {
    let segment = |prio: [u8; 3]| {
        let mut rs = Vec::new();
        for (i, p) in prio.iter().enumerate() {
            let mut f = lan("eth0", BACKBONE, &format!("198.51.100.{}/29", i + 1));
            f.priority = *p;
            rs.push((
                ["r1", "r2", "r3"][i],
                v2(&format!("203.0.113.{}", i + 1), vec![f]),
            ));
        }
        twin(rs)
    };
    let built = segment([1, 1, 0]);
    let d = db(&built, "r3", Version::V2);
    let nets = find(d, LsaType::Network, "203.0.113.2");
    assert_eq!(nets.len(), 1);
    assert_eq!(nets[0].lsid, ip("198.51.100.2"));
    assert_eq!(
        nets[0].body,
        Body::Network {
            mask: Some(ip("255.255.255.248")),
            attached: vec![ip("203.0.113.1"), ip("203.0.113.2"), ip("203.0.113.3")],
        }
    );
    assert_eq!(nets[0].span, SourceSpan::line("eth0", 1));
    assert_eq!(
        router_links(d, BACKBONE, "203.0.113.3"),
        vec![v2_link(
            LinkKind::Transit,
            "198.51.100.2",
            "198.51.100.3",
            10
        )]
    );
    let built = segment([5, 1, 0]);
    let d = db(&built, "r2", Version::V2);
    assert_eq!(
        find(d, LsaType::Network, "203.0.113.1")[0].lsid,
        ip("198.51.100.1")
    );
    assert!(find(d, LsaType::Network, "203.0.113.2").is_empty());
    let built = segment([0, 0, 0]);
    let d = db(&built, "r1", Version::V2);
    assert!(d.lsas.values().all(|l| l.lsa_type != LsaType::Network));
    assert_eq!(
        router_links(d, BACKBONE, "203.0.113.1"),
        vec![v2_link(
            LinkKind::Stub,
            "198.51.100.0",
            "255.255.255.248",
            10
        )]
    );
    assert!(kinds(&built, "r1").contains(&"ospf-no-designated-router".to_string()));
}

#[test]
fn a_passive_interface_and_a_segment_with_no_neighbour_give_stub_links_and_a_down_interface_gives_nothing()
 {
    let mut passive = lan("eth1", BACKBONE, "198.51.100.9/29");
    passive.passive = true;
    let mut down = p2p("eth2", BACKBONE, "192.0.2.5/30");
    down.up = false;
    let built = twin(vec![
        (
            "r1",
            router(
                Platform::FrrTraditional,
                vec![process(
                    Version::V2,
                    Some("203.0.113.1"),
                    vec![
                        lan("eth0", BACKBONE, "198.51.100.1/29"),
                        passive,
                        down,
                        lo(BACKBONE, "203.0.113.1/32"),
                    ],
                )],
            ),
        ),
        (
            "r2",
            v2("203.0.113.2", vec![p2p("eth0", BACKBONE, "192.0.2.6/30")]),
        ),
    ]);
    let d = db(&built, "r1", Version::V2);
    assert_eq!(
        router_links(d, BACKBONE, "203.0.113.1"),
        vec![
            v2_link(LinkKind::Stub, "198.51.100.0", "255.255.255.248", 10),
            v2_link(LinkKind::Stub, "198.51.100.8", "255.255.255.248", 10),
            v2_link(LinkKind::Stub, "203.0.113.1", "255.255.255.255", 0),
        ]
    );
    assert!(d.interfaces.iter().all(|i| i.name != "eth2"));
    assert!(d.neighbors.is_empty());
    assert_eq!(
        router_links(db(&built, "r2", Version::V2), BACKBONE, "203.0.113.2"),
        vec![v2_link(LinkKind::Stub, "192.0.2.4", "255.255.255.252", 10)]
    );
}

#[test]
fn the_cost_is_the_configured_cost_else_the_reference_bandwidth_over_the_bandwidth() {
    let mut a = p2p("eth0", BACKBONE, "192.0.2.1/30");
    a.cost = None;
    a.bandwidth_kbps = Some(10_000);
    let mut b = p2p("eth1", BACKBONE, "192.0.2.5/30");
    b.cost = None;
    let mut p = process(Version::V2, Some("203.0.113.1"), vec![a, b]);
    let built = twin(vec![("r1", router(Platform::Iosxe, vec![p.clone()]))]);
    let links = router_links(db(&built, "r1", Version::V2), BACKBONE, "203.0.113.1");
    assert_eq!(links[0].metric, 10);
    assert_eq!(links[1].metric, 1);
    assert_eq!(kinds(&built, "r1"), vec!["ospf-cost-default".to_string()]);
    p.reference_bandwidth_mbps = Some(1000);
    let built = twin(vec![("r1", router(Platform::Iosxe, vec![p]))]);
    let links = router_links(db(&built, "r1", Version::V2), BACKBONE, "203.0.113.1");
    assert_eq!(links[0].metric, 100);
}

#[test]
fn the_router_id_is_the_configured_one_else_the_rule_of_the_platform() {
    let addr = |a: &str, loopback: bool| Address {
        interface: a.to_string(),
        address: ip(a),
        loopback,
        up: true,
    };
    let list = [addr("203.0.113.9", true), addr("203.0.113.200", false)];
    assert_eq!(
        default_router_id(Platform::Iosxe, &list),
        Some(ip("203.0.113.9"))
    );
    assert_eq!(
        default_router_id(Platform::Nxos, &list),
        Some(ip("203.0.113.9"))
    );
    assert_eq!(
        default_router_id(Platform::FrrTraditional, &list),
        Some(ip("203.0.113.200"))
    );
    assert_eq!(default_router_id(Platform::Iosxe, &[]), None);

    let p = process(
        Version::V2,
        None,
        vec![
            p2p("eth0", BACKBONE, "192.0.2.1/30"),
            lo(BACKBONE, "203.0.113.7/32"),
        ],
    );
    let built = twin(vec![("r1", router(Platform::Iosxe, vec![p]))]);
    assert_eq!(
        db(&built, "r1", Version::V2).router_id,
        Some(ip("203.0.113.7"))
    );

    let mut p = process(
        Version::V2,
        None,
        vec![p2p("eth0", BACKBONE, "192.0.2.1/30")],
    );
    p.interfaces[0].address = None;
    let built = twin(vec![("r1", router(Platform::Iosxe, vec![p]))]);
    let d = db(&built, "r1", Version::V2);
    assert_eq!(d.router_id, None);
    assert!(d.lsas.is_empty());
    assert_eq!(
        kinds(&built, "r1"),
        vec![
            "ospf-no-router-id".to_string(),
            "ospf-no-address".to_string()
        ]
    );
}

/// r1 (area 1) - r2 (areas 1 and 0) - r3 (areas 0 and 2) - r4 (area 2), with
/// point-to-point links of cost 10 and a loopback on r1 and r4.
fn chain(area2: AreaType, no_summary: bool) -> Vec<(&'static str, RouterInput)> {
    let mut r3 = process(
        Version::V2,
        Some("203.0.113.3"),
        vec![
            p2p("eth0", BACKBONE, "192.0.2.6/30"),
            p2p("eth1", AREA2, "192.0.2.9/30"),
        ],
    );
    let mut r4 = process(
        Version::V2,
        Some("203.0.113.4"),
        vec![
            p2p("eth0", AREA2, "192.0.2.10/30"),
            lo(AREA2, "203.0.113.4/32"),
        ],
    );
    for p in [&mut r3, &mut r4] {
        let a = p.areas.get_mut(&AREA2).unwrap();
        a.kind = area2;
        a.no_summary = no_summary;
        a.default_cost = Some(7);
    }
    vec![
        (
            "r1",
            v2(
                "203.0.113.1",
                vec![
                    p2p("eth0", AREA1, "192.0.2.1/30"),
                    lo(AREA1, "203.0.113.1/32"),
                ],
            ),
        ),
        (
            "r2",
            v2(
                "203.0.113.2",
                vec![
                    p2p("eth0", AREA1, "192.0.2.2/30"),
                    p2p("eth1", BACKBONE, "192.0.2.5/30"),
                ],
            ),
        ),
        ("r3", router(Platform::Iosxe, vec![r3])),
        ("r4", router(Platform::Iosxe, vec![r4])),
    ]
}

fn summaries(db: &Database, adv: &str) -> BTreeMap<Prefix, u32> {
    find(db, LsaType::Summary, adv)
        .into_iter()
        .filter_map(|l| match l.body {
            Body::Summary { prefix, metric } => Some((prefix, metric)),
            _ => None,
        })
        .collect()
}

#[test]
fn area_border_routers_give_the_summaries_of_the_intra_area_and_the_backbone_inter_area_routes() {
    let built = twin(chain(AreaType::Normal, false));
    let d2 = db(&built, "r2", Version::V2);
    assert_eq!(
        summaries(d2, "203.0.113.3"),
        BTreeMap::from([(pfx("192.0.2.8/30"), 10), (pfx("203.0.113.4/32"), 11)])
    );
    let d1 = db(&built, "r1", Version::V2);
    assert_eq!(
        summaries(d1, "203.0.113.2"),
        BTreeMap::from([
            (pfx("192.0.2.4/30"), 10),
            (pfx("192.0.2.8/30"), 20),
            (pfx("203.0.113.4/32"), 21),
        ])
    );
    assert!(find(d1, LsaType::Router, "203.0.113.3").is_empty());
    let c = calc(&built, "r1", "203.0.113.1");
    assert_eq!(
        route(&c, "203.0.113.4/32"),
        (
            PathType::InterArea,
            31,
            vec!["192.0.2.2 on eth0".to_string()]
        )
    );
    let c = calc(&built, "r4", "203.0.113.4");
    assert_eq!(route(&c, "203.0.113.1/32").1, 31);
}

#[test]
fn a_stub_area_gets_a_default_summary_and_a_totally_stubby_area_gets_only_the_default() {
    let built = twin(chain(AreaType::Stub, false));
    let d4 = db(&built, "r4", Version::V2);
    let s = summaries(d4, "203.0.113.3");
    assert_eq!(s.get(&pfx("0.0.0.0/0")), Some(&7));
    assert_eq!(s.get(&pfx("203.0.113.1/32")), Some(&21));
    let built = twin(chain(AreaType::Stub, true));
    let d4 = db(&built, "r4", Version::V2);
    assert_eq!(
        summaries(d4, "203.0.113.3"),
        BTreeMap::from([(pfx("0.0.0.0/0"), 7)])
    );
    let c = calc(&built, "r4", "203.0.113.4");
    assert_eq!(
        route(&c, "0.0.0.0/0"),
        (
            PathType::InterArea,
            17,
            vec!["192.0.2.9 on eth0".to_string()]
        )
    );
}

fn redistribute(source: Source, metric: Option<u32>, metric_type: Option<u8>) -> Redistribute {
    Redistribute {
        source,
        metric,
        metric_type,
        route_map: None,
        span: SourceSpan::line("redistribute", 1),
    }
}

/// The chain with r4 as an ASBR of its connected and static routes.
fn asbr_routers(area2: AreaType) -> Vec<(&'static str, RouterInput)> {
    let mut rs = chain(area2, false);
    let r4 = &mut rs[3].1;
    let p = &mut r4.config.processes[0];
    p.redistribute = vec![
        redistribute(Source::Connected, None, None),
        redistribute(Source::Static, Some(50), Some(1)),
    ];
    r4.connected.insert(
        "default".to_string(),
        vec![
            pfx("192.0.2.8/30"),
            pfx("203.0.113.4/32"),
            pfx("198.51.100.128/25"),
        ],
    );
    r4.statics.insert(
        "default".to_string(),
        vec![pfx("0.0.0.0/0"), pfx("203.0.113.128/25")],
    );
    rs
}

fn asbr_chain(area2: AreaType) -> Built {
    twin(asbr_routers(area2))
}

#[test]
fn an_asbr_gives_external_lsas_and_the_area_border_routers_give_asbr_summaries() {
    let built = asbr_chain(AreaType::Normal);
    let d1 = db(&built, "r1", Version::V2);
    let ext: Vec<(Prefix, u32, Option<u8>)> = find(d1, LsaType::External, "203.0.113.4")
        .into_iter()
        .filter_map(|l| match l.body {
            Body::External {
                prefix,
                metric,
                metric_type,
                ..
            } => Some((prefix, metric, metric_type)),
            _ => None,
        })
        .collect();
    assert_eq!(
        ext,
        vec![
            (pfx("198.51.100.128/25"), 20, Some(2)),
            (pfx("203.0.113.128/25"), 50, Some(1)),
        ]
    );
    let asbr = find(d1, LsaType::AsbrSummary, "203.0.113.2");
    assert_eq!(asbr.len(), 1);
    assert_eq!(
        asbr[0].body,
        Body::AsbrSummary {
            router: ip("203.0.113.4"),
            metric: 20
        }
    );
    let c = calc(&built, "r1", "203.0.113.1");
    assert_eq!(route(&c, "198.51.100.128/25").0, PathType::External2);
    assert_eq!(route(&c, "198.51.100.128/25").1, 20);
    assert_eq!(
        route(&c, "203.0.113.128/25"),
        (
            PathType::External1,
            80,
            vec!["192.0.2.2 on eth0".to_string()]
        )
    );
    assert!(c.route(pfx("0.0.0.0/0")).is_none());
    assert!(c.gaps.is_empty());
    assert!(c.absent_gap(pfx("0.0.0.0/0")).is_none());
}

#[test]
fn left_out_external_lsas_are_gaps_of_each_database_of_the_as() {
    let mut rs = asbr_routers(AreaType::Normal);
    let p = &mut rs[3].1.config.processes[0];
    p.redistribute[0].route_map = Some("ONLY".to_string());
    p.default_originate = Some(DefaultOriginate {
        always: true,
        metric: None,
        metric_type: None,
        route_map: Some("DEFAULT".to_string()),
        span: SourceSpan::line("default", 1),
    });
    let built = twin(rs.clone());
    let k = kinds(&built, "r4");
    assert!(k.contains(&"ospf-redistribute-unknown".to_string()));
    assert!(k.contains(&"ospf-default-unknown".to_string()));
    for device in ["r1", "r2", "r3"] {
        let d = db(&built, device, Version::V2);
        assert_eq!(d.gaps.len(), 2, "the gaps of {device}");
        assert!(
            d.gaps
                .iter()
                .all(|g| g.lsa_type == LsaType::External && g.lsid == ip("203.0.113.4"))
        );
    }
    let c = calc(&built, "r1", "203.0.113.1");
    assert!(c.route(pfx("198.51.100.128/25")).is_none());
    assert!(c.absent_gap(pfx("198.51.100.128/25")).is_some());
    assert!(c.absent_gap(pfx("0.0.0.0/0")).is_some());
    assert!(c.absent_gap(pfx("198.51.100.0/25")).is_none());
    assert_eq!(route(&c, "203.0.113.128/25").0, PathType::External1);

    rs[3].1.config.processes[0]
        .redistribute
        .push(redistribute(Source::Bgp, None, None));
    let built = twin(rs);
    let c = calc(&built, "r1", "203.0.113.1");
    let r = c.route(pfx("203.0.113.128/25")).unwrap();
    assert!(r.unknown.as_ref().is_some_and(|u| u.contains("bgp")));
    assert!(c.absent_gap(pfx("198.51.100.0/25")).is_some());
    assert_eq!(route(&c, "203.0.113.4/32").0, PathType::InterArea);
}

#[test]
fn default_information_originate_needs_always_or_a_default_route() {
    let make = |always: bool, has_default: bool| {
        let mut r = v2("203.0.113.1", vec![p2p("eth0", BACKBONE, "192.0.2.1/30")]);
        r.config.processes[0].default_originate = Some(DefaultOriginate {
            always,
            metric: None,
            metric_type: None,
            route_map: None,
            span: SourceSpan::line("default", 1),
        });
        if has_default {
            r.default_route.insert("default".to_string());
        }
        let built = twin(vec![("r1", r)]);
        find(
            db(&built, "r1", Version::V2),
            LsaType::External,
            "203.0.113.1",
        )
        .into_iter()
        .map(|l| (l.body.clone(), l.span.clone()))
        .collect::<Vec<_>>()
    };
    assert!(make(false, false).is_empty());
    let expected = vec![(
        Body::External {
            prefix: pfx("0.0.0.0/0"),
            metric: 1,
            metric_type: Some(2),
            forwarding: None,
        },
        SourceSpan::line("default", 1),
    )];
    assert_eq!(make(false, true), expected);
    assert_eq!(make(true, false), expected);
}

#[test]
fn an_asbr_in_an_nssa_gives_nssa_lsas_with_a_forwarding_address_and_the_nssa_border_router_translates_them()
 {
    let built = asbr_chain(AreaType::Nssa);
    let d4 = db(&built, "r4", Version::V2);
    let nssa = find(d4, LsaType::NssaExternal, "203.0.113.4");
    assert_eq!(nssa.len(), 2);
    assert!(nssa.iter().all(|l| l.area == Some(AREA2)));
    assert!(nssa.iter().all(|l| matches!(
        l.body,
        Body::External {
            forwarding: Some(fa),
            ..
        } if fa == IpAddr::V4(ip("203.0.113.4"))
    )));
    assert!(find(d4, LsaType::External, "203.0.113.4").is_empty());
    assert!(
        find(
            db(&built, "r1", Version::V2),
            LsaType::External,
            "203.0.113.4"
        )
        .is_empty()
    );
    let c = compute(d4, ip("203.0.113.4"), &OspfProfile::of(Platform::Iosxe));
    assert_eq!(route(&c, "203.0.113.1/32").1, 31);
    let c = compute(
        db(&built, "r3", Version::V2),
        ip("203.0.113.3"),
        &OspfProfile::of(Platform::Iosxe),
    );
    assert_eq!(route(&c, "198.51.100.128/25").0, PathType::External2);
    let translated = find(
        db(&built, "r1", Version::V2),
        LsaType::External,
        "203.0.113.3",
    );
    assert_eq!(translated.len(), 1);
    assert_eq!(
        translated[0].body,
        Body::External {
            prefix: pfx("198.51.100.128/25"),
            metric: 20,
            metric_type: Some(2),
            forwarding: Some(IpAddr::V4(ip("203.0.113.4"))),
        }
    );
    let c = calc(&built, "r1", "203.0.113.1");
    assert_eq!(
        route(&c, "198.51.100.128/25"),
        (
            PathType::External2,
            20,
            vec!["192.0.2.2 on eth0".to_string()]
        )
    );
    assert!(
        c.route(pfx("203.0.113.128/25")).is_none(),
        "the forwarding address of the NSSA LSA of a static route is not known"
    );
    assert!(c.absent_gap(pfx("203.0.113.128/25")).is_some());
}

#[test]
fn the_nssa_border_router_with_the_highest_router_id_translates_and_a_border_asbr_clears_the_p_bit()
{
    let mut rs = asbr_routers(AreaType::Nssa);
    rs[1].1.config.processes[0]
        .interfaces
        .push(p2p("eth2", BACKBONE, "192.0.2.13/30"));
    rs[3].1.config.processes[0]
        .interfaces
        .push(p2p("eth1", AREA2, "192.0.2.17/30"));
    let mut r5 = process(
        Version::V2,
        Some("203.0.113.5"),
        vec![
            p2p("eth0", BACKBONE, "192.0.2.14/30"),
            p2p("eth1", AREA2, "192.0.2.18/30"),
        ],
    );
    r5.areas.get_mut(&AREA2).unwrap().kind = AreaType::Nssa;
    r5.redistribute = vec![redistribute(Source::Connected, None, None)];
    let mut r5 = router(Platform::Iosxe, vec![r5]);
    r5.connected
        .insert("default".to_string(), vec![pfx("198.51.100.0/25")]);
    rs.push(("r5", r5));
    let built = twin(rs);
    let d4 = db(&built, "r4", Version::V2);
    let own = find(d4, LsaType::NssaExternal, "203.0.113.5");
    assert_eq!(own.len(), 1);
    assert!(matches!(
        own[0].body,
        Body::External {
            forwarding: None,
            ..
        }
    ));
    let d1 = db(&built, "r1", Version::V2);
    assert!(find(d1, LsaType::External, "203.0.113.3").is_empty());
    let prefixes: Vec<Prefix> = find(d1, LsaType::External, "203.0.113.5")
        .into_iter()
        .filter_map(|l| match l.body {
            Body::External { prefix, .. } => Some(prefix),
            _ => None,
        })
        .collect();
    assert_eq!(
        prefixes,
        vec![pfx("198.51.100.0/25"), pfx("198.51.100.128/25")]
    );
}

#[test]
fn a_gap_behind_an_area_border_router_is_a_gap_of_the_routers_of_the_other_areas() {
    let mut rs = chain(AreaType::Normal, false);
    rs[3].1.config.processes[0].unhandled.push((
        "area 2 virtual-link 203.0.113.3".to_string(),
        SourceSpan::line("process", 9),
    ));
    let built = twin(rs);
    let d1 = db(&built, "r1", Version::V2);
    assert!(
        d1.gaps
            .iter()
            .any(|g| g.lsa_type == LsaType::Summary && g.reach == GapReach::InterArea)
    );
    let c = calc(&built, "r1", "203.0.113.1");
    assert!(c.route(pfx("203.0.113.4/32")).is_none());
    assert!(c.absent_gap(pfx("203.0.113.4/32")).is_some());
    assert!(c.route(pfx("192.0.2.4/30")).unwrap().unknown.is_some());
}

#[test]
fn an_active_interface_with_no_address_leaves_out_the_router_and_its_neighbours_see_a_gap() {
    let mut rs = chain(AreaType::Normal, false);
    rs[2].1.config.processes[0].interfaces[1].address = None;
    let built = twin(rs);
    assert!(kinds(&built, "r3").contains(&"ospf-no-address".to_string()));
    let d2 = db(&built, "r2", Version::V2);
    assert!(d2.lsas.values().all(|l| l.adv_router != ip("203.0.113.3")));
    let c = calc(&built, "r2", "203.0.113.2");
    assert!(
        c.gaps
            .iter()
            .any(|g| g.lsa_type == LsaType::Router && g.lsid == ip("203.0.113.3"))
    );
    assert!(c.absent_gap(pfx("203.0.113.4/32")).is_some());
    let c = calc(&built, "r1", "203.0.113.1");
    assert!(c.absent_gap(pfx("203.0.113.4/32")).is_some());

    let built = twin(vec![(
        "r1",
        v3_router(
            "203.0.113.1",
            vec![
                p2p("eth0", BACKBONE, "fe80::1/64"),
                lo(BACKBONE, "2001:db8:ffff::1/128"),
            ],
            &[("eth0", "fe80::1")],
        ),
    )]);
    assert!(kinds(&built, "r1").contains(&"ospf-no-address".to_string()));
    let d = db(&built, "r1", Version::V3);
    assert!(d.lsas.values().all(|l| l.adv_router != ip("203.0.113.1")));
}

#[test]
fn a_process_with_an_unhandled_line_gives_no_lsa_and_its_neighbours_see_a_gap() {
    let mut rs = chain(AreaType::Normal, false);
    rs[1].1.config.processes[0].unhandled.push((
        "area 1 virtual-link 203.0.113.3".to_string(),
        SourceSpan::line("process", 9),
    ));
    let built = twin(rs);
    let d1 = db(&built, "r1", Version::V2);
    assert!(d1.lsas.values().all(|l| l.adv_router != ip("203.0.113.2")));
    assert!(kinds(&built, "r2").contains(&"ospf-unhandled-line".to_string()));
    let c = calc(&built, "r1", "203.0.113.1");
    assert!(!c.gaps.is_empty());
    assert!(c.absent_gap(pfx("203.0.113.4/32")).is_some());
}

#[test]
fn interfaces_in_different_vrfs_or_areas_are_not_neighbours() {
    let mut r2 = v2("203.0.113.2", vec![p2p("eth0", BACKBONE, "192.0.2.2/30")]);
    r2.config.processes[0].vrf = "blue".to_string();
    let built = twin(vec![
        (
            "r1",
            v2("203.0.113.1", vec![p2p("eth0", BACKBONE, "192.0.2.1/30")]),
        ),
        ("r2", r2),
    ]);
    let d1 = db(&built, "r1", Version::V2);
    assert!(d1.neighbors.is_empty());
    assert!(find(d1, LsaType::Router, "203.0.113.2").is_empty());

    let built = twin(vec![
        (
            "r1",
            v2("203.0.113.1", vec![p2p("eth0", BACKBONE, "192.0.2.1/30")]),
        ),
        (
            "r2",
            v2("203.0.113.2", vec![p2p("eth0", AREA1, "192.0.2.2/30")]),
        ),
    ]);
    assert!(db(&built, "r1", Version::V2).neighbors.is_empty());
    assert!(kinds(&built, "r1").contains(&"ospf-adjacency-mismatch".to_string()));
}

fn v3_router(
    rid: &str,
    interfaces: Vec<OspfInterface>,
    link_local: &[(&str, &str)],
) -> RouterInput {
    let mut r = router(
        Platform::Iosxe,
        vec![process(Version::V3, Some(rid), interfaces)],
    );
    for (name, a) in link_local {
        r.link_local
            .insert(name.to_string(), a.parse::<Ipv6Addr>().unwrap());
    }
    r
}

#[test]
fn ospfv3_gives_router_link_intra_area_prefix_and_network_lsas_with_interface_ids() {
    let built = twin(vec![
        (
            "r1",
            v3_router(
                "203.0.113.1",
                vec![
                    p2p("eth0", BACKBONE, "2001:db8::1/64"),
                    lan("eth1", BACKBONE, "2001:db8:1::1/64"),
                ],
                &[("eth0", "fe80::1"), ("eth1", "fe80::11")],
            ),
        ),
        (
            "r2",
            v3_router(
                "203.0.113.2",
                vec![
                    p2p("eth0", BACKBONE, "2001:db8::2/64"),
                    lo(BACKBONE, "2001:db8:ffff::2/128"),
                ],
                &[("eth0", "fe80::2")],
            ),
        ),
        (
            "r3",
            v3_router(
                "203.0.113.3",
                vec![lan("eth1", BACKBONE, "2001:db8:1::3/64")],
                &[("eth1", "fe80::13")],
            ),
        ),
    ]);
    let d1 = db(&built, "r1", Version::V3);
    assert_eq!(
        router_links(d1, BACKBONE, "203.0.113.1"),
        vec![
            RouterLink {
                kind: LinkKind::PointToPoint,
                id: ip("203.0.113.2"),
                data: None,
                metric: 10,
                interface_id: Some(1),
                neighbor_interface_id: Some(1),
            },
            RouterLink {
                kind: LinkKind::Transit,
                id: ip("203.0.113.3"),
                data: None,
                metric: 10,
                interface_id: Some(2),
                neighbor_interface_id: Some(1),
            },
        ]
    );
    let net = find(d1, LsaType::Network, "203.0.113.3");
    assert_eq!(net.len(), 1);
    assert_eq!(net[0].lsid, Ipv4Addr::from(1));
    let prefixes: Vec<&Lsa> = find(d1, LsaType::IntraAreaPrefix, "203.0.113.3");
    assert_eq!(
        prefixes[0].body,
        Body::IntraAreaPrefix {
            reference: Reference::Network(1),
            router: ip("203.0.113.3"),
            prefixes: vec![(pfx("2001:db8:1::/64"), 0)],
        }
    );
    assert_eq!(
        find(d1, LsaType::IntraAreaPrefix, "203.0.113.2")[0].body,
        Body::IntraAreaPrefix {
            reference: Reference::Router,
            router: ip("203.0.113.2"),
            prefixes: vec![(pfx("2001:db8::/64"), 10), (pfx("2001:db8:ffff::2/128"), 0)],
        }
    );
    let links = find(d1, LsaType::Link, "203.0.113.2");
    assert_eq!(
        links[0].body,
        Body::Link {
            address: Some("fe80::2".parse().unwrap()),
            prefixes: vec![pfx("2001:db8::/64")],
            interface: Some("eth0".to_string()),
        }
    );
    assert!(find(d1, LsaType::Link, "203.0.113.1").len() == 2);
    let c = compute(d1, ip("203.0.113.1"), &OspfProfile::of(Platform::Iosxe));
    let r = c.route(pfx("2001:db8:ffff::2/128")).unwrap();
    assert_eq!(r.unknown, None);
    assert_eq!(r.metric, 10);
    assert_eq!(
        r.next_hops,
        vec![NextHop {
            gateway: "fe80::2".parse().unwrap(),
            interface: Some("eth0".to_string()),
        }]
    );
    let d3 = db(&built, "r3", Version::V3);
    let c = compute(d3, ip("203.0.113.3"), &OspfProfile::of(Platform::Iosxe));
    let r = c.route(pfx("2001:db8:ffff::2/128")).unwrap();
    assert_eq!(r.metric, 20);
    assert_eq!(
        r.next_hops[0].gateway,
        "fe80::11".parse::<IpAddr>().unwrap()
    );
    let devices: BTreeSet<&str> = built.databases.keys().map(|k| k.0.as_str()).collect();
    assert_eq!(devices.len(), 3);
}

#[test]
fn the_build_is_deterministic() {
    let a = asbr_chain(AreaType::Normal);
    let b = asbr_chain(AreaType::Normal);
    assert_eq!(a, b);
}

#[test]
fn a_stub_area_gets_no_as_external_lsa_and_no_asbr_summary() {
    let mut rs = chain(AreaType::Normal, false);
    for r in [0, 1] {
        rs[r].1.config.processes[0]
            .areas
            .get_mut(&AREA1)
            .unwrap()
            .kind = AreaType::Stub;
    }
    let r4 = &mut rs[3].1;
    r4.config.processes[0].redistribute = vec![redistribute(Source::Connected, None, None)];
    r4.connected
        .insert("default".to_string(), vec![pfx("198.51.100.128/25")]);
    let built = twin(rs);
    let d1 = db(&built, "r1", Version::V2);
    assert!(
        d1.lsas
            .values()
            .all(|l| !matches!(l.lsa_type, LsaType::External | LsaType::AsbrSummary))
    );
    assert_eq!(
        summaries(d1, "203.0.113.2").get(&pfx("0.0.0.0/0")),
        Some(&1)
    );
    assert_eq!(
        find(
            db(&built, "r2", Version::V2),
            LsaType::External,
            "203.0.113.4"
        )
        .len(),
        1
    );
}

#[test]
fn two_prefixes_with_one_network_address_get_the_link_state_ids_of_rfc_2328_appendix_e() {
    let mut r = v2("203.0.113.1", vec![p2p("eth0", BACKBONE, "192.0.2.1/30")]);
    r.config.processes[0].redistribute = vec![redistribute(Source::Static, None, None)];
    r.statics.insert(
        "default".to_string(),
        vec![pfx("198.51.100.0/24"), pfx("198.51.100.0/25")],
    );
    let built = twin(vec![("r1", r)]);
    let ids: Vec<(Ipv4Addr, Prefix)> = find(
        db(&built, "r1", Version::V2),
        LsaType::External,
        "203.0.113.1",
    )
    .into_iter()
    .filter_map(|l| match l.body {
        Body::External { prefix, .. } => Some((l.lsid, prefix)),
        _ => None,
    })
    .collect();
    assert_eq!(
        ids,
        vec![
            (ip("198.51.100.0"), pfx("198.51.100.0/24")),
            (ip("198.51.100.127"), pfx("198.51.100.0/25")),
        ]
    );
}

#[test]
fn an_as_external_lsa_reaches_only_the_routers_of_the_same_as() {
    let mut r9 = v2("203.0.113.9", vec![p2p("eth0", BACKBONE, "192.0.2.13/30")]);
    r9.config.processes[0].default_originate = Some(DefaultOriginate {
        always: true,
        metric: None,
        metric_type: None,
        route_map: None,
        span: SourceSpan::line("default", 1),
    });
    let built = twin(vec![
        (
            "r1",
            v2("203.0.113.1", vec![p2p("eth0", BACKBONE, "192.0.2.1/30")]),
        ),
        (
            "r2",
            v2("203.0.113.2", vec![p2p("eth0", BACKBONE, "192.0.2.2/30")]),
        ),
        ("r9", r9),
    ]);
    assert!(
        find(
            db(&built, "r1", Version::V2),
            LsaType::External,
            "203.0.113.9"
        )
        .is_empty()
    );
    assert_eq!(
        find(
            db(&built, "r9", Version::V2),
            LsaType::External,
            "203.0.113.9"
        )
        .len(),
        1
    );
}

#[test]
fn ospfv3_area_border_routers_and_asbrs_give_inter_area_prefix_inter_area_router_and_as_external_lsas()
 {
    let ll = |s: &str| {
        [
            ("eth0", format!("fe80::{s}0")),
            ("eth1", format!("fe80::{s}1")),
        ]
    };
    let make = |rid: &str, n: &str, interfaces: Vec<OspfInterface>| {
        let l = ll(n);
        v3_router(
            rid,
            interfaces,
            &[(l[0].0, l[0].1.as_str()), (l[1].0, l[1].1.as_str())],
        )
    };
    let mut r4 = make(
        "203.0.113.4",
        "4",
        vec![
            p2p("eth0", AREA2, "2001:db8:0:3::2/64"),
            lo(AREA2, "2001:db8:ffff::4/128"),
        ],
    );
    r4.config.processes[0].redistribute = vec![redistribute(Source::Connected, None, None)];
    r4.connected.insert(
        "default".to_string(),
        vec![pfx("2001:db8:ffff::4/128"), pfx("2001:db8:abcd::/48")],
    );
    let built = twin(vec![
        (
            "r1",
            make(
                "203.0.113.1",
                "1",
                vec![
                    p2p("eth0", AREA1, "2001:db8:0:1::1/64"),
                    lo(AREA1, "2001:db8:ffff::1/128"),
                ],
            ),
        ),
        (
            "r2",
            make(
                "203.0.113.2",
                "2",
                vec![
                    p2p("eth0", AREA1, "2001:db8:0:1::2/64"),
                    p2p("eth1", BACKBONE, "2001:db8:0:2::1/64"),
                ],
            ),
        ),
        (
            "r3",
            make(
                "203.0.113.3",
                "3",
                vec![
                    p2p("eth0", BACKBONE, "2001:db8:0:2::2/64"),
                    p2p("eth1", AREA2, "2001:db8:0:3::1/64"),
                ],
            ),
        ),
        ("r4", r4),
    ]);
    let d1 = db(&built, "r1", Version::V3);
    let ids: Vec<(Ipv4Addr, Prefix, u32)> = find(d1, LsaType::Summary, "203.0.113.2")
        .into_iter()
        .filter_map(|l| match l.body {
            Body::Summary { prefix, metric } => Some((l.lsid, prefix, metric)),
            _ => None,
        })
        .collect();
    assert_eq!(
        ids,
        vec![
            (Ipv4Addr::from(0), pfx("2001:db8:0:2::/64"), 10),
            (Ipv4Addr::from(1), pfx("2001:db8:0:3::/64"), 20),
            (Ipv4Addr::from(2), pfx("2001:db8:ffff::4/128"), 20),
        ]
    );
    let asbr = find(d1, LsaType::AsbrSummary, "203.0.113.2");
    assert_eq!(asbr.len(), 1);
    assert_eq!(asbr[0].lsid, ip("203.0.113.4"));
    let ext = find(d1, LsaType::External, "203.0.113.4");
    assert_eq!(ext.len(), 1);
    assert_eq!(ext[0].lsid, Ipv4Addr::from(0));
    let c = compute(d1, ip("203.0.113.1"), &OspfProfile::of(Platform::Iosxe));
    let hop = NextHop {
        gateway: "fe80::20".parse().unwrap(),
        interface: Some("eth0".to_string()),
    };
    let r = c.route(pfx("2001:db8:ffff::4/128")).unwrap();
    assert_eq!(
        (
            r.path_type,
            r.metric,
            r.unknown.clone(),
            r.next_hops.clone()
        ),
        (PathType::InterArea, 30, None, vec![hop.clone()])
    );
    let r = c.route(pfx("2001:db8:abcd::/48")).unwrap();
    assert_eq!(
        (
            r.path_type,
            r.metric,
            r.unknown.clone(),
            r.next_hops.clone()
        ),
        (PathType::External2, 20, None, vec![hop])
    );
}
