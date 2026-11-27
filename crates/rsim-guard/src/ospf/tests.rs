use super::*;

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn p(s: &str) -> Prefix {
    s.parse().unwrap()
}

fn lsa(lsa_type: LsaType, area: Option<&str>, lsid: &str, adv: &str, body: Body, line: u32) -> Lsa {
    Lsa {
        lsa_type,
        area: area.map(ip),
        lsid: ip(lsid),
        adv_router: ip(adv),
        seq: Some(0x8000_0000 + line),
        age: Some(line),
        body,
        span: SourceSpan::new("r1/ospf", line, line),
    }
}

fn db(version: Version, lsas: Vec<Lsa>) -> Database {
    let mut d = Database::new(version, "default", "1");
    for l in lsas {
        d.insert(l);
    }
    d
}

fn link(kind: LinkKind, id: &str, data: Option<&str>, metric: u32) -> RouterLink {
    RouterLink {
        kind,
        id: ip(id),
        data: data.map(ip),
        metric,
        interface_id: None,
        neighbor_interface_id: None,
    }
}

fn v3_link(kind: LinkKind, id: &str, metric: u32, own: u32, theirs: u32) -> RouterLink {
    RouterLink {
        kind,
        id: ip(id),
        data: None,
        metric,
        interface_id: Some(own),
        neighbor_interface_id: Some(theirs),
    }
}

fn router(area: &str, adv: &str, links: Vec<RouterLink>, line: u32) -> Lsa {
    lsa(
        LsaType::Router,
        Some(area),
        adv,
        adv,
        Body::Router { links },
        line,
    )
}

fn network(area: &str, lsid: &str, adv: &str, mask: Option<&str>, attached: &[&str]) -> Lsa {
    lsa(
        LsaType::Network,
        Some(area),
        lsid,
        adv,
        Body::Network {
            mask: mask.map(ip),
            attached: attached.iter().map(|a| ip(a)).collect(),
        },
        20,
    )
}

fn external(
    t: LsaType,
    area: Option<&str>,
    prefix: &str,
    adv: &str,
    metric: u32,
    metric_type: u8,
    fwd: Option<&str>,
) -> Lsa {
    lsa(
        t,
        area,
        &p(prefix).addr().to_string(),
        adv,
        Body::External {
            prefix: p(prefix),
            metric,
            metric_type: Some(metric_type),
            forwarding: fwd.map(|f| f.parse().unwrap()),
        },
        30,
    )
}

fn categories(rows: &[LsaRow]) -> Vec<(&str, Category)> {
    rows.iter().map(|r| (r.key.as_str(), r.category)).collect()
}

const A0: &str = "0.0.0.0";
const R1: &str = "198.51.100.1";
const R2: &str = "198.51.100.2";
const R3: &str = "198.51.100.3";

#[test]
fn a_router_lsa_with_the_same_links_matches_with_a_different_age_and_sequence() {
    let links = || {
        vec![
            link(LinkKind::Stub, "203.0.113.0", Some("255.255.255.0"), 10),
            link(LinkKind::PointToPoint, R2, Some("192.0.2.1"), 5),
        ]
    };
    let built = db(Version::V2, vec![router(A0, R1, links(), 1)]);
    let mut theirs = links();
    theirs.reverse();
    let collected = db(Version::V2, vec![router(A0, R1, theirs, 7)]);
    let rows = compare_databases(&built, &collected);
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(r.category, Category::Match);
    assert_eq!(r.lsa_type, LsaType::Router);
    assert_eq!(r.area, Some(ip(A0)));
    assert_eq!(r.vrf, "default");
    assert_eq!(r.version, Version::V2);
    assert_eq!(r.key, R1);
    assert_eq!(r.built, r.collected);
    assert_eq!(
        r.built.as_deref(),
        Some(
            "links point-to-point 198.51.100.2 data 192.0.2.1 metric 5, \
             stub 203.0.113.0 data 255.255.255.0 metric 10"
        )
    );
    assert_eq!(r.built_spans, vec![SourceSpan::new("r1/ospf", 1, 1)]);
    assert_eq!(r.collected_spans, vec![SourceSpan::new("r1/ospf", 7, 7)]);
}

#[test]
fn a_different_designated_router_is_not_a_difference_in_ospfv2() {
    let mask = Some("255.255.255.0");
    let built = db(
        Version::V2,
        vec![
            router(
                A0,
                R1,
                vec![link(LinkKind::Transit, "192.0.2.1", Some("192.0.2.1"), 10)],
                1,
            ),
            router(
                A0,
                R2,
                vec![link(LinkKind::Transit, "192.0.2.1", Some("192.0.2.2"), 10)],
                2,
            ),
            network(A0, "192.0.2.1", R1, mask, &[R1, R2]),
        ],
    );
    let collected = db(
        Version::V2,
        vec![
            router(
                A0,
                R1,
                vec![link(LinkKind::Transit, "192.0.2.2", Some("192.0.2.1"), 10)],
                1,
            ),
            router(
                A0,
                R2,
                vec![link(LinkKind::Transit, "192.0.2.2", Some("192.0.2.2"), 10)],
                2,
            ),
            network(A0, "192.0.2.2", R2, mask, &[R2, R1]),
        ],
    );
    let rows = compare_databases(&built, &collected);
    assert_eq!(
        categories(&rows),
        vec![
            (R1, Category::Match),
            (R2, Category::Match),
            ("192.0.2.0/24", Category::Match),
        ]
    );
    assert_eq!(
        rows[0].built.as_deref(),
        Some("links transit 192.0.2.0/24 data 192.0.2.1 metric 10")
    );
}

#[test]
fn a_transit_link_with_no_network_lsa_maps_by_the_link_data_or_keeps_the_designated_router() {
    let built = db(
        Version::V2,
        vec![
            router(
                A0,
                R1,
                vec![link(LinkKind::Transit, "192.0.2.9", Some("192.0.2.1"), 10)],
                1,
            ),
            network(A0, "192.0.2.2", R2, Some("255.255.255.0"), &[R1, R2]),
        ],
    );
    let collected = db(
        Version::V2,
        vec![router(
            A0,
            R1,
            vec![link(LinkKind::Transit, "192.0.2.9", Some("192.0.2.1"), 10)],
            1,
        )],
    );
    let rows = compare_databases(&built, &collected);
    assert_eq!(rows[0].category, Category::Differ);
    assert_eq!(rows[0].fields, vec!["links"]);
    assert_eq!(
        rows[0].built.as_deref(),
        Some("links transit 192.0.2.0/24 data 192.0.2.1 metric 10")
    );
    assert_eq!(
        rows[0].collected.as_deref(),
        Some("links transit dr 192.0.2.9 data 192.0.2.1 metric 10")
    );
    assert_eq!(rows[1].category, Category::OnlyBuilt);
}

#[test]
fn a_router_lsa_with_another_metric_differs_in_its_links() {
    let built = db(
        Version::V2,
        vec![router(
            A0,
            R1,
            vec![link(LinkKind::PointToPoint, R2, Some("192.0.2.1"), 10)],
            1,
        )],
    );
    let collected = db(
        Version::V2,
        vec![router(
            A0,
            R1,
            vec![link(LinkKind::PointToPoint, R2, Some("192.0.2.1"), 20)],
            1,
        )],
    );
    let rows = compare_databases(&built, &collected);
    assert_eq!(rows[0].category, Category::Differ);
    assert_eq!(rows[0].fields, vec!["links"]);
    assert_eq!(
        rows[0].collected.as_deref(),
        Some("links point-to-point 198.51.100.2 data 192.0.2.1 metric 20")
    );
}

#[test]
fn a_network_lsa_has_the_key_of_its_subnet_and_compares_the_attached_routers() {
    let mask = Some("255.255.255.0");
    let built = db(
        Version::V2,
        vec![network(A0, "192.0.2.1", R1, mask, &[R1, R2])],
    );
    let collected = db(
        Version::V2,
        vec![network(A0, "192.0.2.1", R1, mask, &[R1, R2, R3])],
    );
    let rows = compare_databases(&built, &collected);
    assert_eq!(categories(&rows), vec![("192.0.2.0/24", Category::Differ)]);
    assert_eq!(rows[0].fields, vec!["attached"]);
    assert_eq!(
        rows[0].built.as_deref(),
        Some("attached 198.51.100.1, 198.51.100.2")
    );
}

#[test]
fn a_summary_lsa_compares_the_metric_and_an_asbr_summary_lsa_matches() {
    let summary = |metric| {
        lsa(
            LsaType::Summary,
            Some("0.0.0.1"),
            "203.0.113.0",
            R1,
            Body::Summary {
                prefix: p("203.0.113.0/24"),
                metric,
            },
            3,
        )
    };
    let asbr = lsa(
        LsaType::AsbrSummary,
        Some("0.0.0.1"),
        R3,
        R1,
        Body::AsbrSummary {
            router: ip(R3),
            metric: 15,
        },
        4,
    );
    let built = db(Version::V2, vec![summary(10), asbr.clone()]);
    let collected = db(Version::V2, vec![summary(11), asbr]);
    let rows = compare_databases(&built, &collected);
    assert_eq!(
        categories(&rows),
        vec![
            ("203.0.113.0/24 from 198.51.100.1", Category::Differ),
            ("198.51.100.3 from 198.51.100.1", Category::Match),
        ]
    );
    assert_eq!(rows[0].fields, vec!["metric"]);
    assert_eq!(rows[0].built.as_deref(), Some("metric 10"));
    assert_eq!(rows[0].collected.as_deref(), Some("metric 11"));
}

#[test]
fn an_external_lsa_compares_the_metric_the_metric_type_and_the_forwarding_address() {
    let built = db(
        Version::V2,
        vec![
            external(LsaType::External, None, "203.0.113.0/24", R1, 20, 2, None),
            external(
                LsaType::External,
                None,
                "198.51.100.128/25",
                R1,
                20,
                2,
                None,
            ),
            external(
                LsaType::NssaExternal,
                Some("0.0.0.2"),
                "192.0.2.128/25",
                R2,
                5,
                1,
                Some("192.0.2.2"),
            ),
        ],
    );
    let collected = db(
        Version::V2,
        vec![
            external(
                LsaType::External,
                None,
                "203.0.113.0/24",
                R1,
                20,
                1,
                Some("192.0.2.7"),
            ),
            external(
                LsaType::External,
                None,
                "198.51.100.128/25",
                R1,
                20,
                2,
                Some("0.0.0.0"),
            ),
            external(
                LsaType::NssaExternal,
                Some("0.0.0.2"),
                "192.0.2.128/25",
                R2,
                5,
                1,
                Some("192.0.2.2"),
            ),
        ],
    );
    let rows = compare_databases(&built, &collected);
    assert_eq!(
        categories(&rows),
        vec![
            ("192.0.2.128/25 from 198.51.100.2", Category::Match),
            ("198.51.100.128/25 from 198.51.100.1", Category::Match),
            ("203.0.113.0/24 from 198.51.100.1", Category::Differ),
        ]
    );
    assert_eq!(rows[0].lsa_type, LsaType::NssaExternal);
    assert_eq!(rows[1].area, None);
    assert_eq!(rows[2].fields, vec!["metric_type", "forwarding"]);
    assert_eq!(
        rows[2].built.as_deref(),
        Some("metric 20; metric_type 2; forwarding none")
    );
    assert_eq!(
        rows[2].collected.as_deref(),
        Some("metric 20; metric_type 1; forwarding 192.0.2.7")
    );
}

#[test]
fn each_category_is_counted_and_the_rate_holds_all_rows() {
    let p2p = |m| vec![link(LinkKind::PointToPoint, R2, Some("192.0.2.1"), m)];
    let mut expired = router(A0, R3, p2p(1), 9);
    expired.age = Some(3600);
    let built = db(
        Version::V2,
        vec![router(A0, R1, p2p(1), 1), router(A0, R2, p2p(1), 2)],
    );
    let collected = db(
        Version::V2,
        vec![
            router(A0, R1, p2p(1), 1),
            router(A0, R2, p2p(2), 2),
            external(LsaType::External, None, "203.0.113.0/24", R1, 20, 2, None),
            expired,
        ],
    );
    let built = {
        let mut b = built;
        b.insert(router("0.0.0.1", R1, p2p(1), 3));
        b
    };
    let rows = compare_databases(&built, &collected);
    assert_eq!(
        categories(&rows),
        vec![
            (R1, Category::Match),
            (R2, Category::Differ),
            (R1, Category::OnlyBuilt),
            ("203.0.113.0/24 from 198.51.100.1", Category::OnlyCollected),
        ]
    );
    assert_eq!(rows[2].area, Some(ip("0.0.0.1")));
    assert_eq!(rows[2].collected, None);
    assert!(rows[2].collected_spans.is_empty());
    assert_eq!(rows[3].built, None);
    let counts = Counts::of(&rows);
    assert_eq!(
        counts,
        Counts {
            matched: 1,
            differ: 1,
            only_built: 1,
            only_collected: 1,
        }
    );
    assert_eq!(counts.rate(), Some(25.0));
    assert_eq!(Counts::default().rate(), None);
    assert_eq!(Category::OnlyBuilt.name(), "only_built");
    assert_eq!(Category::OnlyCollected.name(), "only_collected");
}

fn v3_network(adv: &str, id: u32, attached: &[&str]) -> Lsa {
    let mut l = network(A0, A0, adv, None, attached);
    l.lsid = Ipv4Addr::from(id);
    l
}

fn iap(reference: Reference, router: &str, adv: &str, lsid: u32, prefixes: &[(&str, u32)]) -> Lsa {
    let mut l = lsa(
        LsaType::IntraAreaPrefix,
        Some(A0),
        A0,
        adv,
        Body::IntraAreaPrefix {
            reference,
            router: ip(router),
            prefixes: prefixes.iter().map(|(x, m)| (p(x), *m)).collect(),
        },
        40,
    );
    l.lsid = Ipv4Addr::from(lsid);
    l
}

fn link_lsa(adv: &str, interface: &str, prefixes: &[&str]) -> Lsa {
    lsa(
        LsaType::Link,
        Some(A0),
        "0.0.0.5",
        adv,
        Body::Link {
            address: Some("fe80::1".parse().unwrap()),
            prefixes: prefixes.iter().map(|x| p(x)).collect(),
            interface: Some(interface.to_string()),
        },
        50,
    )
}

/// The OSPFv3 database of 2 routers on one transit link with `dr` as the
/// designated router with the interface ID `id`.
fn v3_segment(dr: &str, id: u32, metric: u32, link_prefix: &str) -> Database {
    db(
        Version::V3,
        vec![
            router(
                A0,
                R1,
                vec![v3_link(LinkKind::Transit, dr, metric, 3, id)],
                1,
            ),
            router(A0, R2, vec![v3_link(LinkKind::Transit, dr, 10, 4, id)], 2),
            v3_network(dr, id, &[R1, R2]),
            iap(Reference::Network(id), dr, dr, 1, &[("2001:db8:1::/64", 0)]),
            iap(Reference::Router, R1, R1, 2, &[("2001:db8:ff::1/128", 0)]),
            link_lsa(R2, "eth0", &[link_prefix]),
        ],
    )
}

#[test]
fn ospfv3_lsas_match_with_a_different_designated_router_and_interface_ids() {
    let built = v3_segment(R1, 3, 10, "2001:db8:1::/64");
    let collected = v3_segment(R2, 4, 10, "2001:db8:1::/64");
    let rows = compare_databases(&built, &collected);
    assert_eq!(
        categories(&rows),
        vec![
            (R1, Category::Match),
            (R2, Category::Match),
            ("2001:db8:1::/64", Category::Match),
            ("198.51.100.2 on eth0", Category::Match),
            (R1, Category::Match),
            ("network of 198.51.100.1 198.51.100.2", Category::Match),
        ]
    );
    assert!(rows.iter().all(|r| r.version == Version::V3));
    assert_eq!(
        rows[0].built.as_deref(),
        Some("links transit network of 198.51.100.1 198.51.100.2 metric 10")
    );
    assert_eq!(
        rows[5].built.as_deref(),
        Some("prefixes 2001:db8:1::/64 metric 0")
    );
}

#[test]
fn ospfv3_lsas_differ_in_the_router_metric_and_the_link_prefixes() {
    let built = v3_segment(R1, 3, 10, "2001:db8:1::/64");
    let collected = v3_segment(R1, 3, 20, "2001:db8:2::/64");
    let rows = compare_databases(&built, &collected);
    let differ: Vec<(&str, LsaType, &[&str])> = rows
        .iter()
        .filter(|r| r.category == Category::Differ)
        .map(|r| (r.key.as_str(), r.lsa_type, r.fields.as_slice()))
        .collect();
    assert_eq!(
        differ,
        vec![
            (R1, LsaType::Router, &["links"][..]),
            ("198.51.100.2 on eth0", LsaType::Link, &["prefixes"][..]),
        ]
    );
}

#[test]
fn an_ospfv3_intra_area_prefix_lsa_compares_the_prefixes_with_their_metrics() {
    let built = db(
        Version::V3,
        vec![iap(
            Reference::Router,
            R1,
            R1,
            0,
            &[("2001:db8:ff::1/128", 0)],
        )],
    );
    let collected = db(
        Version::V3,
        vec![
            iap(Reference::Router, R1, R1, 0, &[("2001:db8:ff::1/128", 1)]),
            iap(Reference::Router, R1, R1, 1, &[("2001:db8:fe::/64", 10)]),
        ],
    );
    let rows = compare_databases(&built, &collected);
    assert_eq!(categories(&rows), vec![(R1, Category::Differ)]);
    assert_eq!(rows[0].fields, vec!["prefixes"]);
    assert_eq!(
        rows[0].collected.as_deref(),
        Some("prefixes 2001:db8:fe::/64 metric 10, 2001:db8:ff::1/128 metric 1")
    );
    assert_eq!(rows[0].collected_spans.len(), 2);
}
