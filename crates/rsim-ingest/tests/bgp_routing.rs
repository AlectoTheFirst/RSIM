//! The BGP calculation of the estate on the synthetic NX-OS switch n1 and
//! the IOS-XR routers x1, x2 and x3 of `tests/fixtures/bgp/`:
//!
//! | Session | Kind |
//! |---|---|
//! | n1 198.51.100.1 to x1 198.51.100.2 | eBGP, AS 64501 to AS 64502 |
//! | x1 192.0.2.1 to x2 192.0.2.2 | iBGP over the loopbacks and OSPF, x2 a client of the reflector x1 |
//! | x1 192.0.2.1 to x3 192.0.2.3 | iBGP over the loopbacks and OSPF, x3 a client of the reflector x1 |
//! | n1 203.0.113.1 to 203.0.113.2 | eBGP to a peer outside the twin, AS 64499 |
//!
//! n1 originates 203.0.113.64/26 and 203.0.113.128/26, and x2 originates
//! 192.0.2.64/27 and 203.0.113.128/26. The import policy of x1 from n1 sets
//! the local preference 200 for 203.0.113.128/26. The collected route of
//! 198.51.100.128/25 of n1 comes from the peer outside the twin, and the
//! tables of that peer in `n1-routes.json` hold it and 192.0.2.128/25,
//! which the import policy of n1 denies.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{Header, PROTO_TCP};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_guard::Category;
use rsim_ingest::bgp::Collected as Section;
use rsim_ingest::collected::{Collected, RouteRow, row_span};
use rsim_ingest::estate::{Estate, Input, assemble, assemble_scenario, assemble_with};
use rsim_ingest::scenario::{Layer, NOT_RECOMPUTED};

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/bgp/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path).unwrap()
}

/// The collected route rows of n1: the prefix, the protocol, the next hop
/// and the interface.
type Row = (
    &'static str,
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
);

const N1_ROUTES: &[Row] = &[
    ("198.51.100.0/30", "direct", None, Some("Ethernet1/1")),
    ("198.51.100.1/32", "local", None, Some("Ethernet1/1")),
    ("203.0.113.0/30", "direct", None, Some("Ethernet1/2")),
    ("203.0.113.1/32", "local", None, Some("Ethernet1/2")),
    ("203.0.113.64/26", "direct", None, Some("Ethernet1/3")),
    ("203.0.113.65/32", "local", None, Some("Ethernet1/3")),
    ("203.0.113.128/26", "static", None, Some("Null0")),
    (
        "192.0.2.64/27",
        "bgp-64501",
        Some("198.51.100.2"),
        Some("Ethernet1/1"),
    ),
    (
        "198.51.100.128/25",
        "bgp-64501",
        Some("203.0.113.2"),
        Some("Ethernet1/2"),
    ),
];

fn inputs_with(n1: &str, x1: &str) -> Vec<Input> {
    let routes = N1_ROUTES
        .iter()
        .enumerate()
        .map(|(i, (prefix, protocol, hop, iface))| RouteRow {
            vrf: "default".into(),
            prefix: (*prefix).to_string(),
            protocol: (*protocol).to_string(),
            selected: true,
            next_hop: hop.map(str::to_string),
            interface: iface.map(str::to_string),
            span: row_span("n1", "routes", "b1", i as u64),
        })
        .collect();
    let mut out = vec![Input::Nxos {
        name: "n1".into(),
        config: n1.as_bytes().to_vec(),
        file: "n1/config".into(),
        collected: Collected {
            routes,
            ..Collected::default()
        },
        sections: BTreeMap::new(),
    }];
    for x in ["x1", "x2", "x3"] {
        let config = if x == "x1" {
            x1.to_string()
        } else {
            fixture(&format!("{x}-config.txt"))
        };
        out.push(Input::Iosxr {
            name: x.into(),
            config: config.into_bytes(),
            file: format!("{x}/config"),
            collected: Collected::default(),
            sections: BTreeMap::from([(
                "rib".to_string(),
                (
                    fixture(&format!("{x}-rib.txt")).into_bytes(),
                    format!("{x}/rib"),
                ),
            )]),
        });
    }
    out
}

fn inputs() -> Vec<Input> {
    inputs_with(&fixture("n1-config.txt"), &fixture("x1-config.txt"))
}

/// The guard row of `prefix` of `device`: the category, the reason and the
/// next hops of the computed route.
fn row(e: &Estate, device: &str, prefix: &str) -> (Category, String, Vec<String>) {
    let r = e.guard[device]
        .iter()
        .find(|r| r.vrf == "default" && r.prefix.to_string() == prefix)
        .unwrap_or_else(|| panic!("{device} {prefix} not in {:#?}", e.guard[device]));
    (
        r.category,
        r.reason.clone(),
        r.computed
            .as_ref()
            .map(|v| v.next_hops.clone())
            .unwrap_or_default(),
    )
}

/// The BGP routes of the twin with their devices.
const BGP_ROUTES: &[(&str, &str)] = &[
    ("n1", "192.0.2.64/27"),
    ("x1", "192.0.2.64/27"),
    ("x1", "198.51.100.128/25"),
    ("x1", "203.0.113.64/26"),
    ("x1", "203.0.113.128/26"),
    ("x2", "198.51.100.128/25"),
    ("x2", "203.0.113.64/26"),
    ("x3", "192.0.2.64/27"),
    ("x3", "198.51.100.128/25"),
    ("x3", "203.0.113.64/26"),
    ("x3", "203.0.113.128/26"),
];

#[test]
fn the_ebgp_pair_the_loopback_sessions_and_the_reflector_explain_each_bgp_route() {
    let e = assemble(inputs());
    for (d, p) in BGP_ROUTES {
        let r = row(&e, d, p);
        assert_eq!(
            r.0,
            Category::Match,
            "{d} {p}: {r:?}\n{:#?}",
            e.notes.get("estate")
        );
    }
    // x3 reaches the route of the client x2 through the reflector, with the
    // next hop of x2 over OSPF.
    assert_eq!(
        row(&e, "x3", "192.0.2.64/27").2,
        ["198.51.100.9@TenGigE0/0/0/0"]
    );
    let b = e.bgp_routing.as_ref().expect("a BGP calculation");
    assert_eq!(b.input.sessions.len(), 3);
    assert!(b.gaps.is_empty(), "{:?}", b.gaps);
    for list in e.unread.values() {
        assert_eq!(list, &Vec::<String>::new());
    }
}

#[test]
fn a_route_from_a_peer_outside_the_twin_is_a_seed() {
    let e = assemble(inputs());
    assert_eq!(row(&e, "n1", "198.51.100.128/25").0, Category::Seeded);
    let b = e.bgp_routing.as_ref().unwrap();
    assert_eq!(b.input.seeds.len(), 1);
    let s = &b.input.seeds[0];
    assert_eq!(s.neighbor, "203.0.113.2".parse::<IpAddr>().unwrap());
    assert!(!s.path.attributes_collected);
    // The seed reaches x2 through x1, with the next hop of x1.
    assert_eq!(
        row(&e, "x2", "198.51.100.128/25").2,
        ["198.51.100.5@TenGigE0/0/0/0"]
    );
}

#[test]
fn the_received_table_of_a_peer_outside_the_twin_goes_through_the_import_policy() {
    let e = assemble_with(inputs(), &n1_tables(&[]));
    let b = e.bgp_routing.as_ref().unwrap();
    assert_eq!(b.input.seeds.len(), 2);
    for s in &b.input.seeds {
        assert!(s.received && s.path.attributes_collected, "{s:?}");
    }
    assert_eq!(row(&e, "n1", "198.51.100.128/25").0, Category::Seeded);
    assert_eq!(row(&e, "x2", "198.51.100.128/25").0, Category::Match);
    // The import policy of n1 denies 192.0.2.128/25, so no device has it.
    for rows in e.guard.values() {
        assert!(
            rows.iter()
                .all(|r| r.prefix.to_string() != "192.0.2.128/25")
        );
    }
}

/// The tables of n1 of `n1-routes.json` with the answer of each direction
/// of `empty` replaced by an empty table.
fn n1_tables(empty: &[&str]) -> BTreeMap<String, BTreeMap<String, Section>> {
    let mut v: serde_json::Value = serde_json::from_str(&fixture("n1-routes.json")).unwrap();
    for d in empty {
        v["default"]["203.0.113.2"][*d]["answer"] = serde_json::json!({});
    }
    let section = Section::Fresh(v.to_string().into_bytes(), "n1/bgp_routes".into());
    BTreeMap::from([(
        "n1".to_string(),
        BTreeMap::from([(rsim_ingest::bgp_routes::ROUTES.to_string(), section)]),
    )])
}

#[test]
fn a_table_that_lacks_a_collected_route_of_its_peer_is_not_a_source_of_seeds() {
    // An empty received table, as of a neighbour with no soft
    // reconfiguration, leaves the accepted table as the source.
    let e = assemble_with(inputs(), &n1_tables(&["received-routes"]));
    let seeds = &e.bgp_routing.as_ref().unwrap().input.seeds;
    assert_eq!(seeds.len(), 1, "{seeds:?}");
    assert!(!seeds[0].received && seeds[0].path.attributes_collected);
    assert_eq!(row(&e, "n1", "198.51.100.128/25").0, Category::Seeded);
    // With both tables empty, the collected route is the seed.
    let e = assemble_with(inputs(), &n1_tables(&["received-routes", "routes"]));
    let seeds = &e.bgp_routing.as_ref().unwrap().input.seeds;
    assert_eq!(seeds.len(), 1, "{seeds:?}");
    assert!(!seeds[0].received && !seeds[0].path.attributes_collected);
    assert_eq!(row(&e, "n1", "198.51.100.128/25").0, Category::Seeded);
}

#[test]
fn the_import_policy_of_x1_selects_the_path_of_n1_by_the_local_preference() {
    let e = assemble(inputs());
    assert_eq!(
        row(&e, "x1", "203.0.113.128/26").2,
        ["198.51.100.1@TenGigE0/0/0/0"]
    );
    // With no local preference, the shorter AS path of x2 wins, and the
    // computed route differs from the collected route.
    let x1 = fixture("x1-config.txt").replace("    set local-preference 200\n", "");
    let e = assemble(inputs_with(&fixture("n1-config.txt"), &x1));
    let r = row(&e, "x1", "203.0.113.128/26");
    assert_eq!(r.0, Category::Differ, "{r:?}");
    assert_eq!(r.2, ["198.51.100.6@TenGigE0/0/0/1"]);
}

#[test]
fn a_redistribution_on_n1_makes_each_bgp_route_of_its_component_not_computed() {
    let n1 = fixture("n1-config.txt").replace(
        "    network 203.0.113.128/26\n",
        "    network 203.0.113.128/26\n    redistribute direct route-map FROM-ISP\n",
    );
    let e = assemble(inputs_with(&n1, &fixture("x1-config.txt")));
    for (d, p) in BGP_ROUTES {
        let r = row(&e, d, p);
        assert_eq!(r.0, Category::NotComputed, "{d} {p}: {r:?}");
        assert_eq!(
            r.1, "bgp gap: redistribute direct route-map FROM-ISP on n1",
            "{d} {p}"
        );
    }
    assert_eq!(row(&e, "n1", "198.51.100.128/25").0, Category::Seeded);
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// The reason of the route lookup step of x3 for a packet from x1 to
/// 203.0.113.70 that enters x3 on its port to x1.
fn x3_lookup(t: &Twin) -> String {
    let h = Header::request(ip("198.51.100.9"), ip("203.0.113.70"), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(22);
    let q = Query::path(t, &h)
        .with_ingress("x3", "TenGigE0/0/0/0")
        .without_reply();
    let a: Answer = Executor::new(t).run(&q).expect("the query runs");
    a.branches()
        .iter()
        .flat_map(|b| &b.steps)
        .find(|s| s.function.to_string() == "x3/route")
        .map(|s| s.reason.detail.clone())
        .unwrap_or_else(|| panic!("no route lookup of x3"))
}

#[test]
fn a_bgp_route_that_matches_in_the_base_stays_unknown_in_a_scenario() {
    let base = assemble(inputs());
    assert_eq!(row(&base, "x3", "203.0.113.64/26").0, Category::Match);
    let t = base.builder.build().expect("the twin builds");
    let detail = x3_lookup(&t);
    assert!(!detail.contains(NOT_RECOMPUTED), "{detail}");
    let layers = [Layer::link_down("n1:Ethernet1/3").unwrap()];
    let s = assemble_scenario(inputs(), &BTreeMap::new(), &layers).expect("the scenario builds");
    assert_eq!(s.guard, assemble(inputs()).guard);
    let t = s.builder.build().expect("the twin builds");
    let detail = x3_lookup(&t);
    assert!(detail.contains(NOT_RECOMPUTED), "{detail}");
}
