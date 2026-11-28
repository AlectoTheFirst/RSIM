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
fn a_redistribution_that_is_not_lowered_on_n1_makes_each_bgp_route_of_its_component_not_computed() {
    let n1 = fixture("n1-config.txt").replace(
        "    network 203.0.113.128/26\n",
        "    network 203.0.113.128/26\n    redistribute eigrp 1 route-map FROM-ISP\n",
    );
    let e = assemble(inputs_with(&n1, &fixture("x1-config.txt")));
    for (d, p) in BGP_ROUTES {
        let r = row(&e, d, p);
        assert_eq!(r.0, Category::NotComputed, "{d} {p}: {r:?}");
        assert_eq!(
            r.1, "bgp gap: redistribute eigrp 1 route-map FROM-ISP on n1",
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

#[test]
fn a_reflected_route_of_a_client_with_no_router_id_makes_its_group_not_computed() {
    let mut inputs = inputs();
    for i in &mut inputs {
        if let Input::Iosxr { name, config, .. } = i
            && name == "x2"
        {
            *config = String::from_utf8(config.clone())
                .unwrap()
                .replace(" bgp router-id 192.0.2.2\n", "")
                .into_bytes();
        }
    }
    let e = assemble(inputs);
    let b = e.bgp_routing.as_ref().unwrap();
    assert!(b.gaps.is_empty(), "{:?}", b.gaps);
    for d in ["n1", "x1", "x3"] {
        let r = row(&e, d, "192.0.2.64/27");
        assert_eq!(r.0, Category::NotComputed, "{d}: {r:?}");
        assert!(r.1.starts_with("convergence not determined"), "{d}: {r:?}");
    }
    assert!(
        row(&e, "x3", "192.0.2.64/27")
            .1
            .contains("router id not known")
    );
}

/// The section `bgp_routes` of n1 from the text of `n1-routes.json` after
/// `edit`.
fn n1_section(
    edit: impl Fn(&mut serde_json::Value),
) -> BTreeMap<String, BTreeMap<String, Section>> {
    let mut v: serde_json::Value = serde_json::from_str(&fixture("n1-routes.json")).unwrap();
    edit(&mut v);
    let section = Section::Fresh(v.to_string().into_bytes(), "n1/bgp_routes".into());
    BTreeMap::from([(
        "n1".to_string(),
        BTreeMap::from([(rsim_ingest::bgp_routes::ROUTES.to_string(), section)]),
    )])
}

/// The prefix rows of the received table of `v`.
fn received_rows(v: &mut serde_json::Value) -> &mut Vec<serde_json::Value> {
    v["default"]["203.0.113.2"]["received-routes"]["answer"]["TABLE_vrf"]["ROW_vrf"][0]["TABLE_afi"]
        ["ROW_afi"][0]["TABLE_safi"]["ROW_safi"][0]["TABLE_prefix"]["ROW_prefix"]
        .as_array_mut()
        .unwrap()
}

/// The inputs with the next hop and the interface of the collected route of
/// n1 of `prefix` replaced.
fn n1_route_via(inputs: &mut [Input], prefix: &str, hop: &str, iface: &str) {
    if let Input::Nxos { collected, .. } = &mut inputs[0] {
        for r in &mut collected.routes {
            if r.prefix == prefix {
                r.next_hop = Some(hop.to_string());
                r.interface = Some(iface.to_string());
            }
        }
    }
}

#[test]
fn a_route_of_an_outside_reflector_with_a_next_hop_inside_the_twin_is_seeded() {
    // 203.0.113.2 is an iBGP route reflector outside the twin. Its paths
    // have the third-party next hop 198.51.100.2 of x1.
    let n1 = fixture("n1-config.txt")
        .replace("    remote-as 64499\n", "    remote-as 64501\n")
        .replace("      route-map FROM-ISP in\n", "");
    let mut inputs = inputs_with(&n1, &fixture("x1-config.txt"));
    n1_route_via(
        &mut inputs,
        "198.51.100.128/25",
        "198.51.100.2",
        "Ethernet1/1",
    );
    let tables = n1_section(|v| {
        for row in received_rows(v) {
            for p in row["TABLE_path"]["ROW_path"].as_array_mut().unwrap() {
                p["ipnexthop"] = serde_json::json!("198.51.100.2");
            }
        }
    });
    let e = assemble_with(inputs, &tables);
    let seeds = &e.bgp_routing.as_ref().unwrap().input.seeds;
    assert!(
        seeds
            .iter()
            .any(|s| s.path.next_hop == Some(ip("198.51.100.2"))),
        "{seeds:?}"
    );
    let r = row(&e, "n1", "198.51.100.128/25");
    assert_eq!(r.0, Category::Seeded, "{r:?}");
}

#[test]
fn a_collected_route_through_an_outside_peer_with_a_best_path_from_inside_has_a_differ_row() {
    // The received table of the peer outside the twin holds 192.0.2.64/27,
    // which the import policy of n1 denies, and the collected route goes
    // through that peer. The computed best path comes from x1.
    let mut inputs = inputs();
    n1_route_via(&mut inputs, "192.0.2.64/27", "203.0.113.2", "Ethernet1/2");
    let tables = n1_section(|v| {
        let rows = received_rows(v);
        let mut extra = rows[0].clone();
        extra["ipprefix"] = serde_json::json!("192.0.2.64/27");
        rows.push(extra);
    });
    let e = assemble_with(inputs, &tables);
    let r = row(&e, "n1", "192.0.2.64/27");
    assert_eq!(r.0, Category::Differ, "{r:?}");
    assert_eq!(r.2, ["198.51.100.2@Ethernet1/1"]);
}

#[test]
fn the_received_table_of_an_ibgp_peer_outside_the_twin_keeps_the_local_preference() {
    let n1 = fixture("n1-config.txt")
        .replace("    remote-as 64499\n", "    remote-as 64501\n")
        .replace("      route-map FROM-ISP in\n", "");
    let text =
        fixture("n1-routes.json").replace("\"localpref\": \"100\"", "\"localpref\": \"250\"");
    let section = Section::Fresh(text.into_bytes(), "n1/bgp_routes".into());
    let tables = BTreeMap::from([(
        "n1".to_string(),
        BTreeMap::from([(rsim_ingest::bgp_routes::ROUTES.to_string(), section)]),
    )]);
    let e = assemble_with(inputs_with(&n1, &fixture("x1-config.txt")), &tables);
    let seeds = &e.bgp_routing.as_ref().unwrap().input.seeds;
    assert!(!seeds.is_empty());
    for s in seeds {
        assert!(s.received, "{s:?}");
        assert_eq!(s.path.local_pref, Some(250), "{s:?}");
    }
}

/// The inputs with the static route line `line` in the config of x3.
fn with_x3_static(line: &str) -> Vec<Input> {
    let mut inputs = inputs();
    for i in &mut inputs {
        if let Input::Iosxr { name, config, .. } = i
            && name == "x3"
        {
            *config = String::from_utf8(config.clone())
                .unwrap()
                .replace(
                    "router bgp 64502\n",
                    &format!("router static\n address-family ipv4 unicast\n  {line}\n !\n!\nrouter bgp 64502\n"),
                )
                .into_bytes();
        }
    }
    inputs
}

#[test]
fn a_floating_static_route_of_the_config_leaves_the_ospf_cost_of_the_next_hop() {
    use rsim_routing::bgp::Resolution;
    let cost = |inputs: Vec<Input>| {
        let e = assemble(inputs);
        let b = e.bgp_routing.unwrap();
        b.igp[&("x3".to_string(), "default".to_string())].resolve(ip("192.0.2.2"))
    };
    assert_eq!(cost(inputs()), Resolution::Resolved { cost: 21 });
    assert_eq!(
        cost(with_x3_static("192.0.2.2/32 198.51.100.9 250")),
        Resolution::Resolved { cost: 21 }
    );
    assert_eq!(
        cost(with_x3_static("192.0.2.2/32 198.51.100.9")),
        Resolution::Resolved { cost: 0 }
    );
}

/// `config` with the IPv6 addresses `v6` after the IPv4 address lines
/// `v4`, and a `router ospfv3 CORE` process with the router ID `rid` on
/// the interfaces `ifaces`.
fn with_ospfv3(config: &str, v6: &[(&str, &str)], rid: &str, ifaces: &[&str]) -> String {
    let mut out = config.to_string();
    for (v4, a) in v6 {
        let line = format!(" ipv4 address {v4}\n");
        out = out.replace(&line, &format!("{line} ipv6 address {a}\n"));
    }
    let mut ospf = format!("router ospfv3 CORE\n router-id {rid}\n area 0\n");
    for i in ifaces {
        ospf.push_str(&format!("  interface {i}\n  !\n"));
    }
    ospf.push_str(" !\n!\n");
    out.replace("router bgp 64502\n", &format!("{ospf}router bgp 64502\n"))
}

#[test]
fn an_ipv6_next_hop_learned_by_ospfv3_does_not_resolve_through_another_route() {
    let x1 = with_ospfv3(
        &fixture("x1-config.txt"),
        &[
            ("192.0.2.1 255.255.255.255", "2001:db8::1/128"),
            ("198.51.100.5 255.255.255.252", "2001:db8:5::1/64"),
            ("198.51.100.9 255.255.255.252", "2001:db8:9::1/64"),
        ],
        "192.0.2.1",
        &["Loopback0", "TenGigE0/0/0/1", "TenGigE0/0/0/2"],
    );
    let mut inputs = inputs_with(&fixture("n1-config.txt"), &x1);
    for i in &mut inputs {
        if let Input::Iosxr { name, config, .. } = i {
            let text = String::from_utf8(config.clone()).unwrap();
            let text = match name.as_str() {
                "x2" => with_ospfv3(
                    &text,
                    &[
                        ("192.0.2.2 255.255.255.255", "2001:db8::2/128"),
                        ("198.51.100.6 255.255.255.252", "2001:db8:5::2/64"),
                    ],
                    "192.0.2.2",
                    &["Loopback0", "TenGigE0/0/0/0"],
                ),
                "x3" => with_ospfv3(
                    &text,
                    &[
                        ("192.0.2.3 255.255.255.255", "2001:db8::3/128"),
                        ("198.51.100.10 255.255.255.252", "2001:db8:9::2/64"),
                    ],
                    "192.0.2.3",
                    &["Loopback0", "TenGigE0/0/0/0"],
                ),
                _ => text,
            };
            *config = text.into_bytes();
        }
    }
    let e = assemble(inputs);
    let b = e.bgp_routing.unwrap();
    let t = &b.igp[&("x3".to_string(), "default".to_string())];
    let lo: rsim_core::Prefix = "2001:db8::2/128".parse().unwrap();
    // The OSPFv3 route of the loopback of x2 is in the view, or the OSPFv3
    // of x3 is not computed in full.
    assert!(
        t.routes.contains_key(&lo) || t.incomplete.contains_key(&false),
        "{:?} {:?}",
        t.routes.keys().collect::<Vec<_>>(),
        t.incomplete
    );
    assert_ne!(
        t.resolve(ip("2001:db8::2")),
        rsim_routing::bgp::Resolution::Resolved { cost: 0 }
    );
    assert_ne!(t.has_route(lo), Some(false));
}
