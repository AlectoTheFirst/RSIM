//! The NX-OS coverage and the layer 3 lowering on a synthetic running config
//! with fake secrets.

use std::net::IpAddr;

use rsim_core::{Header, PROTO_TCP, PROTO_UDP, VerdictKind};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::collected::{Collected, NeighbourRow, RouteRow, row_span};
use rsim_ingest::estate::{Estate, Input, assemble};
use rsim_ingest::{State, classify, nxos};

const CONFIG: &[u8] = include_bytes!("fixtures/nxos/leaf1-running-config.txt");

/// The fake secrets of the fixture.
const SECRETS: &[&str] = &[
    "FAKESALT",
    "FAKEHASH",
    "FAKETACACSKEY",
    "FAKETACACSHOSTKEY",
    "FAKECOMMUNITY",
    "FAKECOMMUNITYHOST",
    "0xFAKE",
    "FAKEKEYSTRING",
    "FAKEHSRPKEY",
    "FAKEOSPFKEY",
    "FAKEBGPPASSWORD",
    "FAKEUNLISTEDKEY",
];

fn no_secret(text: &str) {
    for s in SECRETS {
        assert!(!text.contains(s), "{s} is in {text}");
    }
}

fn route(vrf: &str, prefix: &str, protocol: &str, iface: &str, hop: Option<&str>) -> RouteRow {
    RouteRow {
        vrf: vrf.into(),
        prefix: prefix.into(),
        protocol: protocol.into(),
        selected: true,
        next_hop: hop.map(str::to_string),
        interface: Some(iface.into()),
        span: row_span("leaf1", "routes", "b1", 0),
    }
}

/// The collected state, with the short interface names of the NX-OS route
/// and ARP tables.
fn collected() -> Collected {
    Collected {
        routes: vec![
            route(
                "default",
                "0.0.0.0/0",
                "static",
                "Eth1/2",
                Some("198.51.100.2"),
            ),
            route("default", "192.0.2.0/26", "direct", "Vlan10", None),
            route("default", "192.0.2.128/26", "direct", "Vlan30", None),
            route("default", "198.51.100.0/30", "direct", "Eth1/2", None),
            route("RED", "192.0.2.64/26", "direct", "Vlan20", None),
            route(
                "RED",
                "0.0.0.0/0",
                "static",
                "Eth1/2",
                Some("198.51.100.2%default"),
            ),
        ],
        neighbours: vec![NeighbourRow {
            interface: "Ethernet1/2".into(),
            ip: "198.51.100.2".into(),
            mac: Some("00:00:5e:00:53:02".into()),
            state: None,
            span: row_span("leaf1", "neighbours", "b2", 0),
        }],
        ..Collected::default()
    }
}

fn estate() -> Estate {
    assemble(vec![Input::Nxos {
        name: "leaf1".into(),
        config: CONFIG.to_vec(),
        file: "leaf1/config@000000000000".into(),
        collected: collected(),
    }])
}

fn twin() -> Twin {
    estate().builder.build().expect("the twin builds")
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn run(t: &Twin, ingress: &str, src: &str, dst: &str, proto: u8, port: u16) -> Answer {
    let h = Header::request(ip(src), ip(dst), proto)
        .with_src_port(40000)
        .with_dst_port(port);
    Executor::new(t)
        .run(
            &Query::path(t, &h)
                .with_ingress("leaf1", ingress)
                .without_reply(),
        )
        .expect("the query runs")
}

/// The verdict of each branch, and the functions and reasons of its steps.
fn show(a: &Answer) -> Vec<(VerdictKind, Vec<String>)> {
    a.branches()
        .iter()
        .map(|b| {
            (
                b.verdict.kind(),
                b.steps
                    .iter()
                    .map(|s| format!("{} {}", s.function, s.reason.detail))
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn each_handled_line_is_read() {
    let e = estate();
    assert_eq!(e.unread["leaf1"], Vec::<String>::new());
}

#[test]
fn the_coverage_lists_the_unhandled_lines() {
    let doc = nxos::read_text(CONFIG);
    let cov = classify(&doc, &nxos::table(true));
    let mut paths: Vec<&str> = cov.ranked().iter().map(|r| r.0).collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        [
            "interface */channel-group 10 mode active",
            "interface */hsrp 10",
            "interface */hsrp version 2",
            "interface */switchport mode trunk",
            "interface */switchport trunk allowed vlan 10,20",
            "ip ospf authentication-key <secret>",
            "vlan 1,10,20",
            "vlan 10",
            "vlan 20",
        ]
    );
    assert!(cov.lines[&State::Handled] > 0);
}

#[test]
fn no_secret_reaches_the_coverage_or_the_notes() {
    let doc = nxos::read_text(CONFIG);
    for rib in [true, false] {
        let cov = classify(&doc, &nxos::table(rib));
        for (path, _, _) in cov.ranked() {
            no_secret(path);
        }
    }
    let e = estate();
    for (path, _, _) in e.coverage["leaf1"].ranked() {
        no_secret(path);
    }
    for list in e.unread.values().chain(e.notes.values()) {
        for line in list {
            no_secret(line);
        }
    }
}

#[test]
fn without_a_route_table_the_routing_protocols_are_unhandled() {
    let doc = nxos::read_text(CONFIG);
    let cov = classify(&doc, &nxos::table(false));
    let paths: Vec<&str> = cov.ranked().iter().map(|r| r.0).collect();
    assert!(paths.contains(&"router ospf .."), "{paths:?}");
    assert!(paths.contains(&"router bgp .."));
}

/// The functions of the steps of the only branch, and its verdict.
fn only(a: &Answer) -> (VerdictKind, Vec<String>) {
    let mut v = show(a);
    assert_eq!(v.len(), 1, "{v:#?}");
    v.remove(0)
}

fn has(steps: &[String], text: &str) -> bool {
    steps.iter().any(|s| s.contains(text))
}

#[test]
fn the_acl_permits_and_the_interface_nat_translates_the_source() {
    let t = twin();
    let (verdict, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "203.0.113.50",
        PROTO_TCP,
        443,
    ));
    assert!(has(
        &steps,
        "acl-in/Vlan30 permitted · ACL leaf1:acl:FROM30 rule FROM30/20"
    ));
    assert!(has(
        &steps,
        "route 0.0.0.0/0 in VRF default via 198.51.100.2 on Ethernet1/2"
    ));
    assert!(has(&steps, "snat translated to 198.51.100.1"));
    assert!(has(
        &steps,
        "nexthop 198.51.100.2 is 00:00:5e:00:53:02 on Ethernet1/2"
    ));
    // The switch has no layer 2 link yet, so the egress is unknown.
    assert!(has(&steps, "out/Ethernet1/2 no link"));
    assert_eq!(verdict, VerdictKind::Unknown);
    // An address group of the ACL.
    let (_, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "203.0.113.53",
        PROTO_UDP,
        53,
    ));
    assert!(has(&steps, "rule FROM30/30"));
}

#[test]
fn the_acl_denies_the_other_packets() {
    let t = twin();
    for dst in ["203.0.113.50", "192.0.2.129"] {
        let (verdict, steps) = only(&run(&t, "Vlan30", "192.0.2.140", dst, PROTO_TCP, 80));
        assert_eq!(verdict, VerdictKind::Drop);
        assert!(has(&steps, "denied · ACL leaf1:acl:FROM30 rule FROM30/40"));
    }
}

#[test]
fn the_static_nat_translates_the_outside_destination_before_the_route_lookup() {
    let t = twin();
    let (_, steps) = only(&run(
        &t,
        "Ethernet1/2",
        "203.0.113.50",
        "198.51.100.5",
        PROTO_TCP,
        443,
    ));
    let dnat = steps
        .iter()
        .position(|s| s.contains("dnat translated to 192.0.2.5"));
    let route = steps
        .iter()
        .position(|s| s.contains("route 192.0.2.0/26 in VRF default"));
    assert!(
        dnat.is_some() && route.is_some() && dnat < route,
        "{steps:#?}"
    );
    // The rule applies only on an outside interface.
    let (_, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "198.51.100.5",
        PROTO_TCP,
        443,
    ));
    assert!(has(&steps, "dnat not translated"), "{steps:#?}");
}

#[test]
fn what_is_not_lowered_gives_unknown() {
    let t = twin();
    // The HSRP lines of Vlan10.
    let (verdict, steps) = only(&run(
        &t,
        "Vlan10",
        "192.0.2.10",
        "203.0.113.50",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(&steps, "options not lowered: hsrp version 2, hsrp 10"));
    // A next hop in another VRF.
    let (verdict, steps) = only(&run(
        &t,
        "Vlan20",
        "192.0.2.70",
        "203.0.113.50",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(&steps, "route 0.0.0.0/0 in VRF RED has no next hop"));
    // IPv6.
    let (verdict, steps) = only(&run(
        &t,
        "Vlan30",
        "2001:db8::1",
        "2001:db8:1::1",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(&steps, "IPv6 not filtered"));
    assert!(has(&steps, "route ::/0 in VRF default has no next hop"));
    let notes = &estate().notes["leaf1"];
    assert_eq!(
        notes,
        &[
            "Vlan10: options not lowered: hsrp version 2, hsrp 10",
            "route 0.0.0.0/0 in VRF RED: a next hop in another VRF is not lowered",
            "IPv6 is not lowered: each IPv6 packet is unknown at the route lookup",
        ]
    );
}

#[test]
fn without_a_route_table_the_config_routes_decide() {
    let e = assemble(vec![Input::Nxos {
        name: "leaf1".into(),
        config: CONFIG.to_vec(),
        file: "leaf1/config@000000000000".into(),
        collected: Collected::default(),
    }]);
    let t = e.builder.build().expect("the twin builds");
    let (_, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "203.0.113.50",
        PROTO_TCP,
        443,
    ));
    assert!(
        has(
            &steps,
            "route 0.0.0.0/0 in VRF default via 198.51.100.2 on Ethernet1/2"
        ),
        "{steps:#?}"
    );
}

#[test]
fn two_builds_give_the_same_answers() {
    let (a, b) = (twin(), twin());
    let q = |t: &Twin| {
        show(&run(
            t,
            "Vlan30",
            "192.0.2.130",
            "203.0.113.50",
            PROTO_TCP,
            443,
        ))
    };
    assert_eq!(q(&a), q(&b));
}

/// A small config with the NAT list rules of `lists`. `vlan30` comes at the
/// end of the stanza of `Vlan30`, and `extra` at the end of the config.
fn small_with(lists: &[&str], vlan30: &str, extra: &str) -> Twin {
    let mut cfg = String::from(
        "interface Vlan30
  no shutdown
  ip address 192.0.2.129/26
  ip nat inside
interface Vlan40
  ip address 192.0.2.193/26
interface Ethernet1/2
  no switchport
  no shutdown
  ip address 198.51.100.1/30
  ip nat outside
  service-policy type qos output Q1
ip access-list A
  10 deny ip host 192.0.2.131 any
  20 permit ip 192.0.2.128/26 any
ip access-list B
  10 permit ip any any
",
    );
    for l in lists {
        cfg.push_str(&format!(
            "ip nat inside source list {l} interface Ethernet1/2 overload\n"
        ));
    }
    cfg.push_str(extra);
    let cfg = cfg.replacen(
        "  ip nat inside\n",
        &format!("  ip nat inside\n{vlan30}"),
        1,
    );
    let e = assemble(vec![Input::Nxos {
        name: "leaf1".into(),
        config: cfg.into_bytes(),
        file: "leaf1/config".into(),
        collected: collected(),
    }]);
    e.builder.build().expect("the twin builds")
}

fn small(lists: &[&str], extra: &str) -> Twin {
    small_with(lists, "", extra)
}

#[test]
fn a_deny_of_a_nat_acl_is_exact_only_in_the_last_list_rule() {
    let t = small(&["A"], "");
    let (_, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.131",
        "203.0.113.50",
        PROTO_TCP,
        443,
    ));
    assert!(
        has(
            &steps,
            "snat not translated · source NAT leaf1:nat:inside rule A/10"
        ),
        "{steps:#?}"
    );
    let (_, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "203.0.113.50",
        PROTO_TCP,
        443,
    ));
    assert!(has(&steps, "snat translated to 198.51.100.1"), "{steps:#?}");
    // With another list rule after it, the deny is not lowered.
    let t = small(&["A", "B"], "");
    let (verdict, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.131",
        "203.0.113.50",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(
        has(&steps, "a deny of a NAT ACL before another NAT rule"),
        "{steps:#?}"
    );
}

#[test]
fn another_nat_form_gives_unknown() {
    let t = small(
        &["B"],
        "ip nat outside source static 203.0.113.9 192.0.2.140\n",
    );
    let (verdict, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "203.0.113.50",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(&steps, "ip nat outside source static"), "{steps:#?}");
}

#[test]
fn a_qos_policy_forwards_and_a_missing_admin_state_gives_unknown() {
    let t = small(&["B"], "");
    let (_, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "203.0.113.50",
        PROTO_TCP,
        443,
    ));
    let qos = steps
        .iter()
        .position(|s| s.starts_with("leaf1/qos-out/Ethernet1/2"));
    let out = steps
        .iter()
        .position(|s| s.starts_with("leaf1/out/Ethernet1/2"));
    assert!(qos.is_some() && out.is_some() && qos < out, "{steps:#?}");
    let (verdict, steps) = only(&run(
        &t,
        "Vlan40",
        "192.0.2.200",
        "203.0.113.50",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(&steps, "the admin state is not known"), "{steps:#?}");
}

#[test]
fn an_empty_acl_gives_unknown() {
    let t = small_with(
        &[],
        "  ip access-group EMPTY in\n",
        "ip access-list EMPTY\n",
    );
    let (verdict, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "203.0.113.50",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(&steps, "ACL EMPTY has no entry"), "{steps:#?}");
}
