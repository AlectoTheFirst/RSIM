//! The NX-OS coverage and the layer 3 lowering on a synthetic running config
//! with fake secrets.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{Header, PROTO_TCP, PROTO_UDP, VerdictKind, VrfId};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_functions::RouteLookup;
use rsim_ingest::collected::{Collected, LinkRow, MacRow, NeighbourRow, RouteRow, row_span};
use rsim_ingest::estate::{Estate, Input, assemble};
use rsim_ingest::route_tables::RouteTables;
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

fn arp(iface: &str, ip: &str, mac: &str, i: u64) -> NeighbourRow {
    NeighbourRow {
        interface: iface.into(),
        ip: ip.into(),
        mac: Some(mac.into()),
        state: None,
        span: row_span("leaf1", "neighbours", "b2", i),
    }
}

fn mac_row(vlan: u64, mac: &str, port: &str, i: u64) -> MacRow {
    MacRow {
        vlan,
        mac: mac.into(),
        port: Some(port.into()),
        kind: Some("dynamic".into()),
        span: row_span("leaf1", "mac_table", "b3", i),
    }
}

fn link(iface: &str, mac: &str) -> LinkRow {
    LinkRow {
        interface: iface.into(),
        mac: Some(mac.into()),
        parent: None,
        vlan: None,
        span: row_span("leaf1", "links", "b4", 0),
    }
}

/// The collected state, with the short interface names of the NX-OS route,
/// ARP and MAC tables.
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
            route("default", "203.0.113.0/25", "direct", "Vlan50", None),
            route("default", "192.0.2.1/32", "hsrp", "Vlan10", None),
            route("RED", "192.0.2.64/26", "direct", "Vlan20", None),
            route("RED", "192.0.2.0/26", "direct", "Vlan60", None),
            route(
                "default",
                "10.0.0.0/8",
                "static",
                "Vlan10",
                Some("192.0.2.20"),
            ),
            route(
                "RED",
                "0.0.0.0/0",
                "static",
                "Eth1/2",
                Some("198.51.100.2%default"),
            ),
        ],
        neighbours: vec![
            arp("Ethernet1/2", "198.51.100.2", "00:00:5e:00:53:02", 0),
            arp("Vlan30", "192.0.2.130", "00:00:5e:00:53:a1", 1),
            arp("Vlan10", "192.0.2.10", "00:00:5e:00:53:a2", 2),
            arp("Vlan10", "192.0.2.5", "00:00:5e:00:53:a3", 3),
            arp("Vlan50", "203.0.113.50", "00:00:5e:00:53:a4", 4),
            arp("Vlan10", "192.0.2.11", "00:00:5e:00:53:b1", 5),
            arp("Vlan10", "192.0.2.12", "00:00:5e:00:53:c1", 6),
            arp("Vlan10", "192.0.2.20", "00:00:5e:00:53:e1", 7),
            arp("Vlan60", "192.0.2.10", "00:00:5e:00:53:d1", 8),
            arp("Vlan10", "192.0.2.30", "00:00:5e:00:53:f1", 9),
            arp("Vlan20", "192.0.2.70", "00:00:5e:00:53:a5", 10),
            arp("Vlan50", "203.0.113.60", "00:00:5e:00:53:a6", 11),
            arp("Vlan10", "192.0.2.13", "00:00:5e:00:53:b2", 12),
            arp("Vlan10", "192.0.2.14", "00:00:5e:00:53:b3", 13),
        ],
        macs: vec![
            mac_row(30, "00:00:5e:00:53:a1", "Eth1/5", 0),
            mac_row(10, "00:00:5e:00:53:a2", "Eth1/6", 1),
            mac_row(10, "00:00:5e:00:53:a3", "Eth1/6", 2),
            mac_row(50, "00:00:5e:00:53:a4", "Eth1/7", 3),
            mac_row(10, "00:00:0c:9f:f0:0a", "sup-eth1(R)", 4),
            mac_row(10, "00:00:5e:00:53:b1", "Po10", 5),
            mac_row(10, "00:00:5e:00:53:e1", "Eth1/6", 6),
            mac_row(60, "00:00:5e:00:53:d1", "Eth1/8", 7),
            mac_row(10, "00:00:5e:00:53:f1", "Eth1/9", 8),
            mac_row(20, "00:00:5e:00:53:a5", "Eth1/10", 9),
            mac_row(20, "00:00:0c:9f:f0:14", "Po10", 10),
            mac_row(10, "00:00:5e:00:53:b2", "Eth1/1", 11),
            mac_row(10, "00:00:5e:00:53:b3", "Eth1/11", 12),
        ],
        links: vec![
            link("Vlan10", "00:00:5e:00:53:10"),
            link("Vlan20", "00:00:5e:00:53:20"),
            link("Vlan30", "00:00:5e:00:53:30"),
            link("Vlan50", "00:00:5e:00:53:50"),
            link("Vlan60", "00:00:5e:00:53:60"),
        ],
        ..Collected::default()
    }
}

/// The synthetic JSON sections of the switch.
fn sections() -> BTreeMap<String, (Vec<u8>, String)> {
    ["interfaces", "hsrp", "vrrp", "lldp", "version"]
        .into_iter()
        .map(|n| {
            let path = format!(
                "{}/tests/fixtures/nxos/{n}.json",
                env!("CARGO_MANIFEST_DIR")
            );
            (
                n.to_string(),
                (std::fs::read(path).unwrap(), format!("leaf1/{n}")),
            )
        })
        .collect()
}

fn estate() -> Estate {
    assemble(vec![Input::Nxos {
        name: "leaf1".into(),
        config: CONFIG.to_vec(),
        file: "leaf1/config@000000000000".into(),
        collected: collected(),
        sections: sections(),
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
    let cov = classify(
        &doc,
        &nxos::table(&RouteTables::uniform(true, nxos::dynamic_vrfs(&doc))),
    );
    let mut paths: Vec<&str> = cov.ranked().iter().map(|r| r.0).collect();
    paths.sort_unstable();
    assert_eq!(paths, ["ip ospf authentication-key <secret>"]);
    assert!(cov.lines[&State::Handled] > 0);
}

#[test]
fn no_secret_reaches_the_coverage_or_the_notes() {
    let doc = nxos::read_text(CONFIG);
    for rib in [true, false] {
        let cov = classify(
            &doc,
            &nxos::table(&RouteTables::uniform(rib, nxos::dynamic_vrfs(&doc))),
        );
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
    let cov = classify(
        &doc,
        &nxos::table(&RouteTables::uniform(false, nxos::dynamic_vrfs(&doc))),
    );
    let paths: Vec<&str> = cov.ranked().iter().map(|r| r.0).collect();
    assert!(paths.contains(&"router ospf .."), "{paths:?}");
    // The neighbour lines are handled, and the routing lines below them
    // are unhandled.
    assert!(!paths.contains(&"router bgp .."), "{paths:?}");
    assert!(
        paths.iter().any(|p| p.starts_with("router bgp */")),
        "{paths:?}"
    );
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
        "203.0.113.200",
        PROTO_TCP,
        443,
    ));
    assert!(has(
        &steps,
        "acl-in/Vlan30 permitted, ACL leaf1:acl:FROM30 rule FROM30/20"
    ));
    assert!(has(
        &steps,
        "route 0.0.0.0/0 in VRF default via 198.51.100.2 on Ethernet1/2"
    ));
    assert!(has(&steps, "snat translated to 198.51.100.1"));
    assert!(has(
        &steps,
        "nexthop 198.51.100.2, 00:00:5e:00:53:02 on Ethernet1/2"
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
        assert!(has(&steps, "denied, ACL leaf1:acl:FROM30 rule FROM30/40"));
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
    assert!(has(&steps, "route ::/0 in VRF default, no next hop"));
    let notes = &estate().notes["leaf1"];
    assert_eq!(
        notes,
        &[
            "leaf1/vlan10/00:00:5e:00:53:e1: a next hop of a route, not an endpoint",
            "Ethernet1/9: vPC domain not known",
            "IPv6 not lowered",
        ]
    );
}

#[test]
fn without_a_route_table_the_config_routes_decide() {
    let text = String::from_utf8(CONFIG.to_vec()).unwrap();
    let start = text.find("router ospf 1\n").unwrap();
    let end = text.find("ip nat inside source static").unwrap();
    let without_protocols = format!("{}{}", &text[..start], &text[end..]);
    for (config, route) in [
        (
            text.as_str(),
            "route 0.0.0.0/0 in VRF default, vrf route table not collected",
        ),
        (
            without_protocols.as_str(),
            "route 0.0.0.0/0 in VRF default via 198.51.100.2 on Ethernet1/2",
        ),
    ] {
        let t = estate_of(config.as_bytes(), Collected::default())
            .builder
            .build()
            .expect("the twin builds");
        let (_, steps) = only(&run(
            &t,
            "Vlan30",
            "192.0.2.130",
            "203.0.113.200",
            PROTO_TCP,
            443,
        ));
        assert!(has(&steps, route), "{steps:#?}");
    }
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
        sections: sections(),
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
        "203.0.113.200",
        PROTO_TCP,
        443,
    ));
    assert!(
        has(
            &steps,
            "snat not translated, source NAT leaf1:nat:inside rule A/10"
        ),
        "{steps:#?}"
    );
    let (_, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "203.0.113.200",
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
        "203.0.113.200",
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
        "203.0.113.200",
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
        "203.0.113.200",
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
        "203.0.113.200",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(&steps, "admin state not known"), "{steps:#?}");
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
        "203.0.113.200",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(&steps, "ACL EMPTY has no entry"), "{steps:#?}");
}

fn run_reply(t: &Twin, src: &str, dst: &str, port: u16) -> Answer {
    let h = Header::request(ip(src), ip(dst), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(port);
    Executor::new(t)
        .run(&Query::path(t, &h))
        .expect("the query runs")
}

/// The verdict and the steps of the only reply.
fn only_reply(a: &Answer) -> (VerdictKind, Vec<String>) {
    assert_eq!(a.replies.len(), 1);
    match &a.replies[0].result {
        rsim_engine::ReplyResult::Ran(r) => only(r),
        rsim_engine::ReplyResult::NotRun(w) => panic!("the reply did not run: {w}"),
    }
}

#[test]
fn a_host_reaches_a_host_of_another_vlan_through_the_svis() {
    let t = twin();
    let a = run_reply(&t, "192.0.2.130", "192.0.2.10", 443);
    let (verdict, steps) = only(&a);
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    for text in [
        "host/Ethernet1/5 from 00:00:5e:00:53:a1 to the gateway 00:00:5e:00:53:30",
        "mac 00:00:5e:00:53:30 on port svi/Vlan30",
        "handoff/Vlan30 untagged to leaf1/in/Vlan30",
        "out/Vlan10 leave on Vlan10 to leaf1/svi/Vlan10/in",
        "mac 00:00:5e:00:53:a2 on port Ethernet1/6",
        "deliver to leaf1/vlan10/00:00:5e:00:53:a2 on port Ethernet1/6",
    ] {
        assert!(has(&steps, text), "{text}: {steps:#?}");
    }
    // The reply goes to the active HSRP virtual MAC, and the stateless
    // input ACL of Vlan10 denies it.
    let (verdict, steps) = only_reply(&a);
    assert_eq!(verdict, VerdictKind::Drop);
    assert!(has(&steps, "to the gateway 00:00:0c:9f:f0:0a"));
    assert!(has(
        &steps,
        "acl-in/Vlan10 denied, ACL leaf1:acl:WEB rule WEB/20"
    ));
}

#[test]
fn the_reply_of_a_static_nat_comes_back_through_the_session() {
    let t = twin();
    let a = run_reply(&t, "192.0.2.5", "203.0.113.50", 443);
    let (verdict, steps) = only(&a);
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    assert!(has(&steps, "snat translated to 198.51.100.5"));
    let (verdict, steps) = only_reply(&a);
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    assert!(has(&steps, "session-lookup session 0, reply, translated"));
    assert!(has(
        &steps,
        "deliver to leaf1/vlan10/00:00:5e:00:53:a3 on port Ethernet1/6"
    ));
}

#[test]
fn a_mac_behind_the_trunk_and_a_flood_copy_to_the_trunk_give_unknown() {
    let t = twin();
    let (verdict, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "192.0.2.11",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(
        has(&steps, "mac 00:00:5e:00:53:b1 on port port-channel10"),
        "{steps:#?}"
    );
    // A MAC that the table does not have floods. The copy to the trunk is
    // unknown, because the spanning tree state is not collected.
    let a = run(&t, "Vlan30", "192.0.2.130", "192.0.2.12", PROTO_TCP, 443);
    let all: Vec<String> = show(&a).into_iter().flat_map(|b| b.1).collect();
    assert!(has(&all, "spanning tree state not collected"), "{all:#?}");
    assert!(show(&a).iter().all(|b| b.0 != VerdictKind::Deliver));
}

#[test]
fn an_hsrp_state_that_is_not_known_gives_unknown() {
    let mut sections = sections();
    sections.insert(
        "hsrp".into(),
        (
            br#"{"TABLE_grp_detail":{"ROW_grp_detail":[{"sh_if_index":"Vlan10","sh_group_num":10,"sh_group_state":"Changing","sh_vip":"192.0.2.1","sh_vmac":"0000.0c9f.f00a"}]}}"#.to_vec(),
            "leaf1/hsrp".into(),
        ),
    );
    let e = assemble(vec![Input::Nxos {
        name: "leaf1".into(),
        config: CONFIG.to_vec(),
        file: "leaf1/config@000000000000".into(),
        collected: collected(),
        sections,
    }]);
    let notes = e.notes["leaf1"].clone();
    let t = e.builder.build().expect("the twin builds");
    let a = run_reply(&t, "192.0.2.130", "192.0.2.10", 443);
    let (verdict, steps) = only_reply(&a);
    assert_eq!(verdict, VerdictKind::Unknown);
    // The virtual MAC is not active, so its MAC table row stays. The row
    // names the supervisor of the switch, which is not a lowered port.
    assert!(
        has(&steps, "no egress function of port sup-eth1(R)"),
        "{steps:#?}"
    );
    assert!(
        notes.iter().any(|n| n.contains("Vlan10: HSRP group 10")),
        "{notes:#?}"
    );
    assert!(
        notes
            .iter()
            .any(|n| n.contains("route 192.0.2.1/32 in VRF default, route of a gateway group")),
        "{notes:#?}"
    );
}

#[test]
fn a_packet_to_a_router_behind_a_port_is_not_delivered() {
    let t = twin();
    let (verdict, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "10.1.1.1",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(has(
        &steps,
        "nexthop 192.0.2.20, 00:00:5e:00:53:e1 on Vlan10"
    ));
    assert!(has(&steps, "mac 00:00:5e:00:53:e1 on port Ethernet1/6"));
    let notes = &estate().notes["leaf1"];
    assert!(notes.contains(
        &"leaf1/vlan10/00:00:5e:00:53:e1: a next hop of a route, not an endpoint".to_string()
    ));
}

#[test]
fn the_same_address_in_two_vrfs_gives_two_endpoints() {
    let e = estate();
    let t = e.builder.build().expect("the twin builds");
    let ids: Vec<String> = t
        .attachments()
        .iter()
        .filter(|a| a.address == ip("192.0.2.10"))
        .map(|a| a.host.clone())
        .collect();
    assert_eq!(
        ids,
        [
            "leaf1/vlan10/00:00:5e:00:53:a2",
            "leaf1/vlan60/00:00:5e:00:53:d1"
        ]
    );
    // The host table of VLAN 60 gives the MAC of Vlan60, not of Vlan10.
    let (verdict, steps) = only(&run(
        &t,
        "Ethernet1/8",
        "192.0.2.10",
        "192.0.2.2",
        PROTO_TCP,
        22,
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    assert!(has(&steps, "00:00:5e:00:53:60"), "{steps:#?}");
    assert!(has(&steps, "in/Vlan60"));
}

#[test]
fn a_port_with_an_unhandled_line_gives_unknown() {
    let t = twin();
    let (verdict, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "192.0.2.30",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(&steps, "port/Ethernet1/9/out"), "{steps:#?}");
    assert!(has(&steps, "vPC domain not known"), "{steps:#?}");
}

#[test]
fn the_virtual_mac_of_a_standby_group_stays_on_its_port() {
    let t = twin();
    let (verdict, steps) = only(&run(
        &t,
        "Ethernet1/10",
        "192.0.2.70",
        "192.0.2.200",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(
        has(&steps, "to the gateway 00:00:0c:9f:f0:14"),
        "{steps:#?}"
    );
    assert!(
        has(&steps, "mac 00:00:0c:9f:f0:14 on port port-channel10"),
        "{steps:#?}"
    );
}

#[test]
fn an_added_trunk_vlan_and_a_member_port_map_to_the_port_channel() {
    let t = twin();
    // VLAN 50 is added to the trunk, so the flood of VLAN 50 has a copy to it.
    let a = run(&t, "Vlan30", "192.0.2.130", "203.0.113.60", PROTO_TCP, 443);
    let all: Vec<String> = show(&a).into_iter().flat_map(|b| b.1).collect();
    assert!(has(&all, "port/port-channel10/stp"), "{all:#?}");
    // A MAC on the member port Ethernet1/1 is on the port channel.
    let (_, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "192.0.2.13",
        PROTO_TCP,
        443,
    ));
    assert!(
        has(&steps, "mac 00:00:5e:00:53:b2 on port port-channel10"),
        "{steps:#?}"
    );
}

#[test]
fn a_vrrp_master_owns_its_virtual_address_and_mac() {
    let t = twin();
    let (verdict, steps) = only(&run(
        &t,
        "Ethernet1/7",
        "203.0.113.50",
        "203.0.113.2",
        PROTO_TCP,
        22,
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    assert!(has(&steps, "00:00:5e:00:01:32"), "{steps:#?}");
}

#[test]
fn the_collected_mode_decides_a_port_with_no_switchport_line() {
    let t = twin();
    let (_, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "192.0.2.14",
        PROTO_TCP,
        443,
    ));
    let last = steps.last().unwrap();
    assert!(
        last.starts_with("leaf1/port/Ethernet1/11/out"),
        "{steps:#?}"
    );
    assert!(!has(&steps, "port mode not known"));
    // Without the collected mode, the port gives Unknown.
    let mut sections = sections();
    let text = String::from_utf8(sections["interfaces"].0.clone()).unwrap();
    let text = text.replace(", \"eth_mode\": \"trunk\"", "");
    sections.insert(
        "interfaces".into(),
        (text.into_bytes(), "leaf1/interfaces".into()),
    );
    let e = assemble(vec![Input::Nxos {
        name: "leaf1".into(),
        config: CONFIG.to_vec(),
        file: "leaf1/config@000000000000".into(),
        collected: collected(),
        sections,
    }]);
    let t = e.builder.build().expect("the twin builds");
    let (verdict, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "192.0.2.14",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(&steps, "port mode not known"), "{steps:#?}");
}

const LEAF2: &str = "hostname leaf2
vlan 1,10,20
interface port-channel20
  switchport
  switchport mode trunk
  switchport trunk allowed vlan 10,20
  no shutdown
interface Ethernet1/49
  switchport
  switchport mode trunk
  switchport trunk allowed vlan 10,20
  channel-group 20 mode active
  no shutdown
interface Ethernet1/3
  switchport
  switchport access vlan 10
  no shutdown
interface Ethernet1/50
  no switchport
  ip address 198.51.100.2/30
  no shutdown
";

/// The sections of leaf2, with the LLDP rows of `lldp`.
fn leaf2_sections(lldp: &str) -> BTreeMap<String, (Vec<u8>, String)> {
    let interfaces = r#"{"TABLE_interface":{"ROW_interface":[
        {"interface":"Ethernet1/49","admin_state":"up","state":"up"},
        {"interface":"Ethernet1/3","admin_state":"up","state":"up"},
        {"interface":"Ethernet1/50","admin_state":"up","state":"up"},
        {"interface":"port-channel20","admin_state":"up","state":"up"}]}}"#;
    BTreeMap::from([
        (
            "interfaces".to_string(),
            (
                interfaces.as_bytes().to_vec(),
                "leaf2/interfaces".to_string(),
            ),
        ),
        (
            "lldp".to_string(),
            (lldp.as_bytes().to_vec(), "leaf2/lldp".to_string()),
        ),
        (
            "version".to_string(),
            (
                br#"{"host_name":"leaf2"}"#.to_vec(),
                "leaf2/version".to_string(),
            ),
        ),
    ])
}

const LEAF2_LLDP: &str = r#"{"TABLE_nbor_detail":{"ROW_nbor_detail":[
    {"l_port_id":"Eth1/49","sys_name":"leaf1","port_id":"Ethernet1/1"},
    {"l_port_id":"Eth1/50","sys_name":"leaf1","port_id":"Ethernet1/2"}]}}"#;

/// leaf1 and leaf2. `extra` adds rows to the MAC tables of both switches.
fn two_switches(lldp: &str, extra: &[(u64, &str)]) -> Estate {
    let mut c1 = collected();
    c1.links.push(link("Ethernet1/2", "00:00:5e:00:53:e2"));
    c1.neighbours
        .push(arp("Vlan10", "192.0.2.40", "00:00:5e:00:53:c4", 20));
    c1.macs.push(mac_row(10, "00:00:5e:00:53:c4", "Eth1/1", 20));
    let mut c2 = Collected {
        routes: vec![RouteRow {
            span: row_span("leaf2", "routes", "b1", 0),
            ..route("default", "198.51.100.0/30", "direct", "Eth1/50", None)
        }],
        macs: vec![
            mac_row(10, "00:00:5e:00:53:c4", "Eth1/3", 0),
            mac_row(10, "00:00:0c:9f:f0:0a", "Eth1/49", 1),
            mac_row(10, "00:00:5e:00:53:10", "Eth1/49", 2),
        ],
        links: vec![link("Ethernet1/50", "00:00:5e:00:53:02")],
        ..Collected::default()
    };
    c2.macs.push(mac_row(10, "00:00:5e:00:53:a2", "Eth1/49", 3));
    c2.macs.push(mac_row(10, "00:00:5e:00:53:a3", "Eth1/49", 4));
    for (i, (vlan, mac)) in extra.iter().enumerate() {
        let i = u64::try_from(i).unwrap();
        c1.neighbours
            .push(arp("Vlan10", &format!("192.0.2.{}", 41 + i), mac, 30 + i));
        c1.macs.push(mac_row(*vlan, mac, "Eth1/1", 30 + i));
        c2.macs.push(mac_row(*vlan, mac, "Eth1/49", 30 + i));
    }
    assemble(vec![
        Input::Nxos {
            name: "leaf1".into(),
            config: CONFIG.to_vec(),
            file: "leaf1/config@000000000000".into(),
            collected: c1,
            sections: sections(),
        },
        Input::Nxos {
            name: "leaf2".into(),
            config: LEAF2.as_bytes().to_vec(),
            file: "leaf2/config".into(),
            collected: c2,
            sections: leaf2_sections(lldp),
        },
    ])
}

#[test]
fn a_host_on_an_access_switch_reaches_a_host_behind_the_svi_of_the_other_switch() {
    let e = two_switches(LEAF2_LLDP, &[]);
    let t = e.builder.build().expect("the twin builds");
    let a = run_reply(&t, "192.0.2.40", "192.0.2.130", 443);
    let (verdict, steps) = only(&a);
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    for text in [
        "leaf2/host/Ethernet1/3 from 00:00:5e:00:53:c4 to the gateway 00:00:0c:9f:f0:0a",
        "leaf2/mac 00:00:0c:9f:f0:0a on port port-channel20",
        "leaf2/port/port-channel20/out leave port port-channel20 VLAN 10 to leaf1/port/port-channel10/in",
        "leaf1/handoff/Vlan10 untagged to leaf1/in/Vlan10",
        "deliver to leaf1/vlan30/00:00:5e:00:53:a1 on port Ethernet1/5",
    ] {
        assert!(has(&steps, text), "{text}: {steps:#?}");
    }
    // The reply goes back across the trunk, and the stateless input ACL
    // of Vlan30 denies it.
    let (verdict, steps) = only_reply(&a);
    assert_eq!(verdict, VerdictKind::Drop, "{steps:#?}");
    assert!(
        has(
            &steps,
            "acl-in/Vlan30 denied, ACL leaf1:acl:FROM30 rule FROM30/40"
        ),
        "{steps:#?}"
    );
}

#[test]
fn a_routed_link_joins_two_switches() {
    let e = two_switches(LEAF2_LLDP, &[]);
    let t = e.builder.build().expect("the twin builds");
    let (verdict, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "198.51.100.2",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    assert!(
        has(
            &steps,
            "leaf1/out/Ethernet1/2 leave on Ethernet1/2 to leaf2/handoff/Ethernet1/50"
        ),
        "{steps:#?}"
    );
    assert!(has(&steps, "leaf2/in/Ethernet1/50"), "{steps:#?}");
}

#[test]
fn rows_that_disagree_give_no_link() {
    let lldp = r#"{"TABLE_nbor_detail":{"ROW_nbor_detail":[
        {"l_port_id":"Eth1/49","sys_name":"leaf9","port_id":"Ethernet1/1"}]}}"#;
    let e = two_switches(lldp, &[]);
    let notes = &e.notes["leaf1"];
    assert!(
        notes.contains(
            &"port-channel10: link not reported back by the neighbour, no link".to_string()
        ),
        "{notes:#?}"
    );
    let t = e.builder.build().expect("the twin builds");
    let (verdict, _) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "198.51.100.2",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
}

#[test]
fn two_mac_tables_that_point_at_each_other_end_the_path() {
    let e = two_switches(LEAF2_LLDP, &[(10, "00:00:5e:00:53:c9")]);
    let t = e.builder.build().expect("the twin builds");
    let a = run(&t, "Vlan30", "192.0.2.130", "192.0.2.41", PROTO_TCP, 443);
    let all = show(&a);
    assert!(!all.is_empty());
    for b in &all {
        assert_ne!(b.0, VerdictKind::Deliver, "{b:#?}");
    }
    // leaf2 has the MAC on the port of the frame, so it filters the frame.
    let steps: Vec<String> = all.into_iter().flat_map(|b| b.1).collect();
    assert!(
        has(
            &steps,
            "leaf2/mac 00:00:5e:00:53:c9 on ingress port port-channel20"
        ),
        "{steps:#?}"
    );
}

#[test]
fn a_host_behind_the_svi_reaches_a_host_on_the_access_switch() {
    let e = two_switches(LEAF2_LLDP, &[]);
    let t = e.builder.build().expect("the twin builds");
    let (verdict, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "192.0.2.40",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    assert!(
        has(
            &steps,
            "leaf1/port/port-channel10/out leave port port-channel10 VLAN 10 to leaf2/port/port-channel20/in"
        ),
        "{steps:#?}"
    );
    assert!(has(
        &steps,
        "deliver to leaf2/vlan10/00:00:5e:00:53:c4 on port Ethernet1/3"
    ));
}

#[test]
fn one_end_is_enough_for_a_router_with_no_neighbour_section() {
    let mut c1 = collected();
    c1.links.push(link("Ethernet1/2", "00:00:5e:00:53:e2"));
    // The next hop of the default route is the router.
    for n in &mut c1.neighbours {
        if n.ip == "198.51.100.2" {
            n.mac = Some("00:00:5e:00:53:77".into());
        }
    }
    let mut s1 = sections();
    s1.insert(
        "lldp".into(),
        (
            br#"{"TABLE_nbor_detail":{"ROW_nbor_detail":[
                {"l_port_id":"Eth1/2","sys_name":"r1","chassis_id":"0000.5e00.5377","port_id":"eth1"}]}}"#
                .to_vec(),
            "leaf1/lldp".into(),
        ),
    );
    let router = Collected {
        links: vec![LinkRow {
            span: row_span("r1", "links", "b4", 0),
            ..link("eth1", "00:00:5e:00:53:77")
        }],
        ..Collected::default()
    };
    let e = assemble(vec![
        Input::Nxos {
            name: "leaf1".into(),
            config: CONFIG.to_vec(),
            file: "leaf1/config@000000000000".into(),
            collected: c1,
            sections: s1,
        },
        Input::Vyos {
            name: "r1".into(),
            config: include_bytes!("fixtures/vyos/r1-config.json").to_vec(),
            file: "r1/config".into(),
            collected: router,
        },
    ]);
    let t = e.builder.build().expect("the twin builds");
    let a = run(&t, "Vlan30", "192.0.2.130", "203.0.113.200", PROTO_TCP, 443);
    let all: Vec<String> = show(&a).into_iter().flat_map(|b| b.1).collect();
    assert!(
        has(
            &all,
            "leaf1/out/Ethernet1/2 leave on Ethernet1/2 to r1/handoff/eth1"
        ),
        "{all:#?}"
    );
    assert!(has(&all, "r1/handoff/eth1"), "{all:#?}");
}

#[test]
fn two_hosts_of_one_vlan_reach_each_other_across_the_trunk() {
    let e = two_switches(LEAF2_LLDP, &[]);
    let t = e.builder.build().expect("the twin builds");
    let a = run_reply(&t, "192.0.2.5", "192.0.2.40", 8080);
    let (verdict, steps) = only(&a);
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    assert!(has(
        &steps,
        "deliver to leaf2/vlan10/00:00:5e:00:53:c4 on port Ethernet1/3"
    ));
    let (verdict, steps) = only_reply(&a);
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    assert!(has(&steps, "leaf2/port/port-channel20/out"), "{steps:#?}");
    assert!(has(
        &steps,
        "deliver to leaf1/vlan10/00:00:5e:00:53:a3 on port Ethernet1/6"
    ));
}

#[test]
fn members_that_name_different_peers_give_no_link() {
    let leaf1_lldp = r#"{"TABLE_nbor_detail":{"ROW_nbor_detail":[
        {"l_port_id":"Eth1/1","sys_name":"leaf2","port_id":"Ethernet1/49"},
        {"l_port_id":"Eth1/1","sys_name":"leaf2","port_id":"Ethernet1/3"}]}}"#;
    let mut e = two_switches(LEAF2_LLDP, &[]);
    let _ = &mut e;
    let mut s1 = sections();
    s1.insert(
        "lldp".into(),
        (leaf1_lldp.as_bytes().to_vec(), "leaf1/lldp".into()),
    );
    let e = assemble(vec![
        Input::Nxos {
            name: "leaf1".into(),
            config: CONFIG.to_vec(),
            file: "leaf1/config".into(),
            collected: collected(),
            sections: s1,
        },
        Input::Nxos {
            name: "leaf2".into(),
            config: LEAF2.as_bytes().to_vec(),
            file: "leaf2/config".into(),
            collected: Collected::default(),
            sections: leaf2_sections(LEAF2_LLDP),
        },
    ]);
    assert!(
        e.notes["leaf1"].contains(
            &"port-channel10: more than one neighbour in the LLDP and CDP rows, no link"
                .to_string()
        ),
        "{:#?}",
        e.notes
    );
    e.builder.build().expect("the twin builds");
}

#[test]
fn a_cdp_row_proves_a_link_and_two_claims_give_no_link() {
    // leaf2 reports its link by CDP, with the serial in the device id.
    let cdp = r#"{"TABLE_cdp_neighbor_brief_info":{"ROW_cdp_neighbor_brief_info":[
        {"intf_id":"Ethernet1/49","device_id":"leaf1.example.test(FDO0001)","port_id":"Ethernet1/1"},
        {"intf_id":"Ethernet1/50","device_id":"leaf1(FDO0001)","port_id":"Ethernet1/2"}]}}"#;
    let mut s2 = leaf2_sections(r#"{}"#);
    s2.remove("lldp");
    s2.insert("cdp".into(), (cdp.as_bytes().to_vec(), "leaf2/cdp".into()));
    let e = assemble(vec![
        Input::Nxos {
            name: "leaf1".into(),
            config: CONFIG.to_vec(),
            file: "leaf1/config".into(),
            collected: collected(),
            sections: sections(),
        },
        Input::Nxos {
            name: "leaf2".into(),
            config: LEAF2.as_bytes().to_vec(),
            file: "leaf2/config".into(),
            collected: Collected::default(),
            sections: s2,
        },
    ]);
    let t = e.builder.build().expect("the twin builds");
    let a = run(&t, "Vlan30", "192.0.2.130", "192.0.2.13", PROTO_TCP, 443);
    let steps: Vec<String> = show(&a).into_iter().flat_map(|b| b.1).collect();
    assert!(has(&steps, "to leaf2/port/port-channel20/in"), "{steps:#?}");

    // With no neighbour section on leaf1, one end is enough, and leaf2 and
    // leaf3 both claim port-channel10 of leaf1: it gets no link.
    let mut s1 = sections();
    s1.remove("lldp");
    let leaf3_lldp = br#"{"TABLE_nbor_detail":{"ROW_nbor_detail":[
        {"l_port_id":"Eth1/49","sys_name":"leaf1","port_id":"Ethernet1/1"}]}}"#;
    let e = assemble(vec![
        Input::Nxos {
            name: "leaf1".into(),
            config: CONFIG.to_vec(),
            file: "leaf1/config".into(),
            collected: collected(),
            sections: s1,
        },
        Input::Nxos {
            name: "leaf2".into(),
            config: LEAF2.as_bytes().to_vec(),
            file: "leaf2/config".into(),
            collected: Collected::default(),
            sections: leaf2_sections(LEAF2_LLDP),
        },
        Input::Nxos {
            name: "leaf3".into(),
            config: LEAF2
                .replace("hostname leaf2", "hostname leaf3")
                .into_bytes(),
            file: "leaf3/config".into(),
            collected: Collected::default(),
            sections: BTreeMap::from([(
                "lldp".to_string(),
                (leaf3_lldp.to_vec(), "leaf3/lldp".to_string()),
            )]),
        },
    ]);
    assert!(
        e.notes["leaf1"].contains(&"port-channel10: 2 links claim the port, no link".to_string()),
        "{:#?}",
        e.notes
    );
    let t = e.builder.build().expect("the twin builds");
    let a = run(&t, "Vlan30", "192.0.2.130", "192.0.2.13", PROTO_TCP, 443);
    let steps: Vec<String> = show(&a).into_iter().flat_map(|b| b.1).collect();
    assert!(!has(&steps, "port-channel20/in"), "{steps:#?}");
}

#[test]
fn a_trunk_vlan_with_no_vlan_line_floods_to_unknown() {
    let config = String::from_utf8(CONFIG.to_vec()).unwrap().replace(
        "switchport trunk allowed vlan add 50",
        "switchport trunk allowed vlan add 50,70",
    );
    let e = assemble(vec![Input::Nxos {
        name: "leaf1".into(),
        config: config.into_bytes(),
        file: "leaf1/config".into(),
        collected: collected(),
        sections: sections(),
    }]);
    assert!(e.notes["leaf1"].contains(&"VLAN 70: allowed on a trunk, no vlan line".to_string()));
    let t = e.builder.build().expect("the twin builds");
    // The rest of the trunk stays exact.
    let (_, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "192.0.2.11",
        PROTO_TCP,
        443,
    ));
    assert!(
        has(&steps, "mac 00:00:5e:00:53:b1 on port port-channel10"),
        "{steps:#?}"
    );
}

fn estate_of(config: &[u8], collected: Collected) -> Estate {
    assemble(vec![Input::Nxos {
        name: "leaf1".into(),
        config: config.to_vec(),
        file: "leaf1/config@000000000000".into(),
        collected,
        sections: sections(),
    }])
}

/// The kind name of each route of the route lookups of a twin in a VRF.
fn kinds(t: &Twin, vrf: &str) -> BTreeMap<String, &'static str> {
    let mut out = BTreeMap::new();
    for f in t.functions() {
        let any: &dyn std::any::Any = f.as_ref();
        let Some(rl) = any.downcast_ref::<RouteLookup>() else {
            continue;
        };
        if let Some(fib) = rl.tables.get(&VrfId::new(vrf)) {
            for (p, r) in fib.entries() {
                out.insert(p.to_string(), r.kind.name());
            }
        }
    }
    out
}

#[test]
fn a_learned_route_keeps_its_protocol() {
    let mut col = collected();
    col.routes.push(route(
        "default",
        "198.51.100.64/26",
        "bgp-65000",
        "Eth1/2",
        Some("198.51.100.2"),
    ));
    col.routes.push(route(
        "default",
        "198.51.100.128/26",
        "ospf-1",
        "Eth1/2",
        Some("198.51.100.2"),
    ));
    let t = estate_of(CONFIG, col)
        .builder
        .build()
        .expect("the twin builds");
    let k = kinds(&t, "default");
    assert_eq!(k["198.51.100.64/26"], "bgp");
    assert_eq!(k["198.51.100.128/26"], "ospf");
    assert_eq!(k["0.0.0.0/0"], "static");
    assert_eq!(k["192.0.2.0/26"], "connected");
    let (_, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "198.51.100.70",
        PROTO_TCP,
        443,
    ));
    assert!(
        has(
            &steps,
            "route 198.51.100.64/26 (bgp) in VRF default via 198.51.100.2 on Ethernet1/2"
        ),
        "{steps:#?}"
    );
}

#[test]
fn a_vrf_with_bgp_and_no_rows_is_unknown_outside_its_connected_routes() {
    let config = String::from_utf8(CONFIG.to_vec())
        .unwrap()
        .replace(
            "router bgp 65000\n",
            "router bgp 65000\n  vrf RED\n    address-family ipv4 unicast\n      redistribute direct route-map RM\n",
        )
        .replace(
            "vrf context RED\n",
            "vrf context RED\n  ip route 0.0.0.0/0 192.0.2.9\n",
        );
    let mut col = collected();
    col.routes.retain(|r| r.vrf != "RED");
    let e = estate_of(config.as_bytes(), col);
    let unhandled = &e.coverage["leaf1"].unhandled;
    assert!(
        unhandled
            .contains_key("router bgp */vrf */address-family ../redistribute direct route-map RM"),
        "{unhandled:?}"
    );
    assert!(!unhandled.contains_key("router bgp .."), "{unhandled:?}");
    let t = e.builder.build().expect("the twin builds");
    for (dst, route) in [("203.0.113.200", "0.0.0.0/0"), ("10.1.1.1", "10.0.0.0/8")] {
        let a = run(&t, "Vlan20", "192.0.2.70", dst, PROTO_TCP, 443);
        let (verdict, steps) = only(&a);
        assert_eq!(verdict, VerdictKind::Unknown);
        assert!(
            has(
                &steps,
                &format!("route {route} in VRF RED, vrf route table not collected")
            ),
            "{steps:#?}"
        );
        let Some(rsim_core::Verdict::Unknown(r)) = a.verdict() else {
            panic!("{steps:#?}");
        };
        assert_eq!(r.code, rsim_core::ReasonCode::NotCollected);
    }
    let k = kinds(&t, "RED");
    assert_eq!(k["0.0.0.0/0"], "static");
    assert_eq!(k["192.0.2.64/26"], "connected");
    let (_, steps) = only(&run(
        &t,
        "Vlan20",
        "192.0.2.70",
        "192.0.2.10",
        PROTO_TCP,
        443,
    ));
    assert!(
        has(&steps, "route 192.0.2.0/26 in VRF RED connected on Vlan60"),
        "{steps:#?}"
    );
}

#[test]
fn a_next_hop_in_another_vrf_resolves_in_that_vrf() {
    let (_, steps) = only(&run(
        &twin(),
        "Vlan20",
        "192.0.2.70",
        "203.0.113.200",
        PROTO_TCP,
        443,
    ));
    assert!(
        has(
            &steps,
            "route 0.0.0.0/0 in VRF RED via 198.51.100.2 on Ethernet1/2"
        ),
        "{steps:#?}"
    );
    let mut col = collected();
    col.routes.push(RouteRow {
        interface: None,
        ..route(
            "RED",
            "198.51.100.64/26",
            "bgp-65000",
            "Eth1/2",
            Some("198.51.100.2%default"),
        )
    });
    col.routes.push(RouteRow {
        interface: None,
        ..route(
            "RED",
            "198.51.100.128/26",
            "bgp-65000",
            "Eth1/2",
            Some("198.51.100.2"),
        )
    });
    let t = estate_of(CONFIG, col)
        .builder
        .build()
        .expect("the twin builds");
    let (_, steps) = only(&run(
        &t,
        "Vlan20",
        "192.0.2.70",
        "198.51.100.70",
        PROTO_TCP,
        443,
    ));
    assert!(
        has(
            &steps,
            "route 198.51.100.64/26 (bgp) in VRF RED via 198.51.100.2 on Ethernet1/2"
        ),
        "{steps:#?}"
    );
    // With no suffix, the next hop resolves in VRF RED, which has no route
    // to it other than the default route through the other VRF.
    let (_, steps) = only(&run(
        &t,
        "Vlan20",
        "192.0.2.70",
        "198.51.100.130",
        PROTO_TCP,
        443,
    ));
    assert!(
        has(
            &steps,
            "route 198.51.100.128/26 (bgp) in VRF RED via 198.51.100.2 on Ethernet1/2"
        ),
        "{steps:#?}"
    );
}

#[test]
fn a_next_hop_that_resolves_through_a_gateway_group_route_is_unknown() {
    let mut col = collected();
    col.routes.push(RouteRow {
        interface: None,
        ..route(
            "default",
            "198.51.100.64/26",
            "bgp-65000",
            "Vlan10",
            Some("192.0.2.1"),
        )
    });
    let t = estate_of(CONFIG, col)
        .builder
        .build()
        .expect("the twin builds");
    let (verdict, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "198.51.100.70",
        PROTO_TCP,
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(
        has(
            &steps,
            "route 198.51.100.64/26 (bgp) in VRF default, next hop not resolved: 192.0.2.1"
        ),
        "{steps:#?}"
    );
}

#[test]
fn a_direct_route_with_an_address_of_the_switch_as_next_hop_is_connected() {
    let mut col = collected();
    for r in &mut col.routes {
        if r.vrf == "default" && r.prefix == "192.0.2.0/26" {
            r.next_hop = Some("192.0.2.2".into());
        }
    }
    let t = estate_of(CONFIG, col)
        .builder
        .build()
        .expect("the twin builds");
    let (_, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "192.0.2.10",
        PROTO_TCP,
        443,
    ));
    assert!(
        has(
            &steps,
            "route 192.0.2.0/26 in VRF default connected on Vlan10"
        ),
        "{steps:#?}"
    );
}
