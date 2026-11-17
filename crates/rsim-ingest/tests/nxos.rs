//! The NX-OS coverage and the layer 3 lowering on a synthetic running config
//! with fake secrets.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{Header, PROTO_TCP, PROTO_UDP, VerdictKind};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::collected::{Collected, LinkRow, MacRow, NeighbourRow, RouteRow, row_span};
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
    ["interfaces", "hsrp", "vrrp", "lldp"]
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
    let cov = classify(&doc, &nxos::table(true));
    let mut paths: Vec<&str> = cov.ranked().iter().map(|r| r.0).collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        ["interface */vpc 10", "ip ospf authentication-key <secret>"]
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
        "203.0.113.200",
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
    // A next hop in another VRF.
    let (verdict, steps) = only(&run(
        &t,
        "Vlan20",
        "192.0.2.70",
        "203.0.113.200",
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
            "Ethernet1/9: options not lowered: vpc 10",
            "leaf1/vlan10/00:00:5e:00:53:e1: a next hop of a route, so it is not an endpoint",
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
        sections: sections(),
    }]);
    let t = e.builder.build().expect("the twin builds");
    let (_, steps) = only(&run(
        &t,
        "Vlan30",
        "192.0.2.130",
        "203.0.113.200",
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
            "snat not translated · source NAT leaf1:nat:inside rule A/10"
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
        "mac 00:00:5e:00:53:30 is on port svi/Vlan30",
        "handoff/Vlan30 untagged to leaf1/in/Vlan30",
        "out/Vlan10 leave on Vlan10 to leaf1/svi/Vlan10/in",
        "mac 00:00:5e:00:53:a2 is on port Ethernet1/6",
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
        "acl-in/Vlan10 denied · ACL leaf1:acl:WEB rule WEB/20"
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
    assert!(has(
        &steps,
        "session-lookup reply packets · session 0, translated"
    ));
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
        has(&steps, "mac 00:00:5e:00:53:b1 is on port port-channel10"),
        "{steps:#?}"
    );
    // A MAC that the table does not have floods. The copy to the trunk is
    // unknown, because the spanning tree state is not collected.
    let a = run(&t, "Vlan30", "192.0.2.130", "192.0.2.12", PROTO_TCP, 443);
    let all: Vec<String> = show(&a).into_iter().flat_map(|b| b.1).collect();
    assert!(
        has(&all, "the spanning tree state of the port is not collected"),
        "{all:#?}"
    );
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
        has(&steps, "no egress function · port sup-eth1(R)"),
        "{steps:#?}"
    );
    assert!(
        notes.iter().any(|n| n.contains("Vlan10: HSRP group 10")),
        "{notes:#?}"
    );
    assert!(
        notes
            .iter()
            .any(|n| n.contains("route 192.0.2.1/32 in VRF default: a route of a gateway group")),
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
        "nexthop 192.0.2.20 is 00:00:5e:00:53:e1 on Vlan10"
    ));
    assert!(has(&steps, "mac 00:00:5e:00:53:e1 is on port Ethernet1/6"));
    let notes = &estate().notes["leaf1"];
    assert!(
        notes.contains(
            &"leaf1/vlan10/00:00:5e:00:53:e1: a next hop of a route, so it is not an endpoint"
                .to_string()
        )
    );
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
    assert!(has(&steps, "options not lowered: vpc 10"), "{steps:#?}");
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
        has(&steps, "mac 00:00:0c:9f:f0:14 is on port port-channel10"),
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
        has(&steps, "mac 00:00:5e:00:53:b2 is on port port-channel10"),
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
