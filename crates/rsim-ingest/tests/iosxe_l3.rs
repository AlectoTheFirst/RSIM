//! The IOS-XE layer 3 lowering on the synthetic running config and the
//! synthetic text sections: the interface state, the route table of each
//! VRF, ARP and the access lists.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{
    EndpointId, FunctionId, Header, InterfaceId, NeighbourTarget, PROTO_TCP, Prefix, PrefixTable,
    Rewrite, SourceSpan, TriePrefixTable, VerdictKind, VrfId,
};
use rsim_engine::{Answer, Endpoint, Executor, Query, ReplyResult, Twin, TwinBuilder};
use rsim_functions::{
    Egress, EgressMode, Fib, Ingress, Link, Meta, Neighbour, NextHopResolution, Route, RouteKind,
    RouteLookup, RouteNextHop, Tag, VrfSelection,
};
use rsim_ingest::collected::Collected;
use rsim_ingest::estate::{Estate, Input, assemble};
use rsim_ingest::links::{External, Peer};
use rsim_ingest::{classify, iosxe};

const CONFIG: &[u8] = include_bytes!("fixtures/iosxe/running-config.txt");
const RIB: &str = include_str!("fixtures/iosxe/rib.txt");

type Sections = BTreeMap<String, (Vec<u8>, String)>;

fn sections() -> Sections {
    iosxe::SECTIONS
        .iter()
        .map(|n| {
            let path = format!(
                "{}/tests/fixtures/iosxe/{n}.txt",
                env!("CARGO_MANIFEST_DIR")
            );
            (
                n.to_string(),
                (std::fs::read(path).unwrap(), format!("edge1/{n}")),
            )
        })
        .collect()
}

/// The sections with one section replaced.
fn with_section(name: &str, text: &str) -> Sections {
    let mut s = sections();
    s.insert(
        name.to_string(),
        (text.as_bytes().to_vec(), format!("edge1/{name}")),
    );
    s
}

fn estate_with(sections: Sections) -> Estate {
    assemble(vec![Input::Iosxe {
        name: "edge1".into(),
        config: CONFIG.to_vec(),
        file: "edge1/config".into(),
        collected: Collected::default(),
        sections,
    }])
}

fn estate() -> Estate {
    estate_with(sections())
}

fn twin_with(sections: Sections) -> Twin {
    estate_with(sections)
        .builder
        .build()
        .expect("the twin builds")
}

fn twin() -> Twin {
    twin_with(sections())
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn header(src: &str, sport: u16, dst: &str, dport: u16) -> Header {
    Header::request(ip(src), ip(dst), PROTO_TCP)
        .with_src_port(sport)
        .with_dst_port(dport)
}

fn run(t: &Twin, ingress: &str, src: &str, dst: &str, port: u16) -> Answer {
    run_from(t, ingress, src, 40000, dst, port)
}

fn run_from(t: &Twin, ingress: &str, src: &str, sport: u16, dst: &str, port: u16) -> Answer {
    Executor::new(t)
        .run(
            &Query::path(t, &header(src, sport, dst, port))
                .with_ingress("edge1", ingress)
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

fn only(a: &Answer) -> (VerdictKind, Vec<String>) {
    let mut v = show(a);
    assert_eq!(v.len(), 1, "{v:#?}");
    v.remove(0)
}

fn has(steps: &[String], text: &str) -> bool {
    steps.iter().any(|s| s.contains(text))
}

/// The line of the route table section that starts with `text`, from 1.
fn rib_line(text: &str) -> u32 {
    let i = RIB
        .lines()
        .position(|l| l.trim_start().starts_with(text))
        .unwrap();
    u32::try_from(i + 1).unwrap()
}

/// The provenance of the step of a function, as `file:first-last`.
fn spans_of(a: &Answer, function: &str) -> Vec<String> {
    a.branches()
        .iter()
        .flat_map(|b| b.steps.iter())
        .filter(|s| s.function.to_string() == function)
        .flat_map(|s| s.provenance.iter())
        .map(|s| format!("{}:{}-{}", s.file, s.first_line, s.last_line))
        .collect()
}

/// A provider router `isp` behind GigabitEthernet0/0/4 of edge1, with the
/// host `server` 198.51.100.77 on its port eth1. The router edge1 has a
/// link from GigabitEthernet0/0/4 to eth0 of `isp`, and `isp` has a link
/// back.
fn linked() -> Twin {
    let doc = iosxe::read_text(CONFIG);
    let cfg = iosxe::read(&doc, &iosxe::table(true));
    let ext = External {
        peers: [(
            "GigabitEthernet0/0/4".to_string(),
            vec![Peer {
                target: FunctionId::new("isp/in/eth0"),
                far: ("isp".into(), "eth0".into()),
                provenance: vec![SourceSpan::line("isp.links", 1)],
                remote: None,
            }],
        )]
        .into_iter()
        .collect(),
        ..External::default()
    };
    let low = iosxe::lower(
        "edge1",
        "edge1/config",
        &iosxe::profile(),
        &cfg,
        &sections(),
        &ext,
    );
    let mut b = TwinBuilder::new();
    for f in low.functions {
        b.add_arc(f);
    }
    for x in low.edges {
        b.edge_interface(x);
    }
    add_isp(&mut b);
    b.build().expect("the twin builds")
}

fn add_isp(b: &mut TwinBuilder) {
    let p = iosxe::profile();
    let meta = |f: &str| {
        Meta::new(format!("isp/{f}"), "isp", &p).with_span(SourceSpan::line("isp.conf", 1))
    };
    let id = |f: &str| FunctionId::new(format!("isp/{f}"));
    let eth = |i: &str| InterfaceId::new(i);
    for i in ["eth0", "eth1"] {
        b.add(Ingress {
            meta: meta(&format!("in/{i}")),
            interface: eth(i),
            next: id("vrf"),
        });
    }
    b.add(VrfSelection {
        meta: meta("vrf"),
        by_interface: [
            (eth("eth0"), VrfId::new("default")),
            (eth("eth1"), VrfId::new("default")),
        ]
        .into_iter()
        .collect(),
        default_vrf: Some(VrfId::new("default")),
        next: id("route"),
    });
    let hop = |i: &str, gw: Option<&str>| RouteNextHop {
        interface: eth(i),
        gateway: gw.map(ip),
        next: id("nexthop"),
    };
    let mut fib = Fib::new();
    fib.insert(
        "198.51.100.64/26".parse().unwrap(),
        Route::new(RouteKind::Connected, vec![hop("eth1", None)], Vec::new()),
    );
    fib.insert(
        "0.0.0.0/0".parse().unwrap(),
        Route::new(
            RouteKind::Static,
            vec![hop("eth0", Some("198.51.100.6"))],
            Vec::new(),
        ),
    );
    b.add(RouteLookup {
        meta: meta("route"),
        tables: [(VrfId::new("default"), fib)].into_iter().collect(),
        fallback: None,
        local: None,
    });
    let mut neighbours: TriePrefixTable<Vec<Neighbour>> = TriePrefixTable::new();
    for (addr, iface, target, mac) in [
        (
            "198.51.100.77",
            "eth1",
            NeighbourTarget::Endpoint(EndpointId::new("server")),
            "00:00:5e:00:53:4d",
        ),
        (
            "198.51.100.6",
            "eth0",
            NeighbourTarget::Link,
            "00:00:5e:00:53:14",
        ),
    ] {
        neighbours.insert(
            Prefix::host(ip(addr)),
            vec![Neighbour {
                interface: eth(iface),
                target,
                owner: addr.to_string(),
                mac: Some(mac.parse().unwrap()),
                spans: Vec::new(),
            }],
        );
    }
    b.add(NextHopResolution {
        meta: meta("nexthop"),
        neighbours,
        complete: false,
        egress: [(eth("eth0"), id("out/eth0")), (eth("eth1"), id("out/eth1"))]
            .into_iter()
            .collect(),
        point_to_point: BTreeMap::new(),
    });
    b.add(Egress {
        meta: meta("out/eth1"),
        interface: eth("eth1"),
        mode: EgressMode::Routed,
        link: None,
        rewrite: Rewrite::default(),
        tag: Tag::Keep,
    });
    b.add(Egress {
        meta: meta("out/eth0"),
        interface: eth("eth0"),
        mode: EgressMode::Routed,
        link: Some(Link {
            peer: Some(FunctionId::new("edge1/in/GigabitEthernet0/0/4")),
            delay_ns: None,
            provenance: Vec::new(),
            facts: None,
        }),
        rewrite: Rewrite::default(),
        tag: Tag::Keep,
    });
    b.endpoint(Endpoint {
        id: EndpointId::new("server"),
        addresses: vec![ip("198.51.100.77")],
    });
}

/// A query from the office port of edge1 with its reply.
fn run_reply(t: &Twin, src: &str, sport: u16, dst: &str, port: u16) -> Answer {
    Executor::new(t)
        .run(
            &Query::path(t, &header(src, sport, dst, port))
                .with_ingress("edge1", "GigabitEthernet0/0/5"),
        )
        .expect("the query runs")
}

/// The verdict and the steps of the only reply.
fn only_reply(a: &Answer) -> (VerdictKind, Vec<String>) {
    assert_eq!(a.replies.len(), 1);
    match &a.replies[0].result {
        ReplyResult::Ran(r) => only(r),
        ReplyResult::NotRun(w) => panic!("the reply did not run: {w}"),
    }
}

#[test]
fn the_route_table_gives_the_global_table_and_each_vrf() {
    let doc = iosxe::read_text(CONFIG);
    let cfg = iosxe::read(&doc, &iosxe::table(true));
    let st = iosxe::state::read(&sections(), &iosxe::names(&cfg));
    let rib = st.l3.rib.unwrap().unwrap();
    let vrfs: std::collections::BTreeSet<&str> = rib.paths.iter().map(|p| p.vrf.as_str()).collect();
    assert_eq!(
        vrfs.into_iter().collect::<Vec<_>>(),
        ["BLUE", "MGMT", "RED", "default"]
    );
    let in_vrf = |vrf: &str, prefix: &str| {
        rib.paths
            .iter()
            .filter(|p| p.vrf == vrf && p.prefix.to_string() == prefix)
            .collect::<Vec<_>>()
    };
    // The same default route in 3 tables, each in its own VRF.
    assert_eq!(
        in_vrf("default", "0.0.0.0/0")[0].gateway,
        Some(ip("198.51.100.1"))
    );
    assert_eq!(
        in_vrf("MGMT", "0.0.0.0/0")[0].gateway,
        Some(ip("203.0.113.1"))
    );
    let red = in_vrf("RED", "0.0.0.0/0");
    assert_eq!(red[0].other_vrf.as_deref(), Some("default"));
    // The second path of a route is on its own line.
    let ecmp = in_vrf("default", "198.51.100.128/25");
    assert_eq!(ecmp.len(), 2);
    let line = rib_line("S        198.51.100.128/25");
    assert_eq!(ecmp[1].span.first_line, line + 1);
    assert_eq!(ecmp[1].span.file.as_ref(), "edge1/rib");
    assert_eq!(
        in_vrf("BLUE", "198.51.100.32/28")[0].interface.as_deref(),
        Some("GigabitEthernet0/0/7")
    );
    let unread: Vec<(Option<&str>, Option<String>, u32)> = rib
        .unread
        .iter()
        .map(|u| {
            (
                u.vrf.as_deref(),
                u.prefix.map(|p| p.to_string()),
                u.span.first_line,
            )
        })
        .collect();
    assert_eq!(
        unread,
        [
            (
                Some("default"),
                Some("198.51.100.192/27".to_string()),
                rib_line("B        198.51.100.192/27")
            ),
            (Some("BLUE"), None, rib_line("% Route table")),
        ]
    );
    // The rows of the addresses of the router are not neighbours.
    let arp = st.l3.arp.unwrap().unwrap();
    assert_eq!(arp.len(), 4);
    assert!(arp.iter().all(|a| a.ip != ip("198.51.100.6")));
    let ifs = st.l3.interfaces.unwrap().unwrap();
    assert_eq!(ifs["GigabitEthernet0/0/6"].oper_up, Some(false));
    assert!(ifs["GigabitEthernet0/0/6"].admin_down);
    assert_eq!(ifs["GigabitEthernet0/0/1.100"].oper_up, Some(true));
}

#[test]
fn a_vrf_header_of_another_form_makes_its_routes_unknown_in_each_vrf() {
    let rib = RIB.replace("Routing Table: MGMT", "Routing Table:MGMT");
    let doc = iosxe::read_text(CONFIG);
    let cfg = iosxe::read(&doc, &iosxe::table(true));
    let st = iosxe::state::read(&with_section("rib", &rib), &iosxe::names(&cfg));
    let r = st.l3.rib.unwrap().unwrap();
    assert!(r.paths.iter().all(|p| p.vrf != "MGMT"));
    let line = rib_line("S*    0.0.0.0/0 [1/0] via 203.0.113.1");
    let u = r.unread.iter().find(|u| u.span.first_line == line).unwrap();
    assert_eq!(u.vrf, None);
    assert_eq!(
        u.prefix.map(|p| p.to_string()).as_deref(),
        Some("0.0.0.0/0")
    );
    // A route of a table whose VRF is not known makes the lookups of its
    // prefix unknown in each VRF, the global table too.
    let t = twin_with(with_section("rib", &rib));
    let (verdict, steps) = only(&run(
        &t,
        "GigabitEthernet0/0/5",
        "192.0.2.200",
        "203.0.113.100",
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(
        has(
            &steps,
            "route 203.0.113.0/24 in VRF default has no next hop"
        ),
        "{steps:#?}"
    );
}

#[test]
fn with_a_route_table_the_routing_is_irrelevant_and_each_handled_line_is_read() {
    let e = estate();
    let doc = iosxe::read_text(CONFIG);
    assert_eq!(e.coverage["edge1"], classify(&doc, &iosxe::table(true)));
    assert_eq!(e.unread["edge1"], Vec::<String>::new());
}

#[test]
fn a_packet_follows_a_static_route_and_the_overload_rule_translates_its_source() {
    let t = twin();
    let a = run(
        &t,
        "GigabitEthernet0/0/5",
        "192.0.2.200",
        "198.51.100.77",
        443,
    );
    let (verdict, steps) = only(&a);
    for text in [
        "route 198.51.100.64/26 in VRF default via 198.51.100.5 on GigabitEthernet0/0/4",
        "snat translated to 203.0.113.32",
        "session-commit",
        "nexthop 198.51.100.5 is 00:00:5e:00:53:05 on GigabitEthernet0/0/4",
        "out/GigabitEthernet0/0/4 no link",
    ] {
        assert!(has(&steps, text), "{text}: {steps:#?}");
    }
    // The order of Cisco IOS: the route lookup, then the NAT of the inside
    // source.
    let route = steps.iter().position(|s| s.starts_with("edge1/route "));
    let snat = steps.iter().position(|s| s.starts_with("edge1/snat "));
    assert!(route < snat, "{steps:#?}");
    assert_eq!(verdict, VerdictKind::Unknown);
    // Provenance: the ingress names the config stanza and the interface
    // state record, the route its line of the route table, and the next hop
    // its ARP row.
    let ingress = spans_of(&a, "edge1/in/GigabitEthernet0/0/5");
    assert!(
        ingress.contains(&"edge1/config:211-215".to_string()),
        "{ingress:?}"
    );
    assert!(ingress.iter().any(|s| s.starts_with("edge1/interfaces:")));
    let l = rib_line("S        198.51.100.64/26");
    assert!(spans_of(&a, "edge1/route").contains(&format!("edge1/rib:{l}-{l}")));
    assert!(spans_of(&a, "edge1/nexthop").contains(&"edge1/arp:7-7".to_string()));
    assert!(
        spans_of(&a, "edge1/snat")
            .iter()
            .any(|s| s.starts_with("edge1/config:253-")),
        "the line of the list rule"
    );
}

#[test]
fn the_reply_of_the_overload_rule_comes_back_through_the_session() {
    let t = linked();
    let a = run_reply(&t, "192.0.2.200", 40000, "198.51.100.77", 443);
    let (verdict, steps) = only(&a);
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    assert!(has(&steps, "snat translated to 203.0.113.32"));
    assert!(has(&steps, "deliver to server on eth1"));
    let (verdict, steps) = only_reply(&a);
    for text in [
        "acl-in/GigabitEthernet0/0/4 permitted · ACL edge1:acl:WAN2-IN rule WAN2-IN/40",
        "session-lookup reply packets · session 0, translated",
        "route 192.0.2.192/27 in VRF default connected on GigabitEthernet0/0/5",
        "nexthop 192.0.2.200 is 00:00:5e:00:53:c8 on GigabitEthernet0/0/5",
        "out/GigabitEthernet0/0/5 no link",
    ] {
        assert!(has(&steps, text), "{text}: {steps:#?}");
    }
    // The office port has no link, so the reply ends there.
    assert_eq!(verdict, VerdictKind::Unknown);
}

#[test]
fn the_static_rule_translates_both_ways() {
    // Inside to outside, and the reply through the session.
    let t = linked();
    let a = run_reply(&t, "192.0.2.220", 40000, "198.51.100.77", 443);
    let (verdict, steps) = only(&a);
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    assert!(has(&steps, "snat translated to 203.0.113.20"));
    let (_, steps) = only_reply(&a);
    assert!(has(&steps, "rule WAN2-IN/30"), "{steps:#?}");
    assert!(has(
        &steps,
        "session-lookup reply packets · session 0, translated"
    ));
    assert!(has(&steps, "nexthop 192.0.2.220 is"));
    // Outside to inside: the NAT of the outside destination comes before
    // the route lookup.
    let t = twin();
    let (_, steps) = only(&run(
        &t,
        "GigabitEthernet0/0/4",
        "198.51.100.77",
        "203.0.113.20",
        443,
    ));
    let dnat = steps
        .iter()
        .position(|s| s.contains("dnat translated to 192.0.2.220"));
    let route = steps.iter().position(|s| {
        s.contains("route 192.0.2.192/27 in VRF default connected on GigabitEthernet0/0/5")
    });
    assert!(
        dnat.is_some() && route.is_some() && dnat < route,
        "{steps:#?}"
    );
    assert!(has(&steps, "nexthop 192.0.2.220 is"));
    // The rule applies only on an outside interface.
    let (_, steps) = only(&run(
        &t,
        "GigabitEthernet0/0/5",
        "192.0.2.200",
        "203.0.113.20",
        443,
    ));
    assert!(has(&steps, "dnat not translated"), "{steps:#?}");
}

#[test]
fn the_input_acl_denies_one_flow() {
    let t = twin();
    let (verdict, steps) = only(&run(
        &t,
        "GigabitEthernet0/0/4",
        "198.51.100.77",
        "203.0.113.20",
        22,
    ));
    assert_eq!(verdict, VerdictKind::Drop, "{steps:#?}");
    assert!(has(
        &steps,
        "acl-in/GigabitEthernet0/0/4 denied · ACL edge1:acl:WAN2-IN rule WAN2-IN/10"
    ));
    // Another packet matches no entry and meets the implicit deny.
    let (verdict, steps) = only(&run(
        &t,
        "GigabitEthernet0/0/4",
        "198.51.100.77",
        "192.0.2.200",
        443,
    ));
    assert_eq!(verdict, VerdictKind::Drop, "{steps:#?}");
    assert!(!has(&steps, "edge1/route"));
}

#[test]
fn the_extendable_static_rule_makes_only_its_packets_unknown() {
    let t = twin();
    let (verdict, steps) = only(&run_from(
        &t,
        "GigabitEthernet0/0/5",
        "192.0.2.10",
        443,
        "198.51.100.77",
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(&steps, "edge1/snat"), "{steps:#?}");
    assert!(!has(&steps, "edge1/nexthop"));
    // Another source port of the same host is not a packet of the rule.
    let (_, steps) = only(&run(
        &t,
        "GigabitEthernet0/0/5",
        "192.0.2.10",
        "198.51.100.77",
        443,
    ));
    assert!(has(&steps, "snat translated to 203.0.113.32"), "{steps:#?}");
    assert!(estate().notes["edge1"].iter().any(|n| n
        == "static 192.0.2.10 to 198.51.100.2: extendable is not lowered, so the packets that the rule can translate are unknown"));
}

#[test]
fn equal_cost_paths_are_a_forwarding_choice() {
    let t = twin();
    let a = run(
        &t,
        "GigabitEthernet0/0/5",
        "192.0.2.200",
        "198.51.100.130",
        443,
    );
    let v = show(&a);
    assert_eq!(v.len(), 2, "{v:#?}");
    assert!(has(&v[0].1, "via 198.51.100.1 on GigabitEthernet0/0/0"));
    assert!(has(&v[1].1, "via 198.51.100.5 on GigabitEthernet0/0/4"));
    let counts: Vec<u32> = a
        .branches()
        .iter()
        .flat_map(|b| b.steps.iter())
        .filter_map(|s| s.alternative.as_ref().map(|x| x.count))
        .collect();
    assert_eq!(counts, [2, 2]);
    // The port with a zone-member line makes its egress unknown.
    assert_eq!(v[0].0, VerdictKind::Unknown);
    assert!(has(&v[0].1, "acl-out/GigabitEthernet0/0/0"));
}

#[test]
fn an_unread_route_line_makes_its_prefix_unknown() {
    let t = twin();
    let a = run(
        &t,
        "GigabitEthernet0/0/5",
        "192.0.2.200",
        "198.51.100.200",
        443,
    );
    let (verdict, steps) = only(&a);
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(
        &steps,
        "route 198.51.100.192/27 in VRF default has no next hop"
    ));
    let l = rib_line("B        198.51.100.192/27");
    assert_eq!(spans_of(&a, "edge1/route"), [format!("edge1/rib:{l}-{l}")]);
    let notes = &estate().notes["edge1"];
    assert!(notes.contains(&format!(
        "route 198.51.100.192/27 in VRF default: edge1/rib line {l} is not read: B        198.51.100.192/27 [20/0] via 2001:db8::9, 1d00h"
    )));
}

#[test]
fn an_unread_line_with_no_prefix_makes_the_vrf_unknown() {
    let t = twin();
    let a = run(
        &t,
        "GigabitEthernet0/0/7",
        "198.51.100.40",
        "198.51.100.34",
        443,
    );
    let (verdict, steps) = only(&a);
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(
        has(&steps, "route 0.0.0.0/0 in VRF BLUE has no next hop"),
        "{steps:#?}"
    );
    let l = rib_line("% Route table");
    assert_eq!(spans_of(&a, "edge1/route"), [format!("edge1/rib:{l}-{l}")]);
    // An address of the router is still local.
    let (verdict, steps) = only(&run(
        &t,
        "GigabitEthernet0/0/7",
        "198.51.100.40",
        "198.51.100.33",
        22,
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
}

#[test]
fn a_next_hop_in_a_vrf_is_unknown_because_its_arp_table_is_not_collected() {
    let t = twin();
    for dst in ["203.0.113.60", "192.0.2.77"] {
        let (verdict, steps) = only(&run(&t, "GigabitEthernet0", "203.0.113.50", dst, 443));
        assert_eq!(verdict, VerdictKind::Unknown);
        assert!(has(&steps, "in VRF MGMT"), "{steps:#?}");
        assert!(
            has(&steps, "the ARP table of VRF MGMT is not collected"),
            "{steps:#?}"
        );
        assert!(!has(&steps, "edge1/nexthop"));
    }
}

#[test]
fn the_unhandled_lines_of_an_interface_make_its_packets_unknown() {
    let t = twin();
    // In: the zone-member line of the WAN port.
    let (verdict, steps) = only(&run(
        &t,
        "GigabitEthernet0/0/0",
        "198.51.100.1",
        "198.51.100.2",
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(&steps, "acl-in/GigabitEthernet0/0/0"), "{steps:#?}");
    assert!(!has(&steps, "edge1/route"));
    // Out: the default route leaves on that port.
    let (verdict, steps) = only(&run(
        &t,
        "GigabitEthernet0/0/5",
        "192.0.2.200",
        "203.0.113.100",
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(&steps, "acl-out/GigabitEthernet0/0/0"), "{steps:#?}");
    let notes = &estate().notes["edge1"];
    for n in [
        "GigabitEthernet0/0/0: options not lowered: zone-member security OUTSIDE, crypto map VPN, ip verify unicast source reachable-via rx",
        "GigabitEthernet0/0/1.100: options not lowered: zone-member security INSIDE, ip nat inside in VRF RED",
        "GigabitEthernet0/0/1.200: options not lowered: ip policy route-map PBR-BLUE",
        "GigabitEthernet0/0/1.100: HSRP group 1: the group state is not read, so the packets to its virtual addresses are unknown",
        "route 0.0.0.0/0 in VRF RED: a next hop in VRF default is not lowered",
        "static route 0.0.0.0/0 via 198.51.100.9 in VRF default: the route table has no such static path",
        "IPv6 is not lowered: each IPv6 packet is unknown at the route lookup",
    ] {
        assert!(notes.iter().any(|x| x == n), "{n} is not in {notes:#?}");
    }
}

#[test]
fn a_shut_interface_and_an_interface_with_no_address_are_not_lowered() {
    let doc = iosxe::read_text(CONFIG);
    let cfg = iosxe::read(&doc, &iosxe::table(true));
    let low = iosxe::lower(
        "edge1",
        "edge1/config",
        &iosxe::profile(),
        &cfg,
        &sections(),
        &External::default(),
    );
    let ids: Vec<String> = low.functions.iter().map(|f| f.id().to_string()).collect();
    for i in [
        "Loopback0",
        "GigabitEthernet0/0/0",
        "GigabitEthernet0/0/1.100",
        "GigabitEthernet0/0/1.200",
        "GigabitEthernet0/0/4",
        "GigabitEthernet0/0/5",
        "GigabitEthernet0/0/7",
        "Tunnel10",
        "GigabitEthernet0",
    ] {
        assert!(ids.contains(&format!("edge1/in/{i}")), "{i}");
    }
    for i in [
        "GigabitEthernet0/0/1",
        "GigabitEthernet0/0/2",
        "GigabitEthernet0/0/3",
        "GigabitEthernet0/0/6",
    ] {
        assert!(!ids.contains(&format!("edge1/in/{i}")), "{i}");
    }
}

#[test]
fn the_access_lists_of_the_section_are_a_cross_check() {
    let notes = &estate().notes["edge1"];
    assert!(!notes.iter().any(|n| n.starts_with("ACL ")), "{notes:#?}");
    let acls =
        String::from_utf8(sections()["acls"].0.clone()).unwrap() + "    50 permit icmp any any\n";
    let notes = &estate_with(with_section("acls", &acls)).notes["edge1"];
    assert!(notes.iter().any(|n| n
        == "ACL WAN2-IN: show ip access-lists gives the entries 10 deny, 20 permit, 30 permit, 40 permit, 50 permit, and the config gives 10 deny, 20 permit, 30 permit, 40 permit; the config decides"), "{notes:#?}");
    // The config decides: the entry is not lowered.
    let t = twin_with(with_section("acls", &acls));
    let (verdict, _) = only(&run(
        &t,
        "GigabitEthernet0/0/4",
        "198.51.100.77",
        "203.0.113.20",
        22,
    ));
    assert_eq!(verdict, VerdictKind::Drop);
}

#[test]
fn without_sections_each_route_lookup_is_unknown() {
    let t = twin_with(BTreeMap::new());
    let (verdict, steps) = only(&run(
        &t,
        "GigabitEthernet0/0/5",
        "192.0.2.200",
        "198.51.100.77",
        443,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(
        &steps,
        "route 0.0.0.0/0 in VRF default has no next hop"
    ));
    let e = estate_with(BTreeMap::new());
    let doc = iosxe::read_text(CONFIG);
    assert_eq!(e.coverage["edge1"], classify(&doc, &iosxe::table(false)));
}

#[test]
fn two_builds_give_the_same_answers() {
    let (a, b) = (twin(), twin());
    for dst in ["198.51.100.130", "198.51.100.200", "198.51.100.77"] {
        let q = |t: &Twin| show(&run(t, "GigabitEthernet0/0/5", "192.0.2.200", dst, 443));
        assert_eq!(q(&a), q(&b));
    }
    assert_eq!(estate().notes, estate().notes);
}
