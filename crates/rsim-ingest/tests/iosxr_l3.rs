//! The IOS-XR layer 3 lowering on the synthetic running config and the
//! synthetic text sections: the interface state, the VRF members, the route
//! table and ARP.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{Header, PROTO_TCP, VerdictKind};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::collected::Collected;
use rsim_ingest::estate::{Estate, Input, assemble};
use rsim_ingest::route_tables::RouteTables;
use rsim_ingest::{classify, iosxr};

const CONFIG: &[u8] = include_bytes!("fixtures/iosxr/running-config.txt");
const RIB: &str = include_str!("fixtures/iosxr/rib.txt");

fn sections() -> BTreeMap<String, (Vec<u8>, String)> {
    iosxr::SECTIONS
        .iter()
        .map(|n| {
            let path = format!(
                "{}/tests/fixtures/iosxr/{n}.txt",
                env!("CARGO_MANIFEST_DIR")
            );
            (
                n.to_string(),
                (std::fs::read(path).unwrap(), format!("pe1/{n}")),
            )
        })
        .collect()
}

fn estate_with(sections: BTreeMap<String, (Vec<u8>, String)>) -> Estate {
    assemble(vec![Input::Iosxr {
        name: "pe1".into(),
        config: CONFIG.to_vec(),
        file: "pe1/config".into(),
        collected: Collected::default(),
        sections,
    }])
}

fn estate() -> Estate {
    estate_with(sections())
}

fn twin() -> Twin {
    estate().builder.build().expect("the twin builds")
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn run(t: &Twin, ingress: &str, src: &str, dst: &str, port: u16) -> Answer {
    let h = Header::request(ip(src), ip(dst), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(port);
    Executor::new(t)
        .run(
            &Query::path(t, &h)
                .with_ingress("pe1", ingress)
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

#[test]
fn the_route_table_section_gives_paths_and_unread_lines() {
    let doc = iosxr::read_text(CONFIG);
    let cfg = iosxr::read(
        &doc,
        &iosxr::table(&RouteTables::uniform(true, iosxr::dynamic_vrfs(&doc))),
    );
    let st = iosxr::state::read(&sections(), &iosxr::names(&cfg));
    let rib = st.rib.unwrap().unwrap();
    let ecmp: Vec<_> = rib
        .paths
        .iter()
        .filter(|p| p.prefix.to_string() == "198.51.100.64/26")
        .collect();
    assert_eq!(ecmp.len(), 2);
    assert_eq!(ecmp[1].interface.as_deref(), Some("GigabitEthernet0/0/0/3"));
    let line = rib_line("O    198.51.100.64/26");
    assert_eq!(
        (ecmp[0].span.first_line, ecmp[0].span.last_line),
        (line, line)
    );
    assert_eq!(ecmp[0].span.file.as_ref(), "pe1/rib");
    let backup = rib.paths.iter().find(|p| p.backup).unwrap();
    assert_eq!(backup.prefix.to_string(), "198.51.100.128/26");
    let vpn = rib
        .paths
        .iter()
        .find(|p| p.prefix.to_string() == "198.51.100.96/27")
        .unwrap();
    assert_eq!(vpn.vrf, "RED");
    assert_eq!(vpn.other_vrf.as_deref(), Some("default"));
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
                Some("198.51.100.160/27".to_string()),
                rib_line("O    198.51.100.160/27") + 1
            ),
            (
                Some("default"),
                Some("198.51.100.192/27".to_string()),
                rib_line("B    198.51.100.192/27")
            ),
            (Some("MGMT"), None, rib_line("Route table of this VRF")),
        ]
    );
    // The short names of ARP resolve to the names of the config.
    let arp = st.arp.unwrap().unwrap();
    assert!(arp.iter().any(|a| a.interface == "Bundle-Ether20.100"));
    assert!(arp.iter().any(|a| a.interface == "GigabitEthernet0/0/0/3"));
    assert!(arp.iter().all(|a| a.ip != ip("192.0.2.1")), "own address");
    let ifs = st.interfaces.unwrap().unwrap();
    assert_eq!(ifs["GigabitEthernet0/0/0/4"].oper_up, Some(false));
    assert_eq!(ifs["Bundle-Ether20.100"].oper_up, Some(true));
}

#[test]
fn with_a_route_table_the_routing_is_irrelevant_and_each_handled_line_is_read() {
    let e = estate();
    let doc = iosxr::read_text(CONFIG);
    assert_eq!(
        e.coverage["pe1"],
        classify(
            &doc,
            &iosxr::table(&RouteTables::uniform(true, iosxr::dynamic_vrfs(&doc)))
        )
    );
    assert_eq!(e.unread["pe1"], Vec::<String>::new());
}

#[test]
fn a_packet_follows_the_static_default_through_its_connected_next_hop() {
    let t = twin();
    let a = run(&t, "Bundle-Ether10", "198.51.100.2", "192.0.2.77", 443);
    let (verdict, steps) = only(&a);
    assert!(
        has(
            &steps,
            "route 0.0.0.0/0 in VRF default via 203.0.113.254 on GigabitEthernet0/0/0/3"
        ),
        "{steps:#?}"
    );
    assert!(has(&steps, "nexthop 203.0.113.254 is"));
    // The interface has no link, so the egress is unknown.
    assert!(has(&steps, "out/GigabitEthernet0/0/0/3 no link"));
    assert_eq!(verdict, VerdictKind::Unknown);
    // Provenance: the ingress names the config stanza and the interface
    // state record, the route names its line of the route table.
    let ingress = spans_of(&a, "pe1/in/Bundle-Ether10");
    assert!(
        ingress.contains(&"pe1/config:114-120".to_string()),
        "{ingress:?}"
    );
    assert!(ingress.iter().any(|s| s.starts_with("pe1/interfaces:2-")));
    let l = rib_line("S*   0.0.0.0/0");
    assert!(spans_of(&a, "pe1/route").contains(&format!("pe1/rib:{l}-{l}")));
    assert!(
        spans_of(&a, "pe1/nexthop")
            .iter()
            .any(|s| s.starts_with("pe1/arp:"))
    );
}

#[test]
fn equal_cost_paths_are_a_forwarding_choice() {
    let t = twin();
    let a = run(&t, "Bundle-Ether10", "198.51.100.2", "198.51.100.70", 443);
    let v = show(&a);
    assert_eq!(v.len(), 2, "{v:#?}");
    assert!(has(&v[0].1, "via 198.51.100.2 on Bundle-Ether10"));
    assert!(has(&v[1].1, "via 203.0.113.254 on GigabitEthernet0/0/0/3"));
    let counts: Vec<u32> = a
        .branches()
        .iter()
        .flat_map(|b| b.steps.iter())
        .filter_map(|s| s.alternative.as_ref().map(|x| x.count))
        .collect();
    assert_eq!(counts, [2, 2]);
}

#[test]
fn a_backup_path_does_not_forward() {
    let t = twin();
    let (_, steps) = only(&run(
        &t,
        "Bundle-Ether10",
        "198.51.100.2",
        "198.51.100.130",
        443,
    ));
    assert!(has(
        &steps,
        "route 198.51.100.128/26 (ospf) in VRF default via 198.51.100.2 on Bundle-Ether10"
    ));
    assert!(!has(&steps, "GigabitEthernet0/0/0/3"));
}

#[test]
fn a_backup_path_with_no_interface_does_not_forward() {
    let mut s = sections();
    let rib = String::from_utf8(s["rib"].0.clone()).unwrap().replace(
        "C    203.0.113.0/24 is directly connected",
        "B    198.51.100.224/27 [20/0] via 198.51.100.2, 1d00h\n                      \
         [20/0] via 203.0.113.254, 1d00h (!)\n\
         C    203.0.113.0/24 is directly connected",
    );
    s.get_mut("rib").unwrap().0 = rib.into_bytes();
    let t = estate_with(s).builder.build().expect("the twin builds");
    let (_, steps) = only(&run(
        &t,
        "Bundle-Ether10",
        "198.51.100.2",
        "198.51.100.230",
        443,
    ));
    assert!(has(
        &steps,
        "route 198.51.100.224/27 (bgp) in VRF default via 198.51.100.2 on Bundle-Ether10"
    ));
    assert!(!has(&steps, "203.0.113.254"), "{steps:#?}");
}

#[test]
fn an_unread_route_line_makes_its_prefix_unknown() {
    let t = twin();
    // A route line that the template cannot read.
    let a = run(&t, "Bundle-Ether10", "198.51.100.2", "198.51.100.200", 443);
    let (verdict, steps) = only(&a);
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(
        &steps,
        "route 198.51.100.192/27 in VRF default has no next hop"
    ));
    let l = rib_line("B    198.51.100.192/27");
    assert_eq!(spans_of(&a, "pe1/route"), [format!("pe1/rib:{l}-{l}")]);
    // A path line that the template cannot read, below a route line that it
    // reads: the route is unknown, not a route with fewer paths.
    let a = run(&t, "Bundle-Ether10", "198.51.100.2", "198.51.100.170", 443);
    let (verdict, steps) = only(&a);
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(
        &steps,
        "route 198.51.100.160/27 in VRF default has no next hop"
    ));
    let l = rib_line("O    198.51.100.160/27") + 1;
    assert_eq!(spans_of(&a, "pe1/route"), [format!("pe1/rib:{l}-{l}")]);
    // A longer prefix inside a shorter one that is read is not affected.
    let (_, steps) = only(&run(
        &t,
        "Bundle-Ether10",
        "198.51.100.2",
        "198.51.100.130",
        443,
    ));
    assert!(has(&steps, "via 198.51.100.2 on Bundle-Ether10"));
    let notes = &estate().notes["pe1"];
    assert!(notes.contains(&format!(
        "route 198.51.100.192/27 in VRF default: pe1/rib line {} is not read: B    198.51.100.192/27 [200/0] via 2001:db8::9, 1d00h",
        rib_line("B    198.51.100.192/27")
    )));
}

#[test]
fn an_unread_line_with_no_prefix_makes_the_vrf_unknown() {
    let t = twin();
    let a = run(&t, "MgmtEth0/RP0/CPU0/0", "192.0.2.63", "192.0.2.64", 443);
    let (verdict, steps) = only(&a);
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(&steps, "route 0.0.0.0/0 in VRF MGMT has no next hop"));
    let l = rib_line("Route table of this VRF");
    assert_eq!(spans_of(&a, "pe1/route"), [format!("pe1/rib:{l}-{l}")]);
    // An address of the router is still local.
    let (verdict, steps) = only(&run(
        &t,
        "MgmtEth0/RP0/CPU0/0",
        "192.0.2.63",
        "192.0.2.250",
        22,
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
}

#[test]
fn the_output_acl_denies_one_flow_and_the_qos_policies_forward() {
    let t = twin();
    let (verdict, steps) = only(&run(
        &t,
        "Bundle-Ether20.100",
        "192.0.2.20",
        "192.0.2.70",
        23,
    ));
    assert_eq!(verdict, VerdictKind::Drop, "{steps:#?}");
    assert!(has(&steps, "qos-in/Bundle-Ether20.100"));
    assert!(has(
        &steps,
        "route 192.0.2.64/26 in VRF RED connected on Bundle-Ether20.100"
    ));
    assert!(has(&steps, "denied · ACL pe1:acl:RED-OUT rule RED-OUT/10"));
    let (verdict, steps) = only(&run(
        &t,
        "Bundle-Ether20.100",
        "192.0.2.20",
        "192.0.2.70",
        80,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(
        &steps,
        "permitted · ACL pe1:acl:RED-OUT rule RED-OUT/20"
    ));
    assert!(has(&steps, "qos-out/Bundle-Ether20.100"));
    assert!(has(&steps, "out/Bundle-Ether20.100 no link"));
}

#[test]
fn a_vrf_static_route_resolves_through_the_connected_network() {
    let t = twin();
    let (_, steps) = only(&run(
        &t,
        "Bundle-Ether20.100",
        "192.0.2.20",
        "192.0.2.200",
        80,
    ));
    assert!(
        has(
            &steps,
            "route 192.0.2.192/27 in VRF RED via 192.0.2.10 on Bundle-Ether20.100"
        ),
        "{steps:#?}"
    );
    assert!(has(&steps, "nexthop 192.0.2.10 is"));
}

#[test]
fn an_unreadable_acl_entry_makes_only_the_packets_that_reach_it_unknown() {
    let t = twin();
    let (_, steps) = only(&run(
        &t,
        "GigabitEthernet0/0/0/3",
        "198.51.100.77",
        "203.0.113.10",
        80,
    ));
    assert!(
        has(&steps, "permitted · ACL pe1:acl:EDGE-IN rule EDGE-IN/20"),
        "{steps:#?}"
    );
    assert!(has(&steps, "nexthop 203.0.113.10 is"));
    let (verdict, steps) = only(&run(
        &t,
        "GigabitEthernet0/0/0/3",
        "198.51.100.77",
        "203.0.113.10",
        22,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(&steps, "acl-in/GigabitEthernet0/0/0/3"), "{steps:#?}");
    assert!(!has(&steps, "pe1/route"));
}

#[test]
fn what_is_not_lowered_gives_unknown() {
    let t = twin();
    // A VPN route whose next hop is in the default VRF.
    let (verdict, steps) = only(&run(
        &t,
        "Bundle-Ether20.100",
        "192.0.2.20",
        "198.51.100.100",
        80,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(
        &steps,
        "route 198.51.100.96/27 (bgp) in VRF RED has no next hop"
    ));
    // A next hop that resolves through a route that is not connected.
    let (verdict, steps) = only(&run(
        &t,
        "Bundle-Ether10",
        "198.51.100.2",
        "198.51.100.40",
        80,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(
        &steps,
        "route 198.51.100.32/27 (bgp) in VRF default has no next hop"
    ));
    // The uRPF line of the interface.
    let (verdict, steps) = only(&run(
        &t,
        "Bundle-Ether20.200",
        "192.0.2.130",
        "192.0.2.129",
        22,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(&steps, "acl-in/Bundle-Ether20.200"));
    let notes = &estate().notes["pe1"];
    for n in [
        "route 198.51.100.96/27 in VRF RED: a next hop in VRF default is reached through a label switched path, which is not lowered",
        "route 198.51.100.32/27 in VRF default: the next hop 203.0.113.9 does not resolve through one connected route",
        "GigabitEthernet0/0/0/4: VRF BLUE in show vrf all detail, and the default VRF in the config; the config decides",
        "IPv6 is not lowered: each IPv6 packet is unknown at the route lookup",
    ] {
        assert!(notes.iter().any(|x| x == n), "{n} is not in {notes:#?}");
    }
}

#[test]
fn a_shut_interface_and_an_interface_with_no_address_are_not_lowered() {
    let doc = iosxr::read_text(CONFIG);
    let cfg = iosxr::read(
        &doc,
        &iosxr::table(&RouteTables::uniform(true, iosxr::dynamic_vrfs(&doc))),
    );
    let (low, _) = iosxr::lower(
        "pe1",
        "pe1/config",
        &iosxr::profile(),
        &cfg,
        &sections(),
        &Default::default(),
    );
    let ids: Vec<String> = low.functions.iter().map(|f| f.id().to_string()).collect();
    for i in [
        "Bundle-Ether10",
        "Bundle-Ether20.100",
        "Bundle-Ether20.200",
        "Loopback0",
        "MgmtEth0/RP0/CPU0/0",
        "GigabitEthernet0/0/0/3",
    ] {
        assert!(ids.contains(&format!("pe1/in/{i}")), "{i}");
    }
    for i in [
        "GigabitEthernet0/0/0/4",
        "Bundle-Ether20",
        "GigabitEthernet0/0/0/0",
    ] {
        assert!(!ids.contains(&format!("pe1/in/{i}")), "{i}");
    }
}

#[test]
fn without_sections_each_route_lookup_is_unknown() {
    let t = estate_with(BTreeMap::new())
        .builder
        .build()
        .expect("the twin builds");
    let (verdict, steps) = only(&run(
        &t,
        "Bundle-Ether10",
        "198.51.100.2",
        "203.0.113.10",
        80,
    ));
    assert_eq!(verdict, VerdictKind::Unknown);
    assert!(has(
        &steps,
        "route 0.0.0.0/0 in VRF default: vrf route table not collected"
    ));
}

#[test]
fn two_builds_give_the_same_answers() {
    let (a, b) = (twin(), twin());
    for dst in ["198.51.100.70", "198.51.100.200", "192.0.2.77"] {
        let q = |t: &Twin| show(&run(t, "Bundle-Ether10", "198.51.100.2", dst, 443));
        assert_eq!(q(&a), q(&b));
    }
    assert_eq!(estate().notes, estate().notes);
}

#[test]
fn a_learned_route_keeps_its_protocol() {
    let t = twin();
    let mut kinds = BTreeMap::new();
    for f in t.functions() {
        let any: &dyn std::any::Any = f.as_ref();
        if let Some(rl) = any.downcast_ref::<rsim_functions::RouteLookup>()
            && let Some(fib) = rl.tables.get(&rsim_core::VrfId::new("default"))
        {
            for (p, r) in fib.entries() {
                kinds.insert(p.to_string(), r.kind.name());
            }
        }
    }
    assert_eq!(kinds["198.51.100.64/26"], "ospf");
    assert_eq!(kinds["198.51.100.32/27"], "bgp");
    assert_eq!(kinds["0.0.0.0/0"], "static");
    assert_eq!(kinds["198.51.100.0/30"], "connected");
    assert_eq!(kinds["198.51.100.1/32"], "local");
}
