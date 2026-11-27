//! The OSPF config of IOS-XR: the `router ospf` and `router ospfv3`
//! stanzas into the OSPF config of the router.

use std::net::{IpAddr, Ipv4Addr};

use rsim_ingest::route_tables::RouteTables;
use rsim_ingest::{State, classify, iosxr};
use rsim_routing::ospf::AreaType;
use rsim_routing::ospf::config::{NetworkType, Process, RouterConfig, Source};

const FILE: &str = "pe1/config@000000000000";

fn table(rib: bool, doc: &rsim_ingest::stanza::Document) -> rsim_ingest::coverage::Table {
    iosxr::table(&RouteTables::uniform(rib, iosxr::dynamic_vrfs(doc)))
}

/// The OSPF config of a running config, with a check that each handled line
/// is read.
fn ospf(text: &str) -> RouterConfig {
    let doc = iosxr::read_text(text.as_bytes());
    let mut out = Vec::new();
    for rib in [true, false] {
        let table = table(rib, &doc);
        let cfg = iosxr::read(&doc, &table);
        assert_eq!(iosxr::unread(&doc, &table, &cfg.read), Vec::<String>::new());
        out.push(iosxr::ospf_router_config(&cfg, FILE));
    }
    assert_eq!(out[0], out[1], "the OSPF config depends on the route rows");
    out.remove(0)
}

fn area(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(n)
}

fn unhandled(p: &Process) -> Vec<(&str, u32)> {
    p.unhandled
        .iter()
        .map(|(k, s)| (k.as_str(), s.first_line))
        .collect()
}

const INTERFACES: &str = "\
interface Loopback0
 ipv4 address 192.0.2.1 255.255.255.255
 ipv6 address 2001:db8::1/128
!
interface GigabitEthernet0/0/0/0
 ipv4 address 198.51.100.1 255.255.255.0
 ipv6 address fe80::1 link-local
 ipv6 address 2001:db8:1::1/64
 bandwidth 1000000
!
interface GigabitEthernet0/0/0/1
 ipv4 address 203.0.113.1 255.255.255.252
 shutdown
!
interface tunnel-ip1
 ipv4 address 203.0.113.5 255.255.255.252
!
interface Bundle-Ether10
 ipv4 address 198.51.100.129 255.255.255.128
 ipv6 address 2001:db8:2::1/64
!
";

#[test]
fn the_process_level_lines() {
    let text = format!(
        "{INTERFACES}router ospf CORE
 router-id 192.0.2.1
 auto-cost reference-bandwidth 100000
 log adjacency changes
 area 0
  interface Loopback0
  !
 !
!
"
    );
    let c = ospf(&text);
    assert_eq!(c.processes.len(), 1);
    let p = &c.processes[0];
    assert_eq!(p.vrf, "default");
    assert_eq!(p.process, "CORE");
    assert_eq!(p.router_id, Some(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(p.reference_bandwidth_mbps, Some(100_000));
    assert_eq!(p.span.first_line, 22);
    assert!(p.unhandled.is_empty(), "{:?}", p.unhandled);
}

#[test]
fn a_router_id_of_an_interface_takes_its_primary_address() {
    let text = format!("{INTERFACES}router ospf 1\n router-id Loopback0\n area 0\n");
    let p = &ospf(&text).processes[0];
    assert_eq!(p.router_id, Some(Ipv4Addr::new(192, 0, 2, 1)));
}

#[test]
fn an_interface_takes_the_address_the_bandwidth_and_the_admin_state_of_its_config() {
    let text = format!(
        "{INTERFACES}router ospf 1
 area 0
  interface Loopback0
  !
  interface GigabitEthernet0/0/0/0
  !
  interface GigabitEthernet0/0/0/1
  !
  interface tunnel-ip1
  !
  interface Bundle-Ether10
  !
 !
!
"
    );
    let p = &ospf(&text).processes[0];
    let got: Vec<_> = p
        .interfaces
        .iter()
        .map(|i| {
            (
                i.name.as_str(),
                i.area,
                i.address,
                i.bandwidth_kbps,
                i.network,
                i.passive,
                i.priority,
                i.up,
                i.cost,
            )
        })
        .collect();
    let v4 = |a, b, c, d, l| Some((IpAddr::V4(Ipv4Addr::new(a, b, c, d)), l));
    use NetworkType::{Broadcast, Loopback, PointToPoint};
    assert_eq!(
        got,
        [
            (
                "Loopback0",
                area(0),
                v4(192, 0, 2, 1, 32),
                None,
                Loopback,
                false,
                1,
                true,
                None
            ),
            (
                "GigabitEthernet0/0/0/0",
                area(0),
                v4(198, 51, 100, 1, 24),
                Some(1_000_000),
                Broadcast,
                false,
                1,
                true,
                None
            ),
            (
                "GigabitEthernet0/0/0/1",
                area(0),
                v4(203, 0, 113, 1, 30),
                None,
                Broadcast,
                false,
                1,
                false,
                None
            ),
            (
                "tunnel-ip1",
                area(0),
                v4(203, 0, 113, 5, 30),
                None,
                PointToPoint,
                false,
                1,
                true,
                None
            ),
            (
                "Bundle-Ether10",
                area(0),
                v4(198, 51, 100, 129, 25),
                None,
                Broadcast,
                false,
                1,
                true,
                None
            ),
        ]
    );
    assert!(p.unhandled.is_empty(), "{:?}", p.unhandled);
}

#[test]
fn the_interface_takes_a_setting_from_its_area_else_from_the_process() {
    let text = format!(
        "{INTERFACES}router ospf 1
 passive enable
 cost 50
 network point-to-point
 priority 10
 area 0
  passive disable
  cost 20
  interface GigabitEthernet0/0/0/0
   cost 5
   network broadcast
   priority 0
  !
  interface Bundle-Ether10
  !
 !
 area 1
  interface tunnel-ip1
  !
 !
!
"
    );
    let p = &ospf(&text).processes[0];
    assert!(p.passive_default);
    let got: Vec<_> = p
        .interfaces
        .iter()
        .map(|i| (i.name.as_str(), i.cost, i.network, i.passive, i.priority))
        .collect();
    use NetworkType::{Broadcast, PointToPoint};
    assert_eq!(
        got,
        [
            ("GigabitEthernet0/0/0/0", Some(5), Broadcast, false, 0),
            ("Bundle-Ether10", Some(20), PointToPoint, false, 10),
            ("tunnel-ip1", Some(50), PointToPoint, true, 10),
        ]
    );
}

#[test]
fn a_bare_passive_line_makes_the_interface_passive_and_ospf_shutdown_makes_it_down() {
    let text = format!(
        "{INTERFACES}router ospf 1
 area 0
  interface GigabitEthernet0/0/0/0
   passive
   shutdown
  !
 !
!
"
    );
    let i = &ospf(&text).processes[0].interfaces[0];
    assert!(i.passive);
    assert!(!i.up);
}

#[test]
fn the_area_types() {
    let text = "router ospf 1
 area 0
 !
 area 1
  stub
 !
 area 2
  stub no-summary
  default-cost 15
 !
 area 0.0.0.3
  nssa
 !
 area 4
  nssa no-summary
 !
!
";
    let p = &ospf(text).processes[0];
    let got: Vec<_> = p
        .areas
        .iter()
        .map(|(id, a)| (*id, a.kind, a.no_summary, a.default_cost))
        .collect();
    assert_eq!(
        got,
        [
            (area(0), AreaType::Normal, false, None),
            (area(1), AreaType::Stub, false, None),
            (area(2), AreaType::Stub, true, Some(15)),
            (area(3), AreaType::Nssa, false, None),
            (area(4), AreaType::Nssa, true, None),
        ]
    );
    assert!(p.unhandled.is_empty(), "{:?}", p.unhandled);
}

#[test]
fn the_redistribute_lines_and_the_default_route() {
    let text = "router ospf 1
 redistribute connected
 redistribute static metric 30 metric-type 1
 redistribute bgp 64496 route-policy BGP-TO-OSPF
 redistribute ospf 2 metric 40
 default-information originate always metric 10 metric-type 2 route-policy DEF
 area 0
 !
!
";
    let p = &ospf(text).processes[0];
    let got: Vec<_> = p
        .redistribute
        .iter()
        .map(|r| {
            (
                r.source.clone(),
                r.metric,
                r.metric_type,
                r.route_map.as_deref(),
                r.span.first_line,
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (Source::Connected, None, None, None, 2),
            (Source::Static, Some(30), Some(1), None, 3),
            (Source::Bgp, None, None, Some("BGP-TO-OSPF"), 4),
            (Source::Other("ospf 2".into()), Some(40), None, None, 5),
        ]
    );
    let d = p.default_originate.as_ref().unwrap();
    assert!(d.always);
    assert_eq!(d.metric, Some(10));
    assert_eq!(d.metric_type, Some(2));
    assert_eq!(d.route_map.as_deref(), Some("DEF"));
    assert!(p.unhandled.is_empty(), "{:?}", p.unhandled);
}

#[test]
fn a_default_route_line_with_no_option() {
    let p = &ospf("router ospf 1\n default-information originate\n").processes[0];
    let d = p.default_originate.as_ref().unwrap();
    assert!(!d.always);
    assert_eq!(d.metric, None);
}

#[test]
fn a_line_that_is_not_read_goes_to_the_unhandled_lines() {
    let text = format!(
        "{INTERFACES}router ospf 1
 max-metric router-lsa
 redistribute isis CORE level-2
 network non-broadcast
 area 0
  range 198.51.100.0/24
  nssa default-information-originate
  interface GigabitEthernet0/0/0/0
   mpls ldp sync
   authentication message-digest
  !
 !
!
"
    );
    let doc = iosxr::read_text(text.as_bytes());
    let p = &ospf(&text).processes[0];
    assert_eq!(
        unhandled(p),
        [
            ("max-metric router-lsa", 23),
            ("redistribute isis CORE level-2", 24),
            ("network non-broadcast", 25),
            ("range 198.51.100.0/24", 27),
            ("nssa default-information-originate", 28),
            ("mpls ldp sync", 30),
        ]
    );
    assert_eq!(p.unhandled[0].1.file.as_ref(), FILE);
    let cov = classify(&doc, &table(false, &doc));
    let paths: Vec<&str> = cov.ranked().into_iter().map(|r| r.0).collect();
    for want in [
        "router ospf */max-metric router-lsa",
        "router ospf */network non-broadcast",
        "router ospf */area */range 198.51.100.0/24",
        "router ospf */area */interface */mpls ldp sync",
    ] {
        assert!(paths.contains(&want), "{want} is not in {paths:?}");
    }
}

#[test]
fn the_states_of_the_ospf_lines() {
    use State::{Handled, Irrelevant, Unhandled};
    let doc = iosxr::read_text(b"");
    let with = table(true, &doc);
    let without = table(false, &doc);
    for (path, rib, no_rib) in [
        (&["router ospf 1"][..], Handled, Handled),
        (&["router ospf 1", "router-id 192.0.2.1"], Handled, Handled),
        (&["router ospf 1", "area 0"], Handled, Handled),
        (&["router ospf 1", "area 0", "stub"], Handled, Handled),
        (
            &["router ospf 1", "area 0", "interface Bundle-Ether10"],
            Handled,
            Handled,
        ),
        (
            &[
                "router ospf 1",
                "area 0",
                "interface Bundle-Ether10",
                "cost 10",
            ],
            Handled,
            Handled,
        ),
        (
            &[
                "router ospf 1",
                "area 0",
                "interface Bundle-Ether10",
                "hello-interval 1",
            ],
            Irrelevant,
            Irrelevant,
        ),
        (
            &["router ospf 1", "max-metric router-lsa"],
            Irrelevant,
            Unhandled,
        ),
        (&["router ospf 1", "vrf RED"], Handled, Handled),
        (&["router ospf 1", "vrf RED", "area 0"], Handled, Handled),
        (
            &["router ospf 1", "vrf RED", "max-metric"],
            Irrelevant,
            Unhandled,
        ),
        (&["router ospfv3 1"], Handled, Handled),
        (&["router ospfv3 1", "area 0", "nssa"], Handled, Handled),
        (&["router ospfv3 1", "max-metric"], Unhandled, Unhandled),
        (&["interface Gi0/0/0/0", "bandwidth 1000"], Handled, Handled),
    ] {
        assert_eq!(with.state(path), rib, "{path:?} with route rows");
        assert_eq!(without.state(path), no_rib, "{path:?} without route rows");
    }
}

#[test]
fn a_vrf_stanza_is_a_process_of_its_vrf() {
    let text = format!(
        "{INTERFACES}router ospf 1
 router-id 192.0.2.1
 area 0
  interface Loopback0
  !
 !
 vrf RED
  router-id 192.0.2.9
  area 1
   stub
   interface Bundle-Ether10
    cost 7
   !
  !
  redistribute connected
 !
!
"
    );
    let c = ospf(&text);
    let got: Vec<_> = c
        .processes
        .iter()
        .map(|p| {
            (
                p.vrf.as_str(),
                p.process.as_str(),
                p.router_id,
                p.areas.keys().copied().collect::<Vec<_>>(),
                p.interfaces
                    .iter()
                    .map(|i| (i.name.as_str(), i.cost))
                    .collect::<Vec<_>>(),
                p.redistribute.len(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (
                "default",
                "1",
                Some(Ipv4Addr::new(192, 0, 2, 1)),
                vec![area(0)],
                vec![("Loopback0", None)],
                0
            ),
            (
                "RED",
                "1",
                Some(Ipv4Addr::new(192, 0, 2, 9)),
                vec![area(1)],
                vec![("Bundle-Ether10", Some(7))],
                1
            ),
        ]
    );
    assert_eq!(c.processes[1].areas[&area(1)].kind, AreaType::Stub);
    assert!(c.processes[1].unhandled.is_empty());
}

#[test]
fn a_vrf_process_gets_only_the_setting_lines_of_the_default_vrf() {
    let text = "router ospf 1
 cost 30
 cost 0
 network non-broadcast
 max-metric router-lsa
 area 0
  range 198.51.100.0/24
  interface Loopback0
   mpls ldp sync
  !
 !
 vrf RED
  area 0
  !
 !
!
";
    let c = ospf(text);
    assert_eq!(
        unhandled(&c.processes[0]),
        [
            ("cost 0", 3),
            ("network non-broadcast", 4),
            ("max-metric router-lsa", 5),
            ("range 198.51.100.0/24", 7),
            ("interface Loopback0", 8),
            ("mpls ldp sync", 9),
        ]
    );
    assert_eq!(c.processes[1].vrf, "RED");
    assert_eq!(
        unhandled(&c.processes[1]),
        [("cost 30", 2), ("cost 0", 3), ("network non-broadcast", 4)]
    );
}

#[test]
fn an_unreadable_form_of_a_handled_line_is_not_handled_in_the_coverage() {
    use State::{Handled, Irrelevant, Unhandled};
    let text = "router ospf 1
 cost 0
 redistribute connected tag 5
 area 0
  default-cost x
 !
!
";
    let p = &ospf(text).processes[0];
    assert_eq!(
        unhandled(p),
        [
            ("cost 0", 2),
            ("redistribute connected tag 5", 3),
            ("default-cost x", 5)
        ]
    );
    let doc = iosxr::read_text(text.as_bytes());
    let cov = classify(&doc, &table(false, &doc));
    let paths: Vec<&str> = cov.ranked().into_iter().map(|r| r.0).collect();
    for want in [
        "router ospf */cost 0",
        "router ospf */redistribute connected tag 5",
        "router ospf */area */default-cost x",
    ] {
        assert!(paths.contains(&want), "{want} is not in {paths:?}");
    }
    let empty = iosxr::read_text(b"");
    let with = table(true, &empty);
    let without = table(false, &empty);
    for (path, rib, no_rib) in [
        (&["router ospf 1", "cost 0"][..], Irrelevant, Unhandled),
        (&["router ospf 1", "cost 1"], Handled, Handled),
        (&["router ospf 1", "priority 300"], Irrelevant, Unhandled),
        (&["router ospf 1", "router-id 0x1"], Irrelevant, Unhandled),
        (
            &["router ospf 1", "auto-cost reference-bandwidth 0"],
            Irrelevant,
            Unhandled,
        ),
        (
            &["router ospf 1", "redistribute bgp ASX"],
            Irrelevant,
            Unhandled,
        ),
        (
            &["router ospf 1", "redistribute bgp 64496 route-policy P"],
            Handled,
            Handled,
        ),
        (
            &["router ospf 1", "default-information originate metric x"],
            Irrelevant,
            Unhandled,
        ),
        (
            &["router ospf 1", "default-information originate always"],
            Handled,
            Handled,
        ),
        (
            &["router ospf 1", "area 0", "default-cost x"],
            Irrelevant,
            Unhandled,
        ),
        (
            &["router ospfv3 1", "area 0", "interface Loopback0", "cost 0"],
            Unhandled,
            Unhandled,
        ),
    ] {
        assert_eq!(with.state(path), rib, "{path:?} with route rows");
        assert_eq!(without.state(path), no_rib, "{path:?} without route rows");
    }
}

#[test]
fn an_ospf_interface_with_no_interface_stanza_is_unhandled() {
    let text = "router ospf 1\n area 0\n  interface GigabitEthernet0/0/0/7\n  !\n !\n!\n";
    let p = &ospf(text).processes[0];
    assert_eq!(p.interfaces[0].address, None);
    assert_eq!(unhandled(p), [("interface GigabitEthernet0/0/0/7", 3)]);
}

#[test]
fn a_default_vrf_with_only_vrf_stanzas_gives_no_default_process() {
    let text = "router ospf 1
 passive enable
 vrf RED
  area 0
  !
 !
!
";
    let c = ospf(text);
    let vrfs: Vec<&str> = c.processes.iter().map(|p| p.vrf.as_str()).collect();
    assert_eq!(vrfs, ["RED"]);
    assert_eq!(unhandled(&c.processes[0]), [("passive enable", 2)]);
}

#[test]
fn a_default_vrf_with_only_an_unreadable_area_keeps_its_process() {
    let text = "router ospf 1
 area x
 !
 vrf RED
  area 0
  !
 !
!
";
    let c = ospf(text);
    let vrfs: Vec<&str> = c.processes.iter().map(|p| p.vrf.as_str()).collect();
    assert_eq!(vrfs, ["default", "RED"]);
    assert_eq!(unhandled(&c.processes[0]), [("area x", 2)]);
}

#[test]
fn a_secondary_address_is_a_stub_network_of_the_interface() {
    let text = "interface GigabitEthernet0/0/0/0
 ipv4 address 198.51.100.1 255.255.255.0
 ipv4 address 203.0.113.1 255.255.255.0 secondary
!
router ospf 1
 area 0
  interface GigabitEthernet0/0/0/0
  !
 !
!
";
    let p = &ospf(text).processes[0];
    assert!(unhandled(p).is_empty());
    assert_eq!(
        p.interfaces[0].secondaries,
        [("203.0.113.1".parse().unwrap(), 24)]
    );
}

#[test]
fn ospfv3_reads_the_same_structure_with_the_ipv6_addresses() {
    let text = format!(
        "{INTERFACES}router ospfv3 CORE6
 router-id 192.0.2.1
 auto-cost reference-bandwidth 40000
 passive enable
 redistribute static metric 20
 default-information originate
 area 0
  interface Loopback0
  !
  interface GigabitEthernet0/0/0/0
   passive disable
   network point-to-point
  !
 !
 area 1
  nssa no-summary
  interface Bundle-Ether10
   cost 3
  !
 !
!
"
    );
    let c = ospf(&text);
    assert_eq!(c.processes.len(), 1);
    let p = &c.processes[0];
    assert_eq!(p.version, rsim_routing::ospf::Version::V3);
    assert_eq!(p.process, "CORE6");
    assert_eq!(p.reference_bandwidth_mbps, Some(40_000));
    assert_eq!(p.areas[&area(1)].kind, AreaType::Nssa);
    assert!(p.areas[&area(1)].no_summary);
    assert_eq!(p.redistribute[0].source, Source::Static);
    assert_eq!(p.redistribute[0].metric, Some(20));
    assert!(p.default_originate.is_some());
    let got: Vec<_> = p
        .interfaces
        .iter()
        .map(|i| (i.name.as_str(), i.address, i.network, i.passive, i.cost))
        .collect();
    let v6 = |t: &str, l| Some((IpAddr::V6(t.parse().unwrap()), l));
    assert_eq!(
        got,
        [
            (
                "Loopback0",
                v6("2001:db8::1", 128),
                NetworkType::Loopback,
                true,
                None
            ),
            (
                "GigabitEthernet0/0/0/0",
                v6("2001:db8:1::1", 64),
                NetworkType::PointToPoint,
                false,
                None
            ),
            (
                "Bundle-Ether10",
                v6("2001:db8:2::1", 64),
                NetworkType::Broadcast,
                true,
                Some(3)
            ),
        ]
    );
    assert!(p.unhandled.is_empty(), "{:?}", p.unhandled);
}

#[test]
fn an_ospfv3_line_that_is_not_read_is_unhandled_in_the_coverage() {
    let text = "router ospfv3 1
 area 0
  interface GigabitEthernet0/0/0/0
   instance 3
  !
 !
!
";
    let doc = iosxr::read_text(text.as_bytes());
    let p = &ospf(text).processes[0];
    assert_eq!(
        unhandled(p),
        [("interface GigabitEthernet0/0/0/0", 3), ("instance 3", 4)]
    );
    let cov = classify(&doc, &table(true, &doc));
    let paths: Vec<&str> = cov.ranked().into_iter().map(|r| r.0).collect();
    assert_eq!(paths, ["router ospfv3 */area */interface */instance 3"]);
}

#[test]
fn an_interface_of_a_type_with_no_known_network_type_is_unhandled() {
    let text = "router ospf 1\n area 0\n  interface FooBar0/1\n  !\n !\n!\n";
    let p = &ospf(text).processes[0];
    assert_eq!(unhandled(p), [("interface FooBar0/1", 3)]);
}

#[test]
fn a_vrf_process_gets_each_unread_interface_line_of_the_default_vrf() {
    let text = "router ospf 1
 mpls ldp sync
 prefix-suppression
 loopback stub-network enable
 demand-circuit
 database-filter all out
 distribute-list prefix-list IN-FILTER in
 max-metric router-lsa
 summary-prefix 198.51.100.0/24
 distance 120
 maximum paths 8
 default-metric 20
 redistribute isis CORE level-2
 router-id 0x1
 hello-interval 5
 vrf RED
  area 0
  !
 !
!
";
    let c = ospf(text);
    assert_eq!(c.processes[1].vrf, "RED");
    assert_eq!(
        unhandled(&c.processes[1]),
        [
            ("mpls ldp sync", 2),
            ("prefix-suppression", 3),
            ("loopback stub-network enable", 4),
            ("demand-circuit", 5),
            ("database-filter all out", 6),
            ("distribute-list prefix-list IN-FILTER in", 7),
        ]
    );
}

#[test]
fn an_ospfv2_interface_with_no_primary_address_is_unhandled() {
    let text = "interface Loopback0
 ipv4 address 192.0.2.1 255.255.255.255
!
interface GigabitEthernet0/0/0/2
 ipv4 unnumbered Loopback0
!
router ospf 1
 area 0
  interface GigabitEthernet0/0/0/2
  !
 !
!
";
    let p = &ospf(text).processes[0];
    assert_eq!(p.interfaces[0].address, None);
    assert_eq!(unhandled(p), [("interface GigabitEthernet0/0/0/2", 9)]);
}
