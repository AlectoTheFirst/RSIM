//! The IOS-XR summary for the link join, the links of an IOS-XR router to
//! an NX-OS switch and to a second IOS-XR router in the estate, and HSRP,
//! on the synthetic running config and text sections of `pe1`, with the
//! switch `core1` and the router `pe2` written here.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{FieldValue, Header, Mac, PROTO_ICMP, PROTO_TCP, VerdictKind};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::collected::{Collected, LinkRow, NeighbourRow, row_span};
use rsim_ingest::estate::{Estate, Input, assemble};
use rsim_ingest::iosxr;
use rsim_ingest::route_tables::RouteTables;

type Sections = BTreeMap<String, (Vec<u8>, String)>;

const CONFIG: &[u8] = include_bytes!("fixtures/iosxr/running-config.txt");

fn sections() -> Sections {
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

fn pe1(sections: Sections) -> Input {
    Input::Iosxr {
        name: "pe1".into(),
        config: CONFIG.to_vec(),
        file: "pe1/config".into(),
        collected: Collected::default(),
        sections,
    }
}

const CORE1: &str = "hostname core1
interface port-channel10
  no switchport
  ip address 198.51.100.2/30
  no shutdown
interface Ethernet1/1
  no switchport
  channel-group 10 mode active
  no shutdown
interface Ethernet1/2
  no switchport
  channel-group 10 mode active
  no shutdown
interface Ethernet1/3
  no switchport
  ip address 198.51.100.129/26
  no shutdown
ip route 203.0.113.0/24 198.51.100.1
";

const CORE1_LLDP: &str = r#"{"TABLE_nbor_detail":{"ROW_nbor_detail":[
    {"l_port_id":"Eth1/1","sys_name":"pe1.example.net","chassis_id":"0000.5e00.5300","port_id":"GigabitEthernet0/0/0/0"},
    {"l_port_id":"Eth1/2","sys_name":"pe1.example.net","chassis_id":"0000.5e00.5300","port_id":"GigabitEthernet0/0/0/1"}]}}"#;

/// The NX-OS switch on the other end of `Bundle-Ether10` of pe1.
fn core1() -> Input {
    let link = |i: &str, mac: &str, n: u64| LinkRow {
        interface: i.into(),
        mac: Some(mac.into()),
        parent: None,
        vlan: None,
        span: row_span("core1", "links", "b1", n),
    };
    let arp = |i: &str, ip: &str, mac: &str, n: u64| NeighbourRow {
        interface: i.into(),
        ip: ip.into(),
        mac: Some(mac.into()),
        state: Some("REACHABLE".into()),
        span: row_span("core1", "neighbours", "b2", n),
    };
    Input::Nxos {
        name: "core1".into(),
        config: CORE1.as_bytes().to_vec(),
        file: "core1/config".into(),
        collected: Collected {
            links: vec![
                link("port-channel10", "00:00:5e:00:53:02", 0),
                link("Ethernet1/3", "00:00:5e:00:53:50", 1),
            ],
            neighbours: vec![
                arp("port-channel10", "198.51.100.1", "00:00:5e:00:53:01", 0),
                arp("Ethernet1/3", "198.51.100.130", "00:00:5e:00:53:60", 1),
            ],
            ..Collected::default()
        },
        sections: BTreeMap::from([(
            "lldp".to_string(),
            (CORE1_LLDP.as_bytes().to_vec(), "core1/lldp".to_string()),
        )]),
    }
}

const PE2_CONFIG: &str = "Tue Nov 17 10:00:00.000 UTC
hostname pe2
vrf RED
!
interface Bundle-Ether20
!
interface Bundle-Ether20.100
 vrf RED
 ipv4 address 192.0.2.2 255.255.255.192
 encapsulation dot1q 100
!
interface GigabitEthernet0/0/0/2
 bundle id 20 mode on
!
interface GigabitEthernet0/0/0/5
 vrf RED
 ipv4 address 198.51.100.249 255.255.255.252
!
router hsrp
 interface Bundle-Ether20.100
  address-family ipv4
   hsrp 1
    address 192.0.2.3
    mac-address 0000.5e00.53a1
   !
   hsrp 2
    address 192.0.2.4
    mac-address 0000.5e00.53a2
   !
  !
 !
!
end
";

const PE2_INTERFACES: &str = "Tue Nov 17 10:00:01.000 UTC
Bundle-Ether20 is up, line protocol is up
  Interface state transitions: 1
  Hardware is Aggregated Ethernet interface(s), address is 0000.5e00.5370
  Internet address is Unknown
  MTU 1514 bytes, BW 1000000 Kbit (Max: 1000000 Kbit)
  Encapsulation ARPA,
  Full-duplex, 1000Mb/s

Bundle-Ether20.100 is up, line protocol is up
  Interface state transitions: 1
  Hardware is VLAN sub-interface(s), address is 0000.5e00.5370
  Internet address is 192.0.2.2/26
  MTU 1518 bytes, BW 1000000 Kbit (Max: 1000000 Kbit)
  Encapsulation 802.1Q Virtual LAN, VLAN Id 100,  loopback not set,

GigabitEthernet0/0/0/2 is up, line protocol is up
  Interface state transitions: 1
  Hardware is GigabitEthernet, address is 0000.5e00.5372 (bia 0000.5e00.5372)
  Internet address is Unknown
  MTU 1514 bytes, BW 1000000 Kbit (Max: 1000000 Kbit)
  Encapsulation ARPA,

GigabitEthernet0/0/0/5 is up, line protocol is up
  Interface state transitions: 1
  Hardware is GigabitEthernet, address is 0000.5e00.5375 (bia 0000.5e00.5375)
  Internet address is 198.51.100.249/30
  MTU 1514 bytes, BW 1000000 Kbit (Max: 1000000 Kbit)
  Encapsulation ARPA,
";

const PE2_RIB: &str = "Tue Nov 17 10:00:02.000 UTC

VRF: RED

Codes: C - connected, S - static, R - RIP, B - BGP, (>) - Diversion path
       L - local, (!) - FRR Backup path

Gateway of last resort is not set

C    192.0.2.0/26 is directly connected, 3d04h, Bundle-Ether20.100
L    192.0.2.2/32 is directly connected, 3d04h, Bundle-Ether20.100
C    198.51.100.248/30 is directly connected, 3d04h, GigabitEthernet0/0/0/5
L    198.51.100.249/32 is directly connected, 3d04h, GigabitEthernet0/0/0/5
";

/// The ARP rows of pe2, with the virtual MACs of the groups 1 and 3.
const PE2_ARP: &str = "Tue Nov 17 10:00:03.000 UTC

-------------------------------------------------------------------------------
0/0/CPU0
-------------------------------------------------------------------------------
Address         Age        Hardware Addr   State      Type  Interface
192.0.2.2       -          0000.5e00.5370  Interface  ARPA  BE20.100
192.0.2.1       00:00:41   0000.5e00.5320  Dynamic    ARPA  BE20.100
192.0.2.3       00:00:41   0000.5e00.53a1  Dynamic    ARPA  BE20.100
192.0.2.5       00:00:41   0000.5e00.53a3  Dynamic    ARPA  BE20.100
198.51.100.249  -          0000.5e00.5375  Interface  ARPA  Gi0/0/0/5
198.51.100.250  00:00:41   0000.5e00.5376  Dynamic    ARPA  Gi0/0/0/5
";

const PE2_LLDP: &str = "Tue Nov 17 10:00:06.000 UTC
Capability codes:
        (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device
        (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other

------------------------------------------------
Local Interface: GigabitEthernet0/0/0/2
Chassis id: 0000.5e00.5300
Port id: GigabitEthernet0/0/0/2
Port Description: red-customer
System Name: pe1

System Description:
Example XR Software, Version 7.11.2

Time remaining: 101 seconds
Hold Time: 120 seconds
System Capabilities: R
Enabled Capabilities: R
Management Addresses:
  IPv4 address: 192.0.2.250
Peer MAC Address: 00:00:5e:00:53:42

Total entries displayed: 1

";

const PE2_HSRP: &str = "Tue Nov 17 10:00:05.000 UTC

IPv4 Groups:
                     P indicates configured to preempt.
                     |
Interface   Grp  Pri P State   Active addr     Standby addr    Group addr
BE20.100      1  100   Standby 192.0.2.1       local           192.0.2.3
BE20.100      2  110 P Active  local           192.0.2.1       192.0.2.4
";

/// The second router, on the other end of `Bundle-Ether20` of pe1.
fn pe2() -> Input {
    let sections = [
        ("interfaces", PE2_INTERFACES),
        ("rib", PE2_RIB),
        ("arp", PE2_ARP),
        ("lldp", PE2_LLDP),
        ("hsrp", PE2_HSRP),
    ]
    .into_iter()
    .map(|(n, t)| (n.to_string(), (t.as_bytes().to_vec(), format!("pe2/{n}"))))
    .collect();
    Input::Iosxr {
        name: "pe2".into(),
        config: PE2_CONFIG.as_bytes().to_vec(),
        file: "pe2/config".into(),
        collected: Collected::default(),
        sections,
    }
}

/// The estate of pe1 with its sections changed by `change`, core1 and pe2.
fn estate_with(change: impl Fn(&mut Sections)) -> Estate {
    let mut s = sections();
    change(&mut s);
    assemble(vec![core1(), pe1(s), pe2()])
}

fn estate() -> Estate {
    estate_with(|_| {})
}

fn twin_of(e: Estate) -> Twin {
    e.builder.build().expect("the twin builds")
}

fn twin() -> Twin {
    twin_of(estate())
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn query(t: &Twin, device: &str, ingress: &str, src: &str, dst: &str, reply: bool) -> Answer {
    let h = Header::request(ip(src), ip(dst), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(22);
    run(t, &h, device, ingress, reply)
}

fn run(t: &Twin, h: &Header, device: &str, ingress: &str, reply: bool) -> Answer {
    let q = Query::path(t, h).with_ingress(device, ingress);
    let q = if reply { q } else { q.without_reply() };
    Executor::new(t).run(&q).expect("the query runs")
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

fn has(steps: &[String], function: &str) -> bool {
    steps.iter().any(|s| s.split(' ').next() == Some(function))
}

fn mac(s: &str) -> Mac {
    s.parse().unwrap()
}

#[test]
fn the_summary_of_the_router() {
    let doc = iosxr::read_text(CONFIG);
    let cfg = iosxr::read(
        &doc,
        &iosxr::table(&RouteTables::uniform(true, iosxr::dynamic_vrfs(&doc))),
    );
    let (_, sum) = iosxr::lower(
        "pe1",
        "pe1/config",
        &iosxr::profile(),
        &cfg,
        &sections(),
        &Default::default(),
    );
    assert_eq!(sum.host_name.as_deref(), Some("pe1"));
    let ports: Vec<&str> = sum.entries.keys().map(String::as_str).collect();
    assert_eq!(
        ports,
        [
            "Bundle-Ether10",
            "Bundle-Ether20",
            "GigabitEthernet0/0/0/3",
            "MgmtEth0/RP0/CPU0/0"
        ]
    );
    assert_eq!(
        sum.entries["Bundle-Ether20"].as_str(),
        "pe1/handoff/Bundle-Ether20"
    );
    assert_eq!(sum.port_macs["Bundle-Ether10"], mac("00:00:5e:00:53:01"));
    assert_eq!(sum.port_macs["Bundle-Ether20"], mac("00:00:5e:00:53:20"));
    assert_eq!(&*sum.port_spans["Bundle-Ether10"].file, "pe1/interfaces");
    assert_eq!(sum.facts["GigabitEthernet0/0/0/3"].speed_mbps, Some(1000));
    assert_eq!(sum.facts["GigabitEthernet0/0/0/3"].full_duplex, Some(true));
    assert_eq!(sum.facts["Bundle-Ether10"].speed_mbps, Some(20_000));
    // The bundle members, and the short names of the sections.
    assert_eq!(sum.port("Gi0/0/0/1"), "Bundle-Ether10");
    assert_eq!(sum.port("GigabitEthernet0/0/0/2"), "Bundle-Ether20");
    assert_eq!(sum.port("Gi0/0/0/3"), "GigabitEthernet0/0/0/3");
    // The layer 3 addresses by the dot1q VLAN of the sub-interfaces, with
    // the IPv6 addresses.
    let l3 = |p: &str, v: Option<u16>| -> Vec<String> {
        sum.l3[p][&v]
            .iter()
            .map(|(a, l)| format!("{a}/{l}"))
            .collect()
    };
    assert_eq!(sum.l3["Bundle-Ether20"].len(), 2);
    assert_eq!(
        l3("Bundle-Ether20", Some(100)),
        ["192.0.2.1/26", "192.0.2.65/26"]
    );
    assert_eq!(l3("Bundle-Ether20", Some(200)), ["192.0.2.129/26"]);
    assert_eq!(
        l3("Bundle-Ether10", None),
        ["198.51.100.1/30", "2001:db8:10::1/64"]
    );
    // The LLDP and CDP rows.
    assert!(sum.neighbour_section);
    let rows: Vec<(String, Option<&str>, Option<&str>)> = sum
        .neighbours
        .iter()
        .map(|n| {
            (
                sum.port(&n.port),
                n.name.as_deref(),
                n.remote_port.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            ("Bundle-Ether10".into(), Some("core1"), Some("Ethernet1/2")),
            (
                "Bundle-Ether20".into(),
                Some("pe2"),
                Some("GigabitEthernet0/0/0/2")
            ),
            ("Bundle-Ether10".into(), Some("core1"), Some("Ethernet1/1")),
            ("Bundle-Ether10".into(), Some("core1"), Some("Ethernet1/2")),
        ]
    );
    assert_eq!(sum.neighbours[0].chassis, Some(mac("00:00:5e:00:53:51")));
    assert_eq!(&*sum.neighbours[0].span.file, "pe1/lldp");
    assert_eq!(&*sum.neighbours[2].span.file, "pe1/cdp");
    // The next hops of each VRF, the backup path too.
    for hop in ["203.0.113.254", "198.51.100.2", "203.0.113.9", "192.0.2.10"] {
        assert!(sum.next_hops.contains(&ip(hop)), "{hop}");
    }
    // The ARP rows of the sub-interfaces with their VLAN.
    let arp: BTreeSet<(u16, String)> = sum
        .arp
        .iter()
        .map(|(v, a, _, _)| (*v, a.to_string()))
        .collect();
    assert!(arp.contains(&(100, "192.0.2.10".into())));
    assert!(arp.contains(&(200, "192.0.2.130".into())));
    assert!(!arp.iter().any(|(_, a)| a == "198.51.100.2"));
    assert!(sum.ports.is_empty() && sum.macs.is_empty());
}

#[test]
fn a_path_crosses_from_the_switch_to_the_router() {
    let t = twin();
    let a = query(
        &t,
        "core1",
        "Ethernet1/3",
        "198.51.100.130",
        "203.0.113.1",
        false,
    );
    let (verdict, steps) = only(&a);
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    for f in [
        "core1/out/port-channel10",
        "pe1/handoff/Bundle-Ether10",
        "pe1/in/Bundle-Ether10",
        "pe1/deliver",
    ] {
        assert!(has(&steps, f), "{f} not in {steps:#?}");
    }
}

#[test]
fn a_path_crosses_from_the_router_to_the_switch() {
    let t = twin();
    let mut h = Header::request(ip("203.0.113.10"), ip("198.51.100.129"), PROTO_ICMP);
    h.icmp_type = FieldValue::Known(8);
    h.icmp_code = FieldValue::Known(0);
    let a = run(&t, &h, "pe1", "GigabitEthernet0/0/0/3", false);
    let (verdict, steps) = only(&a);
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    for f in [
        "pe1/acl-in/GigabitEthernet0/0/0/3",
        "pe1/out/Bundle-Ether10",
        "core1/handoff/port-channel10",
        "core1/in/port-channel10",
        "core1/deliver",
    ] {
        assert!(has(&steps, f), "{f} not in {steps:#?}");
    }
    // The link step names the speed of both ends, and the frame leaves
    // with the MAC of the bundle and no tag.
    let b = &a.branches()[0];
    let out = b
        .steps
        .iter()
        .find(|s| s.function.as_str() == "pe1/out/Bundle-Ether10")
        .unwrap();
    assert!(
        out.reason.detail.contains("20000 Mbit/s full duplex"),
        "{}",
        out.reason.detail
    );
    let w = out.output.witness().unwrap();
    assert_eq!(
        w.current.src_mac,
        FieldValue::Known(mac("00:00:5e:00:53:01"))
    );
    assert_eq!(
        w.current.dst_mac,
        FieldValue::Known(mac("00:00:5e:00:53:02"))
    );
    assert_eq!(w.current.vlan, FieldValue::Absent);
}

#[test]
fn a_sub_interface_sends_its_dot1q_vlan_to_the_active_router_of_the_group() {
    let t = twin();
    // Group 1: pe1 is active, pe2 is standby.
    let a = query(
        &t,
        "pe2",
        "GigabitEthernet0/0/0/5",
        "198.51.100.250",
        "192.0.2.3",
        false,
    );
    let (verdict, steps) = only(&a);
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    for f in [
        "pe2/out/Bundle-Ether20.100",
        "pe1/handoff/Bundle-Ether20",
        "pe1/in/Bundle-Ether20.100",
        "pe1/deliver",
    ] {
        assert!(has(&steps, f), "{f} not in {steps:#?}");
    }
    let b = &a.branches()[0];
    let out = b
        .steps
        .iter()
        .find(|s| s.function.as_str() == "pe2/out/Bundle-Ether20.100")
        .unwrap();
    let w = out.output.witness().unwrap();
    assert_eq!(w.current.vlan, FieldValue::Known(100));
    assert_eq!(
        w.current.dst_mac,
        FieldValue::Known(mac("00:00:5e:00:53:a1"))
    );
    // Group 2: pe2 is active and delivers on its own.
    let (verdict, steps) = only(&query(
        &t,
        "pe2",
        "GigabitEthernet0/0/0/5",
        "198.51.100.250",
        "192.0.2.4",
        false,
    ));
    assert_eq!(verdict, VerdictKind::Deliver);
    assert!(has(&steps, "pe2/deliver"), "{steps:#?}");
    assert!(!has(&steps, "pe1/handoff/Bundle-Ether20"), "{steps:#?}");
}

#[test]
fn the_standby_router_sends_to_the_virtual_mac_of_the_active_router() {
    let t = twin_of(estate());
    let (verdict, steps) = only(&query(
        &t,
        "pe1",
        "Bundle-Ether20.100",
        "192.0.2.20",
        "192.0.2.4",
        false,
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    for f in [
        "pe1/qos-out/Bundle-Ether20.100",
        "pe1/out/Bundle-Ether20.100",
        "pe2/handoff/Bundle-Ether20",
        "pe2/in/Bundle-Ether20.100",
        "pe2/deliver",
    ] {
        assert!(has(&steps, f), "{f} not in {steps:#?}");
    }
    assert!(!has(&steps, "pe1/deliver"), "{steps:#?}");
}

#[test]
fn a_group_with_no_row_in_show_hsrp_gives_unknown_for_its_address_and_mac() {
    let e = estate();
    assert!(
        e.notes["pe1"].iter().any(|n| n
            == "Bundle-Ether20.100: HSRP group 3: 0 IPv4 rows of the group in show hsrp, virtual address and MAC unknown"),
        "{:#?}",
        e.notes["pe1"]
    );
    let t = twin_of(e);
    // The virtual MAC of the group at the hand-off.
    let (verdict, steps) = only(&query(
        &t,
        "pe2",
        "GigabitEthernet0/0/0/5",
        "198.51.100.250",
        "192.0.2.5",
        false,
    ));
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(has(&steps, "pe1/handoff/Bundle-Ether20"), "{steps:#?}");
    assert!(!has(&steps, "pe1/in/Bundle-Ether20.100"), "{steps:#?}");
    // The virtual address at the route lookup.
    let (verdict, steps) = only(&query(
        &t,
        "pe1",
        "Bundle-Ether20.100",
        "192.0.2.20",
        "192.0.2.5",
        false,
    ));
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(has(&steps, "pe1/route"), "{steps:#?}");
    // The other MACs of the port stay exact.
    let (verdict, _) = only(&query(
        &t,
        "pe2",
        "GigabitEthernet0/0/0/5",
        "198.51.100.250",
        "192.0.2.3",
        false,
    ));
    assert_eq!(verdict, VerdictKind::Deliver);
}

#[test]
fn a_state_that_cannot_be_read_gives_unknown() {
    let bogus = |s: &mut Sections| {
        let (b, _) = s.get_mut("hsrp").unwrap();
        *b = String::from_utf8(b.clone())
            .unwrap()
            .replace("P Active  local", "P Resign  local")
            .into_bytes();
    };
    let without = |s: &mut Sections| {
        s.remove("hsrp");
    };
    for (change, why) in [
        (
            &bogus as &dyn Fn(&mut Sections),
            "state \"Resign\" not known",
        ),
        (&without, "no show hsrp section"),
    ] {
        let e = estate_with(change);
        let note =
            format!("Bundle-Ether20.100: HSRP group 1: {why}, virtual address and MAC unknown");
        assert!(e.notes["pe1"].contains(&note), "{:#?}", e.notes["pe1"]);
        let t = twin_of(e);
        for (device, ingress, src) in [
            ("pe2", "GigabitEthernet0/0/0/5", "198.51.100.250"),
            ("pe1", "Bundle-Ether20.100", "192.0.2.20"),
        ] {
            let (verdict, steps) = only(&query(&t, device, ingress, src, "192.0.2.3", false));
            assert_eq!(verdict, VerdictKind::Unknown, "{why}: {steps:#?}");
            assert!(!has(&steps, "pe1/deliver"), "{steps:#?}");
        }
    }
}

#[test]
fn an_active_group_with_no_virtual_mac_makes_the_port_unknown() {
    let config = String::from_utf8_lossy(CONFIG).replace("    mac-address 0000.5e00.53a1\n", "");
    let e = assemble(vec![
        core1(),
        Input::Iosxr {
            name: "pe1".into(),
            config: config.into_bytes(),
            file: "pe1/config".into(),
            collected: Collected::default(),
            sections: sections(),
        },
        pe2(),
    ]);
    assert!(
        e.notes["pe1"]
            .iter()
            .any(|n| n
                == "Bundle-Ether20.100: HSRP group 1: no mac-address line, virtual MAC not known"),
        "{:#?}",
        e.notes["pe1"]
    );
    let t = twin_of(e);
    // Each frame of the port is unknown.
    let (verdict, steps) = only(&query(
        &t,
        "pe2",
        "GigabitEthernet0/0/0/5",
        "198.51.100.250",
        "192.0.2.1",
        false,
    ));
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(has(&steps, "pe1/handoff/Bundle-Ether20"), "{steps:#?}");
    // The virtual address of the active group stays a local route.
    let (verdict, steps) = only(&query(
        &t,
        "pe1",
        "Bundle-Ether20.100",
        "192.0.2.20",
        "192.0.2.3",
        false,
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
}

/// pe2 with the sub-interface `Bundle-Ether20.300` on VLAN 300 and ARP rows
/// for 192.0.2.193, a MAC of pe1, and 192.0.2.200, a MAC of no router.
fn pe2_with_vlan_300() -> Input {
    let config = PE2_CONFIG.replace(
        "interface GigabitEthernet0/0/0/2\n",
        "interface Bundle-Ether20.300\n vrf RED\n ipv4 address 192.0.2.194 255.255.255.192\n encapsulation dot1q 300\n!\ninterface GigabitEthernet0/0/0/2\n",
    );
    let interfaces = PE2_INTERFACES.replace(
        "GigabitEthernet0/0/0/2 is up",
        "Bundle-Ether20.300 is up, line protocol is up
  Interface state transitions: 1
  Hardware is VLAN sub-interface(s), address is 0000.5e00.5370
  Internet address is 192.0.2.194/26
  MTU 1518 bytes, BW 1000000 Kbit (Max: 1000000 Kbit)
  Encapsulation 802.1Q Virtual LAN, VLAN Id 300,  loopback not set,

GigabitEthernet0/0/0/2 is up",
    );
    let rib = format!(
        "{PE2_RIB}C    192.0.2.192/26 is directly connected, 3d04h, Bundle-Ether20.300\n\
         L    192.0.2.194/32 is directly connected, 3d04h, Bundle-Ether20.300\n"
    );
    let arp = format!(
        "{PE2_ARP}192.0.2.193     00:00:41   0000.5e00.5320  Dynamic    ARPA  BE20.300\n\
         192.0.2.200     00:00:41   0000.5e00.5390  Dynamic    ARPA  BE20.300\n"
    );
    let sections = [
        ("interfaces", interfaces.as_str()),
        ("rib", rib.as_str()),
        ("arp", arp.as_str()),
        ("lldp", PE2_LLDP),
        ("hsrp", PE2_HSRP),
    ]
    .into_iter()
    .map(|(n, t)| (n.to_string(), (t.as_bytes().to_vec(), format!("pe2/{n}"))))
    .collect();
    Input::Iosxr {
        name: "pe2".into(),
        config: config.into_bytes(),
        file: "pe2/config".into(),
        collected: Collected::default(),
        sections,
    }
}

/// pe1 with `stanza` added before `Loopback0`.
fn pe1_with(stanza: &str) -> Input {
    let config = String::from_utf8_lossy(CONFIG).replace(
        "interface Loopback0\n",
        &format!("{stanza}interface Loopback0\n"),
    );
    Input::Iosxr {
        name: "pe1".into(),
        config: config.into_bytes(),
        file: "pe1/config".into(),
        collected: Collected::default(),
        sections: sections(),
    }
}

#[test]
fn a_vlan_of_a_sub_interface_that_is_not_lowered_gives_unknown() {
    let l2 = "interface Bundle-Ether20.300 l2transport\n encapsulation dot1q 300\n!\n";
    let routed = "interface Bundle-Ether20.300\n vrf BLUE\n ipv4 address 192.0.2.193 255.255.255.192\n encapsulation dot1q 300 second-dot1q 5\n!\n";
    let unnumbered = "interface Bundle-Ether20.300\n vrf BLUE\n ipv4 unnumbered Loopback0\n encapsulation dot1q 300\n!\n";
    let ipv6 = "interface Bundle-Ether20.300\n vrf BLUE\n ipv6 address 2001:db8::1/64\n encapsulation dot1q 300\n!\n";
    for (stanza, dst) in [
        (l2, "192.0.2.200"),
        (l2, "192.0.2.193"),
        (routed, "192.0.2.193"),
        (unnumbered, "192.0.2.193"),
        (ipv6, "192.0.2.193"),
    ] {
        let t = twin_of(assemble(vec![
            core1(),
            pe1_with(stanza),
            pe2_with_vlan_300(),
        ]));
        let (verdict, steps) = only(&query(
            &t,
            "pe2",
            "GigabitEthernet0/0/0/5",
            "198.51.100.250",
            dst,
            false,
        ));
        assert_eq!(verdict, VerdictKind::Unknown, "{stanza}{dst}: {steps:#?}");
        assert!(has(&steps, "pe1/handoff/Bundle-Ether20"), "{steps:#?}");
        // A frame of a VLAN of a lowered sub-interface is not affected.
        let (verdict, steps) = only(&query(
            &t,
            "pe2",
            "GigabitEthernet0/0/0/5",
            "198.51.100.250",
            "192.0.2.3",
            false,
        ));
        assert_eq!(verdict, VerdictKind::Deliver, "{stanza}: {steps:#?}");
    }
    // A routed sub-interface whose VLAN is not read leaves a frame to a MAC
    // of no router dropped.
    let t = twin_of(assemble(vec![
        core1(),
        pe1_with(routed),
        pe2_with_vlan_300(),
    ]));
    let (verdict, steps) = only(&query(
        &t,
        "pe2",
        "GigabitEthernet0/0/0/5",
        "198.51.100.250",
        "192.0.2.200",
        false,
    ));
    assert_eq!(verdict, VerdictKind::Drop, "{steps:#?}");
    // With no such sub-interface, the frames of VLAN 300 are dropped.
    let t = twin_of(assemble(vec![
        core1(),
        pe1(sections()),
        pe2_with_vlan_300(),
    ]));
    for dst in ["192.0.2.200", "192.0.2.193"] {
        let (verdict, steps) = only(&query(
            &t,
            "pe2",
            "GigabitEthernet0/0/0/5",
            "198.51.100.250",
            dst,
            false,
        ));
        assert_eq!(verdict, VerdictKind::Drop, "{dst}: {steps:#?}");
        assert!(has(&steps, "pe1/handoff/Bundle-Ether20"), "{steps:#?}");
    }
}

#[test]
fn the_links_carry_their_provenance() {
    let t = twin();
    let a = query(
        &t,
        "core1",
        "Ethernet1/3",
        "198.51.100.130",
        "203.0.113.1",
        false,
    );
    let b = &a.branches()[0];
    let files: BTreeSet<String> = b
        .steps
        .iter()
        .filter(|s| s.function.as_str() == "core1/out/port-channel10")
        .flat_map(|s| s.provenance.iter())
        .map(|s| s.file.to_string())
        .collect();
    // The LLDP rows of the NX-OS switch are rows of a JSON table.
    for f in ["core1/lldp#row", "pe1/lldp", "pe1/cdp", "pe1/interfaces"] {
        assert!(files.contains(f), "{f} not in {files:?}");
    }
}

#[test]
fn an_egress_with_no_link_stays_without_a_link() {
    let t = twin_of(assemble(vec![pe1(sections())]));
    let (_, steps) = only(&query(
        &t,
        "pe1",
        "GigabitEthernet0/0/0/3",
        "203.0.113.10",
        "198.51.100.70",
        false,
    ));
    assert!(
        !steps.iter().any(|s| s.starts_with("pe1/handoff")),
        "{steps:#?}"
    );
    assert!(!steps.iter().any(|s| s.starts_with("core1/")), "{steps:#?}");
}

#[test]
fn two_builds_give_the_same_answers() {
    let (a, b) = (twin(), twin());
    for (device, ingress, src, dst) in [
        ("core1", "Ethernet1/3", "198.51.100.130", "203.0.113.1"),
        (
            "pe2",
            "GigabitEthernet0/0/0/5",
            "198.51.100.250",
            "192.0.2.3",
        ),
        (
            "pe2",
            "GigabitEthernet0/0/0/5",
            "198.51.100.250",
            "192.0.2.5",
        ),
        ("pe1", "Bundle-Ether20.100", "192.0.2.20", "192.0.2.5"),
    ] {
        let q = |t: &Twin| show(&query(t, device, ingress, src, dst, true));
        assert_eq!(q(&a), q(&b));
    }
    assert_eq!(estate().notes, estate().notes);
}
