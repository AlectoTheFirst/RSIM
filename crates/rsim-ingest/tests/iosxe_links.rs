//! The IOS-XE summary for the link join, the links of the router `edge1`
//! to the IOS-XR routers `pe1` and `pe3`, HSRP and VRRP, and the layer 2
//! part of the Catalyst switch `acc1` with its router `dist1`, on the
//! synthetic running configs and text sections of `edge1` and `acc1`. The
//! sections of `pe1` come from the IOS-XR fixtures; `pe3` and `dist1` are
//! written here.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{FunctionId, Header, InterfaceId, Mac, PROTO_TCP, Prefix, PrefixTable, SourceSpan};
use rsim_core::{TriePrefixTable, VerdictKind};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_functions::{HostMac, HostResolution, Meta};
use rsim_ingest::collected::Collected;
use rsim_ingest::estate::{Estate, Input, assemble};
use rsim_ingest::links::{PortVlans, Summary};
use rsim_ingest::route_tables::RouteTables;
use rsim_ingest::{iosxe, iosxr};

type Sections = BTreeMap<String, (Vec<u8>, String)>;

const EDGE1: &[u8] = include_bytes!("fixtures/iosxe/running-config.txt");
const ACC1: &[u8] = include_bytes!("fixtures/iosxe/switch-config.txt");

/// The sections of an IOS-XE device that have a fixture with the prefix.
fn fixtures(device: &str, prefix: &str) -> Sections {
    iosxe::SECTIONS
        .iter()
        .filter_map(|n| {
            let path = format!(
                "{}/tests/fixtures/iosxe/{prefix}{n}.txt",
                env!("CARGO_MANIFEST_DIR")
            );
            let bytes = std::fs::read(path).ok()?;
            Some((n.to_string(), (bytes, format!("{device}/{n}"))))
        })
        .collect()
}

fn text_sections(device: &str, list: &[(&str, &str)]) -> Sections {
    list.iter()
        .map(|(n, t)| {
            (
                n.to_string(),
                (t.as_bytes().to_vec(), format!("{device}/{n}")),
            )
        })
        .collect()
}

fn xe(name: &str, config: &[u8], sections: Sections) -> Input {
    Input::Iosxe {
        name: name.into(),
        config: config.to_vec(),
        file: format!("{name}/config"),
        collected: Collected::default(),
        sections,
    }
}

fn xr(name: &str, config: &[u8], sections: Sections) -> Input {
    Input::Iosxr {
        name: name.into(),
        config: config.to_vec(),
        file: format!("{name}/config"),
        collected: Collected::default(),
        sections,
    }
}

/// The LLDP row of pe1 for its link to GigabitEthernet0 of edge1.
const PE1_TO_EDGE1: &str = "------------------------------------------------
Local Interface: GigabitEthernet0/0/0/3
Chassis id: 0000.5e00.53f2
Port id: Gi0
Port Description: management
System Name: edge1

System Description:
Example IOS XE Software, Version 17.09.04

Time remaining: 99 seconds
Hold Time: 120 seconds
System Capabilities: R
Enabled Capabilities: R
Management Addresses:
  IPv4 address: 203.0.113.10
Peer MAC Address: 00:00:5e:00:53:31

Total entries displayed: 3";

/// The IOS-XR router pe1 of the IOS-XR fixtures, with an LLDP row of its
/// link to edge1.
fn pe1() -> Input {
    let sections = iosxr::SECTIONS
        .iter()
        .map(|n| {
            let path = format!(
                "{}/tests/fixtures/iosxr/{n}.txt",
                env!("CARGO_MANIFEST_DIR")
            );
            let mut bytes = std::fs::read(path).unwrap();
            if *n == "lldp" {
                bytes = String::from_utf8(bytes)
                    .unwrap()
                    .replace("Total entries displayed: 2", PE1_TO_EDGE1)
                    .into_bytes();
            }
            (n.to_string(), (bytes, format!("pe1/{n}")))
        })
        .collect();
    xr(
        "pe1",
        include_bytes!("fixtures/iosxr/running-config.txt"),
        sections,
    )
}

const PE3_CONFIG: &str = "Tue Nov 17 10:00:00.000 UTC
hostname pe3
vrf RED
!
vrf BLUE
!
interface GigabitEthernet0/0/0/0
 description to-edge1-lan
!
interface GigabitEthernet0/0/0/0.100
 vrf RED
 ipv4 address 192.0.2.4 255.255.255.192
 encapsulation dot1q 100
!
interface GigabitEthernet0/0/0/0.200
 vrf BLUE
 ipv4 address 192.0.2.131 255.255.255.192
 encapsulation dot1q 200
!
interface GigabitEthernet0/0/0/5
 description to-edge1-wan
 ipv4 address 198.51.100.5 255.255.255.252
!
interface GigabitEthernet0/0/0/6
 ipv4 address 198.51.100.65 255.255.255.192
!
end
";

const PE3_INTERFACES: &str = "Tue Nov 17 10:00:01.000 UTC
GigabitEthernet0/0/0/0 is up, line protocol is up
  Interface state transitions: 1
  Hardware is GigabitEthernet, address is 0000.5e00.5390 (bia 0000.5e00.5390)
  Internet address is Unknown
  MTU 1514 bytes, BW 1000000 Kbit (Max: 1000000 Kbit)
  Encapsulation ARPA,
  Full-duplex, 1000Mb/s, link type is force-up

GigabitEthernet0/0/0/0.100 is up, line protocol is up
  Interface state transitions: 1
  Hardware is VLAN sub-interface(s), address is 0000.5e00.5390
  Internet address is 192.0.2.4/26
  MTU 1518 bytes, BW 1000000 Kbit (Max: 1000000 Kbit)
  Encapsulation 802.1Q Virtual LAN, VLAN Id 100,  loopback not set,

GigabitEthernet0/0/0/0.200 is up, line protocol is up
  Interface state transitions: 1
  Hardware is VLAN sub-interface(s), address is 0000.5e00.5390
  Internet address is 192.0.2.131/26
  MTU 1518 bytes, BW 1000000 Kbit (Max: 1000000 Kbit)
  Encapsulation 802.1Q Virtual LAN, VLAN Id 200,  loopback not set,

GigabitEthernet0/0/0/5 is up, line protocol is up
  Interface state transitions: 1
  Hardware is GigabitEthernet, address is 0000.5e00.5305 (bia 0000.5e00.5305)
  Internet address is 198.51.100.5/30
  MTU 1514 bytes, BW 1000000 Kbit (Max: 1000000 Kbit)
  Encapsulation ARPA,
  Full-duplex, 1000Mb/s, link type is force-up

GigabitEthernet0/0/0/6 is up, line protocol is up
  Interface state transitions: 1
  Hardware is GigabitEthernet, address is 0000.5e00.5396 (bia 0000.5e00.5396)
  Internet address is 198.51.100.65/26
  MTU 1514 bytes, BW 1000000 Kbit (Max: 1000000 Kbit)
  Encapsulation ARPA,
";

const PE3_RIB: &str = "Tue Nov 17 10:00:02.000 UTC

VRF: default

Codes: C - connected, S - static, R - RIP, B - BGP, (>) - Diversion path
       L - local, (!) - FRR Backup path

Gateway of last resort is not set

C    198.51.100.4/30 is directly connected, 3d04h, GigabitEthernet0/0/0/5
L    198.51.100.5/32 is directly connected, 3d04h, GigabitEthernet0/0/0/5
C    198.51.100.64/26 is directly connected, 3d04h, GigabitEthernet0/0/0/6
L    198.51.100.65/32 is directly connected, 3d04h, GigabitEthernet0/0/0/6

VRF: RED

Codes: C - connected, S - static, R - RIP, B - BGP, (>) - Diversion path
       L - local, (!) - FRR Backup path

Gateway of last resort is not set

C    192.0.2.0/26 is directly connected, 3d04h, GigabitEthernet0/0/0/0.100
L    192.0.2.4/32 is directly connected, 3d04h, GigabitEthernet0/0/0/0.100

VRF: BLUE

Codes: C - connected, S - static, R - RIP, B - BGP, (>) - Diversion path
       L - local, (!) - FRR Backup path

Gateway of last resort is not set

C    192.0.2.128/26 is directly connected, 3d04h, GigabitEthernet0/0/0/0.200
L    192.0.2.131/32 is directly connected, 3d04h, GigabitEthernet0/0/0/0.200
";

/// The ARP rows of pe3: the MAC of edge1 on each sub-interface, and the
/// virtual MAC of HSRP group 2 of edge1.
const PE3_ARP: &str = "Tue Nov 17 10:00:03.000 UTC

-------------------------------------------------------------------------------
0/0/CPU0
-------------------------------------------------------------------------------
Address         Age        Hardware Addr   State      Type  Interface
192.0.2.4       -          0000.5e00.5390  Interface  ARPA  Gi0/0/0/0.100
192.0.2.2       00:00:41   0000.5e00.5311  Dynamic    ARPA  Gi0/0/0/0.100
192.0.2.3       00:00:41   0000.5e00.53a2  Dynamic    ARPA  Gi0/0/0/0.100
192.0.2.131     -          0000.5e00.5390  Interface  ARPA  Gi0/0/0/0.200
192.0.2.129     00:00:41   0000.5e00.5311  Dynamic    ARPA  Gi0/0/0/0.200
198.51.100.5    -          0000.5e00.5305  Interface  ARPA  Gi0/0/0/5
198.51.100.6    00:00:41   0000.5e00.5314  Dynamic    ARPA  Gi0/0/0/5
";

const PE3_LLDP: &str = "Tue Nov 17 10:00:06.000 UTC
Capability codes:
        (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device
        (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other

------------------------------------------------
Local Interface: GigabitEthernet0/0/0/0
Chassis id: 0000.5e00.53f2
Port id: Gi0/0/1
Port Description: LAN trunk
System Name: edge1

System Description:
Example IOS XE Software, Version 17.09.04

Time remaining: 101 seconds
Hold Time: 120 seconds
System Capabilities: R
Enabled Capabilities: R
Management Addresses:
  IPv4 address: 198.51.100.6
Peer MAC Address: 00:00:5e:00:53:11

------------------------------------------------
Local Interface: GigabitEthernet0/0/0/5
Chassis id: 0000.5e00.53f2
Port id: Gi0/0/4
Port Description: second provider uplink
System Name: edge1

System Description:
Example IOS XE Software, Version 17.09.04

Time remaining: 101 seconds
Hold Time: 120 seconds
System Capabilities: R
Enabled Capabilities: R
Management Addresses:
  IPv4 address: 198.51.100.6
Peer MAC Address: 00:00:5e:00:53:14

Total entries displayed: 2
";

/// The IOS-XR router on the trunk of edge1 and on its second provider
/// uplink.
fn pe3() -> Input {
    xr(
        "pe3",
        PE3_CONFIG.as_bytes(),
        text_sections(
            "pe3",
            &[
                ("interfaces", PE3_INTERFACES),
                ("rib", PE3_RIB),
                ("arp", PE3_ARP),
                ("lldp", PE3_LLDP),
            ],
        ),
    )
}

/// The estate of edge1 with its sections changed by `change`, pe1 and pe3.
fn routers_with(change: impl Fn(&mut Sections)) -> Estate {
    let mut s = fixtures("edge1", "");
    change(&mut s);
    assemble(vec![xe("edge1", EDGE1, s), pe1(), pe3()])
}

fn routers() -> Estate {
    routers_with(|_| {})
}

/// A section of edge1 with one text replaced.
fn replace(name: &'static str, from: &'static str, to: &'static str) -> impl Fn(&mut Sections) {
    move |s: &mut Sections| {
        let (b, _) = s.get_mut(name).unwrap();
        let text = String::from_utf8(b.clone()).unwrap();
        assert!(text.contains(from), "{from}");
        *b = text.replace(from, to).into_bytes();
    }
}

const DIST1_CONFIG: &str = "hostname dist1
!
interface Port-channel1
 description downlink to acc1
 no ip address
!
interface Port-channel1.99
 encapsulation dot1Q 99
 ip address 198.51.100.1 255.255.255.0
!
interface GigabitEthernet0/0/0
 no ip address
 channel-group 1 mode active
!
interface GigabitEthernet0/0/1
 no ip address
 channel-group 1 mode active
!
ip route 192.0.2.0 255.255.255.128 198.51.100.10
!
end
";

const DIST1_INTERFACES: &str = "Port-channel1 is up, line protocol is up
  Hardware is GEChannel, address is 0000.5e00.53e1 (bia 0000.5e00.53e1)
  Description: downlink to acc1
  MTU 1500 bytes, BW 2000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation 802.1Q Virtual LAN, Vlan ID  1., loopback not set
  Full Duplex, 1000Mbps, link type is auto, media type is RJ45
Port-channel1.99 is up, line protocol is up
  Hardware is GEChannel, address is 0000.5e00.53e1 (bia 0000.5e00.53e1)
  Internet address is 198.51.100.1/24
  MTU 1500 bytes, BW 2000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation 802.1Q Virtual LAN, Vlan ID  99.
GigabitEthernet0/0/0 is up, line protocol is up
  Hardware is ISR4331-3x1GE, address is 0000.5e00.53e2 (bia 0000.5e00.53e2)
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Full Duplex, 1000Mbps, link type is auto, media type is RJ45
GigabitEthernet0/0/1 is up, line protocol is up
  Hardware is ISR4331-3x1GE, address is 0000.5e00.53e3 (bia 0000.5e00.53e3)
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Full Duplex, 1000Mbps, link type is auto, media type is RJ45
";

const DIST1_RIB: &str = "Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP

Gateway of last resort is not set

      192.0.2.0/24 is variably subnetted, 1 subnets, 1 masks
S        192.0.2.0/25 [1/0] via 198.51.100.10
      198.51.100.0/24 is variably subnetted, 2 subnets, 2 masks
C        198.51.100.0/24 is directly connected, Port-channel1.99
L        198.51.100.1/32 is directly connected, Port-channel1.99
";

const DIST1_ARP: &str = "Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  198.51.100.1            -   0000.5e00.53e1  ARPA   Port-channel1.99
Internet  198.51.100.10           2   0000.5e00.5382  ARPA   Port-channel1.99
";

const DIST1_LLDP: &str = "------------------------------------------------
Local Intf: Gi0/0/0
Chassis id: 0000.5e00.5384
Port id: Gi1/0/47
Port Description: uplink member
System Name: acc1.example.test

System Description:
Example IOS XE Software, Version 17.06.05

Time remaining: 110 seconds
System Capabilities: B,R
Enabled Capabilities: B,R
Management Addresses:
    IP: 198.51.100.10
Auto Negotiation - supported, enabled
Physical media capabilities:
    1000baseT(FD)
Media Attachment Unit type: 30
Vlan ID: 1

------------------------------------------------
Local Intf: Gi0/0/1
Chassis id: 0000.5e00.5384
Port id: Gi1/0/48
Port Description: uplink member
System Name: acc1.example.test

System Description:
Example IOS XE Software, Version 17.06.05

Time remaining: 110 seconds
System Capabilities: B,R
Enabled Capabilities: B,R
Management Addresses:
    IP: 198.51.100.10
Auto Negotiation - supported, enabled
Physical media capabilities:
    1000baseT(FD)
Media Attachment Unit type: 30
Vlan ID: 1


Total entries displayed: 2
";

/// The router on the uplink port channel of acc1.
fn dist1() -> Input {
    xe(
        "dist1",
        DIST1_CONFIG.as_bytes(),
        text_sections(
            "dist1",
            &[
                ("interfaces", DIST1_INTERFACES),
                ("rib", DIST1_RIB),
                ("arp", DIST1_ARP),
                ("lldp", DIST1_LLDP),
            ],
        ),
    )
}

/// The running config of acc1 without the lines that make its access ports
/// and Vlan10 `Unknown`: the voice VLAN, the port security, the storm
/// control and the DHCP relay.
fn acc1_clean() -> Vec<u8> {
    let mut text = String::from_utf8(ACC1.to_vec()).unwrap();
    for line in [
        " switchport voice vlan 20\n",
        " switchport port-security\n",
        " storm-control broadcast level 10.00\n",
        " ip helper-address 192.0.2.53\n",
    ] {
        assert!(text.contains(line), "{line}");
        text = text.replace(line, "");
    }
    text.into_bytes()
}

fn campus_with(acc1_config: &[u8]) -> Estate {
    assemble(vec![
        xe("acc1", acc1_config, fixtures("acc1", "switch-")),
        dist1(),
    ])
}

fn campus() -> Estate {
    campus_with(&acc1_clean())
}

/// The host 192.0.2.50 on the access port GigabitEthernet1/0/2 of acc1, in
/// VLAN 10, with the MAC of its ARP row and Vlan10 as its gateway.
fn with_host(e: Estate) -> Twin {
    with_host_to(e, "00:00:5e:00:53:81")
}

/// The host of [`with_host`] with the gateway MAC `gateway`.
fn with_host_to(mut e: Estate, gateway: &str) -> Twin {
    let p = iosxe::profile();
    let span = SourceSpan::line("host.test", 1);
    let mut hosts: TriePrefixTable<HostMac> = TriePrefixTable::new();
    hosts.insert(
        Prefix::host(ip("192.0.2.50")),
        HostMac {
            mac: mac("00:00:5e:00:53:b0"),
            spans: vec![span.clone()],
        },
    );
    e.builder.add(HostResolution {
        meta: Meta::new("acc1/host/GigabitEthernet1/0/2", "acc1", &p).with_span(span.clone()),
        interface: InterfaceId::new("GigabitEthernet1/0/2"),
        hosts,
        local: vec!["192.0.2.0/25".parse().unwrap()],
        gateway: Some(HostMac {
            mac: mac(gateway),
            spans: vec![span],
        }),
        next: FunctionId::new("acc1/port/GigabitEthernet1/0/2/in"),
    });
    e.builder.build().expect("the twin builds")
}

fn twin_of(e: Estate) -> Twin {
    e.builder.build().expect("the twin builds")
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn mac(s: &str) -> Mac {
    s.parse().unwrap()
}

fn query(t: &Twin, device: &str, ingress: &str, src: &str, dst: &str) -> Answer {
    let h = Header::request(ip(src), ip(dst), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(22);
    let q = Query::path(t, &h)
        .with_ingress(device, ingress)
        .without_reply();
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

fn says(steps: &[String], text: &str) -> bool {
    steps.iter().any(|s| s.contains(text))
}

fn summary_of(name: &str, config: &[u8], sections: &Sections) -> Summary {
    let doc = iosxe::read_text(config);
    let cfg = iosxe::read(
        &doc,
        &iosxe::table(&RouteTables::uniform(true, iosxe::dynamic_vrfs(&doc))),
    );
    let (_, sum) = iosxe::lower(
        name,
        &format!("{name}/config"),
        &iosxe::profile(),
        &cfg,
        sections,
        &Default::default(),
    );
    sum
}

#[test]
fn the_sections_parse_through_their_templates() {
    let doc = iosxe::read_text(EDGE1);
    let cfg = iosxe::read(
        &doc,
        &iosxe::table(&RouteTables::uniform(true, iosxe::dynamic_vrfs(&doc))),
    );
    let st = iosxe::state::read(&fixtures("edge1", ""), &iosxe::names(&cfg));
    let lldp = st.l3.lldp.unwrap().unwrap();
    assert_eq!(lldp.len(), 3);
    assert_eq!(st.l3.cdp.unwrap().unwrap().len(), 1);
    let hsrp: Vec<(String, u32, String, Option<IpAddr>)> = st
        .l3
        .hsrp
        .unwrap()
        .unwrap()
        .into_iter()
        .map(|r| (r.interface, r.group, r.state, r.address))
        .collect();
    assert_eq!(
        hsrp,
        [
            (
                "GigabitEthernet0/0/1.100".to_string(),
                1,
                "Standby".to_string(),
                Some(ip("192.0.2.1"))
            ),
            (
                "GigabitEthernet0/0/1.100".to_string(),
                2,
                "Active".to_string(),
                Some(ip("192.0.2.3"))
            ),
        ]
    );
    let vrrp = st.vrrp.unwrap().unwrap();
    assert_eq!(
        (
            vrrp[0].interface.as_str(),
            vrrp[0].group,
            vrrp[0].state.as_str(),
            vrrp[0].address
        ),
        (
            "GigabitEthernet0/0/1.200",
            10,
            "Backup",
            Some(ip("192.0.2.130"))
        )
    );
    assert_eq!(&*vrrp[0].span.file, "edge1/vrrp");
}

#[test]
fn the_summary_of_the_router() {
    let sum = summary_of("edge1", EDGE1, &fixtures("edge1", ""));
    assert_eq!(sum.host_name.as_deref(), Some("edge1"));
    let ports: Vec<&str> = sum.entries.keys().map(String::as_str).collect();
    assert_eq!(
        ports,
        [
            "GigabitEthernet0",
            "GigabitEthernet0/0/0",
            "GigabitEthernet0/0/1",
            "GigabitEthernet0/0/4",
            "GigabitEthernet0/0/5",
            "GigabitEthernet0/0/7",
        ]
    );
    assert_eq!(
        sum.entries["GigabitEthernet0/0/1"].as_str(),
        "edge1/handoff/GigabitEthernet0/0/1"
    );
    assert_eq!(sum.port_macs["GigabitEthernet0"], mac("00:00:5e:00:53:31"));
    assert_eq!(
        sum.port_macs["GigabitEthernet0/0/1"],
        mac("00:00:5e:00:53:11")
    );
    assert_eq!(
        &*sum.port_spans["GigabitEthernet0/0/4"].file,
        "edge1/interfaces"
    );
    assert_eq!(sum.facts["GigabitEthernet0/0/4"].speed_mbps, Some(1000));
    assert_eq!(sum.facts["GigabitEthernet0/0/4"].full_duplex, Some(true));
    // The addresses of the trunk by the dot1Q VLAN of its sub-interfaces.
    let l3 = |p: &str, v: Option<u16>| -> Vec<String> {
        sum.l3[p][&v]
            .iter()
            .map(|(a, l)| format!("{a}/{l}"))
            .collect()
    };
    assert_eq!(
        l3("GigabitEthernet0/0/1", Some(100)),
        ["192.0.2.2/26", "192.0.2.66/26"]
    );
    assert_eq!(l3("GigabitEthernet0/0/1", Some(200)), ["192.0.2.129/26"]);
    assert_eq!(l3("GigabitEthernet0", None), ["203.0.113.10/24"]);
    // The LLDP and CDP rows with the short names resolved.
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
            ("GigabitEthernet0".into(), Some("pe1"), Some("Gi0/0/0/3")),
            (
                "GigabitEthernet0/0/1".into(),
                Some("pe3"),
                Some("GigabitEthernet0/0/0/0")
            ),
            (
                "GigabitEthernet0/0/4".into(),
                Some("pe3"),
                Some("GigabitEthernet0/0/0/5")
            ),
            (
                "GigabitEthernet0/0/4".into(),
                Some("pe3"),
                Some("GigabitEthernet0/0/0/5")
            ),
        ]
    );
    assert_eq!(sum.neighbours[0].chassis, Some(mac("00:00:5e:00:53:f1")));
    assert_eq!(&*sum.neighbours[3].span.file, "edge1/cdp");
    // The next hops of the route table and of the static routes.
    for hop in [
        "198.51.100.1",
        "198.51.100.5",
        "203.0.113.1",
        "198.51.100.9",
    ] {
        assert!(sum.next_hops.contains(&ip(hop)), "{hop}");
    }
    // A router has no switch port.
    assert!(sum.ports.is_empty() && sum.vlans.is_empty());
}

#[test]
fn the_summary_of_the_switch() {
    let sum = summary_of("acc1", ACC1, &fixtures("acc1", "switch-"));
    assert_eq!(sum.host_name.as_deref(), Some("acc1"));
    // The switch ports: the uplink port channel is exact, and the access
    // ports with lines that are not lowered give `Unknown`.
    let ports: Vec<(&str, Option<&PortVlans>)> = sum
        .ports
        .iter()
        .map(|(p, v)| (p.as_str(), v.as_ref()))
        .collect();
    let trunk = PortVlans {
        native: None,
        tagged: BTreeSet::from([10, 20, 99]),
        edge: false,
    };
    assert_eq!(
        ports,
        [
            ("GigabitEthernet1/0/1", None),
            ("GigabitEthernet1/0/2", None),
            ("Port-channel1", Some(&trunk)),
        ]
    );
    assert_eq!(
        sum.entries["Port-channel1"].as_str(),
        "acc1/port/Port-channel1/in"
    );
    assert_eq!(
        sum.entries["GigabitEthernet0/0"].as_str(),
        "acc1/handoff/GigabitEthernet0/0"
    );
    assert_eq!(sum.port_macs["Port-channel1"], mac("00:00:5e:00:53:87"));
    assert_eq!(sum.port("Gi1/0/48"), "Port-channel1");
    assert_eq!(sum.facts["Port-channel1"].speed_mbps, Some(1000));
    // The VLANs with an SVI, and the ARP rows of the SVIs.
    assert_eq!(sum.vlans.keys().copied().collect::<Vec<_>>(), [10, 99]);
    assert_eq!(
        sum.vlans[&10].local,
        ["192.0.2.0/25".parse::<Prefix>().unwrap()]
    );
    assert_eq!(
        sum.vlans[&10].gateway.as_ref().map(|g| g.mac),
        Some(mac("00:00:5e:00:53:81"))
    );
    let arp: Vec<(u16, String)> = sum
        .arp
        .iter()
        .map(|(v, a, _, _)| (*v, a.to_string()))
        .collect();
    assert_eq!(
        arp,
        [(10, "192.0.2.50".into()), (99, "198.51.100.1".into())]
    );
    // No MAC table is collected, so no MAC has a port.
    assert!(sum.macs.is_empty());
    assert!(sum.next_hops.contains(&ip("198.51.100.1")));
    assert_eq!(sum.neighbours.len(), 2);
}

#[test]
fn a_path_crosses_from_the_ios_xr_router_to_the_ios_xe_router() {
    let t = twin_of(routers());
    let (verdict, steps) = only(&query(
        &t,
        "pe1",
        "Bundle-Ether10",
        "198.51.100.2",
        "203.0.113.10",
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    for f in [
        "pe1/out/GigabitEthernet0/0/0/3",
        "edge1/handoff/GigabitEthernet0",
        "edge1/in/GigabitEthernet0",
        "edge1/deliver",
    ] {
        assert!(has(&steps, f), "{f} not in {steps:#?}");
    }
    assert!(says(&steps, "in VRF MGMT"), "{steps:#?}");
}

#[test]
fn a_path_crosses_from_the_ios_xe_router_to_the_ios_xr_router() {
    let e = routers();
    let t = twin_of(e);
    let a = query(
        &t,
        "edge1",
        "GigabitEthernet0/0/5",
        "192.0.2.200",
        "198.51.100.65",
    );
    let (verdict, steps) = only(&a);
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    for f in [
        "edge1/snat",
        "edge1/out/GigabitEthernet0/0/4",
        "pe3/handoff/GigabitEthernet0/0/0/5",
        "pe3/in/GigabitEthernet0/0/0/5",
        "pe3/deliver",
    ] {
        assert!(has(&steps, f), "{f} not in {steps:#?}");
    }
    // The link carries the LLDP and CDP rows of both ends.
    let files: BTreeSet<String> = a.branches()[0]
        .steps
        .iter()
        .filter(|s| s.function.as_str() == "edge1/out/GigabitEthernet0/0/4")
        .flat_map(|s| s.provenance.iter())
        .map(|s| s.file.to_string())
        .collect();
    for f in ["edge1/lldp", "edge1/cdp", "pe3/lldp"] {
        assert!(files.contains(f), "{f} not in {files:?}");
    }
}

#[test]
fn the_active_hsrp_group_takes_its_virtual_mac_at_the_hand_off() {
    let t = twin_of(routers());
    let (verdict, steps) = only(&query(
        &t,
        "pe3",
        "GigabitEthernet0/0/0/0.100",
        "192.0.2.20",
        "192.0.2.3",
    ));
    for f in [
        "pe3/out/GigabitEthernet0/0/0/0.100",
        "edge1/handoff/GigabitEthernet0/0/1",
        "edge1/in/GigabitEthernet0/0/1.100",
    ] {
        assert!(has(&steps, f), "{f} not in {steps:#?}");
    }
    // The zone-member line of the sub-interface is not lowered.
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(has(&steps, "edge1/acl-in/GigabitEthernet0/0/1.100"));
}

#[test]
fn a_standby_hsrp_group_does_not_take_its_virtual_mac() {
    let e = routers_with(replace(
        "hsrp",
        "100   Active  local           192.0.2.4",
        "100   Standby 192.0.2.4       local    ",
    ));
    let t = twin_of(e);
    let (verdict, steps) = only(&query(
        &t,
        "pe3",
        "GigabitEthernet0/0/0/0.100",
        "192.0.2.20",
        "192.0.2.3",
    ));
    assert_eq!(verdict, VerdictKind::Drop, "{steps:#?}");
    assert!(
        says(&steps, "destination MAC not a MAC of the router"),
        "{steps:#?}"
    );
    assert!(!has(&steps, "edge1/in/GigabitEthernet0/0/1.100"));
}

#[test]
fn an_active_group_with_no_virtual_mac_makes_the_port_unknown() {
    let e = routers_with(replace(
        "hsrp",
        "110 P Standby 192.0.2.4       local    ",
        "110 P Active  local           192.0.2.4",
    ));
    assert!(
        e.notes["edge1"].iter().any(|n| n
            == "GigabitEthernet0/0/1.100: HSRP group 1: no mac-address line, none in show standby brief, virtual MAC not known"),
        "{:#?}",
        e.notes["edge1"]
    );
    let t = twin_of(e);
    let (verdict, steps) = only(&query(
        &t,
        "pe3",
        "GigabitEthernet0/0/0/0.100",
        "192.0.2.20",
        "192.0.2.3",
    ));
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(says(&steps, "virtual MAC not known"), "{steps:#?}");
    assert!(!has(&steps, "edge1/in/GigabitEthernet0/0/1.100"));
}

#[test]
fn a_state_that_cannot_be_read_gives_unknown() {
    let bogus = replace("hsrp", "100   Active  local", "100   Resign  local");
    let without = |s: &mut Sections| {
        s.remove("hsrp");
    };
    for (change, why) in [
        (
            &bogus as &dyn Fn(&mut Sections),
            "state \"Resign\" not known",
        ),
        (&without, "no show standby brief section"),
    ] {
        let e = routers_with(change);
        let note = format!(
            "GigabitEthernet0/0/1.100: HSRP group 2: {why}, virtual address and MAC unknown"
        );
        assert!(e.notes["edge1"].contains(&note), "{:#?}", e.notes["edge1"]);
        let t = twin_of(e);
        let (verdict, steps) = only(&query(
            &t,
            "pe3",
            "GigabitEthernet0/0/0/0.100",
            "192.0.2.20",
            "192.0.2.3",
        ));
        assert_eq!(verdict, VerdictKind::Unknown, "{why}: {steps:#?}");
        assert!(
            has(&steps, "edge1/handoff/GigabitEthernet0/0/1"),
            "{steps:#?}"
        );
        assert!(
            !has(&steps, "edge1/in/GigabitEthernet0/0/1.100"),
            "{steps:#?}"
        );
    }
}

#[test]
fn the_vrrp_master_owns_the_virtual_address_and_the_backup_does_not() {
    let to_vip = |t: &Twin| {
        only(&query(
            t,
            "edge1",
            "GigabitEthernet0/0/7",
            "198.51.100.40",
            "192.0.2.130",
        ))
    };
    // Backup: the virtual address is not local, and each other route of the
    // VRF is unknown.
    let (verdict, steps) = to_vip(&twin_of(routers()));
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(says(&steps, "route 0.0.0.0/0 in VRF BLUE"), "{steps:#?}");
    assert!(!has(&steps, "edge1/deliver"));
    // Master: the virtual address is local. The brief form gives no virtual
    // MAC, so the frames of the trunk are unknown at its hand-off.
    let e = routers_with(replace(
        "vrrp",
        "Y  Backup  192.0.2.131 ",
        "Y  Master  192.0.2.129 ",
    ));
    assert!(
        e.notes["edge1"].iter().any(|n| n
            == "GigabitEthernet0/0/1.200: VRRP group 10: none in show vrrp brief, virtual MAC not known"),
        "{:#?}",
        e.notes["edge1"]
    );
    let t = twin_of(e);
    let (verdict, steps) = to_vip(&t);
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    let (verdict, steps) = only(&query(
        &t,
        "pe3",
        "GigabitEthernet0/0/0/0.100",
        "192.0.2.20",
        "192.0.2.3",
    ));
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(
        says(&steps, "VRRP group 10 of GigabitEthernet0/0/1.200"),
        "{steps:#?}"
    );
    // A state that is not known: the virtual address has no next hop.
    let e = routers_with(replace("vrrp", "Y  Backup ", "Y  Fault  "));
    let (verdict, steps) = to_vip(&twin_of(e));
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(
        says(&steps, "route 192.0.2.130/32 in VRF BLUE"),
        "{steps:#?}"
    );
}

#[test]
fn a_frame_from_the_router_reaches_the_svi_of_the_switch_over_the_trunk() {
    let t = twin_of(campus());
    let (verdict, steps) = only(&query(
        &t,
        "dist1",
        "Port-channel1.99",
        "198.51.100.50",
        "192.0.2.1",
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    for f in [
        "dist1/out/Port-channel1.99",
        "acc1/port/Port-channel1/in",
        "acc1/mac",
        "acc1/svi/Vlan99/out",
        "acc1/handoff/Vlan99",
        "acc1/in/Vlan99",
        "acc1/deliver",
    ] {
        assert!(has(&steps, f), "{f} not in {steps:#?}");
    }
}

#[test]
fn a_host_on_an_access_port_reaches_the_router_through_the_svi() {
    let t = with_host(campus());
    let (verdict, steps) = only(&query(
        &t,
        "acc1",
        "GigabitEthernet1/0/2",
        "192.0.2.50",
        "198.51.100.1",
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    for f in [
        "acc1/port/GigabitEthernet1/0/2/in",
        "acc1/handoff/Vlan10",
        "acc1/in/Vlan10",
        "acc1/out/Vlan99",
        "acc1/svi/Vlan99/in",
        "acc1/port/Port-channel1/out",
        "dist1/handoff/Port-channel1",
        "dist1/in/Port-channel1.99",
        "dist1/deliver",
    ] {
        assert!(has(&steps, f), "{f} not in {steps:#?}");
    }
    // The router is on the far end of the link of the port channel.
    assert!(says(&steps, "on port Port-channel1"), "{steps:#?}");
}

#[test]
fn with_no_mac_table_a_frame_to_a_host_is_unknown() {
    let t = twin_of(campus());
    let (verdict, steps) = only(&query(
        &t,
        "dist1",
        "Port-channel1.99",
        "198.51.100.50",
        "192.0.2.50",
    ));
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(has(&steps, "acc1/out/Vlan10"), "{steps:#?}");
    assert!(has(&steps, "acc1/mac-miss"), "{steps:#?}");
    assert!(says(&steps, "MAC table not collected"), "{steps:#?}");
}

#[test]
fn a_flood_copy_toward_the_trunk_is_unknown() {
    let doc = iosxe::read_text(&acc1_clean());
    let cfg = iosxe::read(
        &doc,
        &iosxe::table(&RouteTables::uniform(true, iosxe::dynamic_vrfs(&doc))),
    );
    let (low, _) = iosxe::lower(
        "acc1",
        "acc1/config",
        &iosxe::profile(),
        &cfg,
        &fixtures("acc1", "switch-"),
        &Default::default(),
    );
    let flood = low
        .functions
        .iter()
        .find(|f| f.id().as_str() == "acc1/flood")
        .expect("a flood");
    let next: Vec<String> = flood.successors().iter().map(|f| f.to_string()).collect();
    // The trunk goes through the function of the spanning tree state, which
    // is not collected; an edge access port gets its copy.
    assert!(
        next.contains(&"acc1/port/Port-channel1/stp".to_string()),
        "{next:?}"
    );
    assert!(
        next.contains(&"acc1/port/GigabitEthernet1/0/2/out".to_string()),
        "{next:?}"
    );
    assert!(
        !next.contains(&"acc1/port/Port-channel1/out".to_string()),
        "{next:?}"
    );
}

#[test]
fn an_access_port_with_lines_that_are_not_lowered_is_unknown() {
    let e = campus_with(ACC1);
    assert!(
        e.notes["acc1"].iter().any(|n| n
            == "GigabitEthernet1/0/2: options not lowered: storm-control broadcast level 10.00"),
        "{:#?}",
        e.notes["acc1"]
    );
    let t = with_host(e);
    let (verdict, steps) = only(&query(
        &t,
        "acc1",
        "GigabitEthernet1/0/2",
        "192.0.2.50",
        "198.51.100.1",
    ));
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(
        has(&steps, "acc1/port/GigabitEthernet1/0/2/in"),
        "{steps:#?}"
    );
    assert!(!has(&steps, "acc1/mac"), "{steps:#?}");
}

#[test]
fn a_switch_port_with_no_mode_line_is_unknown() {
    let config = String::from_utf8(acc1_clean()).unwrap();
    let config = config.replace(
        "interface GigabitEthernet1/0/2\n switchport access vlan 10\n switchport mode access\n",
        "interface GigabitEthernet1/0/2\n switchport access vlan 10\n",
    );
    let e = campus_with(config.as_bytes());
    assert!(
        e.notes["acc1"].iter().any(|n| n
            == "GigabitEthernet1/0/2: options not lowered: no switchport mode line, mode negotiated"),
        "{:#?}",
        e.notes["acc1"]
    );
}

#[test]
fn a_vlan_filter_makes_the_ports_of_its_vlans_unknown() {
    let config = String::from_utf8(acc1_clean()).unwrap().replacen(
        "vlan 100,200\n!\n",
        "vlan 100,200\n!\nvlan access-map BLOCK 10\n match ip address 101\n action drop\n!\nvlan filter BLOCK vlan-list 10\n!\n",
        1,
    );
    let t = with_host(campus_with(config.as_bytes()));
    let (verdict, steps) = only(&query(
        &t,
        "acc1",
        "GigabitEthernet1/0/2",
        "192.0.2.50",
        "198.51.100.1",
    ));
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(
        has(&steps, "acc1/port/GigabitEthernet1/0/2/in"),
        "{steps:#?}"
    );
    assert!(says(&steps, "VLAN 10"), "{steps:#?}");
    assert!(!has(&steps, "acc1/mac"), "{steps:#?}");
}

#[test]
fn the_tagging_of_the_native_vlan_makes_each_trunk_unknown() {
    let config = String::from_utf8(acc1_clean()).unwrap().replacen(
        "vtp mode transparent\n",
        "vtp mode transparent\nvlan dot1q tag native\n",
        1,
    );
    let e = campus_with(config.as_bytes());
    assert!(
        e.notes["acc1"]
            .iter()
            .any(|n| n == "Port-channel1: options not lowered: vlan dot1q tag native"),
        "{:#?}",
        e.notes["acc1"]
    );
    let t = with_host(e);
    let (verdict, steps) = only(&query(
        &t,
        "acc1",
        "GigabitEthernet1/0/2",
        "192.0.2.50",
        "198.51.100.1",
    ));
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(!has(&steps, "dist1/handoff/Port-channel1"), "{steps:#?}");
}

/// The estate of edge1 with one line of its running config changed, pe1
/// and the router `pe3` given.
fn routers_with_config(from: &str, to: &str, pe3: Input) -> Estate {
    let text = String::from_utf8(EDGE1.to_vec()).unwrap();
    assert!(text.contains(from), "{from}");
    let config = text.replacen(from, to, 1);
    assemble(vec![
        xe("edge1", config.as_bytes(), fixtures("edge1", "")),
        pe1(),
        pe3,
    ])
}

/// pe3 with the address of VLAN 100 on its port to edge1, so it sends
/// untagged frames to edge1.
fn pe3_untagged() -> Input {
    let config = PE3_CONFIG.replacen(
        " description to-edge1-lan\n!\ninterface GigabitEthernet0/0/0/0.100\n vrf RED\n ipv4 address 192.0.2.4 255.255.255.192\n encapsulation dot1q 100\n!\n",
        " description to-edge1-lan\n vrf RED\n ipv4 address 192.0.2.4 255.255.255.192\n!\n",
        1,
    );
    assert_ne!(config, PE3_CONFIG);
    let rib = PE3_RIB.replace("GigabitEthernet0/0/0/0.100", "GigabitEthernet0/0/0/0");
    let arp = PE3_ARP.replace("Gi0/0/0/0.100", "Gi0/0/0/0");
    xr(
        "pe3",
        config.as_bytes(),
        text_sections(
            "pe3",
            &[
                ("interfaces", PE3_INTERFACES),
                ("rib", &rib),
                ("arp", &arp),
                ("lldp", PE3_LLDP),
            ],
        ),
    )
}

#[test]
fn a_sub_interface_with_a_vlan_that_is_not_lowered_makes_its_frames_unknown() {
    for (line, why) in [
        (
            " encapsulation dot1Q 100 native\n",
            "native VLAN of GigabitEthernet0/0/1.100 not lowered",
        ),
        (
            " encapsulation dot1Q 100 second-dot1q 20\n",
            "dot1q VLAN of GigabitEthernet0/0/1.100 not read",
        ),
    ] {
        let t = twin_of(routers_with_config(
            " encapsulation dot1Q 100\n",
            line,
            pe3(),
        ));
        let (verdict, steps) = only(&query(
            &t,
            "pe3",
            "GigabitEthernet0/0/0/0.100",
            "192.0.2.20",
            "192.0.2.3",
        ));
        assert_eq!(verdict, VerdictKind::Unknown, "{line}: {steps:#?}");
        assert!(
            has(&steps, "edge1/handoff/GigabitEthernet0/0/1"),
            "{line}: {steps:#?}"
        );
        assert!(says(&steps, why), "{line}: {steps:#?}");
        assert!(
            !has(&steps, "edge1/in/GigabitEthernet0/0/1.100"),
            "{line}: {steps:#?}"
        );
    }
}

#[test]
fn a_native_sub_interface_makes_the_untagged_frames_unknown() {
    // With a tagged sub-interface, the untagged frame has no interface.
    let t = twin_of(routers_with_config(
        " encapsulation dot1Q 100\n",
        " encapsulation dot1Q 100\n",
        pe3_untagged(),
    ));
    let (verdict, steps) = only(&query(
        &t,
        "pe3",
        "GigabitEthernet0/0/0/0",
        "192.0.2.20",
        "192.0.2.3",
    ));
    assert_eq!(verdict, VerdictKind::Drop, "{steps:#?}");
    assert!(
        says(&steps, "no router interface for untagged frames"),
        "{steps:#?}"
    );
    let t = twin_of(routers_with_config(
        " encapsulation dot1Q 100\n",
        " encapsulation dot1Q 100 native\n",
        pe3_untagged(),
    ));
    let (verdict, steps) = only(&query(
        &t,
        "pe3",
        "GigabitEthernet0/0/0/0",
        "192.0.2.20",
        "192.0.2.3",
    ));
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(
        says(
            &steps,
            "native VLAN of GigabitEthernet0/0/1.100 not lowered"
        ),
        "{steps:#?}"
    );
}

#[test]
fn a_port_with_a_layer_3_line_that_is_not_lowered_makes_the_untagged_frames_unknown() {
    for line in [
        " ip address dhcp\n",
        " ip unnumbered Loopback0\n",
        " no ip address\n ipv6 address 2001:db8::2/64\n",
    ] {
        let t = twin_of(routers_with_config(
            " description LAN trunk\n no ip address\n",
            &format!(" description LAN trunk\n{line}"),
            pe3_untagged(),
        ));
        let (verdict, steps) = only(&query(
            &t,
            "pe3",
            "GigabitEthernet0/0/0/0",
            "192.0.2.20",
            "192.0.2.3",
        ));
        assert_eq!(verdict, VerdictKind::Unknown, "{line}: {steps:#?}");
        assert!(
            says(&steps, "GigabitEthernet0/0/1 not lowered"),
            "{line}: {steps:#?}"
        );
    }
}

#[test]
fn with_no_vtp_mode_line_the_vlans_of_each_switch_port_are_not_known() {
    let config = String::from_utf8(acc1_clean())
        .unwrap()
        .replace("vtp mode transparent\n", "");
    let sum = summary_of("acc1", config.as_bytes(), &fixtures("acc1", "switch-"));
    assert!(!sum.ports.is_empty());
    assert!(sum.ports.values().all(Option::is_none), "{:?}", sum.ports);
    let e = campus_with(config.as_bytes());
    assert!(
        e.notes["acc1"].iter().any(|n| n
            == "Port-channel1: options not lowered: no vtp mode line, VLANs not in the running config"),
        "{:#?}",
        e.notes["acc1"]
    );
}

#[test]
fn two_builds_give_the_same_answers() {
    let (a, b) = (twin_of(routers()), twin_of(routers()));
    for (device, ingress, src, dst) in [
        ("pe1", "Bundle-Ether10", "198.51.100.2", "203.0.113.10"),
        (
            "edge1",
            "GigabitEthernet0/0/5",
            "192.0.2.200",
            "198.51.100.65",
        ),
        (
            "pe3",
            "GigabitEthernet0/0/0/0.100",
            "192.0.2.20",
            "192.0.2.3",
        ),
        (
            "edge1",
            "GigabitEthernet0/0/7",
            "198.51.100.40",
            "192.0.2.130",
        ),
    ] {
        let q = |t: &Twin| show(&query(t, device, ingress, src, dst));
        assert_eq!(q(&a), q(&b));
    }
    let (a, b) = (with_host(campus()), with_host(campus()));
    for (device, ingress, src, dst) in [
        ("acc1", "GigabitEthernet1/0/2", "192.0.2.50", "198.51.100.1"),
        ("dist1", "Port-channel1.99", "198.51.100.50", "192.0.2.50"),
    ] {
        let q = |t: &Twin| show(&query(t, device, ingress, src, dst));
        assert_eq!(q(&a), q(&b));
    }
    assert_eq!(routers().notes, routers().notes);
    assert_eq!(campus().notes, campus().notes);
}

/// The HSRP group of Vlan10 of acc1, in the state `state`.
fn campus_with_group(state: &str) -> Estate {
    let config = String::from_utf8(acc1_clean()).unwrap().replace(
        " ip address 192.0.2.1 255.255.255.128\n",
        " ip address 192.0.2.1 255.255.255.128\n standby 1 ip 192.0.2.126\n standby 1 mac-address 0000.5e00.53a9\n",
    );
    let mut sections = fixtures("acc1", "switch-");
    let hsrp = format!(
        "                     P indicates configured to preempt.
                     |
Interface   Grp  Pri P State   Active          Standby         Virtual IP
Vl10        1    110 P {state:<7} local           192.0.2.2       192.0.2.126
"
    );
    sections.insert(
        "hsrp".to_string(),
        (hsrp.into_bytes(), "acc1/hsrp".to_string()),
    );
    assemble(vec![xe("acc1", config.as_bytes(), sections), dist1()])
}

#[test]
fn the_active_group_of_an_svi_takes_its_virtual_mac_and_address() {
    let t = with_host_to(campus_with_group("Active"), "00:00:5e:00:53:a9");
    let (verdict, steps) = only(&query(
        &t,
        "acc1",
        "GigabitEthernet1/0/2",
        "192.0.2.50",
        "198.51.100.1",
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    for f in [
        "acc1/svi/Vlan10/out",
        "acc1/handoff/Vlan10",
        "dist1/deliver",
    ] {
        assert!(has(&steps, f), "{f} not in {steps:#?}");
    }
    let (verdict, steps) = only(&query(
        &t,
        "dist1",
        "Port-channel1.99",
        "198.51.100.50",
        "192.0.2.126",
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    assert!(has(&steps, "acc1/deliver"), "{steps:#?}");
    // On the standby switch the virtual MAC is on another switch, which the
    // twin cannot place with no MAC table.
    let t = with_host_to(campus_with_group("Standby"), "00:00:5e:00:53:a9");
    let (verdict, steps) = only(&query(
        &t,
        "acc1",
        "GigabitEthernet1/0/2",
        "192.0.2.50",
        "198.51.100.1",
    ));
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(has(&steps, "acc1/mac-miss"), "{steps:#?}");
    // A state that is not known makes the hand-off of the SVI unknown.
    let e = campus_with_group("Resign");
    assert!(
        e.notes["acc1"].iter().any(|n| n
            == "Vlan10: HSRP group 1: state \"Resign\" not known, virtual address and MAC unknown"),
        "{:#?}",
        e.notes["acc1"]
    );
    let t = with_host_to(e, "00:00:5e:00:53:81");
    let (verdict, steps) = only(&query(
        &t,
        "acc1",
        "GigabitEthernet1/0/2",
        "192.0.2.50",
        "198.51.100.1",
    ));
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(has(&steps, "acc1/svi/Vlan10/out"), "{steps:#?}");
    assert!(!has(&steps, "acc1/in/Vlan10"), "{steps:#?}");
}

const ACC1_MAC_TABLE: &str = "          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 All    0100.0ccc.cccc    STATIC      CPU
  10    0000.5e00.5381    STATIC      Vl10
  10    0000.5e00.53b0    DYNAMIC     Gi1/0/2
  99    0000.5e00.53e1    DYNAMIC     Po1
Total Mac Addresses for this criterion: 4
";

const ACC1_STP: &str = "
VLAN0010
  Spanning tree enabled protocol rstp
  Root ID    Priority    32778
             Address     0000.5e00.53e0
             Cost        3
             Port        25 (Port-channel1)
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec

Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- --------------------------------
Gi1/0/1             Desg FWD 4         128.1    P2p Edge
Gi1/0/2             Desg FWD 4         128.2    P2p Edge
Po1                 Root FWD 3         128.25   P2p

VLAN0020
  Spanning tree enabled protocol rstp
Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- --------------------------------
Po1                 Root FWD 3         128.25   P2p

VLAN0099
  Spanning tree enabled protocol rstp
Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- --------------------------------
Po1                 Root FWD 3         128.25   P2p
";

const ACC1_VLANS: &str = "
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi1/0/3
10   USERS                            active    Gi1/0/1, Gi1/0/2
20   VOICE                            active
99   MGMT                             active
1002 fddi-default                     act/unsup
";

/// The sections of acc1 with the sections `extra` added or replaced.
fn acc1_sections(extra: &[(&str, &str)]) -> Sections {
    let mut sections = fixtures("acc1", "switch-");
    for (n, t) in extra {
        sections.insert(n.to_string(), (t.as_bytes().to_vec(), format!("acc1/{n}")));
    }
    sections
}

/// The campus with the sections `extra` of acc1.
fn campus_plus(config: &[u8], extra: &[(&str, &str)]) -> Estate {
    assemble(vec![xe("acc1", config, acc1_sections(extra)), dist1()])
}

/// The successors of the flood of acc1 with the sections `extra`, the
/// notes, and the function of the spanning tree state of Port-channel1 as
/// debug text.
fn flood_of(config: &[u8], extra: &[(&str, &str)]) -> (Vec<String>, Vec<String>, String) {
    let doc = iosxe::read_text(config);
    let cfg = iosxe::read(
        &doc,
        &iosxe::table(&RouteTables::uniform(true, iosxe::dynamic_vrfs(&doc))),
    );
    let (low, _) = iosxe::lower(
        "acc1",
        "acc1/config",
        &iosxe::profile(),
        &cfg,
        &acc1_sections(extra),
        &Default::default(),
    );
    let find = |id: &str| low.functions.iter().find(|f| f.id().as_str() == id);
    let next = find("acc1/flood")
        .expect("a flood")
        .successors()
        .iter()
        .map(|f| f.to_string())
        .collect();
    let stp = find("acc1/port/Port-channel1/stp").map_or(String::new(), |f| format!("{f:?}"));
    (next, low.notes.clone(), stp)
}

fn contains(list: &[String], item: &str) -> bool {
    list.iter().any(|x| x == item)
}

#[test]
fn with_the_mac_table_a_frame_to_a_host_reaches_its_endpoint() {
    let t = twin_of(campus_plus(&acc1_clean(), &[("mac_table", ACC1_MAC_TABLE)]));
    let (verdict, steps) = only(&query(
        &t,
        "dist1",
        "Port-channel1.99",
        "198.51.100.50",
        "192.0.2.50",
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    for f in [
        "acc1/out/Vlan10",
        "acc1/mac",
        "acc1/port/GigabitEthernet1/0/2/out",
    ] {
        assert!(has(&steps, f), "{f} not in {steps:#?}");
    }
    assert!(!has(&steps, "acc1/mac-miss"), "{steps:#?}");
}

#[test]
fn the_endpoint_of_an_arp_row_sits_on_the_edge_port_of_its_mac() {
    let sum = summary_of(
        "acc1",
        &acc1_clean(),
        &acc1_sections(&[("mac_table", ACC1_MAC_TABLE)]),
    );
    let port = |v: u16, m: &str| sum.macs.get(&(v, mac(m))).map(|x| x.0.clone());
    assert_eq!(
        port(10, "00:00:5e:00:53:b0").as_deref(),
        Some("GigabitEthernet1/0/2")
    );
    assert_eq!(
        port(99, "00:00:5e:00:53:e1").as_deref(),
        Some("Port-channel1")
    );
    // The row of the MAC of the SVI is not a row of the table.
    assert_eq!(port(10, "00:00:5e:00:53:81"), None);
    let t = twin_of(campus_plus(&acc1_clean(), &[("mac_table", ACC1_MAC_TABLE)]));
    // The host sends from its own port through its host resolution.
    let (verdict, steps) = only(&query(
        &t,
        "acc1",
        "GigabitEthernet1/0/2",
        "192.0.2.50",
        "198.51.100.1",
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    assert!(has(&steps, "acc1/host/GigabitEthernet1/0/2"), "{steps:#?}");
    assert!(has(&steps, "dist1/deliver"), "{steps:#?}");
}

#[test]
fn the_spanning_tree_gives_the_flood_copy_of_each_forwarding_port() {
    let config = acc1_clean();
    // Without the section, the trunk goes through the function of the
    // state that is not collected.
    let (next, _, stp) = flood_of(&config, &[]);
    assert!(contains(&next, "acc1/port/Port-channel1/stp"), "{next:?}");
    assert!(stp.contains("spanning tree state not collected"));
    // Forwarding in each VLAN: the copy goes to the egress.
    let (next, _, stp) = flood_of(&config, &[("spanning_tree", ACC1_STP)]);
    assert!(contains(&next, "acc1/port/Port-channel1/out"), "{next:?}");
    assert!(!contains(&next, "acc1/port/Port-channel1/stp"), "{next:?}");
    assert!(stp.is_empty(), "{stp}");
    assert!(
        contains(&next, "acc1/port/GigabitEthernet1/0/2/out"),
        "{next:?}"
    );
    // Blocking in each VLAN: no copy at all.
    let blocked = ACC1_STP.replace("Root FWD", "Altn BLK");
    let (next, _, _) = flood_of(&config, &[("spanning_tree", &blocked)]);
    assert!(
        !next
            .iter()
            .any(|n| n.starts_with("acc1/port/Port-channel1/")),
        "{next:?}"
    );
    // An edge port that blocks gets no copy either.
    let edge_blocked = ACC1_STP.replace(
        "Gi1/0/2             Desg FWD",
        "Gi1/0/2             Desg BLK",
    );
    let (next, _, _) = flood_of(&config, &[("spanning_tree", &edge_blocked)]);
    assert!(
        !contains(&next, "acc1/port/GigabitEthernet1/0/2/out"),
        "{next:?}"
    );
}

#[test]
fn a_port_with_no_known_state_in_a_vlan_of_the_flood_is_unknown() {
    let config = acc1_clean();
    // No tree of VLAN 99: the copy of the trunk in VLAN 99 is unknown, and
    // the copies in VLANs 10 and 20 go to the egress.
    let no_99 = &ACC1_STP[..ACC1_STP.find("\nVLAN0099").unwrap()];
    let (next, _, stp) = flood_of(&config, &[("spanning_tree", no_99)]);
    assert!(contains(&next, "acc1/port/Port-channel1/stp"), "{next:?}");
    assert!(contains(&next, "acc1/port/Port-channel1/out"), "{next:?}");
    assert!(
        stp.contains("Port-channel1: spanning tree state not known in VLAN 99"),
        "{stp}"
    );
    // A state word that is not known.
    let odd = ACC1_STP.replace(
        "Po1                 Root FWD",
        "Po1                 Root XYZ",
    );
    let (next, _, stp) = flood_of(&config, &[("spanning_tree", &odd)]);
    assert!(contains(&next, "acc1/port/Port-channel1/stp"), "{next:?}");
    assert!(stp.contains("not known in VLAN 10, 20, 99"), "{stp}");
    // An MST instance, which the section does not map to VLANs.
    let mst = "\nMST0\n  Spanning tree enabled protocol mstp\nInterface           Role Sts Cost      Prio.Nbr Type\n------------------- ---- --- --------- -------- --------------------------------\nPo1                 Root FWD 3         128.25   P2p\n";
    let (next, notes, _) = flood_of(&config, &[("spanning_tree", mst)]);
    assert!(contains(&next, "acc1/port/Port-channel1/stp"), "{next:?}");
    assert!(
        notes
            .iter()
            .any(|n| n.starts_with("section spanning_tree not read")),
        "{notes:#?}"
    );
}

#[test]
fn show_vlan_brief_gives_the_vlans_of_a_switch_with_no_vtp_mode_line() {
    let config = String::from_utf8(acc1_clean())
        .unwrap()
        .replace("vtp mode transparent\n", "");
    let sum = summary_of(
        "acc1",
        config.as_bytes(),
        &acc1_sections(&[("vlans", ACC1_VLANS)]),
    );
    assert!(!sum.ports.is_empty());
    assert!(sum.ports.values().all(Option::is_some), "{:?}", sum.ports);
    assert_eq!(
        sum.ports["Port-channel1"]
            .as_ref()
            .map(|p| p.tagged.clone()),
        Some(BTreeSet::from([10, 20, 99]))
    );
    let t = twin_of(campus_plus(config.as_bytes(), &[("vlans", ACC1_VLANS)]));
    let (verdict, steps) = only(&query(
        &t,
        "dist1",
        "Port-channel1.99",
        "198.51.100.50",
        "192.0.2.1",
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    // A VLAN that is not active makes each port that carries it unknown.
    let suspended = ACC1_VLANS.replace(
        "20   VOICE                            active",
        "20   VOICE                            suspended",
    );
    let e = campus_plus(config.as_bytes(), &[("vlans", &suspended)]);
    assert!(
        e.notes["acc1"].iter().any(|n| n
            == "VLAN 20: status suspended in show vlan brief, each port that carries it unknown"),
        "{:#?}",
        e.notes["acc1"]
    );
    let (verdict, steps) = only(&query(
        &twin_of(e),
        "dist1",
        "Port-channel1.99",
        "198.51.100.50",
        "192.0.2.1",
    ));
    assert_eq!(verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(has(&steps, "acc1/port/Port-channel1/in"), "{steps:#?}");
    // In VTP mode transparent the running config holds the VLANs, and the
    // section does not change them.
    let sum = summary_of(
        "acc1",
        &acc1_clean(),
        &acc1_sections(&[("vlans", &suspended)]),
    );
    assert!(sum.ports.values().all(Option::is_some), "{:?}", sum.ports);
}

/// `show standby` of the group 1 of Vlan10 of acc1 in the state `state`,
/// with the active router `active` and the virtual MAC `vmac`.
fn standby(state: &str, active: &str, vmac: &str) -> String {
    format!(
        "Vlan10 - Group 1
  State is {state}
    2 state changes, last state change 1w2d
  Virtual IP address is 192.0.2.126
  Active virtual MAC address is {vmac} (MAC In Use)
    Local virtual MAC address is {vmac} (v1 default)
  Hello time 3 sec, hold time 10 sec
    Next hello sent in 1.264 secs
  Preemption enabled
  Active router is {active}
  Standby router is 192.0.2.2, priority 100 (expires in 9.808 sec)
  Priority 110 (configured 110)
  Group name is \"hsrp-Vl10-1\" (default)
"
    )
}

/// acc1 with the HSRP group 1 of Vlan10 and no `mac-address` line.
fn acc1_group_config() -> Vec<u8> {
    String::from_utf8(acc1_clean())
        .unwrap()
        .replace(
            " ip address 192.0.2.1 255.255.255.128\n",
            " ip address 192.0.2.1 255.255.255.128\n standby 1 ip 192.0.2.126\n",
        )
        .into_bytes()
}

#[test]
fn show_standby_gives_the_virtual_mac_of_the_active_group() {
    let text = standby("Active", "local", "0000.5e00.53a9");
    let e = campus_plus(&acc1_group_config(), &[("hsrp_detail", &text)]);
    assert!(
        !e.notes["acc1"].iter().any(|n| n.contains("HSRP group 1")),
        "{:#?}",
        e.notes["acc1"]
    );
    let t = twin_of(e);
    let (verdict, steps) = only(&query(
        &t,
        "dist1",
        "Port-channel1.99",
        "198.51.100.50",
        "192.0.2.126",
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    assert!(has(&steps, "acc1/deliver"), "{steps:#?}");
    // With the brief form only, the virtual MAC is not known.
    let brief = "Interface   Grp  Pri P State   Active          Standby         Virtual IP
Vl10        1    110 P Active  local           192.0.2.2       192.0.2.126
";
    let e = campus_plus(&acc1_group_config(), &[("hsrp", brief)]);
    assert!(
        e.notes["acc1"].iter().any(|n| n
            == "Vlan10: HSRP group 1: no mac-address line, none in show standby brief, virtual MAC not known"),
        "{:#?}",
        e.notes["acc1"]
    );
}

#[test]
fn a_contradiction_of_show_standby_makes_the_group_unknown() {
    for (text, why) in [
        (
            standby(
                "Active",
                "192.0.2.2, priority 120 (expires in 8.000 sec)",
                "0000.5e00.53a9",
            ),
            "state Active and another active router in show standby",
        ),
        (
            standby("Standby", "local", "0000.5e00.53a9"),
            "state Standby and the router itself as the active router in show standby",
        ),
    ] {
        let e = campus_plus(&acc1_group_config(), &[("hsrp_detail", &text)]);
        let note = format!("Vlan10: HSRP group 1: {why}, virtual address and MAC unknown");
        assert!(e.notes["acc1"].contains(&note), "{:#?}", e.notes["acc1"]);
    }
    let config = String::from_utf8(acc1_group_config()).unwrap().replace(
        " standby 1 ip 192.0.2.126\n",
        " standby 1 ip 192.0.2.126\n standby 1 mac-address 0000.5e00.53aa\n",
    );
    let text = standby("Active", "local", "0000.5e00.53a9");
    let e = campus_plus(config.as_bytes(), &[("hsrp_detail", &text)]);
    assert!(
        e.notes["acc1"].iter().any(|n| n.starts_with(
            "Vlan10: HSRP group 1: virtual MAC 00:00:5e:00:53:a9 in show standby, 00:00:5e:00:53:aa in the config"
        )),
        "{:#?}",
        e.notes["acc1"]
    );
}

#[test]
fn show_vrrp_gives_the_virtual_mac_of_the_master() {
    let text = "GigabitEthernet0/0/1.200 - Group 10
  State is Master
  Virtual IP address is 192.0.2.130
  Virtual MAC address is 0000.5e00.53aa
  Advertisement interval is 1.000 sec
  Preemption enabled
  Priority is 120
  Master Router is 192.0.2.129 (local), priority is 120
  Master Advertisement interval is 1.000 sec
  Master Down interval is 3.531 sec
";
    let e = routers_with(|s: &mut Sections| {
        s.insert(
            "vrrp_detail".into(),
            (text.as_bytes().to_vec(), "edge1/vrrp_detail".into()),
        );
    });
    assert!(
        !e.notes["edge1"].iter().any(|n| n.contains("VRRP group 10")),
        "{:#?}",
        e.notes["edge1"]
    );
    let t = twin_of(e);
    let (verdict, steps) = only(&query(
        &t,
        "edge1",
        "GigabitEthernet0/0/7",
        "198.51.100.40",
        "192.0.2.130",
    ));
    assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
    // The frames of the trunk pass the hand-off; the unknown part is the
    // zone-member line of the sub-interface.
    let (_, steps) = only(&query(
        &t,
        "pe3",
        "GigabitEthernet0/0/0/0.100",
        "192.0.2.20",
        "192.0.2.3",
    ));
    assert!(
        !says(&steps, "VRRP group 10 of GigabitEthernet0/0/1.200"),
        "{steps:#?}"
    );
    assert!(
        has(&steps, "edge1/in/GigabitEthernet0/0/1.100"),
        "{steps:#?}"
    );
}

#[test]
fn a_trunk_with_no_allowed_list_carries_the_vlans_of_show_vlan_brief_without_the_reserved_ones() {
    let config = String::from_utf8(acc1_clean())
        .unwrap()
        .replace("vtp mode transparent\n", "")
        .replacen(" switchport trunk allowed vlan 10,20,99\n", "", 1);
    let sum = summary_of(
        "acc1",
        config.as_bytes(),
        &acc1_sections(&[("vlans", ACC1_VLANS)]),
    );
    // The VLANs of the section and of the `vlan` lines, with no reserved
    // VLAN 1002.
    assert_eq!(
        sum.ports["Port-channel1"]
            .as_ref()
            .map(|p| p.tagged.clone()),
        Some(BTreeSet::from([10, 20, 99, 100, 200])),
        "{:?}",
        sum.ports
    );
}

#[test]
fn a_show_vrrp_that_the_template_cannot_read_leaves_the_brief_form_to_decide() {
    let v3 = "GigabitEthernet0/0/1.200 - Group 10 - Address-Family IPv4
  State is BACKUP
  State duration 1 hours 2 mins 3.456 secs
  Virtual IP address is 192.0.2.130
  Virtual MAC address is 0000.5E00.53AA
  Advertise time 1000 msec
  Preemption enabled
  Priority is 120
  Master Router is 192.0.2.131, priority is 130
  Master Advertisement interval is 1000 msec (expires in 456 msec)
  Master Down interval is unknown
  FLAGS: 0/1
";
    let e = routers_with(|s: &mut Sections| {
        s.insert(
            "vrrp_detail".into(),
            (v3.as_bytes().to_vec(), "edge1/vrrp_detail".into()),
        );
    });
    assert!(
        e.notes["edge1"]
            .iter()
            .any(|n| n.starts_with("section vrrp_detail not read")),
        "{:#?}",
        e.notes["edge1"]
    );
    let to_vip = |t: &Twin| {
        show(&query(
            t,
            "edge1",
            "GigabitEthernet0/0/7",
            "198.51.100.40",
            "192.0.2.130",
        ))
    };
    assert_eq!(to_vip(&twin_of(e)), to_vip(&twin_of(routers())));
}

#[test]
fn the_mtu_of_show_interfaces_is_the_layer_3_mtu() {
    let e = routers();
    let mtu = |device: &str, interface: &str| {
        e.mtu
            .get(&(device.to_string(), interface.to_string()))
            .map(|m| m.bytes)
    };
    assert_eq!(mtu("edge1", "GigabitEthernet0/0/0"), Some(1500));
    assert_eq!(mtu("edge1", "GigabitEthernet0/0/1.100"), Some(1500));
    assert_eq!(mtu("edge1", "Loopback0"), None, "encapsulation LOOPBACK");
    assert_eq!(mtu("pe1", "Bundle-Ether10"), Some(9202), "9216 less 14");
    assert_eq!(mtu("pe1", "Bundle-Ether20"), Some(1500), "1514 less 14");
    assert_eq!(mtu("pe1", "Bundle-Ether20.100"), Some(1500), "1518 less 18");
    assert_eq!(mtu("pe1", "GigabitEthernet0/0/0/3"), Some(1500));
    assert_eq!(mtu("pe1", "Loopback0"), None, "encapsulation Loopback");
    let m = &e.mtu[&("pe1".to_string(), "Bundle-Ether20.100".to_string())];
    assert_eq!(&*m.span.file, "pe1/interfaces");
    assert!(
        m.span.first_line <= 27 && 27 <= m.span.last_line,
        "{:?}",
        m.span
    );
}
