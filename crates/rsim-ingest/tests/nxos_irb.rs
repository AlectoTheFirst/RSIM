//! Two NX-OS leaves with symmetric routing over a layer 3 VNI and an
//! anycast gateway, on synthetic configs and sections.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{Header, PROTO_TCP, VerdictKind};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::collected::{Collected, LinkRow, MacRow, NeighbourRow, RouteRow, row_span};
use rsim_ingest::estate::{Estate, Input, assemble};

const HOST1: &str = "00:00:5e:00:53:11";
const HOST2: &str = "00:00:5e:00:53:12";

/// The options of the fixture.
#[derive(Clone)]
struct Opts {
    /// The `fabric forwarding anycast-gateway-mac` line.
    anycast_line: &'static str,
    /// The VNI of the VXLAN path to the far host in the route table section
    /// of leaf1.
    segid: u32,
    /// True if leaf2 has the SVI of the layer 3 VNI.
    l3_svi: bool,
    /// The suffix of the VXLAN next hop of leaf1, for example `%default`.
    suffix: &'static str,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            anycast_line: "fabric forwarding anycast-gateway-mac 0000.5e00.5300\n",
            segid: 50001,
            l3_svi: true,
            suffix: "",
        }
    }
}

fn config(n: u8, o: &Opts) -> String {
    let link = if n == 1 { "172.16.0.0" } else { "172.16.0.1" };
    let access = if n == 1 { 10 } else { 20 };
    let l3_svi = if n == 1 || o.l3_svi {
        "interface Vlan3001\n  no shutdown\n  vrf member RED\n  ip forward\n"
    } else {
        ""
    };
    format!(
        "hostname leaf{n}
feature nv overlay
nv overlay evpn
{anycast}vlan 1,10,20,3001
vlan 10
  vn-segment 10010
vlan 20
  vn-segment 10020
vlan 3001
  vn-segment 50001
vrf context RED
  vni 50001
  rd auto
  address-family ipv4 unicast
    route-target both auto evpn
interface nve1
  no shutdown
  host-reachability protocol bgp
  source-interface loopback1
  member vni 10010
    ingress-replication protocol bgp
  member vni 10020
    ingress-replication protocol bgp
  member vni 50001 associate-vrf
interface loopback1
  ip address 192.0.2.{n}/32
interface Ethernet1/49
  no switchport
  ip address {link}/31
  no shutdown
interface Vlan10
  no shutdown
  vrf member RED
  ip address 198.51.100.1/24
  fabric forwarding mode anycast-gateway
interface Vlan20
  no shutdown
  vrf member RED
  ip address 203.0.113.1/24
  fabric forwarding mode anycast-gateway
{l3_svi}interface Ethernet1/5
  switchport
  switchport access vlan {access}
  no shutdown
evpn
  vni 10010 l2
    rd auto
router bgp 65000
  neighbor 172.16.0.{peer}
",
        anycast = o.anycast_line,
        peer = if n == 1 { 1 } else { 0 },
    )
}

fn route(
    dev: &str,
    i: u64,
    vrf: &str,
    prefix: &str,
    protocol: &str,
    gw: Option<&str>,
    iface: Option<&str>,
) -> RouteRow {
    RouteRow {
        vrf: vrf.into(),
        prefix: prefix.into(),
        protocol: protocol.into(),
        selected: true,
        next_hop: gw.map(Into::into),
        interface: iface.map(Into::into),
        span: row_span(dev, "routes", "b1", i),
    }
}

fn mac_row(dev: &str, vlan: u64, mac: &str, port: &str, i: u64) -> MacRow {
    MacRow {
        vlan,
        mac: mac.into(),
        port: Some(port.into()),
        kind: Some("dynamic".into()),
        span: row_span(dev, "mac_table", "b3", i),
    }
}

fn arp(dev: &str, iface: &str, ip: &str, mac: &str, i: u64) -> NeighbourRow {
    NeighbourRow {
        interface: iface.into(),
        ip: ip.into(),
        mac: Some(mac.into()),
        state: None,
        span: row_span(dev, "neighbours", "b2", i),
    }
}

fn link(dev: &str, iface: &str, mac: &str, i: u64) -> LinkRow {
    LinkRow {
        interface: iface.into(),
        mac: Some(mac.into()),
        parent: None,
        vlan: None,
        span: row_span(dev, "links", "b4", i),
    }
}

/// The far host and the tunnel end of leaf `n`.
fn far(n: u8) -> (&'static str, &'static str) {
    if n == 1 {
        ("203.0.113.12", "192.0.2.2")
    } else {
        ("198.51.100.11", "192.0.2.1")
    }
}

fn collected(n: u8, o: &Opts) -> Collected {
    let dev = format!("leaf{n}");
    let d = dev.as_str();
    let (local_link, peer_link) = if n == 1 {
        ("172.16.0.0", "172.16.0.1")
    } else {
        ("172.16.0.1", "172.16.0.0")
    };
    let (far_host, far_vtep) = far(n);
    let (host, host_ip, svi, vlan) = if n == 1 {
        (HOST1, "198.51.100.11", "Vlan10", 10)
    } else {
        (HOST2, "203.0.113.12", "Vlan20", 20)
    };
    Collected {
        routes: vec![
            route(
                d,
                0,
                "default",
                &format!("192.0.2.{n}/32"),
                "local",
                None,
                Some("loopback1"),
            ),
            route(
                d,
                1,
                "default",
                &format!("{far_vtep}/32"),
                "ospf-1",
                Some(peer_link),
                Some("Ethernet1/49"),
            ),
            route(
                d,
                2,
                "default",
                "172.16.0.0/31",
                "direct",
                None,
                Some("Ethernet1/49"),
            ),
            route(
                d,
                3,
                "default",
                &format!("{local_link}/32"),
                "local",
                None,
                Some("Ethernet1/49"),
            ),
            route(
                d,
                4,
                "RED",
                "198.51.100.0/24",
                "direct",
                None,
                Some("Vlan10"),
            ),
            route(
                d,
                5,
                "RED",
                "203.0.113.0/24",
                "direct",
                None,
                Some("Vlan20"),
            ),
            route(
                d,
                6,
                "RED",
                &format!("{far_host}/32"),
                "bgp-65000",
                Some(&format!("{far_vtep}{}", if n == 1 { o.suffix } else { "" })),
                None,
            ),
        ],
        links: vec![
            link(d, "Ethernet1/49", &format!("00:00:5e:00:53:4{n}"), 0),
            link(d, "Vlan10", &format!("00:00:5e:00:53:5{n}"), 1),
            link(d, "Vlan20", &format!("00:00:5e:00:53:6{n}"), 2),
            link(d, "Vlan3001", &format!("00:00:5e:00:53:7{n}"), 3),
        ],
        neighbours: vec![
            arp(
                d,
                "Ethernet1/49",
                peer_link,
                &format!("00:00:5e:00:53:4{}", 3 - n),
                0,
            ),
            arp(d, svi, host_ip, host, 1),
        ],
        macs: vec![mac_row(d, vlan, host, "Eth1/5", 0)],
        ..Collected::default()
    }
}

fn sections(n: u8, o: &Opts) -> BTreeMap<String, (Vec<u8>, String)> {
    let peer = 3 - n;
    let host = format!("leaf{n}");
    let ifs: Vec<String> = [
        "Ethernet1/49",
        "Ethernet1/5",
        "Vlan10",
        "Vlan20",
        "Vlan3001",
        "loopback1",
        "nve1",
    ]
    .iter()
    .map(|i| format!(r#"{{"interface":"{i}","admin_state":"up","state":"up","svi_admin_state":"up","svi_line_proto":"up"}}"#))
    .collect();
    let vnis: Vec<String> = [10010, 10020, 50001]
        .iter()
        .map(|v| format!(r#"{{"if-name":"nve1","vni":"{v}","vni-state":"Up"}}"#))
        .collect();
    let (far_host, far_vtep) = far(n);
    let segid = if n == 1 { o.segid } else { 50001 };
    let suffix = if n == 1 { o.suffix } else { "" };
    let rib = format!(
        r#"{{"TABLE_vrf":{{"ROW_vrf":[{{"vrf-name-out":"RED","TABLE_addrf":{{"ROW_addrf":[{{"addrf":"ipv4","TABLE_prefix":{{"ROW_prefix":[{{"ipprefix":"{far_host}/32","TABLE_path":{{"ROW_path":[{{"ipnexthop":"{far_vtep}{suffix}","clientname":"bgp-65000","ubest":"true","segid":"{segid}","encap":"vxlan"}}]}}}}]}}}}]}}}}]}}}}"#
    );
    let m = BTreeMap::from([
        (
            "interfaces".to_string(),
            format!(
                r#"{{"TABLE_interface":{{"ROW_interface":[{}]}}}}"#,
                ifs.join(",")
            ),
        ),
        (
            "lldp".to_string(),
            format!(
                r#"{{"TABLE_nbor_detail":{{"ROW_nbor_detail":[{{"l_port_id":"Eth1/49","sys_name":"leaf{peer}","port_id":"Ethernet1/49"}}]}}}}"#
            ),
        ),
        (
            "version".to_string(),
            format!(r#"{{"host_name":"{host}"}}"#),
        ),
        (
            "nve_vnis".to_string(),
            format!(
                r#"{{"TABLE_nve_vni":{{"ROW_nve_vni":[{}]}}}}"#,
                vnis.join(",")
            ),
        ),
        (
            "nve_peers".to_string(),
            format!(
                r#"{{"TABLE_nve_peers":{{"ROW_nve_peers":[{{"if-name":"nve1","peer-ip":"192.0.2.{peer}","peer-state":"Up"}}]}}}}"#
            ),
        ),
        ("rib".to_string(), rib),
    ]);
    m.into_iter()
        .map(|(k, v)| (k.clone(), (v.into_bytes(), format!("{host}/{k}"))))
        .collect()
}

fn estate(o: &Opts) -> Estate {
    assemble(
        [1u8, 2]
            .iter()
            .map(|&n| Input::Nxos {
                name: format!("leaf{n}"),
                config: config(n, o).into_bytes(),
                file: format!("leaf{n}/config"),
                collected: collected(n, o),
                sections: sections(n, o),
            })
            .collect(),
    )
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn run(t: &Twin) -> Answer {
    let h = Header::request(ip("198.51.100.11"), ip("203.0.113.12"), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(443);
    Executor::new(t)
        .run(&Query::path(t, &h))
        .expect("the query runs")
}

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

fn has(steps: &[String], text: &str) -> bool {
    steps.iter().any(|s| s.contains(text))
}

#[test]
fn the_vxlan_and_anycast_lines_are_handled_and_read() {
    let e = estate(&Opts::default());
    for leaf in ["leaf1", "leaf2"] {
        let unhandled: Vec<&String> = e.coverage[leaf].unhandled.keys().collect();
        assert!(unhandled.is_empty(), "{leaf}: {unhandled:?}");
        assert!(e.unread[leaf].is_empty(), "{leaf}: {:?}", e.unread[leaf]);
    }
}

#[test]
fn a_routed_packet_crosses_the_layer_3_vni_and_the_reply_comes_back() {
    let t = estate(&Opts::default())
        .builder
        .build()
        .expect("the twin builds");
    let a = run(&t);
    let branches = show(&a);
    assert_eq!(branches.len(), 1, "{branches:#?}");
    let (verdict, steps) = &branches[0];
    assert_eq!(*verdict, VerdictKind::Deliver, "{steps:#?}");
    for text in [
        "leaf1/host/Ethernet1/5 from 00:00:5e:00:53:11 to the gateway 00:00:5e:00:53:00",
        "leaf1/route 203.0.113.12/32 (bgp) in VRF RED via 192.0.2.2 on nve1",
        "leaf1/nexthop next hop of nve1, peer tunnel end",
        "leaf1/vxlan/encap-l3 VXLAN VNI 50001 from 192.0.2.1 to 192.0.2.2, VRF RED",
        "leaf2/vxlan-decap-l3 VXLAN VNI 50001, VRF RED",
        "leaf2/in/Vlan3001 enter leaf2 on Vlan3001",
        "leaf2/route 203.0.113.0/24 in VRF RED connected on Vlan20",
    ] {
        assert!(has(steps, text), "{text}: {steps:#?}");
    }
    let reply = a.reply_of(0).expect("the reply ran");
    let rb = show(reply);
    assert_eq!(rb[0].0, VerdictKind::Deliver, "{rb:#?}");
    assert!(
        has(&rb[0].1, "leaf1/vxlan-decap-l3 VXLAN VNI 50001, VRF RED"),
        "{rb:#?}"
    );
}

#[test]
fn a_vxlan_path_with_another_vni_is_unknown() {
    let o = Opts {
        segid: 50002,
        ..Opts::default()
    };
    let t = estate(&o).builder.build().expect("the twin builds");
    let branches = show(&run(&t));
    assert_eq!(branches[0].0, VerdictKind::Unknown, "{branches:#?}");
    assert!(
        has(
            &branches[0].1,
            "route 203.0.113.12/32 (bgp) in VRF RED, no next hop"
        ),
        "{branches:#?}"
    );
}

#[test]
fn a_layer_3_vni_with_no_svi_is_unknown_at_the_far_end() {
    let o = Opts {
        l3_svi: false,
        ..Opts::default()
    };
    let e = estate(&o);
    assert!(
        e.notes["leaf2"]
            .iter()
            .any(|n| n.contains("VNI 50001: no active SVI in VRF RED")),
        "{:?}",
        e.notes["leaf2"]
    );
    let t = e.builder.build().expect("the twin builds");
    let branches = show(&run(&t));
    assert_eq!(branches[0].0, VerdictKind::Unknown, "{branches:#?}");
    assert!(has(&branches[0].1, "leaf2/vxlan/l3/50001"), "{branches:#?}");
}

#[test]
fn an_anycast_gateway_with_no_mac_is_unknown() {
    let o = Opts {
        anycast_line: "",
        ..Opts::default()
    };
    let e = estate(&o);
    assert!(
        e.notes["leaf1"]
            .iter()
            .any(|n| n.contains("an anycast gateway with no anycast gateway MAC")),
        "{:?}",
        e.notes["leaf1"]
    );
}

#[test]
fn a_vxlan_next_hop_in_the_vrf_of_the_underlay_is_lowered() {
    let o = Opts {
        suffix: "%default",
        ..Opts::default()
    };
    let t = estate(&o).builder.build().expect("the twin builds");
    let branches = show(&run(&t));
    assert_eq!(branches[0].0, VerdictKind::Deliver, "{branches:#?}");
}
