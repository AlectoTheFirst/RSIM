//! A vPC pair of NX-OS leaves with one shared VXLAN tunnel end, and a third
//! leaf, on synthetic configs and sections.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{Header, PROTO_TCP, VerdictKind};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::collected::{Collected, LinkRow, MacRow, NeighbourRow, RouteRow, row_span};
use rsim_ingest::estate::{Estate, Input, assemble};

/// The host on the orphan port Ethernet1/5 of vpca.
const ORPHAN: &str = "00:00:5e:00:53:20";
/// The host on Ethernet1/5 of leaf3.
const FAR: &str = "00:00:5e:00:53:30";

fn pair(name: &str, primary: &str, svi: &str, uplink: &str, vpc: bool) -> String {
    let domain = if vpc {
        "vpc domain 10\n  peer-keepalive destination 192.0.2.250\n"
    } else {
        ""
    };
    let peer_link = if vpc { "  vpc peer-link\n" } else { "" };
    format!(
        "hostname {name}
feature nv overlay
nv overlay evpn
vlan 1,10
vlan 10
  vn-segment 10010
{domain}interface nve1
  no shutdown
  host-reachability protocol bgp
  source-interface loopback1
  advertise virtual-rmac
  member vni 10010
    ingress-replication protocol bgp
interface loopback1
  ip address {primary}/32
  ip address 192.0.2.10/32 secondary
interface Vlan10
  no shutdown
  ip address {svi}/24
interface port-channel1
  switchport
  switchport mode trunk
  switchport trunk allowed vlan 10
{peer_link}  no shutdown
interface Ethernet1/53
  switchport
  switchport mode trunk
  switchport trunk allowed vlan 10
  channel-group 1 mode active
  no shutdown
interface Ethernet1/49
  no switchport
  ip address {uplink}/31
  no shutdown
interface Ethernet1/5
  switchport
  switchport access vlan 10
  no shutdown
"
    )
}

const LEAF3: &str = "hostname leaf3
feature nv overlay
nv overlay evpn
vlan 1,10
vlan 10
  vn-segment 10010
interface nve1
  no shutdown
  host-reachability protocol bgp
  source-interface loopback1
  member vni 10010
    ingress-replication protocol bgp
interface loopback1
  ip address 192.0.2.3/32
interface Vlan10
  no shutdown
  ip address 198.51.100.4/24
interface Ethernet1/49
  no switchport
  ip address 172.16.1.1/31
  no shutdown
interface Ethernet1/50
  no switchport
  ip address 172.16.2.1/31
  no shutdown
interface Ethernet1/5
  switchport
  switchport access vlan 10
  no shutdown
";

fn route(
    dev: &str,
    i: u64,
    prefix: &str,
    protocol: &str,
    gw: Option<&str>,
    iface: &str,
) -> RouteRow {
    RouteRow {
        vrf: "default".into(),
        prefix: prefix.into(),
        protocol: protocol.into(),
        selected: true,
        next_hop: gw.map(Into::into),
        interface: Some(iface.into()),
        span: row_span(dev, "routes", "b1", i),
    }
}

fn mac_row(dev: &str, mac: &str, port: &str, i: u64) -> MacRow {
    MacRow {
        vlan: 10,
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

/// The collected state of vpca (`a` true) or vpcb.
fn pair_collected(a: bool) -> Collected {
    let (d, primary, net, svi_mac, up_mac, far_up) = if a {
        (
            "vpca",
            "192.0.2.11",
            "1",
            "00:00:5e:00:53:1a",
            "00:00:5e:00:53:4a",
            "00:00:5e:00:53:4c",
        )
    } else {
        (
            "vpcb",
            "192.0.2.12",
            "2",
            "00:00:5e:00:53:1b",
            "00:00:5e:00:53:4b",
            "00:00:5e:00:53:4d",
        )
    };
    Collected {
        routes: vec![
            route(d, 0, &format!("{primary}/32"), "local", None, "loopback1"),
            route(d, 1, "192.0.2.10/32", "local", None, "loopback1"),
            route(
                d,
                2,
                "192.0.2.3/32",
                "ospf-1",
                Some(&format!("172.16.{net}.1")),
                "Ethernet1/49",
            ),
            route(
                d,
                3,
                &format!("172.16.{net}.0/31"),
                "direct",
                None,
                "Ethernet1/49",
            ),
            route(d, 4, "198.51.100.0/24", "direct", None, "Vlan10"),
        ],
        links: vec![
            link(d, "Vlan10", svi_mac, 0),
            link(d, "Ethernet1/49", up_mac, 1),
        ],
        neighbours: vec![
            arp(d, "Ethernet1/49", &format!("172.16.{net}.1"), far_up, 0),
            arp(d, "Vlan10", "198.51.100.20", ORPHAN, 1),
        ],
        macs: vec![
            mac_row(d, ORPHAN, if a { "Eth1/5" } else { "Po1" }, 0),
            mac_row(d, FAR, "nve1(192.0.2.3)", 1),
        ],
        ..Collected::default()
    }
}

fn leaf3_collected() -> Collected {
    let d = "leaf3";
    Collected {
        routes: vec![
            route(d, 0, "192.0.2.3/32", "local", None, "loopback1"),
            route(
                d,
                1,
                "192.0.2.10/32",
                "ospf-1",
                Some("172.16.1.0"),
                "Ethernet1/49",
            ),
            route(
                d,
                2,
                "192.0.2.10/32",
                "ospf-1",
                Some("172.16.2.0"),
                "Ethernet1/50",
            ),
            route(d, 3, "172.16.1.0/31", "direct", None, "Ethernet1/49"),
            route(d, 4, "172.16.2.0/31", "direct", None, "Ethernet1/50"),
            route(d, 5, "198.51.100.0/24", "direct", None, "Vlan10"),
        ],
        links: vec![
            link(d, "Vlan10", "00:00:5e:00:53:1c", 0),
            link(d, "Ethernet1/49", "00:00:5e:00:53:4c", 1),
            link(d, "Ethernet1/50", "00:00:5e:00:53:4d", 2),
        ],
        neighbours: vec![
            arp(d, "Ethernet1/49", "172.16.1.0", "00:00:5e:00:53:4a", 0),
            arp(d, "Ethernet1/50", "172.16.2.0", "00:00:5e:00:53:4b", 1),
            arp(d, "Vlan10", "198.51.100.30", FAR, 2),
        ],
        macs: vec![
            mac_row(d, FAR, "Eth1/5", 0),
            mac_row(d, ORPHAN, "nve1(192.0.2.10)", 1),
        ],
        ..Collected::default()
    }
}

fn sections(
    host: &str,
    lldp: &[(&str, &str, &str)],
    up: &[&str],
    peers: &[&str],
    vpc: bool,
) -> BTreeMap<String, (Vec<u8>, String)> {
    let rows: Vec<String> = lldp
        .iter()
        .map(|(l, n, p)| format!(r#"{{"l_port_id":"{l}","sys_name":"{n}","port_id":"{p}"}}"#))
        .collect();
    let ifs: Vec<String> = up
        .iter()
        .map(|i| format!(r#"{{"interface":"{i}","admin_state":"up","state":"up","svi_admin_state":"up","svi_line_proto":"up"}}"#))
        .collect();
    let peer_rows: Vec<String> = peers
        .iter()
        .map(|p| format!(r#"{{"if-name":"nve1","peer-ip":"{p}","peer-state":"Up"}}"#))
        .collect();
    let mut m = BTreeMap::from([
        (
            "lldp".to_string(),
            format!(r#"{{"TABLE_nbor_detail":{{"ROW_nbor_detail":[{}]}}}}"#, rows.join(",")),
        ),
        (
            "interfaces".to_string(),
            format!(r#"{{"TABLE_interface":{{"ROW_interface":[{}]}}}}"#, ifs.join(",")),
        ),
        ("version".to_string(), format!(r#"{{"host_name":"{host}"}}"#)),
        (
            "nve_peers".to_string(),
            format!(r#"{{"TABLE_nve_peers":{{"ROW_nve_peers":[{}]}}}}"#, peer_rows.join(",")),
        ),
        (
            "nve_vnis".to_string(),
            r#"{"TABLE_nve_vni":{"ROW_nve_vni":[{"if-name":"nve1","vni":"10010","vni-state":"Up"}]}}"#
                .to_string(),
        ),
    ]);
    if vpc {
        m.insert(
            "vpc".into(),
            r#"{"vpc-domain-id":"10","vpc-peer-status":"peer-ok","TABLE_peerlink":{"ROW_peerlink":[{"peerlink-ifindex":"Po1"}]}}"#.into(),
        );
    }
    m.into_iter()
        .map(|(k, v)| (k.clone(), (v.into_bytes(), format!("{host}/{k}"))))
        .collect()
}

const PAIR_UP: &[&str] = &[
    "Vlan10",
    "port-channel1",
    "Ethernet1/53",
    "Ethernet1/49",
    "Ethernet1/5",
    "loopback1",
    "nve1",
];

fn estate(vpc: bool) -> Estate {
    let mut inputs = Vec::new();
    for (a, name, primary, svi, uplink, far_port) in [
        (
            true,
            "vpca",
            "192.0.2.11",
            "198.51.100.2",
            "172.16.1.0",
            "Ethernet1/49",
        ),
        (
            false,
            "vpcb",
            "192.0.2.12",
            "198.51.100.3",
            "172.16.2.0",
            "Ethernet1/50",
        ),
    ] {
        let other = if a { "vpcb" } else { "vpca" };
        inputs.push(Input::Nxos {
            name: name.into(),
            config: pair(name, primary, svi, uplink, vpc).into_bytes(),
            file: format!("{name}/config"),
            collected: pair_collected(a),
            sections: sections(
                name,
                &[
                    ("Eth1/53", other, "Ethernet1/53"),
                    ("Eth1/49", "leaf3", far_port),
                ],
                PAIR_UP,
                &["192.0.2.3"],
                vpc,
            ),
        });
    }
    inputs.push(Input::Nxos {
        name: "leaf3".into(),
        config: LEAF3.as_bytes().to_vec(),
        file: "leaf3/config".into(),
        collected: leaf3_collected(),
        sections: sections(
            "leaf3",
            &[
                ("Eth1/49", "vpca", "Ethernet1/49"),
                ("Eth1/50", "vpcb", "Ethernet1/49"),
            ],
            &[
                "Vlan10",
                "Ethernet1/49",
                "Ethernet1/50",
                "Ethernet1/5",
                "loopback1",
                "nve1",
            ],
            &["192.0.2.10"],
            false,
        ),
    });
    assemble(inputs)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn run(t: &Twin, src: &str, dst: &str) -> Answer {
    let h = Header::request(ip(src), ip(dst), PROTO_TCP)
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
fn the_pair_lines_are_handled_and_read() {
    let e = estate(true);
    for leaf in ["vpca", "vpcb", "leaf3"] {
        let unhandled: Vec<&String> = e.coverage[leaf].unhandled.keys().collect();
        assert!(unhandled.is_empty(), "{leaf}: {unhandled:?}");
        assert!(e.unread[leaf].is_empty(), "{leaf}: {:?}", e.unread[leaf]);
    }
}

#[test]
fn the_shared_tunnel_end_is_reached_through_either_switch_of_the_pair() {
    let t = estate(true).builder.build().expect("the twin builds");
    let a = run(&t, "198.51.100.30", "198.51.100.20");
    let branches = show(&a);
    assert_eq!(branches.len(), 2, "{branches:#?}");
    for (verdict, steps) in &branches {
        assert_eq!(*verdict, VerdictKind::Deliver, "{steps:#?}");
        assert!(
            has(
                steps,
                "leaf3/vxlan/encap/192.0.2.10 VXLAN VNI 10010 from 192.0.2.3 to 192.0.2.10"
            ),
            "{steps:#?}"
        );
        assert!(has(
            steps,
            "deliver to vpca/vlan10/00:00:5e:00:53:20 on port Ethernet1/5"
        ));
    }
    assert!(
        has(&branches[0].1, "vpca/vxlan-decap VXLAN VNI 10010"),
        "{branches:#?}"
    );
    // Through vpcb, the frame crosses the peer link to the orphan port.
    assert!(
        has(&branches[1].1, "vpcb/vxlan-decap VXLAN VNI 10010"),
        "{branches:#?}"
    );
    assert!(
        has(&branches[1].1, "is on port port-channel1"),
        "{branches:#?}"
    );
    let reply = a.reply_of(0).expect("the reply ran");
    let rb = show(reply);
    assert_eq!(rb[0].0, VerdictKind::Deliver, "{rb:#?}");
    assert!(
        has(
            &rb[0].1,
            "vpca/vxlan/encap/192.0.2.3 VXLAN VNI 10010 from 192.0.2.10 to 192.0.2.3"
        ),
        "{rb:#?}"
    );
}

#[test]
fn a_secondary_source_address_with_no_vpc_domain_is_unknown() {
    let e = estate(false);
    let t = e.builder.build().expect("the twin builds");
    let a = run(&t, "198.51.100.20", "198.51.100.30");
    let branches = show(&a);
    assert_eq!(branches[0].0, VerdictKind::Unknown, "{branches:#?}");
    assert!(
        has(
            &branches[0].1,
            "has a secondary address, and the switch has no lowered vPC domain"
        ),
        "{branches:#?}"
    );
}
