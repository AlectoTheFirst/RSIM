//! Two NX-OS leaves with a layer 2 VNI over a routed link, on synthetic
//! configs and sections.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{Header, PROTO_TCP, VerdictKind};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::collected::{Collected, LinkRow, MacRow, NeighbourRow, RouteRow, row_span};
use rsim_ingest::estate::{Estate, Input, assemble};

const HOST1: &str = "00:00:5e:00:53:11";
const HOST2: &str = "00:00:5e:00:53:12";

/// The MAC of the routed port Ethernet1/49 of leaf `n`.
fn uplink_mac(n: u8) -> String {
    format!("00:00:5e:00:53:4{n}")
}

/// The MAC of the SVI Vlan10 of leaf `n`.
fn svi_mac(n: u8) -> String {
    format!("00:00:5e:00:53:1{}", n + 4)
}

/// The options of the fixture.
#[derive(Clone)]
struct Opts {
    /// The `member vni` block of the NVE interface.
    member: &'static str,
    /// More lines of the NVE interface.
    nve_extra: &'static str,
    /// The NVE peer section of leaf1, or `None` for no section.
    peers: Option<&'static str>,
    /// The state of the VNI in the NVE VNI section of leaf1.
    vni_state: &'static str,
    /// True if the MAC table of leaf1 has host2.
    leaf1_knows_host2: bool,
    /// More lines of Ethernet1/49 of leaf1.
    uplink_extra: &'static str,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            member: "  member vni 10010\n    ingress-replication protocol bgp\n",
            nve_extra: "",
            peers: Some("Up"),
            vni_state: "Up",
            leaf1_knows_host2: true,
            uplink_extra: "",
        }
    }
}

fn config(n: u8, o: &Opts) -> String {
    let link = if n == 1 { "172.16.0.0" } else { "172.16.0.1" };
    format!(
        "hostname leaf{n}
feature nv overlay
nv overlay evpn
vlan 1,10
vlan 10
  vn-segment 10010
interface nve1
  no shutdown
  host-reachability protocol bgp
  source-interface loopback1
{extra}{member}interface loopback1
  ip address 192.0.2.{n}/32
interface Ethernet1/49
  no switchport
  ip address {link}/31
{uplink}  no shutdown
interface Vlan10
  no shutdown
  ip address 198.51.100.{n}/24
interface Ethernet1/5
  switchport
  switchport access vlan 10
  no shutdown
evpn
  vni 10010 l2
    rd auto
    route-target import auto
router bgp 65000
  neighbor 172.16.0.{peer}
",
        extra = o.nve_extra,
        uplink = if n == 1 { o.uplink_extra } else { "" },
        member = o.member,
        peer = if n == 1 { 1 } else { 0 },
    )
}

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

fn collected(n: u8, o: &Opts) -> Collected {
    let dev = format!("leaf{n}");
    let d = dev.as_str();
    let (me, peer) = (n, 3 - n);
    let (local_link, peer_link) = if n == 1 {
        ("172.16.0.0", "172.16.0.1")
    } else {
        ("172.16.0.1", "172.16.0.0")
    };
    let (local_host, remote_host) = if n == 1 {
        (HOST1, HOST2)
    } else {
        (HOST2, HOST1)
    };
    Collected {
        routes: vec![
            route(
                d,
                0,
                &format!("192.0.2.{me}/32"),
                "local",
                None,
                "loopback1",
            ),
            route(
                d,
                1,
                &format!("192.0.2.{peer}/32"),
                "ospf-1",
                Some(peer_link),
                "Ethernet1/49",
            ),
            route(d, 2, "172.16.0.0/31", "direct", None, "Ethernet1/49"),
            route(
                d,
                3,
                &format!("{local_link}/32"),
                "local",
                None,
                "Ethernet1/49",
            ),
            route(d, 4, "198.51.100.0/24", "direct", None, "Vlan10"),
        ],
        links: vec![
            link(d, "Ethernet1/49", &uplink_mac(n), 0),
            link(d, "Vlan10", &svi_mac(n), 1),
        ],
        neighbours: vec![
            arp(d, "Ethernet1/49", peer_link, &uplink_mac(3 - n), 0),
            arp(d, "Vlan10", "198.51.100.11", HOST1, 1),
            arp(d, "Vlan10", "198.51.100.12", HOST2, 2),
        ],
        macs: [
            Some(mac_row(d, local_host, "Eth1/5", 0)),
            (n == 2 || o.leaf1_knows_host2)
                .then(|| mac_row(d, remote_host, &format!("nve1(192.0.2.{peer})"), 1)),
        ]
        .into_iter()
        .flatten()
        .collect(),
        ..Collected::default()
    }
}

fn sections(n: u8, o: &Opts) -> BTreeMap<String, (Vec<u8>, String)> {
    let peer = 3 - n;
    let host = format!("leaf{n}");
    let ifs: Vec<String> = ["Ethernet1/49", "Ethernet1/5", "Vlan10", "loopback1", "nve1"]
        .iter()
        .map(|i| format!(r#"{{"interface":"{i}","admin_state":"up","state":"up","svi_admin_state":"up","svi_line_proto":"up"}}"#))
        .collect();
    let mut m = BTreeMap::from([
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
    ]);
    let state = if n == 1 { o.vni_state } else { "Up" };
    m.insert(
        "nve_vnis".into(),
        format!(
            r#"{{"TABLE_nve_vni":{{"ROW_nve_vni":[{{"if-name":"nve1","vni":"10010","vni-state":"{state}","type":"L2 [10]"}}]}}}}"#
        ),
    );
    let peers = if n == 1 { o.peers } else { Some("Up") };
    if let Some(p) = peers {
        m.insert(
            "nve_peers".into(),
            format!(
                r#"{{"TABLE_nve_peers":{{"ROW_nve_peers":[{{"if-name":"nve1","peer-ip":"192.0.2.{peer}","peer-state":"{p}"}}]}}}}"#
            ),
        );
    }
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
fn the_vxlan_lines_are_handled_and_read() {
    let e = estate(&Opts::default());
    for leaf in ["leaf1", "leaf2"] {
        let c = &e.coverage[leaf];
        let unhandled: Vec<&String> = c.unhandled.keys().collect();
        assert!(unhandled.is_empty(), "{leaf}: {unhandled:?}");
        assert!(e.unread[leaf].is_empty(), "{leaf}: {:?}", e.unread[leaf]);
    }
}

#[test]
fn a_frame_to_a_remote_mac_crosses_the_tunnel_and_the_reply_comes_back() {
    let t = estate(&Opts::default())
        .builder
        .build()
        .expect("the twin builds");
    let a = run(&t, "198.51.100.11", "198.51.100.12");
    let branches = show(&a);
    assert_eq!(branches.len(), 1, "{branches:#?}");
    let (verdict, steps) = &branches[0];
    assert_eq!(*verdict, VerdictKind::Deliver, "{steps:#?}");
    for text in [
        "leaf1/mac 00:00:5e:00:53:12 is on port nve1(192.0.2.2)",
        "leaf1/vxlan/encap/192.0.2.2 VXLAN VNI 10010 from 192.0.2.1 to 192.0.2.2",
        "leaf1/vxlan/route 192.0.2.2/32 in VRF default via 172.16.0.1 on Ethernet1/49",
        "leaf2/vxlan-decap VXLAN VNI 10010 · bridge domain leaf2/vlan10",
        "leaf2/mac-tunnel 00:00:5e:00:53:12 is on port Ethernet1/5",
    ] {
        assert!(has(steps, text), "{text}: {steps:#?}");
    }
    let reply = a.reply_of(0).expect("the reply ran");
    assert_eq!(
        reply.verdict().map(rsim_core::Verdict::kind),
        Some(VerdictKind::Deliver),
        "{:#?}",
        show(reply)
    );
    assert!(has(
        &show(reply)[0].1,
        "leaf2/vxlan/encap/192.0.2.1 VXLAN VNI 10010 from 192.0.2.2 to 192.0.2.1"
    ));
}

#[test]
fn the_flood_copies_into_the_tunnel_and_the_far_end_does_not_send_it_back() {
    let o = Opts {
        leaf1_knows_host2: false,
        ..Opts::default()
    };
    let t = estate(&o).builder.build().expect("the twin builds");
    let a = run(&t, "198.51.100.11", "198.51.100.12");
    let branches = show(&a);
    let tunnel: Vec<&(VerdictKind, Vec<String>)> = branches
        .iter()
        .filter(|(_, s)| has(s, "flood copy to port nve1(192.0.2.2)"))
        .collect();
    assert_eq!(tunnel.len(), 1, "{branches:#?}");
    let (verdict, steps) = tunnel[0];
    assert_eq!(*verdict, VerdictKind::Deliver, "{steps:#?}");
    assert!(has(steps, "leaf2/vxlan-decap"), "{steps:#?}");
    // A frame out of the tunnel never floods back into it.
    let flood = t
        .function(&rsim_core::FunctionId::new("leaf2/flood-tunnel"))
        .expect("the flood of the tunnel");
    let next: Vec<String> = flood.successors().iter().map(ToString::to_string).collect();
    assert!(!next.is_empty(), "{next:?}");
    assert!(next.iter().all(|f| !f.contains("vxlan/encap")), "{next:?}");
    let mac = t
        .function(&rsim_core::FunctionId::new("leaf2/mac-tunnel"))
        .expect("the MAC lookup of the tunnel");
    assert!(
        mac.successors()
            .iter()
            .all(|f| !f.as_str().contains("vxlan/encap")),
        "{:?}",
        mac.successors()
    );
}

#[test]
fn a_tunnel_end_with_an_option_that_is_not_lowered_is_unknown() {
    let o = Opts {
        nve_extra: "  source-interface hold-down-time 30\n",
        ..Opts::default()
    };
    let e = estate(&o);
    let t = e.builder.build().expect("the twin builds");
    let a = run(&t, "198.51.100.11", "198.51.100.12");
    let branches = show(&a);
    assert_eq!(branches[0].0, VerdictKind::Unknown, "{branches:#?}");
    assert!(
        has(&branches[0].1, "source-interface hold-down-time 30"),
        "{branches:#?}"
    );
}

#[test]
fn with_no_peer_section_the_flood_into_the_tunnel_is_unknown() {
    let o = Opts {
        peers: None,
        leaf1_knows_host2: false,
        ..Opts::default()
    };
    let t = estate(&o).builder.build().expect("the twin builds");
    let a = run(&t, "198.51.100.11", "198.51.100.12");
    let branches = show(&a);
    assert!(
        branches
            .iter()
            .any(|(v, s)| *v == VerdictKind::Unknown && has(s, "no NVE peer section")),
        "{branches:#?}"
    );
    // A known MAC still crosses the tunnel.
    let o = Opts {
        peers: None,
        ..Opts::default()
    };
    let t = estate(&o).builder.build().expect("the twin builds");
    let a = run(&t, "198.51.100.11", "198.51.100.12");
    assert_eq!(show(&a)[0].0, VerdictKind::Deliver);
}

#[test]
fn a_vni_that_is_down_has_no_tunnel() {
    let o = Opts {
        vni_state: "Down",
        ..Opts::default()
    };
    let e = estate(&o);
    assert!(
        e.notes["leaf1"]
            .iter()
            .any(|n| n.contains("VNI 10010: the collected state is not up")),
        "{:?}",
        e.notes["leaf1"]
    );
    let t = e.builder.build().expect("the twin builds");
    let a = run(&t, "198.51.100.11", "198.51.100.12");
    let branches = show(&a);
    assert_eq!(branches[0].0, VerdictKind::Unknown, "{branches:#?}");
}

#[test]
fn a_peer_with_a_state_that_is_not_read_makes_the_flood_unknown() {
    let o = Opts {
        peers: Some("Init"),
        leaf1_knows_host2: false,
        ..Opts::default()
    };
    let t = estate(&o).builder.build().expect("the twin builds");
    let a = run(&t, "198.51.100.11", "198.51.100.12");
    let branches = show(&a);
    assert!(
        branches.iter().any(|(v, s)| *v == VerdictKind::Unknown
            && has(s, "the state of the NVE peer 192.0.2.2 is not known")),
        "{branches:#?}"
    );
}

#[test]
fn an_output_acl_on_the_egress_of_the_outer_header_is_unknown() {
    let o = Opts {
        uplink_extra: "  ip access-group FABRIC out\n",
        ..Opts::default()
    };
    let t = estate(&o).builder.build().expect("the twin builds");
    let a = run(&t, "198.51.100.11", "198.51.100.12");
    let branches = show(&a);
    assert_eq!(branches[0].0, VerdictKind::Unknown, "{branches:#?}");
    assert!(
        has(&branches[0].1, "leaf1/vxlan/acl-out/Ethernet1/49"),
        "{branches:#?}"
    );
}
