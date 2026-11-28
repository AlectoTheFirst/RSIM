//! Two NX-OS leaves with a layer 2 VNI over 2 routed links and OSPF, on
//! synthetic configs and sections, in a link-down scenario.
//!
//! | Link | leaf1 | leaf2 |
//! |---|---|---|
//! | 172.16.0.0/31 | Ethernet1/49 .0 | Ethernet1/49 .1 |
//! | 172.16.0.2/31 | Ethernet1/50 .2 | Ethernet1/50 .3 |

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{Header, PROTO_TCP, VerdictKind};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::collected::{Collected, LinkRow, MacRow, NeighbourRow, RouteRow, row_span};
use rsim_ingest::estate::{Input, assemble, assemble_scenario};
use rsim_ingest::scenario::Layer;

const HOST1: &str = "00:00:5e:00:53:11";
const HOST2: &str = "00:00:5e:00:53:12";

/// The MAC of the routed port `Ethernet1/<port>` of leaf `n`.
fn port_mac(n: u8, port: u8) -> String {
    let p = if port == 49 { 4 } else { 5 };
    format!("00:00:5e:00:53:{p}{n}")
}

/// The MAC of the SVI Vlan10 of leaf `n`.
fn svi_mac(n: u8) -> String {
    format!("00:00:5e:00:53:2{n}")
}

/// The address of leaf `n` on the link of `Ethernet1/<port>`.
fn link_addr(n: u8, port: u8) -> String {
    let base = if port == 49 { 0 } else { 2 };
    format!("172.16.0.{}", base + n - 1)
}

fn config(n: u8) -> String {
    let peer = 3 - n;
    let mut ports = String::new();
    for port in [49, 50] {
        ports.push_str(&format!(
            "interface Ethernet1/{port}\n  no switchport\n  ip address {}/31\n  ip ospf network point-to-point\n  ip ospf cost 10\n  ip router ospf 1 area 0.0.0.0\n  no shutdown\n",
            link_addr(n, port)
        ));
    }
    format!(
        "hostname leaf{n}
feature ospf
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
  ip address 192.0.2.{n}/32
  ip router ospf 1 area 0.0.0.0
{ports}interface Vlan10
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
router ospf 1
  router-id 192.0.2.{n}
router bgp 65000
  neighbor 192.0.2.{peer}
"
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

fn collected(n: u8) -> Collected {
    let dev = format!("leaf{n}");
    let d = dev.as_str();
    let peer = 3 - n;
    let (local_host, remote_host) = if n == 1 {
        (HOST1, HOST2)
    } else {
        (HOST2, HOST1)
    };
    let mut routes = vec![
        route(d, 0, &format!("192.0.2.{n}/32"), "local", None, "loopback1"),
        route(d, 1, "198.51.100.0/24", "direct", None, "Vlan10"),
        route(d, 2, &format!("198.51.100.{n}/32"), "local", None, "Vlan10"),
    ];
    let mut links = vec![LinkRow {
        interface: "Vlan10".into(),
        mac: Some(svi_mac(n)),
        parent: None,
        vlan: None,
        span: row_span(d, "links", "b4", 0),
    }];
    let mut neighbours = Vec::new();
    for port in [49u8, 50] {
        let iface = format!("Ethernet1/{port}");
        let net = format!("{}/31", link_addr(1, port));
        let i = routes.len() as u64;
        routes.push(route(d, i, &net, "direct", None, &iface));
        routes.push(route(
            d,
            i + 1,
            &format!("{}/32", link_addr(n, port)),
            "local",
            None,
            &iface,
        ));
        routes.push(route(
            d,
            i + 2,
            &format!("192.0.2.{peer}/32"),
            "ospf-1",
            Some(&link_addr(peer, port)),
            &iface,
        ));
        links.push(LinkRow {
            interface: iface.clone(),
            mac: Some(port_mac(n, port)),
            parent: None,
            vlan: None,
            span: row_span(d, "links", "b4", u64::from(port)),
        });
        neighbours.push(NeighbourRow {
            interface: iface,
            ip: link_addr(peer, port),
            mac: Some(port_mac(peer, port)),
            state: None,
            span: row_span(d, "neighbours", "b2", u64::from(port)),
        });
    }
    for (i, (ip, mac)) in [("198.51.100.11", HOST1), ("198.51.100.12", HOST2)]
        .into_iter()
        .enumerate()
    {
        neighbours.push(NeighbourRow {
            interface: "Vlan10".into(),
            ip: ip.into(),
            mac: Some(mac.into()),
            state: None,
            span: row_span(d, "neighbours", "b2", i as u64),
        });
    }
    let mac_row = |mac: &str, port: &str, i: u64| MacRow {
        vlan: 10,
        mac: mac.into(),
        port: Some(port.into()),
        kind: Some("dynamic".into()),
        span: row_span(d, "mac_table", "b3", i),
    };
    Collected {
        routes,
        links,
        neighbours,
        macs: vec![
            mac_row(local_host, "Eth1/5", 0),
            mac_row(remote_host, &format!("nve1(192.0.2.{peer})"), 1),
        ],
        ..Collected::default()
    }
}

fn sections(n: u8) -> BTreeMap<String, (Vec<u8>, String)> {
    let peer = 3 - n;
    let host = format!("leaf{n}");
    let ifs: Vec<String> = [
        "Ethernet1/49",
        "Ethernet1/50",
        "Ethernet1/5",
        "Vlan10",
        "loopback1",
        "nve1",
    ]
    .iter()
    .map(|i| format!(r#"{{"interface":"{i}","admin_state":"up","state":"up","svi_admin_state":"up","svi_line_proto":"up"}}"#))
    .collect();
    let lldp: Vec<String> = [49, 50]
        .iter()
        .map(|p| {
            format!(
                r#"{{"l_port_id":"Eth1/{p}","sys_name":"leaf{peer}","port_id":"Ethernet1/{p}"}}"#
            )
        })
        .collect();
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
                r#"{{"TABLE_nbor_detail":{{"ROW_nbor_detail":[{}]}}}}"#,
                lldp.join(",")
            ),
        ),
        ("version".to_string(), format!(r#"{{"host_name":"{host}"}}"#)),
        (
            "nve_vnis".to_string(),
            r#"{"TABLE_nve_vni":{"ROW_nve_vni":[{"if-name":"nve1","vni":"10010","vni-state":"Up","type":"L2 [10]"}]}}"#.to_string(),
        ),
        (
            "nve_peers".to_string(),
            format!(
                r#"{{"TABLE_nve_peers":{{"ROW_nve_peers":[{{"if-name":"nve1","peer-ip":"192.0.2.{peer}","peer-state":"Up"}}]}}}}"#
            ),
        ),
    ]);
    m.into_iter()
        .map(|(k, v)| (k.clone(), (v.into_bytes(), format!("{host}/{k}"))))
        .collect()
}

fn inputs() -> Vec<Input> {
    [1u8, 2]
        .iter()
        .map(|&n| Input::Nxos {
            name: format!("leaf{n}"),
            config: config(n).into_bytes(),
            file: format!("leaf{n}/config"),
            collected: collected(n),
            sections: sections(n),
        })
        .collect()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn run(t: &Twin) -> Answer {
    let h = Header::request(ip("198.51.100.11"), ip("198.51.100.12"), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(443);
    Executor::new(t)
        .run(&Query::path(t, &h).without_reply())
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
fn the_underlay_route_with_2_uplinks_matches_its_computed_route_in_the_base() {
    let e = assemble(inputs());
    let p: rsim_core::Prefix = "192.0.2.2/32".parse().unwrap();
    let row = e.guard["leaf1"]
        .iter()
        .find(|r| r.prefix == p)
        .expect("a guard row of the tunnel end of leaf2");
    assert_eq!(row.category, rsim_guard::Category::Match, "{row:?}");
    let t = e.builder.build().expect("the twin builds");
    let branches = show(&run(&t));
    assert!(
        branches
            .iter()
            .any(|(_, s)| has(s, "leaf1/vxlan/route 192.0.2.2/32")),
        "{branches:#?}"
    );
}

#[test]
fn a_tunnel_route_takes_the_other_uplink_when_a_layer_takes_one_down() {
    let layers = [Layer::link_down("leaf1:Ethernet1/49").unwrap()];
    let e = assemble_scenario(inputs(), &BTreeMap::new(), &layers).expect("the scenario builds");
    let t = e.builder.build().expect("the twin builds");
    let branches = show(&run(&t));
    assert_eq!(branches.len(), 1, "{branches:#?}");
    let (verdict, steps) = &branches[0];
    assert_eq!(*verdict, VerdictKind::Deliver, "{steps:#?}");
    assert!(
        has(
            steps,
            "leaf1/vxlan/route 192.0.2.2/32 (ospf) in VRF default via 172.16.0.3 on Ethernet1/50"
        ),
        "{steps:#?}"
    );
    assert!(!has(steps, "Ethernet1/49"), "{steps:#?}");
    assert!(has(
        steps,
        "leaf2/mac-tunnel 00:00:5e:00:53:12 on port Ethernet1/5"
    ));
}
