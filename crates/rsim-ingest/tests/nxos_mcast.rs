//! Two NX-OS leaves and a spine with a multicast underlay for the flood of
//! a layer 2 VNI, on synthetic configs and sections.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{Header, PROTO_TCP, VerdictKind};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::collected::{Collected, LinkRow, MacRow, NeighbourRow, RouteRow, row_span};
use rsim_ingest::estate::{Estate, Input, assemble};

const HOST1: &str = "00:00:5e:00:53:11";
const HOST2: &str = "00:00:5e:00:53:12";
const GROUP: &str = "233.252.0.20";

/// The options of the fixture.
#[derive(Clone, Default)]
struct Opts {
    /// The incoming interface of the (S,G) route of the spine.
    spine_iif: Option<&'static str>,
    /// True if the spine has only the (*,G) route.
    spine_star_only: bool,
}

fn leaf_config(n: u8) -> String {
    format!(
        "hostname leaf{n}
feature nv overlay
feature pim
nv overlay evpn
ip pim rp-address 192.0.2.254 group-list 233.252.0.0/24
vlan 1,10
vlan 10
  vn-segment 10010
interface nve1
  no shutdown
  host-reachability protocol bgp
  source-interface loopback1
  member vni 10010
    mcast-group {GROUP}
interface loopback1
  ip address 192.0.2.{n}/32
  ip pim sparse-mode
interface Ethernet1/49
  no switchport
  ip address 172.16.{n}.1/31
  ip pim sparse-mode
  no shutdown
interface Vlan10
  no shutdown
  ip address 198.51.100.{n}/24
interface Ethernet1/5
  switchport
  switchport access vlan 10
  no shutdown
"
    )
}

const SPINE: &str = "hostname spine
feature pim
ip pim rp-address 192.0.2.254 group-list 233.252.0.0/24
interface loopback254
  ip address 192.0.2.254/32
interface Ethernet1/1
  no switchport
  ip address 172.16.1.0/31
  ip pim sparse-mode
  no shutdown
interface Ethernet1/2
  no switchport
  ip address 172.16.2.0/31
  ip pim sparse-mode
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

fn leaf_collected(n: u8) -> Collected {
    let dev = format!("leaf{n}");
    let d = dev.as_str();
    let other = 3 - n;
    let (host, ip) = if n == 1 {
        (HOST1, "198.51.100.11")
    } else {
        (HOST2, "198.51.100.12")
    };
    Collected {
        routes: vec![
            route(d, 0, &format!("192.0.2.{n}/32"), "local", None, "loopback1"),
            route(
                d,
                1,
                &format!("192.0.2.{other}/32"),
                "ospf-1",
                Some(&format!("172.16.{n}.0")),
                "Ethernet1/49",
            ),
            route(
                d,
                2,
                &format!("172.16.{n}.0/31"),
                "direct",
                None,
                "Ethernet1/49",
            ),
            route(d, 3, "198.51.100.0/24", "direct", None, "Vlan10"),
        ],
        links: vec![
            link(d, "Ethernet1/49", &format!("00:00:5e:00:53:4{n}"), 0),
            link(d, "Vlan10", &format!("00:00:5e:00:53:5{n}"), 1),
        ],
        neighbours: vec![
            arp(
                d,
                "Ethernet1/49",
                &format!("172.16.{n}.0"),
                &format!("00:00:5e:00:53:6{n}"),
                0,
            ),
            arp(d, "Vlan10", ip, host, 1),
        ],
        macs: vec![mac_row(d, host, "Eth1/5", 0)],
        ..Collected::default()
    }
}

fn spine_collected() -> Collected {
    let d = "spine";
    Collected {
        routes: vec![
            route(
                d,
                0,
                "192.0.2.1/32",
                "ospf-1",
                Some("172.16.1.1"),
                "Ethernet1/1",
            ),
            route(
                d,
                1,
                "192.0.2.2/32",
                "ospf-1",
                Some("172.16.2.1"),
                "Ethernet1/2",
            ),
            route(d, 2, "172.16.1.0/31", "direct", None, "Ethernet1/1"),
            route(d, 3, "172.16.2.0/31", "direct", None, "Ethernet1/2"),
        ],
        links: vec![
            link(d, "Ethernet1/1", "00:00:5e:00:53:61", 0),
            link(d, "Ethernet1/2", "00:00:5e:00:53:62", 1),
        ],
        neighbours: vec![
            arp(d, "Ethernet1/1", "172.16.1.1", "00:00:5e:00:53:41", 0),
            arp(d, "Ethernet1/2", "172.16.2.1", "00:00:5e:00:53:42", 1),
        ],
        ..Collected::default()
    }
}

/// A route row of the multicast section.
fn mroute(source: &str, iif: &str, oifs: &[&str]) -> String {
    let oifs: Vec<String> = oifs
        .iter()
        .map(|o| format!(r#"{{"oif-name":"{o}"}}"#))
        .collect();
    format!(
        r#"{{"source-addr":"{source}","group-addr":"{GROUP}/32","route-iif":"{iif}","TABLE_oif":{{"ROW_oif":[{}]}}}}"#,
        oifs.join(",")
    )
}

fn sections(
    host: &str,
    lldp: &[(&str, &str, &str)],
    up: &[&str],
    mroutes: &[String],
    peer: Option<&str>,
) -> BTreeMap<String, (Vec<u8>, String)> {
    let rows: Vec<String> = lldp
        .iter()
        .map(|(l, n, p)| format!(r#"{{"l_port_id":"{l}","sys_name":"{n}","port_id":"{p}"}}"#))
        .collect();
    let ifs: Vec<String> = up
        .iter()
        .map(|i| format!(r#"{{"interface":"{i}","admin_state":"up","state":"up","svi_admin_state":"up","svi_line_proto":"up"}}"#))
        .collect();
    let mut m = BTreeMap::from([
        (
            "lldp".to_string(),
            format!(
                r#"{{"TABLE_nbor_detail":{{"ROW_nbor_detail":[{}]}}}}"#,
                rows.join(",")
            ),
        ),
        (
            "interfaces".to_string(),
            format!(
                r#"{{"TABLE_interface":{{"ROW_interface":[{}]}}}}"#,
                ifs.join(",")
            ),
        ),
        (
            "version".to_string(),
            format!(r#"{{"host_name":"{host}"}}"#),
        ),
        (
            "mroutes".to_string(),
            format!(
                r#"{{"TABLE_vrf":{{"ROW_vrf":[{{"vrf-name":"default","TABLE_one_route":{{"ROW_one_route":[{}]}}}}]}}}}"#,
                mroutes.join(",")
            ),
        ),
    ]);
    if let Some(peer) = peer {
        m.insert(
            "nve_vnis".into(),
            r#"{"TABLE_nve_vni":{"ROW_nve_vni":[{"if-name":"nve1","vni":"10010","vni-state":"Up"}]}}"#.into(),
        );
        m.insert(
            "nve_peers".into(),
            format!(
                r#"{{"TABLE_nve_peers":{{"ROW_nve_peers":[{{"if-name":"nve1","peer-ip":"{peer}","peer-state":"Up"}}]}}}}"#
            ),
        );
    }
    m.into_iter()
        .map(|(k, v)| (k.clone(), (v.into_bytes(), format!("{host}/{k}"))))
        .collect()
}

fn estate(o: &Opts) -> Estate {
    let mut inputs = Vec::new();
    for n in [1u8, 2] {
        let name = format!("leaf{n}");
        let mroutes = if n == 1 {
            vec![
                mroute("192.0.2.1", "loopback1", &["Ethernet1/49"]),
                mroute("*", "Ethernet1/49", &["nve1"]),
            ]
        } else {
            vec![
                mroute("192.0.2.1", "Ethernet1/49", &["nve1"]),
                mroute("*", "Ethernet1/49", &["nve1"]),
            ]
        };
        inputs.push(Input::Nxos {
            name: name.clone(),
            config: leaf_config(n).into_bytes(),
            file: format!("{name}/config"),
            collected: leaf_collected(n),
            sections: sections(
                &name,
                &[("Eth1/49", "spine", &format!("Ethernet1/{n}"))],
                &["Ethernet1/49", "Ethernet1/5", "Vlan10", "loopback1", "nve1"],
                &mroutes,
                Some(&format!("192.0.2.{}", 3 - n)),
            ),
        });
    }
    let mut spine_routes = Vec::new();
    if !o.spine_star_only {
        spine_routes.push(mroute(
            "192.0.2.1",
            o.spine_iif.unwrap_or("Ethernet1/1"),
            &["Ethernet1/2"],
        ));
    }
    spine_routes.push(mroute("*", "loopback254", &["Ethernet1/1", "Ethernet1/2"]));
    inputs.push(Input::Nxos {
        name: "spine".into(),
        config: SPINE.as_bytes().to_vec(),
        file: "spine/config".into(),
        collected: spine_collected(),
        sections: sections(
            "spine",
            &[
                ("Eth1/1", "leaf1", "Ethernet1/49"),
                ("Eth1/2", "leaf2", "Ethernet1/49"),
            ],
            &["Ethernet1/1", "Ethernet1/2", "loopback254"],
            &spine_routes,
            None,
        ),
    });
    assemble(inputs)
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

/// The branch of the flood copy into the tunnel.
fn tunnel_copy(branches: &[(VerdictKind, Vec<String>)]) -> &(VerdictKind, Vec<String>) {
    let found: Vec<&(VerdictKind, Vec<String>)> = branches
        .iter()
        .filter(|(_, s)| has(s, &format!("flood copy to port nve1({GROUP})")))
        .collect();
    assert_eq!(found.len(), 1, "{branches:#?}");
    found[0]
}

#[test]
fn the_multicast_lines_are_handled_or_known_irrelevant() {
    let e = estate(&Opts::default());
    for d in ["leaf1", "leaf2", "spine"] {
        let unhandled: Vec<&String> = e.coverage[d].unhandled.keys().collect();
        assert!(unhandled.is_empty(), "{d}: {unhandled:?}");
        assert!(e.unread[d].is_empty(), "{d}: {:?}", e.unread[d]);
    }
}

#[test]
fn the_flood_goes_to_the_group_and_the_spine_replicates_it_to_the_far_leaf() {
    let t = estate(&Opts::default())
        .builder
        .build()
        .expect("the twin builds");
    let branches = show(&run(&t));
    let (verdict, steps) = tunnel_copy(&branches);
    assert_eq!(*verdict, VerdictKind::Deliver, "{steps:#?}");
    for text in [
        "leaf1/vxlan/encap/233.252.0.20 VXLAN VNI 10010 from 192.0.2.1 to 233.252.0.20",
        "leaf1/vxlan/mroute (192.0.2.1, 233.252.0.20/32) in VRF default copy to Ethernet1/49",
        "spine/mroute (192.0.2.1, 233.252.0.20/32) in VRF default copy to Ethernet1/2",
        "leaf2/mroute (192.0.2.1, 233.252.0.20/32) in VRF default copy to nve1",
        "leaf2/vxlan-decap VXLAN VNI 10010",
        "deliver to leaf2/vlan10/00:00:5e:00:53:12 on port Ethernet1/5",
    ] {
        assert!(has(steps, text), "{text}: {steps:#?}");
    }
}

#[test]
fn a_reverse_path_failure_of_an_s_g_route_drops_the_copy() {
    let o = Opts {
        spine_iif: Some("Ethernet1/2"),
        ..Opts::default()
    };
    let t = estate(&o).builder.build().expect("the twin builds");
    let branches = show(&run(&t));
    let (verdict, steps) = tunnel_copy(&branches);
    assert_eq!(*verdict, VerdictKind::Drop, "{steps:#?}");
    assert!(has(steps, "the reverse path check fails"), "{steps:#?}");
}

#[test]
fn a_copy_that_only_a_shared_tree_route_matches_off_its_path_is_unknown() {
    let o = Opts {
        spine_star_only: true,
        ..Opts::default()
    };
    let t = estate(&o).builder.build().expect("the twin builds");
    let branches = show(&run(&t));
    let (verdict, steps) = tunnel_copy(&branches);
    assert_eq!(*verdict, VerdictKind::Unknown, "{steps:#?}");
    assert!(
        has(steps, "spine/mroute (*, 233.252.0.20/32)"),
        "{steps:#?}"
    );
}
