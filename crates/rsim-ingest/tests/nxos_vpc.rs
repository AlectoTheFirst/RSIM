//! A vPC pair of NX-OS switches with an access switch below it, on
//! synthetic configs and sections.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{Header, PROTO_TCP, VerdictKind};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::collected::{Collected, LinkRow, MacRow, NeighbourRow, RouteRow, row_span};
use rsim_ingest::estate::{Estate, Input, assemble};

fn leaf(name: &str, svi: &str) -> String {
    format!(
        "hostname {name}
vlan 1,10
vpc domain 10
  peer-keepalive destination 192.0.2.250
  peer-gateway
interface Vlan10
  no shutdown
  ip address {svi}/26
  hsrp 10
    ip 192.0.2.1
interface port-channel1
  switchport
  switchport mode trunk
  switchport trunk allowed vlan 10
  vpc peer-link
  no shutdown
interface Ethernet1/53
  switchport
  switchport mode trunk
  switchport trunk allowed vlan 10
  channel-group 1 mode active
  no shutdown
interface port-channel20
  switchport
  switchport mode trunk
  switchport trunk allowed vlan 10
  vpc 20
  no shutdown
interface Ethernet1/20
  switchport
  switchport mode trunk
  switchport trunk allowed vlan 10
  channel-group 20 mode active
  no shutdown
interface Ethernet1/5
  switchport
  switchport access vlan 10
  no shutdown
"
    )
}

const ACC1: &str = "hostname acc1
vlan 1,10
interface port-channel30
  switchport
  switchport mode trunk
  switchport trunk allowed vlan 10
  no shutdown
interface Ethernet1/1
  switchport
  switchport mode trunk
  switchport trunk allowed vlan 10
  channel-group 30 mode active
  no shutdown
interface Ethernet1/2
  switchport
  switchport mode trunk
  switchport trunk allowed vlan 10
  channel-group 30 mode active
  no shutdown
interface Ethernet1/3
  switchport
  switchport access vlan 10
  no shutdown
";

const HOST: &str = "00:00:5e:00:53:c4";
const ORPHAN: &str = "00:00:5e:00:53:c5";
const LOOPED: &str = "00:00:5e:00:53:c7";
const VMAC: &str = "0000.0c9f.f00a";

fn arp(dev: &str, iface: &str, ip: &str, mac: &str, i: u64) -> NeighbourRow {
    NeighbourRow {
        interface: iface.into(),
        ip: ip.into(),
        mac: Some(mac.into()),
        state: None,
        span: row_span(dev, "neighbours", "b2", i),
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

fn link(dev: &str, iface: &str, mac: &str) -> LinkRow {
    LinkRow {
        interface: iface.into(),
        mac: Some(mac.into()),
        parent: None,
        vlan: None,
        span: row_span(dev, "links", "b4", 0),
    }
}

fn route(dev: &str) -> RouteRow {
    RouteRow {
        vrf: "default".into(),
        prefix: "192.0.2.0/26".into(),
        protocol: "direct".into(),
        selected: true,
        next_hop: None,
        interface: Some("Vlan10".into()),
        span: row_span(dev, "routes", "b1", 0),
    }
}

fn sections(
    host: &str,
    lldp: &[(&str, &str, &str)],
    up: &[&str],
    extra: &[(&str, &str)],
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
    ]);
    for (k, v) in extra {
        m.insert((*k).to_string(), (*v).to_string());
    }
    m.into_iter()
        .map(|(k, v)| (k.clone(), (v.into_bytes(), format!("{host}/{k}"))))
        .collect()
}

fn vpc_section() -> &'static str {
    r#"{"vpc-domain-id":"10","vpc-peer-status":"peer-ok","TABLE_peerlink":{"ROW_peerlink":[{"peerlink-ifindex":"Po1"}]}}"#
}

fn hsrp(state: &str) -> String {
    format!(
        r#"{{"TABLE_grp_detail":{{"ROW_grp_detail":[{{"sh_if_index":"Vlan10","sh_group_num":10,"sh_group_state":"{state}","sh_vip":"192.0.2.1","sh_vmac":"{VMAC}"}}]}}}}"#
    )
}

const UP: &[&str] = &[
    "Vlan10",
    "port-channel1",
    "Ethernet1/53",
    "port-channel20",
    "Ethernet1/20",
    "Ethernet1/5",
];

fn estate() -> Estate {
    let a = Collected {
        routes: vec![route("vpca")],
        links: vec![link("vpca", "Vlan10", "00:00:5e:00:53:1a")],
        neighbours: vec![
            arp("vpca", "Vlan10", "192.0.2.40", HOST, 0),
            arp("vpca", "Vlan10", "192.0.2.41", ORPHAN, 1),
            arp("vpca", "Vlan10", "192.0.2.43", LOOPED, 2),
        ],
        macs: vec![
            mac_row("vpca", HOST, "Po20", 0),
            mac_row("vpca", ORPHAN, "Eth1/5", 1),
            mac_row("vpca", LOOPED, "Po20", 2),
        ],
        ..Collected::default()
    };
    let b = Collected {
        routes: vec![route("vpcb")],
        links: vec![link("vpcb", "Vlan10", "00:00:5e:00:53:1b")],
        neighbours: vec![
            arp("vpcb", "Vlan10", "192.0.2.40", HOST, 0),
            arp("vpcb", "Vlan10", "192.0.2.43", LOOPED, 1),
        ],
        macs: vec![
            mac_row("vpcb", HOST, "Po20", 0),
            mac_row("vpcb", ORPHAN, "Po1", 1),
            mac_row("vpcb", LOOPED, "Po1", 2),
        ],
        ..Collected::default()
    };
    let c = Collected {
        macs: vec![
            mac_row("acc1", HOST, "Eth1/3", 0),
            mac_row("acc1", ORPHAN, "Po30", 1),
            mac_row("acc1", "00:00:0c:9f:f0:0a", "Po30", 2),
            mac_row("acc1", "00:00:5e:00:53:1a", "Po30", 3),
        ],
        ..Collected::default()
    };
    let hsrp_a = hsrp("Active");
    let hsrp_b = hsrp("Standby");
    assemble(vec![
        Input::Nxos {
            name: "vpca".into(),
            config: leaf("vpca", "192.0.2.2").into_bytes(),
            file: "vpca/config".into(),
            collected: a,
            sections: sections(
                "vpca",
                &[
                    ("Eth1/53", "vpcb", "Ethernet1/53"),
                    ("Eth1/20", "acc1", "Ethernet1/1"),
                ],
                UP,
                &[("vpc", vpc_section()), ("hsrp", &hsrp_a)],
            ),
        },
        Input::Nxos {
            name: "vpcb".into(),
            config: leaf("vpcb", "192.0.2.3").into_bytes(),
            file: "vpcb/config".into(),
            collected: b,
            sections: sections(
                "vpcb",
                &[
                    ("Eth1/53", "vpca", "Ethernet1/53"),
                    ("Eth1/20", "acc1", "Ethernet1/2"),
                ],
                UP,
                &[("vpc", vpc_section()), ("hsrp", &hsrp_b)],
            ),
        },
        Input::Nxos {
            name: "acc1".into(),
            config: ACC1.as_bytes().to_vec(),
            file: "acc1/config".into(),
            collected: c,
            sections: sections(
                "acc1",
                &[
                    ("Eth1/1", "vpca", "Ethernet1/20"),
                    ("Eth1/2", "vpcb", "Ethernet1/20"),
                ],
                &[
                    "port-channel30",
                    "Ethernet1/1",
                    "Ethernet1/2",
                    "Ethernet1/3",
                ],
                &[],
            ),
        },
    ])
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn run(t: &Twin, dst: &str) -> Answer {
    let h = Header::request(ip("192.0.2.40"), ip(dst), PROTO_TCP)
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
fn the_host_below_the_pair_is_one_endpoint() {
    let e = estate();
    let t = e.builder.build().expect("the twin builds");
    let hosts: Vec<(String, String)> = t
        .attachments()
        .iter()
        .filter(|a| a.address == ip("192.0.2.40"))
        .map(|a| (a.host.clone(), a.interface.to_string()))
        .collect();
    assert_eq!(
        hosts,
        [(
            "acc1/vlan10/00:00:5e:00:53:c4".to_string(),
            "Ethernet1/3".to_string()
        )]
    );
}

#[test]
fn the_port_channel_to_the_pair_is_a_forwarding_choice() {
    let t = estate().builder.build().expect("the twin builds");
    let a = run(&t, "192.0.2.41");
    let branches = show(&a);
    assert_eq!(branches.len(), 2, "{branches:#?}");
    for (verdict, steps) in &branches {
        assert_eq!(*verdict, VerdictKind::Deliver, "{steps:#?}");
        assert!(has(
            steps,
            "deliver to vpca/vlan10/00:00:5e:00:53:c5 on port Ethernet1/5"
        ));
    }
    // Through vpcb, the frame crosses the peer link to the orphan port.
    assert!(
        branches
            .iter()
            .any(|b| has(&b.1, "vpcb/port/port-channel1/out"))
    );
}

#[test]
fn a_frame_from_the_peer_link_does_not_leave_on_a_vpc_member_port() {
    let t = estate().builder.build().expect("the twin builds");
    // vpcb routes the packet into VLAN 10. Its MAC table has the MAC on the
    // peer link, and vpca has it on the vPC member port.
    let h = Header::request(ip("192.0.2.40"), ip("192.0.2.43"), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(443);
    let a = Executor::new(&t)
        .run(
            &Query::path(&t, &h)
                .with_ingress("vpcb", "Vlan10")
                .without_reply(),
        )
        .expect("the query runs");
    let branches = show(&a);
    assert_eq!(branches.len(), 1, "{branches:#?}");
    assert_eq!(branches[0].0, VerdictKind::Drop);
    assert!(
        has(&branches[0].1, "vpcb/port/port-channel1/out"),
        "{branches:#?}"
    );
    assert!(has(&branches[0].1, "vpca/mac-peer"), "{branches:#?}");
    assert!(
        has(&branches[0].1, "vpca/vpc/loop/port-channel20 denied"),
        "{branches:#?}"
    );
}

#[test]
fn both_peers_hand_the_virtual_mac_and_the_peer_mac_to_layer_3() {
    let t = estate().builder.build().expect("the twin builds");
    // The gateway is the virtual MAC: the active and the standby peer both
    // take it.
    let a = run(&t, "10.9.9.9");
    let branches = show(&a);
    assert_eq!(branches.len(), 2, "{branches:#?}");
    for dev in ["vpca", "vpcb"] {
        assert!(
            branches.iter().any(|b| has(
                &b.1,
                &format!("{dev}/handoff/Vlan10 untagged to {dev}/in/Vlan10")
            )),
            "{dev}: {branches:#?}"
        );
    }
    // With peer-gateway, vpcb takes the MAC of the SVI of vpca too.
    let a = run(&t, "192.0.2.2");
    let all: Vec<String> = show(&a).into_iter().flat_map(|b| b.1).collect();
    assert!(
        has(&all, "vpcb/mac 00:00:5e:00:53:1a is on port svi/Vlan10"),
        "{all:#?}"
    );
}

#[test]
fn a_vpc_domain_with_no_state_gives_unknown() {
    let mut inputs = Vec::new();
    // The same estate, with no vPC section on vpca.
    let a = Collected {
        routes: vec![route("vpca")],
        links: vec![link("vpca", "Vlan10", "00:00:5e:00:53:1a")],
        ..Collected::default()
    };
    let hsrp_a = hsrp("Active");
    inputs.push(Input::Nxos {
        name: "vpca".into(),
        config: leaf("vpca", "192.0.2.2").into_bytes(),
        file: "vpca/config".into(),
        collected: a,
        sections: sections("vpca", &[], UP, &[("hsrp", &hsrp_a)]),
    });
    let e = assemble(inputs);
    assert!(
        e.notes["vpca"].contains(&"port-channel20: the vPC domain is not known".to_string()),
        "{:#?}",
        e.notes
    );
    e.builder.build().expect("the twin builds");
}
