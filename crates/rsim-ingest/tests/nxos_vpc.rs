//! A vPC pair of NX-OS switches with an access switch below it, on
//! synthetic configs and sections.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{FunctionId, Header, PROTO_TCP, VerdictKind};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::collected::{Collected, LinkRow, MacRow, NeighbourRow, RouteRow, row_span};
use rsim_ingest::estate::{Estate, Input, assemble};

fn leaf(name: &str, svi: &str, o: &Opts) -> String {
    let gw = if o.peer_gateway {
        "  peer-gateway\n"
    } else {
        ""
    };
    let hsrp = if o.hsrp {
        "  hsrp 10\n    ip 192.0.2.1\n"
    } else {
        ""
    };
    format!(
        "hostname {name}
vlan 1,10
vpc domain 10
  peer-keepalive destination 192.0.2.250
{gw}interface Vlan10
  no shutdown
  ip address {svi}/26
{hsrp}interface port-channel1
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

/// acc1 with a routed port channel to the pair.
const ACC1_ROUTED: &str = "hostname acc1
interface port-channel30
  no switchport
  ip address 192.0.2.50/26
  no shutdown
interface Ethernet1/1
  no switchport
  channel-group 30 mode active
  no shutdown
interface Ethernet1/2
  no switchport
  channel-group 30 mode active
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
    sections_down(host, lldp, up, &[], extra)
}

fn sections_down(
    host: &str,
    lldp: &[(&str, &str, &str)],
    up: &[&str],
    down: &[&str],
    extra: &[(&str, &str)],
) -> BTreeMap<String, (Vec<u8>, String)> {
    let rows: Vec<String> = lldp
        .iter()
        .map(|(l, n, p)| format!(r#"{{"l_port_id":"{l}","sys_name":"{n}","port_id":"{p}"}}"#))
        .collect();
    let ifs: Vec<String> = up
        .iter()
        .map(|i| (i, "up"))
        .chain(down.iter().map(|i| (i, "down")))
        .map(|(i, st)| format!(r#"{{"interface":"{i}","admin_state":"up","state":"{st}","svi_admin_state":"up","svi_line_proto":"up"}}"#))
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

/// The options of the fixture.
struct Opts {
    peer_gateway: bool,
    hsrp: bool,
    /// More MAC rows of vpcb.
    b_macs: Vec<(&'static str, &'static str)>,
    /// The interface rows of vpcb.
    b_up: Vec<&'static str>,
    /// The peer-link rows of LLDP.
    peer_link: bool,
    /// The interface rows of vpcb with the state down.
    b_down: Vec<&'static str>,
    /// True if acc1 has a routed port channel to the pair.
    acc_routed: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            peer_gateway: true,
            hsrp: true,
            b_macs: Vec::new(),
            b_up: UP.to_vec(),
            peer_link: true,
            b_down: Vec::new(),
            acc_routed: false,
        }
    }
}

fn estate() -> Estate {
    estate_with(&Opts::default())
}

fn estate_with(o: &Opts) -> Estate {
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
            arp("vpcb", "Vlan10", "192.0.2.2", "00:00:5e:00:53:1a", 2),
        ],
        macs: vec![
            mac_row("vpcb", HOST, "Po20", 0),
            mac_row("vpcb", ORPHAN, "Po1", 1),
            mac_row("vpcb", LOOPED, "Po1", 2),
        ]
        .into_iter()
        .chain(
            o.b_macs
                .iter()
                .enumerate()
                .map(|(i, (m, p))| mac_row("vpcb", m, p, 10 + u64::try_from(i).unwrap())),
        )
        .collect(),
        ..Collected::default()
    };
    let c = if o.acc_routed {
        Collected {
            routes: vec![RouteRow {
                interface: Some("port-channel30".into()),
                ..route("acc1")
            }],
            links: vec![link("acc1", "port-channel30", "00:00:5e:00:53:30")],
            neighbours: vec![arp("acc1", "port-channel30", "192.0.2.1", VMAC, 0)],
            ..Collected::default()
        }
    } else {
        Collected {
            macs: vec![
                mac_row("acc1", HOST, "Eth1/3", 0),
                mac_row("acc1", ORPHAN, "Po30", 1),
                mac_row("acc1", "00:00:0c:9f:f0:0a", "Po30", 2),
                mac_row("acc1", "00:00:5e:00:53:1a", "Po30", 3),
            ],
            ..Collected::default()
        }
    };
    let acc1 = if o.acc_routed { ACC1_ROUTED } else { ACC1 };
    let hsrp_a = hsrp("Active");
    let hsrp_b = hsrp("Standby");
    let extra_a: Vec<(&str, &str)> = if o.hsrp {
        vec![("vpc", vpc_section()), ("hsrp", hsrp_a.as_str())]
    } else {
        vec![("vpc", vpc_section())]
    };
    let extra_b: Vec<(&str, &str)> = if o.hsrp {
        vec![("vpc", vpc_section()), ("hsrp", hsrp_b.as_str())]
    } else {
        vec![("vpc", vpc_section())]
    };
    let pl_a: Vec<(&str, &str, &str)> = if o.peer_link {
        vec![
            ("Eth1/53", "vpcb", "Ethernet1/53"),
            ("Eth1/20", "acc1", "Ethernet1/1"),
        ]
    } else {
        vec![("Eth1/20", "acc1", "Ethernet1/1")]
    };
    let pl_b: Vec<(&str, &str, &str)> = if o.peer_link {
        vec![
            ("Eth1/53", "vpca", "Ethernet1/53"),
            ("Eth1/20", "acc1", "Ethernet1/2"),
        ]
    } else {
        vec![("Eth1/20", "acc1", "Ethernet1/2")]
    };
    assemble(vec![
        Input::Nxos {
            name: "vpca".into(),
            config: leaf("vpca", "192.0.2.2", o).into_bytes(),
            file: "vpca/config".into(),
            collected: a,
            sections: sections("vpca", &pl_a, UP, &extra_a),
        },
        Input::Nxos {
            name: "vpcb".into(),
            config: leaf("vpcb", "192.0.2.3", o).into_bytes(),
            file: "vpcb/config".into(),
            collected: b,
            sections: sections_down("vpcb", &pl_b, &o.b_up, &o.b_down, &extra_b),
        },
        Input::Nxos {
            name: "acc1".into(),
            config: acc1.as_bytes().to_vec(),
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
        config: leaf("vpca", "192.0.2.2", &Opts::default()).into_bytes(),
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

fn run_reply(t: &Twin, dst: &str) -> Answer {
    let h = Header::request(ip("192.0.2.40"), ip(dst), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(443);
    Executor::new(t)
        .run(&Query::path(t, &h))
        .expect("the query runs")
}

/// The run of a packet that vpcb routes into VLAN 10.
fn routed_by_b(t: &Twin, dst: &str) -> Vec<(VerdictKind, Vec<String>)> {
    let h = Header::request(ip("192.0.2.40"), ip(dst), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(443);
    let a = Executor::new(t)
        .run(
            &Query::path(t, &h)
                .with_ingress("vpcb", "Vlan10")
                .without_reply(),
        )
        .expect("the query runs");
    show(&a)
}

#[test]
fn the_pair_reports_no_false_notes_and_the_reply_comes_back() {
    let e = estate();
    for dev in ["vpca", "vpcb", "acc1"] {
        for n in e.notes.get(dev).into_iter().flatten() {
            assert!(!n.contains("does not report the link back"), "{dev}: {n}");
        }
    }
    let t = e.builder.build().expect("the twin builds");
    let a = run_reply(&t, "192.0.2.41");
    assert_eq!(a.replies.len(), 2);
    for r in &a.replies {
        let rsim_engine::ReplyResult::Ran(r) = &r.result else {
            panic!("the reply did not run");
        };
        for (verdict, steps) in show(r) {
            assert_eq!(verdict, VerdictKind::Deliver, "{steps:#?}");
            assert!(has(
                &steps,
                "deliver to acc1/vlan10/00:00:5e:00:53:c4 on port Ethernet1/3"
            ));
        }
    }
}

#[test]
fn a_frame_from_the_peer_link_to_layer_3_gives_unknown() {
    // No peer-gateway and no HSRP: vpcb has the SVI MAC of vpca on the peer
    // link, and the gateway of the host is the SVI MAC of vpca.
    let o = Opts {
        peer_gateway: false,
        hsrp: false,
        b_macs: vec![("00:00:5e:00:53:1a", "Po1")],
        ..Opts::default()
    };
    let t = estate_with(&o).builder.build().expect("the twin builds");
    let branches = show(&run(&t, "10.9.9.9"));
    let via_b = branches
        .iter()
        .find(|b| has(&b.1, "vpcb/port/port-channel20/in"))
        .expect("a branch through vpcb");
    assert_eq!(via_b.0, VerdictKind::Unknown, "{via_b:#?}");
    assert!(has(&via_b.1, "vpca/vpc/routed/Vlan10"), "{via_b:#?}");
}

#[test]
fn a_frame_that_the_standby_peer_routes_uses_the_collected_row() {
    // vpcb routes a packet to the SVI address of vpca. With peer-gateway,
    // vpcb takes the MAC of vpca at its own hand-off, but a frame that vpcb
    // routes itself goes by the collected row: the peer link.
    let o = Opts {
        b_macs: vec![("00:00:5e:00:53:1a", "Po1")],
        ..Opts::default()
    };
    let t = estate_with(&o).builder.build().expect("the twin builds");
    let branches = routed_by_b(&t, "192.0.2.2");
    assert_eq!(branches.len(), 1, "{branches:#?}");
    let (verdict, steps) = &branches[0];
    assert!(
        has(
            steps,
            "vpcb/mac-svi 00:00:5e:00:53:1a is on port port-channel1"
        ),
        "{steps:#?}"
    );
    assert!(has(steps, "vpca/vpc/routed/Vlan10"), "{steps:#?}");
    assert_eq!(*verdict, VerdictKind::Unknown);
}

#[test]
fn the_loop_avoidance_rule_follows_the_state_of_the_member_on_the_peer() {
    let others = || {
        let mut v = UP.to_vec();
        v.retain(|i| *i != "port-channel20");
        v
    };
    // The member of vPC 20 is down on vpcb: the frame from the peer link may
    // leave on the member port of vpca.
    let o = Opts {
        b_up: others(),
        b_down: vec!["port-channel20"],
        ..Opts::default()
    };
    let t = estate_with(&o).builder.build().expect("the twin builds");
    let all: Vec<String> = routed_by_b(&t, "192.0.2.43")
        .into_iter()
        .flat_map(|b| b.1)
        .collect();
    assert!(!has(&all, "vpc/loop"), "{all:#?}");
    assert!(has(&all, "vpca/port/port-channel20/out"), "{all:#?}");

    // vpcb has no state row of the member: the rule gives Unknown.
    let o = Opts {
        b_up: others(),
        ..Opts::default()
    };
    let t = estate_with(&o).builder.build().expect("the twin builds");
    let all: Vec<String> = routed_by_b(&t, "192.0.2.43")
        .into_iter()
        .flat_map(|b| b.1)
        .collect();
    assert!(has(&all, "vpca/vpc/unknown/port-channel20"), "{all:#?}");
}

#[test]
fn a_domain_id_alone_makes_no_pair() {
    let o = Opts {
        peer_link: false,
        ..Opts::default()
    };
    let e = estate_with(&o);
    assert!(
        e.notes["acc1"].contains(
            &"port-channel30: the vPC pair does not report the link back, so the port has no link"
                .to_string()
        ),
        "{:#?}",
        e.notes
    );
    e.builder.build().expect("the twin builds");
}

#[test]
fn a_routed_port_channel_to_the_pair_has_its_hand_off() {
    let o = Opts {
        acc_routed: true,
        ..Opts::default()
    };
    let t = estate_with(&o).builder.build().expect("the twin builds");
    assert!(
        t.function(&FunctionId::new("acc1/handoff/port-channel30"))
            .is_some()
    );
}
