//! 2 NX-OS switches at 2 sites, each bound to a Fabric port of an Equinix
//! account, with a circuit from VLAN 100 at the first site to VLAN 200 at
//! the second site, on synthetic configs and sections.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{Header, PROTO_TCP, Verdict, VerdictKind};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::collected::{Collected, LinkRow, MacRow, NeighbourRow, RouteRow, row_span};
use rsim_ingest::estate::{Estate, Input, assemble};
use serde_json::json;

const ACCT: &str = "equinix-lab";
const H1: &str = "00:00:5e:00:53:a1";
const H2: &str = "00:00:5e:00:53:a2";

fn switch(name: &str, vlan: u16, svi: &str) -> String {
    format!(
        "hostname {name}
vlan 1,{vlan}
interface Vlan{vlan}
  no shutdown
  ip address {svi}/24
interface Ethernet1/49
  switchport
  switchport mode trunk
  switchport trunk allowed vlan {vlan}
  no shutdown
interface Ethernet1/5
  switchport
  switchport access vlan {vlan}
  no shutdown
"
    )
}

fn mac_row(dev: &str, vlan: u16, mac: &str, port: &str, i: u64) -> MacRow {
    MacRow {
        vlan: vlan.into(),
        mac: mac.into(),
        port: Some(port.into()),
        kind: Some("dynamic".into()),
        span: row_span(dev, "mac_table", "b3", i),
    }
}

/// The collected state of a switch: the connected route of its SVI, the
/// MAC of the SVI, and the ARP rows and the MAC rows of both hosts.
fn collected(dev: &str, vlan: u16, host: (&str, &str), far: (&str, &str)) -> Collected {
    let svi = format!("Vlan{vlan}");
    Collected {
        routes: vec![RouteRow {
            vrf: "default".into(),
            prefix: "192.0.2.0/24".into(),
            protocol: "direct".into(),
            selected: true,
            next_hop: None,
            interface: Some(svi.clone()),
            span: row_span(dev, "routes", "b1", 0),
        }],
        links: vec![LinkRow {
            interface: svi.clone(),
            mac: Some(if vlan == 100 {
                "00:00:5e:00:53:01".into()
            } else {
                "00:00:5e:00:53:02".into()
            }),
            parent: None,
            vlan: None,
            span: row_span(dev, "links", "b4", 0),
        }],
        neighbours: [host, far]
            .iter()
            .zip(0u64..)
            .map(|((ip, mac), i)| NeighbourRow {
                interface: svi.clone(),
                ip: (*ip).into(),
                mac: Some((*mac).into()),
                state: None,
                span: row_span(dev, "neighbours", "b2", i),
            })
            .collect(),
        macs: vec![
            mac_row(dev, vlan, host.1, "Eth1/5", 0),
            mac_row(dev, vlan, far.1, "Eth1/49", 1),
        ],
        ..Collected::default()
    }
}

fn sections(host: &str, vlan: u16) -> BTreeMap<String, (Vec<u8>, String)> {
    let ifs: Vec<String> = [format!("Vlan{vlan}"), "Ethernet1/49".into(), "Ethernet1/5".into()]
        .iter()
        .map(|i| {
            format!(
                r#"{{"interface":"{i}","admin_state":"up","state":"up","svi_admin_state":"up","svi_line_proto":"up"}}"#
            )
        })
        .collect();
    BTreeMap::from([
        (
            "lldp".to_string(),
            r#"{"TABLE_nbor_detail":{"ROW_nbor_detail":[]}}"#.to_string(),
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
    ])
    .into_iter()
    .map(|(k, v)| (k.clone(), (v.into_bytes(), format!("{host}/{k}"))))
    .collect()
}

fn account() -> BTreeMap<String, (Vec<u8>, String)> {
    let port = |uuid: &str| {
        json!({"uuid": uuid, "name": format!("lab-{uuid}"), "state": "ACTIVE",
               "encapsulation": {"type": "DOT1Q"}})
    };
    let colo = |p: &str, tag: u16| {
        json!({"accessPoint": {"type": "COLO", "port": {"uuid": p},
               "linkProtocol": {"type": "DOT1Q", "vlanTag": tag}}})
    };
    [
        ("ports", json!([port("p1"), port("p2")])),
        (
            "connections",
            json!([{"uuid": "c1", "type": "EVPL_VC", "state": "ACTIVE",
                    "aSide": colo("p1", 100), "zSide": colo("p2", 200)}]),
        ),
        (
            "bindings",
            json!([
                {"fabric_port": "p1", "device": "sw-a", "port": "Ethernet1/49"},
                {"fabric_port": "lab-p2", "device": "sw-b", "port": "Ethernet1/49"},
            ]),
        ),
    ]
    .into_iter()
    .map(|(k, v)| {
        (
            k.to_string(),
            (
                serde_json::to_vec_pretty(&v).unwrap(),
                format!("{ACCT}/{k}@b1"),
            ),
        )
    })
    .collect()
}

fn estate() -> Estate {
    assemble(vec![
        Input::Nxos {
            name: "sw-a".into(),
            config: switch("sw-a", 100, "192.0.2.1").into_bytes(),
            file: "sw-a/config".into(),
            collected: collected("sw-a", 100, ("192.0.2.10", H1), ("192.0.2.20", H2)),
            sections: sections("sw-a", 100),
        },
        Input::Nxos {
            name: "sw-b".into(),
            config: switch("sw-b", 200, "192.0.2.2").into_bytes(),
            file: "sw-b/config".into(),
            collected: collected("sw-b", 200, ("192.0.2.20", H2), ("192.0.2.10", H1)),
            sections: sections("sw-b", 200),
        },
        Input::Equinix {
            name: ACCT.into(),
            sections: account(),
        },
    ])
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn run(t: &Twin, src: &str, dst: &str) -> Answer {
    let h = Header::request(ip(src), ip(dst), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(443);
    Executor::new(t)
        .run(&Query::path(t, &h).without_reply())
        .expect("the query runs")
}

fn steps(a: &Answer) -> Vec<String> {
    a.branches()
        .iter()
        .flat_map(|b| {
            b.steps
                .iter()
                .map(|s| format!("{} {}", s.function, s.reason.detail))
        })
        .collect()
}

#[test]
fn a_path_crosses_the_circuit_with_the_tag_of_each_site_in_both_directions() {
    let t = estate().builder.build().expect("the twin builds");
    for (src, dst, from, to) in [
        ("192.0.2.10", "192.0.2.20", "p1 VLAN 100", "p2 VLAN 200"),
        ("192.0.2.20", "192.0.2.10", "p2 VLAN 200", "p1 VLAN 100"),
    ] {
        let a = run(&t, src, dst);
        let s = steps(&a);
        assert!(
            matches!(a.verdict(), Some(Verdict::Deliver(_))),
            "{src} to {dst}: {:?} {s:#?}",
            a.verdict()
        );
        assert!(
            s.iter()
                .any(|x| x.contains(&format!("from port port/{from} to port port/{to}"))),
            "{s:#?}"
        );
        assert_eq!(
            a.branches()
                .iter()
                .map(|b| b.verdict.kind())
                .collect::<Vec<_>>(),
            [VerdictKind::Deliver]
        );
    }
}

#[test]
fn the_bound_ports_are_not_edge_ports_and_the_twin_is_the_same_from_2_runs() {
    let one = estate();
    let two = estate();
    assert_eq!(one.notes, two.notes);
    assert!(
        one.notes.get(ACCT).is_none_or(Vec::is_empty),
        "{:?}",
        one.notes.get(ACCT)
    );
    let t = one.builder.build().expect("the twin builds");
    let hosts: Vec<(String, String)> = t
        .attachments()
        .iter()
        .map(|a| (a.address.to_string(), a.interface.to_string()))
        .collect();
    assert!(
        hosts.contains(&("192.0.2.10".into(), "Ethernet1/5".into())),
        "{hosts:?}"
    );
    assert!(
        hosts.contains(&("192.0.2.20".into(), "Ethernet1/5".into())),
        "{hosts:?}"
    );
    assert!(!hosts.iter().any(|(_, i)| i == "Ethernet1/49"), "{hosts:?}");
    let fabric = &one.fabric[ACCT];
    assert_eq!(fabric.len(), 1);
    assert_eq!(fabric[0].verdict, rsim_ingest::equinix::Verdict::Lowered);
}

const NE_MAC: &str = "00:00:5e:00:53:31";
const NE: &str = "bbbbbbbb-0000-4000-8000-0000000000f1";

/// An account with the Fabric port `p1` bound to `sw-a` and a circuit from
/// VLAN 100 on `p1` to the interface `eth0` of the Network Edge device
/// `lab-fw`, which no binding names.
fn edge_account() -> BTreeMap<String, (Vec<u8>, String)> {
    [
        (
            "ports",
            json!([{"uuid": "p1", "name": "lab-p1", "state": "ACTIVE",
                    "encapsulation": {"type": "DOT1Q"}}]),
        ),
        ("connections", json!([])),
        (
            "edge_devices",
            json!([{"uuid": NE, "name": "lab-fw", "status": "PROVISIONED",
                    "interfaces": [{"id": 1, "name": "eth0", "type": "DATA",
                                    "macAddress": NE_MAC}]}]),
        ),
        ("edge_links", json!([])),
        (
            "edge_connections",
            json!([{"uuid": "c-ne", "type": "EVPL_VC", "state": "ACTIVE",
                    "aSide": {"accessPoint": {"type": "COLO", "port": {"uuid": "p1"},
                              "linkProtocol": {"type": "DOT1Q", "vlanTag": 100}}},
                    "zSide": {"accessPoint": {"type": "VD", "interface": {"id": 1},
                              "virtualDevice": {"uuid": NE}}}}]),
        ),
        (
            "bindings",
            json!([{"fabric_port": "p1", "device": "sw-a", "port": "Ethernet1/49"}]),
        ),
    ]
    .into_iter()
    .map(|(k, v)| {
        (
            k.to_string(),
            (
                serde_json::to_vec_pretty(&v).unwrap(),
                format!("{ACCT}/{k}@b1"),
            ),
        )
    })
    .collect()
}

#[test]
fn a_path_through_a_network_edge_device_with_no_binding_crosses_the_circuit_and_is_unknown() {
    // The route of sw-a to 198.51.100.0/24 has the Network Edge device as
    // its next hop.
    let mut col = collected("sw-a", 100, ("192.0.2.10", H1), ("192.0.2.30", NE_MAC));
    col.routes.push(RouteRow {
        vrf: "default".into(),
        prefix: "198.51.100.0/24".into(),
        protocol: "static".into(),
        selected: true,
        next_hop: Some("192.0.2.30".into()),
        interface: Some("Vlan100".into()),
        span: row_span("sw-a", "routes", "b1", 1),
    });
    let e = assemble(vec![
        Input::Nxos {
            name: "sw-a".into(),
            config: switch("sw-a", 100, "192.0.2.1").into_bytes(),
            file: "sw-a/config".into(),
            collected: col,
            sections: sections("sw-a", 100),
        },
        Input::Equinix {
            name: ACCT.into(),
            sections: edge_account(),
        },
    ]);
    let t = e.builder.build().expect("the twin builds");
    let twin = format!("{ACCT}-ne-{NE}");
    assert!(
        t.devices().iter().any(|d| d.to_string() == twin),
        "{:?}",
        t.devices()
    );
    let a = run(&t, "192.0.2.10", "198.51.100.5");
    let s = steps(&a);
    assert_eq!(
        a.branches()
            .iter()
            .map(|b| b.verdict.kind())
            .collect::<Vec<_>>(),
        [VerdictKind::Unknown],
        "{s:#?}"
    );
    assert!(
        s.iter().any(|x| x.contains(&format!(
            "from port port/p1 VLAN 100 to port ne-{NE}/1 VLAN 100"
        ))),
        "{s:#?}"
    );
    assert!(
        s.iter()
            .any(|x| x.contains(&format!("pop VLAN 100 on port ne-{NE}/1"))),
        "{s:#?}"
    );
    assert!(
        s.iter()
            .any(|x| x.contains("the Network Edge device lab-fw is not collected")),
        "{s:#?}"
    );
}
