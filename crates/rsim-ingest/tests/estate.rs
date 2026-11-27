//! A UniFi site joined to a VyOS router, on synthetic sections.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{
    Destination, EndpointId, ExitPoint, FieldValue, Header, PROTO_TCP, ReasonCode, Verdict,
};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_ingest::State;
use rsim_ingest::collected::{AddressRow, Collected, LinkRow, RouteRow, SpeedRow, row_span};
use rsim_ingest::estate::{Estate, Input, assemble};

const VYOS: &[u8] = include_bytes!("fixtures/vyos/r1-config.json");

fn section(name: &str) -> (String, (Vec<u8>, String)) {
    let path = format!(
        "{}/tests/fixtures/unifi/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = std::fs::read(path).unwrap();
    (name.to_string(), (bytes, format!("site1/{name}")))
}

fn route(prefix: &str, protocol: &str, iface: &str) -> RouteRow {
    RouteRow {
        vrf: "default".into(),
        prefix: prefix.into(),
        protocol: protocol.into(),
        selected: true,
        next_hop: None,
        interface: Some(iface.into()),
        span: row_span("r1", "routes", "b1", 0),
    }
}

fn link(iface: &str, parent: Option<&str>) -> LinkRow {
    LinkRow {
        interface: iface.into(),
        mac: Some("00:00:5e:00:53:01".into()),
        parent: parent.map(str::to_string),
        vlan: None,
        span: row_span("r1", "links", "b4", 0),
    }
}

fn estate() -> Estate {
    estate_with(|_, b| b, Vec::new())
}

/// The estate with each UniFi section changed by `change`, and with the
/// routes `extra` in the route table of the router.
fn estate_with(change: impl Fn(&str, Vec<u8>) -> Vec<u8>, extra: Vec<RouteRow>) -> Estate {
    estate_more(change, extra, Vec::new())
}

/// The estate with the inputs `more` too.
fn estate_more(
    change: impl Fn(&str, Vec<u8>) -> Vec<u8>,
    extra: Vec<RouteRow>,
    more: Vec<Input>,
) -> Estate {
    estate_from(VYOS, change, extra, more)
}

/// The estate with the router config `config`.
fn estate_from(
    config: &[u8],
    change: impl Fn(&str, Vec<u8>) -> Vec<u8>,
    extra: Vec<RouteRow>,
    more: Vec<Input>,
) -> Estate {
    let collected = Collected {
        addresses: vec![AddressRow {
            interface: "pppoe0".into(),
            prefix: "203.0.113.10/32".into(),
            span: row_span("r1", "addresses", "b2", 0),
        }],
        routes: vec![
            route("0.0.0.0/0", "kernel", "pppoe0"),
            route("192.0.2.0/26", "connected", "eth0.10"),
            route("192.0.2.64/26", "connected", "eth0.110"),
            route("192.0.2.192/27", "connected", "eth0"),
        ]
        .into_iter()
        .chain(extra)
        .collect(),
        neighbours: Vec::new(),
        links: vec![
            link("eth0", None),
            link("eth0.10", Some("eth0")),
            link("eth0.110", Some("eth0")),
        ],
        speeds: vec![SpeedRow {
            interface: "eth0".into(),
            mbps: Some(1000),
            duplex: Some("full".into()),
            span: row_span("r1", "link_speeds", "b5", 0),
        }],
        macs: Vec::new(),
        ospf: None,
    };
    let sections: BTreeMap<String, (Vec<u8>, String)> =
        ["networks", "wlans", "devices", "clients", "port_profiles"]
            .into_iter()
            .map(section)
            .map(|(n, (b, f))| {
                let b = change(&n, b);
                (n, (b, f))
            })
            .collect();
    let mut inputs = vec![
        Input::Vyos {
            name: "r1".into(),
            config: config.to_vec(),
            file: "r1/config".into(),
            collected,
        },
        Input::Unifi {
            name: "site1".into(),
            sections,
        },
    ];
    inputs.extend(more);
    assemble(inputs)
}

fn twin() -> Twin {
    estate().builder.build().expect("the twin builds")
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn run(t: &Twin, src: &str, dst: &str, port: u16) -> Answer {
    let h = Header::request(ip(src), ip(dst), PROTO_TCP)
        .with_src_port(40000)
        .with_dst_port(port);
    Executor::new(t)
        .run(&Query::path(t, &h))
        .expect("the query runs")
}

#[test]
fn a_guest_reaches_a_lan_host_through_the_access_point_the_switch_and_the_router() {
    let t = twin();
    let a = run(&t, "192.0.2.70", "192.0.2.50", 8123);
    assert_eq!(
        a.verdict(),
        Some(&Verdict::Deliver(Destination::Endpoint(EndpointId::new(
            "h1-005351"
        ))))
    );
    let b = &a.branches()[0];
    let f: Vec<&str> = b.steps.iter().map(|s| s.function.as_str()).collect();
    for want in [
        "ap1/host/wlan/guest",
        "ap1/wlan/guest/in",
        "ap1/port/1/out",
        "sw1/port/3/in",
        "sw1/port/1/out",
        "r1/handoff/eth0",
        "r1/in/eth0.110",
        "r1/policy",
        "r1/out/eth0.10",
        "sw1/port/1/in",
        "sw1/port/2/out",
    ] {
        assert!(f.contains(&want), "{want} not in {f:?}");
    }
    let tag = |name: &str| {
        let s = b
            .steps
            .iter()
            .find(|s| s.function.as_str() == name)
            .unwrap();
        s.output.witness().unwrap().current.vlan
    };
    assert_eq!(tag("ap1/port/1/out"), FieldValue::Known(110));
    assert_eq!(tag("r1/out/eth0.10"), FieldValue::Known(10));
    assert_eq!(tag("sw1/port/2/out"), FieldValue::Absent);
}

#[test]
fn a_lan_host_reaches_the_internet_through_the_switch_and_leaves_the_twin_on_pppoe() {
    let t = twin();
    let a = run(&t, "192.0.2.50", "198.18.0.1", 443);
    assert_eq!(
        a.verdict(),
        Some(&Verdict::Exit(ExitPoint {
            device: "r1".into(),
            interface: "pppoe0".into(),
        }))
    );
    let b = &a.branches()[0];
    let f: Vec<&str> = b.steps.iter().map(|s| s.function.as_str()).collect();
    for want in [
        "sw1/port/2/in",
        "r1/handoff/eth0",
        "r1/in/eth0.10",
        "r1/snat",
    ] {
        assert!(f.contains(&want), "{want} not in {f:?}");
    }
    assert_eq!(f.last(), Some(&"r1/out/pppoe0"));
    // The destination is outside the twin, so the answer has no reply.
    assert!(a.replies.is_empty(), "{:?}", a.replies);
}

#[test]
fn the_router_policy_decides_between_the_vlans() {
    let t = twin();
    let a = run(&t, "192.0.2.70", "192.0.2.50", 22);
    match a.verdict() {
        Some(Verdict::Drop(r)) => assert_eq!(r.code, ReasonCode::Denied),
        v => panic!("{v:?}"),
    }
}

#[test]
fn the_router_reaches_a_client_from_the_client_list() {
    let t = twin();
    // The router has no ARP entry for g1; the client list gives its MAC.
    let a = run(&t, "192.0.2.50", "192.0.2.70", 443);
    assert_eq!(
        a.verdict(),
        Some(&Verdict::Deliver(Destination::Endpoint(EndpointId::new(
            "g1-005352"
        ))))
    );
}

#[test]
fn the_coverage_and_the_notes_name_what_is_not_lowered() {
    let e = estate();
    let cov = &e.coverage["site1"];
    let ranked: Vec<&str> = cov.ranked().iter().map(|r| r.0).collect();
    assert_eq!(ranked, ["networks/*/is_nat"]);
    assert!(cov.share(State::Unhandled) < 0.1);
    let notes = &e.notes["site1"];
    assert!(notes.iter().any(|n| n.contains("gw1")), "{notes:?}");
    assert_eq!(e.unread["r1"], Vec::<String>::new());
}

#[test]
fn two_builds_give_the_same_answers() {
    let (a, b) = (twin(), twin());
    assert_eq!(
        format!("{:?}", run(&a, "192.0.2.70", "192.0.2.50", 8123).summary),
        format!("{:?}", run(&b, "192.0.2.70", "192.0.2.50", 8123).summary)
    );
}

#[test]
fn two_clients_of_one_ssid_reach_each_other_unless_the_ssid_isolates_them() {
    let t = twin();
    let a = run(&t, "192.0.2.70", "192.0.2.71", 443);
    assert_eq!(
        a.verdict(),
        Some(&Verdict::Deliver(Destination::Endpoint(EndpointId::new(
            "g2-005354"
        ))))
    );
    let isolated = estate_with(
        |n, b| {
            if n == "wlans" {
                String::from_utf8(b)
                    .unwrap()
                    .replace("\"l2_isolation\": false", "\"l2_isolation\": true")
                    .into_bytes()
            } else {
                b
            }
        },
        Vec::new(),
    );
    let t = isolated.builder.build().unwrap();
    let a = run(&t, "192.0.2.70", "192.0.2.71", 443);
    match a.verdict() {
        Some(Verdict::Drop(r)) => {
            assert_eq!(r.code, ReasonCode::Denied);
            assert!(r.detail.contains("isolated"), "{}", r.detail);
        }
        v => panic!("{v:?}"),
    }
    // The gateway and the wired hosts stay reachable.
    let a = run(&t, "192.0.2.70", "192.0.2.50", 8123);
    assert!(
        matches!(a.verdict(), Some(Verdict::Deliver(_))),
        "{:?}",
        a.verdict()
    );
}

#[test]
fn the_reply_starts_at_the_attachment_point_of_the_destination() {
    let t = twin();
    let a = run(&t, "192.0.2.70", "192.0.2.50", 8123);
    let r = &a.replies[0];
    match &r.result {
        rsim_engine::ReplyResult::Ran(reply) => assert_eq!(
            reply.verdict(),
            Some(&Verdict::Deliver(Destination::Endpoint(EndpointId::new(
                "g1-005352"
            ))))
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn each_link_step_shows_the_speed_duplex_and_media_of_both_ends() {
    let t = twin();
    let a = run(&t, "192.0.2.70", "192.0.2.50", 8123);
    let b = &a.branches()[0];
    let detail = |name: &str| {
        b.steps
            .iter()
            .find(|s| s.function.as_str() == name)
            .unwrap()
            .reason
            .detail
            .clone()
    };
    let ap = detail("ap1/port/1/out");
    assert!(
        ap.contains("link 100 Mbit/s full duplex GE to 1000 Mbit/s full duplex GE"),
        "{ap}"
    );
    assert!(ap.contains("speed mismatch"), "{ap}");
    let up = detail("sw1/port/1/out");
    assert!(
        up.contains("link 1000 Mbit/s full duplex GE to 1000 Mbit/s full duplex"),
        "{up}"
    );
    assert!(!up.contains("mismatch"), "{up}");
    let router = detail("r1/out/eth0.10");
    assert!(
        router.contains("link 1000 Mbit/s full duplex to 1000 Mbit/s full duplex GE"),
        "{router}"
    );
}

#[test]
fn a_client_that_is_a_next_hop_is_not_an_endpoint() {
    let mut via_h1 = route("10.0.0.0/8", "static", "eth0.10");
    via_h1.next_hop = Some("192.0.2.50".into());
    let e = estate_with(|_, b| b, vec![via_h1]);
    assert!(
        e.notes["site1"].contains(&"client h1: next hop of a route, not an endpoint".to_string()),
        "{:?}",
        e.notes
    );
    let t = e.builder.build().expect("the twin builds");
    // A packet to h1 reaches the port of h1 and is not delivered there,
    // because it can go on beyond h1.
    let a = run(&t, "192.0.2.70", "192.0.2.50", 8123);
    let b = &a.branches()[0];
    let f: Vec<&str> = b.steps.iter().map(|s| s.function.as_str()).collect();
    assert!(f.contains(&"sw1/port/2/out"), "{f:?}");
    assert!(
        matches!(a.verdict(), Some(Verdict::Unknown(_))),
        "{:?}",
        a.verdict()
    );
}

#[test]
fn a_router_interface_that_a_site_and_a_switch_both_claim_has_no_link() {
    let config = "hostname leafx
interface Ethernet1/1
  no switchport
  no shutdown
  ip address 198.51.100.9/30
";
    let lldp = r#"{"TABLE_nbor_detail":{"ROW_nbor_detail":[
        {"l_port_id":"Ethernet1/1","sys_name":"r1","chassis_id":"0000.5e00.5301","port_id":"eth0"}]}}"#;
    let switch = Input::Nxos {
        name: "leafx".into(),
        config: config.as_bytes().to_vec(),
        file: "leafx/config".into(),
        collected: Collected {
            links: vec![LinkRow {
                interface: "Ethernet1/1".into(),
                mac: Some("00:00:5e:00:53:e9".into()),
                parent: None,
                vlan: None,
                span: row_span("leafx", "links", "b1", 0),
            }],
            ..Collected::default()
        },
        sections: BTreeMap::from([(
            "lldp".to_string(),
            (lldp.as_bytes().to_vec(), "leafx/lldp".to_string()),
        )]),
    };
    let e = estate_more(|_, b| b, Vec::new(), vec![switch]);
    assert!(
        e.notes["r1"].contains(&"eth0: 2 links claim the port, no link".to_string()),
        "{:#?}",
        e.notes
    );
    e.builder.build().expect("the twin builds");
}

/// The estate with the text `from` replaced by `to` in the UniFi section
/// `name`.
fn estate_replacing(name: &str, from: &str, to: &str) -> Estate {
    estate_with(
        |n, b| {
            if n == name {
                let s = String::from_utf8(b).unwrap();
                assert!(s.contains(from), "{from}");
                s.replace(from, to).into_bytes()
            } else {
                b
            }
        },
        Vec::new(),
    )
}

/// The verdict of a query that must be unknown, with its reason.
fn unknown_reason(a: &Answer) -> rsim_core::Reason {
    match a.verdict() {
        Some(Verdict::Unknown(r)) => r.clone(),
        v => panic!("{v:?}"),
    }
}

#[test]
fn a_wired_client_of_another_network_than_its_port_is_not_placed() {
    // h1 is on an access port of LAN, with the network of GUEST.
    for ip in ["192.0.2.50", "192.0.2.72"] {
        let e = estate_replacing(
            "clients",
            r#""name": "h1", "ip": "192.0.2.50", "network_id": "n-lan""#,
            &format!(r#""name": "h1", "ip": "{ip}", "network_id": "n-guest""#),
        );
        let notes = &e.notes["site1"];
        assert!(
            notes
                .iter()
                .any(|n| n.starts_with("client h1: network n-guest")),
            "{notes:?}"
        );
        let t = e.builder.build().unwrap();
        let a = run(&t, "192.0.2.70", ip, 8123);
        unknown_reason(&a);
        let a = run(&t, "192.0.2.30", ip, 443);
        unknown_reason(&a);
        let a = run(&t, ip, "192.0.2.70", 443);
        let r = unknown_reason(&a);
        assert!(r.detail.contains("client h1 not placed"), "{r:?}");
        let first = a.branches()[0].steps[0].function.to_string();
        assert_eq!(first, "sw1/unplaced/h1-005351");
    }
}

#[test]
fn a_client_listed_twice_that_is_not_placed_gives_one_ingress() {
    let h1 = r#"{"mac": "00:00:5e:00:53:51", "name": "h1", "ip": "192.0.2.50", "network_id": "n-lan", "is_wired": true, "sw_mac": "00:00:5e:00:53:a1", "sw_port": 2},"#;
    let e = estate_with(
        |n, b| {
            let s = String::from_utf8(b).unwrap();
            if n != "clients" {
                return s.into_bytes();
            }
            let wrong = h1.replace("n-lan", "n-guest");
            s.replace(h1, &format!("{wrong}\n  {wrong}")).into_bytes()
        },
        Vec::new(),
    );
    let notes = &e.notes["site1"];
    assert!(
        notes
            .iter()
            .any(|n| n == "client h1-005351 is listed twice"),
        "{notes:?}"
    );
    let t = e.builder.build().unwrap();
    let a = run(&t, "192.0.2.50", "192.0.2.70", 443);
    let r = unknown_reason(&a);
    assert!(r.detail.contains("client h1 not placed"), "{r:?}");
}

/// A second WLAN `guest` of the network LAN.
const SECOND_GUEST: (&str, &str) = (
    r#""l2_isolation": false}"#,
    r#""l2_isolation": false},
  {"_id": "w-guest2", "name": "guest", "networkconf_id": "n-lan", "enabled": true}"#,
);

#[test]
fn an_ssid_on_an_access_point_has_the_network_of_the_wlan_that_it_names() {
    let e = estate_replacing("wlans", SECOND_GUEST.0, SECOND_GUEST.1);
    let t = e.builder.build().unwrap();
    let a = run(&t, "192.0.2.50", "192.0.2.71", 443);
    assert_eq!(
        a.verdict(),
        Some(&Verdict::Deliver(Destination::Endpoint(EndpointId::new(
            "g2-005354"
        ))))
    );
}

#[test]
fn the_clients_of_an_ssid_with_more_than_one_network_are_not_placed() {
    // The access point names no WLAN.
    let e = estate_with(
        |n, b| {
            let s = String::from_utf8(b).unwrap();
            let s = match n {
                "wlans" => s.replace(SECOND_GUEST.0, SECOND_GUEST.1),
                "devices" => s.replace(r#""wlanconf_id": "w-guest", "#, ""),
                _ => s,
            };
            s.into_bytes()
        },
        Vec::new(),
    );
    let notes = &e.notes["site1"];
    assert!(
        notes.iter().any(|n| n.starts_with("client g2:")),
        "{notes:?}"
    );
    let t = e.builder.build().unwrap();
    let a = run(&t, "192.0.2.50", "192.0.2.71", 443);
    assert!(
        matches!(a.verdict(), Some(Verdict::Unknown(_))),
        "{:?}",
        a.verdict()
    );
}

/// The reply of a guest request to a LAN host, with LAN-GUEST dropping all
/// packets, the state policy `state_policy` and the rules `rules` in
/// LAN-GUEST.
fn reply_with(
    state_policy: Option<serde_json::Value>,
    rules: Option<serde_json::Value>,
) -> (Vec<String>, Verdict) {
    let mut v: serde_json::Value = serde_json::from_slice(VYOS).unwrap();
    let fw = &mut v["firewall"];
    fw["ipv4"]["name"]["LAN-GUEST"]["default-action"] = "drop".into();
    let gopt = fw["global-options"].as_object_mut().unwrap();
    match state_policy {
        Some(sp) => gopt.insert("state-policy".into(), sp),
        None => gopt.remove("state-policy"),
    };
    if let Some(r) = rules {
        fw["ipv4"]["name"]["LAN-GUEST"]["rule"] = r;
    }
    let config = serde_json::to_vec_pretty(&v).unwrap();
    let t = estate_from(&config, |_, b| b, Vec::new(), Vec::new())
        .builder
        .build()
        .unwrap();
    let a = run(&t, "192.0.2.70", "192.0.2.50", 8123);
    assert!(
        matches!(a.verdict(), Some(Verdict::Deliver(_))),
        "{:?}",
        a.verdict()
    );
    match &a.replies[0].result {
        rsim_engine::ReplyResult::Ran(r) => {
            let b = &r.branches()[0];
            let path = b.steps.iter().map(|s| s.function.to_string()).collect();
            (path, b.verdict.clone())
        }
        other => panic!("{other:?}"),
    }
}

fn delivered_to_g1(v: &Verdict) {
    assert_eq!(
        v,
        &Verdict::Deliver(Destination::Endpoint(EndpointId::new("g1-005352")))
    );
}

fn denied_at(path: &[String], v: &Verdict, function: &str) {
    match v {
        Verdict::Drop(r) => assert_eq!(r.code, ReasonCode::Denied, "{r:?}"),
        v => panic!("{v:?}"),
    }
    assert_eq!(path.last().map(String::as_str), Some(function), "{path:?}");
}

#[test]
fn the_state_policy_accepts_the_packets_of_an_established_session() {
    let sp = serde_json::json!({"established": {"action": "accept"}});
    let (_, v) = reply_with(Some(sp), None);
    delivered_to_g1(&v);
}

#[test]
fn the_state_policy_drops_the_packets_of_an_established_session() {
    let sp = serde_json::json!({"established": {"action": "drop"}});
    let (path, v) = reply_with(Some(sp), None);
    denied_at(&path, &v, "r1/session-lookup");
}

#[test]
fn with_no_state_action_the_zone_policy_decides_the_packets_of_a_session() {
    let (path, v) = reply_with(None, None);
    denied_at(&path, &v, "r1/policy");
    let sp = serde_json::json!({"invalid": {"action": "drop"}});
    let (path, v) = reply_with(Some(sp), None);
    denied_at(&path, &v, "r1/policy");
}

#[test]
fn with_no_state_action_a_state_rule_decides_the_packets_of_a_session() {
    let established = serde_json::json!({
        "5": {"action": "accept", "state": ["established", "related"]}
    });
    let (_, v) = reply_with(None, Some(established));
    delivered_to_g1(&v);
    let new = serde_json::json!({"5": {"action": "accept", "state": "new"}});
    let (path, v) = reply_with(None, Some(new));
    denied_at(&path, &v, "r1/policy");
}

#[test]
fn an_accepted_session_packet_skips_the_state_rules() {
    let sp = serde_json::json!({"established": {"action": "accept"}});
    let rules = serde_json::json!({"5": {"action": "drop", "state": "established"}});
    let (_, v) = reply_with(Some(sp), Some(rules));
    delivered_to_g1(&v);
}

/// The guest SSID of the access point with the network LAN on the radio
/// `na`, the client g2 on LAN, and LAN on the port of the access point.
fn two_radios(g1_radio: &str) -> Estate {
    estate_with(
        |n, b| {
            let s = String::from_utf8(b).unwrap();
            let s = match n {
                "wlans" => s.replace(SECOND_GUEST.0, SECOND_GUEST.1),
                "devices" => s
                    .replace(
                        r#""wlanconf_id": "w-guest", "radio": "na""#,
                        r#""wlanconf_id": "w-guest2", "radio": "na""#,
                    )
                    .replace(r#""excluded_networkconf_ids": ["n-lan"]"#, r#""excluded_networkconf_ids": []"#),
                "clients" => s
                    .replace(
                        r#""name": "g2", "ip": "192.0.2.71", "network_id": "n-guest","#,
                        r#""name": "g2", "ip": "192.0.2.51", "network_id": "n-lan", "radio": "na","#,
                    )
                    .replace(
                        r#""name": "g1", "ip": "192.0.2.70", "network_id": "n-guest","#,
                        &format!(
                            r#""name": "g1", "ip": "192.0.2.70", "network_id": "n-guest"{g1_radio},"#
                        ),
                    ),
                _ => s,
            };
            s.into_bytes()
        },
        Vec::new(),
    )
}

#[test]
fn each_radio_of_an_ssid_has_the_network_of_its_wlan() {
    let e = two_radios(r#", "radio": "ng""#);
    let t = e.builder.build().unwrap();
    let a = run(&t, "192.0.2.50", "192.0.2.51", 443);
    assert_eq!(
        a.verdict(),
        Some(&Verdict::Deliver(Destination::Endpoint(EndpointId::new(
            "g2-005354"
        ))))
    );
    let a = run(&t, "192.0.2.50", "192.0.2.70", 443);
    assert_eq!(
        a.verdict(),
        Some(&Verdict::Deliver(Destination::Endpoint(EndpointId::new(
            "g1-005352"
        ))))
    );
}

#[test]
fn a_client_of_an_ssid_with_a_network_on_each_radio_needs_its_radio() {
    let e = two_radios("");
    let notes = &e.notes["site1"];
    assert!(
        notes.iter().any(|n| n.starts_with("client g1:")),
        "{notes:?}"
    );
    let t = e.builder.build().unwrap();
    let a = run(&t, "192.0.2.70", "192.0.2.50", 8123);
    let r = unknown_reason(&a);
    assert!(r.detail.contains("client g1 not placed"), "{r:?}");
    let a = run(&t, "192.0.2.50", "192.0.2.70", 443);
    unknown_reason(&a);
    // g2 names its radio.
    let a = run(&t, "192.0.2.50", "192.0.2.51", 443);
    assert_eq!(
        a.verdict(),
        Some(&Verdict::Deliver(Destination::Endpoint(EndpointId::new(
            "g2-005354"
        ))))
    );
}

#[test]
fn a_vap_with_no_radio_leaves_the_radio_of_a_client_unmatched() {
    // The vap of the network LAN names no radio, so g1 on the radio `ng`
    // can be on either WLAN.
    let e = estate_with(
        |n, b| {
            let s = String::from_utf8(b).unwrap();
            let s = match n {
                "wlans" => s.replace(SECOND_GUEST.0, SECOND_GUEST.1),
                "devices" => s.replace(
                    r#""wlanconf_id": "w-guest", "radio": "na""#,
                    r#""wlanconf_id": "w-guest2""#,
                ),
                "clients" => s.replace(
                    r#""name": "g1", "ip": "192.0.2.70", "network_id": "n-guest","#,
                    r#""name": "g1", "ip": "192.0.2.70", "network_id": "n-guest", "radio": "ng","#,
                ),
                _ => s,
            };
            s.into_bytes()
        },
        Vec::new(),
    );
    let notes = &e.notes["site1"];
    assert!(
        notes.iter().any(|n| n.starts_with("client g1:")),
        "{notes:?}"
    );
    let t = e.builder.build().unwrap();
    let a = run(&t, "192.0.2.70", "192.0.2.50", 8123);
    let r = unknown_reason(&a);
    assert!(r.detail.contains("client g1 not placed"), "{r:?}");
}

#[test]
fn a_bgp_stanza_that_can_hold_a_neighbour_makes_the_bgp_config_not_read() {
    use rsim_ingest::estate::hides_peers;
    for p in [
        "router bgp *",
        "router bgp */vrf *",
        "router bgp */neighbor *",
        "router bgp */bgp listen range ..",
        "protocols/bgp/*",
        "protocols/bgp/neighbor/*",
        "vrf/name/*/protocols/bgp",
    ] {
        assert!(hides_peers(p), "{p}");
    }
    for p in [
        "router bgp */neighbor */password <secret>",
        "router bgp */neighbor 198.51.100.1 password <secret>",
        "router bgp */address-family ../neighbor 198.51.100.1 prefix-list OUR-NETS out",
        "router bgp */bgp router-id 203.0.113.1",
        "router bgp */vrf */rd 64496:100",
        "protocols/bgp/neighbor/*/password",
        "protocols/bgp/parameters/router-id",
        "interface */description",
    ] {
        assert!(!hides_peers(p), "{p}");
    }
}

/// The estate with each replacement `(section, from, to)` in its UniFi
/// section.
fn estate_replacing_all(changes: &[(&str, &str, &str)]) -> Estate {
    estate_with(
        |n, b| {
            let mut s = String::from_utf8(b).unwrap();
            for (_, from, to) in changes.iter().filter(|c| c.0 == n) {
                assert!(s.contains(*from), "{from}");
                s = s.replace(*from, to);
            }
            s.into_bytes()
        },
        Vec::new(),
    )
}

/// The estate with h9 at 192.0.2.52 on port 4 of sw1 and h1 on port 2,
/// both in LAN, with `isolation` on both ports.
fn two_lan_hosts(isolation: bool) -> Estate {
    let port2 =
        format!(r#"{{"port_idx": 2, "isolation": {isolation}, "up": true, "enable": true,"#);
    let port4 = format!(
        r#"{{"port_idx": 4, "isolation": {isolation}, "up": true, "enable": true, "forward": "native", "native_networkconf_id": "n-lan", "stp_state": "forwarding"}}"#
    );
    estate_replacing_all(&[
        (
            "devices",
            r#"{"port_idx": 2, "up": true, "enable": true,"#,
            port2.as_str(),
        ),
        (
            "devices",
            r#"{"port_idx": 4, "up": false, "enable": true, "forward": "native", "native_networkconf_id": "n-lan", "stp_state": "disabled"}"#,
            port4.as_str(),
        ),
        (
            "clients",
            r#""name": "h9", "network_id": "n-lan", "is_wired": true, "sw_mac": "00:00:5e:00:53:a1", "sw_port": 2}"#,
            r#""name": "h9", "ip": "192.0.2.52", "network_id": "n-lan", "is_wired": true, "sw_mac": "00:00:5e:00:53:a1", "sw_port": 4}"#,
        ),
    ])
}

#[test]
fn a_host_on_an_isolated_port_reaches_no_host_on_another_isolated_port() {
    let t = two_lan_hosts(false).builder.build().unwrap();
    let a = run(&t, "192.0.2.50", "192.0.2.52", 443);
    assert_eq!(
        a.verdict(),
        Some(&Verdict::Deliver(Destination::Endpoint(EndpointId::new(
            "h9-005353"
        ))))
    );
    let t = two_lan_hosts(true).builder.build().unwrap();
    let a = run(&t, "192.0.2.50", "192.0.2.52", 443);
    match a.verdict() {
        Some(Verdict::Drop(r)) => {
            assert_eq!(r.code, ReasonCode::Denied);
            assert!(r.detail.contains("isolated"), "{}", r.detail);
        }
        v => panic!("{v:?}"),
    }
    // The uplink port is not isolated.
    let a = run(&t, "192.0.2.50", "198.18.0.1", 443);
    assert!(
        matches!(a.verdict(), Some(Verdict::Exit(_))),
        "{:?}",
        a.verdict()
    );
}

#[test]
fn a_disabled_network_is_in_no_bridge_domain() {
    let e = estate_replacing(
        "networks",
        r#""vlan": 110, "vlan_enabled": true"#,
        r#""vlan": 110, "vlan_enabled": true, "enabled": false"#,
    );
    let notes = &e.notes["site1"];
    assert!(
        notes
            .iter()
            .any(|n| n == "client g1: network of its port not known"),
        "{notes:?}"
    );
    let t = e.builder.build().unwrap();
    let a = run(&t, "192.0.2.50", "192.0.2.70", 443);
    assert!(
        !matches!(a.verdict(), Some(Verdict::Deliver(_))),
        "{:?}",
        a.verdict()
    );
}

/// The start of the entry of port 3 of sw1, the uplink port of ap1, with
/// its `forward` field.
const PORT3: &str = r#""port_idx": 3, "up": true, "enable": true, "forward": "customize", "#;

#[test]
fn a_port_with_no_forward_mode_carries_only_its_native_network() {
    let e = estate_replacing(
        "devices",
        PORT3,
        r#""port_idx": 3, "up": true, "enable": true, "#,
    );
    let t = e.builder.build().unwrap();
    let a = run(&t, "192.0.2.70", "192.0.2.50", 8123);
    assert!(
        !matches!(a.verdict(), Some(Verdict::Deliver(_))),
        "{:?}",
        a.verdict()
    );
}

#[test]
fn the_tagged_vlan_management_of_a_port_sets_its_tagged_networks() {
    for (mgmt, delivered) in [
        (r#""tagged_vlan_mgmt": "block_all", "#, false),
        (r#""tagged_vlan_mgmt": "auto", "#, true),
        (
            r#""tagged_vlan_mgmt": "custom", "tagged_networkconf_ids": ["n-guest"], "#,
            true,
        ),
        (
            r#""tagged_vlan_mgmt": "custom", "tagged_networkconf_ids": ["n-lan"], "#,
            false,
        ),
    ] {
        let e = estate_replacing("devices", PORT3, &format!("{PORT3}{mgmt}"));
        let t = e.builder.build().unwrap();
        let a = run(&t, "192.0.2.70", "192.0.2.50", 8123);
        assert_eq!(
            matches!(a.verdict(), Some(Verdict::Deliver(_))),
            delivered,
            "{mgmt}: {:?}",
            a.verdict()
        );
    }
}

#[test]
fn the_uplink_port_of_an_access_point_with_no_forward_mode_carries_each_network() {
    let e = estate_replacing(
        "devices",
        r#""name": "ap1", "type": "uap", "#,
        r#""name": "ap1", "type": "uap", "port_table": [{"port_idx": 1, "up": true}], "#,
    );
    let t = e.builder.build().unwrap();
    let a = run(&t, "192.0.2.70", "192.0.2.50", 8123);
    assert_eq!(
        a.verdict(),
        Some(&Verdict::Deliver(Destination::Endpoint(EndpointId::new(
            "h1-005351"
        ))))
    );
}

#[test]
fn the_jumbo_frame_flag_of_a_unifi_device_gives_the_mtu_of_its_ports() {
    let jumbo = |on: bool| {
        estate_with(
            move |n, b| {
                if n == "devices" {
                    String::from_utf8(b)
                        .unwrap()
                        .replace(
                            "\"name\": \"sw1\",",
                            &format!("\"name\": \"sw1\", \"jumboframe_enabled\": {on},"),
                        )
                        .into_bytes()
                } else {
                    b
                }
            },
            Vec::new(),
        )
    };
    let key = |port: &str| ("sw1".to_string(), port.to_string());
    let on = jumbo(true);
    assert_eq!(on.mtu[&key("port/1")].bytes, 9198);
    assert_eq!(on.mtu[&key("port/4")].bytes, 9198);
    assert_eq!(&*on.mtu[&key("port/1")].span.file, "site1/devices#row");
    assert_eq!(jumbo(false).mtu[&key("port/2")].bytes, 1500);
    assert!(
        estate().mtu.keys().all(|(d, _)| d != "sw1"),
        "no flag, no MTU"
    );
}

#[test]
fn the_rib_guard_compares_the_connected_routes_and_leaves_the_kernel_route_out() {
    let e = estate();
    let rows = &e.guard["r1"];
    let category = |p: &str| {
        let r = rows
            .iter()
            .find(|r| r.prefix.to_string() == p)
            .unwrap_or_else(|| panic!("{p} not in the guard"));
        (r.category, r.reason.clone())
    };
    use rsim_guard::Category;
    assert_eq!(category("192.0.2.0/26"), (Category::Match, String::new()));
    assert_eq!(
        category("0.0.0.0/0"),
        (Category::NotComputed, "kernel route".to_string())
    );
    assert_eq!(category("203.0.113.128/25").0, Category::OnlyComputed);
    let t = e.builder.build().expect("the twin builds");
    let a = run(&t, "192.0.2.70", "192.0.2.50", 8123);
    let branches = a.branches();
    let step = branches[0]
        .steps
        .iter()
        .find(|s| s.function.as_str() == "r1/route")
        .unwrap();
    assert_eq!(step.rib_guard, rsim_core::RibGuardFlag::MatchesCollected);
}

#[test]
fn a_static_route_of_a_higher_distance_installs_only_when_the_better_route_is_absent() {
    let config = String::from_utf8(VYOS.to_vec()).unwrap().replacen(
        "\"static\": {\n      \"table\"",
        r#""static": {"route": {"198.51.100.0/24": {"next-hop": {"192.0.2.2": {}, "192.0.2.3": {"distance": "200"}}}}, "table""#,
        1,
    );
    let e = estate_from(
        config.as_bytes(),
        |_, b| b,
        vec![RouteRow {
            next_hop: Some("192.0.2.2".into()),
            ..route("198.51.100.0/24", "static", "eth0.10")
        }],
        Vec::new(),
    );
    let r = e.guard["r1"]
        .iter()
        .find(|r| r.prefix.to_string() == "198.51.100.0/24")
        .unwrap();
    assert_eq!(r.category, rsim_guard::Category::Match, "{r:?}");
    assert_eq!(
        r.computed.as_ref().unwrap().next_hops,
        ["192.0.2.2@eth0.10"]
    );
}

#[test]
fn a_static_route_whose_gateway_does_not_resolve_gives_way_to_a_floating_static_route() {
    let config = String::from_utf8(VYOS.to_vec()).unwrap().replacen(
        "\"static\": {\n      \"table\"",
        r#""static": {"route": {"198.51.100.0/24": {"next-hop": {"203.0.113.5": {}, "192.0.2.3": {"distance": "200"}}}}, "table""#,
        1,
    );
    let e = estate_from(
        config.as_bytes(),
        |_, b| b,
        vec![RouteRow {
            next_hop: Some("192.0.2.3".into()),
            ..route("198.51.100.0/24", "static", "eth0.10")
        }],
        Vec::new(),
    );
    let r = e.guard["r1"]
        .iter()
        .find(|r| r.prefix.to_string() == "198.51.100.0/24")
        .unwrap();
    assert_eq!(r.category, rsim_guard::Category::Match, "{r:?}");
    assert_eq!(
        r.computed.as_ref().unwrap().next_hops,
        ["192.0.2.3@eth0.10"]
    );
}

#[test]
fn a_dhcpv6_route_is_seeded_and_an_ospf6_route_has_the_kind_ospf() {
    let config = String::from_utf8(VYOS.to_vec()).unwrap().replacen(
        r#""eth2": {"description""#,
        r#""eth2": {"address": "dhcpv6", "description""#,
        1,
    );
    let e = estate_from(
        config.as_bytes(),
        |_, b| b,
        vec![
            route("2001:db8:1::/64", "connected", "eth2"),
            route("2001:db8:5::/64", "ospf6", "eth0"),
        ],
        Vec::new(),
    );
    let row = |p: &str| {
        e.guard["r1"]
            .iter()
            .find(|r| r.prefix.to_string() == p)
            .unwrap()
            .clone()
    };
    assert_eq!(
        row("2001:db8:1::/64").category,
        rsim_guard::Category::Seeded
    );
    let o = row("2001:db8:5::/64");
    assert_eq!(o.category, rsim_guard::Category::NotComputed);
    assert_eq!(o.collected.unwrap().kind, "ospf");
}
