//! The VyOS handlers and lowering on a synthetic configuration.

use rsim_ingest::route_tables::RouteTables;
use rsim_ingest::vyos::{self, config::Action, config::Family};
use rsim_ingest::{State, classify, read_json};

const CONFIG: &[u8] = include_bytes!("fixtures/vyos/r1-config.json");

/// The configuration with the change `f`.
fn edited(f: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut v: serde_json::Value = serde_json::from_slice(CONFIG).unwrap();
    f(&mut v);
    serde_json::to_vec_pretty(&v).unwrap()
}

/// Sets the value at a path of keys, with the objects on the path.
fn put(v: &mut serde_json::Value, path: &[&str], value: serde_json::Value) {
    let mut cur = v;
    for k in &path[..path.len() - 1] {
        cur = cur
            .as_object_mut()
            .unwrap()
            .entry(k.to_string())
            .or_insert_with(|| serde_json::json!({}));
    }
    cur.as_object_mut()
        .unwrap()
        .insert(path[path.len() - 1].to_string(), value);
}

#[test]
fn nested_rule_options_with_no_handler_make_the_rule_unhandled() {
    use serde_json::json;
    let config = edited(|v| {
        put(
            v,
            &["firewall", "ipv4", "name", "LAN-WAN", "rule", "6"],
            json!({"action": "drop", "inbound-interface": {"group": "IG"}}),
        );
        put(
            v,
            &["firewall", "ipv4", "name", "LAN-WAN", "rule", "7"],
            json!({"action": "accept", "protocol": "icmp", "icmp": {"type": "8", "code": "0"}}),
        );
        put(
            v,
            &["nat", "source", "rule", "100", "translation"],
            json!({"address": "203.0.113.5", "options": {"port-mapping": "random"}}),
        );
    });
    let cfg = vyos::read(&read_json(&config).unwrap());
    let lw = cfg.rule_set(Family::V4, "LAN-WAN").unwrap();
    let rule = |n: u32| lw.rules.iter().find(|r| r.number == n).unwrap();
    assert_eq!(rule(6).unhandled, ["inbound-interface group"]);
    assert_eq!(rule(7).unhandled, ["icmp code", "icmp type"]);
    let snat = cfg.source_nat.iter().find(|r| r.number == 100).unwrap();
    assert_eq!(snat.unhandled, ["translation options"]);
}

#[test]
fn a_state_option_with_no_state_names_makes_the_rule_unhandled() {
    use serde_json::json;
    let config = edited(|v| {
        put(
            v,
            &["firewall", "ipv4", "name", "LAN-WAN", "rule", "6"],
            json!({"action": "accept", "state": {"established": "enable"}}),
        );
    });
    let cfg = vyos::read(&read_json(&config).unwrap());
    let lw = cfg.rule_set(Family::V4, "LAN-WAN").unwrap();
    let rule = lw.rules.iter().find(|r| r.number == 6).unwrap();
    assert_eq!(rule.unhandled, ["state"]);
}

#[test]
fn a_group_has_the_members_of_its_include_and_each_family_has_its_own_groups() {
    use serde_json::json;
    let config = edited(|v| {
        put(
            v,
            &[
                "firewall",
                "group",
                "address-group",
                "vpn-clients",
                "include",
            ],
            json!("more"),
        );
        put(
            v,
            &["firewall", "group", "address-group", "more"],
            json!({"address": "192.0.2.30", "include": "vpn-clients"}),
        );
        put(
            v,
            &["firewall", "group", "address-group", "broken"],
            json!({"address": "192.0.2.31", "include": "missing"}),
        );
        put(
            v,
            &["firewall", "group", "ipv6-address-group", "vpn-clients"],
            json!({"address": "2001:db8::10"}),
        );
    });
    let cfg = vyos::read(&read_json(&config).unwrap());
    assert_eq!(
        cfg.address_groups["vpn-clients"],
        Ok(vec![
            "192.0.2.10".to_string(),
            "192.0.2.20-192.0.2.23".to_string(),
            "192.0.2.30".to_string(),
        ])
    );
    assert!(cfg.address_groups["broken"].is_err());
    assert_eq!(
        cfg.ipv6_address_groups["vpn-clients"],
        Ok(vec!["2001:db8::10".to_string()])
    );
}

#[test]
fn a_disabled_next_hop_is_left_out_and_another_next_hop_option_is_unhandled() {
    use serde_json::json;
    let config = edited(|v| {
        put(
            v,
            &["protocols", "static", "route", "198.18.0.0/15"],
            json!({"next-hop": {"192.0.2.40": {"disable": {}}, "192.0.2.41": {}}}),
        );
        put(
            v,
            &["protocols", "static", "route", "198.20.0.0/16"],
            json!({"next-hop": {"192.0.2.42": {"distance": "10"}}}),
        );
    });
    let cfg = vyos::read(&read_json(&config).unwrap());
    let r = |p: &str| cfg.static_routes.iter().find(|r| r.prefix == p).unwrap();
    assert_eq!(r("198.18.0.0/15").gateways, ["192.0.2.41"]);
    assert!(r("198.18.0.0/15").unhandled.is_empty());
    assert_eq!(
        r("198.20.0.0/16").unhandled,
        ["next-hop 192.0.2.42 distance"]
    );
}

#[test]
fn each_handled_stanza_is_read() {
    let doc = read_json(CONFIG).unwrap();
    let table = vyos::table(&RouteTables::uniform(true, vyos::dynamic_vrfs(&doc)));
    let cfg = vyos::read(&doc);
    assert_eq!(vyos::unread(&doc, &table, &cfg.read), Vec::<String>::new());
}

#[test]
fn the_coverage_names_the_unhandled_rule_option() {
    let doc = read_json(CONFIG).unwrap();
    let cov = classify(
        &doc,
        &vyos::table(&RouteTables::uniform(true, vyos::dynamic_vrfs(&doc))),
    );
    let ranked: Vec<&str> = cov.ranked().iter().map(|r| r.0).collect();
    assert_eq!(ranked, ["firewall/ipv4/name/*/rule/*/recent"]);
    assert!(cov.share(State::Unhandled) < 0.02);
}

#[test]
fn the_handlers_give_typed_structures() {
    let cfg = vyos::read(&read_json(CONFIG).unwrap());
    let names: Vec<&str> = cfg.interfaces.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "eth0", "eth0.10", "eth0.110", "eth1", "eth2", "dum0", "lo", "pppoe0", "wg0"
        ]
    );
    let lan = cfg.interfaces.iter().find(|i| i.name == "eth0.10").unwrap();
    assert_eq!(lan.addresses, ["192.0.2.1/26"]);
    let ppp = cfg.interfaces.iter().find(|i| i.name == "pppoe0").unwrap();
    assert_eq!(ppp.source_interface.as_deref(), Some("eth2"));
    assert!(ppp.dynamic.contains(&"pppoe".to_string()));
    let wg = cfg.interfaces.iter().find(|i| i.name == "wg0").unwrap();
    assert_eq!(wg.allowed_ips, ["0.0.0.0/0"]);

    let local = cfg.zones.iter().find(|z| z.name == "LOCAL").unwrap();
    assert!(local.local && local.members.is_empty());
    let lan_zone = cfg.zones.iter().find(|z| z.name == "LAN").unwrap();
    assert_eq!(lan_zone.members, ["eth0", "eth0.10"]);
    assert_eq!(lan_zone.intra_zone, Some(Action::Accept));
    let from_wan = lan_zone.from.iter().find(|f| f.from == "WAN").unwrap();
    assert_eq!(from_wan.ipv6.as_deref(), Some("WAN6-LAN6"));

    let gl = cfg.rule_set(Family::V4, "GUEST-LAN").unwrap();
    assert_eq!(
        gl.rules.iter().map(|r| r.number).collect::<Vec<_>>(),
        [10, 20, 30]
    );
    assert_eq!(
        gl.rules[0].matches.destination.port.as_deref(),
        Some("8123,8443-8445")
    );
    assert_eq!(gl.rules[2].unhandled, ["recent"]);
    assert_eq!(cfg.state_policy.invalid, Some(Action::Drop));
    assert_eq!(cfg.address_groups["vpn-clients"].as_ref().unwrap().len(), 2);

    assert_eq!(cfg.source_nat.len(), 2);
    assert_eq!(
        cfg.source_nat[0].translation_address.as_deref(),
        Some("masquerade")
    );
    assert_eq!(cfg.policy_routes[0].interfaces, ["eth0.10"]);
    assert_eq!(cfg.policy_routes[0].rules[1].table.as_deref(), Some("100"));
    let t100 = cfg
        .static_routes
        .iter()
        .find(|r| r.table.as_deref() == Some("100"))
        .unwrap();
    assert_eq!(t100.interfaces, ["wg0"]);
    assert_eq!(cfg.qos[0].policy, "WAN");
}

mod twin {
    use std::net::IpAddr;

    use rsim_core::{
        Destination, ExitPoint, FieldValue, Header, PROTO_TCP, PROTO_UDP, PacketSet, Prefix,
        ReasonCode, SetSpec, Verdict,
    };
    use rsim_engine::{Answer, Executor, Query, Summary, Twin, TwinBuilder};
    use rsim_ingest::collected::{AddressRow, Collected, NeighbourRow, RouteRow, row_span};
    use rsim_ingest::{read_json, vyos};

    use super::CONFIG;

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

    fn collected() -> Collected {
        Collected {
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
                route("203.0.113.128/25", "connected", "eth1"),
            ],
            neighbours: vec![NeighbourRow {
                interface: "eth0.10".into(),
                ip: "192.0.2.50".into(),
                mac: Some("00:00:5e:00:53:50".into()),
                state: Some("REACHABLE".into()),
                span: row_span("r1", "neighbours", "b3", 0),
            }],
            links: Vec::new(),
            speeds: Vec::new(),
            macs: Vec::new(),
        }
    }

    fn build() -> (Twin, Vec<String>) {
        build_from(CONFIG)
    }

    fn build_from(config: &[u8]) -> (Twin, Vec<String>) {
        build_with(config, &collected())
    }

    fn build_with(config: &[u8], col: &Collected) -> (Twin, Vec<String>) {
        let cfg = vyos::read(&read_json(config).unwrap());
        let low = vyos::lower(
            "r1",
            "r1/config",
            &vyos::profile(),
            &cfg,
            col,
            &Default::default(),
        );
        let mut b = TwinBuilder::new();
        for f in low.functions {
            b.add_arc(f);
        }
        for e in low.edges {
            b.edge_interface(e);
        }
        (b.build().expect("the twin builds"), low.notes)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn tcp(src: &str, dst: &str, dport: u16) -> Header {
        Header::request(ip(src), ip(dst), PROTO_TCP)
            .with_src_port(40000)
            .with_dst_port(dport)
    }

    fn udp(src: &str, dst: &str, dport: u16) -> Header {
        Header::request(ip(src), ip(dst), PROTO_UDP)
            .with_src_port(40000)
            .with_dst_port(dport)
    }

    fn run(t: &Twin, iface: &str, h: Header) -> Answer {
        Executor::new(t)
            .run(&Query::path(t, &h).with_ingress("r1", iface))
            .expect("the query runs")
    }

    /// The functions of the first branch and its verdict.
    fn first(a: &Answer) -> (Vec<String>, Verdict) {
        let b = &a.branches()[0];
        let path = b.steps.iter().map(|s| s.function.to_string()).collect();
        (path, b.verdict.clone())
    }

    fn code(v: &Verdict) -> Option<ReasonCode> {
        match v {
            Verdict::Drop(r) | Verdict::Unknown(r) => Some(r.code),
            Verdict::Deliver(_) | Verdict::Exit(_) => None,
        }
    }

    #[test]
    fn a_vpn_client_takes_table_100_and_wireguard_with_masquerade() {
        let (t, _) = build();
        let a = run(&t, "eth0.10", tcp("192.0.2.10", "203.0.113.99", 443));
        let (path, v) = first(&a);
        assert!(path.contains(&"r1/pbr".to_string()), "{path:?}");
        assert!(path.contains(&"r1/route-table-100".to_string()), "{path:?}");
        assert!(path.contains(&"r1/out/wg0".to_string()), "{path:?}");
        let b = &a.branches()[0];
        let snat = b
            .steps
            .iter()
            .find(|s| s.function.as_str() == "r1/snat")
            .unwrap();
        assert_eq!(
            snat.output.witness().unwrap().current.src_ip,
            FieldValue::Known(ip("198.51.100.2"))
        );
        assert!(matches!(v, Verdict::Unknown(_)), "{v:?}");
    }

    #[test]
    fn other_lan_clients_take_the_main_table_pppoe_and_qos() {
        let (t, _) = build();
        let a = run(&t, "eth0.10", tcp("192.0.2.30", "203.0.113.99", 443));
        let (path, v) = first(&a);
        assert!(
            !path.contains(&"r1/route-table-100".to_string()),
            "{path:?}"
        );
        assert!(path.contains(&"r1/qos/pppoe0".to_string()), "{path:?}");
        assert!(path.ends_with(&["r1/out/pppoe0".to_string()]), "{path:?}");
        let b = &a.branches()[0];
        let snat = b
            .steps
            .iter()
            .find(|s| s.function.as_str() == "r1/snat")
            .unwrap();
        assert_eq!(
            snat.output.witness().unwrap().current.src_ip,
            FieldValue::Known(ip("203.0.113.10"))
        );
        let qos = b
            .steps
            .iter()
            .find(|s| s.function.as_str() == "r1/qos/pppoe0")
            .unwrap();
        assert_eq!(
            qos.output.witness().unwrap().current.dscp,
            FieldValue::Unknown
        );
        assert_eq!(v, exit("pppoe0"));
        let last = b.steps.last().unwrap();
        assert_eq!(last.reason.code, ReasonCode::Exited);
        assert_eq!(last.reason.detail, "exit at r1 pppoe0 · access link");
    }

    fn exit(iface: &str) -> Verdict {
        Verdict::Exit(ExitPoint {
            device: "r1".into(),
            interface: iface.into(),
        })
    }

    #[test]
    fn an_egress_with_no_link_that_is_not_an_edge_stays_unknown() {
        let (t, _) = build();
        // eth0.10 has no layer 2 link in this twin and is not an edge.
        let (path, v) = first(&run(&t, "eth0.110", tcp("192.0.2.70", "192.0.2.50", 8123)));
        assert!(path.ends_with(&["r1/out/eth0.10".to_string()]), "{path:?}");
        assert_eq!(code(&v), Some(ReasonCode::NoLink));
        // wg0 carries the default route of table 100 only, so it is not an
        // edge.
        let (path, v) = first(&run(&t, "eth0.10", tcp("192.0.2.10", "203.0.113.99", 443)));
        assert!(path.ends_with(&["r1/out/wg0".to_string()]), "{path:?}");
        assert_eq!(code(&v), Some(ReasonCode::NoLink));
    }

    #[test]
    fn the_interface_of_the_default_route_is_an_edge() {
        let mut col = collected();
        col.routes[0] = RouteRow {
            next_hop: Some("203.0.113.140".into()),
            ..route("0.0.0.0/0", "static", "eth1")
        };
        col.neighbours.push(NeighbourRow {
            interface: "eth1".into(),
            ip: "203.0.113.140".into(),
            mac: Some("00:00:5e:00:53:40".into()),
            state: Some("REACHABLE".into()),
            span: row_span("r1", "neighbours", "b3", 1),
        });
        let (t, _) = build_with(CONFIG, &col);
        let a = run(&t, "eth0", tcp("192.0.2.200", "198.18.0.1", 443));
        let b = &a.branches()[0];
        assert_eq!(*b.verdict, exit("eth1"), "{:?}", b.steps.last());
        assert_eq!(
            b.steps.last().unwrap().reason.detail,
            "exit at r1 eth1 · default route"
        );
    }

    #[test]
    fn set_mode_agrees_with_path_mode_on_an_exit() {
        let (t, _) = build();
        let arena = t.arena(None);
        let pfx = |s: &str| s.parse::<Prefix>().unwrap();
        let spec = SetSpec {
            src_ip: Some(vec![pfx("192.0.2.30/32")]),
            dst_ip: Some(vec![pfx("203.0.113.0/26"), pfx("192.0.2.64/30")]),
            protocol: Some(vec![(PROTO_TCP, PROTO_TCP)]),
            src_port: Some(vec![(40000, 40000)]),
            dst_port: Some(vec![(443, 443)]),
            ..SetSpec::default()
        };
        let ex = Executor::new(&t);
        let set = ex
            .run(
                &Query::set(PacketSet::from_spec(&arena, &spec))
                    .with_ingress("r1", "eth0.10")
                    .without_reply(),
            )
            .unwrap();
        assert!(
            set.summary
                .iter()
                .any(|p| p.summary == Summary::Same(exit("pppoe0"))),
            "{:?}",
            set.summary
        );
        for p in &set.summary {
            let w = p.packets.witness().unwrap();
            let one = ex
                .run(
                    &Query::path(&t, &w.original)
                        .with_ingress("r1", "eth0.10")
                        .without_reply(),
                )
                .unwrap();
            assert_eq!(one.single_summary(), Some(&p.summary), "{:?}", w.original);
        }
    }

    #[test]
    fn the_zone_policy_permits_denies_and_bounds_an_unhandled_rule() {
        let (t, _) = build();
        // GUEST to LAN: rule 10 permits port 8123.
        let (path, v) = first(&run(&t, "eth0.110", tcp("192.0.2.70", "192.0.2.50", 8123)));
        assert!(path.contains(&"r1/out/eth0.10".to_string()), "{path:?}");
        assert_eq!(code(&v), Some(ReasonCode::NoLink));
        // Port 22: no rule, the default drops it.
        let (_, v) = first(&run(&t, "eth0.110", tcp("192.0.2.70", "192.0.2.50", 22)));
        assert_eq!(code(&v), Some(ReasonCode::Denied), "{v:?}");
        // Port 9999: rule 30 has an option with no handler, so the result
        // is unknown.
        let (_, v) = first(&run(&t, "eth0.110", tcp("192.0.2.70", "192.0.2.50", 9999)));
        assert!(matches!(v, Verdict::Unknown(_)), "{v:?}");
        // WAN to LAN: denied.
        let (_, v) = first(&run(&t, "pppoe0", tcp("203.0.113.99", "192.0.2.50", 8123)));
        assert_eq!(code(&v), Some(ReasonCode::Denied), "{v:?}");
    }

    #[test]
    fn traffic_to_the_router_passes_the_local_zone_policy() {
        let (t, _) = build();
        let (path, v) = first(&run(&t, "eth0.110", udp("192.0.2.70", "192.0.2.65", 53)));
        assert!(path.contains(&"r1/policy-local".to_string()), "{path:?}");
        assert_eq!(v, Verdict::Deliver(Destination::Device("r1".into())));
        let (_, v) = first(&run(&t, "eth0.110", tcp("192.0.2.70", "192.0.2.65", 22)));
        assert_eq!(code(&v), Some(ReasonCode::Denied), "{v:?}");
    }

    #[test]
    fn two_builds_give_the_same_answers() {
        let (a, notes_a) = build();
        let (b, notes_b) = build();
        assert_eq!(notes_a, notes_b);
        let h = tcp("192.0.2.10", "203.0.113.99", 443);
        assert_eq!(
            format!("{:?}", run(&a, "eth0.10", h.clone()).summary),
            format!("{:?}", run(&b, "eth0.10", h).summary)
        );
    }

    fn policy_step(a: &Answer) -> (String, ReasonCode) {
        let b = &a.branches()[0];
        let s = b
            .steps
            .iter()
            .find(|s| s.function.as_str() == "r1/policy")
            .expect("the path has the zone policy");
        (s.reason.detail.clone(), s.reason.code)
    }

    #[test]
    fn traffic_inside_a_zone_with_no_intra_zone_setting_is_permitted() {
        let (t, notes) = build();
        assert!(!notes.iter().any(|n| n.contains("intra-zone")), "{notes:?}");
        let a = run(&t, "wg0", tcp("198.51.100.9", "203.0.113.99", 443));
        let (detail, code) = policy_step(&a);
        assert_eq!(code, ReasonCode::Permitted, "{detail}");
        assert!(detail.contains("zone WAN intra-zone"), "{detail}");
    }

    #[test]
    fn a_rule_with_an_outbound_interface_applies_only_to_that_interface() {
        let (t, notes) = build();
        assert!(!notes.iter().any(|n| n.contains("LAN-WAN/5")), "{notes:?}");
        // A VPN client leaves on wg0: rule 5 drops port 25.
        let a = run(&t, "eth0.10", tcp("192.0.2.10", "203.0.113.99", 25));
        let (detail, code) = policy_step(&a);
        assert_eq!(code, ReasonCode::Denied, "{detail}");
        assert!(detail.contains("LAN-WAN/5"), "{detail}");
        // Another client leaves on pppoe0: rule 5 does not apply.
        let a = run(&t, "eth0.10", tcp("192.0.2.30", "203.0.113.99", 25));
        let (detail, code) = policy_step(&a);
        assert_eq!(code, ReasonCode::Permitted, "{detail}");
    }

    #[test]
    fn an_interface_in_no_zone_is_reachable_and_cannot_reach_a_zone() {
        let (t, _) = build();
        let a = run(&t, "eth0.10", tcp("192.0.2.30", "203.0.113.130", 443));
        let (detail, code) = policy_step(&a);
        assert_eq!(code, ReasonCode::Permitted, "{detail}");
        assert!(detail.contains("(no zone)"), "{detail}");
        let a = run(&t, "eth1", tcp("203.0.113.130", "192.0.2.30", 443));
        let (detail, code) = policy_step(&a);
        assert_eq!(code, ReasonCode::Denied, "{detail}");
        assert!(detail.contains("zone LAN default"), "{detail}");
    }

    #[test]
    fn a_global_forward_filter_that_is_not_lowered_makes_the_policy_unknown() {
        let text = String::from_utf8(CONFIG.to_vec()).unwrap().replace(
            "\"ipv4\": {\n      \"name\": {",
            "\"ipv4\": {\n      \"forward\": {\"filter\": {\"default-action\": \"drop\"}},\n      \"name\": {",
        );
        assert!(text.contains("forward"));
        let (t, notes) = build_from(text.as_bytes());
        assert!(
            notes.iter().any(|n| n.contains("forward filter")),
            "{notes:?}"
        );
        let a = run(&t, "eth0.10", tcp("192.0.2.30", "203.0.113.99", 443));
        assert!(
            matches!(first(&a).1, Verdict::Unknown(_)),
            "{:?}",
            first(&a).1
        );
    }

    #[test]
    fn a_route_with_no_usable_next_hop_is_unknown_and_hides_no_shorter_route() {
        let cfg = vyos::read(&read_json(CONFIG).unwrap());
        let mut col = collected();
        col.routes.push(RouteRow {
            vrf: "default".into(),
            prefix: "198.18.0.0/15".into(),
            protocol: "bgp".into(),
            selected: true,
            next_hop: Some("203.0.113.10".into()),
            interface: None,
            span: row_span("r1", "routes", "b1", 9),
        });
        let low = vyos::lower(
            "r1",
            "r1/config",
            &vyos::profile(),
            &cfg,
            &col,
            &Default::default(),
        );
        let mut b = TwinBuilder::new();
        for f in low.functions {
            b.add_arc(f);
        }
        for e in low.edges {
            b.edge_interface(e);
        }
        let t = b.build().unwrap();
        let a = run(&t, "eth0.10", tcp("192.0.2.30", "198.18.1.1", 443));
        let (_, v) = first(&a);
        assert_eq!(code(&v), Some(ReasonCode::IncompleteTable), "{v:?}");
        let (detail, _, _) = step(&a, "r1/route");
        assert_eq!(
            detail,
            "route 198.18.0.0/15 (bgp) in VRF default: next hop not resolved: 203.0.113.10"
        );
    }

    /// The reason of the step of `f` on the first branch, and true if the
    /// step is unknown.
    fn step(a: &Answer, f: &str) -> (String, ReasonCode, bool) {
        let b = &a.branches()[0];
        let s = b
            .steps
            .iter()
            .find(|s| s.function.as_str() == f)
            .unwrap_or_else(|| panic!("the path has {f}"));
        (
            s.reason.detail.clone(),
            s.reason.code,
            s.outcome == rsim_core::Outcome::Unknown,
        )
    }

    #[test]
    fn a_firewall_rule_with_an_interface_group_gives_match_bounds() {
        let config = super::edited(|v| {
            super::put(
                v,
                &["firewall", "ipv4", "name", "LAN-WAN", "rule", "6"],
                serde_json::json!({"action": "drop", "inbound-interface": {"group": "IG"}}),
            );
        });
        let (t, _) = build_from(&config);
        let a = run(&t, "eth0.10", tcp("192.0.2.30", "203.0.113.99", 443));
        let (detail, code, unknown) = step(&a, "r1/policy");
        assert!(unknown, "{detail}");
        assert_ne!(code, ReasonCode::Denied, "{detail}");
    }

    #[test]
    fn a_source_nat_rule_with_an_interface_group_or_a_wildcard_is_unknown() {
        for out in [
            serde_json::json!({"group": "WAN"}),
            serde_json::json!({"name": "eth*"}),
            serde_json::json!({"name": "!pppoe0"}),
        ] {
            let config = super::edited(|v| {
                super::put(
                    v,
                    &["nat", "source", "rule", "100"],
                    serde_json::json!({
                        "outbound-interface": out.clone(),
                        "translation": {"address": "203.0.113.5"}
                    }),
                );
            });
            let (t, _) = build_from(&config);
            // A LAN client to eth1: the rule can apply on eth1.
            let a = run(&t, "eth0.10", tcp("192.0.2.30", "203.0.113.130", 443));
            let (detail, _, unknown) = step(&a, "r1/snat");
            assert!(unknown, "{out}: {detail}");
        }
    }

    #[test]
    fn a_group_with_an_include_matches_the_members_of_the_included_group() {
        let config = super::edited(|v| {
            super::put(
                v,
                &[
                    "firewall",
                    "group",
                    "address-group",
                    "vpn-clients",
                    "include",
                ],
                serde_json::json!("more"),
            );
            super::put(
                v,
                &["firewall", "group", "address-group", "more"],
                serde_json::json!({"address": "192.0.2.30"}),
            );
        });
        let (t, _) = build_from(&config);
        let (path, _) = first(&run(&t, "eth0.10", tcp("192.0.2.30", "203.0.113.99", 443)));
        assert!(path.contains(&"r1/route-table-100".to_string()), "{path:?}");
    }

    #[test]
    fn an_ipv6_group_does_not_replace_the_ipv4_group_of_the_same_name() {
        let config = super::edited(|v| {
            super::put(
                v,
                &["firewall", "group", "ipv6-address-group", "vpn-clients"],
                serde_json::json!({"address": "2001:db8::10"}),
            );
        });
        let (t, _) = build_from(&config);
        let (path, _) = first(&run(&t, "eth0.10", tcp("192.0.2.10", "203.0.113.99", 443)));
        assert!(path.contains(&"r1/route-table-100".to_string()), "{path:?}");
    }

    #[test]
    fn with_bgp_and_no_collected_rib_a_route_lookup_off_the_connected_networks_is_unknown() {
        let mut col = collected();
        col.routes.clear();
        let (t, notes) = build_with(CONFIG, &col);
        assert!(
            notes.iter().any(|n| n.contains("protocols bgp")),
            "{notes:?}"
        );
        let a = run(&t, "eth0.10", tcp("192.0.2.30", "198.51.100.99", 443));
        let (_, v) = first(&a);
        assert_eq!(code(&v), Some(ReasonCode::NotCollected), "{v:?}");
        let Verdict::Unknown(r) = &v else {
            panic!("{v:?}");
        };
        assert!(r.detail.contains("vrf route table not collected"), "{v:?}");
        // A connected network stays definite.
        let (path, _) = first(&run(&t, "eth0.110", tcp("192.0.2.70", "192.0.2.50", 8123)));
        assert!(path.contains(&"r1/out/eth0.10".to_string()), "{path:?}");
    }

    #[test]
    fn a_static_route_that_is_not_fully_lowered_is_unknown_and_hides_no_shorter_route() {
        for route in [
            serde_json::json!({"dhcp-interface": "eth2"}),
            serde_json::json!({"next-hop": {"192.0.2.40": {"distance": "10"}}}),
            serde_json::json!({"next-hop": {"198.51.100.200": {}}}),
        ] {
            let config = super::edited(|v| {
                super::put(
                    v,
                    &[
                        "protocols",
                        "static",
                        "table",
                        "100",
                        "route",
                        "198.18.0.0/15",
                    ],
                    route.clone(),
                );
            });
            let (t, _) = build_from(&config);
            // A VPN client takes table 100.
            let a = run(&t, "eth0.10", tcp("192.0.2.10", "198.18.1.1", 443));
            let (path, v) = first(&a);
            assert!(path.contains(&"r1/route-table-100".to_string()), "{path:?}");
            assert_eq!(
                code(&v),
                Some(ReasonCode::IncompleteTable),
                "{route}: {v:?}"
            );
        }
    }

    #[test]
    fn the_ipv6_packets_of_an_interface_with_a_route6_policy_are_unknown() {
        let config = super::edited(|v| {
            super::put(
                v,
                &["policy", "route6", "PBR6"],
                serde_json::json!({"interface": "eth0.10", "rule": {"10": {"set": {"table": "100"}}}}),
            );
        });
        let (t, notes) = build_from(&config);
        assert!(notes.iter().any(|n| n.contains("PBR6")), "{notes:?}");
        let a = run(&t, "eth0.10", tcp("2001:db8::10", "2001:db8:1::1", 443));
        let (detail, _, unknown) = step(&a, "r1/pbr");
        assert!(unknown, "{detail}");
        // The IPv4 packets still take the IPv4 policy.
        let (path, _) = first(&run(&t, "eth0.10", tcp("192.0.2.10", "203.0.113.99", 443)));
        assert!(path.contains(&"r1/route-table-100".to_string()), "{path:?}");
    }

    #[test]
    fn the_packets_of_an_interface_in_a_vrf_are_unknown_at_the_route_lookup() {
        let config = super::edited(|v| {
            super::put(
                v,
                &["interfaces", "ethernet", "eth1", "vrf"],
                serde_json::json!("BLUE"),
            );
        });
        let (t, _) = build_from(&config);
        let a = run(&t, "eth1", tcp("203.0.113.130", "192.0.2.30", 443));
        let (detail, code, unknown) = step(&a, "r1/route");
        assert!(unknown, "{detail}");
        assert_eq!(code, ReasonCode::IncompleteTable, "{detail}");
    }

    #[test]
    fn an_interface_of_a_zone_vrf_has_an_unknown_zone() {
        let config = super::edited(|v| {
            super::put(
                v,
                &["interfaces", "ethernet", "eth1", "vrf"],
                serde_json::json!("BLUE"),
            );
            super::put(
                v,
                &["firewall", "zone", "LAN", "member", "vrf"],
                serde_json::json!("BLUE"),
            );
        });
        let (t, _) = build_from(&config);
        let a = run(&t, "eth1", tcp("203.0.113.130", "192.0.2.30", 443));
        let (detail, code, unknown) = step(&a, "r1/zone-src");
        assert!(unknown, "{detail}");
        assert_eq!(code, ReasonCode::NotInZone, "{detail}");
    }

    #[test]
    fn a_state_rule_does_not_match_new_packets() {
        let config = super::edited(|v| {
            super::put(
                v,
                &["firewall", "ipv4", "name", "GUEST-LAN", "rule", "5"],
                serde_json::json!({"action": "drop", "state": "established"}),
            );
        });
        let (t, _) = build_from(&config);
        let a = run(&t, "eth0.110", tcp("192.0.2.70", "192.0.2.50", 8123));
        assert!(
            !matches!(a.verdict(), Some(Verdict::Drop(_))),
            "{:?}",
            a.verdict()
        );
    }

    #[test]
    fn a_learned_route_keeps_its_protocol() {
        let mut col = collected();
        col.routes.push(route("198.51.100.0/25", "bgp", "eth1"));
        col.routes.push(route("198.51.100.128/25", "ospf", "eth1"));
        let (t, _) = build_with(CONFIG, &col);
        let mut kinds = std::collections::BTreeMap::new();
        for f in t.functions() {
            let any: &dyn std::any::Any = f.as_ref();
            if let Some(rl) = any.downcast_ref::<rsim_functions::RouteLookup>()
                && let Some(fib) = rl.tables.get(&rsim_core::VrfId::new("default"))
            {
                for (p, r) in fib.entries() {
                    kinds.insert(p.to_string(), r.kind.name());
                }
            }
        }
        assert_eq!(kinds["198.51.100.0/25"], "bgp");
        assert_eq!(kinds["198.51.100.128/25"], "ospf");
        assert_eq!(kinds["0.0.0.0/0"], "static");
        assert_eq!(kinds["192.0.2.0/26"], "connected");
    }

    #[test]
    fn the_bgp_config_of_a_vrf_without_rows_is_unhandled() {
        let config = super::edited(|v| {
            super::put(
                v,
                &["vrf", "name", "BLUE", "protocols", "bgp"],
                serde_json::json!({"system-as": "64496"}),
            );
        });
        let doc = read_json(&config).unwrap();
        let tables = rsim_ingest::route_tables::RouteTables::new(
            collected().routes.iter().map(|r| r.vrf.clone()),
            vyos::dynamic_vrfs(&doc),
        );
        let table = vyos::table(&tables);
        let network = ["address-family", "ipv4-unicast", "network"];
        let main: Vec<&str> = ["protocols", "bgp"]
            .iter()
            .chain(&network)
            .copied()
            .collect();
        assert_eq!(table.state(&main), rsim_ingest::State::Irrelevant);
        let blue: Vec<&str> = ["vrf", "name", "BLUE", "protocols", "bgp"]
            .iter()
            .chain(&network)
            .copied()
            .collect();
        assert_eq!(table.state(&blue), rsim_ingest::State::Unhandled);
        // The process and its neighbour lines are handled in each VRF.
        for path in [
            &["protocols", "bgp"][..],
            &["vrf", "name", "BLUE", "protocols", "bgp"],
            &["vrf", "name", "BLUE", "protocols", "bgp", "system-as"],
            &[
                "vrf",
                "name",
                "BLUE",
                "protocols",
                "bgp",
                "neighbor",
                "192.0.2.9",
                "remote-as",
            ],
        ] {
            assert_eq!(table.state(path), rsim_ingest::State::Handled, "{path:?}");
        }
    }

    #[test]
    fn a_learned_route_with_no_interface_resolves_through_the_table() {
        let mut col = collected();
        col.routes.push(RouteRow {
            interface: None,
            next_hop: Some("203.0.113.130".into()),
            ..route("198.51.100.0/25", "bgp", "eth1")
        });
        col.routes.push(RouteRow {
            interface: None,
            next_hop: Some("198.51.100.200".into()),
            ..route("198.51.100.128/26", "bgp", "eth1")
        });
        col.routes.push(RouteRow {
            interface: None,
            next_hop: Some("198.51.100.130".into()),
            ..route("198.51.100.192/26", "bgp", "eth1")
        });
        let (t, _) = build_with(CONFIG, &col);
        let a = run(&t, "eth0.10", tcp("192.0.2.30", "198.51.100.9", 443));
        let (detail, _, unknown) = step(&a, "r1/route");
        assert!(!unknown, "{detail}");
        assert_eq!(
            detail,
            "198.51.100.0/25 (bgp) in VRF default via 203.0.113.130 on eth1"
        );
        // FRR gives a recursive next hop and the next hop that resolves it.
        let mut col = collected();
        col.routes.push(RouteRow {
            interface: None,
            next_hop: Some("198.51.100.250".into()),
            ..route("198.51.100.0/25", "bgp", "eth1")
        });
        col.routes.push(RouteRow {
            next_hop: Some("203.0.113.130".into()),
            ..route("198.51.100.0/25", "bgp", "eth1")
        });
        let (t2, _) = build_with(CONFIG, &col);
        let a = run(&t2, "eth0.10", tcp("192.0.2.30", "198.51.100.9", 443));
        let (detail, _, unknown) = step(&a, "r1/route");
        assert!(!unknown, "{detail}");
        assert_eq!(
            detail,
            "198.51.100.0/25 (bgp) in VRF default via 203.0.113.130 on eth1"
        );
        // A loop between 2 routes.
        let a = run(&t, "eth0.10", tcp("192.0.2.30", "198.51.100.140", 443));
        let (detail, code, unknown) = step(&a, "r1/route");
        assert!(unknown, "{detail}");
        assert_eq!(code, ReasonCode::IncompleteTable);
        assert_eq!(
            detail,
            "route 198.51.100.128/26 (bgp) in VRF default: next hop not resolved: 198.51.100.200"
        );
    }
}
