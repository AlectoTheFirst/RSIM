//! The VyOS handlers and lowering on a synthetic configuration.

use rsim_ingest::vyos::{self, config::Action, config::Family};
use rsim_ingest::{State, classify, read_json};

const CONFIG: &[u8] = include_bytes!("fixtures/vyos/r1-config.json");

#[test]
fn each_handled_stanza_is_read() {
    let doc = read_json(CONFIG).unwrap();
    let table = vyos::table(true);
    let cfg = vyos::read(&doc);
    assert_eq!(vyos::unread(&doc, &table, &cfg.read), Vec::<String>::new());
}

#[test]
fn the_coverage_names_the_unhandled_rule_option() {
    let doc = read_json(CONFIG).unwrap();
    let cov = classify(&doc, &vyos::table(true));
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
            "eth0", "eth0.10", "eth0.110", "eth2", "dum0", "lo", "pppoe0", "wg0"
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
    assert_eq!(cfg.address_groups["vpn-clients"].len(), 2);

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

    use rsim_core::{Destination, FieldValue, Header, PROTO_TCP, PROTO_UDP, ReasonCode, Verdict};
    use rsim_engine::{Answer, Executor, Query, Twin, TwinBuilder};
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
            ],
            neighbours: vec![NeighbourRow {
                interface: "eth0.10".into(),
                ip: "192.0.2.50".into(),
                mac: Some("00:00:5e:00:53:50".into()),
                state: Some("REACHABLE".into()),
                span: row_span("r1", "neighbours", "b3", 0),
            }],
        }
    }

    fn build() -> (Twin, Vec<String>) {
        let cfg = vyos::read(&read_json(CONFIG).unwrap());
        let low = vyos::lower("r1", "r1/config", &vyos::profile(), &cfg, &collected());
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
            Verdict::Deliver(_) => None,
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
        assert_eq!(code(&v), Some(ReasonCode::NoLink));
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
}
