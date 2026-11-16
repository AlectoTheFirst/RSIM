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
