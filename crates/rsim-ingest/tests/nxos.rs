//! The NX-OS coverage on a synthetic running config with fake secrets.

use std::collections::BTreeMap;

use rsim_ingest::collected::Collected;
use rsim_ingest::estate::{Input, assemble};
use rsim_ingest::{State, classify, nxos};

const CONFIG: &[u8] = include_bytes!("fixtures/nxos/leaf1-running-config.txt");

/// The fake secrets of the fixture.
const SECRETS: &[&str] = &[
    "FAKESALT",
    "FAKEHASH",
    "FAKETACACSKEY",
    "FAKETACACSHOSTKEY",
    "FAKECOMMUNITY",
    "FAKECOMMUNITYHOST",
    "0xFAKE",
    "FAKEKEYSTRING",
    "FAKEHSRPKEY",
    "FAKEOSPFKEY",
    "FAKEBGPPASSWORD",
    "FAKEUNLISTEDKEY",
];

fn no_secret(text: &str) {
    for s in SECRETS {
        assert!(!text.contains(s), "{s} is in {text}");
    }
}

#[test]
fn the_coverage_lists_the_unhandled_lines() {
    let doc = nxos::read_text(CONFIG);
    let cov = classify(&doc, &nxos::table(true));
    let mut paths: Vec<&str> = cov.ranked().iter().map(|r| r.0).collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        [
            "interface Ethernet1/1",
            "interface Ethernet1/2",
            "interface Vlan10",
            "interface Vlan20",
            "interface loopback0",
            "interface mgmt0",
            "interface port-channel10",
            "ip access-list WEB",
            "ip nat inside source static 192.0.2.5 198.51.100.5",
            "ip ospf authentication-key <secret>",
            "ip route 0.0.0.0/0 198.51.100.2",
            "vlan 1,10,20",
            "vlan 10",
            "vlan 20",
            "vrf context RED",
            "vrf context management",
        ]
    );
    assert!(cov.lines[&State::Irrelevant] > 0);
}

#[test]
fn no_secret_reaches_the_coverage_or_the_notes() {
    let doc = nxos::read_text(CONFIG);
    for rib in [true, false] {
        let cov = classify(&doc, &nxos::table(rib));
        for (path, _, _) in cov.ranked() {
            no_secret(path);
        }
    }
    let e = assemble(vec![Input::Nxos {
        name: "leaf1".into(),
        config: CONFIG.to_vec(),
        file: "leaf1/config@000000000000".into(),
        collected: Collected::default(),
    }]);
    let cov = &e.coverage["leaf1"];
    for (path, _, _) in cov.ranked() {
        no_secret(path);
    }
    for list in e.unread.values().chain(e.notes.values()) {
        for line in list {
            no_secret(line);
        }
    }
    assert_eq!(e.unread["leaf1"], Vec::<String>::new());
    assert_eq!(
        e.notes,
        BTreeMap::from([(
            "leaf1".to_string(),
            vec![
                "the NX-OS lowering is not built: the twin has no function of this switch"
                    .to_string()
            ]
        )])
    );
}

#[test]
fn without_a_route_table_the_routing_protocols_are_unhandled() {
    let doc = nxos::read_text(CONFIG);
    let cov = classify(&doc, &nxos::table(false));
    let paths: Vec<&str> = cov.ranked().iter().map(|r| r.0).collect();
    assert!(paths.contains(&"router ospf .."), "{paths:?}");
    assert!(paths.contains(&"router bgp .."));
}
