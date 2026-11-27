//! The IOS-XR coverage, the mask and the typed config on a synthetic running
//! config with fake secrets.

use rsim_ingest::collected::Collected;
use rsim_ingest::estate::{Estate, Input, assemble};
use rsim_ingest::nxos::config::{AclAction, AddrSpec, PortSpec};
use rsim_ingest::route_tables::RouteTables;
use rsim_ingest::{State, classify, iosxr};

const CONFIG: &[u8] = include_bytes!("fixtures/iosxr/running-config.txt");

/// The fake secrets of the fixture.
const SECRETS: &[&str] = &[
    "FAKESALT",
    "FAKEHASH",
    "FAKEOPERPASSWORD",
    "FAKETACACSKEY",
    "FAKERADIUSKEY",
    "FAKEKEYSTRING",
    "FAKEFTPPASSWORD",
    "FAKECOMMUNITY",
    "FAKECOMMUNITYHOST",
    "FAKEOSPFKEY",
    "FAKEBGPPASSWORD",
    "FAKEHSRPKEY",
];

fn no_secret(text: &str) {
    for s in SECRETS {
        assert!(!text.contains(s), "{s} is in {text}");
    }
}

fn estate() -> Estate {
    assemble(vec![Input::Iosxr {
        name: "pe1".into(),
        config: CONFIG.to_vec(),
        file: "pe1/config@000000000000".into(),
        collected: Collected::default(),
        sections: Default::default(),
    }])
}

fn ranked(rib: bool) -> Vec<(String, u32, u32)> {
    let doc = iosxr::read_text(CONFIG);
    classify(
        &doc,
        &iosxr::table(&RouteTables::uniform(rib, iosxr::dynamic_vrfs(&doc))),
    )
    .ranked()
    .into_iter()
    .map(|(p, n, l)| (p.to_string(), n, l))
    .collect()
}

#[test]
fn the_coverage_shares_of_the_fixture() {
    let doc = iosxr::read_text(CONFIG);
    let cov = classify(
        &doc,
        &iosxr::table(&RouteTables::uniform(true, Default::default())),
    );
    assert_eq!(cov.lines[&State::Handled], 120);
    assert_eq!(cov.lines[&State::Irrelevant], 122);
    assert_eq!(cov.lines[&State::Unhandled], 5);
    assert!(cov.share(State::Unhandled) < 0.05);
}

#[test]
fn the_coverage_lists_the_unhandled_lines() {
    let want = [
        ("mpls ldp", 1, 3),
        ("ftp client password <secret>", 1, 1),
        (
            "interface */ipv4 verify unicast source reachable-via rx",
            1,
            1,
        ),
    ];
    let got = ranked(true);
    let got: Vec<(&str, u32, u32)> = got.iter().map(|(p, n, l)| (p.as_str(), *n, *l)).collect();
    assert_eq!(got, want);
}

#[test]
fn without_a_route_table_the_routing_protocols_and_policies_are_unhandled() {
    let got = ranked(false);
    let paths: Vec<&str> = got.iter().map(|r| r.0.as_str()).collect();
    for p in [
        "router bgp */vrf */address-family ../redistribute connected",
        "router bgp */bgp router-id 203.0.113.1",
        "router static ..",
        "route-policy ..",
        "end-policy",
        "prefix-set ..",
        "community-set ..",
        "end-set",
        "vrf */address-family ..",
        "vrf */rd ..",
    ] {
        assert!(paths.contains(&p), "{p} is not in {paths:?}");
    }
    let count = |p: &str| got.iter().find(|r| r.0 == p).map(|r| r.1);
    assert_eq!(count("end-policy"), Some(2));
    assert_eq!(count("end-set"), Some(2));
    assert_eq!(count("route-policy .."), Some(2));
    assert_eq!(count("vrf */address-family .."), Some(3));
}

#[test]
fn the_states_of_key_stanzas() {
    use State::{Handled, Irrelevant, Unhandled};
    let with = iosxr::table(&RouteTables::uniform(true, Default::default()));
    let without = iosxr::table(&RouteTables::uniform(false, Default::default()));
    for (path, rib, no_rib) in [
        (&["Tue Nov 17 10:00:00.000 UTC"][..], Irrelevant, Irrelevant),
        (&["Building configuration..."], Irrelevant, Irrelevant),
        (&["end"], Irrelevant, Irrelevant),
        (&["hostname pe1"], Irrelevant, Irrelevant),
        (&["username admin", "secret 10 x"], Irrelevant, Irrelevant),
        (&["key chain KC1", "key 1"], Irrelevant, Irrelevant),
        (&["interface Bundle-Ether20.100"], Handled, Handled),
        (
            &[
                "interface Bundle-Ether20.100",
                "ipv4 access-group RED-OUT egress",
            ],
            Handled,
            Handled,
        ),
        (
            &["interface Gi0/0/0/3", "ipv4 access-group EDGE-IN ingress"],
            Handled,
            Handled,
        ),
        (
            &["interface Gi0/0/0/3", "ipv4 access-group EDGE-IN both"],
            Unhandled,
            Unhandled,
        ),
        (
            &["interface Gi0/0/0/3", "service-policy input Q"],
            Handled,
            Handled,
        ),
        (&["interface Gi0/0/0/3", "description x"], Handled, Handled),
        (&["interface preconfigure Gi0/0/0/9"], Unhandled, Unhandled),
        (&["vrf RED"], Handled, Handled),
        (&["vrf RED", "description x"], Irrelevant, Irrelevant),
        (&["vrf RED", "rd 64496:100"], Irrelevant, Unhandled),
        (
            &[
                "vrf RED",
                "address-family ipv4 unicast",
                "import route-target",
            ],
            Irrelevant,
            Unhandled,
        ),
        (&["ipv4 access-list EDGE-IN", "20 permit"], Handled, Handled),
        (&["ipv6 access-list EDGE6-IN"], Irrelevant, Irrelevant),
        (&["route-policy PASS", "pass"], Irrelevant, Unhandled),
        (&["end-policy"], Irrelevant, Unhandled),
        (&["prefix-set PS-CUSTOMER"], Irrelevant, Unhandled),
        (&["end-set"], Irrelevant, Unhandled),
        (&["router static"], Irrelevant, Unhandled),
        (&["router bgp 64496", "neighbor x"], Handled, Handled),
        (
            &["router bgp 64496", "neighbor x", "remote-as 1"],
            Handled,
            Handled,
        ),
        (
            &[
                "router bgp 64496",
                "neighbor x",
                "address-family ipv4 unicast",
                "route-policy P in",
            ],
            Irrelevant,
            Unhandled,
        ),
        (&["mpls ldp"], Unhandled, Unhandled),
        (&["segment-routing"], Unhandled, Unhandled),
        (&["l2vpn"], Unhandled, Unhandled),
        (&["evpn"], Unhandled, Unhandled),
        (&["multicast-routing"], Unhandled, Unhandled),
        (&["router pim"], Unhandled, Unhandled),
        (&["router hsrp"], Handled, Handled),
        (
            &["router hsrp", "interface Bundle-Ether20.100"],
            Handled,
            Handled,
        ),
        (
            &["router hsrp", "interface BE20.100", "address-family ipv4"],
            Handled,
            Handled,
        ),
        (
            &["router hsrp", "interface BE20.100", "address-family ipv6"],
            Irrelevant,
            Irrelevant,
        ),
        (
            &["router hsrp", "interface BE20.100", "hsrp use-bia"],
            Unhandled,
            Unhandled,
        ),
        (
            &[
                "router hsrp",
                "interface BE20.100",
                "address-family ipv4",
                "hsrp 3 version 2",
                "address 192.0.2.5",
            ],
            Handled,
            Handled,
        ),
        (
            &[
                "router hsrp",
                "interface BE20.100",
                "address-family ipv4",
                "hsrp 1",
                "timers 1 3",
            ],
            Irrelevant,
            Irrelevant,
        ),
        (
            &[
                "router hsrp",
                "interface BE20.100",
                "address-family ipv4",
                "hsrp 1",
                "address learn",
            ],
            Handled,
            Handled,
        ),
        (&["router vrrp"], Unhandled, Unhandled),
    ] {
        assert_eq!(with.state(path), rib, "{path:?} with a route table");
        assert_eq!(without.state(path), no_rib, "{path:?} without one");
    }
}

#[test]
fn the_mask_hides_each_fake_secret_of_the_fixture() {
    let text = String::from_utf8_lossy(CONFIG);
    for line in text.lines() {
        no_secret(&iosxr::mask(line));
    }
}

#[test]
fn no_secret_reaches_the_reports() {
    let doc = iosxr::read_text(CONFIG);
    for rib in [true, false] {
        let table = iosxr::table(&RouteTables::uniform(rib, iosxr::dynamic_vrfs(&doc)));
        for (path, _, _) in classify(&doc, &table).ranked() {
            no_secret(path);
        }
        let cfg = iosxr::read(&doc, &table);
        for i in &cfg.interfaces {
            for line in &i.unhandled {
                no_secret(line);
            }
        }
        for acl in cfg.acls.values() {
            for line in &acl.unreadable {
                no_secret(line);
            }
        }
    }
    let e = estate();
    for (path, _, _) in e.coverage["pe1"].ranked() {
        no_secret(path);
    }
    for list in e.unread.values().chain(e.notes.values()) {
        for line in list {
            no_secret(line);
        }
    }
}

#[test]
fn each_handled_line_is_read() {
    let doc = iosxr::read_text(CONFIG);
    for rib in [true, false] {
        let table = iosxr::table(&RouteTables::uniform(rib, iosxr::dynamic_vrfs(&doc)));
        let cfg = iosxr::read(&doc, &table);
        assert_eq!(iosxr::unread(&doc, &table, &cfg.read), Vec::<String>::new());
    }
    assert_eq!(estate().unread["pe1"], Vec::<String>::new());
}

#[test]
fn without_a_route_table_section_the_routing_is_unhandled() {
    let e = estate();
    let doc = iosxr::read_text(CONFIG);
    assert_eq!(
        e.coverage["pe1"],
        classify(
            &doc,
            &iosxr::table(&RouteTables::uniform(false, Default::default()))
        ),
        "no route table leaves the routing unhandled"
    );
    assert!(
        e.notes["pe1"]
            .iter()
            .any(|n| n == "no route table section, each route lookup unknown")
    );
}

#[test]
fn the_typed_config() {
    let doc = iosxr::read_text(CONFIG);
    let cfg = iosxr::read(
        &doc,
        &iosxr::table(&RouteTables::uniform(true, Default::default())),
    );
    assert_eq!(cfg.hostname.as_deref(), Some("pe1"));
    assert_eq!(
        cfg.vrfs.keys().map(String::as_str).collect::<Vec<_>>(),
        ["BLUE", "MGMT", "RED"]
    );
    let names: Vec<&str> = cfg.interfaces.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "Bundle-Ether10",
            "Bundle-Ether20",
            "Bundle-Ether20.100",
            "Bundle-Ether20.200",
            "Loopback0",
            "MgmtEth0/RP0/CPU0/0",
            "GigabitEthernet0/0/0/0",
            "GigabitEthernet0/0/0/1",
            "GigabitEthernet0/0/0/2",
            "GigabitEthernet0/0/0/3",
            "GigabitEthernet0/0/0/4",
        ]
    );
    let get = |n: &str| cfg.interfaces.iter().find(|i| i.name == n).unwrap();

    let be10 = get("Bundle-Ether10");
    assert_eq!(be10.mtu.map(|m| m.0), Some(9216));
    assert_eq!(be10.addresses[0].prefix, "198.51.100.1/30");
    assert_eq!(be10.ipv6[0].0, "2001:db8:10::1/64");
    assert!(be10.unhandled.is_empty());

    let sub = get("Bundle-Ether20.100");
    assert_eq!(sub.vrf.as_ref().map(|v| v.0.as_str()), Some("RED"));
    let addrs: Vec<(&str, bool)> = sub
        .addresses
        .iter()
        .map(|a| (a.prefix.as_str(), a.secondary))
        .collect();
    assert_eq!(addrs, [("192.0.2.1/26", false), ("192.0.2.65/26", true)]);
    assert_eq!(sub.dot1q.map(|d| d.0), Some(100));
    assert!(sub.acl_in.is_none());
    assert_eq!(sub.acl_out.as_ref().map(|a| a.0.as_str()), Some("RED-OUT"));
    assert_eq!(sub.qos_in.as_ref().map(|q| q.0.as_str()), Some("QOS-IN"));
    assert_eq!(sub.qos_out.as_ref().map(|q| q.0.as_str()), Some("QOS-OUT"));
    assert!(!sub.shutdown);
    assert_eq!((sub.lines.first, sub.lines.last), (125, 132));
    assert_eq!(sub.dot1q.unwrap().1.first, 130);

    let blue = get("Bundle-Ether20.200");
    assert_eq!(
        blue.unhandled,
        ["ipv4 verify unicast source reachable-via rx"]
    );

    assert_eq!(get("GigabitEthernet0/0/0/0").bundle.map(|b| b.0), Some(10));
    assert_eq!(get("GigabitEthernet0/0/0/2").bundle.map(|b| b.0), Some(20));
    let edge = get("GigabitEthernet0/0/0/3");
    assert_eq!(edge.acl_in.as_ref().map(|a| a.0.as_str()), Some("EDGE-IN"));
    assert!(edge.vrf.is_none());
    assert!(get("GigabitEthernet0/0/0/4").shutdown);
    assert!(get("GigabitEthernet0/0/0/4").addresses.is_empty());

    assert_eq!(
        cfg.acls.keys().map(String::as_str).collect::<Vec<_>>(),
        ["EDGE-IN", "RED-OUT"]
    );
    let acl = &cfg.acls["EDGE-IN"];
    let seqs: Vec<&str> = acl.entries.iter().map(|e| e.seq.as_str()).collect();
    assert_eq!(seqs, ["20", "30", "40", "50", "70"]);
    assert_eq!(acl.unreadable, ["60 permit ipv4 any net-group INTERNAL"]);
    let e20 = &acl.entries[0];
    assert_eq!(e20.action, AclAction::Permit);
    assert_eq!(e20.protocol, "tcp");
    assert_eq!(e20.source, AddrSpec::Any);
    assert_eq!(e20.destination, AddrSpec::Prefix("203.0.113.10/32".into()));
    assert_eq!(e20.destination_port, PortSpec::Eq(vec!["www".into()]));
    let e40 = &acl.entries[2];
    assert_eq!(
        e40.source,
        AddrSpec::Wildcard("198.51.100.0".into(), "0.0.0.255".into())
    );
    assert_eq!(
        acl.entries[3].icmp,
        Some(("echo".to_string(), None::<String>))
    );
    let deny = &acl.entries[4];
    assert_eq!(deny.action, AclAction::Deny);
    assert_eq!(deny.protocol, "ipv4");
    assert!(deny.unhandled.is_empty());
    assert_eq!(cfg.acls["RED-OUT"].entries.len(), 2);

    let groups: Vec<(&str, u32, Vec<String>)> = cfg
        .hsrp
        .iter()
        .map(|g| {
            (
                g.interface.as_str(),
                g.group,
                g.addresses.iter().map(|a| a.0.to_string()).collect(),
            )
        })
        .collect();
    assert_eq!(
        groups,
        [
            ("Bundle-Ether20.100", 1, vec!["192.0.2.3".to_string()]),
            ("Bundle-Ether20.100", 2, vec!["192.0.2.4".to_string()]),
            ("Bundle-Ether20.100", 3, vec!["192.0.2.5".to_string()]),
        ]
    );
    let g1 = &cfg.hsrp[0];
    assert_eq!(g1.priority.map(|p| p.0), Some(110));
    assert!(g1.preempt.is_some());
    assert!(g1.unhandled.is_empty());
    assert_eq!(
        cfg.hsrp[1].mac.map(|m| m.0),
        Some("00:00:5e:00:53:a2".parse().unwrap())
    );
    assert_eq!(cfg.hsrp[2].version.map(|v| v.0), Some(2));
}

#[test]
fn an_hsrp_line_that_is_not_read_goes_to_the_group() {
    let text = String::from_utf8_lossy(CONFIG)
        .replace("    preempt\n", "    preempt\n    address learn\n")
        .replace(
            " interface Bundle-Ether20.100\n  address-family ipv4\n",
            " interface Bundle-Ether20.100\n  hsrp use-bia\n  address-family ipv4\n",
        );
    let doc = iosxr::read_text(text.as_bytes());
    let table = iosxr::table(&RouteTables::uniform(true, Default::default()));
    let cfg = iosxr::read(&doc, &table);
    assert_eq!(
        cfg.hsrp[0].unhandled,
        ["address learn", "hsrp use-bia"],
        "{:?}",
        cfg.hsrp
    );
    assert_eq!(cfg.hsrp[1].unhandled, ["hsrp use-bia"]);
    assert_eq!(iosxr::unread(&doc, &table, &cfg.read), Vec::<String>::new());
}

#[test]
fn router_static_gives_the_static_routes_of_the_default_vrf_and_of_each_vrf() {
    let doc = iosxr::read_text(CONFIG);
    let table = iosxr::table(&RouteTables::uniform(false, iosxr::dynamic_vrfs(&doc)));
    let cfg = iosxr::read(&doc, &table);
    let got: Vec<(&str, &str, Option<&str>, u8)> = cfg
        .static_routes
        .iter()
        .map(|r| {
            (
                r.vrf.as_str(),
                r.prefix.as_str(),
                r.next_hop.as_deref(),
                r.preference,
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            ("default", "0.0.0.0/0", Some("203.0.113.254"), 1),
            ("RED", "192.0.2.192/27", Some("192.0.2.10"), 1),
        ]
    );
    assert!(cfg.static_routes.iter().all(|r| r.unhandled.is_empty()));
}
