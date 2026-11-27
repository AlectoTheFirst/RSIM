//! The IOS-XE coverage, the mask and the typed config on a synthetic
//! running config of a router and of a Catalyst access switch, with fake
//! secrets.

use std::collections::BTreeMap;

use rsim_ingest::collected::Collected;
use rsim_ingest::estate::{Estate, Input, assemble};
use rsim_ingest::nxos::config::{
    AclAction, AddrSpec, FhrpKind, NatKind, NatRole, PortMode, PortSpec,
};
use rsim_ingest::route_tables::RouteTables;
use rsim_ingest::{State, classify, iosxe};

const ROUTER: &[u8] = include_bytes!("fixtures/iosxe/running-config.txt");
const SWITCH: &[u8] = include_bytes!("fixtures/iosxe/switch-config.txt");

/// The fake secrets of the fixtures.
const SECRETS: &[&str] = &[
    "FAKESALT",
    "FAKEHASH",
    "FAKEPLAINPASSWORD",
    "FAKEISAKMPKEY",
    "FAKEKEYSTRING",
    "FAKEHSRPKEY",
    "FAKEBGPPASSWORD",
    "FAKECOMMUNITY",
    "FAKETACACSKEY",
    "FAKEVTYPASSWORD",
    "FAKENTPKEY",
];

/// A static route: the VRF, the prefix, the next hop, the interface and
/// the words that the reader does not read.
type RouteRow<'a> = (
    &'a str,
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
    Vec<String>,
);

/// A VLAN stanza: its ranges and its name.
type VlanRow<'a> = (Vec<(u16, u16)>, Option<&'a str>);

fn no_secret(text: &str) {
    for s in SECRETS {
        assert!(!text.contains(s), "{s} is in {text}");
    }
}

fn estate() -> Estate {
    let input = |name: &str, config: &[u8]| Input::Iosxe {
        name: name.into(),
        config: config.to_vec(),
        file: format!("{name}/config@000000000000"),
        collected: Collected::default(),
        sections: BTreeMap::new(),
    };
    assemble(vec![input("edge1", ROUTER), input("acc1", SWITCH)])
}

fn ranked(config: &[u8], rib: bool) -> Vec<(String, u32, u32)> {
    let doc = iosxe::read_text(config);
    classify(
        &doc,
        &iosxe::table(&RouteTables::uniform(rib, iosxe::dynamic_vrfs(&doc))),
    )
    .ranked()
    .into_iter()
    .map(|(p, n, l)| (p.to_string(), n, l))
    .collect()
}

fn as_str(v: &[(String, u32, u32)]) -> Vec<(&str, u32, u32)> {
    v.iter().map(|(p, n, l)| (p.as_str(), *n, *l)).collect()
}

#[test]
fn the_coverage_shares_of_the_fixtures() {
    for (config, handled, irrelevant, unhandled) in [(ROUTER, 139, 134, 27), (SWITCH, 49, 57, 4)] {
        let doc = iosxe::read_text(config);
        let cov = classify(
            &doc,
            &iosxe::table(&RouteTables::uniform(true, Default::default())),
        );
        assert_eq!(cov.lines[&State::Handled], handled);
        assert_eq!(cov.lines[&State::Irrelevant], irrelevant);
        assert_eq!(cov.lines[&State::Unhandled], unhandled);
        assert!(cov.share(State::Unhandled) < 0.11);
    }
}

#[test]
fn the_coverage_lists_the_unhandled_lines() {
    let want = [
        ("policy-map WAN-OUT", 1, 5),
        ("policy-map type inspect INSIDE-OUT-POLICY", 1, 5),
        ("class-map type inspect match-any INSIDE-TO-OUTSIDE", 1, 4),
        ("class-map match-any VOICE", 1, 2),
        (
            "zone-pair security IN-OUT source INSIDE destination OUTSIDE",
            1,
            2,
        ),
        ("interface */crypto map VPN", 1, 1),
        ("interface */ip policy route-map PBR-BLUE", 1, 1),
        (
            "interface */ip verify unicast source reachable-via rx",
            1,
            1,
        ),
        ("interface */tunnel destination 198.51.100.200", 1, 1),
        ("interface */tunnel source GigabitEthernet0/0/0", 1, 1),
        ("interface */zone-member security INSIDE", 1, 1),
        ("interface */zone-member security OUTSIDE", 1, 1),
        ("zone security INSIDE", 1, 1),
        ("zone security OUTSIDE", 1, 1),
    ];
    assert_eq!(as_str(&ranked(ROUTER, true)), want);
    let want = [
        ("interface */ip helper-address 192.0.2.53", 1, 1),
        ("interface */storm-control broadcast level 10.00", 1, 1),
        ("interface */switchport port-security", 1, 1),
        ("interface */switchport voice vlan 20", 1, 1),
    ];
    assert_eq!(as_str(&ranked(SWITCH, true)), want);
}

#[test]
fn without_a_route_table_the_routing_is_unhandled() {
    let got = ranked(ROUTER, false);
    let count = |p: &str| got.iter().find(|r| r.0 == p).map(|r| (r.1, r.2));
    assert_eq!(count("router bgp .."), None);
    assert_eq!(
        count("router bgp */address-family ../network 192.0.2.0 mask 255.255.255.0"),
        Some((1, 1))
    );
    assert_eq!(
        count("router bgp */address-family ipv4 vrf * ../redistribute connected"),
        Some((1, 1))
    );
    assert_eq!(
        count("router bgp */neighbor 198.51.100.1 password <secret>"),
        Some((1, 1))
    );
    assert_eq!(count("route-map .."), Some((2, 6)));
    assert_eq!(count("ip prefix-list .."), Some((2, 2)));
    assert_eq!(count("vrf definition */rd .."), Some((1, 1)));
    assert_eq!(
        count("vrf definition */address-family ipv4/route-target .."),
        Some((2, 2))
    );
    assert_eq!(count("ip vrf */rd .."), Some((1, 1)));
    assert_eq!(count("ip vrf */route-target .."), Some((2, 2)));
    assert_eq!(got.len(), ranked(ROUTER, true).len() + 15);
    assert_eq!(ranked(SWITCH, false), ranked(SWITCH, true));
}

#[test]
fn the_states_of_key_stanzas() {
    use State::{Handled, Irrelevant, Unhandled};
    let with = iosxe::table(&RouteTables::uniform(true, Default::default()));
    let without = iosxe::table(&RouteTables::uniform(false, Default::default()));
    let i = "interface Gi0/0/1.100";
    for (path, rib, no_rib) in [
        (&["Building configuration..."][..], Irrelevant, Irrelevant),
        (
            &["Current configuration : 9876 bytes"],
            Irrelevant,
            Irrelevant,
        ),
        (&["end"], Irrelevant, Irrelevant),
        (&["hostname edge1"], Irrelevant, Irrelevant),
        (&["enable secret 9 x"], Irrelevant, Irrelevant),
        (&["banner exec ^C", "text"], Irrelevant, Irrelevant),
        (&["crypto map VPN 10 ipsec-isakmp"], Irrelevant, Irrelevant),
        (
            &["key chain K", "key 1", "key-string 7 x"],
            Irrelevant,
            Irrelevant,
        ),
        (&["ip http server"], Irrelevant, Irrelevant),
        (&["no ip http secure-server"], Irrelevant, Irrelevant),
        (&["ip routing"], Handled, Handled),
        (&[i], Handled, Handled),
        (&[i, "vrf forwarding RED"], Handled, Handled),
        (&[i, "ip vrf forwarding BLUE"], Handled, Handled),
        (
            &[i, "ip address 192.0.2.2 255.255.255.192"],
            Handled,
            Handled,
        ),
        (&[i, "ip address dhcp"], Handled, Handled),
        (&[i, "no ip address"], Handled, Handled),
        (&[i, "ip access-group 101 out"], Handled, Handled),
        (&[i, "ip access-group 101 both"], Unhandled, Unhandled),
        (&[i, "ip nat inside"], Handled, Handled),
        (&[i, "encapsulation dot1Q 100"], Handled, Handled),
        (&[i, "encapsulation dot1q 100"], Unhandled, Unhandled),
        (&[i, "service-policy output Q"], Handled, Handled),
        (&[i, "switchport mode trunk"], Handled, Handled),
        (
            &[i, "switchport mode dynamic desirable"],
            Unhandled,
            Unhandled,
        ),
        (
            &[i, "switchport trunk encapsulation dot1q"],
            Handled,
            Handled,
        ),
        (&[i, "switchport nonegotiate"], Irrelevant, Irrelevant),
        (&[i, "switchport port-security"], Unhandled, Unhandled),
        (
            &[i, "storm-control broadcast level 10.00"],
            Unhandled,
            Unhandled,
        ),
        (&[i, "standby version 2"], Handled, Handled),
        (&[i, "standby 1 ip 192.0.2.1"], Handled, Handled),
        (&[i, "standby 1 preempt delay minimum 30"], Handled, Handled),
        (&[i, "standby 1 timers 1 3"], Irrelevant, Irrelevant),
        (
            &[i, "standby 1 authentication md5 key-string x"],
            Irrelevant,
            Irrelevant,
        ),
        (&[i, "standby use-bia"], Unhandled, Unhandled),
        (&[i, "vrrp 10 ip 192.0.2.130"], Handled, Handled),
        (&[i, "vrrp 10 address-family ipv4"], Unhandled, Unhandled),
        (&[i, "description x"], Handled, Handled),
        (&[i, "speed 1000"], Irrelevant, Irrelevant),
        (&[i, "ipv6 enable"], Irrelevant, Irrelevant),
        (&[i, "ipv6 address 2001:db8::1/64"], Handled, Handled),
        (&[i, "ip ospf cost 10"], Handled, Handled),
        (&[i, "ip ospf hello-interval 5"], Irrelevant, Unhandled),
        (&[i, "bandwidth 10000"], Handled, Handled),
        (&[i, "zone-member security INSIDE"], Unhandled, Unhandled),
        (&[i, "crypto map VPN"], Unhandled, Unhandled),
        (&[i, "ip policy route-map PBR"], Unhandled, Unhandled),
        (
            &[i, "ip verify unicast source reachable-via rx"],
            Unhandled,
            Unhandled,
        ),
        (&[i, "mpls ip"], Unhandled, Unhandled),
        (&[i, "tunnel source Gi0/0/0"], Unhandled, Unhandled),
        (&["vrf definition RED"], Handled, Handled),
        (
            &["vrf definition RED", "rd 64496:100"],
            Irrelevant,
            Unhandled,
        ),
        (
            &["vrf definition RED", "address-family ipv4"],
            Handled,
            Handled,
        ),
        (
            &[
                "vrf definition RED",
                "address-family ipv4",
                "route-target export 64496:100",
            ],
            Irrelevant,
            Unhandled,
        ),
        (
            &["vrf definition RED", "address-family ipv6"],
            Irrelevant,
            Irrelevant,
        ),
        (
            &["vrf definition RED", "exit-address-family"],
            Irrelevant,
            Irrelevant,
        ),
        (&["ip vrf BLUE"], Handled, Handled),
        (
            &["ip vrf BLUE", "route-target import 64496:200"],
            Irrelevant,
            Unhandled,
        ),
        (
            &["ip access-list extended EDGE-IN", "10 permit ip any any"],
            Handled,
            Handled,
        ),
        (
            &["ip access-list standard NAT-INSIDE", "permit any"],
            Handled,
            Handled,
        ),
        (&["access-list 101 permit ip any any"], Handled, Handled),
        (
            &["ip route vrf RED 0.0.0.0 0.0.0.0 198.51.100.1"],
            Handled,
            Handled,
        ),
        (
            &["ip nat inside source list 10 interface Gi0/0/3 overload"],
            Handled,
            Handled,
        ),
        (
            &["ip nat outside source static 198.51.100.5 192.0.2.5"],
            Unhandled,
            Unhandled,
        ),
        (
            &["ip nat pool P 203.0.113.32 203.0.113.47 netmask 255.255.255.240"],
            Handled,
            Handled,
        ),
        (&["vlan 10"], Handled, Handled),
        (&["vlan 10", "name USERS"], Handled, Handled),
        (
            &["router bgp 64496", "address-family ipv4"],
            Handled,
            Handled,
        ),
        (
            &[
                "router bgp 64496",
                "address-family ipv4",
                "network 192.0.2.0 mask 255.255.255.0",
            ],
            Irrelevant,
            Unhandled,
        ),
        (
            &["router bgp 64496", "neighbor 198.51.100.1 remote-as 64511"],
            Handled,
            Handled,
        ),
        (
            &["router bgp 64496", "neighbor 198.51.100.1 password 7 X"],
            Irrelevant,
            Unhandled,
        ),
        (&["router eigrp 10"], Irrelevant, Unhandled),
        (&["route-map PBR permit 10"], Irrelevant, Unhandled),
        (
            &["ip prefix-list P seq 5 permit 0.0.0.0/0"],
            Irrelevant,
            Unhandled,
        ),
        (
            &["ip community-list standard C permit 64496:1"],
            Irrelevant,
            Unhandled,
        ),
        (
            &["ip as-path access-list 1 permit ^$"],
            Irrelevant,
            Unhandled,
        ),
        (&["zone security INSIDE"], Unhandled, Unhandled),
        (
            &["zone-pair security A source B destination C"],
            Unhandled,
            Unhandled,
        ),
        (&["policy-map type inspect P"], Unhandled, Unhandled),
        (
            &["class-map type inspect match-any C"],
            Unhandled,
            Unhandled,
        ),
        (&["mpls label protocol ldp"], Unhandled, Unhandled),
        (&["ipv6 route ::/0 2001:db8:3::1"], Irrelevant, Irrelevant),
    ] {
        assert_eq!(with.state(path), rib, "{path:?} with a route table");
        assert_eq!(without.state(path), no_rib, "{path:?} without one");
    }
}

#[test]
fn the_lines_of_a_banner_are_not_stanzas_of_their_own() {
    let doc = iosxe::read_text(ROUTER);
    let keys: Vec<&str> = doc.root.children().iter().map(|s| s.key.as_str()).collect();
    assert!(!keys.contains(&"Authorized access only."), "{keys:?}");
    assert!(!keys.contains(&"^C"), "{keys:?}");
    let banner = doc.root.get("banner exec ^C").unwrap();
    assert_eq!(banner.children().len(), 3);
    assert!(
        doc.root
            .get("banner motd ^CLab router of the network team.^C")
            .is_some()
    );
    let switch = iosxe::read_text(SWITCH);
    assert_eq!(
        switch.root.get("banner login ^C").unwrap().children().len(),
        2
    );
}

#[test]
fn the_mask_hides_each_fake_secret_of_the_fixtures() {
    for config in [ROUTER, SWITCH] {
        for line in String::from_utf8_lossy(config).lines() {
            no_secret(&iosxe::mask(line));
        }
    }
}

#[test]
fn no_secret_reaches_the_reports() {
    for config in [ROUTER, SWITCH] {
        let doc = iosxe::read_text(config);
        for rib in [true, false] {
            let table = iosxe::table(&RouteTables::uniform(rib, iosxe::dynamic_vrfs(&doc)));
            for (path, _, _) in classify(&doc, &table).ranked() {
                no_secret(path);
            }
            let cfg = iosxe::read(&doc, &table);
            for i in &cfg.interfaces {
                for line in &i.unhandled {
                    no_secret(line);
                }
                for g in &i.fhrp {
                    for line in &g.unhandled {
                        no_secret(line);
                    }
                }
            }
            for acl in cfg.acls.values() {
                for line in &acl.unreadable {
                    no_secret(line);
                }
            }
            for rule in &cfg.nat_rules {
                if let NatKind::Other(line) = &rule.kind {
                    no_secret(line);
                }
            }
        }
    }
    let e = estate();
    for cov in e.coverage.values() {
        for (path, _, _) in cov.ranked() {
            no_secret(path);
        }
    }
    for list in e.unread.values().chain(e.notes.values()) {
        for line in list {
            no_secret(line);
        }
    }
}

#[test]
fn each_handled_line_is_read() {
    for config in [ROUTER, SWITCH] {
        let doc = iosxe::read_text(config);
        for rib in [true, false] {
            let table = iosxe::table(&RouteTables::uniform(rib, iosxe::dynamic_vrfs(&doc)));
            let cfg = iosxe::read(&doc, &table);
            assert_eq!(iosxe::unread(&doc, &table, &cfg.read), Vec::<String>::new());
        }
    }
    let e = estate();
    assert_eq!(e.unread["edge1"], Vec::<String>::new());
    assert_eq!(e.unread["acc1"], Vec::<String>::new());
}

#[test]
fn without_sections_the_estate_gives_the_coverage_and_a_twin() {
    let e = estate();
    for (name, config) in [("edge1", ROUTER), ("acc1", SWITCH)] {
        let doc = iosxe::read_text(config);
        assert_eq!(
            e.coverage[name],
            classify(
                &doc,
                &iosxe::table(&RouteTables::uniform(false, Default::default()))
            ),
            "no route table leaves the routing unhandled"
        );
    }
    assert!(e.notes["edge1"].iter().any(|n| n
        == "no route table section, each route lookup unknown, static routes of the config not lowered"));
    e.builder.build().expect("the twin builds");
}

#[test]
fn the_typed_config_of_the_router() {
    let doc = iosxe::read_text(ROUTER);
    let cfg = iosxe::read(
        &doc,
        &iosxe::table(&RouteTables::uniform(true, Default::default())),
    );
    assert_eq!(cfg.hostname.as_deref(), Some("edge1"));
    assert!(cfg.ip_routing.is_none());
    let vrfs: Vec<(&str, bool)> = cfg
        .vrfs
        .values()
        .map(|v| (v.name.as_str(), v.ipv4.is_some()))
        .collect();
    assert_eq!(vrfs, [("BLUE", true), ("MGMT", true), ("RED", true)]);
    let names: Vec<&str> = cfg.interfaces.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "Loopback0",
            "GigabitEthernet0/0/0",
            "GigabitEthernet0/0/1",
            "GigabitEthernet0/0/1.100",
            "GigabitEthernet0/0/1.200",
            "GigabitEthernet0/0/2",
            "GigabitEthernet0/0/3",
            "Tunnel10",
            "GigabitEthernet0",
            "GigabitEthernet0/0/4",
            "GigabitEthernet0/0/5",
            "GigabitEthernet0/0/6",
            "GigabitEthernet0/0/7",
        ]
    );
    let get = |n: &str| cfg.interfaces.iter().find(|i| i.name == n).unwrap();

    let wan = get("GigabitEthernet0/0/0");
    assert_eq!(wan.addresses[0].prefix, "198.51.100.2/30");
    assert_eq!(wan.acl_in.as_ref().map(|a| a.0.as_str()), Some("EDGE-IN"));
    assert_eq!(wan.nat.as_ref().map(|n| n.0), Some(NatRole::Outside));
    assert_eq!(wan.qos_out.as_ref().map(|q| q.0.as_str()), Some("WAN-OUT"));
    assert_eq!(
        wan.unhandled,
        [
            "zone-member security OUTSIDE",
            "crypto map VPN",
            "ip verify unicast source reachable-via rx",
        ]
    );

    assert!(get("GigabitEthernet0/0/1").no_address.is_some());
    let red = get("GigabitEthernet0/0/1.100");
    assert_eq!((red.lines.first, red.lines.last), (147, 164));
    assert_eq!(red.vrf.as_ref().map(|v| v.0.as_str()), Some("RED"));
    assert_eq!(red.dot1q.map(|d| (d.0, d.1)), Some((100, false)));
    let addrs: Vec<(&str, bool)> = red
        .addresses
        .iter()
        .map(|a| (a.prefix.as_str(), a.secondary))
        .collect();
    assert_eq!(addrs, [("192.0.2.2/26", false), ("192.0.2.66/26", true)]);
    assert_eq!(red.nat.as_ref().map(|n| n.0), Some(NatRole::Inside));
    assert_eq!(red.acl_out.as_ref().map(|a| a.0.as_str()), Some("101"));
    assert_eq!(red.hsrp_version.map(|v| v.0), Some(2));
    assert_eq!(red.unhandled, ["zone-member security INSIDE"]);
    let g1 = &red.fhrp[0];
    assert_eq!((g1.kind, g1.group), (FhrpKind::Hsrp, 1));
    let vips: Vec<String> = g1.addresses.iter().map(|a| a.0.to_string()).collect();
    assert_eq!(vips, ["192.0.2.1", "192.0.2.65"]);
    assert_eq!(g1.priority.map(|p| p.0), Some(110));
    assert!(g1.preempt.is_some());
    assert_eq!((g1.lines.first, g1.lines.last), (156, 159));
    assert!(g1.unhandled.is_empty());
    let g2 = &red.fhrp[1];
    assert_eq!(g2.group, 2);
    assert_eq!(
        g2.mac.map(|m| m.0),
        Some("00:00:5e:00:53:a2".parse().unwrap())
    );

    let blue = get("GigabitEthernet0/0/1.200");
    assert_eq!(blue.vrf.as_ref().map(|v| v.0.as_str()), Some("BLUE"));
    assert_eq!(blue.ip_mtu.map(|m| m.0), Some(1400));
    assert_eq!(blue.unhandled, ["ip policy route-map PBR-BLUE"]);
    let v10 = &blue.fhrp[0];
    assert_eq!((v10.kind, v10.group), (FhrpKind::Vrrp, 10));
    assert_eq!(v10.addresses[0].0.to_string(), "192.0.2.130");
    assert_eq!(v10.priority.map(|p| p.0), Some(120));

    assert_eq!(get("GigabitEthernet0/0/2").admin_up, Some(false));
    let dhcp = get("GigabitEthernet0/0/3");
    assert!(dhcp.dynamic_address.is_some());
    assert!(dhcp.addresses.is_empty());
    assert_eq!(dhcp.mtu.map(|m| m.0), Some(1500));
    assert_eq!(dhcp.ipv6[0].0, "2001:db8:3::2/64");
    assert_eq!(
        get("Tunnel10").unhandled,
        [
            "tunnel source GigabitEthernet0/0/0",
            "tunnel destination 198.51.100.200"
        ]
    );
    assert_eq!(
        get("GigabitEthernet0").vrf.as_ref().map(|v| v.0.as_str()),
        Some("MGMT")
    );

    assert_eq!(
        cfg.acls.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "10",
            "101",
            "EDGE-IN",
            "NAT-INSIDE",
            "VPN-TRAFFIC",
            "WAN2-IN"
        ]
    );
    let edge = &cfg.acls["EDGE-IN"];
    let seqs: Vec<&str> = edge.entries.iter().map(|e| e.seq.as_str()).collect();
    assert_eq!(seqs, ["10", "20", "30", "40", "50", "70"]);
    assert_eq!(edge.unreadable, ["60 permit ip object-group TRUSTED any"]);
    assert_eq!(
        edge.entries[0].destination,
        AddrSpec::Prefix("198.51.100.2/32".into())
    );
    assert_eq!(
        edge.entries[0].destination_port,
        PortSpec::Eq(vec!["443".into()])
    );
    assert_eq!(edge.entries[2].protocol, "esp");
    assert_eq!(edge.entries[3].icmp, Some(("echo-reply".to_string(), None)));
    assert!(edge.entries[4].established);
    assert_eq!(edge.entries[5].action, AclAction::Deny);
    let std = &cfg.acls["NAT-INSIDE"];
    let entries: Vec<(&str, AclAction, &AddrSpec, &AddrSpec)> = std
        .entries
        .iter()
        .map(|e| (e.seq.as_str(), e.action, &e.source, &e.destination))
        .collect();
    assert_eq!(
        entries,
        [
            (
                "10",
                AclAction::Permit,
                &AddrSpec::Wildcard("192.0.2.0".into(), "0.0.0.127".into()),
                &AddrSpec::Any
            ),
            (
                "20",
                AclAction::Permit,
                &AddrSpec::Prefix("192.0.2.200/32".into()),
                &AddrSpec::Any
            ),
            ("30", AclAction::Deny, &AddrSpec::Any, &AddrSpec::Any),
        ]
    );
    assert!(
        std.entries
            .iter()
            .all(|e| e.protocol == "ip" && e.unhandled.is_empty())
    );
    let vpn = &cfg.acls["VPN-TRAFFIC"];
    assert_eq!(vpn.entries.len(), 1);
    assert_eq!(vpn.entries[0].seq, "10");
    let n10 = &cfg.acls["10"];
    let n10: Vec<(&str, &AddrSpec)> = n10
        .entries
        .iter()
        .map(|e| (e.seq.as_str(), &e.source))
        .collect();
    assert_eq!(
        n10,
        [
            (
                "10",
                &AddrSpec::Wildcard("192.0.2.128".into(), "0.0.0.63".into())
            ),
            ("20", &AddrSpec::Prefix("192.0.2.250/32".into())),
        ]
    );
    let n101 = &cfg.acls["101"];
    assert_eq!(n101.entries.len(), 3);
    assert_eq!(
        n101.entries[1].destination_port,
        PortSpec::Eq(vec!["domain".into()])
    );
    assert_eq!((n101.lines.first, n101.lines.last), (316, 318));

    let routes: Vec<RouteRow> = cfg
        .static_routes
        .iter()
        .map(|r| {
            (
                r.vrf.as_str(),
                r.prefix.as_str(),
                r.next_hop.as_deref(),
                r.interface.as_deref(),
                r.unhandled.clone(),
            )
        })
        .collect();
    assert_eq!(
        routes,
        [
            ("default", "0.0.0.0/0", Some("198.51.100.1"), None, vec![]),
            (
                "default",
                "0.0.0.0/0",
                Some("198.51.100.9"),
                Some("GigabitEthernet0/0/3"),
                vec![]
            ),
            ("default", "203.0.113.128/25", None, Some("Null0"), vec![]),
            (
                "RED",
                "0.0.0.0/0",
                Some("198.51.100.1"),
                None,
                vec!["global".to_string()]
            ),
            ("MGMT", "0.0.0.0/0", Some("203.0.113.1"), None, vec![]),
            (
                "default",
                "198.51.100.64/26",
                Some("198.51.100.5"),
                None,
                vec![]
            ),
            (
                "default",
                "198.51.100.128/25",
                Some("198.51.100.1"),
                None,
                vec![]
            ),
            (
                "default",
                "198.51.100.128/25",
                Some("198.51.100.5"),
                None,
                vec![]
            ),
        ]
    );

    assert_eq!(cfg.nat_pools["PUBLIC"].start, "203.0.113.32");
    assert_eq!(cfg.nat_pools["PUBLIC"].end, "203.0.113.32");
    let kinds: Vec<&NatKind> = cfg.nat_rules.iter().map(|r| &r.kind).collect();
    assert_eq!(kinds.len(), 4);
    assert!(matches!(kinds[0], NatKind::List { acl, overload: true, .. } if acl == "NAT-INSIDE"));
    assert!(matches!(kinds[1], NatKind::List { acl, overload: true, .. } if acl == "10"));
    assert_eq!(
        kinds[2],
        &NatKind::Static {
            protocol: Some("tcp".into()),
            local: "192.0.2.10".into(),
            local_port: Some("443".into()),
            global: "198.51.100.2".into(),
            global_port: Some("443".into()),
            uncertain: Some("extendable".into()),
        }
    );
    assert!(
        matches!(kinds[3], NatKind::Static { local, global, uncertain: None, .. }
        if local == "192.0.2.220" && global == "203.0.113.20")
    );
}

#[test]
fn the_typed_config_of_the_switch() {
    let doc = iosxe::read_text(SWITCH);
    let cfg = iosxe::read(
        &doc,
        &iosxe::table(&RouteTables::uniform(true, Default::default())),
    );
    assert_eq!(cfg.hostname.as_deref(), Some("acc1"));
    assert_eq!(cfg.ip_routing.map(|r| r.0), Some(true));
    let vlans: Vec<VlanRow> = cfg
        .vlans
        .iter()
        .map(|v| (v.ranges.clone(), v.name.as_ref().map(|n| n.0.as_str())))
        .collect();
    assert_eq!(
        vlans,
        [
            (vec![(10, 10)], Some("USERS")),
            (vec![(20, 20)], Some("VOICE")),
            (vec![(99, 99)], Some("MGMT")),
            (vec![(100, 100), (200, 200)], None),
        ]
    );
    let get = |n: &str| cfg.interfaces.iter().find(|i| i.name == n).unwrap();
    let po = get("Port-channel1");
    assert_eq!(po.mode, Some(PortMode::Trunk));
    assert_eq!(po.allowed, Some(vec![(10, 10), (20, 20), (99, 99)]));
    let user = get("GigabitEthernet1/0/1");
    assert_eq!(user.switchport, Some(true));
    assert_eq!(user.mode, Some(PortMode::Access));
    assert_eq!(user.access_vlan, Some(10));
    assert_eq!(
        user.unhandled,
        ["switchport voice vlan 20", "switchport port-security"]
    );
    assert_eq!(
        get("GigabitEthernet1/0/2").unhandled,
        ["storm-control broadcast level 10.00"]
    );
    assert_eq!(get("GigabitEthernet1/0/3").admin_up, Some(false));
    let up = get("GigabitEthernet1/0/48");
    assert_eq!(up.channel_group.map(|c| c.0), Some(1));
    assert_eq!(up.native_vlan, Some(99));
    assert_eq!(up.allowed, Some(vec![(10, 10), (20, 20), (99, 99)]));
    assert!(up.unhandled.is_empty());
    assert_eq!(
        get("GigabitEthernet1/0/47").channel_group.map(|c| c.0),
        Some(1)
    );
    let mgmt = get("GigabitEthernet0/0");
    assert_eq!(mgmt.vrf.as_ref().map(|v| v.0.as_str()), Some("Mgmt-vrf"));
    assert_eq!(mgmt.addresses[0].prefix, "203.0.113.21/24");
    let svi = get("Vlan10");
    assert_eq!(svi.addresses[0].prefix, "192.0.2.1/25");
    assert_eq!(svi.unhandled, ["ip helper-address 192.0.2.53"]);
    assert_eq!(get("Vlan1").admin_up, Some(false));
    assert_eq!(cfg.static_routes.len(), 1);
    assert!(cfg.vrfs["Mgmt-vrf"].ipv4.is_some());
    assert!(cfg.acls.is_empty());
}

#[test]
fn the_short_names_of_the_multigigabit_ports_resolve() {
    let config = "interface TwoGigabitEthernet1/0/5\n switchport mode access\n!\ninterface FiveGigabitEthernet1/0/6\n switchport mode access\n!\n";
    let cfg = iosxe::read(
        &iosxe::read_text(config.as_bytes()),
        &iosxe::table(&RouteTables::uniform(true, Default::default())),
    );
    let names = iosxe::names(&cfg);
    assert_eq!(names.resolve("Tw1/0/5"), "TwoGigabitEthernet1/0/5");
    assert_eq!(names.resolve("Fi1/0/6"), "FiveGigabitEthernet1/0/6");
}

#[test]
fn a_named_eigrp_vrf_follows_the_rows_of_its_vrf() {
    let doc = iosxe::read_text(
        b"router eigrp CORE\n address-family ipv4 unicast vrf RED autonomous-system 10\n  network 192.0.2.0\n",
    );
    let dynamic = iosxe::dynamic_vrfs(&doc);
    assert_eq!(
        dynamic.keys().map(String::as_str).collect::<Vec<_>>(),
        ["RED", "default"]
    );
    let path = [
        "router eigrp CORE",
        "address-family ipv4 unicast vrf RED autonomous-system 10",
    ];
    let without = iosxe::table(&RouteTables::new(["default".to_string()], dynamic.clone()));
    assert_eq!(without.state(&path), State::Unhandled);
    let with = iosxe::table(&RouteTables::new(
        ["default".to_string(), "RED".to_string()],
        dynamic,
    ));
    assert_eq!(with.state(&path), State::Irrelevant);
}
