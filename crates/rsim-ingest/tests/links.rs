//! The join of the links on hand-built summaries, with no vendor config.

use std::collections::{BTreeMap, BTreeSet};

use rsim_core::{FunctionId, Mac, SourceSpan};
use rsim_ingest::links::{AddressPeer, Neighbour, PortAddress, PortVlans, Summary, join};

fn mac(s: &str) -> Mac {
    s.parse().unwrap()
}

/// A device with the ports `ports` and the neighbour records `seen`: the
/// local port, the name and the port of the neighbour.
fn device(
    name: &str,
    ports: &[(&str, &str)],
    seen: &[(&str, Option<&str>, &str, Option<&str>)],
    section: bool,
) -> Summary {
    let mut s = Summary {
        host_name: Some(name.to_string()),
        neighbour_section: section,
        ..Summary::default()
    };
    for (p, m) in ports {
        s.entries
            .insert((*p).to_string(), FunctionId::new(format!("{name}/in/{p}")));
        s.port_macs.insert((*p).to_string(), mac(m));
        s.ports.insert((*p).to_string(), Some(PortVlans::default()));
    }
    for (i, (port, n, rp, chassis)) in seen.iter().enumerate() {
        s.neighbours.push(Neighbour {
            port: (*port).to_string(),
            name: n.map(str::to_string),
            remote_port: Some((*rp).to_string()),
            chassis: chassis.map(mac),
            port_mac: rp.parse().ok(),
            span: SourceSpan::line(format!("{name}/neighbours"), u32::try_from(i + 1).unwrap()),
        });
    }
    s
}

fn peers(devices: &BTreeMap<String, Summary>) -> (BTreeMap<String, Vec<String>>, Vec<String>) {
    let j = join(devices, &BTreeSet::new(), &BTreeSet::new());
    let mut out = BTreeMap::new();
    for (d, ext) in &j.devices {
        for (p, list) in &ext.peers {
            out.insert(
                format!("{d}:{p}"),
                list.iter().map(|x| x.target.to_string()).collect(),
            );
        }
    }
    let notes = j.notes.values().flatten().cloned().collect();
    (out, notes)
}

#[test]
fn both_ends_by_name_give_one_link() {
    let devices = BTreeMap::from([
        (
            "a".to_string(),
            device(
                "a",
                &[("p1", "00:00:5e:00:53:01")],
                &[("p1", Some("b"), "q1", None)],
                true,
            ),
        ),
        (
            "b".to_string(),
            device(
                "b",
                &[("q1", "00:00:5e:00:53:02")],
                &[("q1", Some("a"), "p1", None)],
                true,
            ),
        ),
    ]);
    let (p, notes) = peers(&devices);
    assert_eq!(p["a:p1"], ["b/in/q1"]);
    assert_eq!(p["b:q1"], ["a/in/p1"]);
    assert!(notes.is_empty(), "{notes:?}");
}

#[test]
fn one_end_is_enough_when_the_far_device_has_no_section() {
    // The far device is known by the MAC of its port.
    let devices = BTreeMap::from([
        (
            "a".to_string(),
            device(
                "a",
                &[("p1", "00:00:5e:00:53:01")],
                &[("p1", None, "00:00:5e:00:53:09", None)],
                true,
            ),
        ),
        (
            "r".to_string(),
            device("r", &[("eth0", "00:00:5e:00:53:09")], &[], false),
        ),
    ]);
    let (p, _) = peers(&devices);
    assert_eq!(p["a:p1"], ["r/in/eth0"]);
    assert_eq!(p["r:eth0"], ["a/in/p1"]);
}

#[test]
fn a_chassis_mac_names_the_device_and_the_port_name_the_port() {
    let devices = BTreeMap::from([
        (
            "a".to_string(),
            device(
                "a",
                &[("p1", "00:00:5e:00:53:01"), ("p2", "00:00:5e:00:53:03")],
                &[
                    ("p1", None, "eth1", Some("00:00:5e:00:53:09")),
                    ("p2", None, "eth7", Some("00:00:5e:00:53:09")),
                ],
                true,
            ),
        ),
        (
            "r".to_string(),
            device(
                "r",
                &[("eth0", "00:00:5e:00:53:09"), ("eth1", "00:00:5e:00:53:0a")],
                &[],
                false,
            ),
        ),
    ]);
    let (p, notes) = peers(&devices);
    assert_eq!(p["a:p1"], ["r/in/eth1"]);
    assert!(!p.contains_key("a:p2"));
    assert!(
        notes
            .iter()
            .any(|n| n.starts_with("p2: neighbour r names no port of its own")),
        "{notes:?}"
    );
}

#[test]
fn a_port_that_two_links_claim_has_no_link() {
    let devices = BTreeMap::from([
        (
            "a".to_string(),
            device("a", &[("p1", "00:00:5e:00:53:01")], &[], false),
        ),
        (
            "b".to_string(),
            device(
                "b",
                &[("q1", "00:00:5e:00:53:02")],
                &[("q1", Some("a"), "p1", None)],
                true,
            ),
        ),
        (
            "c".to_string(),
            device(
                "c",
                &[("q1", "00:00:5e:00:53:03")],
                &[("q1", Some("a"), "p1", None)],
                true,
            ),
        ),
    ]);
    let (p, notes) = peers(&devices);
    assert!(p.is_empty(), "{p:?}");
    assert!(
        notes.contains(&"p1: 2 links claim the port, no link".to_string()),
        "{notes:?}"
    );
}

#[test]
fn a_neighbour_that_does_not_report_back_gives_no_link() {
    let devices = BTreeMap::from([
        (
            "a".to_string(),
            device(
                "a",
                &[("p1", "00:00:5e:00:53:01")],
                &[("p1", Some("b"), "q1", None)],
                true,
            ),
        ),
        (
            "b".to_string(),
            device("b", &[("q1", "00:00:5e:00:53:02")], &[], true),
        ),
    ]);
    let (p, notes) = peers(&devices);
    assert!(p.is_empty(), "{p:?}");
    assert!(notes.contains(&"p1: link not reported back by the neighbour, no link".to_string()));
}

#[test]
fn a_host_name_of_more_than_one_device_names_no_neighbour() {
    let rtr = |name: &str, m: &str| Summary {
        host_name: Some("rtr1".to_string()),
        ..device(name, &[("Gi0/0/1", m)], &[], false)
    };
    let devices = BTreeMap::from([
        (
            "a".to_string(),
            device(
                "a",
                &[("p1", "00:00:5e:00:53:01")],
                &[("p1", Some("rtr1"), "Gi0/0/1", None)],
                true,
            ),
        ),
        (
            "site-a-rtr1".to_string(),
            rtr("site-a-rtr1", "00:00:5e:00:53:0a"),
        ),
        (
            "site-b-rtr1".to_string(),
            rtr("site-b-rtr1", "00:00:5e:00:53:0b"),
        ),
    ]);
    let (p, notes) = peers(&devices);
    assert!(p.is_empty(), "{p:?}");
    assert!(
        notes
            .iter()
            .any(|n| n.contains("host name rtr1 on more than one device")),
        "{notes:?}"
    );
}

#[test]
fn a_mac_on_more_than_one_port_proves_no_link() {
    // An anycast gateway MAC on 2 leaf switches.
    let devices = BTreeMap::from([
        (
            "s".to_string(),
            device(
                "s",
                &[("port/1", "00:00:5e:00:53:01")],
                &[("port/1", None, "00:00:5e:00:53:aa", None)],
                false,
            ),
        ),
        (
            "l1".to_string(),
            device("l1", &[("e1", "00:00:5e:00:53:aa")], &[], false),
        ),
        (
            "l2".to_string(),
            device("l2", &[("e1", "00:00:5e:00:53:aa")], &[], false),
        ),
    ]);
    let (p, notes) = peers(&devices);
    assert!(p.is_empty(), "{p:?}");
    assert!(
        notes
            .iter()
            .any(|n| n.contains("on more than one port, no link")),
        "{notes:?}"
    );
}

/// A router whose port `eth0` is routed: it has layer 3 addresses and is
/// not a switch port.
fn router(
    name: &str,
    port_mac: &str,
    seen: &[(&str, Option<&str>, &str, Option<&str>)],
) -> Summary {
    let mut r = device(name, &[("eth0", port_mac)], seen, true);
    r.ports.clear();
    r.l3.insert("eth0".to_string(), BTreeMap::new());
    r
}

#[test]
fn the_mac_of_a_routed_far_end_is_known_to_the_switch_port() {
    let mut devices = BTreeMap::from([
        (
            "s".to_string(),
            device(
                "s",
                &[("p1", "00:00:5e:00:53:01")],
                &[("p1", Some("r"), "eth0", None)],
                true,
            ),
        ),
        (
            "r".to_string(),
            router("r", "00:00:5e:00:53:09", &[("eth0", Some("s"), "p1", None)]),
        ),
    ]);
    let j = join(&devices, &BTreeSet::new(), &BTreeSet::new());
    assert_eq!(j.devices["s"].far_macs["p1"], mac("00:00:5e:00:53:09"));
    // The far end of the router is a switch port, so it has no MAC there.
    assert!(j.devices["r"].far_macs.is_empty());
    // A MAC that another port of the estate has too is no evidence.
    devices.insert(
        "x".to_string(),
        device("x", &[("q1", "00:00:5e:00:53:09")], &[], false),
    );
    let j = join(&devices, &BTreeSet::new(), &BTreeSet::new());
    assert_eq!(j.devices["s"].peers["p1"].len(), 1);
    assert!(j.devices["s"].far_macs.is_empty());
}

#[test]
fn a_named_neighbour_with_no_device_is_seen_by_its_section() {
    let mut a = device(
        "a",
        &[("p1", "00:00:5e:00:53:01"), ("p2", "00:00:5e:00:53:02")],
        &[],
        true,
    );
    let record = |port: &str, name: Option<&str>, rp: &str, file: &str| Neighbour {
        port: port.to_string(),
        name: name.map(str::to_string),
        remote_port: Some(rp.to_string()),
        chassis: None,
        port_mac: None,
        span: SourceSpan::line(file, 1),
    };
    // A neighbour outside the twin by LLDP and by CDP, the device b of the
    // twin, a record with no name, and a record of another section.
    a.neighbours
        .push(record("p1", Some("x"), "e1", "a/lldp@00"));
    a.neighbours.push(record("p2", Some("y"), "e2", "a/cdp@00"));
    a.neighbours.push(record("p2", Some("b"), "q1", "a/cdp@00"));
    a.neighbours.push(record("p1", None, "e3", "a/lldp@00"));
    a.neighbours
        .push(record("p1", Some("z"), "e4", "a/uplinks@00"));
    // A long name of the device b by its chassis MAC, with a port that b
    // does not have.
    let mut by_chassis = record("p1", Some("b.example.net"), "e9", "a/lldp@00");
    by_chassis.chassis = Some(mac("00:00:5e:00:53:03"));
    a.neighbours.push(by_chassis);
    let devices = BTreeMap::from([
        ("a".to_string(), a),
        (
            "b".to_string(),
            device("b", &[("q1", "00:00:5e:00:53:03")], &[], false),
        ),
    ]);
    let j = join(&devices, &BTreeSet::new(), &BTreeSet::new());
    let seen: Vec<(&str, &str, &str, &str)> = j
        .seen
        .iter()
        .map(|s| {
            (
                s.device.as_str(),
                s.port.as_str(),
                s.name.as_str(),
                s.protocol,
            )
        })
        .collect();
    assert_eq!(seen, [("a", "p1", "x", "lldp"), ("a", "p2", "y", "cdp")]);
    assert_eq!(j.seen[0].remote_port.as_deref(), Some("e1"));
}

/// A switch `sw` with the edge access port `p1` in VLAN 10, an ARP row of
/// `addr` with the MAC `00:00:5e:00:53:40`, and the MAC table row of that
/// MAC on `p1`.
fn arp_switch(addr: &str) -> Summary {
    let mut s = device("sw", &[("p1", "00:00:5e:00:53:01")], &[], false);
    s.ports.insert(
        "p1".to_string(),
        Some(PortVlans {
            native: Some(10),
            edge: true,
            ..PortVlans::default()
        }),
    );
    let m = mac("00:00:5e:00:53:40");
    s.arp
        .push((10, addr.parse().unwrap(), m, SourceSpan::line("sw/arp", 1)));
    s.macs
        .insert((10, m), ("p1".to_string(), SourceSpan::line("sw/macs", 1)));
    s
}

/// A device with no MAC whose ports the join links by address: the port
/// `port` with the address `addr` in the VRF `vrf`.
fn by_address(name: &str, port: &str, addr: &str, vrf: Option<&str>) -> Summary {
    let mut s = Summary {
        by_address: true,
        ..Summary::default()
    };
    s.entries.insert(
        port.to_string(),
        FunctionId::new(format!("{name}/in/{port}")),
    );
    s.port_addresses.push(PortAddress {
        port: port.to_string(),
        address: addr.parse().unwrap(),
        vlan: None,
        vrf: vrf.map(str::to_string),
        spans: vec![SourceSpan::line(format!("{name}/config"), 1)],
    });
    s
}

/// A router `name` with the routed port `eth1` and its address `addr` in
/// the VRF `vrf`.
fn router(name: &str, addr: &str, vrf: Option<&str>) -> Summary {
    let mut s = device(name, &[("eth1", "00:00:5e:00:53:21")], &[], false);
    s.ports.clear();
    s.port_addresses.push(PortAddress {
        port: "eth1".to_string(),
        address: addr.parse().unwrap(),
        vlan: None,
        vrf: vrf.map(str::to_string),
        spans: vec![SourceSpan::line(format!("{name}/config"), 2)],
    });
    s
}

/// The address `addr` as the gateway of the port `wan` of `edge`, in the
/// VRF `vrf`.
fn gateway(edge: &mut Summary, addr: &str, vrf: Option<&str>) {
    edge.address_peers.push(AddressPeer {
        port: "wan".to_string(),
        address: addr.parse().unwrap(),
        vrf: vrf.map(str::to_string),
        spans: vec![SourceSpan::line("edge/config", 3)],
    });
}

#[test]
fn an_address_of_one_port_gives_a_link() {
    let mut edge = by_address("edge", "lan", "192.0.2.40", Some("corp"));
    edge.entries
        .insert("wan".to_string(), FunctionId::new("edge/in/wan"));
    gateway(&mut edge, "198.51.100.1", None);
    let devices = BTreeMap::from([
        ("edge".to_string(), edge),
        ("r".to_string(), router("r", "198.51.100.1", None)),
        ("sw".to_string(), arp_switch("192.0.2.40")),
    ]);
    let (links, notes) = peers(&devices);
    assert_eq!(links["sw:p1"], ["edge/in/lan"], "{notes:?}");
    assert_eq!(links["edge:lan"], ["sw/in/p1"]);
    assert_eq!(links["edge:wan"], ["r/in/eth1"]);
    assert_eq!(links["r:eth1"], ["edge/in/wan"]);
}

#[test]
fn an_address_of_2_ports_gives_no_link_and_a_note() {
    let mut edge = by_address("edge", "wan", "198.51.100.10", None);
    gateway(&mut edge, "198.51.100.1", None);
    let devices = BTreeMap::from([
        ("edge".to_string(), edge),
        ("r1".to_string(), router("r1", "198.51.100.1", None)),
        ("r2".to_string(), router("r2", "198.51.100.1", None)),
    ]);
    let (links, notes) = peers(&devices);
    assert!(links.is_empty(), "{links:?}");
    assert!(
        notes.contains(&"wan: 198.51.100.1 is on more than one port, no link".to_string()),
        "{notes:?}"
    );
}

#[test]
fn a_shared_public_address_gives_no_link() {
    let mut e1 = by_address("e1", "lan", "192.0.2.41", None);
    e1.shared_addresses.insert("203.0.113.5".parse().unwrap());
    let mut e2 = by_address("e2", "lan", "192.0.2.42", None);
    e2.shared_addresses.insert("203.0.113.5".parse().unwrap());
    let devices = BTreeMap::from([
        ("e1".to_string(), e1),
        ("e2".to_string(), e2),
        ("sw".to_string(), arp_switch("203.0.113.5")),
    ]);
    let (links, notes) = peers(&devices);
    assert!(links.is_empty(), "{links:?}");
    assert!(
        notes.contains(&"ARP row 203.0.113.5 is a shared address, no link".to_string()),
        "{notes:?}"
    );
}

#[test]
fn an_address_of_a_device_linked_by_address_is_no_endpoint() {
    let devices = BTreeMap::from([
        (
            "edge".to_string(),
            by_address("edge", "lan", "192.0.2.40", None),
        ),
        ("sw".to_string(), arp_switch("192.0.2.40")),
    ]);
    let j = join(&devices, &BTreeSet::new(), &BTreeSet::new());
    assert!(
        j.devices.get("sw").is_none_or(|x| x.endpoints.is_empty()),
        "an endpoint is placed"
    );
    let notes: Vec<&String> = j.notes.values().flatten().collect();
    assert!(
        notes
            .iter()
            .any(|n| n.ends_with("an address of a device of the twin, not an endpoint")),
        "{notes:?}"
    );
}

#[test]
fn an_address_in_another_vrf_gives_no_link() {
    let mut edge = by_address("edge", "wan", "198.51.100.10", Some("blue"));
    gateway(&mut edge, "198.51.100.1", Some("blue"));
    let devices = BTreeMap::from([
        ("edge".to_string(), edge),
        ("r".to_string(), router("r", "198.51.100.1", Some("red"))),
    ]);
    let (links, notes) = peers(&devices);
    assert!(links.is_empty(), "{links:?}");
    assert!(
        notes.contains(&"wan: 198.51.100.1 is in another VRF, no link".to_string()),
        "{notes:?}"
    );
}
