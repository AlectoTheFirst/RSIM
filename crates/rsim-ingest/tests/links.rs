//! The join of the links on hand-built summaries, with no vendor config.

use std::collections::{BTreeMap, BTreeSet};

use rsim_core::{FunctionId, Mac, SourceSpan};
use rsim_ingest::links::{Neighbour, PortVlans, Summary, join};

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
            .any(|n| n.starts_with("p2: the neighbour r names no port of its own")),
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
        notes.contains(&"p1: 2 links claim the port, so it has no link".to_string()),
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
    assert!(notes.contains(
        &"p1: the neighbour does not report the link back, so the port has no link".to_string()
    ));
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
            .any(|n| n.contains("is on more than one port, so it proves no link")),
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
