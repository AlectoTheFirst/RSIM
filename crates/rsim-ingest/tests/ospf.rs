//! The OSPF readers on the synthetic sections in `tests/fixtures/ospf/`:
//! the same OSPFv2 and OSPFv3 database in the format of each vendor. The
//! OSPFv2 formats follow the readers of HST. The FRR OSPFv3 keys of the
//! LSAs come from the FRR source, and the other OSPFv3 formats follow the
//! OSPFv2 formats of the same vendor. No format is confirmed on a device.

use std::collections::BTreeMap;

use rsim_core::SourceSpan;
use rsim_ingest::bgp::{Collected, Outcome};
use rsim_ingest::ospf::{self, DeviceOspf, OspfSections, V2, V3};
use rsim_routing::Platform;
use rsim_routing::ospf::{Calculation, LsaType, OspfProfile, Version, compute};

const VENDORS: [&str; 4] = ["nxos", "iosxe", "iosxr", "vyos"];

fn ext(vendor: &str) -> &'static str {
    if vendor == "nxos" || vendor == "vyos" {
        "json"
    } else {
        "txt"
    }
}

fn fixture(vendor: &str, name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/ospf/{vendor}/{name}.{}",
        env!("CARGO_MANIFEST_DIR"),
        ext(vendor)
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

/// Each OSPF section of a vendor as a fresh read of its fixture.
fn sections(vendor: &str) -> OspfSections {
    V2.names()
        .into_iter()
        .chain(V3.names())
        .map(|n| {
            (
                n.to_string(),
                Collected::Fresh(fixture(vendor, n), format!("r1/{n}")),
            )
        })
        .collect()
}

fn platform(vendor: &str) -> Platform {
    match vendor {
        "nxos" => Platform::Nxos,
        "iosxe" => Platform::Iosxe,
        "iosxr" => Platform::Iosxr,
        _ => Platform::FrrTraditional,
    }
}

/// The calculation of the one database of a version.
fn calc(vendor: &str, d: &DeviceOspf, version: Version) -> Calculation {
    let dbs: Vec<_> = d.of(version, "default").collect();
    assert_eq!(dbs.len(), 1, "{vendor} {version:?}");
    let db = dbs[0];
    let rid = db
        .router_id
        .unwrap_or_else(|| panic!("{vendor}: no router ID"));
    compute(db, rid, &OspfProfile::of(platform(vendor)))
}

/// Each route as its prefix, path type, metric and next hops.
fn rows(c: &Calculation) -> Vec<String> {
    c.routes
        .iter()
        .map(|r| {
            let hops: Vec<String> = r.next_hops.iter().map(|h| h.gateway.to_string()).collect();
            format!(
                "{} {} {} {}",
                r.prefix,
                r.path_type.name(),
                r.metric,
                hops.join(",")
            )
        })
        .collect()
}

fn interfaces(vendor: &str) -> [&'static str; 2] {
    match vendor {
        "nxos" => ["Ethernet1/1", "Ethernet1/2"],
        "iosxe" => ["GigabitEthernet1", "GigabitEthernet2"],
        "iosxr" => ["GigabitEthernet0/0/0/0", "GigabitEthernet0/0/0/1"],
        _ => ["eth0", "eth1"],
    }
}

#[test]
fn each_vendor_gives_each_ospfv2_lsa_type_and_the_same_routes() {
    for vendor in VENDORS {
        let d = ospf::read(vendor, &sections(vendor));
        let o = &d.outcomes[&Version::V2];
        assert_eq!(o.outcome, Outcome::Complete, "{vendor}: {:?}", o.detail);
        assert!(o.scope.covers("default", "ipv4"), "{vendor}");
        let db = d.of(Version::V2, "default").next().unwrap();
        let mut count: BTreeMap<LsaType, usize> = BTreeMap::new();
        for l in db.lsas.values() {
            *count.entry(l.lsa_type).or_default() += 1;
        }
        assert_eq!(
            count.into_iter().collect::<Vec<_>>(),
            [
                (LsaType::Router, 5),
                (LsaType::Network, 1),
                (LsaType::Summary, 2),
                (LsaType::AsbrSummary, 1),
                (LsaType::External, 1),
                (LsaType::NssaExternal, 1),
            ],
            "{vendor}"
        );
        assert_eq!(db.interfaces.len(), 2, "{vendor}");
        assert_eq!(db.neighbors.len(), 2, "{vendor}");
        let c = calc(vendor, &d, Version::V2);
        assert!(
            c.gaps.is_empty() && c.notes.is_empty(),
            "{vendor}: {:?} {:?}",
            c.gaps,
            c.notes
        );
        assert!(c.area_border_router, "{vendor}");
        assert_eq!(
            rows(&c),
            [
                "192.0.2.64/26 intra-area 20 192.0.2.2",
                "198.51.100.2/32 intra-area 11 192.0.2.2",
                "198.51.100.3/32 intra-area 21 192.0.2.2",
                "198.51.100.4/32 intra-area 11 192.0.2.10",
                "203.0.113.0/26 external-2 20 192.0.2.10",
                "203.0.113.64/26 external-1 40 192.0.2.2",
            ],
            "{vendor}"
        );
        let [if1, if2] = interfaces(vendor);
        let hop = |p: &str| {
            c.route(p.parse().unwrap()).unwrap().next_hops[0]
                .interface
                .clone()
        };
        assert_eq!(hop("198.51.100.2/32").as_deref(), Some(if1), "{vendor}");
        assert_eq!(hop("203.0.113.0/26").as_deref(), Some(if2), "{vendor}");
    }
}

#[test]
fn each_vendor_gives_each_ospfv3_lsa_type_and_the_same_routes() {
    for vendor in VENDORS {
        let d = ospf::read(vendor, &sections(vendor));
        let o = &d.outcomes[&Version::V3];
        assert_eq!(o.outcome, Outcome::Complete, "{vendor}: {:?}", o.detail);
        assert!(o.scope.covers("default", "ipv6"), "{vendor}");
        let db = d.of(Version::V3, "default").next().unwrap();
        let mut count: BTreeMap<LsaType, usize> = BTreeMap::new();
        for l in db.lsas.values() {
            *count.entry(l.lsa_type).or_default() += 1;
        }
        assert_eq!(
            count.into_iter().collect::<Vec<_>>(),
            [
                (LsaType::Router, 5),
                (LsaType::Network, 1),
                (LsaType::Summary, 2),
                (LsaType::AsbrSummary, 1),
                (LsaType::External, 1),
                (LsaType::NssaExternal, 1),
                (LsaType::Link, 4),
                (LsaType::IntraAreaPrefix, 6),
            ],
            "{vendor}"
        );
        let c = calc(vendor, &d, Version::V3);
        assert!(
            c.gaps.is_empty() && c.notes.is_empty(),
            "{vendor}: {:?} {:?}",
            c.gaps,
            c.notes
        );
        assert_eq!(
            rows(&c),
            [
                "2001:db8:23::/64 intra-area 20 fe80::2",
                "2001:db8:98::/64 external-1 40 fe80::2",
                "2001:db8:99::/64 external-2 20 fe80::4",
                "2001:db8:ff::2/128 intra-area 10 fe80::2",
                "2001:db8:ff::3/128 intra-area 20 fe80::2",
                "2001:db8:ff::4/128 intra-area 10 fe80::4",
            ],
            "{vendor}"
        );
        let [if1, if2] = interfaces(vendor);
        let hop = |p: &str| {
            c.route(p.parse().unwrap()).unwrap().next_hops[0]
                .interface
                .clone()
        };
        assert_eq!(hop("2001:db8:ff::2/128").as_deref(), Some(if1), "{vendor}");
        assert_eq!(hop("2001:db8:ff::4/128").as_deref(), Some(if2), "{vendor}");
    }
}

#[test]
fn a_dual_stack_router_gives_the_same_graph_for_ospfv2_and_ospfv3() {
    for vendor in VENDORS {
        let d = ospf::read(vendor, &sections(vendor));
        let v2 = calc(vendor, &d, Version::V2);
        let v3 = calc(vendor, &d, Version::V3);
        assert_eq!(v2.router_costs, v3.router_costs, "{vendor}");
    }
}

#[test]
fn an_lsa_keeps_the_span_of_its_lines() {
    let d = ospf::read("iosxe", &sections("iosxe"));
    let db = d.of(Version::V2, "default").next().unwrap();
    let net = db
        .lsas
        .values()
        .find(|l| l.lsa_type == LsaType::Network)
        .unwrap();
    assert_eq!(net.span, SourceSpan::new("r1/ospf_lsdb_network", 6, 16));
    assert_eq!(net.seq, Some(0x8000_0001));
    assert_eq!(net.age, Some(100));
    let d = ospf::read("nxos", &sections("nxos"));
    let db = d.of(Version::V2, "default").next().unwrap();
    let net = db
        .lsas
        .values()
        .find(|l| l.lsa_type == LsaType::Network)
        .unwrap();
    assert_eq!(net.span.file.as_ref(), "r1/ospf_lsdb_network");
    assert!(net.span.first_line < net.span.last_line);
}

#[test]
fn a_failed_section_makes_the_database_failed() {
    let mut s = sections("nxos");
    s.insert(
        "ospf_lsdb_router".into(),
        Collected::Failed("rejected: % Permission denied".into()),
    );
    let d = ospf::read("nxos", &s);
    let o = &d.outcomes[&Version::V2];
    assert_eq!(o.outcome, Outcome::Failed);
    assert!(o.detail.as_deref().unwrap().contains("ospf_lsdb_router"));
    assert_eq!(d.outcomes[&Version::V3].outcome, Outcome::Complete);
}

#[test]
fn absent_sections_are_not_captured_and_empty_answers_are_complete_empty() {
    let absent: OspfSections = V2
        .names()
        .into_iter()
        .map(|n| (n.to_string(), Collected::Absent("% Invalid command".into())))
        .collect();
    let d = ospf::read("nxos", &absent);
    assert_eq!(d.outcomes[&Version::V2].outcome, Outcome::NotCaptured);
    assert_eq!(d.outcomes[&Version::V3].outcome, Outcome::NotCaptured);
    assert!(d.databases.is_empty());

    let empty: OspfSections = V2
        .names()
        .into_iter()
        .map(|n| {
            (
                n.to_string(),
                Collected::Fresh(Vec::new(), format!("r1/{n}")),
            )
        })
        .collect();
    let d = ospf::read("iosxe", &empty);
    assert_eq!(d.outcomes[&Version::V2].outcome, Outcome::CompleteEmpty);

    let mut mixed = sections("iosxr");
    mixed.insert(
        "ospf_lsdb_nssa_external".into(),
        Collected::Absent("% Invalid input".into()),
    );
    let d = ospf::read("iosxr", &mixed);
    assert_eq!(d.outcomes[&Version::V2].outcome, Outcome::Partial);
}

#[test]
fn an_lsa_that_is_not_read_makes_the_database_partial_and_its_router_a_gap() {
    let mut s = sections("iosxr");
    let text = String::from_utf8(fixture("iosxr", "ospf_lsdb_router")).unwrap();
    let broken = text.replacen(
        "Advertising Router: 198.51.100.3",
        "Advertising Router: unknown",
        1,
    );
    assert_ne!(text, broken);
    s.insert(
        "ospf_lsdb_router".into(),
        Collected::Fresh(broken.into_bytes(), "r1/ospf_lsdb_router".into()),
    );
    let d = ospf::read("iosxr", &s);
    let o = &d.outcomes[&Version::V2];
    assert_eq!(o.outcome, Outcome::Partial);
    assert!(o.detail.as_deref().unwrap().contains("advertising router"));
    let c = calc("iosxr", &d, Version::V2);
    assert_eq!(
        c.gaps.len(),
        2,
        "the router LSA in area 0 and the ASBR of the external LSA"
    );
    assert!(c.gaps.iter().all(|g| g.lsid.to_string() == "198.51.100.3"));
    let r3 = c.route("198.51.100.3/32".parse().unwrap());
    assert!(r3.is_none());
    assert!(c.absent_gap("198.51.100.3/32".parse().unwrap()).is_some());
    let unknown: Vec<String> = c
        .routes
        .iter()
        .filter(|r| r.unknown.is_some())
        .map(|r| r.prefix.to_string())
        .collect();
    assert_eq!(
        unknown,
        ["192.0.2.64/26", "203.0.113.0/26"],
        "the LAN at the cost of the gap and each external route"
    );
}

#[test]
fn the_same_sections_give_the_same_databases() {
    for vendor in VENDORS {
        let a = ospf::read(vendor, &sections(vendor));
        let b = ospf::read(vendor, &sections(vendor));
        assert_eq!(a, b);
    }
}

#[test]
fn the_sections_of_each_vendor() {
    assert_eq!(ospf::sections("nxos").len(), 20);
    assert_eq!(ospf::sections("iosxe").len(), 21);
    assert!(ospf::sections("unifi").is_empty());
}
