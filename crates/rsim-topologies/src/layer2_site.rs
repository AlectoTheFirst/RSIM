//! A small switched site behind a router.

use std::collections::{BTreeMap, BTreeSet};

use rsim_core::{
    BridgeDomainId, EndpointId, FieldValue, InterfaceId, Mac, NetFunction, PortId, Prefix,
    PrefixTable, Rewrite, SourceSpan, TriePrefixTable,
};
use rsim_engine::{AttachmentKind, AttachmentRecord, Endpoint, TwinBuilder};
use rsim_functions::{
    EgressMode, Flood, HostMac, HostResolution, Layer3HandOff, MacEntry, MacLookup, Neighbour,
    PortEgress, PortIngress, RouteKind, Tag, WirelessAttachment,
};

use crate::builders::*;
use crate::helpers::*;
use crate::profiles::*;

/// The MAC of the router.
pub const R1_MAC: Mac = Mac([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]);
/// The MACs of the hosts h1, h2, h3 and w1.
pub const H1_MAC: Mac = Mac([0x00, 0x00, 0x5e, 0x00, 0x53, 0x11]);
pub const H2_MAC: Mac = Mac([0x00, 0x00, 0x5e, 0x00, 0x53, 0x12]);
pub const H3_MAC: Mac = Mac([0x00, 0x00, 0x5e, 0x00, 0x53, 0x13]);
pub const W1_MAC: Mac = Mac([0x00, 0x00, 0x5e, 0x00, 0x53, 0x21]);

fn span(file: &str, line: u32) -> SourceSpan {
    SourceSpan::line(file, line)
}

fn bd(s: &str) -> BridgeDomainId {
    BridgeDomainId::new(s)
}

fn port(s: &str) -> PortId {
    PortId::new(s)
}

/// The site:
///
/// - router `r1`: `eth0` untagged in `lan` 192.0.2.0/26 and `eth0.20` with
///   VLAN 20 in `v20` 198.51.100.0/24, on one trunk to `sw1` port 1
/// - switch `sw1`: port 1 trunk to `r1`, port 2 access `lan` with h1
///   192.0.2.10, port 3 trunk to `ap1`, port 4 access `v20` with h2
///   198.51.100.20, port 5 access `lan` and down, port 6 access `lan` with
///   h3 192.0.2.13, which is in no MAC table
/// - access point `ap1`: port 1 trunk to `sw1` port 3, SSID `office` in
///   `v20` with w1 198.51.100.30
pub fn layer2_site() -> TwinBuilder {
    let r = Dev::new("r1", generic_router());
    let sw = Dev::new("sw1", generic_router());
    let ap = Dev::new("ap1", generic_router());
    let lan = bd("site/lan");
    let v20 = bd("site/v20");
    let mut fns: Vec<std::sync::Arc<dyn NetFunction>> = Vec::new();
    macro_rules! add {
        ($e:expr) => {
            fns.push(std::sync::Arc::new($e))
        };
    }

    // Router.
    add!(Layer3HandOff {
        meta: r.meta("handoff", 1, 1),
        macs: BTreeSet::from([R1_MAC]),
        untagged: Some(r.id("in/eth0")),
        tagged: BTreeMap::from([(20, r.id("in/eth0.20"))]),
    });
    add!(r.ingress("eth0", "vrf", 2));
    add!(r.ingress("eth0.20", "vrf", 3));
    add!(r.vrf(&[("eth0", "default"), ("eth0.20", "default")], "route", 4));
    add!(r.routes(
        "default",
        &[
            (
                "192.0.2.0/26",
                RouteKind::Connected,
                &[("eth0", None, "nexthop")]
            ),
            (
                "198.51.100.0/24",
                RouteKind::Connected,
                &[("eth0.20", None, "nexthop")]
            ),
            ("192.0.2.1/32", RouteKind::Local, &[]),
            ("198.51.100.1/32", RouteKind::Local, &[]),
        ],
        10,
    ));
    let mut nh = r.nexthop(&[], &["eth0", "eth0.20"], 20);
    for (addr, iface, mac, owner) in [
        ("192.0.2.10", "eth0", H1_MAC, "h1"),
        ("192.0.2.13", "eth0", H3_MAC, "h3"),
        ("198.51.100.20", "eth0.20", H2_MAC, "h2"),
        ("198.51.100.30", "eth0.20", W1_MAC, "w1"),
    ] {
        nh.neighbours.insert(
            Prefix::host(ip(addr)),
            vec![Neighbour {
                interface: InterfaceId::new(iface),
                target: rsim_core::NeighbourTarget::Link,
                owner: owner.into(),
                mac: Some(mac),
                spans: vec![span("r1.arp", 1)],
            }],
        );
    }
    add!(nh);
    for (iface, tag, line) in [("eth0", Tag::Untagged, 30), ("eth0.20", Tag::Vlan(20), 31)] {
        let mut e = r.egress(
            iface,
            EgressMode::Routed,
            Some(("sw1/port/1/in", None)),
            line,
        );
        e.rewrite = Rewrite {
            src_mac: Some(FieldValue::Known(R1_MAC)),
            ..Rewrite::default()
        };
        e.tag = tag;
        add!(e);
    }

    // Switch.
    let trunk = || (Some(lan.clone()), BTreeMap::from([(20u16, v20.clone())]));
    let sw_ports: [(
        &str,
        (Option<BridgeDomainId>, BTreeMap<u16, BridgeDomainId>),
        Option<&str>,
        bool,
    ); 6] = [
        ("1", trunk(), Some("r1/handoff"), true),
        ("2", (Some(lan.clone()), BTreeMap::new()), None, true),
        ("3", trunk(), Some("ap1/port/1/in"), true),
        ("4", (Some(v20.clone()), BTreeMap::new()), None, true),
        ("5", (Some(lan.clone()), BTreeMap::new()), None, false),
        ("6", (Some(lan.clone()), BTreeMap::new()), None, true),
    ];
    let hosts_on: BTreeMap<&str, (Mac, &str)> = BTreeMap::from([
        ("2", (H1_MAC, "h1")),
        ("4", (H2_MAC, "h2")),
        ("6", (H3_MAC, "h3")),
    ]);
    let mut flood: BTreeMap<BridgeDomainId, Vec<(PortId, rsim_core::FunctionId)>> = BTreeMap::new();
    let mut egress = BTreeMap::new();
    for (n, (native, tagged), peer, up) in &sw_ports {
        let p = port(&format!("port/{n}"));
        add!(PortIngress {
            meta: sw.meta(&format!("port/{n}/in"), 40, 40),
            port: p.clone(),
            native: native.clone(),
            tagged: tagged.clone(),
            next: sw.id("mac"),
        });
        add!(PortEgress {
            meta: sw.meta(&format!("port/{n}/out"), 41, 41),
            port: p.clone(),
            native: native.clone(),
            tagged: tagged.iter().map(|(v, b)| (b.clone(), *v)).collect(),
            peer: peer.map(fid),
            hosts: hosts_on
                .get(n)
                .map(|(m, h)| BTreeMap::from([(*m, EndpointId::new(*h))]))
                .unwrap_or_default(),
        });
        let out = sw.id(&format!("port/{n}/out"));
        egress.insert(p.clone(), out.clone());
        if *up {
            for b in native.iter().chain(tagged.values()) {
                flood
                    .entry(b.clone())
                    .or_default()
                    .push((p.clone(), out.clone()));
            }
        }
    }
    let entry = |p: &str| MacEntry {
        port: port(p),
        spans: vec![span("sw1.macs", 1)],
    };
    add!(MacLookup {
        meta: sw.meta("mac", 50, 50),
        tables: BTreeMap::from([
            (
                lan.clone(),
                BTreeMap::from([(R1_MAC, entry("port/1")), (H1_MAC, entry("port/2"))]),
            ),
            (
                v20.clone(),
                BTreeMap::from([
                    (R1_MAC, entry("port/1")),
                    (H2_MAC, entry("port/4")),
                    (W1_MAC, entry("port/3")),
                ]),
            ),
        ]),
        egress,
        flood: sw.id("flood"),
        hairpin: BTreeSet::new(),
        blocked: BTreeMap::new(),
    });
    add!(Flood {
        meta: sw.meta("flood", 51, 51),
        ports: flood,
    });

    // Access point.
    add!(PortIngress {
        meta: ap.meta("port/1/in", 60, 60),
        port: port("port/1"),
        native: Some(lan.clone()),
        tagged: BTreeMap::from([(20, v20.clone())]),
        next: ap.id("mac"),
    });
    add!(PortEgress {
        meta: ap.meta("port/1/out", 61, 61),
        port: port("port/1"),
        native: Some(lan.clone()),
        tagged: BTreeMap::from([(v20.clone(), 20)]),
        peer: Some(fid("sw1/port/3/in")),
        hosts: BTreeMap::new(),
    });
    add!(WirelessAttachment {
        meta: ap.meta("wlan/office/in", 62, 62),
        port: port("wlan/office"),
        bridge_domain: v20.clone(),
        next: ap.id("mac"),
    });
    add!(PortEgress {
        meta: ap.meta("wlan/office/out", 63, 63),
        port: port("wlan/office"),
        native: Some(v20.clone()),
        tagged: BTreeMap::new(),
        peer: None,
        hosts: BTreeMap::from([(W1_MAC, EndpointId::new("w1"))]),
    });
    let ap_entry = |p: &str| MacEntry {
        port: port(p),
        spans: vec![span("ap1.macs", 1)],
    };
    add!(MacLookup {
        meta: ap.meta("mac", 64, 64),
        tables: BTreeMap::from([
            (
                lan.clone(),
                BTreeMap::from([(R1_MAC, ap_entry("port/1")), (H1_MAC, ap_entry("port/1"))]),
            ),
            (
                v20.clone(),
                BTreeMap::from([
                    (R1_MAC, ap_entry("port/1")),
                    (H2_MAC, ap_entry("port/1")),
                    (W1_MAC, ap_entry("wlan/office")),
                ]),
            ),
        ]),
        egress: BTreeMap::from([
            (port("port/1"), ap.id("port/1/out")),
            (port("wlan/office"), ap.id("wlan/office/out")),
        ]),
        flood: ap.id("flood"),
        hairpin: BTreeSet::from([port("wlan/office")]),
        blocked: BTreeMap::new(),
    });
    add!(Flood {
        meta: ap.meta("flood", 65, 65),
        ports: BTreeMap::from([
            (lan.clone(), vec![(port("port/1"), ap.id("port/1/out"))]),
            (
                v20.clone(),
                vec![
                    (port("port/1"), ap.id("port/1/out")),
                    (port("wlan/office"), ap.id("wlan/office/out")),
                ],
            ),
        ]),
    });

    // Host attachment points: each one knows all host MACs, its networks
    // and its gateway.
    let mut hosts: TriePrefixTable<HostMac> = TriePrefixTable::new();
    for (addr, mac) in [
        ("192.0.2.10", H1_MAC),
        ("192.0.2.13", H3_MAC),
        ("198.51.100.20", H2_MAC),
        ("198.51.100.30", W1_MAC),
        ("192.0.2.1", R1_MAC),
        ("198.51.100.1", R1_MAC),
    ] {
        hosts.insert(
            Prefix::host(ip(addr)),
            HostMac {
                mac,
                spans: vec![span("site.clients", 1)],
            },
        );
    }
    let gw = HostMac {
        mac: R1_MAC,
        spans: vec![span("site.clients", 2)],
    };
    let mut b = TwinBuilder::new();
    for (dev, iface, net, next, host, addr) in [
        (
            &sw,
            "port/2",
            "192.0.2.0/26",
            "port/2/in",
            "h1",
            "192.0.2.10",
        ),
        (
            &sw,
            "port/4",
            "198.51.100.0/24",
            "port/4/in",
            "h2",
            "198.51.100.20",
        ),
        (
            &sw,
            "port/6",
            "192.0.2.0/26",
            "port/6/in",
            "h3",
            "192.0.2.13",
        ),
        (
            &ap,
            "wlan/office",
            "198.51.100.0/24",
            "wlan/office/in",
            "w1",
            "198.51.100.30",
        ),
    ] {
        add!(HostResolution {
            meta: dev.meta(&format!("host/{iface}"), 70, 70),
            interface: InterfaceId::new(iface),
            hosts: hosts.clone(),
            local: vec![pfx(net)],
            gateway: Some(gw.clone()),
            next: dev.id(next),
        });
        b.endpoint(Endpoint {
            id: EndpointId::new(host),
            addresses: vec![ip(addr)],
        });
        b.attachment(AttachmentRecord {
            address: ip(addr),
            device: dev.name.as_str().into(),
            interface: InterfaceId::new(iface),
            kind: AttachmentKind::Client,
            host: host.into(),
            provenance: vec![span("site.clients", 3)],
        });
    }
    for f in fns {
        b.add_arc(f);
    }
    b
}
