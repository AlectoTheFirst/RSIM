//! An SD-WAN overlay: a branch edge and a hub edge over 2 transport
//! networks.

use std::collections::BTreeSet;

use rsim_core::{
    FieldValue, InterfaceId, Match, NextHop, PROTO_UDP, PortCond, RulePredicate, ValueCond, VrfId,
};
use rsim_engine::TwinBuilder;
use rsim_functions::{
    EgressMode, Fib, OverlaySelect, OverlayTunnel, Route, RouteKind, RouteLookup, RouteNextHop,
    RouteProtocol, Rule, RuleAction, TunnelState, VCMP_PORT, VcmpDecap, VcmpEncap,
};

use crate::builders::*;
use crate::helpers::*;
use crate::profiles::*;

const SEGMENT: &str = "segment0";
const UNDERLAY: &str = "default";
const PUBLIC: &str = "wan1";
const PRIVATE: &str = "wan2";

/// The options of [`sdwan_site`].
#[derive(Clone, Copy, Debug)]
pub struct SdwanOpts {
    /// The transport `internet` denies the VCMP packets.
    pub internet_denies_vcmp: bool,
    /// The state of the tunnel of `branch1` over the private links.
    pub private_tunnel: TunnelState,
    /// `branch1` pins the DNS packets to its private link.
    pub pin_dns: bool,
}

impl Default for SdwanOpts {
    fn default() -> Self {
        SdwanOpts {
            internet_denies_vcmp: false,
            private_tunnel: TunnelState::Up,
            pin_dns: false,
        }
    }
}

/// One edge of the site.
struct Edge {
    name: &'static str,
    host: &'static str,
    /// The second octet of the LAN 10.`lan`.0.0/24.
    lan: u8,
    public: &'static str,
    public_gateway: &'static str,
    private: &'static str,
    private_gateway: &'static str,
    /// The interface of each transport toward this edge.
    transport_interface: &'static str,
}

const BRANCH: Edge = Edge {
    name: "branch1",
    host: "host1",
    lan: 1,
    public: "198.51.100.1",
    public_gateway: "198.51.100.254",
    private: "172.16.1.1",
    private_gateway: "172.16.1.254",
    transport_interface: "eth1",
};

const HUB: Edge = Edge {
    name: "hub1",
    host: "host9",
    lan: 9,
    public: "203.0.113.1",
    public_gateway: "203.0.113.254",
    private: "172.16.9.1",
    private_gateway: "172.16.9.254",
    transport_interface: "eth2",
};

/// A branch edge `branch1` and a hub edge `hub1` with one segment, the VRF
/// `segment0`. Each edge has the host 10.`n`.0.10 on eth9, the public link
/// wan1 to the transport `internet` and the private link wan2 to the
/// transport `mpls`. Each edge has 2 tunnels to the other edge: wan1 to
/// wan1 and wan2 to wan2. A transport is a router with a host route to the
/// address of each link.
pub fn sdwan_site(opts: SdwanOpts) -> TwinBuilder {
    let mut b = TwinBuilder::new();
    edge(&mut b, &BRANCH, &HUB, opts.private_tunnel, opts.pin_dns);
    edge(&mut b, &HUB, &BRANCH, TunnelState::Up, false);
    transport(
        &mut b,
        "internet",
        PUBLIC,
        [BRANCH.public, HUB.public],
        opts.internet_denies_vcmp,
    );
    transport(
        &mut b,
        "mpls",
        PRIVATE,
        [BRANCH.private, HUB.private],
        false,
    );
    b
}

fn edge(b: &mut TwinBuilder, e: &Edge, far: &Edge, private_tunnel: TunnelState, pin_dns: bool) {
    let d = Dev::new(e.name, generic_router());
    b.add(d.ingress("eth9", "vrf", 1));
    b.add(d.ingress(PUBLIC, "vrf", 2));
    b.add(d.ingress(PRIVATE, "vrf", 3));
    b.add(d.vrf(&[("eth9", SEGMENT)], "route", 5));

    let select = format!("sdwan/select/0/{}", far.name);
    let nh = |iface: &str, next: &str| RouteNextHop {
        interface: InterfaceId::new(iface),
        gateway: None,
        next: d.id(next),
    };
    let mut segment = Fib::new();
    segment.insert(
        pfx(&format!("10.{}.0.0/24", e.lan)),
        Route::new(
            RouteKind::Connected,
            vec![nh("eth9", "nexthop")],
            vec![d.span(11, 11)],
        ),
    );
    segment.insert(
        pfx(&format!("10.{}.0.0/24", far.lan)),
        Route::new(
            RouteKind::Learned(RouteProtocol::Overlay),
            vec![nh("overlay", &select)],
            vec![d.span(12, 12)],
        ),
    );
    let mut underlay = Fib::new();
    for (i, a) in [e.public, e.private].into_iter().enumerate() {
        underlay.insert(
            pfx(&format!("{a}/32")),
            Route::new(
                RouteKind::Local,
                Vec::new(),
                vec![d.span(13 + i as u32, 13 + i as u32)],
            ),
        );
    }
    b.add(RouteLookup {
        meta: d.meta("route", 10, 14),
        tables: [
            (VrfId::new(SEGMENT), segment),
            (VrfId::new(UNDERLAY), underlay),
        ]
        .into_iter()
        .collect(),
        fallback: None,
        local: Some(d.id("vcmp/decap")),
    });

    let links = [
        (
            PUBLIC,
            e.public,
            e.public_gateway,
            far.public,
            TunnelState::Up,
        ),
        (
            PRIVATE,
            e.private,
            e.private_gateway,
            far.private,
            private_tunnel,
        ),
    ];
    let encap = |link: &str| format!("vcmp/{link}~{}:{link}", far.name);
    let steering = if pin_dns {
        let dns = Match {
            protocol: ValueCond::one(PROTO_UDP),
            dst_port: PortCond::one(53),
            ..Match::any()
        };
        vec![
            Rule::new(
                "dns",
                RulePredicate::exact(dns),
                BTreeSet::from([PRIVATE.to_string()]),
            )
            .with_span(d.span(21, 21)),
        ]
    } else {
        Vec::new()
    };
    b.add(OverlaySelect {
        meta: d.meta(&select, 20, 22),
        far: far.name.to_string(),
        tunnels: links
            .iter()
            .enumerate()
            .map(|(i, (link, _, _, _, state))| OverlayTunnel {
                link: (*link).to_string(),
                far_link: format!("{}:{link}", far.name),
                state: *state,
                next: d.id(&encap(*link)),
                spans: vec![d.span(23 + i as u32, 23 + i as u32)],
            })
            .collect(),
        steering,
    });
    for (i, (link, source, gateway, peer, _)) in links.iter().enumerate() {
        b.add(VcmpEncap {
            meta: d.meta(&encap(*link), 30 + i as u32, 30 + i as u32),
            source: ip(source),
            peer: ip(peer),
            segments: [(VrfId::new(SEGMENT), 0)].into_iter().collect(),
            src_port: FieldValue::Known(VCMP_PORT),
            dscp: FieldValue::Known(0),
            ecn: FieldValue::Unknown,
            underlay: VrfId::new(UNDERLAY),
            interface: InterfaceId::new(*link),
            gateway: NextHop::Gateway(ip(gateway)),
            next: d.id("nexthop"),
        });
    }
    b.add(VcmpDecap {
        meta: d.meta("vcmp/decap", 35, 35),
        segments: [(0, (VrfId::new(SEGMENT), d.id("route")))]
            .into_iter()
            .collect(),
        plain: None,
    });

    let host_addr = format!("10.{}.0.10", e.lan);
    b.add(d.nexthop(
        &[
            (host_addr.as_str(), "eth9", Target::Endpoint(e.host)),
            (e.public_gateway, PUBLIC, Target::Link("internet")),
            (e.private_gateway, PRIVATE, Target::Link("mpls")),
        ],
        &["eth9", PUBLIC, PRIVATE],
        40,
    ));
    b.add(d.egress("eth9", EgressMode::Routed, None, 50));
    for (i, (link, transport)) in [(PUBLIC, "internet"), (PRIVATE, "mpls")]
        .into_iter()
        .enumerate()
    {
        let peer = format!("{transport}/in/{}", e.transport_interface);
        b.add(d.egress(
            link,
            EgressMode::Routed,
            Some((peer.as_str(), None)),
            51 + i as u32,
        ));
    }
    let attach = fid(&format!("{}/in/eth9", e.name));
    add_host(b, endpoint(e.host, &host_addr, attach));
}

/// A transport network as one router. `addresses` are the addresses of the
/// link `link` of the branch and of the hub.
fn transport(
    b: &mut TwinBuilder,
    name: &'static str,
    link: &str,
    addresses: [&'static str; 2],
    denies_vcmp: bool,
) {
    let d = Dev::new(name, generic_router());
    let edges = [&BRANCH, &HUB];
    for (i, e) in edges.iter().enumerate() {
        b.add(d.ingress(e.transport_interface, "vrf", 1 + i as u32));
    }
    let first = if denies_vcmp { "acl" } else { "route" };
    b.add(d.vrf(&[], first, 5));
    if denies_vcmp {
        let vcmp = Match {
            protocol: ValueCond::one(PROTO_UDP),
            dst_port: PortCond::one(VCMP_PORT),
            ..Match::any()
        };
        b.add(d.acl(
            "acl",
            "transit",
            vec![
                rule("deny-vcmp", vcmp, RuleAction::Deny, d.span(7, 7)),
                rule("permit-any", Match::any(), RuleAction::Permit, d.span(8, 8)),
            ],
            "route",
            6,
        ));
    }
    let prefixes: Vec<String> = addresses.iter().map(|a| format!("{a}/32")).collect();
    let hops: Vec<[(&str, Option<&str>, &str); 1]> = edges
        .iter()
        .map(|e| [(e.transport_interface, None, "nexthop")])
        .collect();
    let routes: Vec<(&str, RouteKind, &[(&str, Option<&str>, &str)])> = prefixes
        .iter()
        .zip(&hops)
        .map(|(p, h)| {
            (
                p.as_str(),
                RouteKind::Connected,
                &h[..] as &[(&str, Option<&str>, &str)],
            )
        })
        .collect();
    b.add(d.routes(UNDERLAY, &routes, 10));
    let entries: Vec<(&str, &str, Target)> = edges
        .iter()
        .zip(addresses)
        .map(|(e, a)| (a, e.transport_interface, Target::Link(e.name)))
        .collect();
    let egress: Vec<&str> = edges.iter().map(|e| e.transport_interface).collect();
    b.add(d.nexthop(&entries, &egress, 20));
    for (i, e) in edges.iter().enumerate() {
        let peer = format!("{}/in/{link}", e.name);
        b.add(d.egress(
            e.transport_interface,
            EgressMode::Routed,
            Some((peer.as_str(), None)),
            30 + i as u32,
        ));
    }
}
