//! An SD-WAN overlay: a branch edge and a hub edge over 2 transport
//! networks.

use std::collections::{BTreeMap, BTreeSet};

use rsim_core::{
    FieldValue, InterfaceId, Match, NextHop, ObjectId, PROTO_TCP, PROTO_UDP, PortCond,
    RulePredicate, ValueCond, VrfId,
};
use rsim_engine::TwinBuilder;
use rsim_functions::{
    EgressMode, ExitMark, Fib, OverlaySelect, OverlayTunnel, PolicyRoute, Route, RouteKind,
    RouteLookup, RouteNextHop, RouteProtocol, Rule, RuleAction, TunnelState, VCMP_PORT, VcmpDecap,
    VcmpEncap, VrfSelection,
};

use crate::builders::*;
use crate::helpers::*;
use crate::profiles::*;

const SEGMENT: &str = "segment0";
const UNDERLAY: &str = "default";
const PUBLIC: &str = "wan1";
const PRIVATE: &str = "wan2";
/// The interface of the hub and of the transport `internet` to the
/// internet, which is outside the twin.
const HUB_EXIT: &str = "eth8";
const INTERNET_EXIT: &str = "eth0";
const INTERNET_GATEWAY: &str = "192.0.2.254";

/// The options of [`sdwan_site`].
#[derive(Clone, Copy, Debug)]
pub struct SdwanOpts {
    /// The transport `internet` denies the VCMP packets.
    pub internet_denies_vcmp: bool,
    /// The state of the tunnel of `branch1` over the private links.
    pub private_tunnel: TunnelState,
    /// `branch1` pins the DNS packets to its private link.
    pub pin_dns: bool,
    /// Each edge has a firewall for the packets from its LAN: it denies
    /// Telnet and permits each other packet.
    pub firewall: bool,
}

impl Default for SdwanOpts {
    fn default() -> Self {
        SdwanOpts {
            internet_denies_vcmp: false,
            private_tunnel: TunnelState::Up,
            pin_dns: false,
            firewall: false,
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
    /// The gateway of the default route of the edge on its interface to
    /// the internet. With none, the default route goes to the business
    /// policy.
    breakout: Option<&'static str>,
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
    breakout: None,
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
    breakout: Some("10.9.8.254"),
};

/// A branch edge `branch1` and a hub edge `hub1` with one segment, the VRF
/// `segment0`. Each edge has the host 10.`n`.0.10 on eth9, the public link
/// wan1 to the transport `internet` and the private link wan2 to the
/// transport `mpls`. Each edge has 2 tunnels to the other edge: wan1 to
/// wan1 and wan2 to wan2. A transport is a router with a host route to the
/// address of each link.
///
/// The default route of `branch1` goes to its business policy: the rule
/// `backhaul-dns` sends the DNS packets to `hub1`, and each other packet
/// leaves direct on wan1. The default route of `hub1` leaves on eth8, and
/// the default route of `internet` leaves on eth0. Both interfaces are
/// edges of the twin.
pub fn sdwan_site(opts: SdwanOpts) -> TwinBuilder {
    let mut b = TwinBuilder::new();
    edge(&mut b, &BRANCH, &HUB, opts.private_tunnel, &opts);
    edge(&mut b, &HUB, &BRANCH, TunnelState::Up, &opts);
    transport(
        &mut b,
        "internet",
        PUBLIC,
        [BRANCH.public, HUB.public],
        opts.internet_denies_vcmp,
        Some(INTERNET_GATEWAY),
    );
    transport(
        &mut b,
        "mpls",
        PRIVATE,
        [BRANCH.private, HUB.private],
        false,
        None,
    );
    b
}

fn edge(b: &mut TwinBuilder, e: &Edge, far: &Edge, private_tunnel: TunnelState, opts: &SdwanOpts) {
    let d = Dev::new(e.name, generic_router());
    let pin_dns = opts.pin_dns && e.breakout.is_none();
    b.add(d.ingress("eth9", "vrf", 1));
    b.add(d.ingress(PUBLIC, "vrf-wan", 2));
    b.add(d.ingress(PRIVATE, "vrf-wan", 3));
    let first = if opts.firewall { "firewall" } else { "route" };
    b.add(d.vrf(&[("eth9", SEGMENT)], first, 5));
    b.add(VrfSelection {
        meta: d.meta("vrf-wan", 6, 6),
        by_interface: BTreeMap::new(),
        default_vrf: Some(VrfId::new(UNDERLAY)),
        next: d.id("route"),
    });
    if opts.firewall {
        let telnet = Match {
            protocol: ValueCond::one(PROTO_TCP),
            dst_port: PortCond::one(23),
            ..Match::any()
        };
        b.add(d.acl(
            "firewall",
            "firewall",
            vec![
                rule("deny-telnet", telnet, RuleAction::Deny, d.span(8, 8)),
                rule("allow-any", Match::any(), RuleAction::Permit, d.span(9, 9)),
            ],
            "route",
            7,
        ));
    }

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
    let default_hop = match e.breakout {
        Some(gateway) => RouteNextHop {
            interface: InterfaceId::new(HUB_EXIT),
            gateway: Some(ip(gateway)),
            next: d.id("nexthop"),
        },
        None => nh("policy", "policy/segment0"),
    };
    segment.insert(
        pfx("0.0.0.0/0"),
        Route::new(RouteKind::Static, vec![default_hop], vec![d.span(15, 15)]),
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
                next: d.id(&encap(link)),
                spans: vec![d.span(23 + i as u32, 23 + i as u32)],
            })
            .collect(),
        steering,
        mandatory: if pin_dns {
            BTreeSet::from(["dns".to_string()])
        } else {
            BTreeSet::new()
        },
    });
    for (i, (link, source, gateway, peer, _)) in links.iter().enumerate() {
        b.add(VcmpEncap {
            meta: d.meta(&encap(link), 30 + i as u32, 30 + i as u32),
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
    if e.breakout.is_none() {
        let dns = Match {
            protocol: ValueCond::one(PROTO_UDP),
            dst_port: PortCond::one(53),
            ..Match::any()
        };
        b.add(PolicyRoute::new(
            d.meta("policy/segment0", 24, 26),
            ObjectId::new("business-policy"),
            vec![(
                None,
                Rule::new("backhaul-dns", RulePredicate::exact(dns), d.id(&select))
                    .with_span(d.span(25, 25)),
            )],
            d.id("direct"),
        ));
        let mut direct = Fib::new();
        direct.insert(
            pfx("0.0.0.0/0"),
            Route::new(
                RouteKind::Static,
                vec![RouteNextHop {
                    interface: InterfaceId::new(PUBLIC),
                    gateway: Some(ip(e.public_gateway)),
                    next: d.id("nexthop"),
                }],
                vec![d.span(27, 27)],
            ),
        );
        b.add(RouteLookup {
            meta: d.meta("direct", 27, 27),
            tables: [(VrfId::new(SEGMENT), direct)].into_iter().collect(),
            fallback: None,
            local: None,
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
    let mut neighbours = vec![
        (host_addr.as_str(), "eth9", Target::Endpoint(e.host)),
        (e.public_gateway, PUBLIC, Target::Link("internet")),
        (e.private_gateway, PRIVATE, Target::Link("mpls")),
    ];
    let mut interfaces = vec!["eth9", PUBLIC, PRIVATE];
    if let Some(gateway) = e.breakout {
        neighbours.push((gateway, HUB_EXIT, Target::Link("isp")));
        interfaces.push(HUB_EXIT);
        let mut exit = d.egress(HUB_EXIT, EgressMode::Routed, None, 55);
        exit.exit = Some(ExitMark::Owner);
        b.add(exit);
    }
    b.add(d.nexthop(&neighbours, &interfaces, 40));
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
/// link `link` of the branch and of the hub. With `exit`, the router has a
/// default route to that gateway on an interface that is an edge of the
/// twin.
fn transport(
    b: &mut TwinBuilder,
    name: &'static str,
    link: &str,
    addresses: [&'static str; 2],
    denies_vcmp: bool,
    exit: Option<&'static str>,
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
    let exit_hop = exit.map(|gateway| [(INTERNET_EXIT, Some(gateway), "nexthop")]);
    let mut routes: Vec<(&str, RouteKind, &[(&str, Option<&str>, &str)])> = prefixes
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
    if let Some(h) = &exit_hop {
        routes.push(("0.0.0.0/0", RouteKind::Static, &h[..]));
    }
    b.add(d.routes(UNDERLAY, &routes, 10));
    let mut entries: Vec<(&str, &str, Target)> = edges
        .iter()
        .zip(addresses)
        .map(|(e, a)| (a, e.transport_interface, Target::Link(e.name)))
        .collect();
    let mut egress: Vec<&str> = edges.iter().map(|e| e.transport_interface).collect();
    if let Some(gateway) = exit {
        entries.push((gateway, INTERNET_EXIT, Target::Link("isp")));
        egress.push(INTERNET_EXIT);
        let mut out = d.egress(INTERNET_EXIT, EgressMode::Routed, None, 35);
        out.exit = Some(ExitMark::Owner);
        b.add(out);
    }
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
