//! Hand-built topologies for the step 1 tests and benchmarks.
//!
//! All vendor profile values here are hand-built test data. They are not
//! confirmed against a device (section 6).

#![allow(dead_code, clippy::type_complexity)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{
    AddrCond, EndpointId, FunctionId, Header, InterfaceId, Match, NeighbourTarget, ObjectId,
    PROTO_TCP, PROTO_UDP, PortCond, Prefix, PrefixTable, RulePredicate, SourceSpan,
    TriePrefixTable, ValueCond, VrfId, ZoneId,
};
use rsim_engine::{Endpoint, TwinBuilder};
use rsim_functions::{
    AclMatch, DestinationNat, Egress, EgressMode, FirewallPolicy, Ingress, Link, Meta, NatAction,
    Neighbour, NextHopResolution, PortTranslation, Route, RouteKind, RouteLookup, RouteNextHop,
    Rule, RuleAction, SessionCommit, SessionLookup, SourceNat, UnzonedInterface, VendorProfile,
    VrfSelection, ZoneLookup, ZoneRole, ZoneScope,
};

pub fn ip(s: &str) -> IpAddr {
    s.parse().expect("valid address")
}

pub fn pfx(s: &str) -> Prefix {
    s.parse().expect("valid prefix")
}

pub fn fid(s: &str) -> FunctionId {
    FunctionId::new(s)
}

pub fn udp(src: &str, sport: u16, dst: &str, dport: u16) -> Header {
    Header::request(ip(src), ip(dst), PROTO_UDP)
        .with_src_port(sport)
        .with_dst_port(dport)
}

pub fn tcp(src: &str, sport: u16, dst: &str, dport: u16) -> Header {
    Header::request(ip(src), ip(dst), PROTO_TCP)
        .with_src_port(sport)
        .with_dst_port(dport)
}

// ---------------------------------------------------------------- profiles

fn profile(name: &str, acl_default: RuleAction, default_vrf: &str) -> VendorProfile {
    VendorProfile {
        name: name.to_string(),
        acl_default,
        firewall_default: RuleAction::Deny,
        unzoned_interface: UnzonedInterface::Drop,
        snat_port: PortTranslation::Preserve,
        default_vrf: Some(VrfId::new(default_vrf)),
        processing_delay_ns: None,
        source: vec![SourceSpan::line(format!("profiles/{name}.test-data"), 1)],
    }
}

/// FortiOS: implicit deny at the end of the policy; the source port is kept
/// by source NAT where it is free.
pub fn fortios() -> VendorProfile {
    profile("fortios", RuleAction::Deny, "root")
}

/// An inline IPS: traffic that no filter blocks passes.
pub fn tippingpoint() -> VendorProfile {
    profile("tippingpoint", RuleAction::Permit, "default")
}

/// NX-OS: implicit deny at the end of an ACL.
pub fn nxos() -> VendorProfile {
    profile("nxos", RuleAction::Deny, "default")
}

/// A generic stateful router: implicit deny at the end of an ACL. The
/// session lookup undoes a translation before the ACL, so the ACL sees the
/// reply with the public address.
pub fn generic_router() -> VendorProfile {
    profile("generic-router", RuleAction::Deny, "default")
}

// ---------------------------------------------------------------- builders

/// A device under construction.
pub struct Dev {
    pub name: String,
    pub profile: VendorProfile,
}

impl Dev {
    pub fn new(name: &str, profile: VendorProfile) -> Self {
        Dev {
            name: name.to_string(),
            profile,
        }
    }

    pub fn id(&self, f: &str) -> FunctionId {
        FunctionId::new(format!("{}/{f}", self.name))
    }

    pub fn span(&self, first: u32, last: u32) -> SourceSpan {
        SourceSpan::new(format!("{}.conf", self.name), first, last)
    }

    pub fn meta(&self, f: &str, first: u32, last: u32) -> Meta {
        Meta::new(self.id(f), self.name.as_str(), &self.profile).with_span(self.span(first, last))
    }

    pub fn ingress(&self, iface: &str, next: &str, line: u32) -> Ingress {
        Ingress {
            meta: self.meta(&format!("in/{iface}"), line, line),
            interface: InterfaceId::new(iface),
            next: self.id(next),
        }
    }

    pub fn vrf(&self, map: &[(&str, &str)], next: &str, line: u32) -> VrfSelection {
        VrfSelection {
            meta: self.meta("vrf", line, line + map.len() as u32),
            by_interface: map
                .iter()
                .map(|(i, v)| (InterfaceId::new(*i), VrfId::new(*v)))
                .collect(),
            default_vrf: self.profile.default_vrf.clone(),
            next: self.id(next),
        }
    }

    pub fn zone(
        &self,
        name: &str,
        role: ZoneRole,
        map: &[(&str, &str)],
        next: &str,
        line: u32,
    ) -> ZoneLookup {
        ZoneLookup {
            meta: self.meta(name, line, line + map.len() as u32),
            role,
            by_interface: map
                .iter()
                .map(|(i, z)| (InterfaceId::new(*i), ZoneId::new(*z)))
                .collect(),
            unzoned: self.profile.unzoned_interface,
            next: self.id(next),
        }
    }

    pub fn acl(
        &self,
        name: &str,
        acl: &str,
        rules: Vec<Rule<RuleAction>>,
        next: &str,
        line: u32,
    ) -> AclMatch {
        AclMatch {
            meta: self.meta(name, line, line + rules.len() as u32 + 1),
            acl: ObjectId::new(acl),
            rules,
            default: self.profile.acl_default,
            next: self.id(next),
        }
    }

    pub fn session_lookup(&self, next: &str) -> SessionLookup {
        SessionLookup {
            meta: self.meta("session-lookup", 1, 1),
            next: self.id(next),
        }
    }

    pub fn session_commit(&self, next: &str) -> SessionCommit {
        SessionCommit {
            meta: self.meta("session-commit", 1, 1),
            next: self.id(next),
        }
    }

    pub fn egress(
        &self,
        iface: &str,
        mode: EgressMode,
        link: Option<(&str, Option<u64>)>,
        line: u32,
    ) -> Egress {
        Egress {
            meta: self.meta(&format!("out/{iface}"), line, line),
            interface: InterfaceId::new(iface),
            mode,
            link: link.map(|(peer, delay)| Link {
                peer: (!peer.is_empty()).then(|| fid(peer)),
                delay_ns: delay,
                provenance: vec![SourceSpan::line("topology/links.yaml", line)],
            }),
        }
    }

    pub fn nexthop(
        &self,
        entries: &[(&str, &str, Target)],
        egress: &[&str],
        line: u32,
    ) -> NextHopResolution {
        let mut table: TriePrefixTable<Vec<Neighbour>> = TriePrefixTable::new();
        for (i, (addr, iface, target)) in entries.iter().enumerate() {
            let p = Prefix::host(ip(addr));
            let n = Neighbour {
                interface: InterfaceId::new(*iface),
                target: match target {
                    Target::Link(_) => NeighbourTarget::Link,
                    Target::Endpoint(e) => NeighbourTarget::Endpoint(EndpointId::new(*e)),
                },
                owner: match target {
                    Target::Link(o) | Target::Endpoint(o) => o.to_string(),
                },
                spans: vec![SourceSpan::line(format!("{}.arp", self.name), i as u32 + 1)],
            };
            let mut v = table.get(&p).cloned().unwrap_or_default();
            v.push(n);
            table.insert(p, v);
        }
        NextHopResolution {
            meta: self.meta("nexthop", line, line),
            neighbours: table,
            complete: true,
            egress: egress
                .iter()
                .map(|i| (InterfaceId::new(*i), self.id(&format!("out/{i}"))))
                .collect(),
        }
    }

    /// A route lookup with one VRF. Each route: prefix, kind, next hops of
    /// (interface, gateway, next function).
    pub fn routes(
        &self,
        vrf: &str,
        routes: &[(&str, RouteKind, &[(&str, Option<&str>, &str)])],
        line: u32,
    ) -> RouteLookup {
        let mut t = TriePrefixTable::new();
        for (i, (p, kind, nhs)) in routes.iter().enumerate() {
            let nh = nhs
                .iter()
                .map(|(iface, gw, next)| RouteNextHop {
                    interface: InterfaceId::new(*iface),
                    gateway: gw.map(ip),
                    next: self.id(next),
                })
                .collect();
            t.insert(
                pfx(p),
                Route::new(*kind, nh, vec![self.span(line + i as u32, line + i as u32)]),
            );
        }
        RouteLookup {
            meta: self.meta("route", line, line + routes.len() as u32),
            tables: [(VrfId::new(vrf), t)].into_iter().collect(),
        }
    }
}

#[derive(Clone, Copy)]
pub enum Target {
    /// The neighbour is behind the link; the text names the owner.
    Link(&'static str),
    Endpoint(&'static str),
}

pub fn rule(name: &str, m: Match, action: RuleAction, span: SourceSpan) -> Rule<RuleAction> {
    Rule::new(name, RulePredicate::exact(m), action).with_span(span)
}

pub fn m_src_dst(src: &[&str], dst: &[&str]) -> Match {
    Match {
        src_ip: if src.is_empty() {
            AddrCond::Any
        } else {
            AddrCond::prefixes(src)
        },
        dst_ip: if dst.is_empty() {
            AddrCond::Any
        } else {
            AddrCond::prefixes(dst)
        },
        ..Match::any()
    }
}

pub fn with_proto_dport(m: Match, proto: u8, dport: u16) -> Match {
    Match {
        protocol: ValueCond::one(proto),
        dst_port: PortCond::one(dport),
        ..m
    }
}

pub fn endpoint(id: &str, addr: &str, attachment: FunctionId) -> Endpoint {
    Endpoint {
        id: EndpointId::new(id),
        addresses: vec![ip(addr)],
        attachment,
    }
}

// ---------------------------------------------------------------- topology 1

/// Options for the mini-enterprise topology.
#[derive(Clone, Copy, Debug, Default)]
pub struct MiniOpts {
    /// Add a FortiGate policy rule from an unhandled stanza after rule 1.
    pub unhandled_policy_rule: bool,
    /// Leave out the destination zone lookup on the FortiGate.
    pub skip_dst_zone: bool,
    /// Build the functions in reverse order.
    pub reverse_insertion: bool,
}

/// The guest-to-DNS path of the baseline fixture
/// `rsim-baseline-enterprise.yaml`:
///
/// guest-client 172.31.10.20 -> fra01-fgt-01 port2 (zone guest) -> policy
/// guest-to-dns, SNAT guest-snat to 10.20.0.254 -> port1 (zone corp) ->
/// fra01-ips-01 1B -> 1A (inline) -> fra01-core-01 eth1-1 -> vlan100 ->
/// fra01-dns 10.20.0.53.
///
/// Differences from the fixture:
/// - Step 1 has no layer 2 functions, so core-01 routes between eth1-1 and
///   vlan100 with a host route to the FortiGate address. In the fixture,
///   this hop is switched in VLAN 100.
/// - The fixture has no ACL on core-01, no static route on core-01 and no
///   rules in the IPS profile. The ACL "users-in", the static route to
///   172.31.0.0/16 and the IPS filters are added here.
pub fn mini_enterprise(opts: MiniOpts) -> TwinBuilder {
    let fgt = Dev::new("fra01-fgt-01", fortios());
    let ips = Dev::new("fra01-ips-01", tippingpoint());
    let core = Dev::new("fra01-core-01", nxos());

    let mut fns: Vec<std::sync::Arc<dyn rsim_core::NetFunction>> = Vec::new();
    macro_rules! add {
        ($e:expr) => {
            fns.push(std::sync::Arc::new($e))
        };
    }

    // FortiGate.
    add!(fgt.ingress("port1", "vrf", 10));
    add!(fgt.ingress("port2", "vrf", 20));
    add!(fgt.vrf(&[("port1", "root"), ("port2", "root")], "zone-src", 30));
    add!(fgt.zone(
        "zone-src",
        ZoneRole::Source,
        &[("port1", "corp"), ("port2", "guest")],
        "session-lookup",
        40
    ));
    add!(fgt.session_lookup("dnat"));
    add!(DestinationNat {
        meta: fgt.meta("dnat", 50, 50),
        table: ObjectId::new("fgt:root:vip"),
        rules: Vec::new(),
        next: fgt.id("route"),
    });
    let after_route = if opts.skip_dst_zone {
        "policy"
    } else {
        "zone-dst"
    };
    add!(fgt.routes(
        "root",
        &[
            (
                "10.20.0.0/24",
                RouteKind::Connected,
                &[("port1", None, after_route)]
            ),
            (
                "172.31.10.0/24",
                RouteKind::Connected,
                &[("port2", None, after_route)]
            ),
            ("10.20.0.254/32", RouteKind::Local, &[]),
            ("172.31.10.1/32", RouteKind::Local, &[]),
        ],
        60,
    ));
    if !opts.skip_dst_zone {
        add!(fgt.zone(
            "zone-dst",
            ZoneRole::Destination,
            &[("port1", "corp"), ("port2", "guest")],
            "policy",
            40
        ));
    }
    let mut rules = vec![(
        ZoneScope::between("guest", "corp"),
        rule(
            "guest-to-dns",
            with_proto_dport(
                m_src_dst(&["172.31.0.0/16"], &["10.20.0.53/32"]),
                PROTO_UDP,
                53,
            ),
            RuleAction::Permit,
            fgt.span(100, 108),
        ),
    )];
    if opts.unhandled_policy_rule {
        rules.push((
            ZoneScope::default(),
            Rule::unhandled("internet-service-rule", fgt.span(110, 118)),
        ));
    }
    rules.push((
        ZoneScope::between("corp", "guest"),
        rule(
            "corp-to-guest-mgmt",
            m_src_dst(&["10.20.0.53/32"], &["172.31.0.0/16"]),
            RuleAction::Permit,
            fgt.span(120, 127),
        ),
    ));
    add!(FirewallPolicy::new(
        fgt.meta("policy", 100, 130),
        ObjectId::new("fgt:root:policy"),
        rules,
        fgt.profile.firewall_default,
        fgt.id("snat"),
    ));
    let guest_snat = Rule::new(
        "guest-snat",
        RulePredicate::exact(m_src_dst(&["172.31.0.0/16"], &[])),
        NatAction::Translate {
            addr: ip("10.20.0.254"),
            port: fgt.profile.snat_port,
        },
    )
    .with_span(fgt.span(140, 146));
    add!(SourceNat::new(
        fgt.meta("snat", 140, 146),
        ObjectId::new("fgt:root:ippool:guest-snat"),
        vec![(
            Some(
                [InterfaceId::new("port1")]
                    .into_iter()
                    .collect::<BTreeSet<_>>()
            ),
            guest_snat
        )],
        fgt.id("session-commit"),
    ));
    add!(fgt.session_commit("nexthop"));
    add!(fgt.nexthop(
        &[
            (
                "10.20.0.53",
                "port1",
                Target::Link("fra01-dns behind fra01-ips-01")
            ),
            ("172.31.10.20", "port2", Target::Endpoint("guest-client")),
        ],
        &["port1", "port2"],
        150,
    ));
    add!(fgt.egress(
        "port1",
        EgressMode::Routed,
        Some(("fra01-ips-01/in/1b", None)),
        160
    ));
    add!(fgt.egress("port2", EgressMode::Routed, None, 170));

    // Inline IPS: two directions, one filter each.
    let telnet = |dir: &str| {
        rule(
            &format!("{dir}-block-telnet"),
            Match {
                protocol: ValueCond::one(PROTO_TCP),
                dst_port: PortCond::one(23),
                ..Match::any()
            },
            RuleAction::Deny,
            ips.span(10, 12),
        )
    };
    // The low source port filter is only on the guest side (1B to 1A).
    let low_port = rule(
        "1b-block-low-source-port",
        Match {
            protocol: ValueCond::one(PROTO_UDP),
            src_port: PortCond::In(vec![(0, 1023)]),
            dst_ip: AddrCond::prefixes(&["10.20.0.0/24"]),
            ..Match::any()
        },
        RuleAction::Deny,
        ips.span(13, 15),
    );
    add!(ips.ingress("1b", "filter-1b-1a", 1));
    add!(ips.acl(
        "filter-1b-1a",
        "tp:fra01-inline",
        vec![telnet("1b"), low_port],
        "out/1a",
        10
    ));
    add!(ips.egress(
        "1a",
        EgressMode::Transparent,
        Some(("fra01-core-01/in/eth1-1", None)),
        20
    ));
    add!(ips.ingress("1a", "filter-1a-1b", 2));
    add!(ips.acl(
        "filter-1a-1b",
        "tp:fra01-inline",
        vec![telnet("1a")],
        "out/1b",
        10
    ));
    add!(ips.egress(
        "1b",
        EgressMode::Transparent,
        Some(("fra01-fgt-01/in/port1", None)),
        21
    ));

    // Core.
    add!(core.ingress("eth1-1", "vrf", 10));
    add!(core.ingress("vlan100", "vrf", 20));
    add!(core.vrf(&[("eth1-1", "corp"), ("vlan100", "corp")], "acl", 30));
    add!(core.acl(
        "acl",
        "nxos:users-in",
        vec![
            rule(
                "dns-from-fgt",
                with_proto_dport(
                    m_src_dst(&["10.20.0.254/32"], &["10.20.0.53/32"]),
                    PROTO_UDP,
                    53
                ),
                RuleAction::Permit,
                core.span(41, 41),
            ),
            rule(
                "from-dns",
                m_src_dst(&["10.20.0.53/32"], &[]),
                RuleAction::Permit,
                core.span(42, 42),
            ),
            rule(
                "ssh-replies-from-guest",
                Match {
                    protocol: ValueCond::one(PROTO_TCP),
                    src_port: PortCond::one(22),
                    ..m_src_dst(&["172.31.0.0/16"], &["10.20.0.53/32"])
                },
                RuleAction::Permit,
                core.span(43, 43),
            ),
            rule(
                "deny-users",
                m_src_dst(&[], &["10.20.0.0/24"]),
                RuleAction::Deny,
                core.span(44, 44),
            ),
        ],
        "route",
        40,
    ));
    add!(core.routes(
        "corp",
        &[
            (
                "10.20.0.0/24",
                RouteKind::Connected,
                &[("vlan100", None, "nexthop")]
            ),
            (
                "10.20.0.254/32",
                RouteKind::Connected,
                &[("eth1-1", None, "nexthop")]
            ),
            (
                "172.31.0.0/16",
                RouteKind::Static,
                &[("eth1-1", Some("10.20.0.254"), "nexthop")]
            ),
            ("10.20.0.2/32", RouteKind::Local, &[]),
        ],
        60,
    ));
    add!(core.nexthop(
        &[
            ("10.20.0.53", "vlan100", Target::Endpoint("fra01-dns")),
            ("10.20.0.254", "eth1-1", Target::Link("fra01-fgt-01 port1")),
        ],
        &["vlan100", "eth1-1"],
        70,
    ));
    add!(core.egress("vlan100", EgressMode::Routed, None, 80));
    add!(core.egress(
        "eth1-1",
        EgressMode::Routed,
        Some(("fra01-ips-01/in/1a", None)),
        81
    ));

    if opts.reverse_insertion {
        fns.reverse();
    }
    let mut b = TwinBuilder::new();
    for f in fns {
        b.add_arc(f);
    }
    let mut eps = vec![
        endpoint("guest-client", "172.31.10.20", fid("fra01-fgt-01/in/port2")),
        endpoint("fra01-dns", "10.20.0.53", fid("fra01-core-01/in/vlan100")),
    ];
    if opts.reverse_insertion {
        eps.reverse();
    }
    for e in eps {
        b.endpoint(e);
    }
    b
}

// ---------------------------------------------------------------- topology 2

#[derive(Clone, Copy, Debug, Default)]
pub struct EdgeOpts {
    /// Two owners of the server address in the neighbour table.
    pub duplicate_owner: bool,
}

/// An edge router with destination NAT:
/// client 198.51.100.7 -> edge eth0 -> DNAT 203.0.113.10:443 to
/// 10.20.0.11:8443 -> ACL -> eth1 -> server 10.20.0.11. The links to the
/// two endpoints have known delays; the functions have no delay data.
pub fn edge_dnat(opts: EdgeOpts) -> TwinBuilder {
    let edge = Dev::new("edge-01", generic_router());
    let mut b = TwinBuilder::new();
    b.add(edge.ingress("eth0", "vrf", 10));
    b.add(edge.ingress("eth1", "vrf", 11));
    b.add(edge.vrf(
        &[("eth0", "default"), ("eth1", "default")],
        "session-lookup",
        20,
    ));
    b.add(edge.session_lookup("dnat"));
    b.add(DestinationNat {
        meta: edge.meta("dnat", 30, 36),
        table: ObjectId::new("nat:destination"),
        rules: vec![
            Rule::new(
                "rule 10",
                RulePredicate::exact(with_proto_dport(
                    m_src_dst(&[], &["203.0.113.10/32"]),
                    PROTO_TCP,
                    443,
                )),
                NatAction::Translate {
                    addr: ip("10.20.0.11"),
                    port: PortTranslation::To(8443),
                },
            )
            .with_span(edge.span(31, 36)),
        ],
        next: edge.id("acl"),
    });
    b.add(edge.acl(
        "acl",
        "firewall:forward",
        vec![
            rule(
                "allow-web",
                with_proto_dport(m_src_dst(&[], &["10.20.0.11/32"]), PROTO_TCP, 8443),
                RuleAction::Permit,
                edge.span(41, 44),
            ),
            rule(
                "allow-from-server",
                m_src_dst(&["10.20.0.11/32"], &[]),
                RuleAction::Permit,
                edge.span(48, 48),
            ),
            rule(
                "allow-web-replies",
                Match {
                    protocol: ValueCond::one(PROTO_TCP),
                    src_port: PortCond::one(443),
                    ..m_src_dst(&["203.0.113.10/32"], &[])
                },
                RuleAction::Permit,
                edge.span(45, 47),
            ),
        ],
        "route",
        40,
    ));
    b.add(edge.routes(
        "default",
        &[
            (
                "10.20.0.0/24",
                RouteKind::Connected,
                &[("eth1", None, "session-commit")],
            ),
            (
                "198.51.100.0/24",
                RouteKind::Connected,
                &[("eth0", None, "session-commit")],
            ),
            ("203.0.113.10/32", RouteKind::Local, &[]),
            ("192.0.2.0/24", RouteKind::Null, &[]),
        ],
        50,
    ));
    b.add(edge.session_commit("nexthop"));
    let mut entries = vec![
        ("10.20.0.11", "eth1", Target::Endpoint("server")),
        ("198.51.100.7", "eth0", Target::Endpoint("client")),
    ];
    if opts.duplicate_owner {
        entries.push(("10.20.0.11", "eth1", Target::Endpoint("server-clone")));
    }
    b.add(edge.nexthop(&entries, &["eth0", "eth1"], 60));
    b.add(edge.egress("eth0", EgressMode::Routed, Some(("", Some(2_000_000))), 70));
    b.add(edge.egress("eth1", EgressMode::Routed, Some(("", Some(50_000))), 71));
    b.endpoint(endpoint("client", "198.51.100.7", fid("edge-01/in/eth0")));
    b.endpoint(endpoint("server", "10.20.0.11", fid("edge-01/in/eth1")));
    b.endpoint(endpoint(
        "server-clone",
        "10.20.0.11",
        fid("edge-01/in/eth1"),
    ));
    b
}

// ---------------------------------------------------------------- topology 3

/// Equal-cost paths: r1 has two next hops, r2 and r3, to the server network
/// behind r4. r3 has an ACL that denies TCP 22.
pub fn ecmp() -> TwinBuilder {
    let mut b = TwinBuilder::new();
    let r1 = Dev::new("r1", nxos());
    b.add(r1.ingress("eth0", "vrf", 1));
    b.add(r1.vrf(&[], "route", 2));
    b.add(r1.routes(
        "default",
        &[(
            "10.4.0.0/24",
            RouteKind::Static,
            &[
                ("eth1", Some("10.12.0.2"), "nexthop"),
                ("eth2", Some("10.13.0.3"), "nexthop"),
            ],
        )],
        10,
    ));
    b.add(r1.nexthop(
        &[
            ("10.12.0.2", "eth1", Target::Link("r2")),
            ("10.13.0.3", "eth2", Target::Link("r3")),
        ],
        &["eth1", "eth2"],
        20,
    ));
    b.add(r1.egress("eth1", EgressMode::Routed, Some(("r2/in/eth0", None)), 30));
    b.add(r1.egress("eth2", EgressMode::Routed, Some(("r3/in/eth0", None)), 31));
    for (name, deny) in [("r2", false), ("r3", true)] {
        let r = Dev::new(name, nxos());
        b.add(r.ingress("eth0", "vrf", 1));
        b.add(r.vrf(&[], "acl", 2));
        let mut rules = Vec::new();
        if deny {
            rules.push(rule(
                "deny-ssh",
                with_proto_dport(Match::any(), PROTO_TCP, 22),
                RuleAction::Deny,
                r.span(5, 5),
            ));
        }
        rules.push(rule(
            "permit-any",
            Match::any(),
            RuleAction::Permit,
            r.span(6, 6),
        ));
        b.add(r.acl("acl", "acl-in", rules, "route", 4));
        b.add(r.routes(
            "default",
            &[(
                "10.4.0.0/24",
                RouteKind::Static,
                &[("eth1", Some("10.4.255.4"), "nexthop")],
            )],
            10,
        ));
        b.add(r.nexthop(&[("10.4.255.4", "eth1", Target::Link("r4"))], &["eth1"], 20));
        b.add(r.egress("eth1", EgressMode::Routed, Some(("r4/in/eth0", None)), 30));
    }
    let r4 = Dev::new("r4", nxos());
    b.add(r4.ingress("eth0", "vrf", 1));
    b.add(r4.ingress("eth9", "vrf", 3));
    b.add(r4.vrf(&[], "route", 2));
    b.add(r4.routes(
        "default",
        &[(
            "10.4.0.0/24",
            RouteKind::Connected,
            &[("eth9", None, "nexthop")],
        )],
        10,
    ));
    b.add(r4.nexthop(
        &[("10.4.0.10", "eth9", Target::Endpoint("server"))],
        &["eth9"],
        20,
    ));
    b.add(r4.egress("eth9", EgressMode::Routed, None, 30));
    b.endpoint(endpoint("client", "10.1.0.10", fid("r1/in/eth0")));
    b.endpoint(endpoint("server", "10.4.0.10", fid("r4/in/eth9")));
    b
}

// ---------------------------------------------------------------- topology 4

/// A routing loop: r1 and r2 each route 10.9.0.0/16 to the other.
pub fn routing_loop() -> TwinBuilder {
    let mut b = TwinBuilder::new();
    for (me, peer, gw) in [("r1", "r2", "10.0.12.2"), ("r2", "r1", "10.0.12.1")] {
        let r = Dev::new(me, nxos());
        b.add(r.ingress("eth0", "vrf", 1));
        b.add(r.ingress("eth1", "vrf", 2));
        b.add(r.vrf(&[], "route", 3));
        b.add(r.routes(
            "default",
            &[(
                "10.9.0.0/16",
                RouteKind::Static,
                &[("eth1", Some(gw), "nexthop")],
            )],
            10,
        ));
        b.add(r.nexthop(&[(gw, "eth1", Target::Link("peer"))], &["eth1"], 20));
        b.add(r.egress(
            "eth1",
            EgressMode::Routed,
            Some((&format!("{peer}/in/eth1"), None)),
            30,
        ));
    }
    b.endpoint(endpoint("client", "10.1.0.10", fid("r1/in/eth0")));
    b
}

/// A second visit to a device that is not a loop: r1 sends 10.9.0.10 to r2;
/// r2 translates the destination to 10.1.0.20 and sends it back to r1; r1
/// delivers it to the server.
pub fn hairpin() -> TwinBuilder {
    let mut b = TwinBuilder::new();
    let r1 = Dev::new("r1", nxos());
    b.add(r1.ingress("eth0", "vrf", 1));
    b.add(r1.ingress("eth1", "vrf", 2));
    b.add(r1.vrf(&[], "route", 3));
    b.add(r1.routes(
        "default",
        &[
            (
                "10.9.0.0/16",
                RouteKind::Static,
                &[("eth1", Some("10.0.12.2"), "nexthop")],
            ),
            (
                "10.1.0.0/24",
                RouteKind::Connected,
                &[("eth0", None, "nexthop")],
            ),
        ],
        10,
    ));
    b.add(r1.nexthop(
        &[
            ("10.0.12.2", "eth1", Target::Link("r2")),
            ("10.1.0.20", "eth0", Target::Endpoint("server")),
        ],
        &["eth0", "eth1"],
        20,
    ));
    b.add(r1.egress("eth0", EgressMode::Routed, None, 30));
    b.add(r1.egress("eth1", EgressMode::Routed, Some(("r2/in/eth1", None)), 31));
    let r2 = Dev::new("r2", generic_router());
    b.add(r2.ingress("eth1", "vrf", 1));
    b.add(r2.vrf(&[], "session-lookup", 2));
    b.add(r2.session_lookup("dnat"));
    b.add(DestinationNat {
        meta: r2.meta("dnat", 5, 8),
        table: ObjectId::new("nat:destination"),
        rules: vec![Rule::new(
            "rule 20",
            RulePredicate::exact(m_src_dst(&[], &["10.9.0.10/32"])),
            NatAction::Translate {
                addr: ip("10.1.0.20"),
                port: PortTranslation::Preserve,
            },
        )],
        next: r2.id("route"),
    });
    b.add(r2.routes(
        "default",
        &[(
            "10.1.0.0/24",
            RouteKind::Static,
            &[("eth1", Some("10.0.12.1"), "session-commit")],
        )],
        10,
    ));
    b.add(r2.session_commit("nexthop"));
    b.add(r2.nexthop(&[("10.0.12.1", "eth1", Target::Link("r1"))], &["eth1"], 20));
    b.add(r2.egress("eth1", EgressMode::Routed, Some(("r1/in/eth1", None)), 30));
    b.endpoint(endpoint("client", "10.1.0.10", fid("r1/in/eth0")));
    b.endpoint(endpoint("server", "10.1.0.20", fid("r1/in/eth0")));
    b
}

// ---------------------------------------------------------------- generated

/// A chain of `n` routers for benchmarks: each router has 2 interfaces, an
/// ACL with `acl_rules` rules and `extra_routes` more routes. The client is
/// at r0 and the server at the last router.
pub fn chain(n: usize, acl_rules: usize, extra_routes: usize) -> TwinBuilder {
    assert!(n >= 1);
    let mut b = TwinBuilder::new();
    for i in 0..n {
        let r = Dev::new(&format!("r{i}"), nxos());
        b.add(r.ingress("west", "vrf", 1));
        b.add(r.ingress("east", "vrf", 2));
        b.add(r.vrf(&[], "acl", 3));
        let mut rules = Vec::new();
        for k in 0..acl_rules {
            let third = (k % 250) as u8;
            rules.push(rule(
                &format!("deny-{k}"),
                with_proto_dport(
                    m_src_dst(&[&format!("192.168.{third}.0/24")], &[]),
                    PROTO_TCP,
                    1000 + k as u16,
                ),
                RuleAction::Deny,
                r.span(100 + k as u32, 100 + k as u32),
            ));
        }
        rules.push(rule(
            "permit-any",
            Match::any(),
            RuleAction::Permit,
            r.span(99, 99),
        ));
        b.add(r.acl("acl", "acl-in", rules, "route", 4));
        let mut routes: Vec<(String, RouteKind, Vec<(&str, Option<String>, &str)>)> = Vec::new();
        let east_gw = format!("10.250.{}.2", i % 250);
        let west_gw = format!("10.250.{}.1", (i + 249) % 250);
        if i + 1 < n {
            routes.push((
                "10.255.0.0/24".into(),
                RouteKind::Static,
                vec![("east", Some(east_gw.clone()), "nexthop")],
            ));
        } else {
            routes.push((
                "10.255.0.0/24".into(),
                RouteKind::Connected,
                vec![("east", None, "nexthop")],
            ));
        }
        if i > 0 {
            routes.push((
                "10.254.0.0/24".into(),
                RouteKind::Static,
                vec![("west", Some(west_gw.clone()), "nexthop")],
            ));
        } else {
            routes.push((
                "10.254.0.0/24".into(),
                RouteKind::Connected,
                vec![("west", None, "nexthop")],
            ));
        }
        for k in 0..extra_routes {
            routes.push((
                format!("172.{}.{}.0/24", 16 + (k / 256) % 16, k % 256),
                RouteKind::Static,
                vec![("west", Some(west_gw.clone()), "nexthop")],
            ));
        }
        let mut t = TriePrefixTable::new();
        for (j, (p, kind, nhs)) in routes.iter().enumerate() {
            let nh = nhs
                .iter()
                .map(|(iface, gw, next)| RouteNextHop {
                    interface: InterfaceId::new(*iface),
                    gateway: gw.as_deref().map(ip),
                    next: r.id(next),
                })
                .collect();
            t.insert(
                pfx(p),
                Route::new(*kind, nh, vec![r.span(1000 + j as u32, 1000 + j as u32)]),
            );
        }
        b.add(RouteLookup {
            meta: r.meta("route", 1000, 1000 + routes.len() as u32),
            tables: BTreeMap::from([(VrfId::new("default"), t)]),
        });
        let mut nbr: Vec<(String, &str, Target)> = vec![
            (east_gw.clone(), "east", Target::Link("east neighbour")),
            (west_gw.clone(), "west", Target::Link("west neighbour")),
        ];
        if i + 1 == n {
            nbr.push(("10.255.0.10".into(), "east", Target::Endpoint("server")));
        }
        if i == 0 {
            nbr.push(("10.254.0.10".into(), "west", Target::Endpoint("client")));
        }
        let entries: Vec<(&str, &str, Target)> =
            nbr.iter().map(|(a, i, t)| (a.as_str(), *i, *t)).collect();
        b.add(r.nexthop(&entries, &["east", "west"], 2000));
        let east = (i + 1 < n).then(|| format!("r{}/in/west", i + 1));
        let west = (i > 0).then(|| format!("r{}/in/east", i - 1));
        b.add(r.egress(
            "east",
            EgressMode::Routed,
            east.as_deref().map(|p| (p, None)),
            3000,
        ));
        b.add(r.egress(
            "west",
            EgressMode::Routed,
            west.as_deref().map(|p| (p, None)),
            3001,
        ));
    }
    b.endpoint(endpoint("client", "10.254.0.10", fid("r0/in/west")));
    b.endpoint(endpoint(
        "server",
        "10.255.0.10",
        fid(&format!("r{}/in/east", n - 1)),
    ));
    b
}

pub fn ids(v: &[&str]) -> Vec<FunctionId> {
    v.iter().map(|s| fid(s)).collect()
}
