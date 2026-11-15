//! The mini-enterprise topology.

use std::collections::BTreeSet;

use rsim_core::{
    AddrCond, InterfaceId, Match, ObjectId, PROTO_TCP, PROTO_UDP, PortCond, RulePredicate,
    ValueCond,
};
use rsim_engine::TwinBuilder;
use rsim_functions::{
    DestinationNat, EgressMode, FirewallPolicy, NatAction, PortTranslation, RouteKind, Rule,
    RuleAction, SourceNat, ZoneRole, ZoneScope,
};

use crate::builders::*;
use crate::helpers::*;
use crate::profiles::*;

/// Options for the mini-enterprise topology.
#[derive(Clone, Copy, Debug, Default)]
pub struct MiniOpts {
    /// Add a FortiGate policy rule from an unhandled stanza after rule 1.
    pub unhandled_policy_rule: bool,
    /// Leave out the destination zone lookup on the FortiGate.
    pub skip_dst_zone: bool,
    /// Build the functions in reverse order.
    pub reverse_insertion: bool,
    /// The source NAT selects the source port.
    pub snat_selects_port: bool,
}

/// A guest client reaches a DNS server through a firewall, an inline IPS and
/// a core switch:
///
/// guest-client 172.31.10.20 -> fra01-fgt-01 port2 (zone guest) -> policy
/// guest-to-dns, SNAT guest-snat to 10.20.0.254 -> port1 (zone corp) ->
/// fra01-ips-01 1B -> 1A (inline) -> fra01-core-01 eth1-1 -> vlan100 ->
/// fra01-dns 10.20.0.53.
///
/// core-01 routes between eth1-1 and vlan100 with a host route to the
/// FortiGate address. It has the ACL "users-in" and a static route to
/// 172.31.0.0/16. The IPS has filters.
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
            port: if opts.snat_selects_port {
                PortTranslation::Allocate
            } else {
                fgt.profile.snat_port
            },
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
        add_host(&mut b, e);
    }
    b
}
