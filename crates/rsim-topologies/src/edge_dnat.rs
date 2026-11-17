//! The edge router with destination NAT.

use rsim_core::{Match, ObjectId, PROTO_TCP, PortCond, RulePredicate, ValueCond};
use rsim_engine::TwinBuilder;
use rsim_functions::{
    DestinationNat, EgressMode, NatAction, PortTranslation, RouteKind, Rule, RuleAction,
};

use crate::builders::*;
use crate::helpers::*;
use crate::profiles::*;

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
        ingress: Vec::new(),
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
    add_host(
        &mut b,
        endpoint("client", "198.51.100.7", fid("edge-01/in/eth0")),
    );
    add_host(
        &mut b,
        endpoint("server", "10.20.0.11", fid("edge-01/in/eth1")),
    );
    add_host(
        &mut b,
        endpoint("server-clone", "10.20.0.11", fid("edge-01/in/eth1")),
    );
    b
}
