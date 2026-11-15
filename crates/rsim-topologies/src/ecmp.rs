//! The topology with equal-cost paths.

use rsim_core::{Match, PROTO_TCP};
use rsim_engine::TwinBuilder;
use rsim_functions::{EgressMode, RouteKind, RuleAction};

use crate::builders::*;
use crate::helpers::*;
use crate::profiles::*;

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
    add_host(&mut b, endpoint("client", "10.1.0.10", fid("r1/in/eth0")));
    add_host(&mut b, endpoint("server", "10.4.0.10", fid("r4/in/eth9")));
    b
}
