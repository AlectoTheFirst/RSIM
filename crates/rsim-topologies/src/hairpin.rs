//! The topology with a second visit to a device that is not a loop.

use rsim_core::{ObjectId, RulePredicate};
use rsim_engine::TwinBuilder;
use rsim_functions::{DestinationNat, EgressMode, NatAction, PortTranslation, RouteKind, Rule};

use crate::builders::*;
use crate::helpers::*;
use crate::profiles::*;

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
    add_host(&mut b, endpoint("client", "10.1.0.10", fid("r1/in/eth0")));
    add_host(&mut b, endpoint("server", "10.1.0.20", fid("r1/in/eth0")));
    b
}
