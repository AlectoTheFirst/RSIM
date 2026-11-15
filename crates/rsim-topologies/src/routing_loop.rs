//! The topology with a routing loop.

use rsim_engine::TwinBuilder;
use rsim_functions::{EgressMode, RouteKind};

use crate::builders::*;
use crate::helpers::*;
use crate::profiles::*;

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
