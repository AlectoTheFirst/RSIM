//! The generated chain of routers.

use std::collections::BTreeMap;

use rsim_core::{InterfaceId, Match, PROTO_TCP, PrefixTable, TriePrefixTable, VrfId};
use rsim_engine::TwinBuilder;
use rsim_functions::{EgressMode, Route, RouteKind, RouteLookup, RouteNextHop, RuleAction};

use crate::builders::*;
use crate::helpers::*;
use crate::profiles::*;

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
