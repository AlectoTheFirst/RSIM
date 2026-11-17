//! A VXLAN fabric: 4 leaves and 2 spines.

use std::collections::BTreeMap;

use rsim_core::{FieldValue, Match, PROTO_UDP, VrfId};
use rsim_engine::TwinBuilder;
use rsim_functions::{
    EgressMode, Fib, OuterFields, Route, RouteKind, RouteLookup, RouteNextHop, RuleAction, Segment,
    TunnelPeer, VxlanDecap, VxlanEncap,
};

use crate::builders::*;
use crate::helpers::*;
use crate::profiles::*;

const LEAVES: u8 = 4;
const SPINES: u8 = 2;
const VNI: u32 = 50001;
const TENANT: &str = "tenant";
const UNDERLAY: &str = "default";
const HOSTS: [&str; LEAVES as usize] = ["host1", "host2", "host3", "host4"];
const LEAF_NAMES: [&str; LEAVES as usize] = ["leaf1", "leaf2", "leaf3", "leaf4"];
const SPINE_NAMES: [&str; SPINES as usize] = ["spine1", "spine2"];

/// The tunnel end of leaf `n`.
fn vtep(n: u8) -> String {
    format!("192.0.2.{n}")
}

/// The address of spine `s` on its link to leaf `n`.
fn spine_addr(s: u8, n: u8) -> String {
    format!("172.16.{s}.{}", 2 * n)
}

/// The address of leaf `n` on its link to spine `s`.
fn leaf_addr(s: u8, n: u8) -> String {
    format!("172.16.{s}.{}", 2 * n + 1)
}

/// The outer fields of the test leaves: the UDP port 4789, a source port
/// from a hash of the inner header and the marking not confirmed.
fn outer() -> OuterFields {
    OuterFields {
        udp_port: 4789,
        src_port: FieldValue::Unknown,
        dscp: FieldValue::Unknown,
        ecn: FieldValue::Unknown,
    }
}

/// A VXLAN fabric with symmetric routing in the VRF `tenant` over the VNI
/// 50001. Leaf `n` has the tunnel end 192.0.2.`n` and the host
/// 10.`n`.0.10 on eth9; its links eth1 and eth2 go to spine1 and spine2,
/// which are equal-cost paths to each other leaf. spine2 has an ACL that
/// denies the VXLAN packets to leaf3. spine1 has no route to leaf4.
pub fn leaf_spine() -> TwinBuilder {
    let mut b = TwinBuilder::new();
    for n in 1..=LEAVES {
        leaf(&mut b, n);
    }
    for s in 1..=SPINES {
        spine(&mut b, s);
    }
    b
}

fn leaf(b: &mut TwinBuilder, n: u8) {
    let name = format!("leaf{n}");
    let d = Dev::new(&name, nxos());
    let host = format!("host{n}");
    b.add(d.ingress("eth9", "vrf", 1));
    for s in 1..=SPINES {
        b.add(d.ingress(&format!("eth{s}"), "vrf", 1 + u32::from(s)));
    }
    b.add(d.vrf(&[("eth9", TENANT)], "route", 5));

    let mut tenant = Fib::new();
    let mut underlay = Fib::new();
    let mut line = 10;
    let mut span = || {
        line += 1;
        d.span(line, line)
    };
    let nh = |iface: &str, gw: Option<String>, next: &str| RouteNextHop {
        interface: rsim_core::InterfaceId::new(iface),
        gateway: gw.map(|g| ip(&g)),
        next: d.id(next),
    };
    tenant.insert(
        pfx(&format!("10.{n}.0.0/24")),
        Route::new(
            RouteKind::Connected,
            vec![nh("eth9", None, "nexthop")],
            vec![span()],
        ),
    );
    underlay.insert(
        pfx(&format!("{}/32", vtep(n))),
        Route::new(RouteKind::Local, Vec::new(), vec![span()]),
    );
    for m in (1..=LEAVES).filter(|&m| m != n) {
        tenant.insert(
            pfx(&format!("10.{m}.0.0/24")),
            Route::new(
                RouteKind::Static,
                vec![nh("nve1", Some(vtep(m)), "vxlan-encap")],
                vec![span()],
            ),
        );
        underlay.insert(
            pfx(&format!("{}/32", vtep(m))),
            Route::new(
                RouteKind::Static,
                (1..=SPINES)
                    .map(|s| nh(&format!("eth{s}"), Some(spine_addr(s, n)), "nexthop"))
                    .collect(),
                vec![span()],
            ),
        );
    }
    b.add(RouteLookup {
        meta: d.meta("route", 10, line),
        tables: [
            (VrfId::new(TENANT), tenant),
            (VrfId::new(UNDERLAY), underlay),
        ]
        .into_iter()
        .collect(),
        fallback: None,
        local: Some(d.id("vxlan-decap")),
    });

    let ten = format!("10.{n}.0.10");
    let spines: Vec<String> = (1..=SPINES).map(|s| spine_addr(s, n)).collect();
    let ifaces: Vec<String> = (1..=SPINES).map(|s| format!("eth{s}")).collect();
    let mut entries = vec![(
        ten.as_str(),
        "eth9",
        Target::Endpoint(HOSTS[usize::from(n) - 1]),
    )];
    for (i, a) in spines.iter().enumerate() {
        entries.push((a.as_str(), ifaces[i].as_str(), Target::Link(SPINE_NAMES[i])));
    }
    let mut egress: Vec<&str> = vec!["eth9"];
    egress.extend(ifaces.iter().map(String::as_str));
    b.add(d.nexthop(&entries, &egress, 40));
    b.add(d.egress("eth9", EgressMode::Routed, None, 50));
    for s in 1..=SPINES {
        let peer = format!("spine{s}/in/eth{n}");
        b.add(d.egress(
            &format!("eth{s}"),
            EgressMode::Routed,
            Some((peer.as_str(), None)),
            50 + u32::from(s),
        ));
    }

    b.add(VxlanEncap {
        meta: d.meta("vxlan-encap", 60, 62),
        source: ip(&vtep(n)),
        peer: TunnelPeer::NextHop,
        vnis: [(Segment::Vrf(VrfId::new(TENANT)), VNI)]
            .into_iter()
            .collect(),
        outer: outer(),
        underlay: VrfId::new(UNDERLAY),
        next: d.id("route"),
    });
    let vnis: BTreeMap<u32, (Segment, rsim_core::FunctionId)> =
        [(VNI, (Segment::Vrf(VrfId::new(TENANT)), d.id("route")))]
            .into_iter()
            .collect();
    b.add(VxlanDecap {
        meta: d.meta("vxlan-decap", 60, 62),
        vnis,
        plain: None,
        port: None,
        unmatched: rsim_functions::Unmatched::Drop,
    });
    let attach = fid(&format!("{name}/in/eth9"));
    add_host(b, endpoint(&host, &ten, attach));
}

fn spine(b: &mut TwinBuilder, s: u8) {
    let name = format!("spine{s}");
    let d = Dev::new(&name, nxos());
    for n in 1..=LEAVES {
        b.add(d.ingress(&format!("eth{n}"), "vrf", u32::from(n)));
    }
    let first = if s == 2 { "acl" } else { "route" };
    b.add(d.vrf(&[], first, 5));
    if s == 2 {
        let deny = Match {
            protocol: rsim_core::ValueCond::one(PROTO_UDP),
            dst_port: rsim_core::PortCond::one(4789),
            ..m_src_dst(&[], &[&format!("{}/32", vtep(3))])
        };
        b.add(d.acl(
            "acl",
            "fabric-in",
            vec![
                rule("deny-vxlan-leaf3", deny, RuleAction::Deny, d.span(7, 7)),
                rule("permit-any", Match::any(), RuleAction::Permit, d.span(8, 8)),
            ],
            "route",
            6,
        ));
    }
    let leaves: Vec<u8> = (1..=LEAVES).filter(|&n| !(s == 1 && n == 4)).collect();
    let prefixes: Vec<String> = leaves.iter().map(|&n| format!("{}/32", vtep(n))).collect();
    let gws: Vec<String> = leaves.iter().map(|&n| leaf_addr(s, n)).collect();
    let ifaces: Vec<String> = leaves.iter().map(|&n| format!("eth{n}")).collect();
    let hops: Vec<[(&str, Option<&str>, &str); 1]> = leaves
        .iter()
        .enumerate()
        .map(|(i, _)| [(ifaces[i].as_str(), Some(gws[i].as_str()), "nexthop")])
        .collect();
    let routes: Vec<(&str, RouteKind, &[(&str, Option<&str>, &str)])> = leaves
        .iter()
        .enumerate()
        .map(|(i, _)| {
            (
                prefixes[i].as_str(),
                RouteKind::Static,
                &hops[i][..] as &[(&str, Option<&str>, &str)],
            )
        })
        .collect();
    b.add(d.routes(UNDERLAY, &routes, 10));
    let all: Vec<u8> = (1..=LEAVES).collect();
    let all_gws: Vec<String> = all.iter().map(|&n| leaf_addr(s, n)).collect();
    let all_ifaces: Vec<String> = all.iter().map(|&n| format!("eth{n}")).collect();
    let entries: Vec<(&str, &str, Target)> = all
        .iter()
        .enumerate()
        .map(|(i, &n)| {
            (
                all_gws[i].as_str(),
                all_ifaces[i].as_str(),
                Target::Link(LEAF_NAMES[usize::from(n) - 1]),
            )
        })
        .collect();
    let egress: Vec<&str> = all_ifaces.iter().map(String::as_str).collect();
    b.add(d.nexthop(&entries, &egress, 20));
    for n in all {
        let peer = format!("leaf{n}/in/eth{s}");
        b.add(d.egress(
            &format!("eth{n}"),
            EgressMode::Routed,
            Some((peer.as_str(), None)),
            30 + u32::from(n),
        ));
    }
}
