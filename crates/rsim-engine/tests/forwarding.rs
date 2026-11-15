//! Step 1 "Done when": hand-built multi-device topologies with ACL, NAT and
//! firewall session give correct verdicts and traces in the two directions.

mod common;

use common::*;
use rsim_core::{
    Destination, EndpointId, FieldValue, Header, PROTO_TCP, PROTO_UDP, ReasonCode, SourceSpan,
    TraceStep, Verdict,
};
use rsim_engine::{Answer, BuildError, Executor, Query, Summary, Twin};

fn run(twin: &Twin, from: &str, h: Header) -> Answer {
    let q = Query::from_endpoint(twin, &EndpointId::new(from), h).expect("endpoint");
    Executor::new(twin).run(&q).expect("query runs")
}

fn path(steps: &[&TraceStep]) -> Vec<String> {
    steps.iter().map(|s| s.function.to_string()).collect()
}

fn step<'a>(steps: &[&'a TraceStep], f: &str) -> &'a TraceStep {
    steps
        .iter()
        .find(|s| s.function.as_str() == f)
        .unwrap_or_else(|| panic!("no step {f}"))
}

fn deliver(e: &str) -> Verdict {
    Verdict::Deliver(Destination::Endpoint(EndpointId::new(e)))
}

fn reason_code(v: &Verdict) -> Option<ReasonCode> {
    match v {
        Verdict::Drop(r) | Verdict::Unknown(r) => Some(r.code),
        Verdict::Deliver(_) => None,
    }
}

const FGT: &str = "fra01-fgt-01";

fn f(dev: &str, name: &str) -> String {
    format!("{dev}/{name}")
}

#[test]
fn guest_to_dns_through_firewall_snat_ips_and_acl_and_back() {
    let twin = mini_enterprise(MiniOpts::default())
        .build()
        .expect("twin builds");
    let a = run(
        &twin,
        "guest-client",
        udp("172.31.10.20", 40000, "10.20.0.53", 53),
    );

    assert_eq!(*a.verdict().unwrap(), deliver("fra01-dns"));
    let branches = a.branches();
    assert_eq!(branches.len(), 1);
    let b = &branches[0];
    assert_eq!(
        path(&b.steps),
        [
            "fra01-fgt-01/in/port2",
            "fra01-fgt-01/vrf",
            "fra01-fgt-01/zone-src",
            "fra01-fgt-01/session-lookup",
            "fra01-fgt-01/dnat",
            "fra01-fgt-01/route",
            "fra01-fgt-01/zone-dst",
            "fra01-fgt-01/policy",
            "fra01-fgt-01/snat",
            "fra01-fgt-01/session-commit",
            "fra01-fgt-01/nexthop",
            "fra01-fgt-01/out/port1",
            "fra01-ips-01/in/1b",
            "fra01-ips-01/filter-1b-1a",
            "fra01-ips-01/out/1a",
            "fra01-core-01/in/eth1-1",
            "fra01-core-01/vrf",
            "fra01-core-01/acl",
            "fra01-core-01/route",
            "fra01-core-01/nexthop",
            "fra01-core-01/out/vlan100",
        ]
    );

    // The firewall policy permits by rule guest-to-dns, with its provenance.
    let pol = step(&b.steps, &f(FGT, "policy"));
    assert_eq!(pol.reason.code, ReasonCode::Permitted);
    assert!(
        pol.reason.detail.contains("guest-to-dns"),
        "{:?}",
        pol.reason
    );
    assert!(
        pol.provenance
            .contains(&SourceSpan::new("fra01-fgt-01.conf", 100, 108))
    );

    // Source NAT changes the current header and keeps the original request.
    let snat = step(&b.steps, &f(FGT, "snat"));
    assert_eq!(snat.reason.code, ReasonCode::Translated);
    let w = snat.output.witness().unwrap();
    assert_eq!(w.current.src_ip, FieldValue::Known(ip("10.20.0.254")));
    assert_eq!(w.current.src_port, FieldValue::Known(40000));
    assert_eq!(w.original.src_ip, FieldValue::Known(ip("172.31.10.20")));

    // The session holds the binding.
    assert_eq!(b.state.session_count(), 1);
    let s = &b.state.sessions(&FGT.into())[0];
    assert!(s.is_translated());

    // The core ACL permits by rule dns-from-fgt.
    let acl = step(&b.steps, "fra01-core-01/acl");
    assert!(
        acl.reason.detail.contains("dns-from-fgt"),
        "{:?}",
        acl.reason
    );
    assert!(
        acl.provenance
            .contains(&SourceSpan::line("fra01-core-01.conf", 41))
    );

    // The route lookup steps carry the RIB guard flag of step 1.
    assert_eq!(
        step(&b.steps, "fra01-core-01/route").rib_guard,
        rsim_core::RibGuardFlag::NotChecked
    );

    // The reply runs from the DNS server with the flow state of the forward
    // branch, matches the session and undoes the translation.
    let r = a.reply_of(0).expect("reply ran");
    assert_eq!(*r.verdict().unwrap(), deliver("guest-client"));
    let rb = r.branches();
    assert_eq!(rb.len(), 1);
    assert_eq!(
        path(&rb[0].steps),
        [
            "fra01-core-01/in/vlan100",
            "fra01-core-01/vrf",
            "fra01-core-01/acl",
            "fra01-core-01/route",
            "fra01-core-01/nexthop",
            "fra01-core-01/out/eth1-1",
            "fra01-ips-01/in/1a",
            "fra01-ips-01/filter-1a-1b",
            "fra01-ips-01/out/1b",
            "fra01-fgt-01/in/port1",
            "fra01-fgt-01/vrf",
            "fra01-fgt-01/zone-src",
            "fra01-fgt-01/session-lookup",
            "fra01-fgt-01/dnat",
            "fra01-fgt-01/route",
            "fra01-fgt-01/zone-dst",
            "fra01-fgt-01/policy",
            "fra01-fgt-01/snat",
            "fra01-fgt-01/session-commit",
            "fra01-fgt-01/nexthop",
            "fra01-fgt-01/out/port2",
        ]
    );
    let lookup = step(&rb[0].steps, &f(FGT, "session-lookup"));
    assert_eq!(lookup.reason.code, ReasonCode::SessionMatched);
    assert!(
        lookup
            .reason
            .detail
            .starts_with("reply packets · session 0")
    );
    let pol = step(&rb[0].steps, &f(FGT, "policy"));
    assert_eq!(pol.reason.code, ReasonCode::SessionMatched);
    let end = rb[0].packets.witness().unwrap();
    assert_eq!(end.current.src_ip, FieldValue::Known(ip("10.20.0.53")));
    assert_eq!(end.current.src_port, FieldValue::Known(53));
    assert_eq!(end.current.dst_ip, FieldValue::Known(ip("172.31.10.20")));
    assert_eq!(end.current.dst_port, FieldValue::Known(40000));
    // The original request of the reply is the reply as the server sent it.
    assert_eq!(end.original.dst_ip, FieldValue::Known(ip("10.20.0.254")));
}

#[test]
fn guest_to_dns_on_tcp_80_is_denied_by_the_default_action() {
    let twin = mini_enterprise(MiniOpts::default()).build().unwrap();
    let a = run(
        &twin,
        "guest-client",
        tcp("172.31.10.20", 40000, "10.20.0.53", 80),
    );
    let Some(Verdict::Drop(r)) = a.verdict() else {
        panic!("{:?}", a.summary)
    };
    assert_eq!(r.code, ReasonCode::Denied);
    assert!(r.detail.contains("default action"), "{r:?}");
    let b = &a.branches()[0];
    assert_eq!(
        b.steps.last().unwrap().function.as_str(),
        "fra01-fgt-01/policy"
    );
    assert!(a.replies.is_empty());
}

#[test]
fn corp_to_guest_on_telnet_is_blocked_by_the_inline_ips() {
    let twin = mini_enterprise(MiniOpts::default()).build().unwrap();
    let a = run(
        &twin,
        "fra01-dns",
        tcp("10.20.0.53", 50000, "172.31.10.20", 23),
    );
    let Some(Verdict::Drop(r)) = a.verdict() else {
        panic!("{:?}", a.summary)
    };
    assert_eq!(r.code, ReasonCode::Denied);
    assert!(r.detail.contains("1a-block-telnet"), "{r:?}");
    let last = a.branches()[0].steps.last().unwrap().function.to_string();
    assert_eq!(last, "fra01-ips-01/filter-1a-1b");
}

#[test]
fn corp_to_guest_on_ssh_passes_and_the_reply_uses_the_session() {
    let twin = mini_enterprise(MiniOpts::default()).build().unwrap();
    let a = run(
        &twin,
        "fra01-dns",
        tcp("10.20.0.53", 50000, "172.31.10.20", 22),
    );
    assert_eq!(*a.verdict().unwrap(), deliver("guest-client"));
    let b = &a.branches()[0];
    let pol = step(&b.steps, &f(FGT, "policy"));
    assert!(pol.reason.detail.contains("corp-to-guest-mgmt"));
    assert_eq!(
        step(&b.steps, &f(FGT, "snat")).reason.code,
        ReasonCode::NotTranslated
    );

    let r = a.reply_of(0).expect("reply ran");
    assert_eq!(*r.verdict().unwrap(), deliver("fra01-dns"));
    let rb = &r.branches()[0];
    assert_eq!(
        step(&rb.steps, &f(FGT, "session-lookup")).reason.code,
        ReasonCode::SessionMatched
    );
    // The reply passes the policy by the session; no policy rule permits
    // guest to corp on these ports.
    assert_eq!(
        step(&rb.steps, &f(FGT, "policy")).reason.code,
        ReasonCode::SessionMatched
    );
}

#[test]
fn an_unstated_source_port_against_a_rule_that_reads_it_is_unknown() {
    let twin = mini_enterprise(MiniOpts::default()).build().unwrap();
    // The request states no source port.
    let h = Header::request(ip("172.31.10.20"), ip("10.20.0.53"), PROTO_UDP).with_dst_port(53);
    let a = run(&twin, "guest-client", h);
    let Some(Verdict::Unknown(r)) = a.verdict() else {
        panic!("{:?}", a.summary)
    };
    assert_eq!(r.code, ReasonCode::MatchUnknown);
    assert!(r.detail.contains("1b-block-low-source-port"), "{r:?}");
    // A stated high port does not match the rule, and a stated low port does.
    let high = run(
        &twin,
        "guest-client",
        udp("172.31.10.20", 40000, "10.20.0.53", 53),
    );
    assert_eq!(*high.verdict().unwrap(), deliver("fra01-dns"));
    let low = run(
        &twin,
        "guest-client",
        udp("172.31.10.20", 123, "10.20.0.53", 53),
    );
    assert_eq!(
        reason_code(low.verdict().unwrap()),
        Some(ReasonCode::Denied)
    );
}

#[test]
fn an_unhandled_policy_rule_makes_only_the_affected_packets_unknown() {
    let twin = mini_enterprise(MiniOpts {
        unhandled_policy_rule: true,
        ..MiniOpts::default()
    })
    .build()
    .unwrap();
    // Rule 1 matches before the unhandled rule, so the answer stays.
    let dns = run(
        &twin,
        "guest-client",
        udp("172.31.10.20", 40000, "10.20.0.53", 53),
    );
    assert_eq!(*dns.verdict().unwrap(), deliver("fra01-dns"));
    // Packets that reach the unhandled rule are unknown, with its span.
    let web = run(
        &twin,
        "guest-client",
        tcp("172.31.10.20", 40000, "10.20.0.53", 80),
    );
    let Some(Verdict::Unknown(r)) = web.verdict() else {
        panic!("{:?}", web.summary)
    };
    assert_eq!(r.code, ReasonCode::UnhandledStanza);
    let last = *web.branches()[0].steps.last().unwrap();
    assert!(
        last.provenance
            .contains(&SourceSpan::new("fra01-fgt-01.conf", 110, 118))
    );
}

#[test]
fn a_missing_context_provider_is_a_build_error() {
    let errors = mini_enterprise(MiniOpts {
        skip_dst_zone: true,
        ..MiniOpts::default()
    })
    .build()
    .expect_err("the policy needs the destination zone");
    assert_eq!(
        errors,
        vec![BuildError::MissingContext {
            function: fid("fra01-fgt-01/policy"),
            attribute: rsim_core::ContextAttr::DstZone,
            via: Some(fid("fra01-fgt-01/route")),
        }]
    );
}

#[test]
fn destination_nat_at_the_edge_and_the_reply_restores_the_public_address() {
    let twin = edge_dnat(EdgeOpts::default()).build().unwrap();
    let a = run(
        &twin,
        "client",
        tcp("198.51.100.7", 51000, "203.0.113.10", 443),
    );
    assert_eq!(*a.verdict().unwrap(), deliver("server"));
    let b = &a.branches()[0];
    let dnat = step(&b.steps, "edge-01/dnat");
    assert_eq!(dnat.reason.code, ReasonCode::Translated);
    let w = dnat.output.witness().unwrap();
    assert_eq!(w.current.dst_ip, FieldValue::Known(ip("10.20.0.11")));
    assert_eq!(w.current.dst_port, FieldValue::Known(8443));
    assert_eq!(w.original.dst_ip, FieldValue::Known(ip("203.0.113.10")));
    assert_eq!(w.original.dst_port, FieldValue::Known(443));
    // The ACL reads the translated header.
    assert!(
        step(&b.steps, "edge-01/acl")
            .reason
            .detail
            .contains("allow-web")
    );

    // Delay: the link to the server is known, the functions are not, so the
    // total is a lower bound with the missing components listed.
    assert_eq!(b.delay.known_ns(), 50_000);
    assert!(b.delay.is_lower_bound());
    assert_eq!(b.delay.missing().len(), b.steps.len());

    let r = a.reply_of(0).expect("reply ran");
    assert_eq!(*r.verdict().unwrap(), deliver("client"));
    let rb = &r.branches()[0];
    let end = rb.packets.witness().unwrap();
    assert_eq!(end.current.src_ip, FieldValue::Known(ip("203.0.113.10")));
    assert_eq!(end.current.src_port, FieldValue::Known(443));
    assert_eq!(end.current.dst_ip, FieldValue::Known(ip("198.51.100.7")));
    assert_eq!(rb.delay.known_ns(), 2_000_000);
}

#[test]
fn no_route_and_null_route_are_drops() {
    let twin = edge_dnat(EdgeOpts::default()).build().unwrap();
    let a = run(&twin, "server", tcp("10.20.0.11", 8443, "8.8.8.8", 443));
    assert_eq!(reason_code(a.verdict().unwrap()), Some(ReasonCode::NoRoute));
    let a = run(&twin, "server", tcp("10.20.0.11", 8443, "192.0.2.5", 443));
    assert_eq!(
        reason_code(a.verdict().unwrap()),
        Some(ReasonCode::NullRoute)
    );
}

#[test]
fn two_owners_of_one_address_are_unknown_and_named() {
    let twin = edge_dnat(EdgeOpts {
        duplicate_owner: true,
    })
    .build()
    .unwrap();
    let a = run(
        &twin,
        "client",
        tcp("198.51.100.7", 51000, "203.0.113.10", 443),
    );
    let Some(Verdict::Unknown(r)) = a.verdict() else {
        panic!("{:?}", a.summary)
    };
    assert_eq!(r.code, ReasonCode::AmbiguousOwner);
    assert!(r.detail.contains("server, server-clone"), "{r:?}");
}

#[test]
fn equal_cost_paths_are_shown_one_by_one() {
    let twin = ecmp().build().unwrap();
    let ssh = tcp("10.1.0.10", 40000, "10.4.0.10", 22);
    let a = run(&twin, "client", ssh);
    assert_eq!(a.summary, Summary::DependsOnPath);

    // The trace names each path with its result, in the fixed order.
    let br = a.branches();
    assert_eq!(br.len(), 2);
    let alt = |i: usize| {
        br[i]
            .steps
            .iter()
            .find_map(|s| s.alternative.clone())
            .unwrap()
    };
    assert_eq!((alt(0).index, alt(0).count), (0, 2));
    assert_eq!(alt(0).label, "via 10.12.0.2 on eth1");
    assert_eq!(alt(1).label, "via 10.13.0.3 on eth2");
    assert_eq!(br[0].verdict, &deliver("server"));
    assert_eq!(reason_code(br[1].verdict), Some(ReasonCode::Denied));

    // Web traffic is delivered on both paths.
    let web = tcp("10.1.0.10", 40000, "10.4.0.10", 80);
    assert_eq!(
        run(&twin, "client", web).summary,
        Summary::Same(deliver("server"))
    );
}

#[test]
fn a_routing_loop_is_a_drop_with_reason_loop() {
    let twin = routing_loop().build().unwrap();
    let a = run(&twin, "client", tcp("10.1.0.10", 40000, "10.9.0.1", 80));
    assert_eq!(reason_code(a.verdict().unwrap()), Some(ReasonCode::Loop));
    let b = &a.branches()[0];
    let ingresses: Vec<String> = b
        .steps
        .iter()
        .filter(|s| s.kind == rsim_core::FunctionKind::Ingress)
        .map(|s| s.function.to_string())
        .collect();
    // The second arrival at r2 eth1 has a different context at its input
    // (r1 had received the packets on eth1, not on eth0), so it is not a
    // loop. After the ingress of r2, the context is the same as on the first
    // visit, so the full state at r2/vrf repeats: that is the loop.
    assert_eq!(
        ingresses,
        ["r1/in/eth0", "r2/in/eth1", "r1/in/eth1", "r2/in/eth1"]
    );
    let last = *b.steps.last().unwrap();
    assert_eq!(last.outcome, rsim_core::Outcome::Forward(fid("r2/vrf")));
}

#[test]
fn a_second_visit_with_a_different_header_is_not_a_loop() {
    let twin = hairpin().build().unwrap();
    let a = run(&twin, "client", tcp("10.1.0.10", 40000, "10.9.0.10", 80));
    assert_eq!(*a.verdict().unwrap(), deliver("server"));
    let b = &a.branches()[0];
    let r1_routes = b
        .steps
        .iter()
        .filter(|s| s.function.as_str() == "r1/route")
        .count();
    assert_eq!(r1_routes, 2);
}

#[test]
fn a_later_fragment_has_no_ports_and_does_not_match_a_port_rule() {
    let twin = edge_dnat(EdgeOpts::default()).build().unwrap();
    let h = Header::request(ip("198.51.100.7"), ip("203.0.113.10"), PROTO_TCP).as_later_fragment();
    let a = run(&twin, "client", h);
    // The DNAT rule reads the destination port, which is absent, so the rule
    // does not match. The packet goes to the edge itself and the ACL denies it.
    let b = &a.branches()[0];
    assert_eq!(
        step(&b.steps, "edge-01/dnat").reason.code,
        ReasonCode::NotTranslated
    );
    assert_eq!(reason_code(a.verdict().unwrap()), Some(ReasonCode::Denied));
}
