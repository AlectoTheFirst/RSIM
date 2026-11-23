//! The SD-WAN overlay: the candidate tunnels of a branch to a hub over 2
//! transport networks, the VCMP encapsulation, a transport ACL on the outer
//! header, the tunnel states, a steering rule, the reply, the firewall of an
//! edge, and the business policy with a direct exit and a backhaul.

use rsim_core::{
    AlternativeKind, Destination, DeviceId, Encap, EndpointId, ExitPoint, FieldValue, Header,
    InterfaceId, PROTO_UDP, ReasonCode, Verdict,
};
use rsim_engine::{Answer, Executor, Query, Twin};
use rsim_functions::TunnelState;
use rsim_topologies::*;

const SELECT: &str = "branch1/sdwan/select/0/hub1";

fn twin(opts: SdwanOpts) -> Twin {
    sdwan_site(opts).build().expect("twin builds")
}

fn run(twin: &Twin, h: &Header) -> Answer {
    Executor::new(twin)
        .run(&Query::path(twin, h))
        .expect("query runs")
}

fn deliver(e: &str) -> Verdict {
    Verdict::Deliver(Destination::Endpoint(EndpointId::new(e)))
}

fn exit(device: &str, interface: &str) -> Verdict {
    Verdict::Exit(ExitPoint {
        device: DeviceId::new(device),
        interface: InterfaceId::new(interface),
    })
}

fn code(v: &Verdict) -> Option<ReasonCode> {
    match v {
        Verdict::Drop(r) | Verdict::Unknown(r) => Some(r.code),
        Verdict::Deliver(_) | Verdict::Exit(_) => None,
    }
}

fn functions(a: &Answer, branch: usize) -> Vec<String> {
    a.branches()[branch]
        .steps
        .iter()
        .map(|s| s.function.to_string())
        .collect()
}

fn web() -> Header {
    tcp("10.1.0.10", 40000, "10.9.0.10", 443)
}

fn dns() -> Header {
    udp("10.1.0.10", 40000, "10.9.0.10", 53)
}

#[test]
fn each_tunnel_is_a_candidate_and_both_deliver() {
    let twin = twin(SdwanOpts::default());
    let a = run(&twin, &web());
    let b = a.branches();
    assert_eq!(b.len(), 2);
    for (i, transport) in ["internet", "mpls"].iter().enumerate() {
        assert_eq!(b[i].verdict, &deliver("host9"));
        let f = functions(&a, i);
        let at = |name: &str| {
            f.iter()
                .position(|x| x == name)
                .unwrap_or_else(|| panic!("{name} is not in {f:?}"))
        };
        assert!(at(SELECT) < at(&format!("{transport}/route")));
        assert!(at(&format!("{transport}/route")) < at("hub1/vcmp/decap"));
        let step = b[i]
            .steps
            .iter()
            .find(|s| s.function.as_str() == SELECT)
            .unwrap();
        let alt = step.alternative.as_ref().expect("a candidate");
        assert_eq!(alt.kind, AlternativeKind::Candidate);
        assert_eq!((alt.index, alt.count), (i as u32, 2));
        assert_eq!(
            step.assumption.as_deref(),
            Some("branch1 sends the flow on one or more of its 2 tunnels to hub1")
        );
        let reply = a.reply_of(i).expect("the reply ran");
        assert_eq!(reply.verdict(), Some(&deliver("host1")));
    }
    assert_eq!(a.verdict(), Some(&deliver("host9")));
}

#[test]
fn the_packets_on_a_transport_have_the_vcmp_header_and_the_inner_header() {
    let twin = twin(SdwanOpts::default());
    let a = run(&twin, &web());
    let b = &a.branches()[0];
    let step = b
        .steps
        .iter()
        .find(|s| s.function.as_str() == "internet/route")
        .unwrap();
    let w = step.input.witness().unwrap().current;
    assert_eq!(w.src_ip, FieldValue::Known(ip("198.51.100.1")));
    assert_eq!(w.dst_ip, FieldValue::Known(ip("203.0.113.1")));
    assert_eq!(w.protocol, FieldValue::Known(PROTO_UDP));
    assert_eq!(w.dst_port, FieldValue::Known(2426));
    assert_eq!(
        w.encap,
        vec![Encap::Vcmp {
            src: ip("198.51.100.1"),
            dst: ip("203.0.113.1"),
            segment: 0,
        }]
    );
    let inner = w.inner.expect("the inner header");
    assert_eq!(inner.dst_ip, FieldValue::Known(ip("10.9.0.10")));
    assert_eq!(inner.dst_port, FieldValue::Known(443));
    let end = b.packets.witness().unwrap().current;
    assert!(end.encap.is_empty() && end.inner.is_none());
}

#[test]
fn candidates_with_different_results_give_unknown() {
    let twin = twin(SdwanOpts {
        internet_denies_vcmp: true,
        ..SdwanOpts::default()
    });
    let a = run(&twin, &web());
    let b = a.branches();
    assert_eq!(b.len(), 2);
    assert_eq!(code(b[0].verdict), Some(ReasonCode::Denied));
    assert_eq!(b[0].steps.last().unwrap().function.as_str(), "internet/acl");
    assert_eq!(b[1].verdict, &deliver("host9"));
    let v = a.verdict().expect("one result");
    assert_eq!(code(v), Some(ReasonCode::SelectionNotCollected));
    let Verdict::Unknown(r) = v else {
        panic!("the result is not unknown: {v:?}");
    };
    assert_eq!(
        r.detail,
        "the candidates of branch1/sdwan/select/0/hub1 end differently"
    );
}

#[test]
fn a_tunnel_that_is_down_is_no_candidate() {
    let twin = twin(SdwanOpts {
        private_tunnel: TunnelState::Down,
        ..SdwanOpts::default()
    });
    let a = run(&twin, &web());
    let b = a.branches();
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].verdict, &deliver("host9"));
    let f = functions(&a, 0);
    assert!(f.contains(&"internet/route".to_string()), "{f:?}");
    assert!(!f.contains(&"mpls/route".to_string()), "{f:?}");
    let step = b[0]
        .steps
        .iter()
        .find(|s| s.function.as_str() == SELECT)
        .unwrap();
    assert!(step.alternative.is_none());
    assert!(step.assumption.is_none());
}

#[test]
fn a_tunnel_state_that_is_not_collected_gives_unknown() {
    let twin = twin(SdwanOpts {
        private_tunnel: TunnelState::NotCollected,
        ..SdwanOpts::default()
    });
    let a = run(&twin, &web());
    let b = a.branches();
    assert_eq!(b.len(), 1);
    assert_eq!(code(b[0].verdict), Some(ReasonCode::NotCollected));
    assert_eq!(b[0].steps.last().unwrap().function.as_str(), SELECT);
}

#[test]
fn a_steering_rule_keeps_only_the_tunnels_of_its_link() {
    let twin = twin(SdwanOpts {
        pin_dns: true,
        ..SdwanOpts::default()
    });
    let a = run(&twin, &dns());
    let b = a.branches();
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].verdict, &deliver("host9"));
    let f = functions(&a, 0);
    assert!(f.contains(&"mpls/route".to_string()), "{f:?}");
    assert!(!f.contains(&"internet/route".to_string()), "{f:?}");
    // A packet that the rule does not match has both candidates.
    assert_eq!(run(&twin, &web()).branches().len(), 2);
}

#[test]
fn a_steering_rule_with_no_tunnel_up_on_its_link_drops() {
    let twin = twin(SdwanOpts {
        pin_dns: true,
        private_tunnel: TunnelState::Down,
        ..SdwanOpts::default()
    });
    let a = run(&twin, &dns());
    let b = a.branches();
    assert_eq!(b.len(), 1);
    assert_eq!(code(b[0].verdict), Some(ReasonCode::NoNeighbour));
    assert_eq!(b[0].steps.last().unwrap().function.as_str(), SELECT);
    // A packet that the rule does not match goes on the other tunnel.
    let web = run(&twin, &web());
    assert_eq!(web.branches().len(), 1);
    assert_eq!(web.verdict(), Some(&deliver("host9")));
}

#[test]
fn the_firewall_of_the_branch_drops_before_the_overlay() {
    let twin = twin(SdwanOpts {
        firewall: true,
        ..SdwanOpts::default()
    });
    let a = run(&twin, &tcp("10.1.0.10", 40000, "10.9.0.10", 23));
    let b = a.branches();
    assert_eq!(b.len(), 1);
    assert_eq!(code(b[0].verdict), Some(ReasonCode::Denied));
    assert_eq!(
        b[0].steps.last().unwrap().function.as_str(),
        "branch1/firewall"
    );
    // A packet that the firewall permits has both candidates.
    let web = run(&twin, &web());
    assert_eq!(web.branches().len(), 2);
    assert_eq!(web.verdict(), Some(&deliver("host9")));
}

#[test]
fn the_business_policy_sends_internet_packets_direct() {
    let twin = twin(SdwanOpts::default());
    let a = run(&twin, &tcp("10.1.0.10", 40000, "192.0.2.80", 443));
    let b = a.branches();
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].verdict, &exit("internet", "eth0"));
    let f = functions(&a, 0);
    let at = |name: &str| {
        f.iter()
            .position(|x| x == name)
            .unwrap_or_else(|| panic!("{name} is not in {f:?}"))
    };
    assert!(at("branch1/policy/segment0") < at("branch1/direct"));
    assert!(at("branch1/direct") < at("internet/route"));
    assert!(!f.contains(&SELECT.to_string()), "{f:?}");
    let w = b[0].packets.witness().unwrap().current;
    assert!(w.encap.is_empty() && w.inner.is_none());
}

#[test]
fn the_business_policy_backhauls_dns_packets_to_the_hub() {
    let twin = twin(SdwanOpts::default());
    let a = run(&twin, &udp("10.1.0.10", 40000, "192.0.2.53", 53));
    let b = a.branches();
    assert_eq!(b.len(), 2);
    for (i, transport) in ["internet", "mpls"].iter().enumerate() {
        assert_eq!(b[i].verdict, &exit("hub1", "eth8"));
        let f = functions(&a, i);
        let at = |name: &str| {
            f.iter()
                .position(|x| x == name)
                .unwrap_or_else(|| panic!("{name} is not in {f:?}"))
        };
        assert!(at("branch1/policy/segment0") < at(SELECT));
        assert!(at(SELECT) < at(&format!("{transport}/route")));
        assert!(at("hub1/vcmp/decap") < at("hub1/out/eth8"));
    }
    assert_eq!(a.verdict(), Some(&exit("hub1", "eth8")));
}
