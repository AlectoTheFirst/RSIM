//! Property tests: the branches partition the input in each alternative of a
//! forwarding choice, the result is deterministic, and a function with no
//! QoS write leaves the marking and the class unchanged.

use proptest::prelude::*;
use rsim_core::{
    AddrCond, Context, EndpointId, FieldValue, FlowState, Header, Match, MatchClass, NetFunction,
    Outcome, PROTO_ICMP, PROTO_TCP, PROTO_UDP, PacketSet, PortCond, RulePredicate, SourceSpan,
    Uniform, ValueCond,
};
use rsim_engine::{Executor, Query, Twin, check_partition};
use rsim_functions::{AclMatch, Meta, Rule, RuleAction, RuleBody};
use rsim_topologies::*;

const ADDRS: [&str; 13] = [
    "172.31.10.20",
    "10.20.0.53",
    "10.20.0.254",
    "198.51.100.7",
    "203.0.113.10",
    "10.20.0.11",
    "8.8.8.8",
    "192.0.2.5",
    "172.31.10.99",
    // The ECMP, loop and hairpin topologies.
    "10.4.0.10",
    "10.9.0.10",
    "10.1.0.20",
    "10.1.0.10",
];

fn field<T: Copy + std::fmt::Debug>(
    v: impl Strategy<Value = T>,
) -> impl Strategy<Value = FieldValue<T>> {
    prop_oneof![
        4 => v.prop_map(FieldValue::Known),
        1 => Just(FieldValue::Unstated),
        1 => Just(FieldValue::Unknown),
    ]
}

prop_compose! {
    fn header()(
        src in 0..ADDRS.len(),
        dst in 0..ADDRS.len(),
        proto in prop_oneof![Just(PROTO_TCP), Just(PROTO_UDP), Just(PROTO_ICMP)],
        sport in field(prop_oneof![Just(22u16), Just(53), Just(123), Just(443), Just(40000)]),
        dport in field(prop_oneof![Just(22u16), Just(23), Just(53), Just(80), Just(443), Just(8443)]),
        dscp in field(0u8..64),
        later_fragment in prop::bool::weighted(0.1),
    ) -> Header {
        let mut h = Header::request(ip(ADDRS[src]), ip(ADDRS[dst]), proto);
        if h.src_port.is_present() {
            h.src_port = sport;
            h.dst_port = dport;
        }
        h.dscp = dscp;
        if later_fragment {
            h = h.as_later_fragment();
        }
        h
    }
}

fn twins() -> Vec<Twin> {
    vec![
        mini_enterprise(MiniOpts::default()).build().unwrap(),
        mini_enterprise(MiniOpts {
            unhandled_policy_rule: true,
            ..MiniOpts::default()
        })
        .build()
        .unwrap(),
        edge_dnat(EdgeOpts::default()).build().unwrap(),
        ecmp().build().unwrap(),
        hairpin().build().unwrap(),
    ]
}

const STARTS: [&str; 5] = ["guest-client", "fra01-dns", "client", "server", "client"];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Every function application satisfies the partition rule and the QoS
    /// rule (the executor checks both at each step), and the answer is the
    /// same on a second run.
    #[test]
    fn queries_keep_the_contract_and_are_deterministic(
        t in 0..5usize,
        start in 0..5usize,
        h in header(),
    ) {
        let twins = twins();
        let twin = &twins[t];
        let ep = EndpointId::new(STARTS[start]);
        prop_assume!(twin.endpoint(&ep).is_some());
        let q = Query::from_endpoint(twin, &ep, h.clone()).unwrap();
        let a = Executor::new(twin).run(&q);
        prop_assert!(a.is_ok(), "{:?}", a.err());
        let a = a.unwrap();
        prop_assert_eq!(&a, &Executor::new(twin).run(&q).unwrap());

        // No function of these twins writes QoS fields, so each step shows the
        // marking of the request.
        for b in a.branches() {
            for s in &b.steps {
                prop_assert_eq!(s.qos.dscp, Uniform::Value(h.dscp));
                prop_assert!(s.function_qos_unset());
            }
        }
    }
}

trait QosUnset {
    fn function_qos_unset(&self) -> bool;
}

impl QosUnset for rsim_core::TraceStep {
    fn function_qos_unset(&self) -> bool {
        self.qos.traffic_class == rsim_core::Attr::Unset && self.qos.queue == rsim_core::Attr::Unset
    }
}

// ------------------------------------------------------------ ordered rules

fn addr_cond() -> impl Strategy<Value = AddrCond> {
    prop_oneof![
        Just(AddrCond::Any),
        prop::sample::subsequence(
            vec![
                "10.20.0.0/24",
                "10.0.0.0/8",
                "172.31.0.0/16",
                "8.8.8.8/32",
                "203.0.113.10/32"
            ],
            1..3
        )
        .prop_map(|v| AddrCond::prefixes(&v)),
    ]
}

prop_compose! {
    fn a_match()(
        src in addr_cond(),
        dst in addr_cond(),
        proto in prop_oneof![Just(ValueCond::Any), Just(ValueCond::one(PROTO_TCP)), Just(ValueCond::one(PROTO_UDP))],
        sport in prop_oneof![Just(PortCond::Any), Just(PortCond::In(vec![(0, 1023)]))],
        dport in prop_oneof![Just(PortCond::Any), Just(PortCond::one(53)), Just(PortCond::In(vec![(20, 80)]))],
        dscp in prop_oneof![Just(ValueCond::Any), Just(ValueCond::one(46))],
    ) -> Match {
        Match { src_ip: src, dst_ip: dst, protocol: proto, src_port: sport, dst_port: dport, dscp, ..Match::any() }
    }
}

fn a_rule() -> impl Strategy<Value = Rule<RuleAction>> {
    let action = prop_oneof![Just(RuleAction::Permit), Just(RuleAction::Deny)];
    prop_oneof![
        6 => (a_match(), action.clone()).prop_map(|(m, a)| Rule::new("r", RulePredicate::exact(m), a)),
        // An object with members that are not known: the definite set is
        // narrower than the upper bound.
        2 => (a_match(), action).prop_map(|(m, a)| {
            Rule::new("bounded", RulePredicate::bounded(Match { dscp: ValueCond::one(1), ..m.clone() }, m), a)
        }),
        1 => Just(Rule::unhandled("unhandled", SourceSpan::line("x.conf", 1))),
    ]
}

/// The oracle: the actions of all possible first-match rules, from the
/// regions `F_i^+ = M_i^+ minus the union of M_k^- for k < i`. The packet
/// has a definite action if all possible first-match rules agree.
fn oracle(rules: &[Rule<RuleAction>], default: RuleAction, h: &Header) -> Option<RuleAction> {
    let mut possible: Vec<Option<RuleAction>> = Vec::new();
    for r in rules {
        match &r.body {
            // An unhandled rule: M- is empty, M+ is all packets, and its
            // action is not known.
            RuleBody::Unhandled => {
                possible.push(None);
            }
            RuleBody::Handled { predicate, action } => match predicate.classify(h) {
                MatchClass::NoMatch => {}
                MatchClass::Uncertain => possible.push(Some(*action)),
                MatchClass::Match => {
                    possible.push(Some(*action));
                    return agree(&possible);
                }
            },
        }
    }
    possible.push(Some(default));
    agree(&possible)
}

fn agree(v: &[Option<RuleAction>]) -> Option<RuleAction> {
    let first = v[0]?;
    v.iter().all(|a| *a == Some(first)).then_some(first)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// The ACL partitions its input, is deterministic, and agrees with the
    /// first-match regions of the ordered rules.
    #[test]
    fn ordered_rules_partition_and_agree_with_the_first_match_regions(
        rules in prop::collection::vec(a_rule(), 0..6),
        default in prop_oneof![Just(RuleAction::Permit), Just(RuleAction::Deny)],
        h in header(),
    ) {
        let acl = AclMatch {
            meta: Meta::new("dev/acl", "dev", &tippingpoint()),
            acl: "acl".into(),
            rules: rules.clone(),
            default,
            next: fid("dev/next"),
        };
        let input = PacketSet::single(h.clone());
        let out = acl.apply(&input, &Context::default(), &FlowState::new());
        prop_assert!(check_partition(&input, &out).is_ok(), "{:?}", check_partition(&input, &out));
        prop_assert_eq!(&out, &acl.apply(&input, &Context::default(), &FlowState::new()));
        prop_assert_eq!(out.len(), 1);
        let got = match &out[0].outcome {
            Outcome::Forward(_) => Some(RuleAction::Permit),
            Outcome::Drop => Some(RuleAction::Deny),
            Outcome::Unknown => None,
            Outcome::Deliver(_) => unreachable!(),
        };
        prop_assert_eq!(got, oracle(&rules, default, &h));
    }
}
