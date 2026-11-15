//! Set mode: a reply through a source NAT that selects a port, the node
//! budget, the flood rule with a flood function that exists only in the
//! tests, and the 2 rules that join concrete mode and set mode.

use proptest::prelude::*;
use rsim_core::{
    Branch, Context, ContextAttr, Dependency, Destination, EndpointId, FieldValue, FloodCopy,
    FlowState, FunctionId, FunctionKind, Header, HeaderField, Match, NetFunction, Outcome,
    PROTO_TCP, PROTO_UDP, PacketPair, PacketSet, PortCond, PortId, Reason, ReasonCode,
    RulePredicate, SourceSpan, Verdict,
};
use rsim_engine::{Answer, ExecOptions, Executor, Query, Summary, Twin, TwinBuilder};
use rsim_functions::{Ingress, Meta};
use rsim_topologies::*;

fn deliver(e: &str) -> Verdict {
    Verdict::Deliver(Destination::Endpoint(EndpointId::new(e)))
}

#[test]
fn a_reply_through_a_source_nat_that_selects_a_port_matches_its_session() {
    let twin = mini_enterprise(MiniOpts {
        snat_selects_port: true,
        ..MiniOpts::default()
    })
    .build()
    .unwrap();
    let a = Executor::new(&twin)
        .run(&Query::path(
            &twin,
            &udp("172.31.10.20", 40000, "10.20.0.53", 53),
        ))
        .unwrap();
    // The inline IPS after the firewall reads the source port, which the
    // source NAT made unknown, so its result is not known.
    let Some(Verdict::Unknown(r)) = a.verdict() else {
        panic!("{:?}", a.summary)
    };
    assert!(r.detail.contains("source port unknown"), "{r:?}");
    let b = &a.branches()[0];
    let snat = b
        .steps
        .iter()
        .find(|s| s.function.as_str() == "fra01-fgt-01/snat")
        .unwrap();
    assert_eq!(
        snat.output.witness().unwrap().current.src_port,
        FieldValue::Unknown
    );
    // The reply of the translated packets at the session lookup of the
    // firewall, with the flow state of the branch, matches the session.
    let reply = b.packets.reply();
    let lookup = twin.function(&fid("fra01-fgt-01/session-lookup")).unwrap();
    let ctx = Context {
        device: rsim_core::Attr::Known("fra01-fgt-01".into()),
        ..Context::default()
    };
    let out = lookup.apply(&reply, &ctx, b.state);
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(out[0].reason.code, ReasonCode::SessionMatched);
    let back = out[0].packets.witness().unwrap().current;
    assert_eq!(back.dst_port, FieldValue::Known(40000));
    assert_eq!(back.dst_ip, FieldValue::Known(ip("172.31.10.20")));
}

/// The summary parts with a witness of each part.
fn view(a: &Answer) -> Vec<String> {
    let mut v: Vec<String> = a
        .summary
        .iter()
        .map(|p| {
            format!(
                "{:?} {:?}",
                p.summary,
                p.packets.witness().map(|w| w.original)
            )
        })
        .collect();
    v.sort();
    v
}

#[test]
fn a_run_over_the_node_budget_splits_its_input() {
    let twin = ecmp().build().unwrap();
    let untagged = |mut h: Header| {
        h.vlan = FieldValue::Absent;
        h.l2_priority = FieldValue::Absent;
        h
    };
    let run = |budget, hs: &[Header]| {
        let arena = twin.arena(None);
        let mut s = PacketSet::single(&arena, &hs[0]);
        for h in &hs[1..] {
            s = s.union(&PacketSet::single(&arena, h));
        }
        let opts = ExecOptions {
            node_budget: budget,
            max_runs: 8,
            ..ExecOptions::default()
        };
        Executor::with_options(&twin, opts)
            .run(&Query::set(s).without_reply())
            .unwrap()
    };
    let one = [untagged(tcp("10.1.0.10", 40000, "10.4.0.10", 80))];
    let two = [
        untagged(tcp("10.1.0.10", 40000, "10.4.0.10", 80)),
        untagged(tcp("10.1.0.10", 40001, "10.4.0.10", 22)),
    ];
    // A budget that the input arena does not have gives each run its own
    // arena, so the node counts are those of the runs.
    let n1 = run(Some(usize::MAX), &one).runs[0]
        .input
        .arena()
        .local_nodes();
    let full = run(Some(usize::MAX), &two);
    let n2 = full.runs[0].input.arena().local_nodes();
    assert!(n1 < n2, "{n1} {n2}");
    // A budget below the need of the 2 packets and above the need of one.
    let split = run(Some(n2 - 1), &two);
    assert!(split.runs.len() >= 2, "{}", split.runs.len());
    assert_eq!(view(&split), view(&full));
    assert_eq!(split.summary.len(), full.summary.len());
    // A part over the budget at the run limit does not split again. The
    // request has unstated fields, so it has many original requests.
    let tiny = run(Some(50), &one);
    assert!(tiny.runs.len() <= 8);
    for p in &tiny.summary {
        let Summary::Same(Verdict::Unknown(r)) = &p.summary else {
            panic!("{:?}", p.summary)
        };
        assert_eq!(r.code, ReasonCode::SetBudget);
    }
    // One original request that is over the budget cannot split.
    let mut h = one[0].clone();
    h.src_mac = FieldValue::Known(rsim_core::Mac([0; 6]));
    h.dst_mac = FieldValue::Known(rsim_core::Mac([0; 6]));
    h = h.with_dscp(0).with_ecn(0).with_tcp_flags(0x02);
    let single = run(Some(50), &[h]);
    assert_eq!(single.runs.len(), 1);
    let Some(Verdict::Unknown(r)) = single.verdict() else {
        panic!("{:?}", single.summary)
    };
    assert_eq!(r.code, ReasonCode::SetBudget);
    assert!(r.detail.contains("one original request"), "{r:?}");
}

/// A flood to 2 ports. Copy 0 delivers the DNS packets and drops the
/// others. Copy 1 drops all packets.
#[derive(Debug)]
struct TestFlood {
    meta: Meta,
}

impl NetFunction for TestFlood {
    fn id(&self) -> &FunctionId {
        &self.meta.id
    }
    fn kind(&self) -> FunctionKind {
        FunctionKind::Flood
    }
    fn device(&self) -> Option<&rsim_core::DeviceId> {
        Some(&self.meta.device)
    }
    fn requires(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn provides(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn reads(&self) -> Vec<Dependency> {
        Vec::new()
    }
    fn qos_reads(&self) -> Vec<HeaderField> {
        Vec::new()
    }
    fn qos_writes(&self) -> Vec<HeaderField> {
        Vec::new()
    }
    fn provenance(&self) -> &[SourceSpan] {
        &self.meta.provenance
    }
    fn successors(&self) -> Vec<FunctionId> {
        Vec::new()
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let dns = RulePredicate::exact(Match {
            dst_port: PortCond::one(53),
            ..Match::any()
        });
        let split = input.split(&dns);
        let copy = |index: u32| FloodCopy {
            flood: self.meta.id.clone(),
            port: PortId::new(format!("p{index}")),
            index,
            count: 2,
        };
        let mut out = Vec::new();
        let mut push = |set: PacketSet, outcome: Outcome, index: u32| {
            if set.is_empty() {
                return;
            }
            let mut b = self.meta.branch(
                set,
                outcome,
                Reason::new(ReasonCode::Passed, "flood copy"),
                ctx.clone(),
                state,
            );
            b.flood_copy = Some(copy(index));
            out.push(b);
        };
        let other = split.unmatched.union(&split.uncertain);
        push(
            split.matched.clone(),
            Outcome::Deliver(Destination::Endpoint(EndpointId::new("server"))),
            0,
        );
        push(other, Outcome::Drop, 0);
        push(input.clone(), Outcome::Drop, 1);
        out
    }
}

fn flood_twin() -> Twin {
    let p = nxos();
    let mut b = TwinBuilder::new();
    b.add(Ingress {
        meta: Meta::new("sw/in/p9", "sw", &p),
        interface: "p9".into(),
        next: fid("sw/flood"),
    });
    b.add(TestFlood {
        meta: Meta::new("sw/flood", "sw", &p),
    });
    b.build().unwrap()
}

#[test]
fn a_flood_keeps_the_partition_in_each_copy_and_delivers_if_a_copy_delivers() {
    let twin = flood_twin();
    let arena = twin.arena(None);
    let dns = udp("10.0.0.1", 40000, "10.0.0.2", 53);
    let web = udp("10.0.0.1", 40000, "10.0.0.2", 80);
    let s = PacketSet::single(&arena, &dns).union(&PacketSet::single(&arena, &web));
    // The executor checks the partition rule in each copy.
    let a = Executor::new(&twin)
        .run(&Query::set(s).with_ingress("sw", "p9").without_reply())
        .unwrap();
    assert_eq!(a.summary.len(), 2, "{:?}", a.summary);
    for p in &a.summary {
        let pair = |h: &Header| PacketPair {
            original: h.clone(),
            current: h.clone(),
        };
        let w = p.packets.witness().unwrap();
        let want = if w.original.dst_port == FieldValue::Known(53) {
            assert!(p.packets.contains(&pair(&w.original)));
            Summary::Same(deliver("server"))
        } else {
            Summary::Same(Verdict::Drop(Reason::new(ReasonCode::Passed, "flood copy")))
        };
        assert_eq!(p.summary, want);
    }
}

// ------------------------------------------------------------ the 2 rules

const ADDRS: [&str; 6] = [
    "172.31.10.20",
    "10.20.0.53",
    "198.51.100.7",
    "203.0.113.10",
    "10.1.0.10",
    "10.4.0.10",
];

prop_compose! {
    fn header()(
        src in 0..ADDRS.len(),
        dst in 0..ADDRS.len(),
        proto in prop_oneof![Just(PROTO_TCP), Just(PROTO_UDP)],
        sport in prop::option::of(prop_oneof![Just(53u16), Just(123), Just(40000)]),
        dport in prop::option::of(prop_oneof![Just(22u16), Just(53), Just(80), Just(443)]),
        dscp in prop::option::of(prop_oneof![Just(0u8), Just(46)]),
    ) -> Header {
        let mut h = Header::request(ip(ADDRS[src]), ip(ADDRS[dst]), proto);
        if let Some(p) = sport {
            h = h.with_src_port(p);
        }
        if let Some(p) = dport {
            h = h.with_dst_port(p);
        }
        if let Some(d) = dscp {
            h = h.with_dscp(d);
        }
        h
    }
}

fn twins() -> Vec<Twin> {
    vec![
        mini_enterprise(MiniOpts::default()).build().unwrap(),
        edge_dnat(EdgeOpts::default()).build().unwrap(),
        ecmp().build().unwrap(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Rule 1: for a packet with all fields stated, the path query and the
    /// set query give the same result. Rule 2: a path query with unstated
    /// fields that gives `Deliver` or `Drop` gives it for each member.
    #[test]
    fn concrete_mode_and_set_mode_agree(t in 0..3usize, h in header()) {
        let twins = twins();
        let twin = &twins[t];
        let ex = Executor::new(twin);
        let path = ex.run(&Query::path(twin, &h).without_reply()).unwrap();
        let set = ex.run(&Query::set(Query::path(twin, &h).packets).without_reply()).unwrap();
        let path_summary = path.single_summary().unwrap().clone();
        if let Summary::Same(v @ (Verdict::Deliver(_) | Verdict::Drop(_))) = &path_summary {
            for p in &set.summary {
                prop_assert_eq!(&p.summary, &Summary::Same(v.clone()));
            }
        }
        for p in &set.summary {
            let w = p.packets.witness().unwrap();
            let one = ex.run(&Query::path(twin, &w.original).without_reply()).unwrap();
            prop_assert_eq!(one.single_summary(), Some(&p.summary), "{:?}", w.original);
        }
    }
}
