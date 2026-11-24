//! The circuits of an Equinix Fabric account between 2 switched sites: a
//! circuit with one tag at both ends, a circuit with a QinQ end, a tag of no
//! circuit, a service profile end, and the set query.

use rsim_core::{
    Context, DelayGap, Destination, EndpointId, FieldValue, FlowState, Header, Outcome, PROTO_TCP,
    PacketSet, ReasonCode, SetSpec, Verdict, VerdictKind,
};
use rsim_engine::{Answer, BranchView, Executor, Query, Summary, Twin, check_partition};
use rsim_topologies::*;

fn twin() -> Twin {
    equinix_fabric().build().expect("the twin builds")
}

fn run(t: &Twin, h: &Header) -> Answer {
    Executor::new(t)
        .run(&Query::path(t, h))
        .expect("the query runs")
}

fn deliver(e: &str) -> Verdict {
    Verdict::Deliver(Destination::Endpoint(EndpointId::new(e)))
}

fn functions(b: &BranchView<'_>) -> Vec<String> {
    b.steps.iter().map(|s| s.function.to_string()).collect()
}

/// The outer VLAN, its TPID, the inner VLAN and its TPID.
type TagFields = (
    FieldValue<u16>,
    FieldValue<u16>,
    FieldValue<u16>,
    FieldValue<u16>,
);

/// The tag fields after the step of the function `f`.
fn tags_after(b: &BranchView<'_>, f: &str) -> TagFields {
    let s = b
        .steps
        .iter()
        .find(|s| s.function.as_str() == f)
        .unwrap_or_else(|| panic!("{f} is not in {:?}", functions(b)));
    let w = s.output.witness().unwrap().current;
    (w.vlan, w.vlan_tpid, w.inner_vlan, w.inner_vlan_tpid)
}

fn one_tag(vlan: u16) -> TagFields {
    (
        FieldValue::Known(vlan),
        FieldValue::Known(0x8100),
        FieldValue::Absent,
        FieldValue::Absent,
    )
}

const QINQ: TagFields = (
    FieldValue::Known(300),
    FieldValue::Known(0x88a8),
    FieldValue::Known(200),
    FieldValue::Known(0x8100),
);

fn unknown_reason(b: &BranchView<'_>) -> (ReasonCode, String) {
    match b.verdict {
        Verdict::Unknown(r) => (r.code, r.detail.clone()),
        v => panic!("{v:?}"),
    }
}

#[test]
fn a_path_and_its_reply_cross_the_circuit_with_the_same_tag_at_both_ends() {
    let t = twin();
    let a = run(&t, &tcp("192.0.2.10", 40000, "192.0.2.20", 443));
    assert_eq!(a.verdict(), Some(&deliver("hb")));
    let b = &a.branches()[0];
    assert_eq!(
        functions(b),
        [
            "sw-a/host/port/2",
            "sw-a/port/2/in",
            "sw-a/mac",
            "sw-a/port/1/out",
            "equinix-acct/port/fp-a/in",
            "equinix-acct/port/fp-a/circuit",
            "sw-b/port/1/in",
            "sw-b/mac",
            "sw-b/port/3/out",
        ]
    );
    assert_eq!(tags_after(b, "sw-a/port/1/out"), one_tag(100));
    assert_eq!(
        tags_after(b, "equinix-acct/port/fp-a/circuit"),
        one_tag(100)
    );
    let circuit = &b.steps[5];
    assert_eq!(circuit.reason.code, ReasonCode::LinkHandOff);
    assert!(
        circuit.reason.detail.contains("circuit evpl-100"),
        "{:?}",
        circuit.reason
    );
    let link = DelayGap::Link(fid("equinix-acct/port/fp-a/circuit"));
    assert!(b.delay.missing().contains(&link));

    let reply = a.reply_of(0).expect("a reply");
    assert_eq!(reply.verdict(), Some(&deliver("ha")));
    let r = &reply.branches()[0];
    assert_eq!(tags_after(r, "sw-b/port/1/out"), one_tag(100));
    assert_eq!(
        tags_after(r, "equinix-acct/port/fp-b1/circuit"),
        one_tag(100)
    );
}

#[test]
fn a_path_and_its_reply_cross_the_circuit_with_a_qinq_end() {
    let t = twin();
    let a = run(&t, &tcp("198.51.100.10", 40000, "198.51.100.20", 443));
    assert_eq!(a.verdict(), Some(&deliver("hb2")));
    let b = &a.branches()[0];
    assert_eq!(
        functions(b),
        [
            "sw-a/host/port/3",
            "sw-a/port/3/in",
            "sw-a/mac",
            "sw-a/port/1/out",
            "equinix-acct/port/fp-a/in",
            "equinix-acct/port/fp-a/circuit",
            "sw-b/port/2/pop",
            "sw-b/port/2/in",
            "sw-b/mac",
            "sw-b/port/4/out",
        ]
    );
    assert_eq!(tags_after(b, "sw-a/port/1/out"), one_tag(200));
    assert_eq!(tags_after(b, "equinix-acct/port/fp-a/circuit"), QINQ);
    assert_eq!(tags_after(b, "sw-b/port/2/pop"), one_tag(200));

    let reply = a.reply_of(0).expect("a reply");
    assert_eq!(reply.verdict(), Some(&deliver("ha2")));
    let r = &reply.branches()[0];
    assert_eq!(tags_after(r, "sw-b/port/2/push"), QINQ);
    assert_eq!(
        tags_after(r, "equinix-acct/port/fp-b2/circuit"),
        one_tag(200)
    );
    assert_eq!(
        functions(r)[functions(r).len() - 3..],
        ["sw-a/port/1/in", "sw-a/mac", "sw-a/port/3/out"]
    );
}

#[test]
fn a_frame_with_a_tag_of_no_circuit_is_unknown_at_the_port_gate() {
    let t = twin();
    let a = run(&t, &tcp("198.51.100.70", 40000, "198.51.100.80", 443));
    let b = &a.branches()[0];
    assert_eq!(tags_after(b, "sw-a/port/1/out"), one_tag(150));
    assert_eq!(
        b.steps.last().unwrap().function.as_str(),
        "equinix-acct/port/fp-a/in"
    );
    let (code, detail) = unknown_reason(b);
    assert_eq!(code, ReasonCode::UnhandledStanza);
    assert!(detail.contains("no circuit for the frame tags"), "{detail}");
    assert!(a.replies.is_empty());
}

#[test]
fn a_frame_with_2_tags_on_an_end_with_one_tag_is_unknown_at_the_circuit() {
    let t = twin();
    let arena = t.arena(None);
    let spec = SetSpec {
        vlan: Some(vec![(100, 100)]),
        inner_vlan: Some(vec![(30, 30)]),
        ..SetSpec::default()
    };
    let input = PacketSet::from_spec(&arena, &spec);
    let f = t.function(&fid("equinix-acct/port/fp-a/circuit")).unwrap();
    let out = f.apply(&input, &Context::default(), &FlowState::default());
    check_partition(&input, &out).unwrap();
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(out[0].outcome, Outcome::Unknown);
    assert_eq!(
        out[0].reason.detail,
        "no circuit for the frame tags on port port/fp-a"
    );
}

#[test]
fn each_frame_of_a_port_goes_to_one_circuit_or_is_unknown() {
    let t = twin();
    let arena = t.arena(None);
    let input = PacketSet::from_spec(&arena, &SetSpec::default());
    let f = t.function(&fid("equinix-acct/port/fp-a/circuit")).unwrap();
    let out = f.apply(&input, &Context::default(), &FlowState::default());
    check_partition(&input, &out).unwrap();
    let targets: Vec<String> = out
        .iter()
        .map(|b| match &b.outcome {
            Outcome::Forward(next) => next.to_string(),
            o => format!("{o:?}"),
        })
        .collect();
    assert_eq!(
        targets,
        [
            "sw-b/port/1/in",
            "sw-b/port/2/pop",
            "equinix-acct/circuit/sp-cloud/sink",
            "Unknown",
        ]
    );
}

#[test]
fn a_frame_to_the_service_profile_end_is_unknown_with_its_reason() {
    let t = twin();
    let a = run(&t, &tcp("203.0.113.10", 40000, "203.0.113.1", 443));
    let b = &a.branches()[0];
    assert_eq!(
        functions(b)[functions(b).len() - 3..],
        [
            "equinix-acct/port/fp-a/in",
            "equinix-acct/port/fp-a/circuit",
            "equinix-acct/circuit/sp-cloud/sink",
        ]
    );
    let (code, detail) = unknown_reason(b);
    assert_eq!(code, ReasonCode::UnhandledStanza);
    assert!(
        detail.contains(
            "the far end is the service profile cloud-onramp-1 of the provider example-cloud"
        ),
        "{detail}"
    );
    assert!(!b.steps.last().unwrap().provenance.is_empty());
}

const QUERIES: [(&str, &str); 4] = [
    ("192.0.2.10", "192.0.2.20"),
    ("198.51.100.10", "198.51.100.20"),
    ("198.51.100.70", "198.51.100.80"),
    ("203.0.113.10", "203.0.113.1"),
];

#[test]
fn the_set_query_agrees_with_the_path_query() {
    let t = twin();
    let ex = Executor::new(&t);
    for (src, dst) in QUERIES {
        for h in [tcp(src, 40000, dst, 443), udp(src, 40000, dst, 53)] {
            let path = ex.run(&Query::path(&t, &h)).unwrap();
            let set = ex.run(&Query::set(Query::path(&t, &h).packets)).unwrap();
            let want = path.single_summary().unwrap();
            assert!(!set.summary.is_empty(), "{h:?}");
            for p in &set.summary {
                assert_eq!(&p.summary, want, "{h:?}");
            }
        }
    }
}

#[test]
fn a_set_query_over_all_ports_crosses_both_circuits() {
    let t = twin();
    let arena = t.arena(None);
    for (src, dst, host) in [
        ("192.0.2.10", "192.0.2.20", "hb"),
        ("198.51.100.10", "198.51.100.20", "hb2"),
    ] {
        let spec = SetSpec {
            src_ip: Some(vec![pfx(&format!("{src}/32"))]),
            dst_ip: Some(vec![pfx(&format!("{dst}/32"))]),
            protocol: Some(vec![(PROTO_TCP, PROTO_TCP)]),
            ..SetSpec::default()
        };
        let set = PacketSet::from_spec(&arena, &spec);
        let a = Executor::new(&t).run(&Query::set(set)).unwrap();
        for p in &a.summary {
            assert_eq!(p.summary, Summary::Same(deliver(host)), "{src}");
        }
        for b in a.branches() {
            assert_eq!(b.verdict.kind(), VerdictKind::Deliver, "{src}");
        }
    }
}
