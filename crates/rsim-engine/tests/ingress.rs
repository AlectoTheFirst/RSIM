//! The ingress of a query: an explicit ingress, attachment records, a
//! connected network of an edge interface, no candidate or 2 candidates,
//! and the start of the reply.

use rsim_core::{Header, PacketSet, ReasonCode, SourceSpan, Verdict};
use rsim_engine::{
    Answer, AttachmentKind, AttachmentRecord, Executor, Ingress, IngressBasis, Query, Twin,
};
use rsim_topologies::*;

fn twin() -> Twin {
    let mut b = ecmp();
    let rec = |addr: &str, dev: &str, iface: &str, kind| AttachmentRecord {
        address: ip(addr),
        device: dev.into(),
        interface: iface.into(),
        kind,
        host: format!("host-{addr}"),
        provenance: vec![SourceSpan::line(format!("{dev}.arp"), 1)],
    };
    // A neighbour entry that names a host.
    b.attachment(rec("10.1.0.77", "r1", "eth0", AttachmentKind::Neighbour));
    // One address with 2 records on 2 interfaces.
    b.attachment(rec("10.1.0.55", "r1", "eth0", AttachmentKind::Client));
    b.attachment(rec("10.1.0.55", "r4", "eth0", AttachmentKind::Neighbour));
    b.build().unwrap()
}

fn web(src: &str) -> Header {
    tcp(src, 40000, "10.4.0.10", 80)
}

fn run(twin: &Twin, q: &Query) -> Answer {
    Executor::new(twin).run(q).unwrap()
}

fn only_ingress(a: &Answer) -> &Ingress {
    assert_eq!(a.runs.len(), 1, "{:?}", a.runs);
    &a.runs[0].ingress
}

fn interface(i: &Ingress) -> String {
    match i {
        Ingress::Found {
            device, interface, ..
        } => format!("{device}/{interface}"),
        Ingress::NotFound(r) => panic!("no ingress: {r:?}"),
    }
}

#[test]
fn an_explicit_ingress_is_always_accepted() {
    let t = twin();
    // A source with no record and no edge network, as from the internet.
    let q = Query::path(&t, &web("8.8.8.8")).with_ingress("r1", "eth0");
    let a = run(&t, &q);
    let i = only_ingress(&a);
    assert_eq!(interface(i), "r1/eth0");
    assert!(matches!(
        i,
        Ingress::Found {
            basis: IngressBasis::Explicit,
            ..
        }
    ));
    assert!(!a.branches()[0].steps.is_empty());
}

#[test]
fn an_attachment_record_gives_the_ingress() {
    let t = twin();
    for (src, kind) in [("10.1.0.10", "client"), ("10.1.0.77", "neighbour")] {
        let a = run(&t, &Query::path(&t, &web(src)));
        let i = only_ingress(&a);
        assert_eq!(interface(i), "r1/eth0", "{kind}");
        assert!(
            matches!(
                i,
                Ingress::Found {
                    basis: IngressBasis::Attachment(_),
                    ..
                }
            ),
            "{kind}"
        );
        assert!(i.host_confirmed());
    }
}

#[test]
fn a_connected_network_alone_is_an_ingress_only_on_an_edge_interface() {
    let t = twin();
    let a = run(&t, &Query::path(&t, &web("10.1.0.99")));
    let i = only_ingress(&a);
    assert_eq!(interface(i), "r1/eth0");
    assert!(matches!(
        i,
        Ingress::Found {
            basis: IngressBasis::ConnectedNetwork { .. },
            ..
        }
    ));
    assert!(!i.host_confirmed());
    // The link network between r1 and r2 is not on an edge interface.
    let a = run(&t, &Query::path(&t, &web("10.12.0.1")));
    assert!(matches!(only_ingress(&a), Ingress::NotFound(_)));
}

#[test]
fn no_candidate_or_two_candidates_give_unknown_with_the_candidates() {
    let t = twin();
    let a = run(&t, &Query::path(&t, &web("8.8.8.8")));
    let Some(Verdict::Unknown(r)) = a.verdict() else {
        panic!("{:?}", a.summary)
    };
    assert_eq!(r.code, ReasonCode::UnknownAttribute);
    assert!(r.detail.contains("no ingress"), "{r:?}");

    let a = run(&t, &Query::path(&t, &web("10.1.0.55")));
    let Some(Verdict::Unknown(r)) = a.verdict() else {
        panic!("{:?}", a.summary)
    };
    assert_eq!(r.code, ReasonCode::AmbiguousOwner);
    assert!(r.detail.contains("r1/eth0, r4/eth0"), "{r:?}");
}

#[test]
fn in_set_mode_each_part_has_its_own_ingress() {
    let t = twin();
    let arena = t.arena(None);
    let s = PacketSet::single(&arena, &web("10.1.0.10"))
        .union(&PacketSet::single(&arena, &web("8.8.8.8")));
    let a = run(&t, &Query::set(s));
    let found = a
        .runs
        .iter()
        .filter(|r| matches!(r.ingress, Ingress::Found { .. }))
        .count();
    assert_eq!((a.runs.len(), found), (2, 1));
    assert_eq!(a.summary.len(), 2, "{:?}", a.summary);
}

#[test]
fn the_reply_starts_at_the_interface_that_delivered_the_packets() {
    let t = twin();
    let a = run(&t, &Query::path(&t, &web("10.1.0.10")));
    let r = a.reply_of(0).expect("a reply ran");
    let i = only_ingress(r);
    assert_eq!(interface(i), "r4/eth9");
    assert!(matches!(
        i,
        Ingress::Found {
            basis: IngressBasis::Reply,
            ..
        }
    ));
}
