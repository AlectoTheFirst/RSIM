//! The session lookup of one flow, with plain compares on the flows of the
//! relation, against the session lookup with set operations: random single
//! flows and random session relations with NAT bindings, unknown ports and
//! more than one binding.

use std::net::IpAddr;
use std::sync::Arc;

use proptest::prelude::*;
use rsim_core::{
    FieldValue, Header, Mac, PROTO_ICMP, PROTO_TCP, PROTO_UDP, PacketSet, Rewrite,
    SessionDirection, SetArena,
};

const ADDRS: [&str; 3] = ["10.0.0.1", "10.0.0.2", "192.0.2.9"];
const ADDRS6: [&str; 3] = ["2001:db8::1", "2001:db8::2", "2001:db8:1::7"];
const PORTS: [u16; 3] = [53, 1024, 40000];

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn addr(v6: bool, i: usize) -> IpAddr {
    if v6 { ip(ADDRS6[i]) } else { ip(ADDRS[i]) }
}

fn port() -> impl Strategy<Value = FieldValue<u16>> {
    prop_oneof![
        5 => prop::sample::select(PORTS.to_vec()).prop_map(FieldValue::Known),
        1 => Just(FieldValue::Unknown),
    ]
}

/// A header of the family `v6` that states each flow field. In about half
/// of the headers, the MAC addresses, the VLAN tag and the QoS fields are
/// unstated.
fn header(v6: bool) -> impl Strategy<Value = Header> {
    (
        0..ADDRS.len(),
        0..ADDRS.len(),
        prop_oneof![Just(PROTO_TCP), Just(PROTO_UDP), Just(PROTO_ICMP)],
        port(),
        port(),
        any::<bool>(),
    )
        .prop_map(move |(s, d, proto, sp, dp, free)| {
            let proto = if v6 && proto == PROTO_ICMP { 58 } else { proto };
            let mut h = Header::request(addr(v6, s), addr(v6, d), proto);
            if h.src_port.is_present() {
                h.src_port = sp;
                h.dst_port = dp;
            }
            if h.tcp_flags.is_present() {
                h.tcp_flags = FieldValue::Known(0x02);
            }
            if h.icmp_type.is_present() {
                h.icmp_type = FieldValue::Known(if v6 { 128 } else { 8 });
                h.icmp_code = FieldValue::Known(0);
            }
            if !free {
                h.dscp = FieldValue::Known(0);
                h.ecn = FieldValue::Known(0);
                h.src_mac = FieldValue::Known(Mac([0, 0, 0, 0, 0, 1]));
                h.dst_mac = FieldValue::Known(Mac([0, 0, 0, 0, 0, 2]));
                h.vlan = FieldValue::Absent;
                h.l2_priority = FieldValue::Absent;
            }
            h
        })
}

/// A NAT rewrite of the family `v6`, with an unknown port at times.
fn rewrite(v6: bool) -> impl Strategy<Value = Rewrite> {
    let a = move || {
        prop::option::of((0..ADDRS.len()).prop_map(move |i| FieldValue::Known(addr(v6, i))))
    };
    (a(), a(), prop::option::of(port()), prop::option::of(port())).prop_map(|(s, d, sp, dp)| {
        Rewrite {
            src_ip: s,
            dst_ip: d,
            src_port: sp,
            dst_port: dp,
            ..Rewrite::default()
        }
    })
}

/// A case: the headers at the lookup, one or two bindings, and the probes.
#[derive(Debug)]
struct Case {
    lookup: Vec<Header>,
    rewrites: Vec<Rewrite>,
    probes: Vec<Header>,
}

fn case() -> impl Strategy<Value = Case> {
    any::<bool>().prop_flat_map(|v6| {
        (
            prop::collection::vec(header(v6), 1..4),
            prop::collection::vec(rewrite(v6), 1..3),
            prop::collection::vec(header(v6), 0..3),
            prop::collection::vec((any::<bool>(), any::<prop::sample::Index>()), 0..4),
        )
            .prop_map(|(lookup, rewrites, random, picks)| {
                let mut probes = random;
                // Probes of the flows of the relation: a header at the
                // lookup, and the reply of a header at the commit.
                for (reply, i) in picks {
                    let h = i.get(&lookup).clone();
                    if reply {
                        let mut c = h.clone();
                        i.get(&rewrites).apply_to(&mut c);
                        probes.push(c.reply());
                    } else {
                        probes.push(h);
                    }
                }
                Case {
                    lookup,
                    rewrites,
                    probes,
                }
            })
    })
}

fn union(arena: &Arc<SetArena>, sets: impl IntoIterator<Item = PacketSet>) -> PacketSet {
    let mut acc: Option<PacketSet> = None;
    for s in sets {
        acc = Some(match acc {
            None => s,
            Some(a) => a.union(&s),
        });
    }
    acc.unwrap_or_else(|| {
        PacketSet::single(arena, &Header::request(ip("10.0.0.1"), ip("10.0.0.2"), 17)).empty()
    })
}

/// True if the header states its ports: a known value, an unknown value or
/// absent.
fn states_flow(h: &Header) -> bool {
    ![h.src_port, h.dst_port].iter().any(|p| p.is_unstated())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn the_lookup_of_one_flow_equals_the_lookup_with_set_operations(c in case()) {
        let ar = SetArena::standalone();
        let lookup = union(&ar, c.lookup.iter().map(|h| PacketSet::single(&ar, h)));
        let commit = union(&ar, c.rewrites.iter().map(|rw| lookup.rewrite(rw)));
        let rel = lookup.session_relation(&commit);
        for p in &c.probes {
            let s = PacketSet::single(&ar, p);
            for dir in [SessionDirection::Forward, SessionDirection::Reply] {
                let sets = s.session_lookup_sets(&rel, dir);
                let one = s.session_lookup_one_flow(&rel, dir);
                prop_assert!(states_flow(p));
                let one = one.expect("a probe of one flow and a small relation take the short path");
                prop_assert_eq!(&one, &sets, "{:?} {:?}", dir, p);
                prop_assert_eq!(&s.session_lookup(&rel, dir), &sets);
            }
        }
        // A probe with an unstated port has many flows: the set path.
        let mut wide = c.lookup[0].clone();
        if wide.src_port.is_present() {
            wide.src_port = FieldValue::Unstated;
            let s = PacketSet::single(&ar, &wide);
            for dir in [SessionDirection::Forward, SessionDirection::Reply] {
                prop_assert!(s.session_lookup_one_flow(&rel, dir).is_none());
                prop_assert_eq!(s.session_lookup(&rel, dir), s.session_lookup_sets(&rel, dir));
            }
        }
        // The empty relation and the empty probe.
        let none = rel.empty();
        let s = PacketSet::single(&ar, &c.lookup[0]);
        for dir in [SessionDirection::Forward, SessionDirection::Reply] {
            prop_assert_eq!(s.session_lookup_one_flow(&none, dir), Some(s.session_lookup_sets(&none, dir)));
            let e = s.empty();
            prop_assert_eq!(e.session_lookup_one_flow(&rel, dir), Some(e.session_lookup_sets(&rel, dir)));
        }
    }
}

#[test]
fn a_relation_with_an_unstated_port_takes_the_set_path() {
    let ar = SetArena::standalone();
    let h = Header::request(ip("10.0.0.1"), ip("192.0.2.9"), PROTO_UDP).with_dst_port(53);
    let lookup = PacketSet::single(&ar, &h);
    let rel = lookup.session_relation(&lookup);
    let probe = PacketSet::single(&ar, &h.clone().with_src_port(40000));
    for dir in [SessionDirection::Forward, SessionDirection::Reply] {
        assert!(probe.session_lookup_one_flow(&rel, dir).is_none());
        assert_eq!(
            probe.session_lookup(&rel, dir),
            probe.session_lookup_sets(&rel, dir)
        );
    }
}

#[test]
fn the_short_path_gives_each_kind_of_result() {
    let ar = SetArena::standalone();
    let h = Header::request(ip("10.0.0.1"), ip("192.0.2.9"), PROTO_UDP)
        .with_src_port(40000)
        .with_dst_port(53);
    let lookup = PacketSet::single(&ar, &h);
    let snat = Rewrite {
        src_ip: Some(FieldValue::Known(ip("10.0.0.2"))),
        src_port: Some(FieldValue::Unknown),
        ..Rewrite::default()
    };
    let dnat = Rewrite {
        dst_ip: Some(FieldValue::Known(ip("10.0.0.2"))),
        ..Rewrite::default()
    };
    let one = lookup.session_relation(&lookup.rewrite(&snat));
    let two = lookup.session_relation(&lookup.rewrite(&snat).union(&lookup.rewrite(&dnat)));
    let mut translated = h.clone();
    snat.apply_to(&mut translated);
    let known_reply = Header::request(ip("192.0.2.9"), ip("10.0.0.2"), PROTO_UDP)
        .with_src_port(53)
        .with_dst_port(5000);
    // The index of the part that is not empty: matched, uncertain,
    // ambiguous or unmatched.
    let cases: [(&PacketSet, Header, SessionDirection, usize); 5] = [
        (&one, h.clone(), SessionDirection::Forward, 0),
        (&one, translated.reply(), SessionDirection::Reply, 0),
        (&one, known_reply, SessionDirection::Reply, 1),
        (&two, h.clone(), SessionDirection::Forward, 2),
        (&one, h.reply(), SessionDirection::Reply, 3),
    ];
    for (rel, probe, dir, kind) in cases {
        let s = PacketSet::single(&ar, &probe);
        let fast = s.session_lookup_one_flow(rel, dir).expect("the short path");
        assert_eq!(fast, s.session_lookup_sets(rel, dir), "{probe:?}");
        let parts = [
            &fast.matched,
            &fast.uncertain,
            &fast.ambiguous,
            &fast.unmatched,
        ];
        for (i, p) in parts.iter().enumerate() {
            assert_eq!(!p.is_empty(), i == kind, "{probe:?} {i}");
        }
    }
}
