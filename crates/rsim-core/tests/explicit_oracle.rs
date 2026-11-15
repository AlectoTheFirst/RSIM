//! The packet set operations compared with an explicit list of packet pairs
//! on small random sets. Each header of the lists states all fields, so it
//! is one member of a set.

use std::net::IpAddr;
use std::sync::Arc;

use proptest::prelude::*;
use rsim_core::{
    AddrCond, AddrField, FieldValue, Header, Mac, Match, MatchClass, PROTO_ICMP, PROTO_TCP,
    PROTO_UDP, PacketPair, PacketSet, PortCond, Prefix, PrefixTable, Rewrite, RulePredicate,
    SessionDirection, SetArena, SetBase, TriePrefixTable, ValueCond,
};

const ADDRS: [&str; 4] = ["10.0.0.1", "10.0.0.2", "10.0.1.7", "192.0.2.9"];
const ADDRS6: [&str; 3] = ["2001:db8::1", "2001:db8::2", "2001:db8:1::7"];
const PORTS: [u16; 4] = [22, 53, 1024, 40000];

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn unknown_or<T: Copy + std::fmt::Debug + 'static>(
    v: impl Strategy<Value = T>,
) -> impl Strategy<Value = FieldValue<T>> {
    prop_oneof![5 => v.prop_map(FieldValue::Known), 1 => Just(FieldValue::Unknown)]
}

prop_compose! {
    /// A header that states each field.
    fn header()(
        v6 in prop::bool::weighted(0.3),
        src in 0..ADDRS.len(),
        dst in 0..ADDRS.len(),
        proto in prop_oneof![Just(PROTO_TCP), Just(PROTO_UDP), Just(PROTO_ICMP)],
        sport in unknown_or(prop::sample::select(PORTS.to_vec())),
        dport in unknown_or(prop::sample::select(PORTS.to_vec())),
        flags in prop_oneof![Just(0x02u8), Just(0x10), Just(0x12)],
        icmp in prop_oneof![Just(8u8), Just(0), Just(13)],
        dscp in unknown_or(prop_oneof![Just(0u8), Just(46)]),
        later in prop::bool::weighted(0.1),
        mac in 0u8..3,
    ) -> Header {
        let (s, d) = if v6 {
            (ADDRS6[src % ADDRS6.len()], ADDRS6[dst % ADDRS6.len()])
        } else {
            (ADDRS[src], ADDRS[dst])
        };
        let mut h = Header::request(ip(s), ip(d), proto);
        if h.src_port.is_present() {
            h.src_port = sport;
            h.dst_port = dport;
        }
        if h.tcp_flags.is_present() {
            h.tcp_flags = FieldValue::Known(flags);
        }
        if h.icmp_type.is_present() {
            h.icmp_type = FieldValue::Known(icmp);
            h.icmp_code = FieldValue::Known(0);
        }
        h.dscp = dscp;
        h.ecn = FieldValue::Known(0);
        h.src_mac = FieldValue::Known(Mac([0, 0, 0, 0, 0, mac]));
        h.dst_mac = FieldValue::Known(Mac([0, 0, 0, 0, 1, mac]));
        h.vlan = FieldValue::Absent;
        h.l2_priority = FieldValue::Absent;
        if later {
            h = h.as_later_fragment();
        }
        h
    }
}

fn headers() -> impl Strategy<Value = Vec<Header>> {
    prop::collection::vec(header(), 0..6)
}

/// True if each address that the rewrite sets has the family of each header.
/// A rewrite does not change the address family.
fn same_family(rw: &Rewrite, hs: &[Header]) -> bool {
    let fam = |v: &Option<FieldValue<IpAddr>>| match v {
        Some(FieldValue::Known(a)) => Some(a.is_ipv6()),
        _ => None,
    };
    [fam(&rw.src_ip), fam(&rw.dst_ip)]
        .into_iter()
        .flatten()
        .all(|v6| {
            hs.iter()
                .all(|h| h.src_ip.known().is_none_or(|a| a.is_ipv6() == v6))
        })
}

/// An explicit set: sorted pairs without repeats.
type Explicit = Vec<PacketPair>;

fn explicit(hs: &[Header]) -> Explicit {
    let mut v: Explicit = hs
        .iter()
        .map(|h| PacketPair {
            original: h.clone(),
            current: h.clone(),
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

/// The set of an explicit list.
fn set(arena: &Arc<SetArena>, e: &Explicit) -> PacketSet {
    let mut s = PacketSet::single(arena, &e.first().map_or_else(dummy, |p| p.current.clone()));
    s = s.empty();
    for p in e {
        s = s.union(&PacketSet::pair(arena, p));
    }
    s
}

fn dummy() -> Header {
    Header::request(ip("10.0.0.1"), ip("10.0.0.2"), PROTO_UDP)
}

fn arena() -> Arc<SetArena> {
    SetArena::standalone()
}

fn addr_cond() -> impl Strategy<Value = AddrCond> {
    prop_oneof![
        Just(AddrCond::Any),
        prop::sample::subsequence(
            vec!["10.0.0.0/24", "10.0.0.2/32", "192.0.2.0/24", "10.0.0.0/8"],
            1..3
        )
        .prop_map(|v| AddrCond::prefixes(&v)),
    ]
}

prop_compose! {
    fn a_match()(
        src in addr_cond(),
        dst in addr_cond(),
        proto in prop_oneof![Just(ValueCond::Any), Just(ValueCond::one(PROTO_TCP)), Just(ValueCond::one(PROTO_ICMP))],
        sport in prop_oneof![Just(PortCond::Any), Just(PortCond::In(vec![(0, 1023)]))],
        dport in prop_oneof![Just(PortCond::Any), Just(PortCond::one(53)), Just(PortCond::In(vec![(20, 1024)]))],
        dscp in prop_oneof![Just(ValueCond::Any), Just(ValueCond::one(46))],
        icmp in prop_oneof![Just(ValueCond::Any), Just(ValueCond::one(8))],
    ) -> Match {
        Match { src_ip: src, dst_ip: dst, protocol: proto, src_port: sport, dst_port: dport, dscp, icmp_type: icmp, ..Match::any() }
    }
}

fn predicate() -> impl Strategy<Value = RulePredicate> {
    prop_oneof![
        3 => a_match().prop_map(RulePredicate::exact),
        1 => a_match().prop_map(|m| RulePredicate::bounded(Match { dscp: ValueCond::one(0), ..m.clone() }, m)),
    ]
}

fn rewrite() -> impl Strategy<Value = Rewrite> {
    let addr = || {
        prop::option::of(unknown_or(
            prop::sample::select(ADDRS.to_vec()).prop_map(ip),
        ))
    };
    let port = || prop::option::of(unknown_or(prop::sample::select(PORTS.to_vec())));
    let dscp = prop::option::of(unknown_or(prop_oneof![Just(0u8), Just(10)]));
    (addr(), addr(), port(), port(), dscp).prop_map(|(s, d, sp, dp, q)| Rewrite {
        src_ip: s,
        dst_ip: d,
        src_port: sp,
        dst_port: dp,
        dscp: q,
        ..Rewrite::default()
    })
}

/// The flow of a header: the protocol, the addresses and the ports.
type Flow = (
    FieldValue<u8>,
    FieldValue<IpAddr>,
    FieldValue<IpAddr>,
    FieldValue<u16>,
    FieldValue<u16>,
);

fn flow(h: &Header) -> Flow {
    (h.protocol, h.src_ip, h.dst_ip, h.src_port, h.dst_port)
}

fn reverse(f: Flow) -> Flow {
    (f.0, f.2, f.1, f.4, f.3)
}

fn with_flow(h: &Header, f: Flow) -> Header {
    let mut h = h.clone();
    h.protocol = f.0;
    h.src_ip = f.1;
    h.dst_ip = f.2;
    h.src_port = f.3;
    h.dst_port = f.4;
    h
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn set_algebra_agrees_with_the_explicit_lists(a in headers(), b in headers()) {
        let ar = arena();
        let (ea, eb) = (explicit(&a), explicit(&b));
        let (sa, sb) = (set(&ar, &ea), set(&ar, &eb));
        let mut union = ea.clone();
        union.extend(eb.iter().cloned());
        union.sort();
        union.dedup();
        let inter: Explicit = ea.iter().filter(|p| eb.contains(p)).cloned().collect();
        let diff: Explicit = ea.iter().filter(|p| !eb.contains(p)).cloned().collect();
        prop_assert_eq!(sa.union(&sb), set(&ar, &union));
        prop_assert_eq!(sa.intersect(&sb), set(&ar, &inter));
        prop_assert_eq!(sa.difference(&sb), set(&ar, &diff));
        prop_assert_eq!(sa.is_empty(), ea.is_empty());
        for p in &ea {
            prop_assert!(sa.contains(p));
        }
        if let Some(w) = sa.witness() {
            prop_assert!(ea.contains(&w), "{:?}", w);
        }
        prop_assert_eq!(sa.project_original(), sa.clone());
    }

    #[test]
    fn a_split_agrees_with_the_concrete_classification(a in headers(), pred in predicate(), base in any::<bool>()) {
        let ar = if base {
            SetArena::new(&SetBase::build([&pred]).unwrap(), None)
        } else {
            arena()
        };
        let ea = explicit(&a);
        let s = set(&ar, &ea).split(&pred);
        let class = |c: MatchClass| -> Explicit {
            ea.iter().filter(|p| pred.classify(&p.current) == c).cloned().collect()
        };
        prop_assert_eq!(s.matched, set(&ar, &class(MatchClass::Match)));
        prop_assert_eq!(s.uncertain, set(&ar, &class(MatchClass::Uncertain)));
        prop_assert_eq!(s.unmatched, set(&ar, &class(MatchClass::NoMatch)));
    }

    #[test]
    fn a_prefix_partition_agrees_with_the_longest_match(
        a in headers(),
        ps in prop::sample::subsequence(
            vec!["10.0.0.0/8", "10.0.0.0/24", "10.0.0.2/32", "0.0.0.0/0", "2001:db8::/48", "::/0"],
            0..6
        ),
        dst in any::<bool>(),
    ) {
        let ar = arena();
        let mut t: TriePrefixTable<usize> = TriePrefixTable::new();
        for (i, p) in ps.iter().enumerate() {
            t.insert(p.parse::<Prefix>().unwrap(), i);
        }
        let ea = explicit(&a);
        let field = if dst { AddrField::Dst } else { AddrField::Src };
        let part = set(&ar, &ea).partition_by_prefix(field, &t);
        let addr = |h: &Header| if dst { h.dst_ip } else { h.src_ip };
        let mut want: Vec<(Prefix, Explicit)> = Vec::new();
        let mut unmatched = Vec::new();
        let mut uncertain = Vec::new();
        for p in &ea {
            match addr(&p.current) {
                FieldValue::Known(a) => match t.longest_match(a) {
                    Some((pfx, _)) => match want.iter_mut().find(|(q, _)| *q == pfx) {
                        Some((_, v)) => v.push(p.clone()),
                        None => want.push((pfx, vec![p.clone()])),
                    },
                    None => unmatched.push(p.clone()),
                },
                _ => uncertain.push(p.clone()),
            }
        }
        want.sort_by_key(|(p, _)| *p);
        let got: Vec<(Prefix, PacketSet)> = part.matched.iter().map(|(p, _, s)| (*p, s.clone())).collect();
        let want: Vec<(Prefix, PacketSet)> = want.iter().map(|(p, e)| (*p, set(&ar, e))).collect();
        prop_assert_eq!(got, want);
        prop_assert_eq!(part.unmatched, set(&ar, &unmatched));
        prop_assert_eq!(part.uncertain, set(&ar, &uncertain));
    }

    #[test]
    fn a_rewrite_agrees_with_the_rewrite_of_each_header(a in headers(), rw in rewrite()) {
        prop_assume!(same_family(&rw, &a));
        let ar = arena();
        let ea = explicit(&a);
        let mut want: Explicit = ea
            .iter()
            .map(|p| {
                let mut c = p.current.clone();
                rw.apply_to(&mut c);
                PacketPair { original: p.original.clone(), current: c }
            })
            .collect();
        want.sort();
        want.dedup();
        prop_assert_eq!(set(&ar, &ea).rewrite(&rw), set(&ar, &want));
    }

    #[test]
    fn a_reply_agrees_with_the_reply_header(a in headers(), rw in rewrite()) {
        prop_assume!(same_family(&rw, &a));
        let ar = arena();
        let ea = explicit(&a);
        let s = set(&ar, &ea).rewrite(&rw);
        // The reply header has unstated fields, and they have all values. A
        // header with 2 unknown addresses does not record the address
        // family, so the explicit model cannot state it.
        let mut want = s.empty();
        for p in &ea {
            let mut c = p.current.clone();
            rw.apply_to(&mut c);
            prop_assume!(c.src_ip != FieldValue::Unknown || c.dst_ip != FieldValue::Unknown);
            want = want.union(&PacketSet::single(&ar, &c.reply()));
        }
        prop_assert_eq!(s.reply(), want);
    }

    #[test]
    fn a_session_lookup_agrees_with_the_relation_of_the_flows(
        a in headers(),
        rw in rewrite(),
        later in headers(),
    ) {
        prop_assume!(same_family(&rw, &a));
        let ar = arena();
        let known = |h: &Header| [h.src_port, h.dst_port, h.src_ip.map(|_| 0), h.dst_ip.map(|_| 0)]
            .iter()
            .all(|v| !matches!(v, FieldValue::Unknown));
        let mut rw = rw;
        // The explicit model has exact matches only: no unknown value.
        for f in [&mut rw.src_port, &mut rw.dst_port] {
            if matches!(f, Some(FieldValue::Unknown)) {
                *f = None;
            }
        }
        for f in [&mut rw.src_ip, &mut rw.dst_ip] {
            if matches!(f, Some(FieldValue::Unknown)) {
                *f = None;
            }
        }
        let ea: Explicit = explicit(&a).into_iter().filter(|p| known(&p.current)).collect();
        let lookup = set(&ar, &ea);
        let commit = lookup.rewrite(&rw);
        let rel = lookup.session_relation(&commit);
        let pairs: Vec<(Flow, Flow)> = ea
            .iter()
            .map(|p| {
                let mut c = p.current.clone();
                rw.apply_to(&mut c);
                (flow(&p.current), flow(&c))
            })
            .collect();
        prop_assert_eq!(rel.changes_flow(), pairs.iter().any(|(l, c)| l != c));
        let probe: Explicit = explicit(&later).into_iter().filter(|p| known(&p.current)).collect();
        let s = set(&ar, &probe);
        for dir in [SessionDirection::Forward, SessionDirection::Reply] {
            let r = s.session_lookup(&rel, dir);
            let mut matched = Vec::new();
            let mut unmatched = Vec::new();
            let mut ambiguous = Vec::new();
            for p in &probe {
                let f = flow(&p.current);
                let mut images: Vec<Flow> = pairs
                    .iter()
                    .filter_map(|(l, c)| match dir {
                        SessionDirection::Forward => (*l == f).then_some(*c),
                        SessionDirection::Reply => (reverse(*c) == f).then_some(reverse(*l)),
                    })
                    .collect();
                images.sort();
                images.dedup();
                match images.as_slice() {
                    [] => unmatched.push(p.clone()),
                    [img] => matched.push(PacketPair {
                        original: p.original.clone(),
                        current: with_flow(&p.current, *img),
                    }),
                    _ => ambiguous.push(p.clone()),
                }
            }
            matched.sort();
            matched.dedup();
            prop_assert_eq!(&r.matched, &set(&ar, &matched), "{:?}", dir);
            prop_assert_eq!(&r.unmatched, &set(&ar, &unmatched), "{:?}", dir);
            prop_assert_eq!(&r.ambiguous, &set(&ar, &ambiguous), "{:?}", dir);
            prop_assert!(r.uncertain.is_empty());
        }
    }
}

#[test]
fn an_unknown_port_matches_its_own_session_and_is_uncertain_against_a_known_port() {
    let ar = arena();
    let h = Header::request(ip("10.0.0.1"), ip("192.0.2.9"), PROTO_UDP)
        .with_src_port(40000)
        .with_dst_port(53);
    let lookup = PacketSet::single(&ar, &h);
    // A source NAT that selects a port makes the port unknown.
    let commit = lookup.rewrite(&Rewrite {
        src_ip: Some(FieldValue::Known(ip("10.0.0.2"))),
        src_port: Some(FieldValue::Unknown),
        ..Rewrite::default()
    });
    let rel = lookup.session_relation(&commit);
    // The reply of the translated packets has the unknown port: it matches.
    let reply = commit.reply();
    let r = reply.session_lookup(&rel, SessionDirection::Reply);
    assert!(!r.matched.is_empty());
    assert!(r.uncertain.is_empty() && r.unmatched.is_empty());
    let back = r.matched.witness().unwrap().current;
    assert_eq!(back.dst_ip, FieldValue::Known(ip("10.0.0.1")));
    assert_eq!(back.dst_port, FieldValue::Known(40000));
    // A reply to a known port can be equal to the selected port.
    let known = Header::request(ip("192.0.2.9"), ip("10.0.0.2"), PROTO_UDP)
        .with_src_port(53)
        .with_dst_port(5000);
    let r = PacketSet::single(&ar, &known).session_lookup(&rel, SessionDirection::Reply);
    assert!(r.matched.is_empty());
    assert!(!r.uncertain.is_empty());
    // A reply from another address does not match.
    let other = Header::request(ip("192.0.2.1"), ip("10.0.0.2"), PROTO_UDP)
        .with_src_port(53)
        .with_dst_port(5000);
    let r = PacketSet::single(&ar, &other).session_lookup(&rel, SessionDirection::Reply);
    assert!(r.matched.is_empty() && r.uncertain.is_empty());
}

#[test]
fn sets_of_two_queries_give_a_fault_and_then_empty_sets() {
    let (a, b) = (arena(), arena());
    let x = PacketSet::single(&a, &dummy());
    let y = PacketSet::single(&b, &dummy());
    assert!(x.union(&y).is_empty());
    assert!(a.fault().is_some());
    assert!(PacketSet::single(&a, &dummy()).is_empty());
    assert!(b.fault().is_none());
}

#[test]
fn a_copy_to_another_arena_has_the_same_members() {
    let (a, b) = (arena(), arena());
    let x =
        PacketSet::single(&a, &dummy()).union(&PacketSet::single(&a, &dummy().with_dst_port(53)));
    let y = x.copy_to(&b);
    assert_eq!(y.describe(), x.describe());
    assert_eq!(
        y,
        PacketSet::single(&b, &dummy()).union(&PacketSet::single(&b, &dummy().with_dst_port(53)))
    );
}

#[test]
fn a_set_over_the_budget_gives_the_fault_node_budget() {
    let base = SetBase::build([]).unwrap();
    let a = SetArena::new(&base, Some(100));
    let s = PacketSet::single(&a, &dummy());
    assert!(s.is_empty());
    assert!(matches!(
        a.fault(),
        Some(rsim_core::DdError::NodeBudget { budget: 100 })
    ));
}

// ------------------------------------------------------------ description

use rsim_core::{HeaderField, Member, Values};

fn field_value(h: &Header, f: HeaderField) -> FieldValue<u128> {
    let ip = |v: FieldValue<IpAddr>| v.map(rsim_core::bits::ip_bits);
    let n = |v: FieldValue<u16>| v.map(u128::from);
    let b = |v: FieldValue<u8>| v.map(u128::from);
    match f {
        HeaderField::SrcMac => h.src_mac.map(rsim_core::bits::mac_bits),
        HeaderField::DstMac => h.dst_mac.map(rsim_core::bits::mac_bits),
        HeaderField::Vlan => n(h.vlan),
        HeaderField::L2Priority => b(h.l2_priority),
        HeaderField::SrcIp => ip(h.src_ip),
        HeaderField::DstIp => ip(h.dst_ip),
        HeaderField::Protocol => b(h.protocol),
        HeaderField::Dscp => b(h.dscp),
        HeaderField::Ecn => b(h.ecn),
        HeaderField::Fragment => h.fragment.map(rsim_core::bits::fragment_code),
        HeaderField::SrcPort => n(h.src_port),
        HeaderField::DstPort => n(h.dst_port),
        HeaderField::TcpFlags => b(h.tcp_flags),
        HeaderField::IcmpType => b(h.icmp_type),
        HeaderField::IcmpCode => b(h.icmp_code),
        HeaderField::MplsTrafficClass => b(h.mpls_tc),
    }
}

fn holds(v: &Values, x: FieldValue<u128>, addr: Option<IpAddr>, orig: FieldValue<u128>) -> bool {
    match (v, x) {
        (Values::Absent, FieldValue::Absent) => true,
        (Values::Unknown, FieldValue::Unknown) => true,
        (Values::Original, x) => x == orig,
        (Values::Ranges(rs), FieldValue::Known(x)) => rs.iter().any(|&(lo, hi)| lo <= x && x <= hi),
        (Values::Prefixes(ps), FieldValue::Known(_)) => {
            addr.is_some_and(|a| ps.iter().any(|p| p.contains(a)))
        }
        _ => false,
    }
}

/// True if the member holds the pair: each field of each header.
fn member_contains(m: &Member, p: &PacketPair) -> bool {
    use rsim_core::HEADER_FIELDS;
    let addr = |h: &Header, f: HeaderField| match f {
        HeaderField::SrcIp => h.src_ip.known(),
        HeaderField::DstIp => h.dst_ip.known(),
        _ => None,
    };
    HEADER_FIELDS.iter().all(|&f| {
        let o = field_value(&p.original, f);
        holds(m.original.get(f), o, addr(&p.original, f), o)
            && holds(
                m.current.get(f),
                field_value(&p.current, f),
                addr(&p.current, f),
                o,
            )
    }) && m.original.encap.is_none()
        && m.current.encap.is_none()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Each pair of the set is in exactly 1 member of its description, and
    /// the description has no member outside the set.
    #[test]
    fn the_members_of_a_description_are_disjoint_and_cover_the_set(a in headers(), rw in rewrite()) {
        prop_assume!(same_family(&rw, &a));
        let ar = arena();
        let mut want: Explicit = explicit(&a)
            .into_iter()
            .map(|p| {
                let mut c = p.current.clone();
                rw.apply_to(&mut c);
                PacketPair { original: p.original, current: c }
            })
            .collect();
        want.sort();
        want.dedup();
        let s = set(&ar, &want);
        let members = s.describe();
        for p in &want {
            let n = members.iter().filter(|m| member_contains(m, p)).count();
            prop_assert_eq!(n, 1, "{:?} in {:?}", p, members);
        }
        // The set of the explicit pairs has as many pairs as the members
        // hold: each member of these sets holds exactly the pairs in it.
        for m in &members {
            prop_assert!(want.iter().any(|p| member_contains(m, p)), "{:?}", m);
        }
    }
}
