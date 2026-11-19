//! The input of a set query: a constraint for each field. A field with no
//! constraint has all values. A constraint on a field holds only packets
//! where the header of the field is present.

use std::sync::Arc;

use rsim_dd::{DdError, Edge};

use crate::addr::{Mac, Prefix};
use crate::bits::{self, Bank, FieldBits};
use crate::header::{Fragment, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use crate::packet_set::PacketSet;
use crate::set::{Builder, Ops, SetArena};

/// The constraints of a set query. `None` is a field with no constraint.
/// The ranges are inclusive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetSpec {
    pub src_ip: Option<Vec<Prefix>>,
    pub dst_ip: Option<Vec<Prefix>>,
    pub protocol: Option<Vec<(u8, u8)>>,
    pub src_port: Option<Vec<(u16, u16)>>,
    pub dst_port: Option<Vec<(u16, u16)>>,
    pub src_mac: Option<Vec<Mac>>,
    pub dst_mac: Option<Vec<Mac>>,
    pub vlan: Option<Vec<(u16, u16)>>,
    pub l2_priority: Option<Vec<(u8, u8)>>,
    pub tcp_flags: Option<Vec<(u8, u8)>>,
    pub icmp_type: Option<Vec<(u8, u8)>>,
    pub icmp_code: Option<Vec<(u8, u8)>>,
    pub dscp: Option<Vec<(u8, u8)>>,
    pub ecn: Option<Vec<(u8, u8)>>,
    pub fragment: Option<Vec<Fragment>>,
}

/// One class of protocols with the same transport headers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Tcp,
    Udp,
    Icmp,
    Other,
}

impl Class {
    /// The protocol values of the class, as ranges.
    fn ranges(self) -> Vec<(u8, u8)> {
        match self {
            Class::Tcp => vec![(PROTO_TCP, PROTO_TCP)],
            Class::Udp => vec![(PROTO_UDP, PROTO_UDP)],
            Class::Icmp => vec![(PROTO_ICMP, PROTO_ICMP), (PROTO_ICMPV6, PROTO_ICMPV6)],
            Class::Other => {
                let mut v = Vec::new();
                let mut lo = 0u16;
                for p in [PROTO_ICMP, PROTO_TCP, PROTO_UDP, PROTO_ICMPV6] {
                    if u16::from(p) > lo {
                        v.push((lo as u8, p - 1));
                    }
                    lo = u16::from(p) + 1;
                }
                v.push((lo as u8, 255));
                v
            }
        }
    }
}

fn intersect(a: &[(u8, u8)], b: &[(u8, u8)]) -> Vec<(u8, u8)> {
    let mut out = Vec::new();
    for &(x0, x1) in a {
        for &(y0, y1) in b {
            let (lo, hi) = (x0.max(y0), x1.min(y1));
            if lo <= hi {
                out.push((lo, hi));
            }
        }
    }
    out
}

impl PacketSet {
    /// The set of a set query: each original request equals its current
    /// header. The set is a union of products with fixed presence bits:
    /// one for each address family, class of protocol, fragment state and
    /// VLAN presence that the constraints allow. No field is unknown and no
    /// packet has an encapsulation.
    pub fn from_spec(arena: &Arc<SetArena>, spec: &SetSpec) -> PacketSet {
        let e = arena.run(|ops| spec_edge(ops, spec)).unwrap_or(Edge::FALSE);
        PacketSet::from_edge(arena, e)
    }
}

fn spec_edge(ops: &mut Ops<'_>, spec: &SetSpec) -> Result<Edge, DdError> {
    let families: Vec<bool> = {
        let fam = |ps: &Option<Vec<Prefix>>| -> Option<Vec<bool>> {
            ps.as_ref().map(|ps| {
                let mut v: Vec<bool> = ps.iter().map(|p| !p.is_ipv4()).collect();
                v.sort_unstable();
                v.dedup();
                v
            })
        };
        let mut all = vec![false, true];
        for f in [fam(&spec.src_ip), fam(&spec.dst_ip)].into_iter().flatten() {
            all.retain(|v6| f.contains(v6));
        }
        all
    };
    let protocols = spec.protocol.clone().unwrap_or_else(|| vec![(0, 255)]);
    let fragments = spec
        .fragment
        .clone()
        .unwrap_or_else(|| vec![Fragment::Unfragmented, Fragment::First, Fragment::Later]);
    let vlans: Vec<bool> = if spec.vlan.is_some() || spec.l2_priority.is_some() {
        vec![true]
    } else {
        vec![false, true]
    };
    let mut acc = Edge::FALSE;
    for &v6 in &families {
        for class in [Class::Tcp, Class::Udp, Class::Icmp, Class::Other] {
            let protos = intersect(&protocols, &class.ranges());
            if protos.is_empty() {
                continue;
            }
            for &frag in &fragments {
                for &tagged in &vlans {
                    let transport = frag != Fragment::Later;
                    let ports = transport && matches!(class, Class::Tcp | Class::Udp);
                    let tcp = transport && class == Class::Tcp;
                    let icmp = transport && class == Class::Icmp;
                    // A constraint on a field holds only packets with the field.
                    let needs = |given: bool, present: bool| !given || present;
                    if !(needs(spec.src_port.is_some() || spec.dst_port.is_some(), ports)
                        && needs(spec.tcp_flags.is_some(), tcp)
                        && needs(spec.icmp_type.is_some() || spec.icmp_code.is_some(), icmp))
                    {
                        continue;
                    }
                    let p = product(ops, spec, v6, &protos, frag, ports, tcp, icmp, tagged)?;
                    acc = ops.dd.or(acc, p)?;
                }
            }
        }
    }
    ops.dd.and(acc, ops.base.eq)
}

/// One product on the current bank.
#[allow(clippy::too_many_arguments)]
fn product(
    ops: &mut Ops<'_>,
    spec: &SetSpec,
    v6: bool,
    protos: &[(u8, u8)],
    frag: Fragment,
    ports: bool,
    tcp: bool,
    icmp: bool,
    tagged: bool,
) -> Result<Edge, DdError> {
    let c = Bank::Current;
    let mut b: Builder<'_> = ops.builder();
    let mut lits: Vec<(u32, bool)> = Vec::new();
    for (p, v) in [
        (bits::P_PORTS, ports),
        (bits::P_TCP, tcp),
        (bits::P_ICMP, icmp),
        (bits::P_VLAN, tagged),
        (bits::P_MPLS, false),
    ] {
        lits.push((bits::level(p, c), v));
    }
    for u in bits::U_SRC_IP..=bits::U_VLAN {
        lits.push((bits::level(u, c), false));
    }
    lits.push((bits::level(bits::AF, c), v6));
    // The fields of absent headers, the high bits of IPv4 addresses and the
    // encapsulation are 0.
    let mut zero: Vec<u32> = Vec::new();
    let absent = |f: FieldBits, present: bool, zero: &mut Vec<u32>| {
        if !present {
            zero.extend(f.value_bits());
        }
    };
    absent(bits::SRC_PORT, ports, &mut zero);
    absent(bits::DST_PORT, ports, &mut zero);
    absent(bits::TCP_FLAGS, tcp, &mut zero);
    absent(bits::ICMP_TYPE, icmp, &mut zero);
    absent(bits::ICMP_CODE, icmp, &mut zero);
    absent(bits::VLAN, tagged, &mut zero);
    absent(bits::L2_PRIORITY, tagged, &mut zero);
    // With no tag constraint for them, the TPID is 0x8100 and the inner tag
    // is absent.
    if tagged {
        lits.extend(crate::set::value_lits(
            bits::VLAN_TPID,
            c,
            u128::from(bits::TPID_8021Q),
        ));
    } else {
        zero.extend(bits::VLAN_TPID.value_bits());
    }
    for x in [
        bits::P_INNER_VLAN,
        bits::U_INNER_VLAN,
        bits::U_INNER_L2_PRIORITY,
    ] {
        lits.push((bits::level(x, c), false));
    }
    for f in bits::INNER_TAG {
        zero.extend(f.value_bits());
    }
    zero.extend(bits::MPLS_TC.value_bits());
    for f in [
        bits::ENCAP_KIND,
        bits::ENCAP_SRC,
        bits::ENCAP_DST,
        bits::ENCAP_VNI,
        bits::ENCAP_LABEL,
    ] {
        zero.extend(f.value_bits());
    }
    if !v6 {
        for f in [bits::SRC_IP, bits::DST_IP] {
            zero.extend(f.start..f.start + 96);
        }
    }
    for x in zero {
        lits.push((bits::level(x, c), false));
    }
    let mut acc = b.dd.literals(&lits)?;
    let mut and = |b: &mut Builder<'_>, e: Edge| -> Result<(), DdError> {
        acc = b.dd.and(acc, e)?;
        Ok(())
    };
    let ranges8 = |b: &mut Builder<'_>, f: FieldBits, rs: &[(u8, u8)]| {
        let items: Vec<_> = rs
            .iter()
            .map(|&(lo, hi)| b.range(f, c, u128::from(lo), u128::from(hi)))
            .collect();
        b.any_of(items)
    };
    let ranges16 = |b: &mut Builder<'_>, f: FieldBits, rs: &[(u16, u16)]| {
        let items: Vec<_> = rs
            .iter()
            .map(|&(lo, hi)| b.range(f, c, u128::from(lo), u128::from(hi)))
            .collect();
        b.any_of(items)
    };
    let e = ranges8(&mut b, bits::PROTOCOL, protos)?;
    and(&mut b, e)?;
    let e = b.value(bits::FRAGMENT, c, bits::fragment_code(frag))?;
    and(&mut b, e)?;
    for (f, ps) in [(bits::SRC_IP, &spec.src_ip), (bits::DST_IP, &spec.dst_ip)] {
        if let Some(ps) = ps {
            let items: Vec<_> = ps
                .iter()
                .filter(|p| p.is_ipv4() != v6)
                .map(|p| b.prefix(f, c, p))
                .collect();
            let e = b.any_of(items)?;
            and(&mut b, e)?;
        }
    }
    for (f, macs) in [
        (bits::SRC_MAC, &spec.src_mac),
        (bits::DST_MAC, &spec.dst_mac),
    ] {
        if let Some(ms) = macs {
            let items: Vec<_> = ms
                .iter()
                .map(|m| b.value(f, c, bits::mac_bits(*m)))
                .collect();
            let e = b.any_of(items)?;
            and(&mut b, e)?;
        }
    }
    let p16 = [
        (bits::SRC_PORT, &spec.src_port, ports),
        (bits::DST_PORT, &spec.dst_port, ports),
        (bits::VLAN, &spec.vlan, tagged),
    ];
    for (f, rs, present) in p16 {
        if let (Some(rs), true) = (rs, present) {
            let e = ranges16(&mut b, f, rs)?;
            and(&mut b, e)?;
        }
    }
    let p8 = [
        (bits::L2_PRIORITY, &spec.l2_priority, tagged),
        (bits::TCP_FLAGS, &spec.tcp_flags, tcp),
        (bits::ICMP_TYPE, &spec.icmp_type, icmp),
        (bits::ICMP_CODE, &spec.icmp_code, icmp),
        (bits::DSCP, &spec.dscp, true),
        (bits::ECN, &spec.ecn, true),
    ];
    for (f, rs, present) in p8 {
        if let (Some(rs), true) = (rs, present) {
            let e = ranges8(&mut b, f, rs)?;
            and(&mut b, e)?;
        }
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{HeaderField, PROTO_TCP};
    use crate::{PacketPair, Values};

    fn pfx(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn a_constraint_on_ports_holds_only_packets_with_ports() {
        let a = SetArena::standalone();
        let s = PacketSet::from_spec(
            &a,
            &SetSpec {
                src_ip: Some(vec![pfx("10.0.0.0/24")]),
                dst_ip: Some(vec![pfx("192.0.2.1/32")]),
                dst_port: Some(vec![(53, 53)]),
                ..SetSpec::default()
            },
        );
        for m in s.describe() {
            let p = m.original.get(HeaderField::Protocol);
            assert!(
                matches!(p, Values::Ranges(r) if r.iter().all(|&(lo, hi)| (lo == 6 && hi == 6) || (lo == 17 && hi == 17))),
                "{p:?}"
            );
            assert_eq!(m.original.get(HeaderField::DstPort).single(), Some(53));
            assert_eq!(m.current.get(HeaderField::DstPort).single(), Some(53));
        }
        let h = crate::header::Header::request(
            "10.0.0.9".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            PROTO_TCP,
        )
        .with_src_port(1)
        .with_dst_port(53)
        .with_tcp_flags(0x02)
        .with_dscp(0)
        .with_ecn(0);
        let mut h = h;
        h.src_mac = crate::field::FieldValue::Known(Mac([0; 6]));
        h.dst_mac = crate::field::FieldValue::Known(Mac([0; 6]));
        h.vlan = crate::field::FieldValue::Absent;
        h.l2_priority = crate::field::FieldValue::Absent;
        assert!(s.contains(&PacketPair {
            original: h.clone(),
            current: h
        }));
    }

    #[test]
    fn no_constraint_holds_both_families_and_each_protocol() {
        let a = SetArena::standalone();
        let all = PacketSet::from_spec(&a, &SetSpec::default());
        let v4 = PacketSet::from_spec(
            &a,
            &SetSpec {
                src_ip: Some(vec![pfx("0.0.0.0/0")]),
                ..SetSpec::default()
            },
        );
        let v6 = PacketSet::from_spec(
            &a,
            &SetSpec {
                dst_ip: Some(vec![pfx("::/0")]),
                ..SetSpec::default()
            },
        );
        assert_eq!(v4.union(&v6), all);
        assert!(v4.intersect(&v6).is_empty());
        // Mixed families of source and destination give no packet.
        let mixed = PacketSet::from_spec(
            &a,
            &SetSpec {
                src_ip: Some(vec![pfx("0.0.0.0/0")]),
                dst_ip: Some(vec![pfx("::/0")]),
                ..SetSpec::default()
            },
        );
        assert!(mixed.is_empty());
    }
}
