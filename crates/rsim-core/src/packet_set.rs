//! The packet set (section 4).
//!
//! A packet set is a region of header space. It holds pairs of the original
//! request header and the current header. The representation is private.
//! Functions use only the operations of this interface, so that step 2 can
//! add the decision diagram representation with no change to the functions.
//!
//! The step 1 representation is an explicit, sorted list of packet pairs.
//! Concrete mode always uses a set with one packet.

use std::net::IpAddr;

use crate::addr::{Mac, Prefix};
use crate::field::{FieldValue, Tri};
use crate::header::{FlowKey, Header};
use crate::predicate::{MatchClass, RulePredicate};
use crate::prefix_table::PrefixTable;

/// One member of a packet set: the original request header and the current header.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PacketPair {
    pub original: Header,
    pub current: Header,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PacketSet {
    /// Sorted and without duplicates.
    pairs: Vec<PacketPair>,
}

/// The result of a split by a predicate with match bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Split {
    /// Packets in the definite match set `M-`.
    pub matched: PacketSet,
    /// Packets in `M+` and not in `M-`.
    pub uncertain: PacketSet,
    /// Packets not in `M+`.
    pub unmatched: PacketSet,
}

/// Which address field a prefix partition reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddrField {
    Src,
    Dst,
}

/// The result of a partition by a prefix table with longest-prefix match.
#[derive(Debug)]
pub struct PrefixPartition<'t, V> {
    /// For each matched prefix, in prefix order: the value and the packets.
    pub matched: Vec<(Prefix, &'t V, PacketSet)>,
    /// Packets with a known address that no prefix contains.
    pub unmatched: PacketSet,
    /// Packets where the address is unstated, unknown or absent.
    pub uncertain: PacketSet,
}

/// A rewrite of the current header. `None` leaves a field as it is.
/// A rewrite never changes the original request header.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rewrite {
    pub src_ip: Option<FieldValue<IpAddr>>,
    pub dst_ip: Option<FieldValue<IpAddr>>,
    pub src_port: Option<FieldValue<u16>>,
    pub dst_port: Option<FieldValue<u16>>,
    pub dscp: Option<FieldValue<u8>>,
    pub ecn: Option<FieldValue<u8>>,
    pub src_mac: Option<FieldValue<Mac>>,
    pub dst_mac: Option<FieldValue<Mac>>,
    pub vlan: Option<FieldValue<u16>>,
    pub l2_priority: Option<FieldValue<u8>>,
    pub mpls_tc: Option<FieldValue<u8>>,
}

impl Rewrite {
    pub fn is_identity(&self) -> bool {
        *self == Rewrite::default()
    }

    fn apply(&self, h: &mut Header) {
        fn set<T: Copy>(slot: &mut FieldValue<T>, v: Option<FieldValue<T>>) {
            if let Some(v) = v {
                // A rewrite does not create a header that is absent.
                if slot.is_present() {
                    *slot = v;
                }
            }
        }
        set(&mut h.src_ip, self.src_ip);
        set(&mut h.dst_ip, self.dst_ip);
        set(&mut h.src_port, self.src_port);
        set(&mut h.dst_port, self.dst_port);
        set(&mut h.dscp, self.dscp);
        set(&mut h.ecn, self.ecn);
        set(&mut h.src_mac, self.src_mac);
        set(&mut h.dst_mac, self.dst_mac);
        set(&mut h.vlan, self.vlan);
        set(&mut h.l2_priority, self.l2_priority);
        set(&mut h.mpls_tc, self.mpls_tc);
    }
}

/// The QoS fields of the current header, where all members agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Uniform<T> {
    Value(T),
    /// The members of the set have different values.
    Varies,
    /// The set is empty.
    None,
}

impl PacketSet {
    pub fn empty() -> Self {
        PacketSet { pairs: Vec::new() }
    }

    /// A set with one packet. The original request is the header itself.
    pub fn single(h: Header) -> Self {
        PacketSet {
            pairs: vec![PacketPair {
                original: h.clone(),
                current: h,
            }],
        }
    }

    fn from_pairs(mut pairs: Vec<PacketPair>) -> Self {
        pairs.sort();
        pairs.dedup();
        PacketSet { pairs }
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    pub fn intersect(&self, other: &PacketSet) -> PacketSet {
        PacketSet {
            pairs: self
                .pairs
                .iter()
                .filter(|p| other.pairs.binary_search(p).is_ok())
                .cloned()
                .collect(),
        }
    }

    pub fn union(&self, other: &PacketSet) -> PacketSet {
        let mut v = self.pairs.clone();
        v.extend(other.pairs.iter().cloned());
        PacketSet::from_pairs(v)
    }

    pub fn difference(&self, other: &PacketSet) -> PacketSet {
        PacketSet {
            pairs: self
                .pairs
                .iter()
                .filter(|p| other.pairs.binary_search(p).is_err())
                .cloned()
                .collect(),
        }
    }

    /// One concrete member, if the set is not empty. The engine uses it for
    /// reports and tests. A function must not branch on it.
    pub fn witness(&self) -> Option<&PacketPair> {
        self.pairs.first()
    }

    /// The projection to the original request headers. Each member of the
    /// result has the original request as both headers.
    pub fn project_original(&self) -> PacketSet {
        PacketSet::from_pairs(
            self.pairs
                .iter()
                .map(|p| PacketPair {
                    original: p.original.clone(),
                    current: p.original.clone(),
                })
                .collect(),
        )
    }

    fn filter3(&self, f: impl Fn(&Header) -> MatchClass) -> Split {
        let mut m = Vec::new();
        let mut u = Vec::new();
        let mut n = Vec::new();
        for p in &self.pairs {
            match f(&p.current) {
                MatchClass::Match => m.push(p.clone()),
                MatchClass::Uncertain => u.push(p.clone()),
                MatchClass::NoMatch => n.push(p.clone()),
            }
        }
        Split {
            matched: PacketSet { pairs: m },
            uncertain: PacketSet { pairs: u },
            unmatched: PacketSet { pairs: n },
        }
    }

    /// Splits the set by a predicate on the current header.
    pub fn split(&self, pred: &RulePredicate) -> Split {
        self.filter3(|h| pred.classify(h))
    }

    /// Splits the set by a flow key on the current header. See [`FlowKey::matches`].
    pub fn split_flow(&self, key: &FlowKey) -> Split {
        self.filter3(|h| match key.matches(h) {
            Tri::True => MatchClass::Match,
            Tri::Unknown => MatchClass::Uncertain,
            Tri::False => MatchClass::NoMatch,
        })
    }

    /// Partitions the set by longest-prefix match of an address field.
    pub fn partition_by_prefix<'t, V, T>(
        &self,
        field: AddrField,
        table: &'t T,
    ) -> PrefixPartition<'t, V>
    where
        T: PrefixTable<V> + ?Sized,
    {
        let mut matched: Vec<(Prefix, &'t V, Vec<PacketPair>)> = Vec::new();
        let mut unmatched = Vec::new();
        let mut uncertain = Vec::new();
        for p in &self.pairs {
            let v = match field {
                AddrField::Src => p.current.src_ip,
                AddrField::Dst => p.current.dst_ip,
            };
            match v {
                FieldValue::Known(ip) => match table.longest_match(ip) {
                    Some((pfx, val)) => match matched.iter_mut().find(|(q, _, _)| *q == pfx) {
                        Some((_, _, v)) => v.push(p.clone()),
                        None => matched.push((pfx, val, vec![p.clone()])),
                    },
                    None => unmatched.push(p.clone()),
                },
                _ => uncertain.push(p.clone()),
            }
        }
        matched.sort_by_key(|(p, _, _)| *p);
        PrefixPartition {
            matched: matched
                .into_iter()
                .map(|(p, v, ps)| (p, v, PacketSet::from_pairs(ps)))
                .collect(),
            unmatched: PacketSet { pairs: unmatched },
            uncertain: PacketSet { pairs: uncertain },
        }
    }

    /// Rewrites fields of the current header. The original request stays.
    pub fn rewrite(&self, rw: &Rewrite) -> PacketSet {
        if rw.is_identity() {
            return self.clone();
        }
        PacketSet::from_pairs(
            self.pairs
                .iter()
                .map(|p| {
                    let mut c = p.current.clone();
                    rw.apply(&mut c);
                    PacketPair {
                        original: p.original.clone(),
                        current: c,
                    }
                })
                .collect(),
        )
    }

    /// The reply packets: the current header with addresses and ports
    /// swapped. The reply is a new request, so its original request is the
    /// swapped header.
    pub fn reply(&self) -> PacketSet {
        PacketSet::from_pairs(
            self.pairs
                .iter()
                .map(|p| {
                    let h = p.current.swapped();
                    PacketPair {
                        original: h.clone(),
                        current: h,
                    }
                })
                .collect(),
        )
    }

    /// The flow key of the current header, if all members have the same key.
    ///
    /// Step 1 keeps firewall sessions per flow key. A set with more than one
    /// key needs the relation form of step 2.
    pub fn flow_key(&self) -> Uniform<FlowKey> {
        uniform(self.pairs.iter().map(|p| FlowKey::of(&p.current)))
    }

    pub fn dscp(&self) -> Uniform<FieldValue<u8>> {
        uniform(self.pairs.iter().map(|p| p.current.dscp))
    }

    pub fn ecn(&self) -> Uniform<FieldValue<u8>> {
        uniform(self.pairs.iter().map(|p| p.current.ecn))
    }

    /// The members. For reports, tests and contract checks only.
    pub fn members(&self) -> &[PacketPair] {
        &self.pairs
    }
}

fn uniform<T: PartialEq>(mut it: impl Iterator<Item = T>) -> Uniform<T> {
    match it.next() {
        None => Uniform::None,
        Some(first) => {
            if it.all(|x| x == first) {
                Uniform::Value(first)
            } else {
                Uniform::Varies
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::PROTO_UDP;

    #[test]
    fn rewrite_keeps_original() {
        let h = Header::request(
            "172.31.10.20".parse().unwrap(),
            "10.20.0.53".parse().unwrap(),
            PROTO_UDP,
        )
        .with_dst_port(53);
        let s = PacketSet::single(h.clone());
        let r = s.rewrite(&Rewrite {
            src_ip: Some(FieldValue::Known("10.20.0.254".parse().unwrap())),
            ..Rewrite::default()
        });
        let w = r.witness().unwrap();
        assert_eq!(w.original, h);
        assert_eq!(
            w.current.src_ip,
            FieldValue::Known("10.20.0.254".parse().unwrap())
        );
        assert_eq!(r.project_original(), s);
    }

    #[test]
    fn set_operations() {
        let a = PacketSet::single(Header::request(
            "1.1.1.1".parse().unwrap(),
            "2.2.2.2".parse().unwrap(),
            PROTO_UDP,
        ));
        let b = PacketSet::single(Header::request(
            "1.1.1.1".parse().unwrap(),
            "3.3.3.3".parse().unwrap(),
            PROTO_UDP,
        ));
        let u = a.union(&b);
        assert_eq!(u.intersect(&a), a);
        assert_eq!(u.difference(&a), b);
        assert!(a.intersect(&b).is_empty());
    }
}
