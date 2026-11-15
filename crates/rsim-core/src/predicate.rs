//! Header predicates and match bounds.

use std::collections::BTreeSet;

use crate::addr::{Mac, Prefix};
use crate::field::{FieldValue, Tri};
use crate::header::{Fragment, Header, HeaderField};

/// A condition on an address field.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddrCond {
    Any,
    In(Vec<Prefix>),
}

impl AddrCond {
    pub fn prefixes(ps: &[&str]) -> Self {
        AddrCond::In(
            ps.iter()
                .map(|p| p.parse().expect("valid prefix"))
                .collect(),
        )
    }

    fn eval(&self, v: FieldValue<std::net::IpAddr>) -> Tri {
        match self {
            AddrCond::Any => Tri::True,
            AddrCond::In(ps) => v.test(|ip| ps.iter().any(|p| p.contains(ip))),
        }
    }
}

/// A condition on a small integer field: a set of allowed values.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueCond {
    Any,
    In(BTreeSet<u8>),
}

impl ValueCond {
    pub fn one(v: u8) -> Self {
        ValueCond::In([v].into_iter().collect())
    }

    fn eval(&self, v: FieldValue<u8>) -> Tri {
        match self {
            ValueCond::Any => Tri::True,
            ValueCond::In(s) => v.test(|x| s.contains(&x)),
        }
    }
}

/// A condition on a port field: inclusive ranges.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PortCond {
    Any,
    In(Vec<(u16, u16)>),
}

impl PortCond {
    pub fn one(p: u16) -> Self {
        PortCond::In(vec![(p, p)])
    }

    fn eval(&self, v: FieldValue<u16>) -> Tri {
        match self {
            PortCond::Any => Tri::True,
            PortCond::In(rs) => v.test(|p| rs.iter().any(|&(lo, hi)| lo <= p && p <= hi)),
        }
    }
}

/// A condition on a 16-bit range field other than a port, for example the
/// VLAN tag.
pub type RangeCond = PortCond;

/// A condition on TCP flags: the bits in `mask` must equal `value`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlagsCond {
    Any,
    Bits { mask: u8, value: u8 },
}

impl FlagsCond {
    fn eval(&self, v: FieldValue<u8>) -> Tri {
        match self {
            FlagsCond::Any => Tri::True,
            FlagsCond::Bits { mask, value } => v.test(|f| f & mask == *value),
        }
    }
}

/// A condition on the fragment state.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FragmentCond {
    Any,
    In(BTreeSet<Fragment>),
}

impl FragmentCond {
    fn eval(&self, v: FieldValue<Fragment>) -> Tri {
        match self {
            FragmentCond::Any => Tri::True,
            FragmentCond::In(s) => v.test(|x| s.contains(&x)),
        }
    }
}

/// A condition on a MAC address field.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MacCond {
    Any,
    In(BTreeSet<Mac>),
}

impl MacCond {
    fn eval(&self, v: FieldValue<Mac>) -> Tri {
        match self {
            MacCond::Any => Tri::True,
            MacCond::In(s) => v.test(|x| s.contains(&x)),
        }
    }
}

/// A conjunction of field conditions. A field with `Any` is not read.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Match {
    pub src_ip: AddrCond,
    pub dst_ip: AddrCond,
    pub protocol: ValueCond,
    pub src_port: PortCond,
    pub dst_port: PortCond,
    pub dscp: ValueCond,
    pub ecn: ValueCond,
    pub fragment: FragmentCond,
    pub tcp_flags: FlagsCond,
    pub icmp_type: ValueCond,
    pub icmp_code: ValueCond,
    pub src_mac: MacCond,
    pub dst_mac: MacCond,
    pub vlan: RangeCond,
    pub l2_priority: ValueCond,
    pub mpls_tc: ValueCond,
}

impl Default for Match {
    fn default() -> Self {
        Self::any()
    }
}

impl Match {
    pub fn any() -> Self {
        Match {
            src_ip: AddrCond::Any,
            dst_ip: AddrCond::Any,
            protocol: ValueCond::Any,
            src_port: PortCond::Any,
            dst_port: PortCond::Any,
            dscp: ValueCond::Any,
            ecn: ValueCond::Any,
            fragment: FragmentCond::Any,
            tcp_flags: FlagsCond::Any,
            icmp_type: ValueCond::Any,
            icmp_code: ValueCond::Any,
            src_mac: MacCond::Any,
            dst_mac: MacCond::Any,
            vlan: RangeCond::Any,
            l2_priority: ValueCond::Any,
            mpls_tc: ValueCond::Any,
        }
    }

    /// Evaluates the predicate on one header with Kleene logic.
    pub fn eval(&self, h: &Header) -> Tri {
        self.src_ip
            .eval(h.src_ip)
            .and(self.dst_ip.eval(h.dst_ip))
            .and(self.protocol.eval(h.protocol))
            .and(self.src_port.eval(h.src_port))
            .and(self.dst_port.eval(h.dst_port))
            .and(self.dscp.eval(h.dscp))
            .and(self.ecn.eval(h.ecn))
            .and(self.fragment.eval(h.fragment))
            .and(self.tcp_flags.eval(h.tcp_flags))
            .and(self.icmp_type.eval(h.icmp_type))
            .and(self.icmp_code.eval(h.icmp_code))
            .and(self.src_mac.eval(h.src_mac))
            .and(self.dst_mac.eval(h.dst_mac))
            .and(self.vlan.eval(h.vlan))
            .and(self.l2_priority.eval(h.l2_priority))
            .and(self.mpls_tc.eval(h.mpls_tc))
    }

    /// The fields of `h` for which the predicate has no definite result,
    /// because the value is not given or not known.
    pub fn open_fields(&self, h: &Header) -> Vec<(HeaderField, OpenField)> {
        fn open<T>(t: Tri, v: FieldValue<T>) -> Option<OpenField> {
            match (t, v) {
                (Tri::Unknown, FieldValue::Unstated) => Some(OpenField::NotGiven),
                (Tri::Unknown, FieldValue::Unknown) => Some(OpenField::Unknown),
                _ => None,
            }
        }
        let checks = [
            (
                HeaderField::SrcIp,
                open(self.src_ip.eval(h.src_ip), h.src_ip),
            ),
            (
                HeaderField::DstIp,
                open(self.dst_ip.eval(h.dst_ip), h.dst_ip),
            ),
            (
                HeaderField::Protocol,
                open(self.protocol.eval(h.protocol), h.protocol),
            ),
            (
                HeaderField::SrcPort,
                open(self.src_port.eval(h.src_port), h.src_port),
            ),
            (
                HeaderField::DstPort,
                open(self.dst_port.eval(h.dst_port), h.dst_port),
            ),
            (HeaderField::Dscp, open(self.dscp.eval(h.dscp), h.dscp)),
            (HeaderField::Ecn, open(self.ecn.eval(h.ecn), h.ecn)),
            (
                HeaderField::Fragment,
                open(self.fragment.eval(h.fragment), h.fragment),
            ),
            (
                HeaderField::TcpFlags,
                open(self.tcp_flags.eval(h.tcp_flags), h.tcp_flags),
            ),
            (
                HeaderField::IcmpType,
                open(self.icmp_type.eval(h.icmp_type), h.icmp_type),
            ),
            (
                HeaderField::IcmpCode,
                open(self.icmp_code.eval(h.icmp_code), h.icmp_code),
            ),
            (
                HeaderField::SrcMac,
                open(self.src_mac.eval(h.src_mac), h.src_mac),
            ),
            (
                HeaderField::DstMac,
                open(self.dst_mac.eval(h.dst_mac), h.dst_mac),
            ),
            (HeaderField::Vlan, open(self.vlan.eval(h.vlan), h.vlan)),
            (
                HeaderField::L2Priority,
                open(self.l2_priority.eval(h.l2_priority), h.l2_priority),
            ),
            (
                HeaderField::MplsTrafficClass,
                open(self.mpls_tc.eval(h.mpls_tc), h.mpls_tc),
            ),
        ];
        checks
            .into_iter()
            .filter_map(|(f, o)| o.map(|o| (f, o)))
            .collect()
    }

    /// The header fields that the predicate reads.
    pub fn reads(&self) -> Vec<HeaderField> {
        let mut r = Vec::new();
        if self.src_ip != AddrCond::Any {
            r.push(HeaderField::SrcIp);
        }
        if self.dst_ip != AddrCond::Any {
            r.push(HeaderField::DstIp);
        }
        if self.protocol != ValueCond::Any {
            r.push(HeaderField::Protocol);
        }
        if self.src_port != PortCond::Any {
            r.push(HeaderField::SrcPort);
        }
        if self.dst_port != PortCond::Any {
            r.push(HeaderField::DstPort);
        }
        if self.dscp != ValueCond::Any {
            r.push(HeaderField::Dscp);
        }
        if self.ecn != ValueCond::Any {
            r.push(HeaderField::Ecn);
        }
        if self.fragment != FragmentCond::Any {
            r.push(HeaderField::Fragment);
        }
        if self.tcp_flags != FlagsCond::Any {
            r.push(HeaderField::TcpFlags);
        }
        if self.icmp_type != ValueCond::Any {
            r.push(HeaderField::IcmpType);
        }
        if self.icmp_code != ValueCond::Any {
            r.push(HeaderField::IcmpCode);
        }
        if self.src_mac != MacCond::Any {
            r.push(HeaderField::SrcMac);
        }
        if self.dst_mac != MacCond::Any {
            r.push(HeaderField::DstMac);
        }
        if self.vlan != RangeCond::Any {
            r.push(HeaderField::Vlan);
        }
        if self.l2_priority != ValueCond::Any {
            r.push(HeaderField::L2Priority);
        }
        if self.mpls_tc != ValueCond::Any {
            r.push(HeaderField::MplsTrafficClass);
        }
        r
    }
}

/// A predicate with match bounds: the definite match set `M-` and the upper
/// match bound `M+`. For a fully known predicate the two are equal.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RulePredicate {
    pub definite: Match,
    pub upper: Match,
}

impl RulePredicate {
    pub fn exact(m: Match) -> Self {
        RulePredicate {
            definite: m.clone(),
            upper: m,
        }
    }

    /// A predicate whose match set is only known between two bounds, for
    /// example an address group with members that are not known.
    pub fn bounded(definite: Match, upper: Match) -> Self {
        RulePredicate { definite, upper }
    }

    /// Classifies one header: definite match (in `M-`), definite no match
    /// (not in `M+`), or uncertain.
    pub fn classify(&self, h: &Header) -> MatchClass {
        if self.definite.eval(h) == Tri::True {
            MatchClass::Match
        } else if self.upper.eval(h) == Tri::False {
            MatchClass::NoMatch
        } else {
            MatchClass::Uncertain
        }
    }

    pub fn reads(&self) -> Vec<HeaderField> {
        let mut r = self.definite.reads();
        r.extend(self.upper.reads());
        r.sort();
        r.dedup();
        r
    }
}

/// Why a field gives no definite match result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OpenField {
    /// The query does not give the field.
    NotGiven,
    /// A function made the field unknown.
    Unknown,
}

impl OpenField {
    pub fn text(&self) -> &'static str {
        match self {
            OpenField::NotGiven => "not given",
            OpenField::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MatchClass {
    Match,
    Uncertain,
    NoMatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::PROTO_UDP;

    fn h() -> Header {
        Header::request(
            "172.31.10.20".parse().unwrap(),
            "10.20.0.53".parse().unwrap(),
            PROTO_UDP,
        )
        .with_dst_port(53)
    }

    #[test]
    fn unstated_field_is_uncertain_not_all_values() {
        let p = RulePredicate::exact(Match {
            src_port: PortCond::In(vec![(1024, 65535)]),
            ..Match::any()
        });
        assert_eq!(p.classify(&h()), MatchClass::Uncertain);
        assert_eq!(p.classify(&h().with_src_port(5000)), MatchClass::Match);
        assert_eq!(p.classify(&h().with_src_port(53)), MatchClass::NoMatch);
    }

    #[test]
    fn absent_field_does_not_match() {
        let p = RulePredicate::exact(Match {
            dst_port: PortCond::one(53),
            ..Match::any()
        });
        assert_eq!(p.classify(&h().as_later_fragment()), MatchClass::NoMatch);
    }

    #[test]
    fn bounds_give_uncertain_between() {
        let p = RulePredicate::bounded(
            Match {
                src_ip: AddrCond::prefixes(&["172.31.11.0/24"]),
                ..Match::any()
            },
            Match::any(),
        );
        assert_eq!(p.classify(&h()), MatchClass::Uncertain);
    }
}
