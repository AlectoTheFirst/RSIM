//! BGP: the paths, the processes, the route policies, the vendor profiles,
//! the decision function, the propagation over the sessions and the
//! convergence detection.
//!
//! The order is fixed: communities, route targets and lists are ordered
//! sets, and the policies and lists are held by name in `BTreeMap`s.

pub mod converge;
pub mod decision;
pub mod lists;
pub mod pattern;
pub mod policy;
pub mod process;
pub mod profile;
pub mod propagate;
pub mod session;
pub mod stage;

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use rsim_core::{Prefix, SourceSpan};

pub use converge::{
    BgpResult, Convergence, ConvergenceKind, CycleWitness, Event, GroupResult, Note, Outcome,
    RouteAt, RouteState, WheelSpoke, compute, install_candidates,
};
pub use decision::{Decision, DecisionStage, DecisionStep, decide};
pub use lists::{
    AsPathLine, AsPathList, AsPathTerm, Cmp, CommunityLine, CommunityList, CommunityTerm, Half,
    PrefixList, PrefixListEntry,
};
pub use pattern::Pattern;
pub use policy::{
    Clause, Continue, Direction, Guard, MatchTerm, MedSet, NextHopMatch, NextHopSet, PolicyBody,
    PolicyContext, PolicyResult, PolicyStage, RoutePolicy, RouteTypeMatch, SetAction, Statement,
    evaluate, neighbor_policy,
};
pub use process::{
    Aggregate, BgpOptions, BgpProcess, LocalAs, Neighbor, Network, NextHopSelf, PolicySet,
};
pub use profile::{BgpProfile, DECISION_ORDER, MatchReads, UndefinedPolicy};
pub use propagate::{
    BestPath, BgpInput, IgpView, InputError, OriginateInput, OriginateStage, Resolution, Seed,
    Selection, aggregate_as_path, aggregate_offer, network_offer,
};
pub use session::{Offer, Session, SessionEnd, SessionStage, export, receive};
pub use stage::{ObjectRef, RoutingStage};

/// An AS number in the asplain form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Asn(pub u32);

impl Asn {
    /// True for the private ranges of RFC 6996: 64512 to 65534 and
    /// 4200000000 to 4294967294.
    pub fn is_private(self) -> bool {
        (64_512..=65_534).contains(&self.0) || (4_200_000_000..=4_294_967_294).contains(&self.0)
    }
}

impl fmt::Display for Asn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The text is not an AS number in the asplain or the asdot form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseAsnError(pub String);

impl fmt::Display for ParseAsnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not an AS number: {}", self.0)
    }
}

impl std::error::Error for ParseAsnError {}

impl FromStr for Asn {
    type Err = ParseAsnError;

    /// Reads the asplain form `65546` and the asdot form `1.10` of RFC 5396.
    /// Each half of the asdot form is at most 65535.
    fn from_str(s: &str) -> Result<Asn, ParseAsnError> {
        let err = || ParseAsnError(s.to_string());
        let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
        match s.split_once('.') {
            None if digits(s) => s.parse::<u32>().map(Asn).map_err(|_| err()),
            Some((high, low)) if digits(high) && digits(low) => {
                let high: u32 = high.parse().map_err(|_| err())?;
                let low: u32 = low.parse().map_err(|_| err())?;
                if high > 0xFFFF || low > 0xFFFF {
                    return Err(err());
                }
                Ok(Asn((high << 16) | low))
            }
            _ => Err(err()),
        }
    }
}

/// An address family of a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    Ipv4Unicast,
    Ipv6Unicast,
    /// The EVPN IP prefix route, route type 5 of RFC 9136.
    EvpnIpPrefix,
}

/// The administrator and assigned number of a route distinguisher or a
/// route target (RFC 4364 4.2, RFC 4360 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdminValue {
    /// Type 0: a 2-byte AS number and a 4-byte number.
    As2 { asn: u16, value: u32 },
    /// Type 1: an IPv4 address and a 2-byte number.
    Ipv4 { addr: Ipv4Addr, value: u16 },
    /// Type 2: a 4-byte AS number and a 2-byte number.
    As4 { asn: u32, value: u16 },
}

impl fmt::Display for AdminValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdminValue::As2 { asn, value } => write!(f, "{asn}:{value}"),
            AdminValue::Ipv4 { addr, value } => write!(f, "{addr}:{value}"),
            AdminValue::As4 { asn, value } => write!(f, "{asn}:{value}"),
        }
    }
}

impl FromStr for AdminValue {
    type Err = ParseAsnError;

    /// Reads `a:n`. An IPv4 address gives type 1, an AS number up to 65535
    /// gives type 0, and a larger AS number or an asdot AS number gives
    /// type 2.
    fn from_str(s: &str) -> Result<AdminValue, ParseAsnError> {
        let err = || ParseAsnError(s.to_string());
        let (admin, value) = s.rsplit_once(':').ok_or_else(err)?;
        if let Ok(addr) = admin.parse::<Ipv4Addr>() {
            let value = value.parse().map_err(|_| err())?;
            return Ok(AdminValue::Ipv4 { addr, value });
        }
        let asn: Asn = admin.parse().map_err(|_| err())?;
        if asn.0 <= 0xFFFF && !admin.contains('.') {
            let value = value.parse().map_err(|_| err())?;
            Ok(AdminValue::As2 {
                asn: asn.0 as u16,
                value,
            })
        } else {
            let value = value.parse().map_err(|_| err())?;
            Ok(AdminValue::As4 { asn: asn.0, value })
        }
    }
}

/// A route distinguisher.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteDistinguisher(pub AdminValue);

/// The key of a route: the family, the route distinguisher of an EVPN
/// route and the prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteKey {
    pub family: Family,
    pub rd: Option<RouteDistinguisher>,
    pub prefix: Prefix,
}

impl RouteKey {
    /// The unicast key of a prefix, IPv4 or IPv6 by the prefix.
    pub fn unicast(prefix: Prefix) -> RouteKey {
        let family = if prefix.is_ipv4() {
            Family::Ipv4Unicast
        } else {
            Family::Ipv6Unicast
        };
        RouteKey {
            family,
            rd: None,
            prefix,
        }
    }

    /// The key of an EVPN IP prefix route.
    pub fn evpn_ip_prefix(rd: RouteDistinguisher, prefix: Prefix) -> RouteKey {
        RouteKey {
            family: Family::EvpnIpPrefix,
            rd: Some(rd),
            prefix,
        }
    }
}

/// A standard community of RFC 1997, as the 32-bit value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Community(pub u32);

impl Community {
    pub const NO_EXPORT: Community = Community(0xFFFF_FF01);
    pub const NO_ADVERTISE: Community = Community(0xFFFF_FF02);
    pub const NO_EXPORT_SUBCONFED: Community = Community(0xFFFF_FF03);

    pub fn new(high: u16, low: u16) -> Community {
        Community((u32::from(high) << 16) | u32::from(low))
    }
}

impl fmt::Display for Community {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.0 >> 16, self.0 & 0xFFFF)
    }
}

impl FromStr for Community {
    type Err = ParseAsnError;

    /// Reads `high:low`, a 32-bit number, or the names `no-export`,
    /// `no-advertise`, `local-as` and `no-export-subconfed`.
    fn from_str(s: &str) -> Result<Community, ParseAsnError> {
        let err = || ParseAsnError(s.to_string());
        match s.to_ascii_lowercase().as_str() {
            "no-export" => return Ok(Community::NO_EXPORT),
            "no-advertise" => return Ok(Community::NO_ADVERTISE),
            "local-as" | "no-export-subconfed" => return Ok(Community::NO_EXPORT_SUBCONFED),
            _ => {}
        }
        match s.split_once(':') {
            Some((high, low)) => Ok(Community::new(
                high.parse().map_err(|_| err())?,
                low.parse().map_err(|_| err())?,
            )),
            None => s.parse().map(Community).map_err(|_| err()),
        }
    }
}

/// An extended community of RFC 4360.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExtCommunity {
    RouteTarget(AdminValue),
    /// Another extended community as its 8 bytes.
    Other(u64),
}

/// A large community of RFC 8092.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LargeCommunity(pub u32, pub u32, pub u32);

/// The type of an AS path segment (RFC 4271 4.3, RFC 5065 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SegmentKind {
    Sequence,
    Set,
    ConfedSequence,
    ConfedSet,
}

/// One segment of an AS path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AsSegment {
    pub kind: SegmentKind,
    pub asns: Vec<Asn>,
}

/// The neighbour AS of a path for the MED step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NeighbourAs {
    /// The path has no AS outside the confederation segments: it comes from
    /// the local AS.
    Local,
    /// The first AS of the first AS_SEQUENCE after the confederation
    /// segments.
    As(Asn),
    /// The first segment after the confederation segments is an AS_SET.
    /// The MED of such a path compares with no other path.
    Set,
}

/// An AS path as its segments, the leftmost segment first.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AsPath {
    pub segments: Vec<AsSegment>,
}

impl AsPath {
    /// A path of one AS_SEQUENCE. An empty list gives the empty path.
    pub fn sequence(asns: &[u32]) -> AsPath {
        if asns.is_empty() {
            return AsPath::default();
        }
        AsPath {
            segments: vec![AsSegment {
                kind: SegmentKind::Sequence,
                asns: asns.iter().map(|&a| Asn(a)).collect(),
            }],
        }
    }

    /// The length for the decision (RFC 4271 9.1.2.2 a, RFC 5065 5.3): each
    /// AS of an AS_SEQUENCE counts 1, an AS_SET counts 1, and the
    /// confederation segments count 0.
    #[allow(
        clippy::len_without_is_empty,
        reason = "the decision length of a path, not a container size"
    )]
    pub fn len(&self) -> u32 {
        self.segments
            .iter()
            .map(|s| match s.kind {
                SegmentKind::Sequence => s.asns.len() as u32,
                SegmentKind::Set => u32::from(!s.asns.is_empty()),
                SegmentKind::ConfedSequence | SegmentKind::ConfedSet => 0,
            })
            .sum()
    }

    /// The neighbour AS for the MED step.
    pub fn neighbour_as(&self) -> NeighbourAs {
        let first = self.segments.iter().find(|s| {
            matches!(s.kind, SegmentKind::Sequence | SegmentKind::Set) && !s.asns.is_empty()
        });
        match first {
            None => NeighbourAs::Local,
            Some(s) if s.kind == SegmentKind::Sequence => NeighbourAs::As(s.asns[0]),
            Some(_) => NeighbourAs::Set,
        }
    }

    /// Each AS of each segment, leftmost first.
    pub fn flat(&self) -> Vec<Asn> {
        self.segments
            .iter()
            .flat_map(|s| s.asns.iter().copied())
            .collect()
    }

    /// True if an AS of any segment is `asn`.
    pub fn contains(&self, asn: Asn) -> bool {
        self.segments.iter().any(|s| s.asns.contains(&asn))
    }

    /// The path with the confederation segments removed.
    pub fn without_confed(&self) -> AsPath {
        AsPath {
            segments: self
                .segments
                .iter()
                .filter(|s| matches!(s.kind, SegmentKind::Sequence | SegmentKind::Set))
                .cloned()
                .collect(),
        }
    }

    /// The path with `asn` before it, in the first AS_CONFED_SEQUENCE.
    pub fn prepend_confed(&self, asn: Asn) -> AsPath {
        let mut out = self.clone();
        match out.segments.first_mut() {
            Some(s) if s.kind == SegmentKind::ConfedSequence => s.asns.insert(0, asn),
            _ => out.segments.insert(
                0,
                AsSegment {
                    kind: SegmentKind::ConfedSequence,
                    asns: vec![asn],
                },
            ),
        }
        out
    }

    /// The path with `asns` before it, in the first AS_SEQUENCE.
    pub fn prepend(&self, asns: &[Asn]) -> AsPath {
        let mut out = self.clone();
        if asns.is_empty() {
            return out;
        }
        match out.segments.first_mut() {
            Some(s) if s.kind == SegmentKind::Sequence => {
                let mut v = asns.to_vec();
                v.extend_from_slice(&s.asns);
                s.asns = v;
            }
            _ => out.segments.insert(
                0,
                AsSegment {
                    kind: SegmentKind::Sequence,
                    asns: asns.to_vec(),
                },
            ),
        }
        out
    }
}

impl fmt::Display for AsPath {
    /// The text form that the AS-path patterns match: the segments joined
    /// by a space, an AS_SEQUENCE as `1 2`, an AS_SET as `{1,2}`, an
    /// AS_CONFED_SEQUENCE as `(1 2)` and an AS_CONFED_SET as `[1,2]`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, s) in self.segments.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            let (open, sep, close) = match s.kind {
                SegmentKind::Sequence => ("", " ", ""),
                SegmentKind::Set => ("{", ",", "}"),
                SegmentKind::ConfedSequence => ("(", " ", ")"),
                SegmentKind::ConfedSet => ("[", ",", "]"),
            };
            f.write_str(open)?;
            for (j, a) in s.asns.iter().enumerate() {
                if j > 0 {
                    f.write_str(sep)?;
                }
                write!(f, "{a}")?;
            }
            f.write_str(close)?;
        }
        Ok(())
    }
}

/// The ORIGIN attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BgpOrigin {
    Igp,
    Egp,
    Incomplete,
}

/// The form of a local origination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LocalOrigin {
    Network,
    Redistribute,
    Aggregate,
}

/// The kind of the session that a path came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SessionKind {
    Ebgp,
    Ibgp,
    /// A session to a peer in another member AS of the confederation.
    ConfedEbgp,
    /// The device originates the path.
    Local(LocalOrigin),
}

impl SessionKind {
    /// True for an iBGP or a confederation eBGP session: the decision
    /// ranks both as internal.
    pub fn is_internal(self) -> bool {
        matches!(self, SessionKind::Ibgp | SessionKind::ConfedEbgp)
    }
}

/// The peer that a path came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Peer {
    /// The address of the peer. A local origination has none.
    pub address: Option<IpAddr>,
    pub router_id: Ipv4Addr,
    pub asn: Asn,
    pub kind: SessionKind,
}

/// One path of a route with its attributes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BgpPath {
    pub next_hop: Option<IpAddr>,
    pub as_path: AsPath,
    pub origin: BgpOrigin,
    pub med: Option<u32>,
    /// `None` takes the default local preference of the process.
    pub local_pref: Option<u32>,
    pub weight: u32,
    pub communities: BTreeSet<Community>,
    pub ext_communities: BTreeSet<ExtCommunity>,
    pub large_communities: BTreeSet<LargeCommunity>,
    pub originator_id: Option<Ipv4Addr>,
    pub cluster_list: Vec<Ipv4Addr>,
    pub peer: Peer,
    /// The IGP cost to the next hop. 0 for a local origination and for a
    /// next hop on a connected subnet.
    pub igp_cost: u32,
    pub tag: Option<u32>,
    /// False for a seed path whose attributes other than the prefix, the
    /// next hop and the peer are not collected.
    pub attributes_collected: bool,
    pub spans: Vec<SourceSpan>,
}

impl BgpPath {
    /// A path from `peer` with the origin IGP, no optional attribute and
    /// collected attributes.
    pub fn new(peer: Peer, next_hop: Option<IpAddr>, as_path: AsPath) -> BgpPath {
        BgpPath {
            next_hop,
            as_path,
            origin: BgpOrigin::Igp,
            med: None,
            local_pref: None,
            weight: 0,
            communities: BTreeSet::new(),
            ext_communities: BTreeSet::new(),
            large_communities: BTreeSet::new(),
            originator_id: None,
            cluster_list: Vec::new(),
            peer,
            igp_cost: 0,
            tag: None,
            attributes_collected: true,
            spans: Vec::new(),
        }
    }

    /// The route targets of the extended communities.
    pub fn route_targets(&self) -> impl Iterator<Item = AdminValue> + '_ {
        self.ext_communities.iter().filter_map(|c| match c {
            ExtCommunity::RouteTarget(v) => Some(*v),
            ExtCommunity::Other(_) => None,
        })
    }
}

/// The reason of an unknown BGP result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reason {
    /// A policy clause with an unhandled construct decides the result.
    PolicyClauseNotEvaluated,
    /// The platform of the device has no BGP profile.
    NoBgpProfile,
    /// The decision compares a path whose attributes are not collected.
    PathAttributesNotCollected,
    /// The address families of a neighbour depend on a default that the
    /// profile does not hold.
    AddressFamilyNotKnown,
    /// The IGP view does not know the resolution of a next hop.
    NextHopNotResolved,
    /// The IGP view does not know whether the route of a `network`
    /// statement is present.
    OriginationNotKnown,
    /// A selection that a path depends on is not known: an unknown
    /// selection of the search, or an unknown summary-only aggregate.
    SelectionNotKnown,
    /// The prefix group has more than one stable outcome.
    MultipleStableOutcomes,
    /// The prefix group has no stable outcome.
    NoConvergence,
    /// The calculation reaches a state that its invariants exclude.
    Internal,
}

impl Reason {
    pub fn text(self) -> &'static str {
        match self {
            Reason::PolicyClauseNotEvaluated => "policy clause not evaluated",
            Reason::NoBgpProfile => "no bgp profile",
            Reason::PathAttributesNotCollected => "path attributes not collected",
            Reason::AddressFamilyNotKnown => "address family not known",
            Reason::NextHopNotResolved => "next hop not resolved",
            Reason::OriginationNotKnown => "origination not known",
            Reason::SelectionNotKnown => "selection not known",
            Reason::MultipleStableOutcomes => "multiple stable outcomes",
            Reason::NoConvergence => "no convergence",
            Reason::Internal => "internal error",
        }
    }
}

/// An unknown BGP result with its reason and the constructs that cause it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Unknown {
    pub reason: Reason,
    /// The constructs or paths that cause the result, in a fixed order.
    pub details: BTreeSet<String>,
}

impl Unknown {
    pub fn new(reason: Reason, detail: impl Into<String>) -> Unknown {
        Unknown {
            reason,
            details: BTreeSet::from([detail.into()]),
        }
    }
}

impl fmt::Display for Unknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason.text())?;
        for (i, d) in self.details.iter().enumerate() {
            f.write_str(if i == 0 { ": " } else { "; " })?;
            f.write_str(d)?;
        }
        Ok(())
    }
}
