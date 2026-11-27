//! OSPF: the link-state databases of a device and the OSPF routes that a
//! router computes from its database.
//!
//! [`compute`] follows RFC 2328 section 16 with the RFC 3101 changes for
//! NSSA areas for OSPFv2, and RFC 5340 for OSPFv3 with the same
//! shortest-path code. The calculation is a port of HST `simul/ospf.py`.
//! The order is fixed: LSAs by area, type, link-state ID and advertising
//! router, candidates by cost, vertex kind and ID, routes by prefix and
//! next hops by gateway and interface.

mod change;
pub mod config;
mod spf;

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rsim_core::{Prefix, SourceSpan};

use crate::platform::{Origin, Platform};

pub use spf::{compute, mask_len};

/// A router ID.
pub type RouterId = Ipv4Addr;
/// An area ID in its dotted form.
pub type AreaId = Ipv4Addr;

/// The backbone area.
pub const BACKBONE: AreaId = Ipv4Addr::UNSPECIFIED;
/// The metric that means "unreachable" (RFC 2328 A.4.4 and A.4.5).
pub const LS_INFINITY: u32 = 0xFF_FFFF;
/// An LSA at this age is flushed and is not used (RFC 2328 appendix B).
pub const MAX_AGE: u32 = 3600;
/// The highest metric of a link (RFC 2328 A.4.2).
pub const MAX_LINK_COST: u32 = 65_535;

/// The OSPF version: OSPFv2 for IPv4, OSPFv3 for IPv6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Version {
    V2,
    V3,
}

impl Version {
    pub fn name(self) -> &'static str {
        match self {
            Version::V2 => "ospfv2",
            Version::V3 => "ospfv3",
        }
    }
}

/// The type of an LSA. The OSPFv3 types share the variants of the OSPFv2
/// types with the same role: `Summary` is the inter-area-prefix LSA,
/// `AsbrSummary` the inter-area-router LSA, `External` the AS-external LSA
/// and `NssaExternal` the NSSA LSA. `Link` and `IntraAreaPrefix` are OSPFv3
/// only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LsaType {
    Router,
    Network,
    Summary,
    AsbrSummary,
    External,
    NssaExternal,
    Link,
    IntraAreaPrefix,
}

impl LsaType {
    /// The name of the type in a version.
    pub fn name(self, version: Version) -> &'static str {
        match (self, version) {
            (LsaType::Router, _) => "router",
            (LsaType::Network, _) => "network",
            (LsaType::Summary, Version::V2) => "summary",
            (LsaType::Summary, Version::V3) => "inter-area-prefix",
            (LsaType::AsbrSummary, Version::V2) => "asbr-summary",
            (LsaType::AsbrSummary, Version::V3) => "inter-area-router",
            (LsaType::External, Version::V2) => "external",
            (LsaType::External, Version::V3) => "as-external",
            (LsaType::NssaExternal, Version::V2) => "nssa-external",
            (LsaType::NssaExternal, Version::V3) => "nssa",
            (LsaType::Link, _) => "link",
            (LsaType::IntraAreaPrefix, _) => "intra-area-prefix",
        }
    }

    /// True for a type that the database holds in one area. An AS-external
    /// LSA is flooded in the whole domain and has no area.
    pub fn area_scoped(self) -> bool {
        self != LsaType::External
    }
}

/// The type of a link of a router LSA (RFC 2328 A.4.2, RFC 5340 A.4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LinkKind {
    PointToPoint,
    Transit,
    /// An OSPFv2 stub link. OSPFv3 has no stub link.
    Stub,
    Virtual,
}

impl LinkKind {
    pub fn name(self) -> &'static str {
        match self {
            LinkKind::PointToPoint => "point-to-point",
            LinkKind::Transit => "transit",
            LinkKind::Stub => "stub",
            LinkKind::Virtual => "virtual",
        }
    }
}

/// One link of a router LSA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterLink {
    pub kind: LinkKind,
    /// OSPFv2: the link ID, the neighbour router ID, the address of the
    /// designated router or the stub network. OSPFv3: the neighbour router
    /// ID, which is the designated router for a transit link.
    pub id: Ipv4Addr,
    /// OSPFv2: the link data, the interface address of the router, or the
    /// mask of a stub link. OSPFv3: none.
    pub data: Option<Ipv4Addr>,
    pub metric: u32,
    /// OSPFv3: the interface ID of the router.
    pub interface_id: Option<u32>,
    /// OSPFv3: the interface ID of the neighbour, of the designated router
    /// for a transit link.
    pub neighbor_interface_id: Option<u32>,
}

/// The LSA that an OSPFv3 intra-area-prefix LSA refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reference {
    /// The router LSAs of the referenced router.
    Router,
    /// The network LSA of the referenced router, with its link-state ID,
    /// the interface ID of the designated router.
    Network(u32),
}

/// The body of an LSA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Router {
        links: Vec<RouterLink>,
    },
    /// OSPFv2 has the mask. OSPFv3 has none: its prefixes are in the
    /// intra-area-prefix LSAs.
    Network {
        mask: Option<Ipv4Addr>,
        attached: Vec<RouterId>,
    },
    /// The OSPFv2 summary LSA and the OSPFv3 inter-area-prefix LSA.
    Summary {
        prefix: Prefix,
        metric: u32,
    },
    /// The OSPFv2 ASBR-summary LSA, whose link-state ID is the router, and
    /// the OSPFv3 inter-area-router LSA.
    AsbrSummary {
        router: RouterId,
        metric: u32,
    },
    /// The AS-external LSA and the NSSA LSA. `metric_type` is 1 or 2, the E
    /// bit. A zero forwarding address is no forwarding address.
    External {
        prefix: Prefix,
        metric: u32,
        metric_type: Option<u8>,
        forwarding: Option<IpAddr>,
    },
    /// The OSPFv3 link LSA: the link-local address of the advertising router
    /// on the link, its prefixes on the link and the interface of the
    /// calculating router on which the database lists the LSA.
    Link {
        address: Option<Ipv6Addr>,
        prefixes: Vec<Prefix>,
        interface: Option<String>,
    },
    /// The OSPFv3 intra-area-prefix LSA: the referenced LSA and its
    /// advertising router, and each prefix with its metric.
    IntraAreaPrefix {
        reference: Reference,
        router: RouterId,
        prefixes: Vec<(Prefix, u32)>,
    },
}

/// One LSA with the span of its lines in the collected section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lsa {
    pub lsa_type: LsaType,
    /// `None` for an AS-external LSA.
    pub area: Option<AreaId>,
    /// The link-state ID. An OSPFv3 link-state ID is a number, held in the
    /// same 32 bits.
    pub lsid: Ipv4Addr,
    pub adv_router: RouterId,
    pub seq: Option<u32>,
    pub age: Option<u32>,
    pub body: Body,
    pub span: SourceSpan,
}

impl Lsa {
    /// The key of the LSA in its database.
    pub fn key(&self) -> LsaKey {
        LsaKey {
            no_area: self.area.is_none(),
            area: self.area.unwrap_or(BACKBONE),
            lsa_type: self.lsa_type,
            lsid: self.lsid,
            adv_router: self.adv_router,
        }
    }

    /// True for an LSA at the maximum age.
    pub fn expired(&self) -> bool {
        self.age.is_some_and(|a| a >= MAX_AGE)
    }

    /// The text of the LSA for a note or a gap.
    pub fn describe(&self, version: Version) -> String {
        let area = self
            .area
            .map(|a| format!(" in area {a}"))
            .unwrap_or_default();
        format!(
            "{} LSA {} from {}{area}",
            self.lsa_type.name(version),
            self.lsid,
            self.adv_router
        )
    }

    /// True if this LSA is a newer instance than `other` (RFC 2328 13.1):
    /// the higher sequence number, then the lower age.
    pub fn fresher(&self, other: &Lsa) -> bool {
        let rank = |l: &Lsa| (l.seq.map_or(-1, i64::from), -i64::from(l.age.unwrap_or(0)));
        rank(self) > rank(other)
    }
}

/// The key of an LSA: the area with the area-free LSAs last, the type, the
/// link-state ID and the advertising router.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LsaKey {
    pub no_area: bool,
    pub area: AreaId,
    pub lsa_type: LsaType,
    pub lsid: Ipv4Addr,
    pub adv_router: RouterId,
}

/// The type of an area.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AreaType {
    Normal,
    Stub,
    Nssa,
}

/// An OSPF interface of the calculating router.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub area: Option<AreaId>,
    /// The address and the prefix length. OSPFv3 gives the link-local
    /// address with no length.
    pub address: Option<(IpAddr, Option<u8>)>,
    /// The OSPFv3 interface ID.
    pub interface_id: Option<u32>,
    pub cost: Option<u32>,
    pub span: SourceSpan,
}

/// An OSPF neighbour of the calculating router.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbor {
    pub router_id: RouterId,
    pub address: Option<IpAddr>,
    pub interface: Option<String>,
    /// The state word, such as `FULL`.
    pub state: Option<String>,
    pub span: SourceSpan,
}

/// A fact of a database or of a calculation that a reader or the
/// calculation reports: an LSA that is not read, a virtual link that is
/// not computed, a next hop that is not certain.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Note {
    /// The kind, for example `ospf-virtual-link-not-modeled`.
    pub kind: String,
    pub subject: String,
    pub detail: String,
}

impl Note {
    pub fn new(kind: &str, subject: impl Into<String>, detail: impl Into<String>) -> Note {
        Note {
            kind: kind.to_string(),
            subject: subject.into(),
            detail: detail.into(),
        }
    }
}

/// The link-state database of one OSPF process of a device, in one VRF and
/// one version. The database is immutable for a calculation, and each
/// change gives a new database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Database {
    pub version: Version,
    pub vrf: String,
    pub process: String,
    /// The router ID of the process, the root of the calculation.
    pub router_id: Option<RouterId>,
    /// The area types that the process states. An area that holds an NSSA
    /// LSA is an NSSA.
    pub area_types: BTreeMap<AreaId, AreaType>,
    pub interfaces: Vec<Interface>,
    pub neighbors: Vec<Neighbor>,
    pub lsas: BTreeMap<LsaKey, Lsa>,
    /// The facts of the read of the database.
    pub notes: Vec<Note>,
}

impl Database {
    pub fn new(version: Version, vrf: &str, process: &str) -> Database {
        Database {
            version,
            vrf: vrf.to_string(),
            process: process.to_string(),
            router_id: None,
            area_types: BTreeMap::new(),
            interfaces: Vec::new(),
            neighbors: Vec::new(),
            lsas: BTreeMap::new(),
            notes: Vec::new(),
        }
    }

    /// Adds an LSA. Of 2 instances of one LSA, the database keeps the newer
    /// (RFC 2328 13.1). An AS-external LSA has no area.
    pub fn insert(&mut self, mut lsa: Lsa) {
        if !lsa.lsa_type.area_scoped() {
            lsa.area = None;
        }
        let key = lsa.key();
        match self.lsas.get(&key) {
            Some(held) if !lsa.fresher(held) => {}
            _ => {
                self.lsas.insert(key, lsa);
            }
        }
    }

    /// The areas of the area-scoped LSAs, in order.
    pub fn areas(&self) -> Vec<AreaId> {
        let mut out: Vec<AreaId> = self.lsas.values().filter_map(|l| l.area).collect();
        out.sort();
        out.dedup();
        out
    }

    /// The type of an area: an NSSA if it holds an NSSA LSA, else the
    /// stated type, else normal.
    pub fn area_type(&self, area: AreaId) -> AreaType {
        if self
            .lsas
            .values()
            .any(|l| l.area == Some(area) && l.lsa_type == LsaType::NssaExternal)
        {
            return AreaType::Nssa;
        }
        self.area_types
            .get(&area)
            .copied()
            .unwrap_or(AreaType::Normal)
    }
}

/// The OSPF defaults of a platform, from HST `simul/platforms.py`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OspfProfile {
    pub platform: Platform,
    /// True: the external route preference is the cost rule of RFC 1583.
    /// False: RFC 2328 section 16.4.1, where an intra-area path to the ASBR
    /// through an area other than the backbone ranks first.
    pub rfc1583_compatible: bool,
    /// The default `auto-cost reference-bandwidth`.
    pub reference_bandwidth_mbps: u32,
    /// True if the interface cost rounds the quotient, false if it
    /// truncates it.
    pub cost_rounds: bool,
}

impl OspfProfile {
    /// The OSPF defaults of a platform.
    pub fn of(platform: Platform) -> OspfProfile {
        let (rfc1583_compatible, reference_bandwidth_mbps, cost_rounds) = match platform {
            Platform::Iosxe => (true, 100, false),
            Platform::Iosxr => (false, 100, false),
            Platform::Nxos => (false, 40_000, false),
            Platform::FrrTraditional | Platform::FrrDatacenter => (false, 100, true),
        };
        OspfProfile {
            platform,
            rfc1583_compatible,
            reference_bandwidth_mbps,
            cost_rounds,
        }
    }

    /// The administrative distance of an OSPF route.
    pub fn distance(&self) -> u8 {
        self.platform.distance(Origin::Ospf)
    }

    /// The cost of an interface with no configured cost: the reference
    /// bandwidth over the interface bandwidth, in 1 to [`MAX_LINK_COST`].
    pub fn interface_cost(&self, bandwidth_kbps: u64) -> u32 {
        if bandwidth_kbps == 0 {
            return MAX_LINK_COST;
        }
        let reference = u64::from(self.reference_bandwidth_mbps) * 1000;
        let cost = if self.cost_rounds {
            (2 * reference + bandwidth_kbps) / (2 * bandwidth_kbps)
        } else {
            reference / bandwidth_kbps
        };
        cost.clamp(1, u64::from(MAX_LINK_COST)) as u32
    }
}

/// The path type of an OSPF route, in the order of preference (RFC 2328
/// section 11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathType {
    IntraArea,
    InterArea,
    External1,
    External2,
}

impl PathType {
    pub fn name(self) -> &'static str {
        match self {
            PathType::IntraArea => "intra-area",
            PathType::InterArea => "inter-area",
            PathType::External1 => "external-1",
            PathType::External2 => "external-2",
        }
    }
}

/// A next hop of an OSPF route: the address of the neighbour, a link-local
/// address for OSPFv3, and the interface of the calculating router when the
/// database gives it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NextHop {
    pub gateway: IpAddr,
    pub interface: Option<String>,
}

impl fmt::Display for NextHop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.interface {
            Some(i) => write!(f, "{} on {i}", self.gateway),
            None => write!(f, "{}", self.gateway),
        }
    }
}

/// One route that the OSPF process offers the main route table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub prefix: Prefix,
    pub path_type: PathType,
    /// The total cost for an intra-area, inter-area or type 1 external
    /// path, and the metric of the LSA for a type 2 external path.
    pub metric: u32,
    /// The internal distance of an external path.
    pub forward_metric: Option<u32>,
    pub area: Option<AreaId>,
    pub advertising_router: Option<RouterId>,
    pub lsa_type: Option<LsaType>,
    pub next_hops: Vec<NextHop>,
    /// The spans of the LSAs that give the prefix.
    pub spans: Vec<SourceSpan>,
    /// The reason when the route depends on a gap of the database. A cheaper
    /// path or a path of a better type can pass through the LSA that the
    /// database lacks.
    pub unknown: Option<String>,
}

/// The routes that a gap makes unknown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GapReach {
    /// Each route. The database has no router LSA of the calculating
    /// router.
    All,
    /// The intra-area routes with a cost of at least the bound, and each
    /// inter-area and external route. The gap is a vertex of the shortest
    /// path tree, and the bound is the cost at which the tree meets it. For
    /// a virtual link of the calculating router, the bound is the cost of
    /// the link.
    FromCost(u32),
    /// The inter-area and external routes of the prefixes, and the
    /// prefixes with no route.
    Prefixes(Vec<Prefix>),
}

/// An LSA that the calculation needs and that the database does not hold,
/// or a virtual link of the calculating router. The calculation does not
/// compute a virtual link of the calculating router, and the gap of the link
/// is on the router LSA of the calculating router in the backbone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gap {
    pub lsa_type: LsaType,
    pub lsid: Ipv4Addr,
    pub area: Option<AreaId>,
    pub detail: String,
    pub reach: GapReach,
}

/// The result of the calculation of one router over one database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Calculation {
    pub router_id: RouterId,
    pub version: Version,
    pub routes: Vec<Route>,
    /// The cost to each router that the calculation places, by area and
    /// router ID.
    pub router_costs: BTreeMap<(AreaId, RouterId), u32>,
    pub gaps: Vec<Gap>,
    pub notes: Vec<Note>,
    pub area_border_router: bool,
}

impl Calculation {
    /// The route of a prefix.
    pub fn route(&self, prefix: Prefix) -> Option<&Route> {
        self.routes
            .binary_search_by(|r| r.prefix.cmp(&prefix))
            .ok()
            .map(|i| &self.routes[i])
    }

    /// The gap that makes a prefix with no route unknown: a gap of the
    /// shortest path tree, the missing router LSA of the calculating
    /// router, or a gap of that prefix.
    pub fn absent_gap(&self, prefix: Prefix) -> Option<&Gap> {
        self.gaps.iter().find(|g| match &g.reach {
            GapReach::All | GapReach::FromCost(_) => true,
            GapReach::Prefixes(p) => p.contains(&prefix),
        })
    }
}
