//! The OSPF config of a router in one form for all vendors. The vendor
//! readers of `rsim-ingest` fill it, and [`super::build`] makes the
//! link-state database of the twin from the configs of its routers.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::SourceSpan;

use super::{AreaId, AreaType, RouterId, Version};

/// The OSPF processes of one router.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouterConfig {
    pub processes: Vec<Process>,
}

/// One OSPF process in one VRF and one version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Process {
    pub version: Version,
    pub vrf: String,
    /// The process name or number of the config, for example `1` or
    /// `UNDERLAY`.
    pub process: String,
    /// The router ID of the config. `None` if the config states none.
    pub router_id: Option<RouterId>,
    /// The `auto-cost reference-bandwidth` of the config in Mb/s. `None`
    /// takes the default of the platform.
    pub reference_bandwidth_mbps: Option<u32>,
    pub areas: BTreeMap<AreaId, Area>,
    pub interfaces: Vec<OspfInterface>,
    pub redistribute: Vec<Redistribute>,
    pub default_originate: Option<DefaultOriginate>,
    /// True if each interface is passive unless the config makes it active
    /// (`passive-interface default`).
    pub passive_default: bool,
    /// The lines of the process that the reader does not handle. One such
    /// line makes the LSAs of the router unknown.
    pub unhandled: Vec<(String, SourceSpan)>,
    pub span: SourceSpan,
}

/// The settings of one area of a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Area {
    pub kind: AreaType,
    /// True for `no-summary`: a totally stubby area or NSSA.
    pub no_summary: bool,
    /// The cost of the default route into a stub area or NSSA.
    pub default_cost: Option<u32>,
    pub span: SourceSpan,
}

/// The network type of an OSPF interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkType {
    Broadcast,
    PointToPoint,
    /// A loopback: a stub link of its host address.
    Loopback,
}

/// One interface of a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OspfInterface {
    pub name: String,
    pub area: AreaId,
    /// The address and the prefix length of the interface.
    pub address: Option<(IpAddr, u8)>,
    /// The secondary addresses with their prefix lengths. The router
    /// advertises the network of each one as a stub network of the
    /// interface.
    pub secondaries: Vec<(IpAddr, u8)>,
    /// The cost of the config. `None` takes the reference bandwidth over
    /// `bandwidth_kbps`.
    pub cost: Option<u32>,
    /// The bandwidth of the interface in kb/s: the `bandwidth` of the
    /// config, else the speed of the interface.
    pub bandwidth_kbps: Option<u64>,
    /// The network type of the config, else the default of the interface
    /// kind.
    pub network: NetworkType,
    pub passive: bool,
    /// The priority of the interface for the election of the designated
    /// router, 1 if the config states none.
    pub priority: u8,
    /// True if the interface is administratively up.
    pub up: bool,
    pub span: SourceSpan,
}

/// The source of a redistribution into OSPF.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    Connected,
    Static,
    Bgp,
    /// Another source, by its word in the config.
    Other(String),
}

/// One `redistribute` statement of a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redistribute {
    pub source: Source,
    /// The metric of the statement, else the default of the platform.
    pub metric: Option<u32>,
    /// The external metric type, 1 or 2. `None` takes type 2.
    pub metric_type: Option<u8>,
    /// The name of the route-map. A route-map makes the statement unknown.
    pub route_map: Option<String>,
    pub span: SourceSpan,
}

/// The `default-information originate` statement of a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultOriginate {
    /// True for `always`: the router originates the default route also with
    /// no default route in its own table.
    pub always: bool,
    pub metric: Option<u32>,
    pub metric_type: Option<u8>,
    pub route_map: Option<String>,
    pub span: SourceSpan,
}
