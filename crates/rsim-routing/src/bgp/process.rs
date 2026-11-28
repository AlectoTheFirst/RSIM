//! The BGP process of one device and VRF.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use rsim_core::SourceSpan;

use super::lists::{AsPathList, CommunityList, PrefixList};
use super::policy::RoutePolicy;
use super::profile::BgpProfile;
use super::{AdminValue, Asn, Family, RouteDistinguisher, RouteKey, SessionKind};
use crate::platform::Platform;

/// The options of a process that change the decision and the policy
/// defaults. `None` takes the default of the profile.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BgpOptions {
    /// `bgp always-compare-med`, `bestpath med always` on IOS-XR.
    pub always_compare_med: bool,
    /// `bgp deterministic-med`. NX-OS `bestpath med non-deterministic`
    /// gives `Some(false)`.
    pub deterministic_med: Option<bool>,
    /// `bgp bestpath med missing-as-worst`.
    pub missing_as_worst: Option<bool>,
    /// `bgp bestpath compare-routerid`.
    pub compare_routerid: bool,
    /// `bgp bestpath as-path multipath-relax`: a multipath needs an AS path
    /// of the same length, and not the same AS path.
    pub multipath_relax: bool,
    /// `maximum-paths` for the eBGP paths.
    pub maximum_paths_ebgp: Option<u32>,
    /// `maximum-paths ibgp`.
    pub maximum_paths_ibgp: Option<u32>,
    /// `bgp ebgp-requires-policy` of FRR.
    pub ebgp_requires_policy: Option<bool>,
    /// `bgp default local-preference`.
    pub default_local_pref: Option<u32>,
    /// `bgp default ipv4-unicast`. `Some(false)` for `no bgp default
    /// ipv4-unicast`.
    pub default_ipv4_unicast: Option<bool>,
    /// `bgp network import-check` of FRR. `Some(false)` originates a
    /// `network` statement with no route of its prefix. `None` and
    /// `Some(true)` originate it only with that route.
    pub network_import_check: Option<bool>,
}

/// The `local-as` of a neighbour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalAs {
    pub asn: Asn,
    pub no_prepend: bool,
    pub replace_as: bool,
    pub dual_as: bool,
}

/// The `next-hop-self` of a neighbour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NextHopSelf {
    #[default]
    Off,
    /// `next-hop-self`: the routes that are not reflected.
    On,
    /// `next-hop-self all` or `force`: each route.
    All,
}

/// One neighbour of a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbor {
    pub address: IpAddr,
    /// The local address of the session, from `update-source` or the
    /// interface.
    pub local_address: Option<IpAddr>,
    pub remote_as: Asn,
    pub local_as: Option<LocalAs>,
    pub route_reflector_client: bool,
    pub next_hop_self: NextHopSelf,
    pub send_community: bool,
    pub send_community_extended: bool,
    pub remove_private_as: bool,
    /// The name of the import policy.
    pub import_policy: Option<String>,
    /// The name of the export policy.
    pub export_policy: Option<String>,
    /// The families that the config activates.
    pub activated: BTreeSet<Family>,
    /// The families that the config deactivates (`no neighbor activate`).
    pub deactivated: BTreeSet<Family>,
    pub shutdown: bool,
    pub spans: Vec<SourceSpan>,
}

impl Neighbor {
    /// A neighbour with no option.
    pub fn new(address: IpAddr, remote_as: Asn) -> Neighbor {
        Neighbor {
            address,
            local_address: None,
            remote_as,
            local_as: None,
            route_reflector_client: false,
            next_hop_self: NextHopSelf::Off,
            send_community: false,
            send_community_extended: false,
            remove_private_as: false,
            import_policy: None,
            export_policy: None,
            activated: BTreeSet::new(),
            deactivated: BTreeSet::new(),
            shutdown: false,
            spans: Vec::new(),
        }
    }
}

/// A `network` statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    pub key: RouteKey,
    /// The route-map of the statement.
    pub policy: Option<String>,
    pub spans: Vec<SourceSpan>,
}

/// An `aggregate-address` statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aggregate {
    pub key: RouteKey,
    pub summary_only: bool,
    pub as_set: bool,
    pub spans: Vec<SourceSpan>,
}

/// The source protocol of a `redistribute` statement into BGP.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RedistSource {
    Connected,
    Static,
    /// The OSPF process of the name, or each OSPF process of the VRF for
    /// `None`.
    Ospf(Option<String>),
}

/// The type of an OSPF route for a redistribution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OspfRouteType {
    /// An intra-area or an inter-area route.
    Internal,
    External1,
    External2,
    NssaExternal1,
    NssaExternal2,
}

/// A `redistribute` statement of a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redistribution {
    pub source: RedistSource,
    /// The OSPF route types of a `match` clause. `None` takes the default
    /// of the profile.
    pub ospf_match: Option<BTreeSet<OspfRouteType>>,
    /// The route-map or the route policy of the statement.
    pub policy: Option<String>,
    /// The metric of the statement. The redistributed path has it as its
    /// MED. With none, the MED is the metric of the route.
    pub metric: Option<u32>,
    pub spans: Vec<SourceSpan>,
}

/// The route distinguisher and the route targets of the VRF of a process.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VrfTargets {
    /// The route distinguisher of the EVPN IP prefix routes of the VRF.
    pub rd: Option<RouteDistinguisher>,
    /// The route targets that the VRF imports from the other VRFs of the
    /// device.
    pub import: BTreeSet<AdminValue>,
    /// The route targets of the unicast routes that the VRF exports to the
    /// other VRFs of the device.
    pub export: BTreeSet<AdminValue>,
    /// The route targets of the EVPN IP prefix routes that the VRF imports.
    pub evpn_import: BTreeSet<AdminValue>,
    /// The route targets of the EVPN IP prefix routes that the VRF exports.
    pub evpn_export: BTreeSet<AdminValue>,
    /// `advertise l2vpn evpn`: the unicast selections of the VRF are EVPN
    /// IP prefix routes of the process of the default VRF of the device.
    pub advertise_evpn: bool,
    /// The next hop of the EVPN IP prefix routes of the VRF: the address
    /// of the tunnel end of the device. `None` when it is not known.
    pub evpn_next_hop: Option<IpAddr>,
    pub spans: Vec<SourceSpan>,
}

/// The policies and lists of a process by name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicySet {
    pub policies: BTreeMap<String, RoutePolicy>,
    pub prefix_lists: BTreeMap<String, PrefixList>,
    pub community_lists: BTreeMap<String, CommunityList>,
    pub as_path_lists: BTreeMap<String, AsPathList>,
}

/// The BGP process of one device and VRF.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BgpProcess {
    pub device: String,
    pub vrf: String,
    /// The platform of the device. `None` for a platform with no BGP
    /// profile.
    pub platform: Option<Platform>,
    pub asn: Asn,
    /// `None` when the config states no router ID.
    pub router_id: Option<Ipv4Addr>,
    /// `None` takes the router ID (RFC 4456 7).
    pub cluster_id: Option<Ipv4Addr>,
    /// The confederation identifier.
    pub confederation_id: Option<Asn>,
    /// The other member ASs of the confederation.
    pub confederation_peers: BTreeSet<Asn>,
    pub options: BgpOptions,
    /// The neighbours by address.
    pub neighbors: BTreeMap<IpAddr, Neighbor>,
    pub networks: Vec<Network>,
    pub aggregates: Vec<Aggregate>,
    pub redistributions: Vec<Redistribution>,
    /// `default-information originate`: a redistribution can offer a
    /// default route.
    pub default_originate: bool,
    pub targets: VrfTargets,
    pub policy: PolicySet,
    pub spans: Vec<SourceSpan>,
}

impl BgpProcess {
    /// A process with no neighbour, origination or policy.
    pub fn new(
        device: impl Into<String>,
        vrf: impl Into<String>,
        platform: Option<Platform>,
        asn: Asn,
        router_id: impl Into<Option<Ipv4Addr>>,
    ) -> BgpProcess {
        BgpProcess {
            device: device.into(),
            vrf: vrf.into(),
            platform,
            asn,
            router_id: router_id.into(),
            cluster_id: None,
            confederation_id: None,
            confederation_peers: BTreeSet::new(),
            options: BgpOptions::default(),
            neighbors: BTreeMap::new(),
            networks: Vec::new(),
            aggregates: Vec::new(),
            redistributions: Vec::new(),
            default_originate: false,
            targets: VrfTargets::default(),
            policy: PolicySet::default(),
            spans: Vec::new(),
        }
    }

    /// The BGP profile of the platform, `None` for no profile.
    pub fn profile(&self) -> Option<BgpProfile> {
        self.platform.map(BgpProfile::of)
    }

    /// The cluster ID: the configured one or the router ID. `None` when
    /// neither is known.
    pub fn cluster_id(&self) -> Option<Ipv4Addr> {
        self.cluster_id.or(self.router_id)
    }

    /// The kind of the session to `n`. The session is iBGP when the remote
    /// AS is the `local-as` of the neighbour, or the AS of the process with
    /// no `local-as` or with `dual-as`. It is
    /// confederation eBGP when the remote AS is another member AS of the
    /// confederation, and eBGP otherwise.
    pub fn session_kind(&self, n: &Neighbor) -> SessionKind {
        let local = n.local_as.map_or(self.asn, |l| l.asn);
        if n.remote_as == local
            || (n.local_as.is_some_and(|l| l.dual_as) && n.remote_as == self.asn)
        {
            SessionKind::Ibgp
        } else if self.confederation_id.is_some() && self.confederation_peers.contains(&n.remote_as)
        {
            SessionKind::ConfedEbgp
        } else {
            SessionKind::Ebgp
        }
    }

    /// The families of the session to `n`: the activated families, and
    /// IPv4 unicast when it is active by default and not deactivated. `None`
    /// when that default decides and is not known for the platform.
    pub fn families(&self, n: &Neighbor) -> Option<BTreeSet<Family>> {
        let mut out = n.activated.clone();
        if out.contains(&Family::Ipv4Unicast) || n.deactivated.contains(&Family::Ipv4Unicast) {
            return Some(out);
        }
        let default = self
            .options
            .default_ipv4_unicast
            .or_else(|| self.profile().and_then(|p| p.default_ipv4_unicast))?;
        if default {
            out.insert(Family::Ipv4Unicast);
        }
        Some(out)
    }
}
