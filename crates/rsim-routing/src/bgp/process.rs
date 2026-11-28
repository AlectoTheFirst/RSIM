//! The BGP process of one device and VRF.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use rsim_core::SourceSpan;

use super::lists::{AsPathList, CommunityList, PrefixList};
use super::policy::RoutePolicy;
use super::profile::BgpProfile;
use super::{Asn, Family, RouteKey, SessionKind};
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
    pub router_id: Ipv4Addr,
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
        router_id: Ipv4Addr,
    ) -> BgpProcess {
        BgpProcess {
            device: device.into(),
            vrf: vrf.into(),
            platform,
            asn,
            router_id,
            cluster_id: None,
            confederation_id: None,
            confederation_peers: BTreeSet::new(),
            options: BgpOptions::default(),
            neighbors: BTreeMap::new(),
            networks: Vec::new(),
            aggregates: Vec::new(),
            policy: PolicySet::default(),
            spans: Vec::new(),
        }
    }

    /// The BGP profile of the platform, `None` for no profile.
    pub fn profile(&self) -> Option<BgpProfile> {
        self.platform.map(BgpProfile::of)
    }

    /// The cluster ID: the configured one or the router ID.
    pub fn cluster_id(&self) -> Ipv4Addr {
        self.cluster_id.unwrap_or(self.router_id)
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
