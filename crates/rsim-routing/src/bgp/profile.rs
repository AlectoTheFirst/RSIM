//! The BGP defaults of each platform.
//!
//! The sources of the values:
//! - FRR `bgpd/bgp_vty.c` gives deterministic MED on for the datacenter
//!   profile only, and `ebgp-requires-policy` on for the traditional profile
//!   only.
//! - FRR `bgpd/bgpd.c` `bgp_create` sets the maximum paths to the build value
//!   `multipath_num`.
//! - The FRR user guide gives the decision order, and states that only the
//!   IPv4 unicast family is enabled by default.
//! - Cisco document 13753, "BGP Best Path Selection Algorithm", gives the
//!   decision order, the MED 0 of a path with no MED unless
//!   missing-as-worst is set, and the rank of a local path from `network` or
//!   `redistribute` above a local aggregate.
//! - The NX-OS command references give `med non-deterministic` and `med
//!   missing-as-worst` as disabled by default.
//! - The other values are not confirmed against a device. These are the
//!   deterministic MED default of IOS-XE and IOS-XR, missing-as-worst on
//!   IOS-XR and FRR, the local weight 32768, the rank of a local aggregate on
//!   NX-OS and IOS-XR, the IPv4 unicast activation of NX-OS and IOS-XR, and
//!   the route that a later match reads. The eBGP rule with no policy of the
//!   Cisco platforms, the result of an undefined neighbour policy and the
//!   maximum paths of the Cisco platforms come from HST `simul/platforms.py`
//!   and `simul/bestpath.py`.
//! - The redistribution defaults come from HST `simul/platforms.py`: the
//!   result of an undefined route-map, the OSPF route types that
//!   `redistribute ospf` offers, and the default route that a
//!   redistribution leaves out. The default route rule of FRR is not
//!   known. The iBGP rule of a redistribution of BGP into an IGP comes from
//!   the IOS-XR, IOS-XE and NX-OS command references of `bgp
//!   redistribute-internal`. FRR offers the iBGP routes. These rules are
//!   not confirmed against a device.

use super::SessionKind;
use super::decision::DecisionStep;
use super::process::BgpOptions;
use crate::platform::{Origin, Platform};

/// The result of a neighbour policy name that no policy defines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UndefinedPolicy {
    /// Each route is denied.
    Deny,
    /// The rule of a neighbour with no policy applies.
    NoPolicy,
}

/// The route that a match term reads after an earlier set action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MatchReads {
    /// The route as it entered the policy.
    Input,
    /// The route with the set actions so far.
    Output,
}

/// The defaults of a `redistribute` statement of a platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RedistributeDefaults {
    /// True if a statement whose route-map is not defined redistributes
    /// each route. False if it redistributes none.
    pub undefined_permits: bool,
    /// True if `redistribute ospf` with no `match` clause offers only the
    /// intra-area and the inter-area routes.
    pub ospf_internal_only: bool,
    /// True if a redistribution into BGP leaves out a default route without
    /// `default-information originate`. `None` when it is not known.
    pub excludes_default: Option<bool>,
    /// True if a redistribution of BGP into an IGP offers the iBGP routes
    /// with no `bgp redistribute-internal`.
    pub ibgp_into_igp: bool,
}

/// The decision order of RFC 4271 9.1.2.2 with the vendor steps, the same
/// on IOS-XE, NX-OS, IOS-XR and FRR.
pub const DECISION_ORDER: &[DecisionStep] = &[
    DecisionStep::Weight,
    DecisionStep::LocalPreference,
    DecisionStep::LocallyOriginated,
    DecisionStep::AsPathLength,
    DecisionStep::Origin,
    DecisionStep::Med,
    DecisionStep::ExternalOverInternal,
    DecisionStep::IgpCost,
    DecisionStep::OldestPath,
    DecisionStep::RouterId,
    DecisionStep::ClusterListLength,
    DecisionStep::NeighborAddress,
];

/// The BGP defaults of a platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BgpProfile {
    pub platform: Platform,
    pub order: &'static [DecisionStep],
    /// The default of deterministic MED.
    pub deterministic_med: bool,
    /// True if the config cannot turn deterministic MED off.
    pub deterministic_med_fixed: bool,
    /// The default of missing-as-worst.
    pub missing_as_worst: bool,
    /// The default of the rule that an eBGP session with no policy in a
    /// direction drops the routes of that direction.
    pub ebgp_requires_policy: bool,
    /// True if the config can set `ebgp-requires-policy`.
    pub ebgp_requires_policy_configurable: bool,
    /// True if a local path from `network` or `redistribute` ranks above a
    /// local aggregate.
    pub aggregate_below_network: bool,
    pub default_local_pref: u32,
    /// The weight of a local path.
    pub local_weight: u32,
    /// The default maximum paths. `None` when it is a build value.
    pub maximum_paths_ebgp: Option<u32>,
    pub maximum_paths_ibgp: Option<u32>,
    /// True if a neighbour activates IPv4 unicast with no activation line.
    /// `None` when the version decides.
    pub default_ipv4_unicast: Option<bool>,
    pub undefined_policy: UndefinedPolicy,
    pub match_reads: MatchReads,
    pub redistribute: RedistributeDefaults,
}

impl BgpProfile {
    /// The BGP defaults of a platform.
    pub fn of(platform: Platform) -> BgpProfile {
        let base = BgpProfile {
            platform,
            order: DECISION_ORDER,
            deterministic_med: false,
            deterministic_med_fixed: false,
            missing_as_worst: false,
            ebgp_requires_policy: false,
            ebgp_requires_policy_configurable: false,
            aggregate_below_network: true,
            default_local_pref: 100,
            local_weight: 32_768,
            maximum_paths_ebgp: Some(1),
            maximum_paths_ibgp: Some(1),
            default_ipv4_unicast: Some(false),
            undefined_policy: UndefinedPolicy::Deny,
            match_reads: MatchReads::Input,
            redistribute: RedistributeDefaults {
                undefined_permits: false,
                ospf_internal_only: false,
                excludes_default: Some(true),
                ibgp_into_igp: false,
            },
        };
        match platform {
            Platform::Iosxe => BgpProfile {
                default_ipv4_unicast: Some(true),
                redistribute: RedistributeDefaults {
                    ospf_internal_only: true,
                    ..base.redistribute
                },
                ..base
            },
            Platform::Nxos => BgpProfile {
                deterministic_med: true,
                redistribute: RedistributeDefaults {
                    undefined_permits: true,
                    ..base.redistribute
                },
                ..base
            },
            Platform::Iosxr => BgpProfile {
                deterministic_med: true,
                deterministic_med_fixed: true,
                ebgp_requires_policy: true,
                undefined_policy: UndefinedPolicy::NoPolicy,
                redistribute: RedistributeDefaults {
                    undefined_permits: true,
                    ..base.redistribute
                },
                ..base
            },
            Platform::FrrTraditional | Platform::FrrDatacenter => {
                let datacenter = platform == Platform::FrrDatacenter;
                BgpProfile {
                    deterministic_med: datacenter,
                    ebgp_requires_policy: !datacenter,
                    ebgp_requires_policy_configurable: true,
                    aggregate_below_network: false,
                    maximum_paths_ebgp: None,
                    maximum_paths_ibgp: None,
                    default_ipv4_unicast: Some(true),
                    match_reads: MatchReads::Output,
                    redistribute: RedistributeDefaults {
                        undefined_permits: false,
                        ospf_internal_only: false,
                        excludes_default: None,
                        ibgp_into_igp: true,
                    },
                    ..base
                }
            }
        }
    }

    /// The administrative distance of a path of `kind`. A confederation
    /// eBGP path has the iBGP distance.
    pub fn distance(&self, kind: SessionKind) -> u8 {
        let origin = match kind {
            SessionKind::Ebgp => Origin::Ebgp,
            SessionKind::Ibgp | SessionKind::ConfedEbgp => Origin::Ibgp,
            SessionKind::Local(_) => Origin::LocalBgp,
        };
        self.platform.distance(origin)
    }

    /// True if deterministic MED applies under `options`.
    pub fn deterministic_med(&self, options: &BgpOptions) -> bool {
        if self.deterministic_med_fixed {
            return self.deterministic_med;
        }
        options.deterministic_med.unwrap_or(self.deterministic_med)
    }

    /// True if a missing MED is the worst MED under `options`.
    pub fn missing_as_worst(&self, options: &BgpOptions) -> bool {
        options.missing_as_worst.unwrap_or(self.missing_as_worst)
    }

    /// True if a session of `kind` with no policy in a direction permits
    /// the routes of that direction. Only an eBGP session can drop them.
    pub fn no_policy_permits(&self, kind: SessionKind, options: &BgpOptions) -> bool {
        if kind != SessionKind::Ebgp {
            return true;
        }
        let requires = if self.ebgp_requires_policy_configurable {
            options
                .ebgp_requires_policy
                .unwrap_or(self.ebgp_requires_policy)
        } else {
            self.ebgp_requires_policy
        };
        !requires
    }

    /// The maximum paths for a best path of `kind` under `options`. `None`
    /// when the platform default is a build value and the config sets
    /// none. A local path has no multipath.
    pub fn maximum_paths(&self, kind: SessionKind, options: &BgpOptions) -> Option<u32> {
        match kind {
            SessionKind::Ebgp => options.maximum_paths_ebgp.or(self.maximum_paths_ebgp),
            SessionKind::Ibgp | SessionKind::ConfedEbgp => {
                options.maximum_paths_ibgp.or(self.maximum_paths_ibgp)
            }
            SessionKind::Local(_) => Some(1),
        }
    }

    /// The local preference of a path with none under `options`.
    pub fn default_local_pref(&self, options: &BgpOptions) -> u32 {
        options
            .default_local_pref
            .unwrap_or(self.default_local_pref)
    }
}
