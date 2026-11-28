//! The redistribution of the installed routes of a VRF into BGP.
//!
//! A `redistribute` statement of a process offers each installed route of
//! its source protocol and its family in the VRF of the process as a local
//! path, as in HST
//! `simul/rib.py`: the origin incomplete, the local weight of the profile,
//! the metric of the statement or of the route as the MED, the tag of the
//! route, and the next hop of the route. A connected route has no next hop.
//! The route-map of the statement runs on the path. Without
//! `default-information originate`, a default route is offered only when
//! the profile does not leave it out. `redistribute ospf` with no `match`
//! clause offers the OSPF route types of the profile.

use std::collections::BTreeSet;
use std::net::IpAddr;

use rsim_core::{Prefix, SourceSpan};

use super::policy::{Direction, PolicyContext, PolicyResult, evaluate, policy_reads};
use super::process::{BgpProcess, OspfRouteType, RedistSource, Redistribution};
use super::session::Offer;
use super::stage::{ObjectRef, RoutingStage};
use super::{
    AsPath, BgpOrigin, BgpPath, LocalOrigin, Peer, Reason, RouteKey, SessionKind, Unknown,
};

/// The source protocol of an installed route that a redistribution can
/// offer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IgpSource {
    Connected,
    Static,
    Ospf {
        process: String,
        route_type: OspfRouteType,
    },
}

/// An installed route of the route table of a VRF from a protocol other
/// than BGP.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IgpRoute {
    pub device: String,
    pub vrf: String,
    pub prefix: Prefix,
    pub source: IgpSource,
    pub metric: u32,
    pub tag: Option<u32>,
    /// The gateway of a route with exactly 1 next hop.
    pub next_hop: Option<IpAddr>,
    /// The reason when the route is not known.
    pub unknown: Option<String>,
    pub spans: Vec<SourceSpan>,
}

/// True if the statement `r` takes a route of `source`. `internal_only`
/// is the OSPF default of the profile.
fn takes(r: &Redistribution, source: &IgpSource, internal_only: bool) -> bool {
    match (&r.source, source) {
        (RedistSource::Connected, IgpSource::Connected) => true,
        (RedistSource::Static, IgpSource::Static) => true,
        (
            RedistSource::Ospf(name),
            IgpSource::Ospf {
                process,
                route_type,
            },
        ) => {
            name.as_ref().is_none_or(|n| n == process)
                && match &r.ospf_match {
                    Some(types) => types.contains(route_type),
                    None => !internal_only || *route_type == OspfRouteType::Internal,
                }
        }
        _ => false,
    }
}

/// The path that the statement `r` of `process` offers for `route`, the
/// installed route of the prefix of `key`.
pub fn redistribute_offer(
    process: &BgpProcess,
    r: &Redistribution,
    key: &RouteKey,
    route: &IgpRoute,
) -> Offer {
    let Some(profile) = process.profile() else {
        return Offer::Unknown(Unknown::new(Reason::NoBgpProfile, process.device.clone()));
    };
    let defaults = profile.redistribute;
    if key.family != r.family || !takes(r, &route.source, defaults.ospf_internal_only) {
        return Offer::None;
    }
    let at = format!("{} at {} {}", key.prefix, process.device, process.vrf);
    if key.prefix.len() == 0 && !process.default_originate {
        match defaults.excludes_default {
            Some(true) => return Offer::None,
            Some(false) => {}
            None => {
                return Offer::Unknown(Unknown::new(
                    Reason::RedistributedRouteNotKnown,
                    format!("{at}: the default route rule of the platform is not known"),
                ));
            }
        }
    }
    if let Some(why) = &route.unknown {
        return Offer::Unknown(Unknown::new(
            Reason::RedistributedRouteNotKnown,
            format!("{at}: {why}"),
        ));
    }
    let peer = Peer {
        address: None,
        router_id: process.router_id,
        asn: process.asn,
        kind: SessionKind::Local(LocalOrigin::Redistribute),
    };
    let next_hop = match route.source {
        IgpSource::Connected => None,
        _ => route.next_hop,
    };
    let mut path = BgpPath::new(peer, next_hop, AsPath::default());
    path.origin = BgpOrigin::Incomplete;
    path.weight = profile.local_weight;
    path.med = Some(r.metric.unwrap_or(route.metric));
    path.tag = route.tag;
    path.spans = r.spans.iter().chain(&route.spans).cloned().collect();
    let Some(name) = &r.policy else {
        return Offer::Path(path);
    };
    let Some(policy) = process.policy.policies.get(name) else {
        return if defaults.undefined_permits {
            Offer::Path(path)
        } else {
            Offer::None
        };
    };
    let ctx = PolicyContext {
        set: &process.policy,
        direction: Direction::Redistribute,
        local_address: None,
        peer_address: None,
        default_local_pref: profile.default_local_pref(&process.options),
        match_reads: profile.match_reads,
    };
    match evaluate(policy, key, &path, &ctx) {
        PolicyResult::Permit(p) => Offer::Path(p),
        PolicyResult::Deny => Offer::None,
        PolicyResult::Unknown(u) => Offer::Unknown(u),
    }
}

/// The redistribution stage of one route at one process: the paths of the
/// `redistribute` statements of the process for the installed route of the
/// prefix of the key.
pub struct RedistributeStage<'a> {
    pub process: &'a BgpProcess,
    pub key: RouteKey,
}

impl RoutingStage for RedistributeStage<'_> {
    type Input = Option<IgpRoute>;
    type Output = Vec<Offer>;

    fn name(&self) -> &'static str {
        "bgp redistribute"
    }

    /// The profile, the process, the route-maps of the statements and the
    /// route table entry of the prefix.
    fn reads(&self) -> BTreeSet<ObjectRef> {
        let p = self.process;
        let mut out = BTreeSet::from([
            ObjectRef::Profile(p.platform),
            ObjectRef::Process {
                device: p.device.clone(),
                vrf: p.vrf.clone(),
            },
            ObjectRef::IgpRoute {
                device: p.device.clone(),
                vrf: p.vrf.clone(),
                prefix: self.key.prefix,
            },
        ]);
        for r in &p.redistributions {
            if let Some(name) = &r.policy {
                policy_reads(&p.policy, name, &p.device, &p.vrf, &mut out);
            }
        }
        out
    }

    fn run(&self, input: &Option<IgpRoute>) -> Vec<Offer> {
        let Some(route) = input else {
            return Vec::new();
        };
        self.process
            .redistributions
            .iter()
            .map(|r| redistribute_offer(self.process, r, &self.key, route))
            .filter(|o| !matches!(o, Offer::None))
            .collect()
    }
}
