//! The OSPF routes of a VRF for the install stage and for the RIB guard.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::Prefix;
use rsim_functions::{Route, RouteKind, RouteNextHop, RouteProtocol};
use rsim_routing::ospf::{Calculation, OspfProfile, Version, compute};
use rsim_routing::{Candidate, Platform};

use super::DeviceOspf;
use crate::bgp::Outcome;

/// The OSPF calculations of one VRF, for each version: the calculations, or
/// the reason that the version is not computed.
pub struct OspfRoutes {
    by_version: BTreeMap<Version, Result<Vec<Calculation>, String>>,
}

const KIND: RouteKind = RouteKind::Learned(RouteProtocol::Ospf);

impl OspfRoutes {
    /// The calculations of the databases of a VRF. A version whose sections
    /// are not read in full, or a database with no router ID, is not
    /// computed.
    pub fn of(ospf: Option<&DeviceOspf>, vrf: &str, platform: Platform) -> OspfRoutes {
        let profile = OspfProfile::of(platform);
        let mut by_version = BTreeMap::new();
        for v in [Version::V2, Version::V3] {
            let r = match ospf {
                None => Err(format!("{} not collected", v.name())),
                Some(o) => match o.outcomes.get(&v).map(|s| s.outcome) {
                    Some(Outcome::Complete | Outcome::CompleteEmpty) => o
                        .of(v, vrf)
                        .map(|db| match db.router_id {
                            Some(id) => Ok(compute(db, id, &profile)),
                            None => Err(format!("{} router ID not known", v.name())),
                        })
                        .collect(),
                    _ => Err(format!("{} database not read in full", v.name())),
                },
            };
            by_version.insert(v, r);
        }
        OspfRoutes { by_version }
    }

    /// The candidates of the computed OSPF routes. A next hop with no
    /// interface takes the interface of `interface_of` its gateway. A route
    /// with a next hop whose interface is not known, or that depends on a
    /// gap of the database, is unknown.
    pub fn candidates(
        &self,
        platform: Platform,
        hop: &dyn Fn(&str, Option<IpAddr>) -> RouteNextHop,
        interface_of: &dyn Fn(IpAddr) -> Option<String>,
    ) -> Vec<Candidate> {
        let distance = OspfProfile::of(platform).distance();
        let mut out = Vec::new();
        for calcs in self.by_version.values().flatten() {
            for c in calcs {
                for r in &c.routes {
                    let spans = r.spans.clone();
                    let route = match &r.unknown {
                        Some(why) => Route::unknown(KIND, why.clone(), spans),
                        None => {
                            let hops: Option<Vec<RouteNextHop>> = r
                                .next_hops
                                .iter()
                                .map(|n| {
                                    let i =
                                        n.interface.clone().or_else(|| interface_of(n.gateway))?;
                                    Some(hop(&i, Some(n.gateway)))
                                })
                                .collect();
                            match hops {
                                Some(h) if !h.is_empty() => Route::new(KIND, h, spans),
                                _ => {
                                    Route::unknown(KIND, "OSPF next hop interface not known", spans)
                                }
                            }
                        }
                    };
                    out.push(Candidate {
                        prefix: r.prefix,
                        distance,
                        route,
                    });
                }
            }
        }
        out
    }

    /// The guard class of a collected OSPF route of `prefix`. It is not
    /// computed if its version is not computed, or if the computed tables
    /// have no route of the prefix and a gap of a database covers it.
    pub fn class(&self, prefix: Prefix) -> rsim_guard::Class {
        let v = if prefix.addr().is_ipv4() {
            Version::V2
        } else {
            Version::V3
        };
        match self.by_version.get(&v) {
            Some(Ok(calcs)) => {
                if calcs.iter().any(|c| c.route(prefix).is_some()) {
                    return rsim_guard::Class::Compared;
                }
                match calcs.iter().find_map(|c| c.absent_gap(prefix)) {
                    Some(g) => {
                        rsim_guard::Class::NotComputed(format!("database gap: {}", g.detail))
                    }
                    None => rsim_guard::Class::Compared,
                }
            }
            Some(Err(why)) => rsim_guard::Class::NotComputed(why.clone()),
            None => rsim_guard::Class::NotComputed(format!("{} not computed", v.name())),
        }
    }
}
