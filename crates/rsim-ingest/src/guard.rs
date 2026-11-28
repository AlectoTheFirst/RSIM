//! The inputs of the computed route table of the RIB guard that come from
//! the collected route table.

use std::collections::BTreeMap;

use rsim_core::Prefix;
use rsim_functions::{Fib, Route, RouteKind, RouteProtocol};
use rsim_guard::{Class, CollectedRoute};
use rsim_routing::{Candidate, Origin, Platform, UNKNOWN_DISTANCE};

/// The candidates of the collected routes that the calculation does not
/// compare. A seeded route is an input of the calculation with its next
/// hops. A route that is not computed is an unknown candidate, so a
/// computed next hop that resolves through it is unknown. The distance is
/// the default of the platform for the kind of the collected route.
pub fn outside(
    routes: &BTreeMap<Prefix, CollectedRoute>,
    collected: &Fib,
    platform: Platform,
) -> Vec<Candidate> {
    let mut out = Vec::new();
    for (p, c) in routes {
        let Some(r) = collected.get(p) else {
            continue;
        };
        let d = distance(platform, r.kind);
        match &c.class {
            Class::Compared => {}
            Class::Seeded => out.push(Candidate::new(*p, d, r)),
            Class::NotComputed(why) => out.push(Candidate::new(
                *p,
                d,
                Route::unknown(r.kind, why.clone(), r.spans.clone()),
            )),
        }
    }
    out
}

/// The candidates of the computed route table of a VRF for the IGP view of
/// the BGP calculation, and the flag `COMPUTED_THROUGH_DEFAULT` of the
/// vendor profile for their install.
#[derive(Clone, Debug, Default)]
pub struct IgpRoutes {
    pub cands: Vec<Candidate>,
    pub through_default: bool,
}

/// The lowest distance of a route of `platform` other than a connected or a
/// local route.
pub fn lowest_distance(platform: Platform) -> u8 {
    [
        Origin::Static,
        Origin::Ebgp,
        Origin::Ibgp,
        Origin::Ospf,
        Origin::LocalBgp,
    ]
    .into_iter()
    .map(|o| platform.distance(o))
    .min()
    .unwrap_or(UNKNOWN_DISTANCE)
}

/// The candidates of the computed route table of a VRF for the IGP view of
/// the BGP calculation: `cands`, the candidates other than BGP, with the
/// collected routes of `routes` that are not BGP routes. A seeded route is
/// a candidate with the default distance of its kind. A route that is not
/// computed is an unknown candidate with [`lowest_distance`].
pub fn igp(
    mut cands: Vec<Candidate>,
    routes: &BTreeMap<Prefix, CollectedRoute>,
    collected: &Fib,
    platform: Platform,
    through_default: bool,
) -> IgpRoutes {
    let bgp = RouteKind::Learned(RouteProtocol::Bgp);
    for (p, c) in routes {
        let Some(r) = collected.get(p).filter(|r| r.kind != bgp) else {
            continue;
        };
        match &c.class {
            Class::Compared => {}
            Class::Seeded => cands.push(Candidate::new(*p, distance(platform, r.kind), r)),
            Class::NotComputed(why) => cands.push(Candidate::new(
                *p,
                lowest_distance(platform),
                Route::unknown(r.kind, why.clone(), r.spans.clone()),
            )),
        }
    }
    IgpRoutes {
        cands,
        through_default,
    }
}

/// The default administrative distance of a kind of route.
fn distance(platform: Platform, kind: RouteKind) -> u8 {
    match kind {
        RouteKind::Connected | RouteKind::Local => platform.distance(Origin::Connected),
        RouteKind::Static | RouteKind::Null => platform.distance(Origin::Static),
        RouteKind::Learned(RouteProtocol::Bgp) => platform.distance(Origin::Ebgp),
        RouteKind::Learned(RouteProtocol::Ospf) => platform.distance(Origin::Ospf),
        RouteKind::Learned(_) => UNKNOWN_DISTANCE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsim_core::{FunctionId, InterfaceId, SourceSpan};
    use rsim_functions::RouteNextHop;
    use rsim_routing::install;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn a_static_route_through_a_route_that_is_not_computed_is_unknown_and_a_seed_resolves_one() {
        let hop = RouteNextHop {
            interface: InterfaceId::new("eth0"),
            gateway: Some("192.0.2.1".parse().unwrap()),
            next: FunctionId::new("r1/next"),
        };
        let span = vec![SourceSpan::new("r1/routes", 1, 1)];
        let collected: Fib = [
            (
                p("198.51.100.0/24"),
                Route::new(
                    RouteKind::Learned(RouteProtocol::Bgp),
                    vec![hop.clone()],
                    span.clone(),
                ),
            ),
            (
                p("203.0.113.0/24"),
                Route::new(RouteKind::Static, vec![hop.clone()], span.clone()),
            ),
        ]
        .into_iter()
        .collect();
        let routes = BTreeMap::from([
            (
                p("198.51.100.0/24"),
                CollectedRoute {
                    protocol: "bgp".into(),
                    class: Class::NotComputed("bgp not computed".into()),
                },
            ),
            (
                p("203.0.113.0/24"),
                CollectedRoute {
                    protocol: "static".into(),
                    class: Class::Seeded,
                },
            ),
        ]);
        let mut cands = outside(&routes, &collected, Platform::Nxos);
        assert_eq!(cands.len(), 2);
        cands.push(Candidate::via(
            p("192.0.2.128/25"),
            1,
            RouteKind::Static,
            vec!["198.51.100.7".parse().unwrap()],
            span.clone(),
        ));
        cands.push(Candidate::via(
            p("192.0.2.64/26"),
            1,
            RouteKind::Static,
            vec!["203.0.113.7".parse().unwrap()],
            span,
        ));
        let fib = install(cands, false);
        let through_bgp = fib.get(&p("192.0.2.128/25")).unwrap();
        assert!(through_bgp.next_hops().is_empty());
        assert!(
            through_bgp
                .unknown_reason()
                .unwrap()
                .contains("bgp not computed")
        );
        let through_seed = fib.get(&p("192.0.2.64/26")).unwrap();
        assert_eq!(through_seed.next_hops().len(), 1);
    }
}
