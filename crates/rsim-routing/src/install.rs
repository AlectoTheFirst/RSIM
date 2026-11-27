//! The install stage. It selects the route of each prefix from its
//! candidates by the administrative distance.

use std::collections::BTreeMap;

use rsim_core::Prefix;
use rsim_functions::{Fib, Route, RouteKind};

/// A candidate route of one prefix and its administrative distance. A
/// route whose next hop does not resolve on the device is not a candidate.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub prefix: Prefix,
    pub distance: u8,
    pub route: Route,
}

/// True if a route has no next hop and is not a local or a discard route,
/// so its packets are unknown.
fn unknown(r: &Route) -> bool {
    r.next_hops().is_empty() && !matches!(r.kind, RouteKind::Local | RouteKind::Null)
}

/// The route table of the candidates. For each prefix, the candidates of
/// the lowest distance give the route. One unknown candidate makes the
/// route unknown. Candidates of one kind give one route with all their next
/// hops. Candidates of more than one kind give an unknown route.
pub fn install(candidates: Vec<Candidate>) -> Fib {
    let mut by_prefix: BTreeMap<Prefix, Vec<Candidate>> = BTreeMap::new();
    for c in candidates {
        by_prefix.entry(c.prefix).or_default().push(c);
    }
    let mut fib = Fib::new();
    for (prefix, mut list) in by_prefix {
        let best = list
            .iter()
            .map(|c| c.distance)
            .min()
            .expect("one candidate");
        list.retain(|c| c.distance == best);
        fib.insert(prefix, select(list, best));
    }
    fib
}

fn select(list: Vec<Candidate>, distance: u8) -> Route {
    let kind = list[0].route.kind;
    let spans: Vec<_> = list
        .iter()
        .flat_map(|c| c.route.spans.iter().cloned())
        .collect();
    if let Some(u) = list.iter().find(|c| unknown(&c.route)) {
        if list.len() == 1 {
            return u.route.clone();
        }
        let why = u
            .route
            .unknown_reason()
            .unwrap_or("a route with no next hop");
        return Route::unknown(
            kind,
            format!("a route of distance {distance}: {why}"),
            spans,
        );
    }
    if list.iter().any(|c| c.route.kind != kind) {
        return Route::unknown(
            kind,
            format!("routes of distance {distance} with different kinds"),
            spans,
        );
    }
    let hops = list
        .iter()
        .flat_map(|c| c.route.next_hops().iter().cloned())
        .collect();
    Route::new(kind, hops, spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsim_core::{FunctionId, InterfaceId, SourceSpan};
    use rsim_functions::RouteNextHop;

    fn hop(i: &str) -> RouteNextHop {
        RouteNextHop {
            interface: InterfaceId::new(i),
            gateway: None,
            next: FunctionId::new("r/next"),
        }
    }

    fn cand(p: &str, d: u8, kind: RouteKind, hops: &[&str]) -> Candidate {
        Candidate {
            prefix: p.parse().unwrap(),
            distance: d,
            route: Route::new(
                kind,
                hops.iter().map(|h| hop(h)).collect(),
                vec![SourceSpan::new("r/config", 1, 1)],
            ),
        }
    }

    #[test]
    fn the_lowest_distance_wins_and_a_floating_static_route_installs_alone() {
        let fib = install(vec![
            cand("192.0.2.0/24", 1, RouteKind::Static, &["eth1"]),
            cand("192.0.2.0/24", 0, RouteKind::Connected, &["eth0"]),
            cand("198.51.100.0/24", 250, RouteKind::Static, &["eth2"]),
        ]);
        let r = fib.get(&"192.0.2.0/24".parse().unwrap()).unwrap();
        assert_eq!(r.kind, RouteKind::Connected);
        assert_eq!(r.next_hops(), [hop("eth0")]);
        let f = fib.get(&"198.51.100.0/24".parse().unwrap()).unwrap();
        assert_eq!(f.next_hops(), [hop("eth2")]);
    }

    #[test]
    fn candidates_of_one_distance_merge_their_next_hops_and_an_unknown_one_makes_the_route_unknown()
    {
        let fib = install(vec![
            cand("192.0.2.0/24", 1, RouteKind::Static, &["eth1"]),
            cand("192.0.2.0/24", 1, RouteKind::Static, &["eth0"]),
            cand("198.51.100.0/24", 1, RouteKind::Static, &["eth1"]),
            cand("198.51.100.0/24", 1, RouteKind::Static, &[]),
            cand("203.0.113.0/24", 1, RouteKind::Static, &["eth1"]),
            cand("203.0.113.0/24", 1, RouteKind::Null, &[]),
        ]);
        let r = fib.get(&"192.0.2.0/24".parse().unwrap()).unwrap();
        assert_eq!(r.next_hops(), [hop("eth0"), hop("eth1")]);
        assert!(
            fib.get(&"198.51.100.0/24".parse().unwrap())
                .unwrap()
                .next_hops()
                .is_empty()
        );
        let mixed = fib.get(&"203.0.113.0/24".parse().unwrap()).unwrap();
        assert_eq!(
            mixed.unknown_reason(),
            Some("routes of distance 1 with different kinds")
        );
    }
}
