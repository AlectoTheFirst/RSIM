//! The install stage. It selects the route of each prefix from its
//! candidates by the administrative distance, and it resolves the next hops
//! of the candidates over the routes that it installs.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::Prefix;
use rsim_functions::{Fib, Route, RouteKind, RouteNextHop, RouteProtocol};

/// A candidate route of one prefix and its administrative distance.
/// `gateways` holds the next hops with no interface. The install stage
/// resolves each of them over the routes that it installs, and adds the
/// resolved next hops to the next hops of `route`.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub prefix: Prefix,
    pub distance: u8,
    pub route: Route,
    pub gateways: Vec<IpAddr>,
}

impl Candidate {
    /// A candidate with no gateway to resolve.
    pub fn new(prefix: Prefix, distance: u8, route: Route) -> Candidate {
        Candidate {
            prefix,
            distance,
            route,
            gateways: Vec::new(),
        }
    }

    /// A candidate of the kind `kind` whose next hops are the resolutions of
    /// the gateways `gateways`.
    pub fn via(
        prefix: Prefix,
        distance: u8,
        kind: RouteKind,
        gateways: Vec<IpAddr>,
        spans: Vec<rsim_core::SourceSpan>,
    ) -> Candidate {
        Candidate {
            prefix,
            distance,
            route: Route::new(kind, Vec::new(), spans),
            gateways,
        }
    }
}

/// True if a route has no next hop and is not a local or a discard route,
/// so its packets are unknown.
fn unknown(r: &Route) -> bool {
    r.next_hops().is_empty() && !matches!(r.kind, RouteKind::Local | RouteKind::Null)
}

/// The order of the kinds within one distance, after HST `simul/rib.py`:
/// connected, static, OSPF, BGP, then each other kind. A local route ranks
/// with the connected routes. A discard route ranks with the static routes
/// and after them.
fn rank(kind: RouteKind) -> (u8, u8) {
    match kind {
        RouteKind::Connected => (0, 0),
        RouteKind::Local => (0, 1),
        RouteKind::Static => (1, 0),
        RouteKind::Null => (1, 1),
        RouteKind::Learned(RouteProtocol::Ospf) => (2, 0),
        RouteKind::Learned(RouteProtocol::Bgp) => (3, 0),
        RouteKind::Learned(_) => (9, 0),
    }
}

/// The result of the resolution of one gateway.
enum Resolved {
    Hops(Vec<RouteNextHop>, Vec<rsim_core::SourceSpan>),
    /// No route, a local route or a discard route.
    No,
    Unknown(String),
}

/// The installed routes, with the longest prefix match.
struct Table<'a> {
    routes: &'a BTreeMap<Prefix, Route>,
    through_default: bool,
}

impl Table<'_> {
    /// The resolution of `gw` for a candidate of `own`. The route of `own`
    /// does not resolve it, and a default route resolves it only with
    /// `through_default`.
    fn resolve(&self, gw: IpAddr, own: Prefix) -> Resolved {
        let max = if gw.is_ipv4() { 32 } else { 128 };
        let min = if self.through_default { 0 } else { 1 };
        for len in (min..=max).rev() {
            let p = Prefix::new(gw, len);
            if p == own {
                continue;
            }
            let Some(r) = self.routes.get(&p) else {
                continue;
            };
            if matches!(r.kind, RouteKind::Local | RouteKind::Null) {
                return Resolved::No;
            }
            if r.next_hops().is_empty() {
                let why = r.unknown_reason().unwrap_or("a route with no next hop");
                return Resolved::Unknown(format!("next hop {gw} resolves through {p}: {why}"));
            }
            let hops = r
                .next_hops()
                .iter()
                .map(|h| RouteNextHop {
                    interface: h.interface.clone(),
                    gateway: h.gateway.or(Some(gw)),
                    next: h.next.clone(),
                })
                .collect();
            return Resolved::Hops(hops, r.spans.clone());
        }
        Resolved::No
    }
}

/// The state of one candidate in a pass.
enum State {
    /// The route that the candidate gives.
    Route(Route),
    /// The candidate has no next hop that resolves.
    Absent,
    Unknown(Route),
}

fn state(c: &Candidate, table: &Table<'_>) -> State {
    if c.gateways.is_empty() {
        return if unknown(&c.route) {
            State::Unknown(c.route.clone())
        } else {
            State::Route(c.route.clone())
        };
    }
    let mut hops: Vec<RouteNextHop> = c.route.next_hops().to_vec();
    let mut spans = c.route.spans.clone();
    for gw in &c.gateways {
        match table.resolve(*gw, c.prefix) {
            Resolved::Hops(h, s) => {
                hops.extend(h);
                for x in s {
                    if !spans.contains(&x) {
                        spans.push(x);
                    }
                }
            }
            Resolved::No => {}
            Resolved::Unknown(why) => {
                return State::Unknown(Route::unknown(c.route.kind, why, spans));
            }
        }
    }
    if hops.is_empty() {
        State::Absent
    } else {
        State::Route(Route::new(c.route.kind, hops, spans))
    }
}

/// The route of one prefix from its candidates, in the order of
/// [`order`]. The lowest distance with a candidate that resolves or that is
/// unknown gives the route. One unknown candidate makes the route unknown.
/// Else the candidates of the first kind give one route with all their next
/// hops. `None` if no candidate resolves.
fn select(list: &[Candidate], table: &Table<'_>) -> Option<Route> {
    let mut i = 0;
    while i < list.len() {
        let distance = list[i].distance;
        let level: Vec<&Candidate> = list[i..]
            .iter()
            .take_while(|c| c.distance == distance)
            .collect();
        i += level.len();
        let states: Vec<State> = level.iter().map(|c| state(c, table)).collect();
        if let Some(u) = states.iter().find_map(|s| match s {
            State::Unknown(r) => Some(r),
            _ => None,
        }) {
            if level.len() == 1 {
                return Some(u.clone());
            }
            let spans = level
                .iter()
                .flat_map(|c| c.route.spans.iter().cloned())
                .collect();
            let why = u.unknown_reason().unwrap_or("a route with no next hop");
            return Some(Route::unknown(
                u.kind,
                format!("a route of distance {distance}: {why}"),
                spans,
            ));
        }
        let routes: Vec<Route> = states
            .into_iter()
            .filter_map(|s| match s {
                State::Route(r) => Some(r),
                _ => None,
            })
            .collect();
        let Some(first) = routes.first() else {
            continue;
        };
        let kind = first.kind;
        let same: Vec<&Route> = routes.iter().filter(|r| r.kind == kind).collect();
        let hops = same
            .iter()
            .flat_map(|r| r.next_hops().iter().cloned())
            .collect();
        let spans = same.iter().flat_map(|r| r.spans.iter().cloned()).collect();
        return Some(Route::new(kind, hops, spans));
    }
    None
}

/// The candidates of a prefix in the order of the selection: by distance,
/// then by the kind (see [`rank`]), then in the order of the input.
fn order(list: &mut [Candidate]) {
    list.sort_by_key(|c| (c.distance, rank(c.route.kind)));
}

/// The bound on the passes of the next hop resolution, as in HST
/// `simul/convergence.py`.
pub const PASSES: usize = 64;

/// The route table of the candidates. Each pass selects the route of each
/// prefix in prefix order over the routes that are installed at that
/// moment, from this pass and the passes before. The passes stop when a
/// pass changes no route, after at most [`PASSES`] passes. The routes that
/// the last pass still changes are unknown. `through_default` is the flag
/// `COMPUTED_THROUGH_DEFAULT` of the vendor profile.
pub fn install(candidates: Vec<Candidate>, through_default: bool) -> Fib {
    let mut by_prefix: BTreeMap<Prefix, Vec<Candidate>> = BTreeMap::new();
    for c in candidates {
        by_prefix.entry(c.prefix).or_default().push(c);
    }
    for list in by_prefix.values_mut() {
        order(list);
    }
    let mut routes: BTreeMap<Prefix, Route> = BTreeMap::new();
    let bound = PASSES;
    let mut changed: Vec<Prefix> = Vec::new();
    for _ in 0..bound {
        changed.clear();
        for (prefix, list) in &by_prefix {
            let table = Table {
                routes: &routes,
                through_default,
            };
            let new = select(list, &table);
            if new.as_ref() != routes.get(prefix) {
                changed.push(*prefix);
                match new {
                    Some(r) => routes.insert(*prefix, r),
                    None => routes.remove(prefix),
                };
            }
        }
        if changed.is_empty() {
            break;
        }
    }
    for p in &changed {
        let list = &by_prefix[p];
        let spans = list
            .iter()
            .flat_map(|c| c.route.spans.iter().cloned())
            .collect();
        routes.insert(
            *p,
            Route::unknown(
                list[0].route.kind,
                "next hop resolution does not settle",
                spans,
            ),
        );
    }
    let mut fib = Fib::new();
    for (p, r) in routes {
        fib.insert(p, r);
    }
    fib
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsim_core::{FunctionId, InterfaceId, SourceSpan};

    fn hop(i: &str) -> RouteNextHop {
        RouteNextHop {
            interface: InterfaceId::new(i),
            gateway: None,
            next: FunctionId::new("r/next"),
        }
    }

    fn via(i: &str, gw: &str) -> RouteNextHop {
        RouteNextHop {
            gateway: Some(gw.parse().unwrap()),
            ..hop(i)
        }
    }

    fn span() -> Vec<SourceSpan> {
        vec![SourceSpan::new("r/config", 1, 1)]
    }

    fn cand(p: &str, d: u8, kind: RouteKind, hops: &[&str]) -> Candidate {
        Candidate::new(
            p.parse().unwrap(),
            d,
            Route::new(kind, hops.iter().map(|h| hop(h)).collect(), span()),
        )
    }

    fn gw(p: &str, d: u8, gateway: &str) -> Candidate {
        Candidate::via(
            p.parse().unwrap(),
            d,
            RouteKind::Static,
            vec![gateway.parse().unwrap()],
            span(),
        )
    }

    fn get(fib: &Fib, p: &str) -> Option<Route> {
        fib.get(&p.parse().unwrap())
    }

    #[test]
    fn the_lowest_distance_wins_and_a_floating_static_route_installs_alone() {
        let fib = install(
            vec![
                cand("192.0.2.0/24", 1, RouteKind::Static, &["eth1"]),
                cand("192.0.2.0/24", 0, RouteKind::Connected, &["eth0"]),
                cand("198.51.100.0/24", 250, RouteKind::Static, &["eth2"]),
            ],
            false,
        );
        let r = get(&fib, "192.0.2.0/24").unwrap();
        assert_eq!(r.kind, RouteKind::Connected);
        assert_eq!(r.next_hops(), [hop("eth0")]);
        let f = get(&fib, "198.51.100.0/24").unwrap();
        assert_eq!(f.next_hops(), [hop("eth2")]);
    }

    #[test]
    fn candidates_of_one_distance_merge_their_next_hops_and_an_unknown_one_makes_the_route_unknown()
    {
        let fib = install(
            vec![
                cand("192.0.2.0/24", 1, RouteKind::Static, &["eth1"]),
                cand("192.0.2.0/24", 1, RouteKind::Static, &["eth0"]),
                cand("198.51.100.0/24", 1, RouteKind::Static, &["eth1"]),
                cand("198.51.100.0/24", 1, RouteKind::Static, &[]),
                cand("198.51.100.0/24", 5, RouteKind::Static, &["eth2"]),
            ],
            false,
        );
        let r = get(&fib, "192.0.2.0/24").unwrap();
        assert_eq!(r.next_hops(), [hop("eth0"), hop("eth1")]);
        assert!(get(&fib, "198.51.100.0/24").unwrap().next_hops().is_empty());
    }

    #[test]
    fn candidates_of_one_distance_with_different_kinds_install_the_first_kind() {
        let fib = install(
            vec![
                cand("203.0.113.0/24", 1, RouteKind::Null, &[]),
                cand("203.0.113.0/24", 1, RouteKind::Static, &["eth1"]),
                cand(
                    "198.51.100.0/24",
                    20,
                    RouteKind::Learned(RouteProtocol::Bgp),
                    &["eth2"],
                ),
                cand(
                    "198.51.100.0/24",
                    20,
                    RouteKind::Learned(RouteProtocol::Ospf),
                    &["eth1"],
                ),
            ],
            false,
        );
        let s = get(&fib, "203.0.113.0/24").unwrap();
        assert_eq!(s.kind, RouteKind::Static);
        assert_eq!(s.next_hops(), [hop("eth1")]);
        let o = get(&fib, "198.51.100.0/24").unwrap();
        assert_eq!(o.kind, RouteKind::Learned(RouteProtocol::Ospf));
        assert_eq!(o.next_hops(), [hop("eth1")]);
    }

    #[test]
    fn a_gateway_resolves_recursively_and_a_floating_static_route_installs_when_the_better_one_does_not_resolve()
     {
        let fib = install(
            vec![
                cand("192.0.2.0/24", 0, RouteKind::Connected, &["eth0"]),
                // 198.51.100.9 resolves through 198.51.100.0/24, which
                // resolves through the connected network of eth0.
                gw("203.0.113.0/24", 1, "198.51.100.9"),
                gw("198.51.100.0/24", 1, "192.0.2.1"),
                // 10.0.0.1 is in no route, so the route of distance 250 wins.
                gw("100.64.0.0/10", 1, "10.0.0.1"),
                gw("100.64.0.0/10", 250, "192.0.2.2"),
            ],
            false,
        );
        assert_eq!(
            get(&fib, "198.51.100.0/24").unwrap().next_hops(),
            [via("eth0", "192.0.2.1")]
        );
        assert_eq!(
            get(&fib, "203.0.113.0/24").unwrap().next_hops(),
            [via("eth0", "192.0.2.1")]
        );
        assert_eq!(
            get(&fib, "100.64.0.0/10").unwrap().next_hops(),
            [via("eth0", "192.0.2.2")]
        );
    }

    #[test]
    fn a_gateway_does_not_resolve_through_the_route_itself_and_a_default_route_needs_the_profile_flag()
     {
        let cands = || {
            vec![
                cand("192.0.2.0/24", 0, RouteKind::Connected, &["eth0"]),
                gw("0.0.0.0/0", 1, "192.0.2.1"),
                gw("198.51.100.0/24", 1, "198.51.100.1"),
                gw("203.0.113.0/24", 1, "10.0.0.1"),
            ]
        };
        let off = install(cands(), false);
        assert!(get(&off, "198.51.100.0/24").is_none());
        assert!(get(&off, "203.0.113.0/24").is_none());
        let on = install(cands(), true);
        assert_eq!(
            get(&on, "198.51.100.0/24").unwrap().next_hops(),
            [via("eth0", "192.0.2.1")]
        );
        assert_eq!(
            get(&on, "203.0.113.0/24").unwrap().next_hops(),
            [via("eth0", "192.0.2.1")]
        );
    }

    #[test]
    fn a_gateway_through_an_unknown_route_is_unknown_and_through_a_discard_route_does_not_resolve()
    {
        let fib = install(
            vec![
                cand("192.0.2.0/24", 1, RouteKind::Static, &[]),
                gw("198.51.100.0/24", 1, "192.0.2.1"),
                gw("198.51.100.0/24", 200, "203.0.113.1"),
                cand("10.0.0.0/8", 1, RouteKind::Null, &[]),
                cand("203.0.113.0/24", 0, RouteKind::Connected, &["eth1"]),
                gw("100.64.0.0/10", 1, "10.0.0.1"),
                gw("100.64.0.0/10", 200, "203.0.113.1"),
            ],
            false,
        );
        let u = get(&fib, "198.51.100.0/24").unwrap();
        assert!(u.next_hops().is_empty());
        assert!(
            u.unknown_reason()
                .unwrap()
                .starts_with("next hop 192.0.2.1 resolves through 192.0.2.0/24")
        );
        assert_eq!(
            get(&fib, "100.64.0.0/10").unwrap().next_hops(),
            [via("eth1", "203.0.113.1")]
        );
    }

    #[test]
    fn a_gateway_resolves_through_the_route_of_a_later_prefix() {
        let fib = install(
            vec![
                gw("192.0.2.0/24", 1, "203.0.113.1"),
                gw("203.0.113.0/24", 1, "198.51.100.1"),
                cand("198.51.100.0/24", 0, RouteKind::Connected, &["eth0"]),
            ],
            false,
        );
        assert_eq!(
            get(&fib, "192.0.2.0/24").unwrap().next_hops(),
            [via("eth0", "198.51.100.1")]
        );
    }
}
