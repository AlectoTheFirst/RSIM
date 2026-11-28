//! The convergence result of route-reflector instances against an
//! enumeration of their stable assignments in the test.
//!
//! An instance has 1 AS with 2 route reflectors and 4 clients from a
//! fixed-seed generator: each client is a client of 1 or 2 reflectors, the
//! reflectors have an iBGP session, each reflector has a cluster ID, and 1
//! to 3 routers have an eBGP path of one prefix with a generated AS path
//! length and local preference. Each IGP cost is 0 or a generated value.
//!
//! The enumeration gives each router one source: no path, its eBGP path, or
//! one iBGP neighbour. The path of a router follows from its source with
//! `export`, `receive` and the IGP cost of the instance, and an assignment
//! whose sources form a loop is not valid. An assignment is stable when the
//! decision over the paths that each router receives under the assignment
//! gives the path of its source. The instance gives `Converged` with 1
//! stable outcome, `MultipleStableOutcomes` with more, and `NoConvergence`
//! with none. An instance where a decision is a tie or unknown is left out.

mod bgp_common;

use bgp_common::*;
use rsim_routing::Platform;
use rsim_routing::bgp::{
    BgpPath, ConvergenceKind, Decision, Offer, RouteState, Seed, decide, export, receive,
};

const P: &str = "203.0.113.0/24";
const ROUTERS: usize = 6;

fn name(i: usize) -> String {
    format!("r{i}")
}

/// The address of router `i` on all sessions.
fn addr(i: usize) -> String {
    format!("10.0.0.{}", i + 1)
}

/// The eBGP peer of router `i`.
fn peer(i: usize) -> String {
    format!("198.51.100.{}", i + 1)
}

/// An instance and the sessions as pairs of routers.
fn instance(rng: &mut Rng) -> (Lab, Vec<(usize, usize)>) {
    let mut lab = Lab::default();
    for i in 0..ROUTERS {
        lab.router(
            &name(i),
            Platform::Iosxe,
            65000,
            &format!("10.255.0.{}", i + 1),
        );
    }
    let mut sessions = vec![(0, 1)];
    for c in 2..ROUTERS {
        match rng.below(3) {
            0 => sessions.push((0, c)),
            1 => sessions.push((1, c)),
            _ => {
                sessions.push((0, c));
                sessions.push((1, c));
            }
        }
    }
    for &(a, b) in &sessions {
        lab.peer(&name(a), &addr(a), &name(b), &addr(b));
        if b >= 2 {
            lab.neighbor_mut(&name(a), &addr(b)).route_reflector_client = true;
        }
    }
    for r in 0..2 {
        lab.proc(&name(r)).cluster_id = Some(v4(&format!("10.254.0.{}", r + 1)));
    }
    let count = 1 + rng.below(3) as usize;
    let mut origins: Vec<usize> = (0..ROUTERS).collect();
    for i in 0..count {
        let j = i + rng.below((ROUTERS - i) as u64) as usize;
        origins.swap(i, j);
    }
    for &o in &origins[..count] {
        let len = 1 + rng.below(3) as u32;
        let path: Vec<u32> = (0..len).map(|k| 64600 + o as u32 * 10 + k).collect();
        lab.seed(&name(o), &peer(o), path[0], P, &path, None);
        if rng.below(2) == 0 {
            let s = lab.input.seeds.last_mut().unwrap();
            s.path.local_pref = Some(100 + 50 * rng.below(2) as u32);
        }
    }
    for i in 0..ROUTERS {
        for j in 0..ROUTERS {
            if i != j && rng.below(4) == 0 {
                lab.cost(&name(i), &addr(j), 10 * (1 + rng.below(3) as u32));
            }
        }
    }
    (lab, sessions)
}

/// The source of a router in an assignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Src {
    Empty,
    Seed,
    From(usize),
}

/// The result of an enumeration: the count of stable assignments, or
/// `None` when a decision is a tie or unknown.
fn enumerate(lab: &Lab, sessions: &[(usize, usize)]) -> Option<usize> {
    let neighbours: Vec<Vec<usize>> = (0..ROUTERS)
        .map(|i| {
            sessions
                .iter()
                .filter_map(|&(a, b)| match (a == i, b == i) {
                    (true, _) => Some(b),
                    (_, true) => Some(a),
                    _ => None,
                })
                .collect()
        })
        .collect();
    let seed = |i: usize| -> Option<&Seed> { lab.input.seeds.iter().find(|s| s.device == name(i)) };
    let options: Vec<Vec<Src>> = (0..ROUTERS)
        .map(|i| {
            let mut o = vec![Src::Empty];
            if seed(i).is_some() {
                o.push(Src::Seed);
            }
            o.extend(neighbours[i].iter().map(|&n| Src::From(n)));
            o
        })
        .collect();
    let with_cost = |i: usize, offer: Offer| -> Option<BgpPath> {
        match offer {
            Offer::Path(mut p) => {
                let nh = p.next_hop.expect("a next hop");
                p.igp_cost = lab.igp.costs.get(&(name(i), nh)).copied().unwrap_or(0);
                p.spans.clear();
                Some(p)
            }
            _ => None,
        }
    };
    let key = key(P);
    // The path that router `i` receives from router `n` for the path `best`
    // of `n`.
    let over = |n: usize, i: usize, best: &BgpPath| -> Option<BgpPath> {
        let sender = lab.get(&name(n));
        let sent = export(
            sender,
            &sender.neighbors[&ip(&addr(i))],
            ip(&addr(n)),
            &key,
            best,
        );
        let Offer::Path(sent) = sent else {
            return None;
        };
        let receiver = lab.get(&name(i));
        with_cost(
            i,
            receive(
                receiver,
                &receiver.neighbors[&ip(&addr(n))],
                sender.router_id,
                &key,
                &sent,
            ),
        )
    };
    let from_seed = |i: usize| -> Option<BgpPath> {
        let s = seed(i)?;
        let p = lab.get(&name(i));
        with_cost(
            i,
            receive(
                p,
                &p.neighbors[&s.neighbor],
                s.path.peer.router_id,
                &key,
                &s.path,
            ),
        )
    };
    let mut stable = 0;
    let total: usize = options.iter().map(Vec::len).product();
    for code in 0..total {
        let mut c = code;
        let assign: Vec<Src> = options
            .iter()
            .map(|o| {
                let s = o[c % o.len()];
                c /= o.len();
                s
            })
            .collect();
        // The path of each router, from its source, with a loop as no valid
        // path.
        fn path_of(
            i: usize,
            assign: &[Src],
            depth: usize,
            from_seed: &dyn Fn(usize) -> Option<BgpPath>,
            over: &dyn Fn(usize, usize, &BgpPath) -> Option<BgpPath>,
        ) -> Result<Option<BgpPath>, ()> {
            if depth > ROUTERS {
                return Err(());
            }
            match assign[i] {
                Src::Empty => Ok(None),
                Src::Seed => from_seed(i).map(Some).ok_or(()),
                Src::From(n) => {
                    let Some(b) = path_of(n, assign, depth + 1, from_seed, over)? else {
                        return Err(());
                    };
                    over(n, i, &b).map(Some).ok_or(())
                }
            }
        }
        let paths: Result<Vec<Option<BgpPath>>, ()> = (0..ROUTERS)
            .map(|i| path_of(i, &assign, 0, &from_seed, &over))
            .collect();
        let Ok(paths) = paths else {
            continue;
        };
        let mut ok = true;
        for i in 0..ROUTERS {
            let mut cands: Vec<(Src, BgpPath)> = Vec::new();
            if let Some(p) = from_seed(i) {
                cands.push((Src::Seed, p));
            }
            for &n in &neighbours[i] {
                if let Some(b) = &paths[n]
                    && let Some(p) = over(n, i, b)
                {
                    cands.push((Src::From(n), p));
                }
            }
            let chosen = match cands.len() {
                0 => Src::Empty,
                _ => {
                    let list: Vec<BgpPath> = cands.iter().map(|(_, p)| p.clone()).collect();
                    let p = lab.get(&name(i));
                    match decide(&list, &p.options, p.profile().as_ref()) {
                        Decision::Best { best, .. } => cands[best].0,
                        Decision::NoCandidate => Src::Empty,
                        Decision::Tie { .. } | Decision::Unknown(_) => return None,
                    }
                }
            };
            if chosen != assign[i] {
                ok = false;
                break;
            }
        }
        if ok {
            stable += 1;
        }
    }
    Some(stable)
}

#[test]
fn the_result_of_each_reflector_instance_agrees_with_the_enumeration() {
    let mut rng = Rng(0x5eed_0f_0123);
    let mut checked = 0;
    let mut unique = 0;
    for case in 0..120 {
        let (lab, sessions) = instance(&mut rng);
        let Some(count) = enumerate(&lab, &sessions) else {
            continue;
        };
        checked += 1;
        let r = lab.run();
        let kind = r
            .groups
            .iter()
            .map(|g| g.convergence.kind())
            .max()
            .unwrap_or(ConvergenceKind::Converged);
        let want = match count {
            0 => ConvergenceKind::NoConvergence,
            1 => ConvergenceKind::Converged,
            _ => ConvergenceKind::MultipleStableOutcomes,
        };
        assert_eq!(
            kind, want,
            "case {case}: {count} stable assignments, {:?}",
            r.groups
        );
        if count == 1 {
            unique += 1;
            for i in 0..ROUTERS {
                assert!(
                    !matches!(state(&r, &name(i), P), Some(RouteState::Unknown(_))),
                    "case {case}: r{i}"
                );
            }
        }
    }
    assert!(checked >= 60, "{checked} instances checked");
    assert!(unique >= 20, "{unique} instances with 1 stable assignment");
}
