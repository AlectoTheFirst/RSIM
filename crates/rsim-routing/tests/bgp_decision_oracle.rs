//! The decision function against a second implementation in the test,
//! over each order of up to 5 generated candidates. The result does not
//! depend on the order, except with no deterministic MED and no
//! always-compare-med, where MED differs between candidates of more than
//! one neighbour AS.

mod bgp_common;

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::net::IpAddr;

use bgp_common::{Rng, ibgp, path, permutations};
use rsim_routing::Platform;
use rsim_routing::bgp::{
    AsPath, BgpOptions, BgpOrigin, BgpPath, BgpProfile, Decision, LocalOrigin, SessionKind, decide,
};

const PLATFORMS: [Platform; 5] = [
    Platform::Iosxe,
    Platform::Nxos,
    Platform::Iosxr,
    Platform::FrrTraditional,
    Platform::FrrDatacenter,
];

/// The first AS of the path, `None` for the empty path.
fn neighbour(p: &BgpPath) -> Option<u32> {
    p.as_path.flat().first().map(|a| a.0)
}

struct Oracle {
    platform: Platform,
    always: bool,
    deterministic: bool,
    missing_worst: bool,
    compare_routerid: bool,
}

impl Oracle {
    fn new(platform: Platform, o: &BgpOptions) -> Oracle {
        let deterministic = match platform {
            Platform::Iosxr => true,
            Platform::Nxos | Platform::FrrDatacenter => o.deterministic_med.unwrap_or(true),
            Platform::Iosxe | Platform::FrrTraditional => o.deterministic_med.unwrap_or(false),
        };
        Oracle {
            platform,
            always: o.always_compare_med,
            deterministic,
            missing_worst: o.missing_as_worst.unwrap_or(false),
            compare_routerid: o.compare_routerid,
        }
    }

    fn local(&self, p: &BgpPath) -> u8 {
        let frr = matches!(
            self.platform,
            Platform::FrrTraditional | Platform::FrrDatacenter
        );
        match p.peer.kind {
            SessionKind::Local(LocalOrigin::Aggregate) if !frr => 1,
            SessionKind::Local(_) => 2,
            _ => 0,
        }
    }

    /// `Greater` if `a` is better, `None` if the decision does not
    /// separate them.
    fn better(&self, a: &BgpPath, b: &BgpPath) -> Option<Ordering> {
        if a.weight != b.weight {
            return Some(a.weight.cmp(&b.weight));
        }
        let (la, lb) = (a.local_pref.unwrap_or(100), b.local_pref.unwrap_or(100));
        if la != lb {
            return Some(la.cmp(&lb));
        }
        if self.local(a) != self.local(b) {
            return Some(self.local(a).cmp(&self.local(b)));
        }
        if a.as_path.flat().len() != b.as_path.flat().len() {
            return Some(b.as_path.flat().len().cmp(&a.as_path.flat().len()));
        }
        let origin = |p: &BgpPath| match p.origin {
            BgpOrigin::Igp => 0,
            BgpOrigin::Egp => 1,
            BgpOrigin::Incomplete => 2,
        };
        if origin(a) != origin(b) {
            return Some(origin(b).cmp(&origin(a)));
        }
        if self.always || neighbour(a) == neighbour(b) {
            let missing = if self.missing_worst { u32::MAX } else { 0 };
            let (ma, mb) = (a.med.unwrap_or(missing), b.med.unwrap_or(missing));
            if ma != mb {
                return Some(mb.cmp(&ma));
            }
        }
        let ext = |p: &BgpPath| p.peer.kind == SessionKind::Ebgp;
        if ext(a) != ext(b) {
            return Some(ext(a).cmp(&ext(b)));
        }
        if a.igp_cost != b.igp_cost {
            return Some(b.igp_cost.cmp(&a.igp_cost));
        }
        if ext(a) && ext(b) && !self.compare_routerid {
            return None;
        }
        let rid = |p: &BgpPath| p.originator_id.unwrap_or(p.peer.router_id);
        if rid(a) != rid(b) {
            return Some(rid(b).cmp(&rid(a)));
        }
        if a.cluster_list.len() != b.cluster_list.len() {
            return Some(b.cluster_list.len().cmp(&a.cluster_list.len()));
        }
        let addr = |p: &BgpPath| p.peer.address.map(|a| (u8::from(a.is_ipv6()), a));
        match (addr(a), addr(b)) {
            (x, y) if x == y => None,
            (None, _) => Some(Ordering::Greater),
            (_, None) => Some(Ordering::Less),
            (Some(x), Some(y)) => Some(y.cmp(&x)),
        }
    }

    /// The paths of `set` that no path of `set` beats.
    fn top(&self, c: &[BgpPath], set: &[usize]) -> Vec<usize> {
        set.iter()
            .copied()
            .filter(|&x| {
                set.iter()
                    .all(|&y| self.better(&c[y], &c[x]) != Some(Ordering::Greater))
            })
            .collect()
    }

    fn select(&self, c: &[BgpPath]) -> Vec<usize> {
        let all: Vec<usize> = (0..c.len()).collect();
        if self.always {
            return self.top(c, &all);
        }
        if self.deterministic {
            let groups: BTreeSet<Option<u32>> = c.iter().map(neighbour).collect();
            let winners: Vec<usize> = groups
                .iter()
                .flat_map(|g| {
                    let members: Vec<usize> = all
                        .iter()
                        .copied()
                        .filter(|&i| neighbour(&c[i]) == *g)
                        .collect();
                    self.top(c, &members)
                })
                .collect();
            return self.top(c, &winners);
        }
        let mut win = vec![0];
        for i in 1..c.len() {
            match self.better(&c[i], &c[win[0]]) {
                Some(Ordering::Greater) => win = vec![i],
                None => win.push(i),
                Some(_) => {}
            }
        }
        win
    }
}

fn generate(rng: &mut Rng, n: usize) -> Vec<BgpPath> {
    (0..n)
        .map(|i| {
            let addr = format!("198.51.100.{}", i + 1);
            let kind = rng.pick(&[
                SessionKind::Ebgp,
                SessionKind::Ebgp,
                SessionKind::Ebgp,
                SessionKind::Ibgp,
                SessionKind::Ibgp,
                SessionKind::ConfedEbgp,
                SessionKind::Local(LocalOrigin::Network),
                SessionKind::Local(LocalOrigin::Aggregate),
            ]);
            let len = match kind {
                SessionKind::Ebgp => 1 + rng.below(2),
                SessionKind::Local(_) => 0,
                _ => rng.below(3),
            };
            let as_path: Vec<u32> = (0..len).map(|_| rng.pick(&[65001, 65002])).collect();
            let mut p = path(kind, &addr, &as_path);
            if matches!(kind, SessionKind::Local(_)) {
                p.peer.address = None;
            }
            p.peer.router_id = rng.pick(&[
                bgp_common::v4("192.0.2.1"),
                bgp_common::v4("192.0.2.2"),
                bgp_common::v4("192.0.2.3"),
            ]);
            p.weight = if rng.below(8) == 0 { 100 } else { 0 };
            p.local_pref = rng.pick(&[None, Some(100), Some(100), Some(200)]);
            p.origin = rng.pick(&[
                BgpOrigin::Igp,
                BgpOrigin::Igp,
                BgpOrigin::Egp,
                BgpOrigin::Incomplete,
            ]);
            p.med = rng.pick(&[None, Some(0), Some(10), Some(20)]);
            p.igp_cost = rng.pick(&[0, 10]);
            if kind == SessionKind::Ibgp && rng.below(2) == 0 {
                p.originator_id = Some(bgp_common::v4("192.0.2.9"));
                p.cluster_list = vec![bgp_common::v4("192.0.2.10"); rng.below(2) as usize];
            }
            p
        })
        .collect()
}

fn identities(c: &[BgpPath], set: &[usize]) -> BTreeSet<Option<IpAddr>> {
    set.iter().map(|&i| c[i].next_hop).collect()
}

fn chosen(d: &Decision) -> Vec<usize> {
    match d {
        Decision::Best { best, .. } => vec![*best],
        Decision::Tie { tied, .. } => tied.clone(),
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_decision_agrees_with_the_pairwise_oracle_in_each_order_of_the_candidates() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    let mut order_free = 0;
    let mut order_bound = 0;
    for case in 0..600 {
        let n = 1 + (case % 5);
        let base = generate(&mut rng, n);
        let platform = rng.pick(&PLATFORMS);
        let options = BgpOptions {
            always_compare_med: rng.below(4) == 0,
            deterministic_med: rng.pick(&[None, Some(true), Some(false)]),
            missing_as_worst: rng.pick(&[None, Some(true)]),
            compare_routerid: rng.below(2) == 0,
            ..BgpOptions::default()
        };
        let profile = BgpProfile::of(platform);
        let oracle = Oracle::new(platform, &options);
        let mut seen: BTreeSet<BTreeSet<Option<IpAddr>>> = BTreeSet::new();
        for perm in permutations(n) {
            let c: Vec<BgpPath> = perm.iter().map(|&i| base[i].clone()).collect();
            let got = chosen(&decide(&c, &options, Some(&profile)));
            let want = oracle.select(&c);
            assert_eq!(
                identities(&c, &got),
                identities(&c, &want),
                "case {case} {platform:?} {options:?} order {perm:?}"
            );
            seen.insert(identities(&c, &got));
        }
        if oracle.always || oracle.deterministic {
            assert_eq!(
                seen.len(),
                1,
                "case {case}: the result depends on the order"
            );
            order_free += 1;
        } else {
            order_bound += 1;
        }
    }
    assert!(order_free > 100 && order_bound > 100);
}

/// 3 iBGP paths where MED and the IGP cost form a cycle: P3 beats P1 by
/// MED, P2 beats P3 by the IGP cost, and P1 beats P2 by the IGP cost.
fn med_cycle() -> Vec<BgpPath> {
    let mut p1 = ibgp("198.51.100.1", &[64500]);
    p1.med = Some(10);
    p1.igp_cost = 10;
    let mut p2 = ibgp("198.51.100.2", &[64501]);
    p2.igp_cost = 20;
    let mut p3 = ibgp("198.51.100.3", &[64500]);
    p3.med = Some(5);
    p3.igp_cost = 30;
    vec![p1, p2, p3]
}

#[test]
fn with_no_deterministic_med_the_best_path_of_a_med_cycle_depends_on_the_input_order() {
    let c = med_cycle();
    let profile = BgpProfile::of(Platform::Iosxe);
    let options = BgpOptions::default();
    let best = |order: [usize; 3]| {
        let ordered: Vec<BgpPath> = order.iter().map(|&i| c[i].clone()).collect();
        order[chosen(&decide(&ordered, &options, Some(&profile)))[0]]
    };
    assert_eq!(best([0, 1, 2]), 2);
    assert_eq!(best([2, 0, 1]), 1);
    assert_eq!(best([1, 2, 0]), 0);
}

#[test]
fn with_deterministic_med_the_best_path_of_a_med_cycle_is_the_same_in_each_order() {
    let c = med_cycle();
    let options = BgpOptions {
        deterministic_med: Some(true),
        ..BgpOptions::default()
    };
    for platform in PLATFORMS {
        let profile = BgpProfile::of(platform);
        for perm in permutations(3) {
            let ordered: Vec<BgpPath> = perm.iter().map(|&i| c[i].clone()).collect();
            let got = chosen(&decide(&ordered, &options, Some(&profile)));
            assert_eq!(perm[got[0]], 1, "{platform:?} {perm:?}");
        }
    }
}

#[test]
fn two_paths_with_the_empty_as_path_compare_their_med() {
    let mut a = ibgp("198.51.100.1", &[]);
    a.med = Some(50);
    let mut b = ibgp("198.51.100.2", &[]);
    b.med = Some(10);
    b.igp_cost = 5;
    assert_eq!(a.as_path, AsPath::default());
    let profile = BgpProfile::of(Platform::Iosxe);
    let d = decide(&[a, b], &BgpOptions::default(), Some(&profile));
    assert!(matches!(d, Decision::Best { best: 1, .. }), "{d:?}");
}
