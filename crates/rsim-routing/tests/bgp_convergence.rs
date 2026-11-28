//! The convergence detection on the gadgets of Griffin, Shepherd and
//! Wilfong, the MED oscillations of RFC 3345 and generated stable-paths
//! instances against an enumeration of the stable assignments.

mod bgp_common;

use std::collections::BTreeSet;

use bgp_common::*;
use rsim_routing::Platform;
use rsim_routing::bgp::converge::{NOT_CHECKED, NOT_SAFE};
use rsim_routing::bgp::{Asn, BgpResult, Convergence, Event, Reason, RouteState};

fn spp(perm: &[&[&[usize]]]) -> Spp {
    let mut p = vec![Vec::new()];
    p.extend(
        perm.iter()
            .map(|paths| paths.iter().map(|x| x.to_vec()).collect()),
    );
    Spp { perm: p }
}

fn only_group(r: &BgpResult) -> &Convergence {
    assert_eq!(r.groups.len(), 1);
    &r.groups[0].convergence
}

#[test]
fn good_gadget_converges_to_its_unique_solution() {
    let s = spp(&[
        &[&[1, 3, 0], &[1, 0]],
        &[&[2, 1, 0], &[2, 0]],
        &[&[3, 0], &[3, 2, 0]],
    ]);
    let stable = spp_stable(&s);
    assert_eq!(stable.len(), 1);
    assert_eq!(
        stable[0],
        vec![
            Some(vec![0]),
            Some(vec![1, 3, 0]),
            Some(vec![2, 0]),
            Some(vec![3, 0])
        ]
    );
    let r = spp_lab(&s).run();
    assert_eq!(only_group(&r), &Convergence::Converged { note: None });
    assert!(r.groups[0].fixed_point);
    assert_eq!(spp_paths(&s, &r.routes), stable[0]);
}

#[test]
fn bad_gadget_has_no_convergence_and_its_routes_are_unknown() {
    let s = spp(&[
        &[&[1, 3, 0], &[1, 0]],
        &[&[2, 1, 0], &[2, 0]],
        &[&[3, 2, 0], &[3, 0]],
    ]);
    assert!(spp_stable(&s).is_empty());
    let r = spp_lab(&s).run();
    let Convergence::NoConvergence { cycle } = only_group(&r) else {
        panic!("{:?}", r.groups[0].convergence);
    };
    assert!(cycle.length >= 2);
    assert!(!cycle.changing.is_empty());
    let unknown = state(&r, "n1", SPP_PREFIX).unwrap();
    let RouteState::Unknown(u) = unknown else {
        panic!("{unknown:?}");
    };
    assert_eq!(u.reason, Reason::NoConvergence);
    assert!(r.affected.contains(&key(SPP_PREFIX)));
    assert!(r.events.iter().any(|e| matches!(e, Event::Search { .. })));
}

#[test]
fn disagree_has_exactly_2_stable_outcomes() {
    let s = spp(&[&[&[1, 2, 0], &[1, 0]], &[&[2, 1, 0], &[2, 0]]]);
    let stable = spp_stable(&s);
    assert_eq!(stable.len(), 2);
    let r = spp_lab(&s).run();
    let Convergence::MultipleStableOutcomes { outcomes } = only_group(&r) else {
        panic!("{:?}", r.groups[0].convergence);
    };
    let got: BTreeSet<_> = outcomes.iter().map(|o| spp_paths(&s, &o.routes)).collect();
    let want: BTreeSet<_> = stable.into_iter().collect();
    assert_eq!(got, want);
    assert!(matches!(
        state(&r, "n1", SPP_PREFIX),
        Some(RouteState::Unknown(u)) if u.reason == Reason::MultipleStableOutcomes
    ));
}

#[test]
fn a_unique_solution_with_a_dispute_wheel_converges_with_the_note() {
    let s = spp(&[
        &[&[1, 0], &[1, 3, 0]],
        &[&[2, 3, 0], &[2, 0], &[2, 1, 0]],
        &[&[3, 2, 1, 0], &[3, 0], &[3, 2, 0]],
    ]);
    let stable = spp_stable(&s);
    assert_eq!(stable.len(), 1);
    let r = spp_lab(&s).run();
    let Convergence::Converged { note: Some(note) } = only_group(&r) else {
        panic!("{:?}", r.groups[0].convergence);
    };
    assert_eq!(note.text, NOT_SAFE);
    let wheel: BTreeSet<_> = note.wheel.iter().map(|w| w.at.device.clone()).collect();
    assert_eq!(wheel, BTreeSet::from(["n2".to_string(), "n3".to_string()]));
    assert_eq!(spp_paths(&s, &r.routes), stable[0]);
}

/// Figure 1 of RFC 3345: the route reflectors Ra with the clients Rb and
/// Rc, and Rd with the client Re, in one AS, with the MEDs and the IGP
/// costs of the figure.
fn rfc3345_type_1(always_compare_med: bool) -> Lab {
    let mut lab = Lab::default();
    for (d, rid) in [
        ("ra", "10.255.0.1"),
        ("rb", "10.255.0.2"),
        ("rc", "10.255.0.3"),
        ("rd", "10.255.0.4"),
        ("re", "10.255.0.5"),
    ] {
        lab.router(d, Platform::Nxos, 65001, rid)
            .options
            .always_compare_med = always_compare_med;
    }
    lab.peer("ra", "10.1.2.1", "rb", "10.1.2.2");
    lab.peer("ra", "10.1.3.1", "rc", "10.1.3.3");
    lab.peer("ra", "10.1.4.1", "rd", "10.1.4.4");
    lab.peer("rd", "10.4.5.4", "re", "10.4.5.5");
    lab.neighbor_mut("ra", "10.1.2.2").route_reflector_client = true;
    lab.neighbor_mut("ra", "10.1.3.3").route_reflector_client = true;
    lab.neighbor_mut("rd", "10.4.5.5").route_reflector_client = true;
    lab.seed("rb", "192.0.2.10", 10, SPP_PREFIX, &[10, 100], Some(10));
    lab.seed("rc", "192.0.2.6", 6, SPP_PREFIX, &[6, 100], Some(1));
    lab.seed("re", "198.51.100.6", 6, SPP_PREFIX, &[6, 100], Some(0));
    for (d, costs) in [
        ("ra", [5, 4, 13]),
        ("rb", [0, 9, 18]),
        ("rc", [9, 0, 17]),
        ("rd", [6, 5, 12]),
        ("re", [18, 17, 0]),
    ] {
        for (nh, c) in ["192.0.2.10", "192.0.2.6", "198.51.100.6"]
            .iter()
            .zip(costs)
        {
            lab.cost(d, nh, c);
        }
    }
    lab
}

#[test]
fn rfc_3345_type_1_route_reflection_with_med_has_no_convergence() {
    let r = rfc3345_type_1(false).run();
    assert!(
        matches!(only_group(&r), Convergence::NoConvergence { .. }),
        "{:?}",
        r.groups[0].convergence
    );
}

#[test]
fn rfc_3345_type_1_with_always_compare_med_converges_on_the_exit_of_re() {
    let r = rfc3345_type_1(true).run();
    assert!(
        matches!(only_group(&r), Convergence::Converged { .. }),
        "{:?}",
        r.groups[0].convergence
    );
    for d in ["ra", "rb", "rc", "rd", "re"] {
        assert_eq!(
            best(&r, d, SPP_PREFIX).unwrap().best.next_hop,
            Some(ip("198.51.100.6")),
            "{d}"
        );
    }
}

/// Figure 3 of RFC 3345: the member ASs 65500 (Rc, Rd), 65501 (Ra, Rb)
/// and 65502 (Re, Rf, Rg) of the confederation AS 1, with the MEDs and the
/// IGP costs of the figure.
fn rfc3345_type_2(always_compare_med: bool) -> Lab {
    let mut lab = Lab::default();
    let members = [65500, 65501, 65502];
    for (d, asn, rid) in [
        ("ra", 65501, "10.255.0.1"),
        ("rb", 65501, "10.255.0.2"),
        ("rc", 65500, "10.255.0.3"),
        ("rd", 65500, "10.255.0.4"),
        ("re", 65502, "10.255.0.5"),
        ("rf", 65502, "10.255.0.6"),
        ("rg", 65502, "10.255.0.7"),
    ] {
        let p = lab.router(d, Platform::Nxos, asn, rid);
        p.options.always_compare_med = always_compare_med;
        p.confederation_id = Some(Asn(1));
        p.confederation_peers = members
            .iter()
            .filter(|&&m| m != asn)
            .map(|&m| Asn(m))
            .collect();
    }
    lab.peer("ra", "10.1.2.1", "rb", "10.1.2.2");
    lab.peer("rb", "10.2.3.2", "rc", "10.2.3.3");
    lab.peer("rc", "10.3.4.3", "rd", "10.3.4.4");
    lab.peer("rd", "10.4.5.4", "re", "10.4.5.5");
    lab.peer("re", "10.5.6.5", "rf", "10.5.6.6");
    lab.peer("re", "10.5.7.5", "rg", "10.5.7.7");
    lab.peer("rf", "10.6.7.6", "rg", "10.6.7.7");
    lab.seed("ra", "192.0.2.200", 200, SPP_PREFIX, &[200, 400], Some(0));
    lab.seed("rg", "192.0.2.201", 200, SPP_PREFIX, &[200, 400], Some(1));
    lab.seed("rf", "192.0.2.30", 300, SPP_PREFIX, &[300, 400], None);
    for (d, costs) in [
        ("ra", [0, 94, 95]),
        ("rb", [10, 84, 85]),
        ("rc", [50, 44, 45]),
        ("rd", [52, 42, 43]),
        ("re", [92, 2, 3]),
        ("rf", [95, 5, 0]),
        ("rg", [94, 0, 5]),
    ] {
        for (nh, c) in ["192.0.2.200", "192.0.2.201", "192.0.2.30"]
            .iter()
            .zip(costs)
        {
            lab.cost(d, nh, c);
        }
    }
    lab
}

#[test]
fn rfc_3345_type_2_confederation_with_med_has_no_convergence() {
    let r = rfc3345_type_2(false).run();
    assert!(
        matches!(only_group(&r), Convergence::NoConvergence { .. }),
        "{:?}",
        r.groups[0].convergence
    );
}

#[test]
fn rfc_3345_type_2_with_always_compare_med_converges() {
    let r = rfc3345_type_2(true).run();
    assert!(
        matches!(only_group(&r), Convergence::Converged { .. }),
        "{:?}",
        r.groups[0].convergence
    );
    for (d, nh) in [
        ("ra", "192.0.2.200"),
        ("rb", "192.0.2.200"),
        ("rc", "192.0.2.30"),
        ("rd", "192.0.2.30"),
        ("re", "192.0.2.30"),
        ("rf", "192.0.2.30"),
        ("rg", "192.0.2.30"),
    ] {
        assert_eq!(
            best(&r, d, SPP_PREFIX).unwrap().best.next_hop,
            Some(ip(nh)),
            "{d}"
        );
    }
    let rc = best(&r, "rc", SPP_PREFIX).unwrap();
    assert_eq!(rc.best.as_path.to_string(), "(65502) 300 400");
}

#[test]
fn disagree_between_2_reflector_clusters_has_2_stable_outcomes() {
    let mut lab = Lab::default();
    for (d, rid) in [
        ("rr1", "10.255.0.1"),
        ("rr2", "10.255.0.2"),
        ("c1", "10.255.0.11"),
        ("c2", "10.255.0.12"),
    ] {
        lab.router(d, Platform::Iosxe, 65001, rid);
    }
    lab.peer("rr1", "10.1.2.1", "rr2", "10.1.2.2");
    lab.peer("rr1", "10.1.11.1", "c1", "10.1.11.11");
    lab.peer("rr2", "10.2.12.2", "c2", "10.2.12.12");
    lab.neighbor_mut("rr1", "10.1.11.11").route_reflector_client = true;
    lab.neighbor_mut("rr2", "10.2.12.12").route_reflector_client = true;
    lab.seed("c1", "192.0.2.1", 64500, SPP_PREFIX, &[64500], None);
    lab.seed("c2", "192.0.2.2", 64500, SPP_PREFIX, &[64500], None);
    lab.cost("rr1", "192.0.2.1", 10);
    lab.cost("rr1", "192.0.2.2", 5);
    lab.cost("rr2", "192.0.2.1", 5);
    lab.cost("rr2", "192.0.2.2", 10);
    lab.cost("c1", "192.0.2.2", 15);
    lab.cost("c2", "192.0.2.1", 15);
    let r = lab.run();
    let Convergence::MultipleStableOutcomes { outcomes } = only_group(&r) else {
        panic!("{:?}", r.groups[0].convergence);
    };
    let exits: BTreeSet<Vec<_>> = outcomes
        .iter()
        .map(|o| {
            ["rr1", "rr2"]
                .iter()
                .map(|d| {
                    let at = rsim_routing::bgp::RouteAt {
                        device: d.to_string(),
                        vrf: "default".to_string(),
                        key: key(SPP_PREFIX),
                    };
                    match &o.routes[&at] {
                        RouteState::Selected(s) => s.best.next_hop,
                        RouteState::Unknown(u) => panic!("{u}"),
                    }
                })
                .collect()
        })
        .collect();
    assert_eq!(
        exits,
        BTreeSet::from([
            vec![Some(ip("192.0.2.1")), Some(ip("192.0.2.1"))],
            vec![Some(ip("192.0.2.2")), Some(ip("192.0.2.2"))],
        ])
    );
}

#[test]
fn a_chain_of_201_routers_converges_after_more_than_200_rounds() {
    let mut lab = Lab::default();
    for i in 0..=200u32 {
        lab.router(
            &format!("r{i:03}"),
            Platform::Iosxe,
            65000 + i,
            &format!("10.255.{}.{}", i / 256, i % 256),
        );
    }
    for i in 0..200u32 {
        lab.peer(
            &format!("r{i:03}"),
            &format!("10.{}.{}.1", i / 256, i % 256),
            &format!("r{:03}", i + 1),
            &format!("10.{}.{}.2", i / 256, i % 256),
        );
    }
    lab.originate("r000", SPP_PREFIX);
    let r = lab.run();
    assert_eq!(only_group(&r), &Convergence::Converged { note: None });
    let last = r
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Round { round, changed, .. } if !changed.is_empty() => Some(*round),
            _ => None,
        })
        .max();
    assert_eq!(last, Some(201));
    assert!(r.groups[0].rounds > 201);
    assert_eq!(as_path_of(&r, "r200", SPP_PREFIX).unwrap().len(), 200);
}

/// All simple paths from `u` to 0 over the nodes `0..n`.
fn simple_paths(u: usize, n: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut stack = vec![vec![u]];
    while let Some(p) = stack.pop() {
        for v in 0..n {
            if p.contains(&v) {
                continue;
            }
            let mut q = p.clone();
            q.push(v);
            if v == 0 {
                out.push(q);
            } else {
                stack.push(q);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn generated_instances_give_the_stable_assignments_of_the_definition() {
    let mut rng = Rng(0x5eed_0bad_9a4d_9e75);
    let mut kinds = [0usize; 3];
    let mut searched = 0;
    let mut cases = vec![
        spp(&[
            &[&[1, 3, 0], &[1, 0]],
            &[&[2, 1, 0], &[2, 0]],
            &[&[3, 2, 0], &[3, 0]],
        ]),
        spp(&[&[&[1, 2, 0], &[1, 0]], &[&[2, 1, 0], &[2, 0]]]),
    ];
    for _ in 0..160 {
        let n = 2 + rng.below(4) as usize;
        let mut perm = vec![Vec::new()];
        for u in 1..n {
            let mut all = simple_paths(u, n);
            let k = 1 + rng.below(3) as usize;
            let mut chosen = Vec::new();
            while chosen.len() < k && !all.is_empty() {
                let i = rng.below(all.len() as u64) as usize;
                chosen.push(all.remove(i));
            }
            if cases.len() % 2 == 1 {
                chosen.sort_by_key(|p: &Vec<usize>| std::cmp::Reverse(p.len()));
            }
            perm.push(chosen);
        }
        cases.push(Spp { perm });
    }
    for (case, s) in cases.iter().enumerate() {
        let s = s.clone();
        let stable = spp_stable(&s);
        let r = spp_lab(&s).run();
        let conv = only_group(&r);
        if r.events.iter().any(|e| matches!(e, Event::Search { .. })) {
            searched += 1;
        }
        match stable.len() {
            0 => {
                kinds[2] += 1;
                assert!(
                    matches!(conv, Convergence::NoConvergence { .. }),
                    "case {case} {s:?}: {conv:?}"
                );
            }
            1 => {
                kinds[0] += 1;
                assert!(
                    matches!(conv, Convergence::Converged { .. }),
                    "case {case} {s:?}: {conv:?}"
                );
                assert_eq!(spp_paths(&s, &r.routes), stable[0], "case {case} {s:?}");
            }
            _ => {
                kinds[1] += 1;
                let Convergence::MultipleStableOutcomes { outcomes } = conv else {
                    panic!("case {case} {s:?}: {conv:?}");
                };
                let got: BTreeSet<_> = outcomes.iter().map(|o| spp_paths(&s, &o.routes)).collect();
                assert_eq!(got.len(), outcomes.len(), "case {case}");
                let want: BTreeSet<_> = stable.iter().cloned().collect();
                assert_eq!(got, want, "case {case} {s:?}");
            }
        }
        if let Convergence::Converged { .. } = conv
            && r.groups[0].fixed_point
        {
            assert_eq!(spp_paths(&s, &r.routes), stable[0], "case {case}");
        }
    }
    assert!(kinds.iter().all(|&k| k > 0), "{kinds:?}");
    assert!(searched >= 10, "{searched}");
}

#[test]
fn the_same_input_in_another_order_gives_the_same_result() {
    let mut lab = rfc3345_type_1(false);
    lab.originate("ra", "192.0.2.128/25");
    lab.originate("rd", "192.0.2.128/25");
    let a = lab.run();
    let mut shuffled = lab.clone();
    shuffled.input.processes.reverse();
    shuffled.input.processes.rotate_left(3);
    shuffled.input.sessions.reverse();
    for s in &mut shuffled.input.sessions {
        std::mem::swap(&mut s.a, &mut s.b);
    }
    shuffled.input.seeds.reverse();
    let b = shuffled.run();
    assert_eq!(format!("{a:?}"), format!("{b:?}"));
    assert_eq!(format!("{a:?}"), format!("{:?}", lab.run()));
    assert_eq!(a.groups.len(), 2);
    assert_eq!(a.worst, rsim_routing::bgp::ConvergenceKind::NoConvergence);
}

#[test]
fn disagree_inside_one_reflector_cluster_has_2_stable_outcomes() {
    use rsim_routing::bgp::{Clause, PolicyBody, RoutePolicy, SetAction};
    let mut lab = Lab::default();
    for (d, rid) in [
        ("rr", "10.255.0.1"),
        ("c1", "10.255.0.11"),
        ("c2", "10.255.0.12"),
    ] {
        lab.router(d, Platform::Iosxe, 65001, rid);
    }
    lab.peer("rr", "10.1.11.1", "c1", "10.1.11.11");
    lab.peer("rr", "10.1.12.1", "c2", "10.1.12.12");
    lab.neighbor_mut("rr", "10.1.11.11").route_reflector_client = true;
    lab.neighbor_mut("rr", "10.1.12.12").route_reflector_client = true;
    lab.seed("c1", "192.0.2.1", 64500, SPP_PREFIX, &[64500], None);
    lab.seed("c2", "192.0.2.2", 64500, SPP_PREFIX, &[64500], None);
    for (c, rr) in [("c1", "10.1.11.1"), ("c2", "10.1.12.1")] {
        let mut cl = Clause::new(10, true);
        cl.sets.push(SetAction::LocalPref(200));
        lab.proc(c).policy.policies.insert(
            "from-rr".to_string(),
            RoutePolicy {
                name: "from-rr".to_string(),
                body: PolicyBody::RouteMap(vec![cl]),
                spans: Vec::new(),
            },
        );
        lab.neighbor_mut(c, rr).import_policy = Some("from-rr".to_string());
    }
    let r = lab.run();
    assert!(r.groups[0].fixed_point);
    let Convergence::MultipleStableOutcomes { outcomes } = only_group(&r) else {
        panic!("{:?}", r.groups[0].convergence);
    };
    let exits: BTreeSet<Vec<_>> = outcomes
        .iter()
        .map(|o| {
            o.routes
                .values()
                .map(|s| match s {
                    RouteState::Selected(s) => s.best.next_hop,
                    RouteState::Unknown(u) => panic!("{u}"),
                })
                .collect()
        })
        .collect();
    assert_eq!(
        exits,
        BTreeSet::from([
            vec![Some(ip("192.0.2.1")); 3],
            vec![Some(ip("192.0.2.2")); 3],
        ])
    );
}

/// A route reflector `rrx` with the client `cx` that holds no path of the
/// instance.
fn add_reflector_pair(lab: &mut Lab) {
    lab.router("rrx", Platform::Iosxe, 65100, "10.255.1.1");
    lab.router("cx", Platform::Iosxe, 65100, "10.255.1.2");
    lab.peer("rrx", "10.100.0.1", "cx", "10.100.0.2");
    lab.neighbor_mut("rrx", "10.100.0.2").route_reflector_client = true;
}

#[test]
fn a_reflector_with_no_path_of_the_group_keeps_the_uniqueness_check() {
    let good = spp(&[
        &[&[1, 3, 0], &[1, 0]],
        &[&[2, 1, 0], &[2, 0]],
        &[&[3, 0], &[3, 2, 0]],
    ]);
    let mut lab = spp_lab(&good);
    add_reflector_pair(&mut lab);
    let r = lab.run();
    assert_eq!(only_group(&r), &Convergence::Converged { note: None });
    assert!(!r.events.iter().any(|e| matches!(e, Event::Search { .. })));
    let wheel = spp(&[
        &[&[1, 0], &[1, 3, 0]],
        &[&[2, 3, 0], &[2, 0], &[2, 1, 0]],
        &[&[3, 2, 1, 0], &[3, 0], &[3, 2, 0]],
    ]);
    let mut lab = spp_lab(&wheel);
    add_reflector_pair(&mut lab);
    let r = lab.run();
    let Convergence::Converged { note: Some(note) } = only_group(&r) else {
        panic!("{:?}", r.groups[0].convergence);
    };
    assert_eq!(note.wheel.len(), 2);
}

/// The router `r1` on IOS-XE with the 3 iBGP paths of a MED cycle: P1 from
/// 198.51.100.1 (AS 64500, MED 10, IGP cost 10), P2 from 198.51.100.2 (AS
/// 64501, IGP cost 20) and P3 from 198.51.100.3 (AS 64500, MED 5, IGP cost
/// 30).
fn med_cycle(deterministic_med: Option<bool>) -> Lab {
    let mut lab = Lab::default();
    lab.router("r1", Platform::Iosxe, 65001, "10.255.0.1")
        .options
        .deterministic_med = deterministic_med;
    for (addr, as_path, med, cost) in [
        ("198.51.100.1", 64500, Some(10), 10),
        ("198.51.100.2", 64501, None, 20),
        ("198.51.100.3", 64500, Some(5), 30),
    ] {
        lab.seed("r1", addr, 65001, SPP_PREFIX, &[as_path], med);
        lab.cost("r1", addr, cost);
    }
    lab
}

#[test]
fn a_med_cycle_with_no_deterministic_med_has_one_outcome_for_each_order_winner() {
    let r = med_cycle(None).run();
    let Convergence::MultipleStableOutcomes { outcomes } = only_group(&r) else {
        panic!("{:?}", r.groups[0].convergence);
    };
    let at = rsim_routing::bgp::RouteAt {
        device: "r1".to_string(),
        vrf: "default".to_string(),
        key: key(SPP_PREFIX),
    };
    let hops: BTreeSet<_> = outcomes
        .iter()
        .map(|o| match &o.routes[&at] {
            RouteState::Selected(s) => s.best.next_hop,
            RouteState::Unknown(u) => panic!("{u}"),
        })
        .collect();
    assert_eq!(
        hops,
        BTreeSet::from([
            Some(ip("198.51.100.1")),
            Some(ip("198.51.100.2")),
            Some(ip("198.51.100.3")),
        ])
    );
    assert!(matches!(
        state(&r, "r1", SPP_PREFIX),
        Some(RouteState::Unknown(u)) if u.reason == Reason::MultipleStableOutcomes
    ));
    assert!(r.affected.contains(&key(SPP_PREFIX)));
}

#[test]
fn a_med_cycle_with_deterministic_med_converges_on_p2_with_the_unchecked_note() {
    let r = med_cycle(Some(true)).run();
    let Convergence::Converged { note: Some(note) } = only_group(&r) else {
        panic!("{:?}", r.groups[0].convergence);
    };
    assert_eq!(note.text, NOT_CHECKED);
    assert!(note.wheel.is_empty());
    assert!(r.groups[0].fixed_point);
    assert_eq!(
        best(&r, "r1", SPP_PREFIX).unwrap().best.next_hop,
        Some(ip("198.51.100.2"))
    );
}

#[test]
fn no_convergence_makes_a_route_unknown_that_no_round_of_the_cycle_holds() {
    let s = spp(&[
        &[&[1, 3, 0], &[1, 0], &[1, 2, 0]],
        &[&[2, 1, 0], &[2, 0]],
        &[&[3, 2, 0], &[3, 0]],
        &[&[4, 1, 2, 0]],
    ]);
    assert!(spp_stable(&s).is_empty());
    let r = spp_lab(&s).run();
    let Convergence::NoConvergence { cycle } = only_group(&r) else {
        panic!("{:?}", r.groups[0].convergence);
    };
    assert!(!cycle.changing.keys().any(|at| at.device == "n4"));
    assert!(matches!(
        state(&r, "n4", SPP_PREFIX),
        Some(RouteState::Unknown(u)) if u.reason == Reason::NoConvergence
    ));
}

#[test]
fn an_unhandled_term_inside_bad_gadget_gives_an_unknown_convergence() {
    use rsim_routing::bgp::{ConvergenceKind, MatchTerm, PolicyBody};
    let s = spp(&[
        &[&[1, 3, 0], &[1, 0]],
        &[&[2, 1, 0], &[2, 0]],
        &[&[3, 2, 0], &[3, 0]],
    ]);
    let mut lab = spp_lab(&s);
    let p = lab.proc("n1").policy.policies.get_mut("from-3").unwrap();
    let PolicyBody::RouteMap(clauses) = &mut p.body else {
        panic!("{:?}", p.body);
    };
    clauses[0]
        .matches
        .push(MatchTerm::Unhandled("match rpki valid".to_string()));
    let r = lab.run();
    let Convergence::Unknown { reason } = only_group(&r) else {
        panic!("{:?}", r.groups[0].convergence);
    };
    assert_eq!(reason.reason, Reason::ConvergenceNotDetermined);
    assert_eq!(r.worst, ConvergenceKind::Unknown);
    assert!(r.affected.contains(&key(SPP_PREFIX)));
    for d in ["n1", "n2", "n3"] {
        assert!(
            matches!(
                state(&r, d, SPP_PREFIX),
                Some(RouteState::Unknown(u)) if u.reason == Reason::ConvergenceNotDetermined
            ),
            "{d}: {:?}",
            state(&r, d, SPP_PREFIX)
        );
    }
}

#[test]
fn a_med_cycle_with_11_more_candidates_has_one_outcome_for_each_order_winner() {
    let mut lab = med_cycle(None);
    for i in 0..11u32 {
        let addr = format!("198.51.101.{}", i + 1);
        lab.seed("r1", &addr, 65001, SPP_PREFIX, &[64502], Some(i));
        lab.cost("r1", &addr, 100 + i);
    }
    let r = lab.run();
    let Convergence::MultipleStableOutcomes { outcomes } = only_group(&r) else {
        panic!("{:?}", r.groups[0].convergence);
    };
    let at = rsim_routing::bgp::RouteAt {
        device: "r1".to_string(),
        vrf: "default".to_string(),
        key: key(SPP_PREFIX),
    };
    let hops: BTreeSet<_> = outcomes
        .iter()
        .map(|o| match &o.routes[&at] {
            RouteState::Selected(s) => s.best.next_hop,
            RouteState::Unknown(u) => panic!("{u}"),
        })
        .collect();
    assert_eq!(
        hops,
        BTreeSet::from([
            Some(ip("198.51.100.1")),
            Some(ip("198.51.100.2")),
            Some(ip("198.51.100.3")),
        ])
    );
}

/// An iBGP mesh of x, v and w in AS 65001, with the eBGP peer y of x in AS
/// 65002. The first path of x meets an unhandled term in the import policy
/// of v and w, and the later path of x through y does not.
#[test]
fn an_unhandled_term_on_a_first_path_only_leaves_the_final_paths_known() {
    use rsim_routing::bgp::{
        AsPathLine, AsPathList, Clause, MatchTerm, PolicyBody, RoutePolicy, SetAction,
    };
    let mut lab = Lab::default();
    for (d, asn, rid) in [
        ("x", 65001, "10.255.0.1"),
        ("v", 65001, "10.255.0.2"),
        ("w", 65001, "10.255.0.3"),
        ("y", 65002, "10.255.0.4"),
    ] {
        lab.router(d, Platform::Iosxe, asn, rid);
    }
    lab.peer("x", "10.1.2.1", "v", "10.1.2.2");
    lab.peer("x", "10.1.3.1", "w", "10.1.3.3");
    lab.peer("v", "10.2.3.2", "w", "10.2.3.3");
    lab.peer("x", "10.1.4.1", "y", "10.1.4.4");
    lab.seed(
        "x",
        "192.0.2.1",
        64500,
        SPP_PREFIX,
        &[64500, 64501, 64502],
        None,
    );
    lab.seed("y", "198.51.100.1", 64600, SPP_PREFIX, &[64600], None);
    for (d, x) in [("v", "10.1.2.1"), ("w", "10.1.3.1")] {
        let p = lab.proc(d);
        p.policy.as_path_lists.insert(
            "long".to_string(),
            AsPathList::new(vec![AsPathLine::regex(1, true, "_64502$")]),
        );
        let mut odd = Clause::new(10, true);
        odd.matches
            .push(MatchTerm::AsPathList(vec!["long".to_string()]));
        odd.matches
            .push(MatchTerm::Unhandled("match rpki valid".to_string()));
        odd.sets.push(SetAction::LocalPref(200));
        p.policy.policies.insert(
            "in".to_string(),
            RoutePolicy {
                name: "in".to_string(),
                body: PolicyBody::RouteMap(vec![odd, Clause::new(20, true)]),
                spans: Vec::new(),
            },
        );
        lab.neighbor_mut(d, x).import_policy = Some("in".to_string());
    }
    let r = lab.run();
    assert!(
        matches!(only_group(&r), Convergence::Converged { .. }),
        "{:?}",
        r.groups[0].convergence
    );
    for d in ["x", "v", "w"] {
        assert_eq!(
            as_path_of(&r, d, SPP_PREFIX),
            Some(vec![65002, 64600]),
            "{d}: {:?}",
            state(&r, d, SPP_PREFIX)
        );
    }
}
