//! The decision function, the BGP profiles and the AS numbers.
//!
//! The decision cases are ported from HST `tests/test_simul_bestpath.py`
//! with documentation addresses, and the AS number cases from HST
//! `tests/test_bgp_asdot.py`. The expected results are not confirmed
//! against a device.

mod bgp_common;

use bgp_common::{ebgp, ibgp, ip, key, path, v4};
use rsim_routing::Platform;
use rsim_routing::bgp::{
    AsPath, AsSegment, Asn, BgpOptions, BgpOrigin, BgpPath, BgpProcess, BgpProfile, Decision,
    DecisionStage, DecisionStep, Direction, Family, LocalAs, LocalOrigin, MatchReads, Neighbor,
    PolicyResult, Reason, RoutingStage, SegmentKind, SessionKind, UndefinedPolicy, decide,
    neighbor_policy,
};

const PLATFORMS: [Platform; 5] = [
    Platform::Iosxe,
    Platform::Nxos,
    Platform::Iosxr,
    Platform::FrrTraditional,
    Platform::FrrDatacenter,
];

fn best_of(c: &[BgpPath], options: &BgpOptions, platform: Platform) -> Decision {
    decide(c, options, Some(&BgpProfile::of(platform)))
}

/// The index of the path that wins, in both orders of the 2 paths. `None`
/// for a tie.
fn preferred(a: &BgpPath, b: &BgpPath) -> Option<usize> {
    let pick = |c: &[BgpPath]| match best_of(c, &BgpOptions::default(), Platform::Iosxe) {
        Decision::Best { best, .. } => Some(best),
        Decision::Tie { .. } => None,
        other => panic!("{other:?}"),
    };
    let forward = pick(&[a.clone(), b.clone()]);
    let backward = pick(&[b.clone(), a.clone()]).map(|i| 1 - i);
    assert_eq!(forward, backward);
    forward
}

fn local(kind: LocalOrigin) -> BgpPath {
    let mut p = path(SessionKind::Local(kind), "192.0.2.254", &[]);
    p.peer.address = None;
    p
}

#[test]
fn weight_wins_first() {
    let mut a = ebgp("192.0.2.1", &[64500]);
    a.weight = 100;
    let mut b = ebgp("192.0.2.2", &[64500]);
    b.local_pref = Some(500);
    assert_eq!(preferred(&a, &b), Some(0));
}

#[test]
fn local_preference_beats_as_path_length() {
    let mut a = ibgp("192.0.2.1", &[64500, 64501, 64502]);
    a.local_pref = Some(200);
    let b = ibgp("192.0.2.2", &[64500]);
    assert_eq!(preferred(&a, &b), Some(0));
}

#[test]
fn local_origination_ranks_after_local_preference_and_before_as_path_length() {
    let network = local(LocalOrigin::Network);
    let mut learned = ibgp("192.0.2.1", &[]);
    assert_eq!(preferred(&network, &learned), Some(0));
    learned.local_pref = Some(200);
    assert_eq!(preferred(&network, &learned), Some(1));
}

#[test]
fn a_network_path_ranks_above_an_aggregate_on_cisco_and_equal_to_it_on_frr() {
    let network = local(LocalOrigin::Network);
    let aggregate = local(LocalOrigin::Aggregate);
    assert_eq!(preferred(&network, &aggregate), Some(0));
    assert_eq!(preferred(&aggregate, &ibgp("192.0.2.1", &[])), Some(0));
    for platform in [Platform::FrrTraditional, Platform::FrrDatacenter] {
        let d = best_of(
            &[aggregate.clone(), network.clone()],
            &BgpOptions::default(),
            platform,
        );
        assert!(
            matches!(
                d,
                Decision::Tie {
                    step: DecisionStep::NeighborAddress,
                    ..
                }
            ),
            "{d:?}"
        );
    }
}

#[test]
fn the_shorter_as_path_wins_and_an_as_set_counts_1_and_a_confederation_segment_0() {
    let short = ebgp("192.0.2.1", &[64500]);
    assert_eq!(
        preferred(&short, &ebgp("192.0.2.2", &[64500, 64501])),
        Some(0)
    );
    let seg = |kind, asns: &[u32]| AsSegment {
        kind,
        asns: asns.iter().map(|&a| Asn(a)).collect(),
    };
    let with_set = AsPath {
        segments: vec![
            seg(SegmentKind::Sequence, &[64500]),
            seg(SegmentKind::Set, &[64501, 64502, 64503]),
        ],
    };
    assert_eq!(with_set.len(), 2);
    let with_confed = AsPath {
        segments: vec![
            seg(SegmentKind::ConfedSequence, &[65001, 65002]),
            seg(SegmentKind::Sequence, &[64500]),
        ],
    };
    assert_eq!(with_confed.len(), 1);
    let mut a = ibgp("192.0.2.1", &[]);
    a.as_path = with_set;
    let mut b = ibgp("192.0.2.2", &[]);
    b.as_path = with_confed;
    b.igp_cost = 50;
    assert_eq!(preferred(&a, &b), Some(1));
}

#[test]
fn the_origin_ranks_igp_over_egp_over_incomplete() {
    let mut igp = ibgp("192.0.2.3", &[64500]);
    igp.origin = BgpOrigin::Igp;
    let mut egp = ibgp("192.0.2.2", &[64500]);
    egp.origin = BgpOrigin::Egp;
    let mut incomplete = ibgp("192.0.2.1", &[64500]);
    incomplete.origin = BgpOrigin::Incomplete;
    assert_eq!(preferred(&igp, &egp), Some(0));
    assert_eq!(preferred(&egp, &incomplete), Some(0));
}

#[test]
fn ebgp_beats_ibgp_and_confederation_ebgp() {
    let e = ebgp("192.0.2.9", &[64500]);
    assert_eq!(preferred(&e, &ibgp("192.0.2.1", &[64500])), Some(0));
    let confed = path(SessionKind::ConfedEbgp, "192.0.2.2", &[64500]);
    assert_eq!(preferred(&e, &confed), Some(0));
    let d = best_of(
        &[confed, ibgp("192.0.2.1", &[64500])],
        &BgpOptions::default(),
        Platform::Iosxe,
    );
    assert!(
        matches!(
            d,
            Decision::Best {
                best: 1,
                step: Some(DecisionStep::RouterId),
                ..
            }
        ),
        "{d:?}"
    );
}

#[test]
fn the_lower_med_wins_within_the_same_neighbour_as_only() {
    let mut low = ibgp("192.0.2.2", &[64500, 3]);
    low.med = Some(10);
    let mut high = ibgp("192.0.2.1", &[64500, 4]);
    high.med = Some(50);
    assert_eq!(preferred(&low, &high), Some(0));
    let mut other = ebgp("192.0.2.1", &[64501, 4]);
    other.med = Some(10);
    let mut first = ebgp("192.0.2.2", &[64500, 3]);
    first.med = Some(50);
    assert_eq!(preferred(&first, &other), None, "the MED step is skipped");
}

#[test]
fn med_is_compared_before_ebgp_over_ibgp() {
    let mut e = ebgp("192.0.2.1", &[64500]);
    e.med = Some(100);
    let mut i = ibgp("192.0.2.2", &[64500]);
    i.med = Some(50);
    assert_eq!(preferred(&e, &i), Some(1));
}

#[test]
fn always_compare_med_compares_across_neighbour_ases() {
    let mut a = ebgp("192.0.2.1", &[64500, 3]);
    a.med = Some(50);
    let mut b = ebgp("192.0.2.2", &[64501, 4]);
    b.med = Some(10);
    let options = BgpOptions {
        always_compare_med: true,
        ..BgpOptions::default()
    };
    let d = best_of(&[a, b], &options, Platform::Iosxe);
    assert!(
        matches!(
            d,
            Decision::Best {
                best: 1,
                step: Some(DecisionStep::Med),
                ..
            }
        ),
        "{d:?}"
    );
}

#[test]
fn a_missing_med_is_0_or_the_worst_med_by_missing_as_worst() {
    let missing = ibgp("192.0.2.2", &[64500]);
    let mut explicit = ibgp("192.0.2.1", &[64500]);
    explicit.med = Some(10);
    assert_eq!(preferred(&missing, &explicit), Some(0));
    let worst = BgpOptions {
        missing_as_worst: Some(true),
        ..BgpOptions::default()
    };
    for platform in PLATFORMS {
        let d = best_of(&[missing.clone(), explicit.clone()], &worst, platform);
        assert!(
            matches!(
                d,
                Decision::Best {
                    best: 1,
                    step: Some(DecisionStep::Med),
                    ..
                }
            ),
            "{d:?}"
        );
    }
}

#[test]
fn the_lower_igp_cost_wins() {
    let mut near = ibgp("192.0.2.2", &[64500]);
    near.igp_cost = 5;
    let mut far = ibgp("192.0.2.1", &[64500]);
    far.igp_cost = 50;
    assert_eq!(preferred(&near, &far), Some(0));
}

#[test]
fn two_ebgp_paths_equal_through_the_igp_cost_tie_unless_compare_routerid() {
    let a = ebgp("192.0.2.2", &[64500]);
    let b = ebgp("192.0.2.1", &[64501]);
    let d = best_of(
        &[a.clone(), b.clone()],
        &BgpOptions::default(),
        Platform::Iosxe,
    );
    assert!(
        matches!(&d, Decision::Tie { tied, step: DecisionStep::OldestPath, .. } if tied == &[0, 1]),
        "{d:?}"
    );
    let rid = BgpOptions {
        compare_routerid: true,
        ..BgpOptions::default()
    };
    let d = best_of(&[a, b], &rid, Platform::Iosxe);
    assert!(
        matches!(
            d,
            Decision::Best {
                best: 1,
                step: Some(DecisionStep::RouterId),
                ..
            }
        ),
        "{d:?}"
    );
}

#[test]
fn the_originator_id_then_the_cluster_list_then_the_neighbour_address_break_an_ibgp_tie() {
    let mut low = ibgp("192.0.2.9", &[64500]);
    low.originator_id = Some(v4("192.0.2.1"));
    let mut high = ibgp("192.0.2.1", &[64500]);
    high.originator_id = Some(v4("192.0.2.5"));
    assert_eq!(preferred(&low, &high), Some(0));

    let mut short = ibgp("192.0.2.9", &[64500]);
    short.originator_id = Some(v4("192.0.2.1"));
    let mut long = short.clone();
    long.peer.address = Some(ip("192.0.2.2"));
    long.cluster_list = vec![v4("192.0.2.100")];
    assert_eq!(preferred(&short, &long), Some(0));

    let mut lower = ibgp("192.0.2.9", &[64500]);
    lower.peer.address = Some(ip("192.0.2.3"));
    let mut higher = lower.clone();
    higher.peer.address = Some(ip("192.0.2.4"));
    let d = best_of(&[higher, lower], &BgpOptions::default(), Platform::Iosxe);
    assert!(
        matches!(
            d,
            Decision::Best {
                best: 1,
                step: Some(DecisionStep::NeighborAddress),
                ..
            }
        ),
        "{d:?}"
    );
}

#[test]
fn the_best_path_of_a_candidate_set_and_of_no_candidate() {
    let c = vec![
        ebgp("192.0.2.1", &[64500, 64501, 64502]),
        ebgp("192.0.2.2", &[64500, 64501]),
        ebgp("192.0.2.3", &[64500, 64501, 64502, 64503]),
    ];
    let d = best_of(&c, &BgpOptions::default(), Platform::Iosxe);
    assert!(matches!(d, Decision::Best { best: 1, .. }), "{d:?}");
    assert_eq!(
        best_of(&[], &BgpOptions::default(), Platform::Iosxe),
        Decision::NoCandidate
    );
}

// Multipath.

#[test]
fn maximum_paths_installs_the_equal_paths_with_the_same_as_path_and_distinct_next_hops() {
    let a = ebgp("192.0.2.1", &[64500, 64510]);
    let b = ebgp("192.0.2.2", &[64500, 64510]);
    let mut same_hop = ebgp("192.0.2.3", &[64500, 64510]);
    same_hop.next_hop = a.next_hop;
    let other_path = ebgp("192.0.2.4", &[64501, 64510]);
    let c = vec![a, b, same_hop, other_path];
    let options = BgpOptions {
        maximum_paths_ebgp: Some(4),
        compare_routerid: true,
        ..BgpOptions::default()
    };
    let d = best_of(&c, &options, Platform::Nxos);
    assert!(
        matches!(&d, Decision::Best { best: 0, multipath, multipath_limit: Some(4), .. } if multipath == &[0, 1]),
        "{d:?}"
    );
    let relax = BgpOptions {
        multipath_relax: true,
        ..options.clone()
    };
    let d = best_of(&c, &relax, Platform::Nxos);
    assert!(
        matches!(&d, Decision::Best { multipath, .. } if multipath == &[0, 1, 3]),
        "{d:?}"
    );
    let two = BgpOptions {
        maximum_paths_ebgp: Some(2),
        ..relax
    };
    let d = best_of(&c, &two, Platform::Nxos);
    assert!(
        matches!(&d, Decision::Best { multipath, .. } if multipath == &[0, 1]),
        "{d:?}"
    );
}

#[test]
fn the_default_maximum_paths_is_1_on_cisco_and_a_build_value_on_frr() {
    let c = vec![ebgp("192.0.2.1", &[64500]), ebgp("192.0.2.2", &[64500])];
    for platform in [Platform::Iosxe, Platform::Nxos, Platform::Iosxr] {
        let d = best_of(&c, &BgpOptions::default(), platform);
        assert!(
            matches!(&d, Decision::Tie { multipath, multipath_limit: Some(1), .. } if multipath == &[0]),
            "{d:?}"
        );
    }
    for platform in [Platform::FrrTraditional, Platform::FrrDatacenter] {
        let d = best_of(&c, &BgpOptions::default(), platform);
        assert!(
            matches!(&d, Decision::Tie { multipath, multipath_limit: None, .. } if multipath == &[0, 1]),
            "{d:?}"
        );
    }
}

#[test]
fn an_ibgp_path_is_not_a_multipath_of_an_ebgp_best_path() {
    let mut i = ibgp("192.0.2.1", &[64500]);
    i.local_pref = Some(100);
    let c = vec![ebgp("192.0.2.2", &[64500]), i];
    let options = BgpOptions {
        maximum_paths_ebgp: Some(4),
        maximum_paths_ibgp: Some(4),
        ..BgpOptions::default()
    };
    let d = best_of(&c, &options, Platform::Iosxe);
    assert!(
        matches!(&d, Decision::Best { best: 0, multipath, .. } if multipath == &[0]),
        "{d:?}"
    );
}

// Paths with attributes that are not collected, and no profile.

#[test]
fn a_comparison_with_a_path_whose_attributes_are_not_collected_is_unknown() {
    let mut seed = ebgp("192.0.2.1", &[64500]);
    seed.attributes_collected = false;
    let d = best_of(&[seed.clone()], &BgpOptions::default(), Platform::Iosxe);
    assert!(
        matches!(
            d,
            Decision::Best {
                best: 0,
                step: None,
                ..
            }
        ),
        "{d:?}"
    );
    let d = best_of(
        &[ebgp("192.0.2.2", &[64500]), seed],
        &BgpOptions::default(),
        Platform::Iosxe,
    );
    let Decision::Unknown(u) = d else {
        panic!("{d:?}")
    };
    assert_eq!(u.reason, Reason::PathAttributesNotCollected);
    assert_eq!(u.reason.text(), "path attributes not collected");
    assert_eq!(
        u.to_string(),
        "path attributes not collected: path from 192.0.2.1"
    );
}

#[test]
fn a_platform_with_no_profile_gives_no_bgp_profile() {
    let d = decide(&[ebgp("192.0.2.1", &[64500])], &BgpOptions::default(), None);
    let Decision::Unknown(u) = d else {
        panic!("{d:?}")
    };
    assert_eq!(u.reason, Reason::NoBgpProfile);
    let mut p = BgpProcess::new("r1", "default", None, Asn(64496), v4("192.0.2.254"));
    p.options = BgpOptions::default();
    let stage = DecisionStage {
        process: &p,
        key: key("192.0.2.0/24"),
    };
    assert!(matches!(
        stage.run(&vec![ebgp("192.0.2.1", &[64500])]),
        Decision::Unknown(_)
    ));
    assert_eq!(stage.reads().len(), 3);
}

// The profile values.

/// HST `simul/platforms.py` `_EBGP_REQUIRES_POLICY` and FRR
/// `bgpd/bgp_vty.c` `BGP_EBGP_REQUIRES_POLICY`.
#[test]
fn an_ebgp_session_with_no_policy_drops_on_iosxr_and_frr_traditional_and_permits_elsewhere() {
    for (platform, permits) in [
        (Platform::Iosxe, true),
        (Platform::Nxos, true),
        (Platform::Iosxr, false),
        (Platform::FrrTraditional, false),
        (Platform::FrrDatacenter, true),
    ] {
        let mut proc_ = BgpProcess::new(
            "r1",
            "default",
            Some(platform),
            Asn(64496),
            v4("192.0.2.254"),
        );
        let n = Neighbor::new(ip("192.0.2.1"), Asn(64500));
        proc_.neighbors.insert(n.address, n.clone());
        let profile = proc_.profile();
        let path = ebgp("192.0.2.1", &[64500]);
        for direction in [Direction::Import, Direction::Export] {
            let r = neighbor_policy(
                &proc_,
                &n,
                direction,
                &key("192.0.2.0/24"),
                &path,
                profile.as_ref(),
            );
            assert_eq!(
                matches!(r, PolicyResult::Permit(_)),
                permits,
                "{platform:?}"
            );
        }
        let mut internal = n.clone();
        internal.remote_as = proc_.asn;
        let r = neighbor_policy(
            &proc_,
            &internal,
            Direction::Import,
            &key("192.0.2.0/24"),
            &path,
            profile.as_ref(),
        );
        assert!(matches!(r, PolicyResult::Permit(_)), "iBGP on {platform:?}");
    }
}

#[test]
fn vyos_ebgp_requires_policy_overrides_the_frr_default_and_cisco_ignores_it() {
    let options = |v| BgpOptions {
        ebgp_requires_policy: Some(v),
        ..BgpOptions::default()
    };
    let t = BgpProfile::of(Platform::FrrTraditional);
    let d = BgpProfile::of(Platform::FrrDatacenter);
    assert!(t.no_policy_permits(SessionKind::Ebgp, &options(false)));
    assert!(!d.no_policy_permits(SessionKind::Ebgp, &options(true)));
    assert!(t.no_policy_permits(SessionKind::ConfedEbgp, &BgpOptions::default()));
    assert!(BgpProfile::of(Platform::Iosxe).no_policy_permits(SessionKind::Ebgp, &options(true)));
    assert!(!BgpProfile::of(Platform::Iosxr).no_policy_permits(SessionKind::Ebgp, &options(false)));
}

/// FRR `bgpd/bgp_vty.c` gives the default on for the datacenter profile
/// only. The NX-OS command references give `bestpath med non-deterministic`
/// as disabled by default. IOS-XE off and IOS-XR always on are not
/// confirmed against a device.
#[test]
fn the_deterministic_med_default_of_each_profile() {
    for (platform, default, fixed) in [
        (Platform::Iosxe, false, false),
        (Platform::Nxos, true, false),
        (Platform::Iosxr, true, true),
        (Platform::FrrTraditional, false, false),
        (Platform::FrrDatacenter, true, false),
    ] {
        let p = BgpProfile::of(platform);
        assert_eq!(
            p.deterministic_med(&BgpOptions::default()),
            default,
            "{platform:?}"
        );
        let off = BgpOptions {
            deterministic_med: Some(false),
            ..BgpOptions::default()
        };
        assert_eq!(p.deterministic_med(&off), fixed, "{platform:?}");
    }
}

/// Cisco document 13753 for IOS-XE and the NX-OS command references give
/// the default off. IOS-XR and FRR are not confirmed against a device.
#[test]
fn the_missing_as_worst_default_of_each_profile_is_off() {
    for platform in PLATFORMS {
        let p = BgpProfile::of(platform);
        assert!(!p.missing_as_worst(&BgpOptions::default()), "{platform:?}");
        let on = BgpOptions {
            missing_as_worst: Some(true),
            ..BgpOptions::default()
        };
        assert!(p.missing_as_worst(&on));
    }
}

#[test]
fn the_other_profile_values() {
    for platform in PLATFORMS {
        let p = BgpProfile::of(platform);
        assert_eq!(p.distance(SessionKind::Ebgp), 20);
        assert_eq!(p.distance(SessionKind::Ibgp), 200);
        assert_eq!(p.distance(SessionKind::ConfedEbgp), 200);
        let local = if platform == Platform::Nxos { 220 } else { 200 };
        assert_eq!(p.distance(SessionKind::Local(LocalOrigin::Network)), local);
        assert_eq!((p.default_local_pref, p.local_weight), (100, 32_768));
        let frr = matches!(platform, Platform::FrrTraditional | Platform::FrrDatacenter);
        assert_eq!(
            p.match_reads,
            if frr {
                MatchReads::Output
            } else {
                MatchReads::Input
            }
        );
        assert_eq!(p.maximum_paths_ebgp, if frr { None } else { Some(1) });
        let undefined = if platform == Platform::Iosxr {
            UndefinedPolicy::NoPolicy
        } else {
            UndefinedPolicy::Deny
        };
        assert_eq!(p.undefined_policy, undefined);
        let v4_default = !matches!(platform, Platform::Nxos | Platform::Iosxr);
        assert_eq!(p.default_ipv4_unicast, Some(v4_default));
    }
}

#[test]
fn a_neighbour_activates_ipv4_unicast_by_the_default_of_the_platform() {
    for (platform, default_v4) in [
        (Platform::Iosxe, true),
        (Platform::Nxos, false),
        (Platform::Iosxr, false),
    ] {
        let mut p = BgpProcess::new(
            "r1",
            "default",
            Some(platform),
            Asn(64496),
            v4("192.0.2.254"),
        );
        let mut n = Neighbor::new(ip("2001:db8::1"), Asn(64500));
        n.activated.insert(Family::Ipv6Unicast);
        let families = p.families(&n).unwrap();
        assert_eq!(
            families.contains(&Family::Ipv4Unicast),
            default_v4,
            "{platform:?}"
        );
        p.options.default_ipv4_unicast = Some(false);
        assert!(!p.families(&n).unwrap().contains(&Family::Ipv4Unicast));
    }
}

#[test]
fn the_session_kind_follows_the_remote_as_the_local_as_and_the_confederation() {
    let mut p = BgpProcess::new(
        "r1",
        "default",
        Some(Platform::Iosxe),
        Asn(65001),
        v4("192.0.2.254"),
    );
    p.confederation_id = Some(Asn(64496));
    p.confederation_peers.insert(Asn(65002));
    let n = |asn| Neighbor::new(ip("192.0.2.1"), Asn(asn));
    assert_eq!(p.session_kind(&n(65001)), SessionKind::Ibgp);
    assert_eq!(p.session_kind(&n(65002)), SessionKind::ConfedEbgp);
    assert_eq!(p.session_kind(&n(64500)), SessionKind::Ebgp);
    let mut la = n(64999);
    la.local_as = Some(LocalAs {
        asn: Asn(64999),
        no_prepend: true,
        replace_as: true,
        dual_as: false,
    });
    assert_eq!(p.session_kind(&la), SessionKind::Ibgp);
}

#[test]
fn an_as_number_reads_in_the_asplain_and_the_asdot_form() {
    for (text, want) in [
        ("65001", Some(65001)),
        ("4200000001", Some(4_200_000_001)),
        ("1.10", Some(65546)),
        ("64086.59904", Some(64086 * 65536 + 59904)),
        ("0.65535", Some(65535)),
        ("65536.0", None),
        ("1.65536", None),
        ("4294967296", None),
        ("route-map", None),
        ("", None),
    ] {
        assert_eq!(text.parse::<Asn>().ok().map(|a| a.0), want, "{text}");
    }
}
