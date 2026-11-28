//! The policy evaluator, the lists and the neighbour policies.
//!
//! The list cases are ported from HST `tests/test_simul_matchlist.py` and
//! `tests/test_simul_prefixlist.py` with documentation addresses. From HST
//! `tests/test_simul_policy.py`, the cases of an exit through nested calls,
//! of a call that returns to its caller and of the private AS numbers are
//! ported. The expected results are not confirmed against a device.

mod bgp_common;

use std::collections::BTreeSet;

use bgp_common::{ebgp, ibgp, ip, key, pfx};
use rsim_routing::Platform;
use rsim_routing::bgp::{
    AdminValue, AsPath, AsPathLine, AsPathList, AsPathTerm, Asn, BgpOrigin, BgpPath, BgpProcess,
    Clause, Cmp, Community, CommunityLine, CommunityList, CommunityTerm, Continue, Direction,
    ExtCommunity, Guard, Half, MatchReads, MatchTerm, MedSet, Neighbor, NextHopSet, ObjectRef,
    PolicyBody, PolicyContext, PolicyResult, PolicySet, PolicyStage, PrefixList, PrefixListEntry,
    Reason, RouteKey, RoutePolicy, RoutingStage, SetAction, Statement, evaluate, neighbor_policy,
};

fn c(s: &str) -> Community {
    s.parse().unwrap()
}

fn cs(items: &[&str]) -> BTreeSet<Community> {
    items.iter().map(|s| c(s)).collect()
}

fn standard(seq: u32, permit: bool, items: &[&str]) -> CommunityLine {
    CommunityLine {
        seq,
        permit,
        term: CommunityTerm::All(items.iter().map(|s| c(s)).collect()),
    }
}

fn line(seq: u32, permit: bool, term: CommunityTerm) -> CommunityLine {
    CommunityLine { seq, permit, term }
}

fn entry(
    seq: u32,
    permit: bool,
    p: &str,
    ge: Option<u8>,
    le: Option<u8>,
    eq: Option<u8>,
) -> PrefixListEntry {
    PrefixListEntry::new(seq, permit, pfx(p), ge, le, eq)
}

fn route_map(name: &str, clauses: Vec<Clause>) -> RoutePolicy {
    RoutePolicy {
        name: name.to_string(),
        body: PolicyBody::RouteMap(clauses),
        spans: Vec::new(),
    }
}

fn rpl(name: &str, stmts: Vec<Statement>) -> RoutePolicy {
    RoutePolicy {
        name: name.to_string(),
        body: PolicyBody::Rpl(stmts),
        spans: Vec::new(),
    }
}

fn clause(seq: u32, permit: bool, matches: Vec<MatchTerm>, sets: Vec<SetAction>) -> Clause {
    Clause {
        matches,
        sets,
        ..Clause::new(seq, permit)
    }
}

/// A policy set with the prefix lists `A` (192.0.2.0/24 le 32) and `B`
/// (198.51.100.0/24 le 32).
fn lists() -> PolicySet {
    let mut set = PolicySet::default();
    set.prefix_lists.insert(
        "A".into(),
        PrefixList::new(vec![entry(5, true, "192.0.2.0/24", None, Some(32), None)]),
    );
    set.prefix_lists.insert(
        "B".into(),
        PrefixList::new(vec![entry(
            5,
            true,
            "198.51.100.0/24",
            None,
            Some(32),
            None,
        )]),
    );
    set
}

fn run_with(
    set: &PolicySet,
    policy: &RoutePolicy,
    k: &RouteKey,
    p: &BgpPath,
    reads: MatchReads,
    direction: Direction,
) -> PolicyResult {
    let ctx = PolicyContext {
        set,
        direction,
        local_address: Some(ip("192.0.2.254")),
        peer_address: Some(ip("192.0.2.1")),
        default_local_pref: 100,
        match_reads: reads,
    };
    evaluate(policy, k, p, &ctx)
}

fn run(set: &PolicySet, policy: &RoutePolicy, prefix: &str, p: &BgpPath) -> PolicyResult {
    run_with(
        set,
        policy,
        &key(prefix),
        p,
        MatchReads::Input,
        Direction::Import,
    )
}

fn permitted(r: PolicyResult) -> BgpPath {
    match r {
        PolicyResult::Permit(p) => p,
        other => panic!("{other:?}"),
    }
}

fn unknown_reason(r: &PolicyResult) -> Option<Reason> {
    match r {
        PolicyResult::Unknown(u) => Some(u.reason),
        _ => None,
    }
}

fn route() -> BgpPath {
    ebgp("192.0.2.1", &[64500, 64501])
}

// The lists.

#[test]
fn a_standard_community_line_needs_each_community_that_it_names() {
    let l = CommunityList::new(vec![standard(1, true, &["65000:1", "65000:2"])]);
    assert_eq!(
        l.permits(&cs(&["65000:1", "65000:2", "65001:1"])),
        Some(true)
    );
    assert_eq!(l.permits(&cs(&["65000:1"])), Some(false));
}

#[test]
fn the_first_matching_community_line_wins_and_no_match_denies() {
    let l = CommunityList::new(vec![
        standard(10, false, &["65000:1"]),
        line(20, true, CommunityTerm::Internet),
    ]);
    assert_eq!(l.permits(&cs(&["65000:1"])), Some(false));
    assert_eq!(l.permits(&cs(&["65000:9"])), Some(true));
    let only = CommunityList::new(vec![standard(1, true, &["65000:1"])]);
    assert_eq!(only.permits(&BTreeSet::new()), Some(false));
}

#[test]
fn the_well_known_community_names_parse_to_their_numbers() {
    assert_eq!(c("no-export"), Community::NO_EXPORT);
    assert_eq!(c("65535:65281"), Community::NO_EXPORT);
    assert_eq!(c("no-advertise"), c("65535:65282"));
    assert_eq!(c("local-as"), c("65535:65283"));
    let l = CommunityList::new(vec![standard(1, true, &["no-export"])]);
    assert_eq!(l.permits(&cs(&["65535:65281"])), Some(true));
}

#[test]
fn an_expanded_line_matches_the_communities_as_one_string_in_ascending_order() {
    let l = CommunityList::new(vec![CommunityLine::expanded(1, true, "^65000:1 65000:2$")]);
    assert_eq!(l.permits(&cs(&["65000:2", "65000:1"])), Some(true));
    assert_eq!(l.permits(&cs(&["65000:1"])), Some(false));
}

#[test]
fn an_iosxr_community_wildcard_matches_each_half() {
    let cases = [
        (Half::Value(65000), Half::Any, "65000:7", true),
        (Half::Any, Half::Value(100), "65001:100", true),
        (Half::Range(100, 200), Half::Value(5), "150:5", true),
        (Half::Range(100, 200), Half::Value(5), "250:5", false),
        (Half::Value(65000), Half::Any, "65001:7", false),
    ];
    for (high, low, community, want) in cases {
        let l = CommunityList::new(vec![line(1, true, CommunityTerm::Wildcard(high, low))]);
        assert_eq!(l.permits(&cs(&[community])), Some(want), "{community}");
    }
}

#[test]
fn iosxr_as_path_set_elements_match_a_run_at_the_start_the_end_or_anywhere() {
    let a = |v: &[u32]| v.iter().map(|&x| Asn(x)).collect::<Vec<_>>();
    let cases = [
        (
            AsPathTerm::NeighborIs(a(&[3356, 174])),
            vec![3356, 174, 1],
            true,
        ),
        (AsPathTerm::NeighborIs(a(&[174])), vec![3356, 174], false),
        (
            AsPathTerm::OriginatesFrom(a(&[64512])),
            vec![3356, 64512],
            true,
        ),
        (
            AsPathTerm::PassesThrough(a(&[174, 1])),
            vec![3356, 174, 1, 2],
            true,
        ),
        (
            AsPathTerm::PassesThrough(a(&[1, 174])),
            vec![3356, 174, 1],
            false,
        ),
        (AsPathTerm::Length(Cmp::Le, 2), vec![1, 2], true),
        (AsPathTerm::Length(Cmp::Ge, 3), vec![1, 2], false),
    ];
    for (term, path, want) in cases {
        let l = AsPathList::new(vec![AsPathLine {
            seq: 1,
            permit: true,
            term: term.clone(),
        }]);
        assert_eq!(l.permits(&AsPath::sequence(&path)), Some(want), "{term:?}");
    }
}

#[test]
fn matches_every_needs_each_element_of_the_set() {
    let l = CommunityList::new(vec![
        standard(1, true, &["65000:1"]),
        line(
            2,
            true,
            CommunityTerm::Wildcard(Half::Value(65001), Half::Any),
        ),
    ]);
    assert_eq!(l.matches_every(&cs(&["65000:1", "65001:3"])), Some(true));
    assert_eq!(l.matches_every(&cs(&["65000:1"])), Some(false));
}

#[test]
fn an_unhandled_community_line_decides_only_where_the_result_depends_on_it() {
    let unhandled = || {
        line(
            1,
            true,
            CommunityTerm::Unhandled("dfa-regex '65000:.*'".into()),
        )
    };
    let same = CommunityList::new(vec![unhandled(), line(2, true, CommunityTerm::Internet)]);
    assert_eq!(same.permits(&cs(&["65000:1"])), Some(true));
    let alone = CommunityList::new(vec![unhandled()]);
    assert_eq!(alone.permits(&cs(&["65000:1"])), None);
    let earlier = CommunityList::new(vec![standard(0, false, &["65000:1"]), unhandled()]);
    assert_eq!(earlier.permits(&cs(&["65000:1"])), Some(false));
}

#[test]
fn a_prefix_line_with_no_qualifier_matches_the_exact_length() {
    let l = PrefixList::new(vec![entry(5, true, "192.0.2.0/24", None, None, None)]);
    assert!(l.permits(pfx("192.0.2.0/24")));
    assert!(!l.permits(pfx("192.0.2.0/25")));
}

#[test]
fn ge_alone_runs_to_the_maximum_length_and_le_alone_starts_at_the_prefix_length() {
    let ge = PrefixList::new(vec![entry(5, true, "192.0.2.0/24", Some(26), None, None)]);
    assert!(ge.permits(pfx("192.0.2.64/26")));
    assert!(ge.permits(pfx("192.0.2.1/32")));
    assert!(!ge.permits(pfx("192.0.2.0/24")));
    let le = PrefixList::new(vec![entry(5, true, "192.0.2.0/24", None, Some(28), None)]);
    assert!(le.permits(pfx("192.0.2.0/24")));
    assert!(le.permits(pfx("192.0.2.16/28")));
    assert!(!le.permits(pfx("192.0.2.16/29")));
    let both = entry(5, true, "192.0.2.0/24", Some(26), Some(28), None);
    assert_eq!((both.min_len, both.max_len), (26, 28));
}

#[test]
fn eq_overrides_ge_and_le() {
    let e = entry(5, true, "192.0.2.0/24", Some(26), Some(30), Some(28));
    assert_eq!((e.min_len, e.max_len), (28, 28));
    let l = PrefixList::new(vec![e]);
    assert!(l.permits(pfx("192.0.2.16/28")));
    assert!(!l.permits(pfx("192.0.2.0/30")));
}

#[test]
fn the_first_prefix_line_in_ascending_sequence_wins_and_no_line_denies() {
    let l = PrefixList::new(vec![
        entry(10, true, "192.0.2.0/24", None, Some(32), None),
        entry(5, false, "192.0.2.128/25", None, Some(32), None),
    ]);
    assert!(!l.permits(pfx("192.0.2.192/26")));
    assert!(l.permits(pfx("192.0.2.64/26")));
    assert!(!l.permits(pfx("198.51.100.0/24")));
    assert!(!PrefixList::default().permits(pfx("192.0.2.0/24")));
}

#[test]
fn a_prefix_line_matches_by_containment_of_the_network_address() {
    let l = PrefixList::new(vec![entry(5, true, "192.0.2.0/24", None, Some(28), None)]);
    assert!(l.permits(pfx("192.0.2.240/28")));
    assert!(!l.permits(pfx("198.51.100.0/28")));
}

#[test]
fn an_ipv6_prefix_list_with_ge_and_le_matches_the_lengths_in_its_range() {
    let l = PrefixList::new(vec![entry(
        5,
        true,
        "2001:db8::/32",
        Some(40),
        Some(48),
        None,
    )]);
    assert!(l.permits(pfx("2001:db8:100::/40")));
    assert!(l.permits(pfx("2001:db8:1::/48")));
    assert!(!l.permits(pfx("2001:db8::/32")));
    assert!(!l.permits(pfx("2001:db8:1:1::/64")));
    assert!(!l.permits(pfx("2001:db9::/40")));
}

// Route-maps.

#[test]
fn a_route_map_takes_the_first_matching_clause_and_denies_a_route_that_no_clause_matches() {
    let set = lists();
    let rm = route_map(
        "RM",
        vec![
            clause(
                10,
                false,
                vec![MatchTerm::PrefixList(vec!["A".into()])],
                vec![],
            ),
            clause(
                20,
                true,
                vec![MatchTerm::PrefixList(vec!["B".into()])],
                vec![SetAction::LocalPref(200)],
            ),
        ],
    );
    assert_eq!(run(&set, &rm, "192.0.2.0/24", &route()), PolicyResult::Deny);
    assert_eq!(
        permitted(run(&set, &rm, "198.51.100.0/24", &route())).local_pref,
        Some(200)
    );
    assert_eq!(
        run(&set, &rm, "203.0.113.0/24", &route()),
        PolicyResult::Deny
    );
}

#[test]
fn a_term_with_more_than_one_list_matches_when_one_list_matches() {
    let set = lists();
    let rm = route_map(
        "RM",
        vec![clause(
            10,
            true,
            vec![MatchTerm::PrefixList(vec!["A".into(), "B".into()])],
            vec![],
        )],
    );
    assert!(matches!(
        run(&set, &rm, "198.51.100.0/24", &route()),
        PolicyResult::Permit(_)
    ));
    assert_eq!(
        run(&set, &rm, "203.0.113.0/24", &route()),
        PolicyResult::Deny
    );
}

#[test]
fn continue_goes_on_to_the_target_clause_and_keeps_the_earlier_set_actions() {
    let set = lists();
    let rm = route_map(
        "RM",
        vec![
            Clause {
                continue_to: Some(Continue::Seq(30)),
                ..clause(
                    10,
                    true,
                    vec![],
                    vec![SetAction::CommunityAdd(vec![c("65000:1")])],
                )
            },
            clause(20, true, vec![], vec![SetAction::LocalPref(300)]),
            clause(
                30,
                true,
                vec![MatchTerm::PrefixList(vec!["A".into()])],
                vec![SetAction::Med(MedSet::Value(5))],
            ),
        ],
    );
    let both = permitted(run(&set, &rm, "192.0.2.0/24", &route()));
    assert_eq!(both.communities, cs(&["65000:1"]));
    assert_eq!((both.med, both.local_pref), (Some(5), None));
    let first = permitted(run(&set, &rm, "203.0.113.0/24", &route()));
    assert_eq!(first.communities, cs(&["65000:1"]));
    assert_eq!((first.med, first.local_pref), (None, None));
}

#[test]
fn continue_to_a_matching_deny_clause_denies() {
    let set = lists();
    let rm = route_map(
        "RM",
        vec![
            Clause {
                continue_to: Some(Continue::Next),
                ..clause(10, true, vec![], vec![SetAction::LocalPref(200)])
            },
            clause(
                20,
                false,
                vec![MatchTerm::PrefixList(vec!["A".into()])],
                vec![],
            ),
        ],
    );
    assert_eq!(run(&set, &rm, "192.0.2.0/24", &route()), PolicyResult::Deny);
    assert_eq!(
        permitted(run(&set, &rm, "198.51.100.0/24", &route())).local_pref,
        Some(200)
    );
}

#[test]
fn a_later_clause_reads_the_input_route_or_the_changed_route_by_the_profile() {
    let set = lists();
    let rm = route_map(
        "RM",
        vec![
            Clause {
                continue_to: Some(Continue::Next),
                ..clause(10, true, vec![], vec![SetAction::LocalPref(200)])
            },
            clause(
                20,
                true,
                vec![MatchTerm::LocalPref(Cmp::Eq, 200)],
                vec![SetAction::Med(MedSet::Value(5))],
            ),
        ],
    );
    let k = key("192.0.2.0/24");
    let input = permitted(run_with(
        &set,
        &rm,
        &k,
        &route(),
        MatchReads::Input,
        Direction::Import,
    ));
    assert_eq!(input.med, None);
    let output = permitted(run_with(
        &set,
        &rm,
        &k,
        &route(),
        MatchReads::Output,
        Direction::Import,
    ));
    assert_eq!(output.med, Some(5));
}

// RPL.

fn in_a() -> Guard {
    Guard::Term(MatchTerm::PrefixList(vec!["A".into()]))
}

#[test]
fn rpl_drop_set_and_pass_decide_the_route() {
    let mut set = lists();
    set.community_lists.insert(
        "C".into(),
        CommunityList::new(vec![standard(1, true, &["65000:1"])]),
    );
    let policy = rpl(
        "P",
        vec![Statement::If {
            branches: vec![
                (in_a(), vec![Statement::Drop]),
                (
                    Guard::Term(MatchTerm::CommunityList {
                        names: vec!["C".into()],
                        every: false,
                    }),
                    vec![Statement::Set(SetAction::Med(MedSet::Value(10)))],
                ),
            ],
            otherwise: vec![Statement::Pass],
        }],
    );
    assert_eq!(
        run(&set, &policy, "192.0.2.0/24", &route()),
        PolicyResult::Deny
    );
    let mut tagged = route();
    tagged.communities = cs(&["65000:1"]);
    assert_eq!(
        permitted(run(&set, &policy, "198.51.100.0/24", &tagged)).med,
        Some(10)
    );
    assert_eq!(
        permitted(run(&set, &policy, "198.51.100.0/24", &route())),
        route()
    );
}

#[test]
fn an_rpl_policy_with_no_pass_and_no_set_denies() {
    let set = lists();
    let policy = rpl(
        "P",
        vec![Statement::If {
            branches: vec![(in_a(), vec![Statement::Set(SetAction::LocalPref(200))])],
            otherwise: vec![],
        }],
    );
    assert_eq!(
        permitted(run(&set, &policy, "192.0.2.0/24", &route())).local_pref,
        Some(200)
    );
    assert_eq!(
        run(&set, &policy, "198.51.100.0/24", &route()),
        PolicyResult::Deny
    );
}

#[test]
fn done_in_an_applied_policy_ends_the_parent_and_permits() {
    let mut set = lists();
    set.policies.insert(
        "CHILD".into(),
        rpl(
            "CHILD",
            vec![Statement::If {
                branches: vec![(in_a(), vec![Statement::Done])],
                otherwise: vec![],
            }],
        ),
    );
    let parent = rpl(
        "PARENT",
        vec![
            Statement::Apply("CHILD".into()),
            Statement::Set(SetAction::Med(MedSet::Value(99))),
        ],
    );
    assert_eq!(
        permitted(run(&set, &parent, "192.0.2.0/24", &route())).med,
        None
    );
    assert_eq!(
        permitted(run(&set, &parent, "198.51.100.0/24", &route())).med,
        Some(99)
    );
}

#[test]
fn drop_in_a_nested_applied_policy_ends_each_policy_and_denies() {
    let mut set = lists();
    set.policies
        .insert("INNER".into(), rpl("INNER", vec![Statement::Drop]));
    set.policies.insert(
        "MIDDLE".into(),
        rpl(
            "MIDDLE",
            vec![Statement::Apply("INNER".into()), Statement::Done],
        ),
    );
    let outer = rpl(
        "OUTER",
        vec![
            Statement::If {
                branches: vec![(in_a(), vec![Statement::Apply("MIDDLE".into())])],
                otherwise: vec![],
            },
            Statement::Done,
        ],
    );
    assert_eq!(
        run(&set, &outer, "192.0.2.0/24", &route()),
        PolicyResult::Deny
    );
    assert!(matches!(
        run(&set, &outer, "198.51.100.0/24", &route()),
        PolicyResult::Permit(_)
    ));
}

#[test]
fn an_applied_policy_with_no_verdict_returns_to_its_caller() {
    let mut set = lists();
    set.policies.insert(
        "INNER".into(),
        rpl("INNER", vec![Statement::Set(SetAction::Tag(7))]),
    );
    let outer = rpl(
        "OUTER",
        vec![
            Statement::Apply("INNER".into()),
            Statement::Set(SetAction::Weight(5)),
        ],
    );
    let out = permitted(run(&set, &outer, "192.0.2.0/24", &route()));
    assert_eq!((out.tag, out.weight), (Some(7), 5));
}

#[test]
fn the_private_as_numbers_are_the_ranges_of_rfc_6996() {
    assert!(!Asn(64500).is_private());
    assert!(Asn(65001).is_private());
    assert!(!Asn(65535).is_private());
    assert!(Asn(4_200_000_000).is_private());
    assert!(!Asn(4_294_967_295).is_private());
}

#[test]
fn an_apply_loop_is_unknown() {
    let mut set = lists();
    set.policies
        .insert("P".into(), rpl("P", vec![Statement::Apply("Q".into())]));
    set.policies
        .insert("Q".into(), rpl("Q", vec![Statement::Apply("P".into())]));
    let r = run(&set, &set.policies["P"].clone(), "192.0.2.0/24", &route());
    assert_eq!(unknown_reason(&r), Some(Reason::PolicyClauseNotEvaluated));
}

#[test]
fn rpl_guards_combine_with_not_and_and_or() {
    let set = lists();
    let in_b = Guard::Term(MatchTerm::PrefixList(vec!["B".into()]));
    let policy = rpl(
        "P",
        vec![Statement::If {
            branches: vec![(
                Guard::Or(vec![
                    Guard::And(vec![in_a(), Guard::Term(MatchTerm::Origin(BgpOrigin::Igp))]),
                    Guard::Not(Box::new(Guard::Or(vec![in_a(), in_b]))),
                ]),
                vec![Statement::Pass],
            )],
            otherwise: vec![Statement::Drop],
        }],
    );
    assert!(matches!(
        run(&set, &policy, "192.0.2.0/24", &route()),
        PolicyResult::Permit(_)
    ));
    assert_eq!(
        run(&set, &policy, "198.51.100.0/24", &route()),
        PolicyResult::Deny
    );
    assert!(matches!(
        run(&set, &policy, "203.0.113.0/24", &route()),
        PolicyResult::Permit(_)
    ));
}

// Set actions.

fn apply(actions: Vec<SetAction>, p: &BgpPath, direction: Direction) -> PolicyResult {
    let set = lists();
    let rm = route_map("RM", vec![clause(10, true, vec![], actions)]);
    run_with(
        &set,
        &rm,
        &key("192.0.2.0/24"),
        p,
        MatchReads::Input,
        direction,
    )
}

#[test]
fn set_metric_adds_and_subtracts_within_the_range_of_the_med() {
    let mut p = route();
    p.med = Some(10);
    assert_eq!(
        permitted(apply(
            vec![SetAction::Med(MedSet::Add(5))],
            &p,
            Direction::Import
        ))
        .med,
        Some(15)
    );
    assert_eq!(
        permitted(apply(
            vec![SetAction::Med(MedSet::Subtract(20))],
            &p,
            Direction::Import
        ))
        .med,
        Some(0)
    );
    p.med = Some(u32::MAX - 1);
    assert_eq!(
        permitted(apply(
            vec![SetAction::Med(MedSet::Add(5))],
            &p,
            Direction::Import
        ))
        .med,
        Some(u32::MAX)
    );
    p.med = None;
    assert_eq!(
        permitted(apply(
            vec![SetAction::Med(MedSet::Add(5))],
            &p,
            Direction::Import
        ))
        .med,
        Some(5)
    );
}

#[test]
fn prepend_and_prepend_last_as_add_to_the_front_of_the_path() {
    let p = route();
    let out = permitted(apply(
        vec![SetAction::AsPathPrepend(vec![Asn(64499), Asn(64499)])],
        &p,
        Direction::Export,
    ));
    assert_eq!(out.as_path, AsPath::sequence(&[64499, 64499, 64500, 64501]));
    let last = permitted(apply(
        vec![SetAction::AsPathPrependLastAs(2)],
        &p,
        Direction::Import,
    ));
    assert_eq!(
        last.as_path,
        AsPath::sequence(&[64500, 64500, 64500, 64501])
    );
    let empty = ibgp("192.0.2.1", &[]);
    let r = apply(
        vec![SetAction::AsPathPrependLastAs(2)],
        &empty,
        Direction::Import,
    );
    assert_eq!(unknown_reason(&r), Some(Reason::PolicyClauseNotEvaluated));
}

#[test]
fn next_hop_peer_address_is_the_peer_on_import_and_the_local_address_on_export() {
    let p = route();
    let nh = |d| {
        permitted(apply(
            vec![SetAction::NextHop(NextHopSet::PeerAddress)],
            &p,
            d,
        ))
        .next_hop
    };
    assert_eq!(nh(Direction::Import), Some(ip("192.0.2.1")));
    assert_eq!(nh(Direction::Export), Some(ip("192.0.2.254")));
    let own = permitted(apply(
        vec![SetAction::NextHop(NextHopSet::SelfAddress)],
        &p,
        Direction::Import,
    ));
    assert_eq!(own.next_hop, Some(ip("192.0.2.254")));
}

#[test]
fn community_replace_add_and_delete_and_the_other_set_actions() {
    let mut set = lists();
    set.community_lists.insert(
        "DEL".into(),
        CommunityList::new(vec![
            standard(1, false, &["65000:2"]),
            CommunityLine::expanded(2, true, "^65000:"),
        ]),
    );
    let rm = route_map(
        "RM",
        vec![clause(
            10,
            true,
            vec![],
            vec![
                SetAction::CommunityDelete("DEL".into()),
                SetAction::CommunityAdd(vec![c("64500:7")]),
                SetAction::RouteTargetAdd(vec!["64500:100".parse::<AdminValue>().unwrap()]),
                SetAction::Weight(50),
                SetAction::Origin(BgpOrigin::Incomplete),
                SetAction::Tag(7),
            ],
        )],
    );
    let mut p = route();
    p.communities = cs(&["65000:1", "65000:2", "65001:1"]);
    let out = permitted(run(&set, &rm, "192.0.2.0/24", &p));
    assert_eq!(out.communities, cs(&["65000:2", "65001:1", "64500:7"]));
    assert_eq!(
        out.ext_communities,
        BTreeSet::from([ExtCommunity::RouteTarget(AdminValue::As2 {
            asn: 64500,
            value: 100
        })])
    );
    assert_eq!(
        (out.weight, out.origin, out.tag),
        (50, BgpOrigin::Incomplete, Some(7))
    );
    let replaced = permitted(apply(
        vec![SetAction::CommunityReplace(vec![c("64500:1")])],
        &p,
        Direction::Import,
    ));
    assert_eq!(replaced.communities, cs(&["64500:1"]));
}

// Match bounds.

#[test]
fn an_unhandled_term_gives_a_result_where_both_of_its_values_give_the_same_result() {
    let set = lists();
    let unhandled = || MatchTerm::Unhandled("match ip address 99".into());
    let rm = route_map(
        "RM",
        vec![
            clause(
                10,
                false,
                vec![MatchTerm::PrefixList(vec!["A".into()]), unhandled()],
                vec![],
            ),
            clause(20, true, vec![], vec![]),
        ],
    );
    assert_eq!(
        permitted(run(&set, &rm, "198.51.100.0/24", &route())),
        route()
    );
    let r = run(&set, &rm, "192.0.2.0/24", &route());
    assert_eq!(unknown_reason(&r), Some(Reason::PolicyClauseNotEvaluated));
    let PolicyResult::Unknown(u) = r else {
        unreachable!()
    };
    assert_eq!(u.reason.text(), "policy clause not evaluated");
    assert!(
        u.details.iter().all(|d| d.starts_with("RM 10")),
        "{:?}",
        u.details
    );

    let deny_both = route_map(
        "RM",
        vec![
            clause(10, false, vec![unhandled()], vec![]),
            clause(20, false, vec![], vec![]),
        ],
    );
    assert_eq!(
        run(&set, &deny_both, "192.0.2.0/24", &route()),
        PolicyResult::Deny
    );
}

#[test]
fn two_permits_with_different_set_actions_are_unknown() {
    let set = lists();
    let rm = route_map(
        "RM",
        vec![
            clause(
                10,
                true,
                vec![MatchTerm::Unhandled("match x".into())],
                vec![SetAction::LocalPref(200)],
            ),
            clause(20, true, vec![], vec![]),
        ],
    );
    assert_eq!(
        unknown_reason(&run(&set, &rm, "192.0.2.0/24", &route())),
        Some(Reason::PolicyClauseNotEvaluated)
    );
}

#[test]
fn an_unhandled_action_is_unknown_only_where_a_route_reaches_it() {
    let set = lists();
    let rm = route_map(
        "RM",
        vec![
            clause(
                10,
                true,
                vec![MatchTerm::PrefixList(vec!["A".into()])],
                vec![SetAction::Unhandled("set dampening".into())],
            ),
            clause(20, true, vec![], vec![]),
        ],
    );
    assert_eq!(
        unknown_reason(&run(&set, &rm, "192.0.2.0/24", &route())),
        Some(Reason::PolicyClauseNotEvaluated)
    );
    assert!(matches!(
        run(&set, &rm, "198.51.100.0/24", &route()),
        PolicyResult::Permit(_)
    ));
}

#[test]
fn a_list_that_the_set_does_not_hold_is_an_unknown_match() {
    let set = lists();
    let rm = route_map(
        "RM",
        vec![clause(
            10,
            true,
            vec![MatchTerm::PrefixList(vec!["NONE".into()])],
            vec![],
        )],
    );
    assert_eq!(
        unknown_reason(&run(&set, &rm, "192.0.2.0/24", &route())),
        Some(Reason::PolicyClauseNotEvaluated)
    );
    let or_known = route_map(
        "RM",
        vec![clause(
            10,
            true,
            vec![MatchTerm::PrefixList(vec!["NONE".into(), "A".into()])],
            vec![],
        )],
    );
    assert!(matches!(
        run(&set, &or_known, "192.0.2.0/24", &route()),
        PolicyResult::Permit(_)
    ));
}

// Neighbour policies and the stage.

fn process(platform: Option<Platform>) -> (BgpProcess, Neighbor) {
    let mut p = BgpProcess::new(
        "r1",
        "default",
        platform,
        Asn(64496),
        bgp_common::v4("192.0.2.254"),
    );
    let n = Neighbor::new(ip("192.0.2.1"), Asn(64500));
    p.neighbors.insert(n.address, n.clone());
    (p, n)
}

#[test]
fn an_undefined_neighbour_route_map_denies_and_an_undefined_iosxr_policy_takes_the_no_policy_rule()
{
    for (platform, kind_ebgp, want_permit) in [
        (Platform::Iosxe, true, false),
        (Platform::Nxos, true, false),
        (Platform::FrrDatacenter, true, false),
        (Platform::Iosxr, true, false),
        (Platform::Iosxr, false, true),
    ] {
        let (proc_, mut n) = process(Some(platform));
        if !kind_ebgp {
            n.remote_as = proc_.asn;
        }
        n.import_policy = Some("ABSENT".into());
        let profile = proc_.profile();
        let r = neighbor_policy(
            &proc_,
            &n,
            Direction::Import,
            &key("192.0.2.0/24"),
            &route(),
            profile.as_ref(),
        );
        assert_eq!(
            matches!(r, PolicyResult::Permit(_)),
            want_permit,
            "{platform:?} {kind_ebgp}"
        );
    }
}

#[test]
fn a_platform_with_no_profile_gives_no_bgp_profile() {
    let (proc_, n) = process(None);
    let r = neighbor_policy(
        &proc_,
        &n,
        Direction::Import,
        &key("192.0.2.0/24"),
        &route(),
        None,
    );
    assert_eq!(unknown_reason(&r), Some(Reason::NoBgpProfile));
    assert_eq!(Reason::NoBgpProfile.text(), "no bgp profile");
}

#[test]
fn the_policy_stage_reads_the_policy_its_lists_and_the_applied_policies() {
    let (mut proc_, mut n) = process(Some(Platform::Iosxr));
    n.import_policy = Some("IN".into());
    proc_.neighbors.insert(n.address, n.clone());
    proc_.policy = lists();
    proc_.policy.policies.insert(
        "IN".into(),
        rpl(
            "IN",
            vec![Statement::If {
                branches: vec![(in_a(), vec![Statement::Apply("SUB".into())])],
                otherwise: vec![Statement::Pass],
            }],
        ),
    );
    proc_.policy.policies.insert(
        "SUB".into(),
        rpl(
            "SUB",
            vec![Statement::Set(SetAction::CommunityDelete("DEL".into()))],
        ),
    );
    let stage = PolicyStage {
        process: &proc_,
        neighbor: n.address,
        direction: Direction::Import,
    };
    let reads = stage.reads();
    let names: Vec<String> = reads
        .iter()
        .filter_map(|r| match r {
            ObjectRef::Policy { name, .. } => Some(format!("policy {name}")),
            ObjectRef::PrefixList { name, .. } => Some(format!("prefix-list {name}")),
            ObjectRef::CommunityList { name, .. } => Some(format!("community-list {name}")),
            _ => None,
        })
        .collect();
    assert_eq!(
        names,
        [
            "policy IN",
            "policy SUB",
            "prefix-list A",
            "community-list DEL"
        ]
    );
    assert!(reads.contains(&ObjectRef::Profile(Some(Platform::Iosxr))));
    assert_eq!(stage.name(), "bgp import policy");
    let r = stage.run(&(key("198.51.100.0/24"), route()));
    assert_eq!(permitted(r), route());
}
