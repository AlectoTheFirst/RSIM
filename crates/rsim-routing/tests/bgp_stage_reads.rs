//! Each routing stage gives the same output after a change of an object
//! that its `reads()` does not hold.

mod bgp_common;

use std::collections::BTreeSet;
use std::net::IpAddr;

use bgp_common::*;
use rsim_routing::Platform;
use rsim_routing::bgp::{
    Aggregate, AsPathLine, AsPathList, BestPath, BgpPath, BgpProcess, Clause, Community,
    CommunityLine, CommunityList, DecisionStage, Direction, MatchTerm, Network, NextHopSelf,
    ObjectRef, OriginateInput, OriginateStage, PolicyBody, PolicyStage, PrefixList, RoutePolicy,
    RoutingStage, Session, SessionEnd, SessionStage, SetAction,
};

const P: &str = "203.0.113.0/24";
const AGG: &str = "203.0.112.0/23";

fn route_map(name: &str, clauses: Vec<Clause>) -> RoutePolicy {
    RoutePolicy {
        name: name.to_string(),
        body: PolicyBody::RouteMap(clauses),
        spans: Vec::new(),
    }
}

fn clause(seq: u32, permit: bool, m: Vec<MatchTerm>, s: Vec<SetAction>) -> Clause {
    let mut c = Clause::new(seq, permit);
    c.matches = m;
    c.sets = s;
    c
}

fn plist(p: &str) -> PrefixList {
    PrefixList::set(&[(pfx(p), 24, 32)])
}

fn world() -> Vec<BgpProcess> {
    let mut lab = Lab::default();
    lab.router("r1", Platform::Iosxe, 65001, "10.255.0.1");
    lab.router("r2", Platform::Iosxe, 65002, "10.255.0.2");
    lab.router("r3", Platform::Iosxe, 65001, "10.255.0.3");
    lab.peer("r1", "10.0.0.1", "r2", "10.0.0.2");
    lab.peer("r1", "10.0.1.1", "r3", "10.0.1.3");
    lab.peer("r2", "10.0.5.2", "r3", "10.0.5.3");
    lab.neighbor_mut("r1", "10.0.1.3").route_reflector_client = true;
    let n = lab.neighbor_mut("r1", "10.0.0.2");
    n.export_policy = Some("out".to_string());
    n.import_policy = Some("in".to_string());
    lab.neighbor_mut("r1", "10.0.1.3").import_policy = Some("in3".to_string());
    lab.neighbor_mut("r2", "10.0.0.1").import_policy = Some("r2-in".to_string());
    lab.neighbor_mut("r2", "10.0.5.3").import_policy = Some("r2-other".to_string());
    let r1 = lab.proc("r1");
    let pol = &mut r1.policy;
    pol.policies.insert(
        "out".to_string(),
        route_map(
            "out",
            vec![clause(
                10,
                true,
                vec![MatchTerm::PrefixList(vec!["pl-out".to_string()])],
                vec![SetAction::CommunityAdd(vec![Community::new(65001, 9)])],
            )],
        ),
    );
    pol.policies.insert(
        "in".to_string(),
        route_map(
            "in",
            vec![
                clause(
                    10,
                    false,
                    vec![MatchTerm::CommunityList {
                        names: vec!["cl-in".to_string()],
                        every: false,
                    }],
                    vec![],
                ),
                clause(
                    20,
                    true,
                    vec![MatchTerm::AsPathList(vec!["ap-in".to_string()])],
                    vec![SetAction::LocalPref(150)],
                ),
                clause(30, true, vec![], vec![]),
            ],
        ),
    );
    pol.policies.insert(
        "in3".to_string(),
        route_map(
            "in3",
            vec![clause(
                10,
                true,
                vec![MatchTerm::PrefixList(vec!["pl-in3".to_string()])],
                vec![SetAction::Med(rsim_routing::bgp::MedSet::Value(3))],
            )],
        ),
    );
    pol.policies.insert(
        "net".to_string(),
        route_map(
            "net",
            vec![clause(
                10,
                true,
                vec![MatchTerm::PrefixList(vec!["pl-net".to_string()])],
                vec![SetAction::LocalPref(300)],
            )],
        ),
    );
    pol.policies.insert(
        "unused".to_string(),
        route_map("unused", vec![clause(10, true, vec![], vec![])]),
    );
    for name in ["pl-out", "pl-in3", "pl-net", "pl-unused"] {
        pol.prefix_lists
            .insert(name.to_string(), plist("203.0.112.0/23"));
    }
    for name in ["ap-in", "ap-unused"] {
        pol.as_path_lists.insert(
            name.to_string(),
            AsPathList::new(vec![AsPathLine::regex(1, true, "^65002")]),
        );
    }
    for name in ["cl-in", "cl-unused"] {
        pol.community_lists.insert(
            name.to_string(),
            CommunityList::new(vec![CommunityLine::expanded(1, true, "^65002:666$")]),
        );
    }
    r1.networks.push(Network {
        key: key(P),
        policy: Some("net".to_string()),
        spans: Vec::new(),
    });
    r1.aggregates.push(Aggregate {
        key: key(AGG),
        summary_only: true,
        as_set: true,
        spans: Vec::new(),
    });
    let r2 = lab.proc("r2");
    r2.policy.policies.insert(
        "r2-in".to_string(),
        route_map(
            "r2-in",
            vec![
                clause(
                    10,
                    true,
                    vec![MatchTerm::CommunityList {
                        names: vec!["cl-r2".to_string()],
                        every: false,
                    }],
                    vec![SetAction::LocalPref(50)],
                ),
                clause(20, true, vec![], vec![]),
            ],
        ),
    );
    r2.policy.policies.insert(
        "r2-other".to_string(),
        route_map("r2-other", vec![clause(10, false, vec![], vec![])]),
    );
    for name in ["cl-r2", "cl-r2-unused"] {
        r2.policy.community_lists.insert(
            name.to_string(),
            CommunityList::new(vec![CommunityLine::expanded(1, true, "^65001:9$")]),
        );
    }
    lab.input.processes
}

/// The paths that the stages run on.
fn paths() -> Vec<BgpPath> {
    let mut out = Vec::new();
    for (i, asp) in [&[65002u32][..], &[65003, 65002], &[65010]]
        .iter()
        .enumerate()
    {
        let mut p = ebgp(&format!("10.0.0.{}", 2 + 7 * i), asp);
        p.med = Some(i as u32 * 10);
        if i == 1 {
            p.communities.insert(Community::new(65002, 666));
        }
        out.push(p);
        let mut q = ibgp(&format!("10.0.1.{}", 3 + 7 * i), asp);
        q.igp_cost = 5 * i as u32;
        q.communities.insert(Community::new(65001, 9));
        out.push(q);
    }
    out
}

fn keys() -> Vec<rsim_routing::bgp::RouteKey> {
    vec![key(P), key(AGG), key("198.51.100.0/24")]
}

fn find<'a>(w: &'a [BgpProcess], d: &str) -> &'a BgpProcess {
    w.iter().find(|p| p.device == d).unwrap()
}

type Stage = fn(&[BgpProcess]) -> (BTreeSet<ObjectRef>, String);

fn policy(w: &[BgpProcess], dev: &str, n: &str, dir: Direction) -> (BTreeSet<ObjectRef>, String) {
    let s = PolicyStage {
        process: find(w, dev),
        neighbor: ip(n),
        direction: dir,
    };
    let mut out = String::new();
    for k in keys() {
        for p in paths() {
            out.push_str(&format!("{:?}\n", s.run(&(k, p))));
        }
    }
    (s.reads(), out)
}

fn stages() -> Vec<(&'static str, Stage)> {
    vec![
        ("r1 export to r2", |w: &[BgpProcess]| {
            policy(w, "r1", "10.0.0.2", Direction::Export)
        }),
        ("r1 import from r2", |w: &[BgpProcess]| {
            policy(w, "r1", "10.0.0.2", Direction::Import)
        }),
        ("r1 import from r3", |w: &[BgpProcess]| {
            policy(w, "r1", "10.0.1.3", Direction::Import)
        }),
        ("r1 decision", |w: &[BgpProcess]| {
            let s = DecisionStage {
                process: find(w, "r1"),
                key: key(P),
            };
            let ps = paths();
            let out: String = (0..ps.len())
                .map(|i| format!("{:?}\n", s.run(&ps[i..].to_vec())))
                .collect();
            (s.reads(), out)
        }),
        ("r1 to r2 session", |w: &[BgpProcess]| {
            let session = Session {
                a: SessionEnd {
                    device: "r1".to_string(),
                    vrf: "default".to_string(),
                    neighbor: ip("10.0.0.2"),
                },
                b: SessionEnd {
                    device: "r2".to_string(),
                    vrf: "default".to_string(),
                    neighbor: ip("10.0.0.1"),
                },
            };
            let s = SessionStage {
                sender: find(w, "r1"),
                receiver: find(w, "r2"),
                session: &session,
            };
            let mut out = String::new();
            for k in keys() {
                for p in paths() {
                    out.push_str(&format!("{:?}\n", s.run(&(k, p))));
                }
            }
            (s.reads(), out)
        }),
        ("r1 originate", |w: &[BgpProcess]| {
            let mut out = String::new();
            let mut reads = BTreeSet::new();
            for k in keys() {
                let s = OriginateStage {
                    process: find(w, "r1"),
                    key: k,
                };
                for present in [Some(true), Some(false), None] {
                    let contributors = paths().into_iter().map(BestPath::Path).collect();
                    out.push_str(&format!(
                        "{:?}\n",
                        s.run(&OriginateInput {
                            route_present: present,
                            contributors,
                        })
                    ));
                }
                reads.extend(s.reads());
            }
            (reads, out)
        }),
    ]
}

type Mutation = (ObjectRef, Box<dyn Fn(&mut BgpProcess)>);

/// A change of each object of each process.
fn mutations(w: &[BgpProcess]) -> Vec<(String, Mutation)> {
    let mut out: Vec<(String, Mutation)> = Vec::new();
    for p in w {
        let (d, v) = (p.device.clone(), p.vrf.clone());
        out.push((
            d.clone(),
            (
                ObjectRef::Process {
                    device: d.clone(),
                    vrf: v.clone(),
                },
                Box::new(|p: &mut BgpProcess| {
                    p.router_id = Some(v4("10.255.9.9"));
                    p.cluster_id = Some(v4("10.255.8.8"));
                    p.options.always_compare_med = !p.options.always_compare_med;
                    p.options.default_local_pref = Some(7);
                    p.networks.clear();
                    p.aggregates.clear();
                }),
            ),
        ));
        for a in p.neighbors.keys().copied() {
            out.push((
                d.clone(),
                (
                    ObjectRef::Neighbor {
                        device: d.clone(),
                        vrf: v.clone(),
                        address: a,
                    },
                    Box::new(move |p: &mut BgpProcess| {
                        let n = p.neighbors.get_mut(&a).unwrap();
                        n.route_reflector_client = !n.route_reflector_client;
                        n.next_hop_self = NextHopSelf::All;
                        n.send_community = false;
                        n.import_policy = Some("unused".to_string());
                        n.export_policy = None;
                        n.remote_as = rsim_routing::bgp::Asn(64999);
                    }),
                ),
            ));
        }
        for name in p.policy.policies.keys().cloned() {
            let n2 = name.clone();
            out.push((
                d.clone(),
                (
                    ObjectRef::Policy {
                        device: d.clone(),
                        vrf: v.clone(),
                        name,
                    },
                    Box::new(move |p: &mut BgpProcess| {
                        p.policy.policies.insert(n2.clone(), route_map(&n2, vec![]));
                    }),
                ),
            ));
        }
        for name in p.policy.prefix_lists.keys().cloned() {
            let n2 = name.clone();
            out.push((
                d.clone(),
                (
                    ObjectRef::PrefixList {
                        device: d.clone(),
                        vrf: v.clone(),
                        name,
                    },
                    Box::new(move |p: &mut BgpProcess| {
                        p.policy
                            .prefix_lists
                            .insert(n2.clone(), PrefixList::new(vec![]));
                    }),
                ),
            ));
        }
        for name in p.policy.community_lists.keys().cloned() {
            let n2 = name.clone();
            out.push((
                d.clone(),
                (
                    ObjectRef::CommunityList {
                        device: d.clone(),
                        vrf: v.clone(),
                        name,
                    },
                    Box::new(move |p: &mut BgpProcess| {
                        p.policy
                            .community_lists
                            .insert(n2.clone(), CommunityList::new(vec![]));
                    }),
                ),
            ));
        }
        for name in p.policy.as_path_lists.keys().cloned() {
            let n2 = name.clone();
            out.push((
                d.clone(),
                (
                    ObjectRef::AsPathList {
                        device: d.clone(),
                        vrf: v.clone(),
                        name,
                    },
                    Box::new(move |p: &mut BgpProcess| {
                        p.policy
                            .as_path_lists
                            .insert(n2.clone(), AsPathList::new(vec![]));
                    }),
                ),
            ));
        }
    }
    out
}

#[test]
fn each_stage_reads_only_the_objects_that_it_declares() {
    let base = world();
    for (name, stage) in stages() {
        let (reads, want) = stage(&base);
        let (mut applied, mut declared, mut changed) = (0, 0, 0);
        for (device, (object, change)) in mutations(&base) {
            let mut w = base.clone();
            change(w.iter_mut().find(|p| p.device == device).unwrap());
            let (_, got) = stage(&w);
            if reads.contains(&object) {
                declared += 1;
                if got != want {
                    changed += 1;
                }
                continue;
            }
            applied += 1;
            assert_eq!(got, want, "{name}: {object:?} is not declared");
        }
        assert!(
            applied > 0 && declared > 0 && changed > 0,
            "{name}: {applied} {declared} {changed}"
        );
    }
}

#[test]
fn the_session_stage_declares_both_ends_and_both_policies() {
    let w = world();
    let session = Session {
        a: SessionEnd {
            device: "r1".to_string(),
            vrf: "default".to_string(),
            neighbor: ip("10.0.0.2"),
        },
        b: SessionEnd {
            device: "r2".to_string(),
            vrf: "default".to_string(),
            neighbor: ip("10.0.0.1"),
        },
    };
    let s = SessionStage {
        sender: find(&w, "r1"),
        receiver: find(&w, "r2"),
        session: &session,
    };
    let reads = s.reads();
    let policy = |d: &str, n: &str| ObjectRef::Policy {
        device: d.to_string(),
        vrf: "default".to_string(),
        name: n.to_string(),
    };
    assert!(reads.contains(&policy("r1", "out")));
    assert!(reads.contains(&policy("r2", "r2-in")));
    assert!(!reads.contains(&policy("r1", "in")));
    assert!(!reads.contains(&policy("r2", "r2-other")));
    let addr: IpAddr = ip("10.0.5.3");
    assert!(!reads.contains(&ObjectRef::Neighbor {
        device: "r2".to_string(),
        vrf: "default".to_string(),
        address: addr,
    }));
}
