//! The decision function: the best path of one route from its candidates
//! (RFC 4271 9.1.2.2 with the vendor steps of the profile).
//!
//! With always-compare-med, the candidates form a total preorder and the
//! result does not depend on their order. With deterministic MED, the
//! candidates are grouped by their neighbour AS, the best of each group is
//! selected, and the group winners are compared; the result does not depend
//! on the order either. With neither, the candidates are compared in their
//! input order, each with the best so far, as a device compares them in its
//! list order. MED then makes the comparison non-transitive, and the result
//! can depend on the input order.
//!
//! The oldest-path step is not modelled. Two eBGP paths that are equal
//! through the IGP cost give a tie, unless compare-routerid is set.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use super::process::{BgpOptions, BgpProcess};
use super::profile::BgpProfile;
use super::stage::{ObjectRef, RoutingStage};
use super::{BgpOrigin, BgpPath, LocalOrigin, NeighbourAs, Reason, RouteKey, SessionKind, Unknown};

/// One step of the decision, in the order of [`super::profile::DECISION_ORDER`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DecisionStep {
    Weight,
    LocalPreference,
    LocallyOriginated,
    AsPathLength,
    Origin,
    Med,
    ExternalOverInternal,
    IgpCost,
    OldestPath,
    RouterId,
    ClusterListLength,
    NeighborAddress,
}

/// The result of the decision. The numbers are indexes into the
/// candidates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    NoCandidate,
    Best {
        best: usize,
        /// The last step that separates the best path from another
        /// candidate. `None` for a sole candidate.
        step: Option<DecisionStep>,
        /// The best path and the paths that a multipath installs with it:
        /// the best path first, then by router ID, cluster-list length and
        /// neighbour address.
        multipath: Vec<usize>,
        /// The maximum paths. `None` when it is a build value of the
        /// platform: `multipath` then holds each eligible path.
        multipath_limit: Option<u32>,
    },
    /// The decision reaches `step` with more than one path. `OldestPath`
    /// for eBGP paths with no compare-routerid, `NeighborAddress` for paths
    /// that are equal in each step.
    Tie {
        /// In ascending index order.
        tied: Vec<usize>,
        step: DecisionStep,
        /// The multipath of the first tied path.
        multipath: Vec<usize>,
        multipath_limit: Option<u32>,
    },
    Unknown(Unknown),
}

/// The result of the comparison of path `a` with path `b`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rank {
    Better(DecisionStep),
    Worse(DecisionStep),
    /// The comparison stops at the step with no result.
    Same(DecisionStep),
}

struct Comparator<'a> {
    profile: &'a BgpProfile,
    always_med: bool,
    missing_worst: bool,
    compare_routerid: bool,
    default_lp: u32,
}

impl Comparator<'_> {
    fn local_rank(&self, p: &BgpPath) -> u8 {
        match p.peer.kind {
            SessionKind::Local(LocalOrigin::Aggregate) if self.profile.aggregate_below_network => 1,
            SessionKind::Local(_) => 2,
            _ => 0,
        }
    }

    fn med(&self, p: &BgpPath) -> u32 {
        p.med
            .unwrap_or(if self.missing_worst { u32::MAX } else { 0 })
    }

    fn med_compares(&self, a: &BgpPath, b: &BgpPath) -> bool {
        if self.always_med {
            return true;
        }
        let (x, y) = (a.as_path.neighbour_as(), b.as_path.neighbour_as());
        x == y && x != NeighbourAs::Set
    }

    /// `Greater` when `a` ranks above `b` in `step`.
    fn step(&self, step: DecisionStep, a: &BgpPath, b: &BgpPath) -> Option<Ordering> {
        let origin = |p: &BgpPath| match p.origin {
            BgpOrigin::Igp => 2,
            BgpOrigin::Egp => 1,
            BgpOrigin::Incomplete => 0,
        };
        let rid = |p: &BgpPath| p.originator_id.unwrap_or(p.peer.router_id);
        Some(match step {
            DecisionStep::Weight => a.weight.cmp(&b.weight),
            DecisionStep::LocalPreference => a
                .local_pref
                .unwrap_or(self.default_lp)
                .cmp(&b.local_pref.unwrap_or(self.default_lp)),
            DecisionStep::LocallyOriginated => self.local_rank(a).cmp(&self.local_rank(b)),
            DecisionStep::AsPathLength => b.as_path.len().cmp(&a.as_path.len()),
            DecisionStep::Origin => origin(a).cmp(&origin(b)),
            DecisionStep::Med if self.med_compares(a, b) => self.med(b).cmp(&self.med(a)),
            DecisionStep::Med => Ordering::Equal,
            DecisionStep::ExternalOverInternal => {
                (a.peer.kind == SessionKind::Ebgp).cmp(&(b.peer.kind == SessionKind::Ebgp))
            }
            DecisionStep::IgpCost => b.igp_cost.cmp(&a.igp_cost),
            DecisionStep::OldestPath => {
                if a.peer.kind == SessionKind::Ebgp
                    && b.peer.kind == SessionKind::Ebgp
                    && !self.compare_routerid
                {
                    return None;
                }
                Ordering::Equal
            }
            DecisionStep::RouterId => rid(b).cmp(&rid(a)),
            DecisionStep::ClusterListLength => b.cluster_list.len().cmp(&a.cluster_list.len()),
            DecisionStep::NeighborAddress => b.peer.address.cmp(&a.peer.address),
        })
    }

    fn compare(&self, a: &BgpPath, b: &BgpPath) -> Rank {
        let mut last = DecisionStep::NeighborAddress;
        for &step in self.profile.order {
            last = step;
            match self.step(step, a, b) {
                None => return Rank::Same(step),
                Some(Ordering::Greater) => return Rank::Better(step),
                Some(Ordering::Less) => return Rank::Worse(step),
                Some(Ordering::Equal) => {}
            }
        }
        Rank::Same(last)
    }

    /// True if `a` and `b` are equal in each step up to the IGP cost.
    fn equal_through_igp(&self, a: &BgpPath, b: &BgpPath) -> bool {
        match self.compare(a, b) {
            Rank::Same(_) => true,
            Rank::Better(s) | Rank::Worse(s) => s > DecisionStep::IgpCost,
        }
    }

    /// The best paths of `group`, each compared with the best so far, in
    /// the order of `group`.
    fn fold(&self, c: &[BgpPath], group: impl IntoIterator<Item = Vec<usize>>) -> Vec<usize> {
        let mut win: Vec<usize> = Vec::new();
        for set in group {
            let Some(&first) = set.first() else {
                continue;
            };
            if win.is_empty() {
                win = set;
                continue;
            }
            match self.compare(&c[first], &c[win[0]]) {
                Rank::Better(_) => win = set,
                Rank::Same(_) => win.extend(set),
                Rank::Worse(_) => {}
            }
        }
        win
    }
}

/// The best path of a route from its candidates under the options of the
/// process and the profile of the platform.
///
/// Each candidate is a path whose next hop resolves, with its IGP cost.
/// More than one candidate with a path whose attributes are not collected
/// gives `Unknown` with the reason "path attributes not collected". No
/// profile gives `Unknown` with the reason "no bgp profile".
pub fn decide(
    candidates: &[BgpPath],
    options: &BgpOptions,
    profile: Option<&BgpProfile>,
) -> Decision {
    if candidates.is_empty() {
        return Decision::NoCandidate;
    }
    let Some(profile) = profile else {
        return Decision::Unknown(Unknown::new(Reason::NoBgpProfile, "the platform"));
    };
    if candidates.len() > 1 {
        let not_collected: BTreeSet<String> = candidates
            .iter()
            .filter(|p| !p.attributes_collected)
            .map(|p| match p.peer.address {
                Some(a) => format!("path from {a}"),
                None => "local path".to_string(),
            })
            .collect();
        if !not_collected.is_empty() {
            return Decision::Unknown(Unknown {
                reason: Reason::PathAttributesNotCollected,
                details: not_collected,
            });
        }
    }
    let cmp = Comparator {
        profile,
        always_med: options.always_compare_med,
        missing_worst: profile.missing_as_worst(options),
        compare_routerid: options.compare_routerid,
        default_lp: profile.default_local_pref(options),
    };
    let mut win = if !cmp.always_med && profile.deterministic_med(options) {
        let mut groups: BTreeMap<(NeighbourAs, Option<usize>), Vec<usize>> = BTreeMap::new();
        for (i, p) in candidates.iter().enumerate() {
            let n = p.as_path.neighbour_as();
            let own = (n == NeighbourAs::Set).then_some(i);
            groups.entry((n, own)).or_default().push(i);
        }
        let winners: Vec<Vec<usize>> = groups
            .into_values()
            .map(|g| cmp.fold(candidates, g.into_iter().map(|i| vec![i])))
            .collect();
        cmp.fold(candidates, winners)
    } else {
        cmp.fold(candidates, (0..candidates.len()).map(|i| vec![i]))
    };
    win.sort_unstable();
    let base = win[0];
    let limit = profile.maximum_paths(candidates[base].peer.kind, options);
    let multipath = multipath(candidates, base, &cmp, options, limit);
    if win.len() > 1 {
        let step = match cmp.compare(&candidates[win[0]], &candidates[win[1]]) {
            Rank::Same(s) | Rank::Better(s) | Rank::Worse(s) => s,
        };
        return Decision::Tie {
            tied: win,
            step,
            multipath,
            multipath_limit: limit,
        };
    }
    let step = (0..candidates.len())
        .filter(|&j| j != base)
        .filter_map(|j| match cmp.compare(&candidates[base], &candidates[j]) {
            Rank::Better(s) => Some(s),
            _ => None,
        })
        .max();
    Decision::Best {
        best: base,
        step,
        multipath,
        multipath_limit: limit,
    }
}

/// The paths that a multipath installs with `base`, `base` first: the
/// paths of the same session class (eBGP, or iBGP and confederation eBGP)
/// that are equal to `base` through the IGP cost, with the same AS path
/// (the same length under multipath-relax) and a next hop that no earlier
/// path of the list has. Cut to `limit` when it is known.
fn multipath(
    c: &[BgpPath],
    base: usize,
    cmp: &Comparator<'_>,
    options: &BgpOptions,
    limit: Option<u32>,
) -> Vec<usize> {
    let b = &c[base];
    let class = |k: SessionKind| match k {
        SessionKind::Ebgp => Some(0),
        SessionKind::Ibgp | SessionKind::ConfedEbgp => Some(1),
        SessionKind::Local(_) => None,
    };
    let mut out = vec![base];
    if class(b.peer.kind).is_none() {
        return out;
    }
    let mut eligible: Vec<usize> = (0..c.len())
        .filter(|&j| {
            j != base
                && class(c[j].peer.kind) == class(b.peer.kind)
                && cmp.equal_through_igp(b, &c[j])
                && (if options.multipath_relax {
                    c[j].as_path.len() == b.as_path.len()
                } else {
                    c[j].as_path == b.as_path
                })
        })
        .collect();
    eligible.sort_by_key(|&j| {
        let p = &c[j];
        (
            p.originator_id.unwrap_or(p.peer.router_id),
            p.cluster_list.len(),
            p.peer.address,
            j,
        )
    });
    let mut hops = BTreeSet::from([b.next_hop]);
    for j in eligible {
        if hops.insert(c[j].next_hop) {
            out.push(j);
        }
    }
    if let Some(n) = limit {
        out.truncate(n.max(1) as usize);
    }
    out
}

/// The decision stage of one route at one process.
pub struct DecisionStage<'a> {
    pub process: &'a BgpProcess,
    pub key: RouteKey,
}

impl RoutingStage for DecisionStage<'_> {
    type Input = Vec<BgpPath>;
    type Output = Decision;

    fn name(&self) -> &'static str {
        "bgp decision"
    }

    fn reads(&self) -> BTreeSet<ObjectRef> {
        let (device, vrf) = (self.process.device.clone(), self.process.vrf.clone());
        BTreeSet::from([
            ObjectRef::Profile(self.process.platform),
            ObjectRef::Process {
                device: device.clone(),
                vrf: vrf.clone(),
            },
            ObjectRef::Candidates {
                device,
                vrf,
                key: self.key,
            },
        ])
    }

    fn run(&self, input: &Vec<BgpPath>) -> Decision {
        decide(
            input,
            &self.process.options,
            self.process.profile().as_ref(),
        )
    }
}
