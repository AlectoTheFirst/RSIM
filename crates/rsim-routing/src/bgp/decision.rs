//! The decision function: the best path of one route from its candidates
//! (RFC 4271 9.1.2.2 with the vendor steps of the profile).
//!
//! With always-compare-med, the candidates form a total preorder and the
//! result does not depend on their order. With deterministic MED, the
//! candidates are grouped by their neighbour AS, the best of each group is
//! selected, and the group winners are compared. This result does not
//! depend on the order either. With neither, `decide` compares the
//! candidates in their input order, each with the best so far, as a device
//! compares them in its list order. MED then makes the comparison
//! non-transitive, and the result can depend on the input order.
//! `order_winners` gives each candidate that is the best path in some order.
//!
//! The oldest-path step is not modelled. Two eBGP paths that are equal
//! through the IGP cost give a tie, unless compare-routerid is set. A
//! comparison that reaches the router-ID step with a router ID that is not
//! known gives `Unknown`.

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
    /// The comparison reaches the router-ID step, and a router ID is not
    /// known.
    Unknown,
}

/// The router ID of the decision: the ORIGINATOR_ID, else the router ID of
/// the peer.
fn router_id(p: &BgpPath) -> Option<std::net::Ipv4Addr> {
    p.originator_id.or(p.peer.router_id)
}

/// True if the router-ID step of `a` and `b` has no known result: a router
/// ID is not known, and the 2 paths do not come from the same peer.
fn router_id_unknown(a: &BgpPath, b: &BgpPath) -> bool {
    let same_peer = a.originator_id.is_none()
        && b.originator_id.is_none()
        && a.peer.address.is_some()
        && a.peer.address == b.peer.address;
    (router_id(a).is_none() || router_id(b).is_none()) && !same_peer
}

/// The reason of a decision that needs a router ID that is not known.
fn router_id_reason(c: &[BgpPath]) -> Unknown {
    Unknown {
        reason: Reason::RouterIdNotKnown,
        details: c
            .iter()
            .filter(|p| router_id(p).is_none())
            .map(|p| match p.peer.address {
                Some(a) => format!("path from {a}"),
                None => "local path".to_string(),
            })
            .collect(),
    }
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
            DecisionStep::RouterId => router_id(b).cmp(&router_id(a)),
            DecisionStep::ClusterListLength => b.cluster_list.len().cmp(&a.cluster_list.len()),
            DecisionStep::NeighborAddress => b.peer.address.cmp(&a.peer.address),
        })
    }

    fn compare(&self, a: &BgpPath, b: &BgpPath) -> Rank {
        let mut last = DecisionStep::NeighborAddress;
        for &step in self.profile.order {
            last = step;
            if step == DecisionStep::RouterId && router_id_unknown(a, b) {
                return Rank::Unknown;
            }
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
            Rank::Same(_) | Rank::Unknown => true,
            Rank::Better(s) | Rank::Worse(s) => s > DecisionStep::IgpCost,
        }
    }

    /// The best paths of `group`, each compared with the best so far, in
    /// the order of `group`. `None` when a comparison needs a router ID that
    /// is not known.
    fn fold(
        &self,
        c: &[BgpPath],
        group: impl IntoIterator<Item = Vec<usize>>,
    ) -> Option<Vec<usize>> {
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
                Rank::Unknown => return None,
            }
        }
        Some(win)
    }
}

fn comparator<'a>(profile: &'a BgpProfile, options: &BgpOptions) -> Comparator<'a> {
    Comparator {
        profile,
        always_med: options.always_compare_med,
        missing_worst: profile.missing_as_worst(options),
        compare_routerid: options.compare_routerid,
        default_lp: profile.default_local_pref(options),
    }
}

/// The multipath of `base` among `candidates`, as [`Decision`] gives it for
/// a best path, with `base` first.
pub(crate) fn multipath_for(
    candidates: &[BgpPath],
    base: usize,
    options: &BgpOptions,
    profile: &BgpProfile,
) -> Result<Vec<usize>, Unknown> {
    let cmp = comparator(profile, options);
    let limit = profile.maximum_paths(candidates[base].peer.kind, options);
    multipath(candidates, base, &cmp, options, limit)
}

/// The candidates that are a best path of [`decide`] in some order of
/// `candidates`, in ascending index order. `Ok(None)` when the result does
/// not depend on the order: with always-compare-med, with deterministic
/// MED, with no profile, and when no pair of the top candidates is decided
/// by the MED or each top candidate has the same neighbour AS. The top
/// candidates are the candidates that no candidate beats in a step before
/// the MED. They are the only candidates that can win in an order.
///
/// The set is exact. Each state of the calculation is a set of compared
/// top candidates with the tied paths of one order of them, so its size
/// grows with the number of subsets of the top candidates. A comparison
/// that needs a router ID that is not known gives `Unknown` with the reason
/// "router id not known".
pub fn order_winners(
    candidates: &[BgpPath],
    options: &BgpOptions,
    profile: Option<&BgpProfile>,
) -> Result<Option<Vec<usize>>, Unknown> {
    let Some(profile) = profile else {
        return Ok(None);
    };
    let cmp = comparator(profile, options);
    if cmp.always_med || profile.deterministic_med(options) {
        return Ok(None);
    }
    let n = candidates.len();
    let top: Vec<usize> = (0..n)
        .filter(|&x| {
            !(0..n).any(|y| {
                matches!(
                    cmp.compare(&candidates[y], &candidates[x]),
                    Rank::Better(s) if s < DecisionStep::Med
                )
            })
        })
        .collect();
    let med_pair = top.iter().enumerate().any(|(i, &a)| {
        top[i + 1..].iter().any(|&b| {
            matches!(
                cmp.compare(&candidates[a], &candidates[b]),
                Rank::Better(DecisionStep::Med) | Rank::Worse(DecisionStep::Med)
            )
        })
    });
    if !med_pair {
        return Ok(None);
    }
    let first = candidates[top[0]].as_path.neighbour_as();
    if first != NeighbourAs::Set
        && top
            .iter()
            .all(|&x| candidates[x].as_path.neighbour_as() == first)
    {
        return Ok(None);
    }
    let mut layer: BTreeMap<BTreeSet<usize>, BTreeSet<Vec<usize>>> =
        BTreeMap::from([(BTreeSet::new(), BTreeSet::from([Vec::new()]))]);
    for _ in 0..top.len() {
        let mut next: BTreeMap<BTreeSet<usize>, BTreeSet<Vec<usize>>> = BTreeMap::new();
        for (done, wins) in &layer {
            for &x in top.iter().filter(|x| !done.contains(x)) {
                let mut key = done.clone();
                key.insert(x);
                let entry = next.entry(key).or_default();
                for win in wins {
                    let w = match win.first() {
                        None => vec![x],
                        Some(&first) => match cmp.compare(&candidates[x], &candidates[first]) {
                            Rank::Better(_) => vec![x],
                            Rank::Same(_) => {
                                let mut w = win.clone();
                                w.push(x);
                                w
                            }
                            Rank::Worse(_) => win.clone(),
                            Rank::Unknown => return Err(router_id_reason(candidates)),
                        },
                    };
                    entry.insert(w);
                }
            }
        }
        layer = next;
    }
    let winners: BTreeSet<usize> = layer.into_values().flatten().flatten().collect();
    Ok(Some(winners.into_iter().collect()))
}

/// The best path of a route from its candidates under the options of the
/// process and the profile of the platform.
///
/// Each candidate is a path whose next hop resolves, with its IGP cost.
/// More than one candidate with a path whose attributes are not collected
/// gives `Unknown` with the reason "path attributes not collected". No
/// profile gives `Unknown` with the reason "no bgp profile". A comparison
/// that needs a router ID that is not known, and a multipath whose limit
/// cuts paths in an order of router IDs that are not known, give `Unknown`
/// with the reason "router id not known".
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
    let cmp = comparator(profile, options);
    let win = if !cmp.always_med && profile.deterministic_med(options) {
        let mut groups: BTreeMap<(NeighbourAs, Option<usize>), Vec<usize>> = BTreeMap::new();
        for (i, p) in candidates.iter().enumerate() {
            let n = p.as_path.neighbour_as();
            let own = (n == NeighbourAs::Set).then_some(i);
            groups.entry((n, own)).or_default().push(i);
        }
        let winners: Option<Vec<Vec<usize>>> = groups
            .into_values()
            .map(|g| cmp.fold(candidates, g.into_iter().map(|i| vec![i])))
            .collect();
        winners.and_then(|w| cmp.fold(candidates, w))
    } else {
        cmp.fold(candidates, (0..candidates.len()).map(|i| vec![i]))
    };
    let Some(mut win) = win else {
        return Decision::Unknown(router_id_reason(candidates));
    };
    win.sort_unstable();
    let base = win[0];
    let limit = profile.maximum_paths(candidates[base].peer.kind, options);
    let multipath = match multipath(candidates, base, &cmp, options, limit) {
        Ok(m) => m,
        Err(u) => return Decision::Unknown(u),
    };
    if win.len() > 1 {
        let step = match cmp.compare(&candidates[win[0]], &candidates[win[1]]) {
            Rank::Same(s) | Rank::Better(s) | Rank::Worse(s) => s,
            Rank::Unknown => DecisionStep::RouterId,
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
/// path of the list has. Cut to `limit` when it is known. A cut of a list
/// with a path after `base` whose router ID is not known is `Unknown`.
fn multipath(
    c: &[BgpPath],
    base: usize,
    cmp: &Comparator<'_>,
    options: &BgpOptions,
    limit: Option<u32>,
) -> Result<Vec<usize>, Unknown> {
    let b = &c[base];
    let class = |k: SessionKind| match k {
        SessionKind::Ebgp => Some(0),
        SessionKind::Ibgp | SessionKind::ConfedEbgp => Some(1),
        SessionKind::Local(_) => None,
    };
    let mut out = vec![base];
    if class(b.peer.kind).is_none() {
        return Ok(out);
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
        (router_id(p), p.cluster_list.len(), p.peer.address, j)
    });
    let mut hops = BTreeSet::from([b.next_hop]);
    for j in eligible {
        if hops.insert(c[j].next_hop) {
            out.push(j);
        }
    }
    if let Some(n) = limit {
        let n = n.max(1) as usize;
        if out.len() > n && out[1..].iter().any(|&j| router_id(&c[j]).is_none()) {
            let paths: Vec<BgpPath> = out.iter().map(|&j| c[j].clone()).collect();
            return Err(router_id_reason(&paths));
        }
        out.truncate(n);
    }
    Ok(out)
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
