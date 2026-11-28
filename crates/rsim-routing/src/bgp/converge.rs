//! The convergence detection of each prefix group and the result of the
//! BGP calculation.
//!
//! A prefix group holds the keys that depend on each other: an aggregate
//! with the keys inside it, and each key whose prefix holds a possible next
//! hop with all keys. Each group runs alone, in the order of its first key.
//!
//! 1. The forward pass runs synchronous rounds from the state with no best
//!    path. Each round computes the best path of each variable from the
//!    best paths of the round before. Brent's algorithm finds the fixed
//!    point or the cycle by exact comparison of the states.
//! 2. The uniqueness check builds the possible candidates of each variable
//!    by a closure over the sessions. It applies when no process with a
//!    candidate in the group has a route-reflector client, no candidate is unknown, and no
//!    pair of candidates of a variable is decided by the MED with no
//!    always-compare-med, by the IGP cost, or by a tie. The greedy
//!    construction of Griffin, Shepherd and Wilfong then fixes a variable
//!    when its selection from the fixed variables does not change by any
//!    possible candidate from a variable that is not fixed. A fixed point
//!    with each variable fixed to its value is `Converged`.
//! 3. Else the search assigns each variable that is not fixed a source:
//!    no path, an unknown path, the `network` path, the aggregate path, a
//!    seed or a session. The path of a variable follows from its source and
//!    the path of the sender. An assignment is stable when the source of
//!    each variable gives its selection, or a tied path of it. The search
//!    has no bound.
//! 4. 2 stable assignments are distinct when they differ in the paths that
//!    a variable installs or in a path that a variable sends. 0 distinct
//!    outcomes give `NoConvergence` with the cycle of the forward pass, and
//!    each variable with a possible candidate is unknown. 1 with no
//!    unknown route gives `Converged` with a note: "not safe under all
//!    timings" when the greedy construction stops at a dispute wheel or the
//!    forward pass cycles, and "safety under all timings not checked"
//!    otherwise. 1 with an unknown route gives the result `Unknown` with
//!    the reason "convergence not determined" and the text of each unknown
//!    route of the outcome as its details, and each variable with a
//!    possible candidate is unknown. More give `MultipleStableOutcomes`,
//!    and the routes of the group are unknown.
//!    0 outcomes with a fixed point of the forward pass give the result
//!    `Unknown` with the reason "internal error".

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{Prefix, SourceSpan};
use rsim_functions::{Route, RouteKind, RouteProtocol};

use super::decision::{Decision, DecisionStep, decide};
use super::process::BgpProcess;
use super::propagate::{
    BestPath, BgpInput, Cand, Choice, Group, IgpView, InputError, Net, Selection, Source, inside,
};
use super::session::Offer;
use super::{BgpPath, Family, LocalOrigin, Reason, RouteKey, SessionKind, Unknown};
use crate::install::Candidate;
use crate::platform::{Origin, Platform};

/// The note of a group with one stable outcome and a dispute wheel, or
/// with one stable outcome and a cycle of the forward pass.
pub const NOT_SAFE: &str = "not safe under all timings";

/// The note of a group with one stable outcome of the search, a fixed point
/// of the forward pass and no dispute wheel.
pub const NOT_CHECKED: &str = "safety under all timings not checked";

/// A route key at a process.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteAt {
    pub device: String,
    pub vrf: String,
    pub key: RouteKey,
}

/// The computed state of a route at a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteState {
    Selected(Box<Selection>),
    Unknown(Unknown),
}

/// One stable outcome of a group: the state of each route with a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub routes: BTreeMap<RouteAt, RouteState>,
}

/// One spoke of a dispute wheel: the route `at` prefers the path
/// `prefers` through the route `through` over its selection from the fixed
/// routes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WheelSpoke {
    pub at: RouteAt,
    pub through: RouteAt,
    pub prefers: BgpPath,
}

/// The note of a group with one stable outcome of the search: [`NOT_SAFE`]
/// or [`NOT_CHECKED`]. `wheel` is the dispute wheel where the greedy
/// construction stops, and empty when it finds none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub text: &'static str,
    pub wheel: Vec<WheelSpoke>,
}

/// The cycle of the forward pass: it starts at round `first_round` and
/// repeats after `length` rounds. `changing` holds the best path in each
/// round of the cycle of each route that changes in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CycleWitness {
    pub first_round: usize,
    pub length: usize,
    pub changing: BTreeMap<RouteAt, Vec<BestPath>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Convergence {
    Converged {
        note: Option<Note>,
    },
    MultipleStableOutcomes {
        outcomes: Vec<Outcome>,
    },
    NoConvergence {
        cycle: CycleWitness,
    },
    /// The calculation reaches no result.
    Unknown {
        reason: Unknown,
    },
}

/// The kind of a [`Convergence`], from the best to the worst.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConvergenceKind {
    Converged,
    MultipleStableOutcomes,
    NoConvergence,
    Unknown,
}

impl Convergence {
    pub fn kind(&self) -> ConvergenceKind {
        match self {
            Convergence::Converged { .. } => ConvergenceKind::Converged,
            Convergence::MultipleStableOutcomes { .. } => ConvergenceKind::MultipleStableOutcomes,
            Convergence::NoConvergence { .. } => ConvergenceKind::NoConvergence,
            Convergence::Unknown { .. } => ConvergenceKind::Unknown,
        }
    }
}

/// The result of one prefix group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupResult {
    pub keys: BTreeSet<RouteKey>,
    pub convergence: Convergence,
    /// The rounds that the forward pass runs until Brent's algorithm finds
    /// the fixed point or the cycle.
    pub rounds: usize,
    /// True if the forward pass reaches a fixed point. The routes of a
    /// converged group are then the routes of the fixed point.
    pub fixed_point: bool,
}

/// An event of the calculation for the 3D view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A round of the forward pass of group `group` and the routes whose
    /// best path changed in it.
    Round {
        group: usize,
        round: usize,
        changed: BTreeSet<RouteAt>,
    },
    /// The search of group `group` with the number of distinct stable
    /// outcomes and its result.
    Search {
        group: usize,
        outcomes: usize,
        result: ConvergenceKind,
    },
}

/// The result of the BGP calculation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BgpResult {
    /// The state of each route with a path. The routes of a group with a
    /// result other than `Converged` are unknown.
    pub routes: BTreeMap<RouteAt, RouteState>,
    pub groups: Vec<GroupResult>,
    pub events: Vec<Event>,
    /// The worst result over the groups. `Converged` with no group.
    pub worst: ConvergenceKind,
    /// The keys of the groups with a result other than `Converged`.
    pub affected: BTreeSet<RouteKey>,
}

/// The prefix groups of the input, in the order of their first key.
pub(crate) fn key_groups(net: &Net<'_>) -> Vec<BTreeSet<RouteKey>> {
    let keys: Vec<RouteKey> = net.keys().into_iter().collect();
    let mut parent: Vec<usize> = (0..keys.len()).collect();
    fn root(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    fn union(parent: &mut [usize], a: usize, b: usize) {
        let (ra, rb) = (root(parent, a), root(parent, b));
        if ra != rb {
            parent[ra.max(rb)] = ra.min(rb);
        }
    }
    for p in &net.procs {
        for a in &p.aggregates {
            let Ok(ai) = keys.binary_search(&a.key) else {
                continue;
            };
            for (j, k) in keys.iter().enumerate() {
                if inside(k, &a.key) {
                    union(&mut parent, ai, j);
                }
            }
        }
    }
    for (j, k) in keys.iter().enumerate() {
        if k.family == Family::EvpnIpPrefix
            && let Ok(u) = keys.binary_search(&RouteKey::unicast(k.prefix))
        {
            union(&mut parent, u, j);
        }
    }
    let hops = net.next_hop_addresses();
    for (j, k) in keys.iter().enumerate() {
        if hops.iter().any(|a| k.prefix.contains(*a)) {
            for i in 0..keys.len() {
                union(&mut parent, i, j);
            }
        }
    }
    let mut groups: BTreeMap<usize, BTreeSet<RouteKey>> = BTreeMap::new();
    for (j, k) in keys.iter().enumerate() {
        let r = root(&mut parent, j);
        groups.entry(r).or_default().insert(*k);
    }
    groups.into_values().collect()
}

fn route_at(g: &Group<'_, '_>, v: usize) -> RouteAt {
    let (p, key) = g.at(v);
    RouteAt {
        device: p.device.clone(),
        vrf: p.vrf.clone(),
        key,
    }
}

fn plain(p: &BgpPath) -> BgpPath {
    let mut q = p.clone();
    q.spans.clear();
    q
}

fn plain_offer(o: Offer) -> BestPath {
    match o {
        Offer::None => BestPath::None,
        Offer::Path(p) => BestPath::Path(plain(&p)),
        Offer::Unknown(u) => BestPath::Unknown(u),
    }
}

/// The part of an outcome that tells 2 outcomes apart, for each variable:
/// the installed paths and the sent paths.
type OutcomeKey = Vec<(Option<BTreeSet<BgpPath>>, Vec<BestPath>)>;

/// The routes and the key of the outcome with the best paths `picks`.
fn outcome(g: &Group<'_, '_>, picks: &[BestPath]) -> (OutcomeKey, BTreeMap<RouteAt, RouteState>) {
    let mut routes = BTreeMap::new();
    let mut key = Vec::with_capacity(picks.len());
    let get = |w: usize| Some(picks[w].clone());
    for (v, pick) in picks.iter().enumerate() {
        let choice = g.choice(v, picks);
        let installed = match (pick, &choice) {
            (BestPath::None, _) => Some(BTreeSet::new()),
            (BestPath::Unknown(u), c) => {
                let u = match c {
                    Choice::Unknown(cu) => cu.clone(),
                    _ => u.clone(),
                };
                routes.insert(route_at(g, v), RouteState::Unknown(u));
                None
            }
            (BestPath::Path(p), c) => match c.selection_of(p) {
                Some(sel) => {
                    routes.insert(route_at(g, v), RouteState::Selected(Box::new(sel.clone())));
                    Some(sel.multipath.iter().map(plain).collect())
                }
                None => None,
            },
        };
        let held = g.suppressed(v, &get).expect("a full state");
        let sent = g.outlinks[v]
            .iter()
            .map(|&l| match held {
                Some(true) => BestPath::None,
                Some(false) => plain_offer(g.sent(l, v, pick)),
                None => BestPath::Unknown(Unknown::new(
                    Reason::SelectionNotKnown,
                    "summary-only aggregate".to_string(),
                )),
            })
            .collect();
        key.push((installed, sent));
    }
    (key, routes)
}

/// The forward pass: the fixed point, or the cycle states with the first
/// round of the cycle, and the number of rounds.
enum Forward {
    Fixed(Vec<BestPath>),
    Cycle {
        first_round: usize,
        states: Vec<Vec<BestPath>>,
    },
}

fn forward(g: &Group<'_, '_>, gi: usize, events: &mut Vec<Event>) -> (Forward, usize) {
    let n = g.vars.len();
    let x0 = vec![BestPath::None; n];
    let mut rounds = 0;
    let mut step = |s: &[BestPath], events: &mut Vec<Event>| {
        let next = g.round(s);
        rounds += 1;
        let changed = (0..n)
            .filter(|&v| s[v] != next[v])
            .map(|v| route_at(g, v))
            .collect();
        events.push(Event::Round {
            group: gi,
            round: rounds,
            changed,
        });
        next
    };
    let mut power = 1usize;
    let mut lam = 1usize;
    let mut tortoise = x0.clone();
    let mut hare = step(&x0, events);
    while tortoise != hare {
        if power == lam {
            tortoise = hare.clone();
            power *= 2;
            lam = 0;
        }
        hare = step(&hare, events);
        lam += 1;
    }
    if lam == 1 {
        return (Forward::Fixed(hare), rounds);
    }
    let mut t = x0.clone();
    let mut h = x0;
    for _ in 0..lam {
        h = g.round(&h);
    }
    let mut mu = 0;
    while t != h {
        t = g.round(&t);
        h = g.round(&h);
        mu += 1;
    }
    let mut states = Vec::with_capacity(lam);
    for _ in 0..lam {
        let next = g.round(&t);
        states.push(t);
        t = next;
    }
    (
        Forward::Cycle {
            first_round: mu,
            states,
        },
        rounds,
    )
}

/// Each combination of one value of each list.
fn product(lists: &[Vec<BestPath>]) -> Vec<Vec<BestPath>> {
    let mut out = vec![Vec::new()];
    for list in lists {
        let mut next = Vec::new();
        for prefix in &out {
            for x in list {
                let mut p = prefix.clone();
                p.push(x.clone());
                next.push(p);
            }
        }
        out = next;
    }
    out
}

/// The possible candidates of `v` when each variable can hold each value
/// of its set in `dom`. A variable in `fixed` holds its fixed value only.
/// Each candidate has the variable that it depends on, `None` for a
/// candidate that depends on fixed variables only.
fn possible(
    g: &Group<'_, '_>,
    v: usize,
    dom: &[BTreeSet<BestPath>],
    fixed: &[Option<BestPath>],
) -> Vec<(Option<usize>, Cand)> {
    let values = |w: usize| -> Vec<BestPath> {
        match &fixed[w] {
            Some(x) => vec![x.clone()],
            None => dom[w].iter().cloned().collect(),
        }
    };
    let mut out = Vec::new();
    let mut push = |dep: Option<usize>, source: Source, offer: Offer| match offer {
        Offer::None => {}
        Offer::Path(p) => out.push((
            dep,
            Cand {
                source,
                offer: Ok(p),
            },
        )),
        Offer::Unknown(u) => out.push((
            dep,
            Cand {
                source,
                offer: Err(u),
            },
        )),
    };
    if let Some(n) = &g.network[v] {
        push(None, Source::Network, n.clone());
    }
    for (ri, o) in &g.redistributed[v] {
        push(None, Source::Redistribute(*ri), o.clone());
    }
    for (si, o) in &g.seeds[v] {
        push(None, Source::Seed(*si), o.clone());
    }
    for (pos, &(li, w)) in g.inleaks[v].iter().enumerate() {
        match &fixed[w] {
            Some(x) => push(None, Source::Leak(pos), g.leak(li, x)),
            None => {
                for x in values(w) {
                    push(Some(w), Source::Leak(pos), g.leak(li, &x));
                }
            }
        }
    }
    if g.has_aggregate[v] {
        let cs = &g.contributors[v];
        let dep = cs.iter().copied().find(|&c| fixed[c].is_none());
        let lists: Vec<Vec<BestPath>> = cs.iter().map(|&c| values(c)).collect();
        let mut seen = BTreeSet::new();
        for combo in product(&lists) {
            let o = g.aggregate(v, &combo);
            if seen.insert(o.clone()) {
                push(dep, Source::Aggregate, o);
            }
        }
    }
    for &(l, w) in &g.inlinks[v] {
        let dep = std::iter::once(w)
            .chain(g.suppressors[w].iter().copied())
            .find(|&x| fixed[x].is_none());
        let get = |x: usize| fixed[x].clone();
        if dep.is_none() {
            let best = fixed[w].clone().expect("fixed");
            let o = match g.suppressed(w, &get).expect("fixed") {
                Some(true) => Offer::None,
                Some(false) => g.transfer(l, w, &best),
                None => Offer::Unknown(Unknown::new(
                    Reason::SelectionNotKnown,
                    "summary-only aggregate".to_string(),
                )),
            };
            push(None, Source::Link(l), o);
        } else {
            for x in values(w) {
                push(dep, Source::Link(l), g.transfer(l, w, &x));
            }
        }
    }
    out
}

/// The possible best paths of each variable: `BestPath::None` and each
/// possible candidate, from a closure over the possible candidates of the
/// other variables.
fn domains(g: &Group<'_, '_>) -> Vec<BTreeSet<BestPath>> {
    let n = g.vars.len();
    let none = vec![None; n];
    let mut dom: Vec<BTreeSet<BestPath>> = vec![BTreeSet::from([BestPath::None]); n];
    loop {
        let mut changed = false;
        for v in 0..n {
            for (_, c) in possible(g, v, &dom, &none) {
                let b = match c.offer {
                    Ok(p) => BestPath::Path(p),
                    Err(u) => BestPath::Unknown(u),
                };
                changed |= dom[v].insert(b);
            }
        }
        if !changed {
            return dom;
        }
    }
}

/// True if the uniqueness check applies to the group with the domains
/// `dom`.
fn strict(g: &Group<'_, '_>, dom: &[BTreeSet<BestPath>]) -> bool {
    for (v, d) in dom.iter().enumerate() {
        if d.iter().any(|b| matches!(b, BestPath::Unknown(_))) {
            return false;
        }
        let held: Vec<&BgpPath> = d
            .iter()
            .filter_map(|b| match b {
                BestPath::Path(x) => Some(x),
                _ => None,
            })
            .collect();
        if held.is_empty() {
            continue;
        }
        let (p, _) = g.at(v);
        if p.neighbors.values().any(|nb| nb.route_reflector_client) {
            return false;
        }
        let Some(profile) = p.profile() else {
            return false;
        };
        for i in 0..held.len() {
            for j in i + 1..held.len() {
                let pair = [held[i].clone(), held[j].clone()];
                match decide(&pair, &p.options, Some(&profile)) {
                    Decision::Best { step, .. } => {
                        if step == Some(DecisionStep::IgpCost)
                            || (step == Some(DecisionStep::Med) && !p.options.always_compare_med)
                        {
                            return false;
                        }
                    }
                    _ => return false,
                }
            }
        }
    }
    true
}

/// The greedy construction: the fixed value of each variable that it
/// fixes, and the dispute wheel where it stops.
fn greedy(
    g: &Group<'_, '_>,
    dom: &[BTreeSet<BestPath>],
) -> (Vec<Option<BestPath>>, Option<Vec<WheelSpoke>>) {
    let n = g.vars.len();
    let mut fixed: Vec<Option<BestPath>> = vec![None; n];
    let mut blocks: Vec<Option<(usize, BgpPath)>> = vec![None; n];
    loop {
        let mut progress = false;
        for v in 0..n {
            if fixed[v].is_some() {
                continue;
            }
            blocks[v] = None;
            let all = possible(g, v, dom, &fixed);
            let definite: Vec<Cand> = all
                .iter()
                .filter(|(d, _)| d.is_none())
                .map(|(_, c)| c.clone())
                .collect();
            if all.iter().any(|(_, c)| c.offer.is_err()) {
                continue;
            }
            let base = g.choose(v, &definite);
            if matches!(base, Choice::Tie(_) | Choice::Unknown(_)) {
                continue;
            }
            let block = all.iter().find_map(|(d, c)| {
                let d = (*d)?;
                let mut with = definite.clone();
                with.push(c.clone());
                let changed = match (g.choose(v, &with), &base) {
                    (Choice::Best(_, a), Choice::Best(_, b)) => a != *b,
                    (Choice::None, Choice::None) => false,
                    _ => true,
                };
                changed.then(|| (d, c.offer.clone().expect("a path")))
            });
            match block {
                Some(b) => blocks[v] = Some(b),
                None => {
                    fixed[v] = Some(base.pick());
                    progress = true;
                }
            }
        }
        if !progress {
            break;
        }
    }
    let mut wheel = None;
    'start: for start in 0..n {
        if fixed[start].is_some() {
            continue;
        }
        let mut seen: Vec<usize> = Vec::new();
        let mut cur = start;
        loop {
            if let Some(pos) = seen.iter().position(|&x| x == cur) {
                let spokes = seen[pos..]
                    .iter()
                    .map(|&u| {
                        let (w, q) = blocks[u].clone().expect("a blocked variable");
                        WheelSpoke {
                            at: route_at(g, u),
                            through: route_at(g, w),
                            prefers: q,
                        }
                    })
                    .collect();
                wheel = Some(spokes);
                break 'start;
            }
            match &blocks[cur] {
                Some((w, _)) if fixed[*w].is_none() => {
                    seen.push(cur);
                    cur = *w;
                }
                _ => break,
            }
        }
    }
    (fixed, wheel)
}

/// The source of a variable in the search.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Assign {
    Empty,
    Unknown,
    From(Source),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fail {
    /// A variable that the derivation reads has no source yet.
    Missing,
    /// The sources give no path.
    Invalid,
}

#[derive(Clone)]
enum Memo {
    Todo,
    Busy,
    Done(Box<Result<BestPath, Fail>>),
}

/// The best paths that an assignment of sources gives.
struct Derive<'s, 'g, 'n, 'a> {
    g: &'g Group<'n, 'a>,
    fixed: &'s [Option<BestPath>],
    assign: &'s [Option<Assign>],
    /// The links and leaks into a variable that give no path for each
    /// possible value of their source variable.
    silent: &'s BTreeSet<(usize, Source)>,
    memo: RefCell<Vec<Memo>>,
}

impl Derive<'_, '_, '_, '_> {
    fn path(offer: &Offer) -> Result<BestPath, Fail> {
        match offer {
            Offer::Path(p) => Ok(BestPath::Path(p.clone())),
            _ => Err(Fail::Invalid),
        }
    }

    fn best(&self, v: usize) -> Result<BestPath, Fail> {
        if let Some(x) = &self.fixed[v] {
            return Ok(x.clone());
        }
        match &self.memo.borrow()[v] {
            Memo::Busy => return Err(Fail::Invalid),
            Memo::Done(r) => return (**r).clone(),
            Memo::Todo => {}
        }
        self.memo.borrow_mut()[v] = Memo::Busy;
        let r = self.compute(v);
        self.memo.borrow_mut()[v] = Memo::Done(Box::new(r.clone()));
        r
    }

    fn compute(&self, v: usize) -> Result<BestPath, Fail> {
        let g = self.g;
        match self.assign[v].ok_or(Fail::Missing)? {
            Assign::Empty => Ok(BestPath::None),
            Assign::Unknown => {
                let at = route_at(g, v);
                Ok(BestPath::Unknown(Unknown::new(
                    Reason::SelectionNotKnown,
                    format!("{} at {} {}", at.key.prefix, at.device, at.vrf),
                )))
            }
            Assign::From(Source::Network) => {
                Self::path(g.network[v].as_ref().ok_or(Fail::Invalid)?)
            }
            Assign::From(Source::Aggregate) => {
                let cs: Vec<BestPath> = g.contributors[v]
                    .iter()
                    .map(|&c| self.best(c))
                    .collect::<Result<_, _>>()?;
                Self::path(&g.aggregate(v, &cs))
            }
            Assign::From(Source::Redistribute(ri)) => {
                let (_, o) = g.redistributed[v]
                    .iter()
                    .find(|(r, _)| *r == ri)
                    .ok_or(Fail::Invalid)?;
                Self::path(o)
            }
            Assign::From(Source::Seed(si)) => {
                let (_, o) = g.seeds[v]
                    .iter()
                    .find(|(s, _)| *s == si)
                    .ok_or(Fail::Invalid)?;
                Self::path(o)
            }
            Assign::From(Source::Leak(pos)) => {
                let &(li, w) = g.inleaks[v].get(pos).ok_or(Fail::Invalid)?;
                let b = self.best(w)?;
                Self::path(&g.leak(li, &b))
            }
            Assign::From(Source::Link(l)) => {
                let &(_, w) = g.inlinks[v]
                    .iter()
                    .find(|(x, _)| *x == l)
                    .ok_or(Fail::Invalid)?;
                let b = self.best(w)?;
                for &s in &g.suppressors[w] {
                    if !matches!(self.best(s)?, BestPath::None) {
                        return Err(Fail::Invalid);
                    }
                }
                Self::path(&g.transfer(l, w, &b))
            }
        }
    }

    /// True if the source of `v` gives its selection.
    fn stable(&self, v: usize) -> Result<bool, Fail> {
        if let Err(f) = self.best(v) {
            return if f == Fail::Missing {
                Err(f)
            } else {
                Ok(false)
            };
        }
        let fail = RefCell::new(None);
        let get = |w: usize| match self.best(w) {
            Ok(b) => Some(b),
            Err(f) => {
                fail.borrow_mut().get_or_insert(f);
                None
            }
        };
        let skip = |s: Source| self.silent.contains(&(v, s));
        let Some(cands) = self.g.candidates_with(v, &get, &skip) else {
            return match fail.into_inner() {
                Some(Fail::Missing) => Err(Fail::Missing),
                _ => Ok(false),
            };
        };
        let a = self.assign[v].expect("an assigned variable");
        Ok(match (self.g.choose(v, &cands), a) {
            (Choice::None, Assign::Empty) => true,
            (Choice::Unknown(_), Assign::Unknown) => true,
            (Choice::Best(s, _), Assign::From(t)) => s == t,
            (Choice::Tie(opts), Assign::From(t)) => opts.iter().any(|(s, _)| *s == t),
            _ => false,
        })
    }
}

/// True if each variable with an unknown source is unknown from the
/// other variables. The variables with an unknown source that are not yet
/// unknown run synchronous rounds from no path, each with the selection of
/// the round before, and a variable whose selection is unknown stays
/// unknown. The check fails when the rounds repeat a state before each of
/// them is unknown. `picks` gets the unknown selections with their reasons.
fn grounded(g: &Group<'_, '_>, assign: &[Option<Assign>], picks: &mut [BestPath]) -> bool {
    let n = picks.len();
    let unknown: Vec<usize> = (0..n)
        .filter(|&v| assign[v] == Some(Assign::Unknown))
        .collect();
    let mut done = vec![false; n];
    let mut trial = vec![BestPath::None; n];
    let mut seen: BTreeSet<(Vec<bool>, Vec<BestPath>)> = BTreeSet::new();
    loop {
        if unknown.iter().all(|&v| done[v]) {
            return true;
        }
        if !seen.insert((done.clone(), trial.clone())) {
            return false;
        }
        let value = |w: usize| {
            Some(if assign[w] == Some(Assign::Unknown) && !done[w] {
                trial[w].clone()
            } else {
                picks[w].clone()
            })
        };
        let mut next = trial.clone();
        let mut found = Vec::new();
        for &v in unknown.iter().filter(|&&v| !done[v]) {
            let cands = g.candidates(v, &value).expect("a full assignment");
            match g.choose(v, &cands) {
                Choice::Unknown(u) => found.push((v, u)),
                c => next[v] = c.pick(),
            }
        }
        for (v, u) in found {
            picks[v] = BestPath::Unknown(u);
            done[v] = true;
        }
        trial = next;
    }
}

/// The variables that the candidates of `v` read.
fn dependencies(g: &Group<'_, '_>, v: usize) -> Vec<usize> {
    let mut out = g.contributors[v].clone();
    for &(_, w) in &g.inlinks[v] {
        out.push(w);
        out.extend(g.suppressors[w].iter().copied());
    }
    out.extend(g.inleaks[v].iter().map(|(_, w)| *w));
    out
}

/// The free variables of `fixed` in the components over the dependencies
/// of their candidates, each in the order of the variables.
fn components(g: &Group<'_, '_>, fixed: &[Option<BestPath>]) -> Vec<Vec<usize>> {
    let n = g.vars.len();
    let mut parent: Vec<usize> = (0..n).collect();
    fn root(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    for v in (0..n).filter(|&v| fixed[v].is_none()) {
        for w in dependencies(g, v) {
            if fixed[w].is_none() {
                let (a, b) = (root(&mut parent, v), root(&mut parent, w));
                if a != b {
                    parent[a.max(b)] = a.min(b);
                }
            }
        }
    }
    let mut by: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for v in (0..n).filter(|&v| fixed[v].is_none()) {
        let r = root(&mut parent, v);
        by.entry(r).or_default().push(v);
    }
    by.into_values().collect()
}

/// The best paths of each stable assignment: the search of each component
/// of [`components`] alone, with the free variables of the other components
/// at no path, and each combination of the outcomes of the components. The
/// candidates of a variable read only the variables of its component, so
/// the stable assignments are the combinations.
fn search_parts(
    g: &Group<'_, '_>,
    fixed: &[Option<BestPath>],
    dom: &[BTreeSet<BestPath>],
) -> Vec<Vec<BestPath>> {
    let parts = components(g, fixed);
    let mut found: Vec<Vec<Vec<BestPath>>> = Vec::with_capacity(parts.len());
    for part in &parts {
        let mut inside = vec![false; fixed.len()];
        for &v in part {
            inside[v] = true;
        }
        let local: Vec<Option<BestPath>> = fixed
            .iter()
            .enumerate()
            .map(|(v, f)| match f {
                None if !inside[v] => Some(BestPath::None),
                f => f.clone(),
            })
            .collect();
        let stable = search(g, &local, dom);
        if stable.is_empty() {
            return Vec::new();
        }
        found.push(
            stable
                .iter()
                .map(|s| part.iter().map(|&v| s[v].clone()).collect())
                .collect(),
        );
    }
    let base: Vec<BestPath> = fixed
        .iter()
        .map(|f| f.clone().unwrap_or(BestPath::None))
        .collect();
    let mut out = vec![base];
    for (part, options) in parts.iter().zip(found) {
        let mut next = Vec::with_capacity(out.len() * options.len());
        for o in &out {
            for values in &options {
                let mut x = o.clone();
                for (&v, b) in part.iter().zip(values) {
                    x[v] = b.clone();
                }
                next.push(x);
            }
        }
        out = next;
    }
    out
}

/// The free variables of `fixed` in the order of the search: a
/// breadth-first walk from the variables with an origination, a
/// redistribution or a seed, and from the variables whose dependencies are
/// fixed, along the variables that read them, then the other free variables
/// in their order.
fn search_order(g: &Group<'_, '_>, fixed: &[Option<BestPath>]) -> Vec<usize> {
    let n = g.vars.len();
    let mut readers: Vec<Vec<usize>> = vec![Vec::new(); n];
    for v in (0..n).filter(|&v| fixed[v].is_none()) {
        for w in dependencies(g, v) {
            readers[w].push(v);
        }
    }
    let mut seen = vec![false; n];
    let mut queue = std::collections::VecDeque::new();
    for v in (0..n).filter(|&v| fixed[v].is_none()) {
        let sourced = g.network[v].is_some()
            || g.has_aggregate[v]
            || !g.redistributed[v].is_empty()
            || !g.seeds[v].is_empty()
            || dependencies(g, v).iter().all(|&w| fixed[w].is_some());
        if sourced {
            seen[v] = true;
            queue.push_back(v);
        }
    }
    for v in (0..n).filter(|&v| fixed[v].is_some()) {
        for &r in &readers[v] {
            if !seen[r] {
                seen[r] = true;
                queue.push_back(r);
            }
        }
    }
    let mut out = Vec::new();
    while let Some(v) = queue.pop_front() {
        out.push(v);
        for &r in &readers[v] {
            if !seen[r] {
                seen[r] = true;
                queue.push_back(r);
            }
        }
    }
    out.extend((0..n).filter(|&v| fixed[v].is_none() && !seen[v]));
    out
}

/// The best paths of each stable assignment, in the order of the search.
/// The options of a variable are no path, and with a possible candidate of
/// the domains `dom` an unknown selection and each source of a possible
/// candidate.
fn search(
    g: &Group<'_, '_>,
    fixed: &[Option<BestPath>],
    dom: &[BTreeSet<BestPath>],
) -> Vec<Vec<BestPath>> {
    let n = g.vars.len();
    let free = search_order(g, fixed);
    let domains: Vec<Vec<Assign>> = free
        .iter()
        .map(|&v| {
            let cands = possible(g, v, dom, fixed);
            let sources: BTreeSet<Source> = cands
                .iter()
                .filter(|(_, c)| c.offer.is_ok())
                .map(|(_, c)| c.source)
                .collect();
            let mut d = vec![Assign::Empty];
            if !cands.is_empty() {
                d.push(Assign::Unknown);
            }
            if g.network[v].is_some() {
                d.push(Assign::From(Source::Network));
            }
            if g.has_aggregate[v] {
                d.push(Assign::From(Source::Aggregate));
            }
            d.extend(
                g.redistributed[v]
                    .iter()
                    .map(|(r, _)| Assign::From(Source::Redistribute(*r))),
            );
            d.extend(
                g.seeds[v]
                    .iter()
                    .map(|(s, _)| Assign::From(Source::Seed(*s))),
            );
            d.extend((0..g.inleaks[v].len()).map(|pos| Assign::From(Source::Leak(pos))));
            d.extend(
                g.inlinks[v]
                    .iter()
                    .map(|(l, _)| Assign::From(Source::Link(*l))),
            );
            d.retain(|a| match a {
                Assign::From(s) => sources.contains(s),
                _ => true,
            });
            d
        })
        .collect();
    // A link or a leak whose source gives no path for each value of its
    // domain and for an unknown value gives no candidate, so the check of a
    // variable does not wait for that source.
    let probe = BestPath::Unknown(Unknown::new(Reason::SelectionNotKnown, String::new()));
    let mut silent: BTreeSet<(usize, Source)> = BTreeSet::new();
    for &v in &free {
        for &(l, w) in &g.inlinks[v] {
            if g.suppressors[w].is_empty()
                && dom[w]
                    .iter()
                    .chain([&probe])
                    .all(|x| matches!(g.transfer(l, w, x), Offer::None))
            {
                silent.insert((v, Source::Link(l)));
            }
        }
        for (pos, &(li, w)) in g.inleaks[v].iter().enumerate() {
            if dom[w]
                .iter()
                .chain([&probe])
                .all(|x| matches!(g.leak(li, x), Offer::None))
            {
                silent.insert((v, Source::Leak(pos)));
            }
        }
    }
    let mut assign: Vec<Option<Assign>> = vec![None; n];
    let mut found = Vec::new();
    #[allow(clippy::too_many_arguments)]
    fn walk(
        g: &Group<'_, '_>,
        fixed: &[Option<BestPath>],
        free: &[usize],
        domains: &[Vec<Assign>],
        silent: &BTreeSet<(usize, Source)>,
        depth: usize,
        assign: &mut Vec<Option<Assign>>,
        found: &mut Vec<Vec<BestPath>>,
    ) {
        let n = g.vars.len();
        let d = Derive {
            g,
            fixed,
            assign: &assign[..],
            silent,
            memo: RefCell::new(vec![Memo::Todo; n]),
        };
        let mut complete = true;
        for &u in &free[..depth] {
            match d.stable(u) {
                Ok(true) => {}
                Ok(false) => return,
                Err(_) => complete = false,
            }
        }
        if depth == free.len() {
            if complete {
                let picks: Result<Vec<BestPath>, Fail> = (0..n).map(|v| d.best(v)).collect();
                if let Ok(mut p) = picks
                    && grounded(g, assign, &mut p)
                {
                    found.push(p);
                }
            }
            return;
        }
        drop(d);
        let v = free[depth];
        for &a in &domains[depth] {
            assign[v] = Some(a);
            walk(g, fixed, free, domains, silent, depth + 1, assign, found);
        }
        assign[v] = None;
    }
    walk(
        g,
        fixed,
        &free,
        &domains,
        &silent,
        0,
        &mut assign,
        &mut found,
    );
    found
}

fn unknown_routes(
    g: &Group<'_, '_>,
    unknown: impl Fn(usize) -> bool,
    u: &Unknown,
) -> BTreeMap<RouteAt, RouteState> {
    (0..g.vars.len())
        .filter(|&v| unknown(v))
        .map(|v| (route_at(g, v), RouteState::Unknown(u.clone())))
        .collect()
}

fn run_group(
    net: &Net<'_>,
    gi: usize,
    keys: &BTreeSet<RouteKey>,
    events: &mut Vec<Event>,
) -> (GroupResult, BTreeMap<RouteAt, RouteState>) {
    let g = Group::new(net, keys);
    let (fwd, rounds) = forward(&g, gi, events);
    let dom = domains(&g);
    let possible_path = |v: usize| dom[v].iter().any(|b| *b != BestPath::None);
    let (fixed, wheel) = if strict(&g, &dom) {
        greedy(&g, &dom)
    } else {
        (vec![None; g.vars.len()], None)
    };
    let result = |convergence: Convergence| GroupResult {
        keys: keys.clone(),
        convergence,
        rounds,
        fixed_point: matches!(fwd, Forward::Fixed(_)),
    };
    if let Forward::Fixed(state) = &fwd
        && fixed.iter().zip(state).all(|(f, s)| f.as_ref() == Some(s))
    {
        let (_, routes) = outcome(&g, state);
        return (result(Convergence::Converged { note: None }), routes);
    }
    // A variable with no possible candidate has its domain of no path only,
    // and has no path in each stable assignment.
    let mut fixed = fixed;
    for (v, f) in fixed.iter_mut().enumerate() {
        if f.is_none() && dom[v].len() == 1 {
            *f = dom[v].iter().next().cloned();
        }
    }
    let stable = search_parts(&g, &fixed, &dom);
    let mut keys_seen: Vec<OutcomeKey> = Vec::new();
    let mut picks: Vec<Vec<BestPath>> = Vec::new();
    let mut outcomes: Vec<Outcome> = Vec::new();
    for s in stable {
        let (k, routes) = outcome(&g, &s);
        if !keys_seen.contains(&k) {
            keys_seen.push(k);
            picks.push(s);
            outcomes.push(Outcome { routes });
        }
    }
    let convergence = match (outcomes.len(), &fwd) {
        (
            0,
            Forward::Cycle {
                first_round,
                states,
            },
        ) => {
            let changing = (0..g.vars.len())
                .filter(|&v| states.iter().any(|s| s[v] != states[0][v]))
                .map(|v| {
                    (
                        route_at(&g, v),
                        states.iter().map(|s| s[v].clone()).collect(),
                    )
                })
                .collect();
            Convergence::NoConvergence {
                cycle: CycleWitness {
                    first_round: *first_round,
                    length: states.len(),
                    changing,
                },
            }
        }
        (0, Forward::Fixed(_)) => Convergence::Unknown {
            reason: Unknown::new(
                Reason::Internal,
                "no stable outcome at the fixed point of the forward pass",
            ),
        },
        (1, _) if picks[0].iter().any(|b| matches!(b, BestPath::Unknown(_))) => {
            Convergence::Unknown {
                reason: Unknown {
                    reason: Reason::ConvergenceNotDetermined,
                    details: picks[0]
                        .iter()
                        .filter_map(|b| match b {
                            BestPath::Unknown(u) => Some(u.to_string()),
                            _ => None,
                        })
                        .collect(),
                },
            }
        }
        (1, _) => Convergence::Converged {
            note: Some(match (wheel, &fwd) {
                (Some(w), _) => Note {
                    text: NOT_SAFE,
                    wheel: w,
                },
                (None, Forward::Cycle { .. }) => Note {
                    text: NOT_SAFE,
                    wheel: Vec::new(),
                },
                (None, Forward::Fixed(_)) => Note {
                    text: NOT_CHECKED,
                    wheel: Vec::new(),
                },
            }),
        },
        _ => Convergence::MultipleStableOutcomes {
            outcomes: outcomes.clone(),
        },
    };
    events.push(Event::Search {
        group: gi,
        outcomes: outcomes.len(),
        result: convergence.kind(),
    });
    let routes = match &convergence {
        Convergence::Converged { .. } => match &fwd {
            Forward::Fixed(state) => outcome(&g, state).1,
            Forward::Cycle { .. } => outcomes.swap_remove(0).routes,
        },
        Convergence::MultipleStableOutcomes { outcomes } => unknown_routes(
            &g,
            |v| picks.iter().any(|s| s[v] != BestPath::None),
            &Unknown::new(
                Reason::MultipleStableOutcomes,
                format!("{} outcomes", outcomes.len()),
            ),
        ),
        Convergence::NoConvergence { cycle } => unknown_routes(
            &g,
            possible_path,
            &Unknown::new(
                Reason::NoConvergence,
                format!(
                    "a cycle of {} rounds from round {}",
                    cycle.length, cycle.first_round
                ),
            ),
        ),
        Convergence::Unknown { reason } => unknown_routes(&g, possible_path, reason),
    };
    (result(convergence), routes)
}

/// The BGP calculation: the selection of each route at each process, with
/// the convergence result of each prefix group.
pub fn compute(input: &BgpInput, igp: &dyn IgpView) -> Result<BgpResult, InputError> {
    let net = Net::new(input, igp)?;
    let mut routes = BTreeMap::new();
    let mut groups = Vec::new();
    let mut events = Vec::new();
    for (gi, keys) in key_groups(&net).iter().enumerate() {
        let (r, rs) = run_group(&net, gi, keys, &mut events);
        routes.extend(rs);
        groups.push(r);
    }
    let worst = groups
        .iter()
        .map(|g| g.convergence.kind())
        .max()
        .unwrap_or(ConvergenceKind::Converged);
    let affected = groups
        .iter()
        .filter(|g| g.convergence.kind() != ConvergenceKind::Converged)
        .flat_map(|g| g.keys.iter().copied())
        .collect();
    Ok(BgpResult {
        routes,
        groups,
        events,
        worst,
        affected,
    })
}

const PLATFORMS: [Platform; 5] = [
    Platform::Iosxe,
    Platform::Iosxr,
    Platform::Nxos,
    Platform::FrrTraditional,
    Platform::FrrDatacenter,
];

/// An EVPN IP prefix route that a VRF imports, for the install: the next
/// hops are tunnel ends, and the route enters the tunnel of the VRF.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayCandidate {
    pub prefix: Prefix,
    pub distance: u8,
    /// The tunnel ends of the best path and its multipath.
    pub tunnel_ends: Vec<IpAddr>,
    pub spans: Vec<SourceSpan>,
}

/// The install candidates of the EVPN IP prefix routes that the VRFs of
/// `result` import, by device and VRF, with the distance of the session of
/// the best path.
pub fn overlay_candidates(
    result: &BgpResult,
    processes: &[BgpProcess],
) -> BTreeMap<(String, String), Vec<OverlayCandidate>> {
    let mut out: BTreeMap<(String, String), Vec<OverlayCandidate>> = BTreeMap::new();
    for (at, state) in &result.routes {
        let RouteState::Selected(sel) = state else {
            continue;
        };
        if at.key.family == Family::EvpnIpPrefix
            || !sel.best.leaked.as_ref().is_some_and(|l| l.evpn)
        {
            continue;
        }
        let profile = processes
            .iter()
            .find(|p| p.device == at.device && p.vrf == at.vrf)
            .and_then(|p| p.profile());
        let lowest = lowest_ebgp();
        let mut tunnel_ends: Vec<IpAddr> =
            sel.multipath.iter().filter_map(|p| p.next_hop).collect();
        tunnel_ends.sort();
        tunnel_ends.dedup();
        out.entry((at.device.clone(), at.vrf.clone()))
            .or_default()
            .push(OverlayCandidate {
                prefix: at.key.prefix,
                distance: profile.map_or(lowest, |p| p.distance(sel.best.peer.kind)),
                tunnel_ends,
                spans: sel
                    .multipath
                    .iter()
                    .flat_map(|p| p.spans.iter().cloned())
                    .collect(),
            });
    }
    out
}

/// The lowest eBGP distance of any platform.
fn lowest_ebgp() -> u8 {
    PLATFORMS
        .iter()
        .map(|p| p.distance(Origin::Ebgp))
        .min()
        .unwrap_or(0)
}

/// The install candidates of the unicast routes of `result`, by device and
/// VRF. A best path from a session gives a BGP route through the next hops
/// of its multipath with the distance of the profile. An aggregate gives a
/// discard route with the distance of a local path. A `network` or a
/// redistributed path gives no candidate. An EVPN IP prefix route that a
/// VRF imports gives no candidate here, and [`overlay_candidates`] gives
/// it. A path that a VRF leaks from another VRF gives an unknown BGP route
/// with the distance of the profile. An unknown route gives an unknown BGP
/// route with the lowest eBGP distance of any platform.
pub fn install_candidates(
    result: &BgpResult,
    processes: &[BgpProcess],
) -> BTreeMap<(String, String), Vec<Candidate>> {
    let mut out: BTreeMap<(String, String), Vec<Candidate>> = BTreeMap::new();
    let lowest = lowest_ebgp();
    for (at, state) in &result.routes {
        if at.key.family == Family::EvpnIpPrefix {
            continue;
        }
        let profile = processes
            .iter()
            .find(|p| p.device == at.device && p.vrf == at.vrf)
            .and_then(|p| p.profile());
        let prefix = at.key.prefix;
        let cand = match state {
            RouteState::Selected(sel) => {
                let kind = sel.best.peer.kind;
                let distance = profile.map_or(lowest, |p| p.distance(kind));
                let spans: Vec<_> = sel
                    .multipath
                    .iter()
                    .flat_map(|p| p.spans.iter().cloned())
                    .collect();
                match (kind, &sel.best.leaked) {
                    (_, Some(l)) if l.evpn => continue,
                    (_, Some(l)) => Candidate::new(
                        prefix,
                        distance,
                        Route::unknown(
                            RouteKind::Learned(RouteProtocol::Bgp),
                            format!("next hop in vrf {} not installed", l.vrf),
                            spans,
                        ),
                    ),
                    (SessionKind::Local(LocalOrigin::Aggregate), _) => Candidate::new(
                        prefix,
                        distance,
                        Route::new(RouteKind::Null, Vec::new(), spans),
                    ),
                    (SessionKind::Local(_), _) => continue,
                    _ => {
                        let mut gateways: Vec<_> =
                            sel.multipath.iter().filter_map(|p| p.next_hop).collect();
                        gateways.dedup();
                        Candidate::via(
                            prefix,
                            distance,
                            RouteKind::Learned(RouteProtocol::Bgp),
                            gateways,
                            spans,
                        )
                    }
                }
            }
            RouteState::Unknown(u) => Candidate::new(
                prefix,
                lowest,
                Route::unknown(
                    RouteKind::Learned(RouteProtocol::Bgp),
                    u.to_string(),
                    Vec::new(),
                ),
            ),
        };
        out.entry((at.device.clone(), at.vrf.clone()))
            .or_default()
            .push(cand);
    }
    out
}
