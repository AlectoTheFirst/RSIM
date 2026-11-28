//! Route policies: route-maps with `continue`, and IOS-XR RPL as boolean
//! guards with `if`, `elseif` and `else`, `pass`, `drop`, `done` and
//! `apply`.
//!
//! A route-map walks its clauses in ascending sequence number. A clause
//! matches when each of its match terms matches; a term with more than one
//! name matches when one of the names matches. The first matching deny
//! clause denies the route. A matching permit clause applies its set
//! actions and permits the route, or with `continue` goes on to the target
//! clause, or to the next clause with no target. A route that no clause
//! matches is denied; a route that a permit clause with `continue` matched
//! is permitted when no later clause matches.
//!
//! An RPL policy runs its statements in order. A set action or `pass`
//! marks the route as passed. `drop` denies the route and `done` permits
//! it, and both end the evaluation of each applied policy. At the end, a
//! passed route is permitted and each other route is denied.
//!
//! A match term with an unhandled construct, or a reference to a list that
//! the policy set does not hold, has an unknown match. The evaluation runs
//! once with the term matching and once with the term not matching, for
//! each such term that it reaches. The result is `Unknown` with the reason
//! "policy clause not evaluated" only when these runs give different
//! results. An unhandled action that a run reaches gives `Unknown`.

use std::collections::BTreeSet;
use std::net::IpAddr;

use rsim_core::{Prefix, SourceSpan};

use super::lists::{Cmp, PrefixList};
use super::process::{BgpProcess, Neighbor, PolicySet};
use super::profile::{BgpProfile, MatchReads, UndefinedPolicy};
use super::stage::{ObjectRef, RoutingStage};
use super::{
    AdminValue, Asn, BgpOrigin, BgpPath, Community, ExtCommunity, Reason, RouteKey, SessionKind,
    Unknown,
};

/// The direction of a neighbour policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    Import,
    Export,
}

/// A next-hop match term.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NextHopMatch {
    /// One of the prefix lists permits the next hop as a host prefix.
    PrefixList(Vec<String>),
    /// The next hop is one of the addresses.
    Address(Vec<IpAddr>),
}

/// `match route-type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RouteTypeMatch {
    /// A local origination.
    Local,
    /// A path from an iBGP or a confederation eBGP session.
    Internal,
    /// A path from an eBGP session.
    External,
}

/// A match term.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatchTerm {
    /// One of the named prefix lists permits the prefix of the route.
    PrefixList(Vec<String>),
    /// An inline prefix set permits the prefix of the route.
    PrefixSet(PrefixList),
    /// One of the named community lists permits the communities, or with
    /// `every`, each line of one of the lists matches.
    CommunityList {
        names: Vec<String>,
        every: bool,
    },
    /// One of the named AS-path lists permits the AS path.
    AsPathList(Vec<String>),
    NextHop(NextHopMatch),
    RouteType(RouteTypeMatch),
    /// The tag is one of the values.
    Tag(Vec<u32>),
    /// The local preference compares to the value. A path with none has
    /// the default local preference.
    LocalPref(Cmp, u32),
    /// The MED compares to the value. A path with none has the MED 0.
    Med(Cmp, u32),
    Origin(BgpOrigin),
    /// The decision length of the AS path compares to the value.
    AsPathLength(Cmp, u32),
    /// A term with an unhandled construct, with its text.
    Unhandled(String),
}

/// `set metric`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MedSet {
    Value(u32),
    /// The MED plus the value, at most `u32::MAX`. A path with no MED has 0.
    Add(u32),
    /// The MED minus the value, at least 0.
    Subtract(u32),
}

/// `set ip next-hop`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NextHopSet {
    Address(IpAddr),
    /// The local address of the session.
    SelfAddress,
    /// The address of the peer on import, the local address on export.
    PeerAddress,
}

/// A set action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetAction {
    LocalPref(u32),
    Med(MedSet),
    Weight(u32),
    Origin(BgpOrigin),
    /// `set community ... additive`.
    CommunityAdd(Vec<Community>),
    /// `set community` with no `additive`: the standard communities become
    /// the values.
    CommunityReplace(Vec<Community>),
    /// `set comm-list <name> delete`: the communities that the list
    /// permits are removed.
    CommunityDelete(String),
    /// `set extcommunity rt ... additive`.
    RouteTargetAdd(Vec<AdminValue>),
    AsPathPrepend(Vec<Asn>),
    /// `set as-path prepend last-as <n>`: the leftmost AS `n` times.
    AsPathPrependLastAs(u8),
    NextHop(NextHopSet),
    Tag(u32),
    /// An action with an unhandled construct, with its text.
    Unhandled(String),
}

/// The target of a `continue`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Continue {
    /// The next clause.
    Next,
    /// The first clause with a sequence number of at least the value.
    Seq(u32),
}

/// One clause of a route-map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clause {
    pub seq: u32,
    pub permit: bool,
    pub matches: Vec<MatchTerm>,
    pub sets: Vec<SetAction>,
    pub continue_to: Option<Continue>,
    pub spans: Vec<SourceSpan>,
}

impl Clause {
    /// A clause with no match term, no set action and no `continue`.
    pub fn new(seq: u32, permit: bool) -> Clause {
        Clause {
            seq,
            permit,
            matches: Vec::new(),
            sets: Vec::new(),
            continue_to: None,
            spans: Vec::new(),
        }
    }
}

/// An RPL guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Guard {
    Term(MatchTerm),
    Not(Box<Guard>),
    And(Vec<Guard>),
    Or(Vec<Guard>),
}

/// An RPL statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Statement {
    /// `if`, each `elseif`, and `else`.
    If {
        branches: Vec<(Guard, Vec<Statement>)>,
        otherwise: Vec<Statement>,
    },
    Set(SetAction),
    Pass,
    Drop,
    Done,
    /// `apply <policy>`.
    Apply(String),
    /// A statement with an unhandled construct, with its text.
    Unhandled(String),
}

/// The body of a policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyBody {
    /// A route-map of IOS-XE, NX-OS or FRR.
    RouteMap(Vec<Clause>),
    /// An IOS-XR route policy.
    Rpl(Vec<Statement>),
}

/// A route policy with its name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutePolicy {
    pub name: String,
    pub body: PolicyBody,
    pub spans: Vec<SourceSpan>,
}

/// The data that an evaluation reads besides the route.
#[derive(Clone, Copy, Debug)]
pub struct PolicyContext<'a> {
    pub set: &'a PolicySet,
    pub direction: Direction,
    pub local_address: Option<IpAddr>,
    pub peer_address: Option<IpAddr>,
    pub default_local_pref: u32,
    pub match_reads: MatchReads,
}

/// The result of a policy on a route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyResult {
    /// The route is permitted with the path after the set actions.
    Permit(BgpPath),
    Deny,
    Unknown(Unknown),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Permit(Box<BgpPath>),
    Deny,
}

enum Stop {
    /// The run needs the match of an unknown term.
    Choice(String),
    Unhandled(String),
}

enum Flow {
    Next,
    Drop,
    Done,
}

struct Run<'a> {
    ctx: &'a PolicyContext<'a>,
    key: &'a RouteKey,
    input: &'a BgpPath,
    choices: &'a [bool],
    used: usize,
    applied: Vec<String>,
}

fn any(values: impl IntoIterator<Item = Option<bool>>) -> Option<bool> {
    let mut unknown = false;
    for v in values {
        match v {
            Some(true) => return Some(true),
            None => unknown = true,
            Some(false) => {}
        }
    }
    if unknown { None } else { Some(false) }
}

impl<'a> Run<'a> {
    fn decide(
        &mut self,
        value: Option<bool>,
        detail: impl FnOnce() -> String,
    ) -> Result<bool, Stop> {
        if let Some(v) = value {
            return Ok(v);
        }
        if let Some(&c) = self.choices.get(self.used) {
            self.used += 1;
            return Ok(c);
        }
        Err(Stop::Choice(detail()))
    }

    fn term(&mut self, t: &MatchTerm, path: &BgpPath, at: &str) -> Result<bool, Stop> {
        let set = self.ctx.set;
        let prefix_lists = |names: &[String], p: Prefix| {
            any(names
                .iter()
                .map(|n| set.prefix_lists.get(n).map(|l| l.permits(p))))
        };
        let value = match t {
            MatchTerm::PrefixList(names) => prefix_lists(names, self.key.prefix),
            MatchTerm::PrefixSet(list) => Some(list.permits(self.key.prefix)),
            MatchTerm::CommunityList { names, every } => any(names.iter().map(|n| {
                set.community_lists.get(n).and_then(|l| {
                    if *every {
                        l.matches_every(&path.communities)
                    } else {
                        l.permits(&path.communities)
                    }
                })
            })),
            MatchTerm::AsPathList(names) => any(names.iter().map(|n| {
                set.as_path_lists
                    .get(n)
                    .and_then(|l| l.permits(&path.as_path))
            })),
            MatchTerm::NextHop(NextHopMatch::PrefixList(names)) => match path.next_hop {
                Some(nh) => prefix_lists(names, Prefix::host(nh)),
                None => Some(false),
            },
            MatchTerm::NextHop(NextHopMatch::Address(addrs)) => {
                Some(path.next_hop.is_some_and(|nh| addrs.contains(&nh)))
            }
            MatchTerm::RouteType(rt) => Some(match rt {
                RouteTypeMatch::Local => matches!(path.peer.kind, SessionKind::Local(_)),
                RouteTypeMatch::Internal => path.peer.kind.is_internal(),
                RouteTypeMatch::External => path.peer.kind == SessionKind::Ebgp,
            }),
            MatchTerm::Tag(tags) => Some(path.tag.is_some_and(|t| tags.contains(&t))),
            MatchTerm::LocalPref(cmp, v) => {
                Some(cmp.holds(path.local_pref.unwrap_or(self.ctx.default_local_pref), *v))
            }
            MatchTerm::Med(cmp, v) => Some(cmp.holds(path.med.unwrap_or(0), *v)),
            MatchTerm::Origin(o) => Some(path.origin == *o),
            MatchTerm::AsPathLength(cmp, v) => Some(cmp.holds(path.as_path.len(), *v)),
            MatchTerm::Unhandled(_) => None,
        };
        self.decide(value, || format!("{at}: {t:?}"))
    }

    fn set(&mut self, a: &SetAction, out: &mut BgpPath, at: &str) -> Result<(), Stop> {
        let unhandled = |what: &str| Stop::Unhandled(format!("{at}: {what}"));
        match a {
            SetAction::LocalPref(v) => out.local_pref = Some(*v),
            SetAction::Med(MedSet::Value(v)) => out.med = Some(*v),
            SetAction::Med(MedSet::Add(v)) => {
                out.med = Some(out.med.unwrap_or(0).saturating_add(*v))
            }
            SetAction::Med(MedSet::Subtract(v)) => {
                out.med = Some(out.med.unwrap_or(0).saturating_sub(*v))
            }
            SetAction::Weight(v) => out.weight = *v,
            SetAction::Origin(o) => out.origin = *o,
            SetAction::CommunityAdd(cs) => out.communities.extend(cs.iter().copied()),
            SetAction::CommunityReplace(cs) => out.communities = cs.iter().copied().collect(),
            SetAction::CommunityDelete(name) => {
                let Some(list) = self.ctx.set.community_lists.get(name) else {
                    return Err(unhandled(&format!("community list {name} not defined")));
                };
                let mut kept = BTreeSet::new();
                for &c in &out.communities {
                    match list.deletes(c) {
                        Some(true) => {}
                        Some(false) => {
                            kept.insert(c);
                        }
                        None => return Err(unhandled(&format!("delete by community list {name}"))),
                    }
                }
                out.communities = kept;
            }
            SetAction::RouteTargetAdd(rts) => out
                .ext_communities
                .extend(rts.iter().map(|&r| ExtCommunity::RouteTarget(r))),
            SetAction::AsPathPrepend(asns) => out.as_path = out.as_path.prepend(asns),
            SetAction::AsPathPrependLastAs(n) => {
                let Some(&last) = out.as_path.flat().first() else {
                    return Err(unhandled("prepend last-as on an empty AS path"));
                };
                out.as_path = out.as_path.prepend(&vec![last; usize::from(*n)]);
            }
            SetAction::NextHop(nh) => {
                let addr = match (nh, self.ctx.direction) {
                    (NextHopSet::Address(a), _) => Some(*a),
                    (NextHopSet::SelfAddress, _) | (NextHopSet::PeerAddress, Direction::Export) => {
                        self.ctx.local_address
                    }
                    (NextHopSet::PeerAddress, Direction::Import) => self.ctx.peer_address,
                };
                match addr {
                    Some(a) => out.next_hop = Some(a),
                    None => return Err(unhandled("next hop address of the session not known")),
                }
            }
            SetAction::Tag(v) => out.tag = Some(*v),
            SetAction::Unhandled(text) => return Err(unhandled(text)),
        }
        Ok(())
    }

    fn read<'b>(&self, out: &'b BgpPath) -> &'b BgpPath
    where
        'a: 'b,
    {
        match self.ctx.match_reads {
            MatchReads::Input => self.input,
            MatchReads::Output => out,
        }
    }

    fn route_map(&mut self, name: &str, clauses: &[Clause]) -> Result<Outcome, Stop> {
        let mut order: Vec<&Clause> = clauses.iter().collect();
        order.sort_by_key(|c| c.seq);
        let mut out = self.input.clone();
        let mut matched = false;
        let mut i = 0;
        'clauses: while i < order.len() {
            let c = order[i];
            let at = format!("{name} {}", c.seq);
            for t in &c.matches {
                let read = self.read(&out);
                if !self.term(t, read, &at)? {
                    i += 1;
                    continue 'clauses;
                }
            }
            if !c.permit {
                return Ok(Outcome::Deny);
            }
            for a in &c.sets {
                self.set(a, &mut out, &at)?;
            }
            matched = true;
            match c.continue_to {
                None => return Ok(Outcome::Permit(Box::new(out))),
                Some(Continue::Next) => i += 1,
                Some(Continue::Seq(s)) => {
                    if s <= c.seq {
                        return Err(Stop::Unhandled(format!("{at}: continue to {s}")));
                    }
                    i = order.iter().position(|d| d.seq >= s).unwrap_or(order.len());
                }
            }
        }
        Ok(if matched {
            Outcome::Permit(Box::new(out))
        } else {
            Outcome::Deny
        })
    }

    fn guard(&mut self, g: &Guard, path: &BgpPath, at: &str) -> Result<bool, Stop> {
        match g {
            Guard::Term(t) => self.term(t, path, at),
            Guard::Not(inner) => Ok(!self.guard(inner, path, at)?),
            Guard::And(gs) => {
                for g in gs {
                    if !self.guard(g, path, at)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Guard::Or(gs) => {
                for g in gs {
                    if self.guard(g, path, at)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    fn rpl(
        &mut self,
        name: &str,
        stmts: &[Statement],
        out: &mut BgpPath,
        passed: &mut bool,
    ) -> Result<Flow, Stop> {
        for s in stmts {
            match s {
                Statement::Set(a) => {
                    self.set(a, out, name)?;
                    *passed = true;
                }
                Statement::Pass => *passed = true,
                Statement::Drop => return Ok(Flow::Drop),
                Statement::Done => return Ok(Flow::Done),
                Statement::If {
                    branches,
                    otherwise,
                } => {
                    let mut body = otherwise;
                    for (g, b) in branches {
                        let read = self.read(&*out);
                        if self.guard(g, read, name)? {
                            body = b;
                            break;
                        }
                    }
                    match self.rpl(name, body, out, passed)? {
                        Flow::Next => {}
                        f => return Ok(f),
                    }
                }
                Statement::Apply(callee) => {
                    if self.applied.iter().any(|a| a == callee) {
                        return Err(Stop::Unhandled(format!(
                            "{name}: apply loop through {callee}"
                        )));
                    }
                    let Some(RoutePolicy {
                        body: PolicyBody::Rpl(body),
                        ..
                    }) = self.ctx.set.policies.get(callee)
                    else {
                        return Err(Stop::Unhandled(format!("{name}: apply {callee}")));
                    };
                    self.applied.push(callee.clone());
                    let flow = self.rpl(callee, body, out, passed)?;
                    self.applied.pop();
                    match flow {
                        Flow::Next => {}
                        f => return Ok(f),
                    }
                }
                Statement::Unhandled(text) => {
                    return Err(Stop::Unhandled(format!("{name}: {text}")));
                }
            }
        }
        Ok(Flow::Next)
    }

    fn policy(&mut self, policy: &RoutePolicy) -> Result<Outcome, Stop> {
        match &policy.body {
            PolicyBody::RouteMap(clauses) => self.route_map(&policy.name, clauses),
            PolicyBody::Rpl(stmts) => {
                let mut out = self.input.clone();
                let mut passed = false;
                self.applied.push(policy.name.clone());
                let flow = self.rpl(&policy.name, stmts, &mut out, &mut passed)?;
                Ok(match flow {
                    Flow::Drop => Outcome::Deny,
                    Flow::Done => Outcome::Permit(Box::new(out)),
                    Flow::Next if passed => Outcome::Permit(Box::new(out)),
                    Flow::Next => Outcome::Deny,
                })
            }
        }
    }
}

fn explore(
    policy: &RoutePolicy,
    key: &RouteKey,
    path: &BgpPath,
    ctx: &PolicyContext<'_>,
    choices: &mut Vec<bool>,
    details: &mut BTreeSet<String>,
) -> Option<Outcome> {
    let result = {
        let mut run = Run {
            ctx,
            key,
            input: path,
            choices: choices.as_slice(),
            used: 0,
            applied: Vec::new(),
        };
        run.policy(policy)
    };
    match result {
        Ok(o) => Some(o),
        Err(Stop::Unhandled(d)) => {
            details.insert(d);
            None
        }
        Err(Stop::Choice(d)) => {
            details.insert(d);
            choices.push(false);
            let without = explore(policy, key, path, ctx, choices, details);
            choices.pop();
            choices.push(true);
            let with = explore(policy, key, path, ctx, choices, details);
            choices.pop();
            if without.is_some() && without == with {
                without
            } else {
                None
            }
        }
    }
}

/// The result of `policy` on the route `key` with the path `path`.
pub fn evaluate(
    policy: &RoutePolicy,
    key: &RouteKey,
    path: &BgpPath,
    ctx: &PolicyContext<'_>,
) -> PolicyResult {
    let mut details = BTreeSet::new();
    match explore(policy, key, path, ctx, &mut Vec::new(), &mut details) {
        Some(Outcome::Permit(p)) => PolicyResult::Permit(*p),
        Some(Outcome::Deny) => PolicyResult::Deny,
        None => PolicyResult::Unknown(Unknown {
            reason: Reason::PolicyClauseNotEvaluated,
            details,
        }),
    }
}

/// The result of the policy of `neighbor` in `direction` on a route.
///
/// A neighbour with no policy in the direction permits the route, except
/// an eBGP session under the `ebgp-requires-policy` rule of the profile and
/// the options. A policy name that the process does not define gives the
/// `undefined_policy` result of the profile. No profile gives `Unknown`
/// with the reason "no bgp profile".
pub fn neighbor_policy(
    process: &BgpProcess,
    neighbor: &Neighbor,
    direction: Direction,
    key: &RouteKey,
    path: &BgpPath,
    profile: Option<&BgpProfile>,
) -> PolicyResult {
    let Some(profile) = profile else {
        return PolicyResult::Unknown(Unknown::new(Reason::NoBgpProfile, "the platform"));
    };
    let kind = process.session_kind(neighbor);
    let no_policy = || {
        if profile.no_policy_permits(kind, &process.options) {
            PolicyResult::Permit(path.clone())
        } else {
            PolicyResult::Deny
        }
    };
    let name = match direction {
        Direction::Import => &neighbor.import_policy,
        Direction::Export => &neighbor.export_policy,
    };
    let Some(name) = name else {
        return no_policy();
    };
    let Some(policy) = process.policy.policies.get(name) else {
        return match profile.undefined_policy {
            UndefinedPolicy::Deny => PolicyResult::Deny,
            UndefinedPolicy::NoPolicy => no_policy(),
        };
    };
    let ctx = PolicyContext {
        set: &process.policy,
        direction,
        local_address: neighbor.local_address,
        peer_address: Some(neighbor.address),
        default_local_pref: profile.default_local_pref(&process.options),
        match_reads: profile.match_reads,
    };
    evaluate(policy, key, path, &ctx)
}

/// The import or the export policy stage of one neighbour.
pub struct PolicyStage<'a> {
    pub process: &'a BgpProcess,
    pub neighbor: IpAddr,
    pub direction: Direction,
}

fn term_reads(t: &MatchTerm, device: &str, vrf: &str, out: &mut BTreeSet<ObjectRef>) {
    let (d, v) = (device.to_string(), vrf.to_string());
    match t {
        MatchTerm::PrefixList(names) | MatchTerm::NextHop(NextHopMatch::PrefixList(names)) => {
            for name in names {
                out.insert(ObjectRef::PrefixList {
                    device: d.clone(),
                    vrf: v.clone(),
                    name: name.clone(),
                });
            }
        }
        MatchTerm::CommunityList { names, .. } => {
            for name in names {
                out.insert(ObjectRef::CommunityList {
                    device: d.clone(),
                    vrf: v.clone(),
                    name: name.clone(),
                });
            }
        }
        MatchTerm::AsPathList(names) => {
            for name in names {
                out.insert(ObjectRef::AsPathList {
                    device: d.clone(),
                    vrf: v.clone(),
                    name: name.clone(),
                });
            }
        }
        _ => {}
    }
}

fn set_reads(a: &SetAction, device: &str, vrf: &str, out: &mut BTreeSet<ObjectRef>) {
    if let SetAction::CommunityDelete(name) = a {
        out.insert(ObjectRef::CommunityList {
            device: device.to_string(),
            vrf: vrf.to_string(),
            name: name.clone(),
        });
    }
}

fn guard_reads(g: &Guard, device: &str, vrf: &str, out: &mut BTreeSet<ObjectRef>) {
    match g {
        Guard::Term(t) => term_reads(t, device, vrf, out),
        Guard::Not(inner) => guard_reads(inner, device, vrf, out),
        Guard::And(gs) | Guard::Or(gs) => gs.iter().for_each(|g| guard_reads(g, device, vrf, out)),
    }
}

/// Adds the policy `name`, the lists that it references and the policies
/// that it applies to `out`.
fn policy_reads(
    set: &PolicySet,
    name: &str,
    device: &str,
    vrf: &str,
    out: &mut BTreeSet<ObjectRef>,
) {
    let me = ObjectRef::Policy {
        device: device.to_string(),
        vrf: vrf.to_string(),
        name: name.to_string(),
    };
    if !out.insert(me) {
        return;
    }
    let Some(policy) = set.policies.get(name) else {
        return;
    };
    match &policy.body {
        PolicyBody::RouteMap(clauses) => {
            for c in clauses {
                c.matches
                    .iter()
                    .for_each(|t| term_reads(t, device, vrf, out));
                c.sets.iter().for_each(|a| set_reads(a, device, vrf, out));
            }
        }
        PolicyBody::Rpl(stmts) => {
            let mut stack: Vec<&Statement> = stmts.iter().collect();
            while let Some(s) = stack.pop() {
                match s {
                    Statement::If {
                        branches,
                        otherwise,
                    } => {
                        for (g, b) in branches {
                            guard_reads(g, device, vrf, out);
                            stack.extend(b);
                        }
                        stack.extend(otherwise);
                    }
                    Statement::Set(a) => set_reads(a, device, vrf, out),
                    Statement::Apply(callee) => policy_reads(set, callee, device, vrf, out),
                    _ => {}
                }
            }
        }
    }
}

impl RoutingStage for PolicyStage<'_> {
    type Input = (RouteKey, BgpPath);
    type Output = PolicyResult;

    fn name(&self) -> &'static str {
        match self.direction {
            Direction::Import => "bgp import policy",
            Direction::Export => "bgp export policy",
        }
    }

    fn reads(&self) -> BTreeSet<ObjectRef> {
        let p = self.process;
        let mut out = BTreeSet::from([
            ObjectRef::Profile(p.platform),
            ObjectRef::Process {
                device: p.device.clone(),
                vrf: p.vrf.clone(),
            },
            ObjectRef::Neighbor {
                device: p.device.clone(),
                vrf: p.vrf.clone(),
                address: self.neighbor,
            },
        ]);
        let name = p
            .neighbors
            .get(&self.neighbor)
            .and_then(|n| match self.direction {
                Direction::Import => n.import_policy.as_ref(),
                Direction::Export => n.export_policy.as_ref(),
            });
        if let Some(name) = name {
            policy_reads(&p.policy, name, &p.device, &p.vrf, &mut out);
        }
        out
    }

    /// A neighbour that the process does not hold denies each route.
    fn run(&self, input: &(RouteKey, BgpPath)) -> PolicyResult {
        let Some(n) = self.process.neighbors.get(&self.neighbor) else {
            return PolicyResult::Deny;
        };
        let profile = self.process.profile();
        neighbor_policy(
            self.process,
            n,
            self.direction,
            &input.0,
            &input.1,
            profile.as_ref(),
        )
    }
}
