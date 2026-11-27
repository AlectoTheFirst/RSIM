//! The executor: ingress resolution, the walk of each branch, the node
//! budget of the packet sets and the return path.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use rsim_core::{
    AddrField, Branch, Context, ContextAttr, DdError, Destination, DeviceId, FlowState, FunctionId,
    FunctionKind, Header, HeaderField, InterfaceId, NetFunction, Outcome, PacketSet, QosView,
    Reason, ReasonCode, RibGuardFlag, SourceSpan, TraceStep, Verdict,
};

use crate::answer::{
    Answer, End, ExecEdge, ExecNode, Ingress, IngressBasis, Mode, Part, Reply, ReplyResult, Run,
    RunBody, Summary, aggregate,
};
use crate::twin::Twin;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// The ingress that the query states: a device and an interface. Without
    /// it, the executor finds the ingress from the source address.
    pub ingress: Option<(DeviceId, InterfaceId)>,
    pub packets: PacketSet,
    /// Run the return path for each delivered branch.
    pub reply: bool,
    pub mode: Mode,
}

impl Query {
    /// A path query for one packet. A field that the header does not state
    /// is not known.
    pub fn path(twin: &Twin, header: &Header) -> Query {
        let arena = twin.arena(None);
        Query {
            ingress: None,
            packets: PacketSet::single(&arena, header),
            reply: true,
            mode: Mode::Path,
        }
    }

    /// A set query. A field with no constraint has all values.
    pub fn set(packets: PacketSet) -> Query {
        Query {
            ingress: None,
            packets,
            reply: true,
            mode: Mode::Set,
        }
    }

    pub fn with_ingress(
        mut self,
        device: impl Into<DeviceId>,
        interface: impl Into<InterfaceId>,
    ) -> Self {
        self.ingress = Some((device.into(), interface.into()));
        self
    }

    pub fn without_reply(mut self) -> Self {
        self.reply = false;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecOptions {
    /// Check the partition rule and the QoS rule of the function contract at
    /// each step. A violation is an error of the query.
    pub check_contract: bool,
    /// The maximum number of steps of one branch. A branch that reaches it
    /// ends as `Unknown` with the reason `StepBudget`. Loops are
    /// detected before this limit; see [`ReasonCode::Loop`].
    pub max_steps: usize,
    /// The node budget of the packet sets of one run. A run over the budget
    /// splits its input. `None` is no budget.
    pub node_budget: Option<usize>,
    /// The maximum number of runs of one query. When a query has this
    /// number of runs, a part over the node budget does not split again.
    pub max_runs: usize,
    /// The maximum number of branches of one query, over the forward walks
    /// and the reply walks. A branch to a next function past this limit,
    /// and a part of the input that starts after it, end as `Unknown` with
    /// the reason `StepBudget`.
    pub max_branches: usize,
}

impl Default for ExecOptions {
    fn default() -> Self {
        ExecOptions {
            check_contract: true,
            max_steps: 10_000,
            node_budget: Some(1_000_000),
            max_runs: 256,
            max_branches: 100_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecError {
    UnknownFunction(FunctionId),
    /// The query states an ingress that has no ingress function.
    UnknownIngress(DeviceId, InterfaceId),
    /// The start function requires context that a query does not supply.
    StartRequiresContext(FunctionId, Vec<ContextAttr>),
    ContractViolation {
        function: FunctionId,
        detail: String,
    },
    Aggregation(String),
    /// A fault of the packet sets other than the node budget.
    PacketSet(DdError),
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ExecError {}

/// Why a run stops before its end.
enum Stop {
    Fault(DdError),
    Error(ExecError),
}

impl From<ExecError> for Stop {
    fn from(e: ExecError) -> Self {
        Stop::Error(e)
    }
}

/// The fault of the arena of a set, as a stop.
fn fault_of(s: &PacketSet) -> Result<(), Stop> {
    match s.arena().fault() {
        Some(e) => Err(Stop::Fault(e)),
        None => Ok(()),
    }
}

/// The full state of a branch at the input of a function. A return to the
/// same full state is a loop.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StateKey {
    function: FunctionId,
    ctx: Context,
    packets: PacketSet,
    state: FlowState,
}

/// The runs and the branches of one query so far.
#[derive(Default)]
struct Count {
    runs: usize,
    branches: usize,
}

/// The index of a resolved part and the spans of its attachment records.
type SpanGroup = (usize, BTreeSet<SourceSpan>);

/// One finished run with its summary parts and its replies. A reply holds
/// the index of its forward branch in the run.
struct RunOut {
    run: Run,
    parts: Vec<Part>,
    replies: Vec<(usize, ReplyResult)>,
}

pub struct Executor<'t> {
    twin: &'t Twin,
    opts: ExecOptions,
}

impl<'t> Executor<'t> {
    pub fn new(twin: &'t Twin) -> Self {
        Executor {
            twin,
            opts: ExecOptions::default(),
        }
    }

    pub fn with_options(twin: &'t Twin, opts: ExecOptions) -> Self {
        Executor { twin, opts }
    }

    pub fn run(&self, q: &Query) -> Result<Answer, ExecError> {
        let mut outs = Vec::new();
        let mut count = Count::default();
        for (set, ingress) in self.resolve(q)? {
            if set.is_empty() {
                continue;
            }
            match &ingress {
                Ingress::Found { function, .. } if count.branches < self.opts.max_branches => {
                    let start = function.clone();
                    self.run_part(&set, &ingress, &start, q, &mut outs, &mut count)?;
                }
                Ingress::Found { .. } => {
                    let v = Verdict::Unknown(self.branch_limit());
                    outs.push(ended(&set, ingress.clone(), v));
                }
                Ingress::NotFound(r) => {
                    outs.push(ended(&set, ingress.clone(), Verdict::Unknown(r.clone())));
                }
            }
        }
        Ok(assemble(q.mode, &q.packets, outs))
    }

    /// The parts of the input with their ingress.
    fn resolve(&self, q: &Query) -> Result<Vec<(PacketSet, Ingress)>, ExecError> {
        if let Some((d, i)) = &q.ingress {
            let f = self
                .twin
                .ingress(d, i)
                .ok_or_else(|| ExecError::UnknownIngress(d.clone(), i.clone()))?;
            return Ok(vec![(
                q.packets.clone(),
                Ingress::Found {
                    device: d.clone(),
                    interface: i.clone(),
                    function: f.clone(),
                    basis: IngressBasis::Explicit,
                },
            )]);
        }
        let part = q
            .packets
            .partition_by_prefix(AddrField::Src, self.twin.ingress_table());
        let mut out: Vec<(PacketSet, Ingress)> = Vec::new();
        // The attachment parts with the same device, interface and function
        // join into one part, at the index of the first of them, with the
        // spans of all of their records.
        let mut groups: BTreeMap<(DeviceId, InterfaceId, FunctionId), SpanGroup> = BTreeMap::new();
        for (p, cands, set) in part.matched {
            let ingress = crate::twin::ingress_of(&p, cands);
            let Ingress::Found {
                device,
                interface,
                function,
                basis: IngressBasis::Attachment(spans),
            } = &ingress
            else {
                out.push((set, ingress));
                continue;
            };
            let key = (device.clone(), interface.clone(), function.clone());
            match groups.get_mut(&key) {
                Some((i, seen)) => {
                    let new: Vec<SourceSpan> = spans
                        .iter()
                        .filter(|s| seen.insert((*s).clone()))
                        .cloned()
                        .collect();
                    let (joined, first) = &mut out[*i];
                    *joined = joined.union(&set);
                    if let Ingress::Found {
                        basis: IngressBasis::Attachment(all),
                        ..
                    } = first
                    {
                        all.extend(new);
                    }
                }
                None => {
                    let seen = spans.iter().cloned().collect();
                    groups.insert(key, (out.len(), seen));
                    out.push((set, ingress));
                }
            }
        }
        out.push((
            part.unmatched,
            Ingress::NotFound(Reason::new(
                ReasonCode::UnknownAttribute,
                "no ingress, no attachment record or edge network of the source address",
            )),
        ));
        out.push((
            part.uncertain,
            Ingress::NotFound(Reason::new(
                ReasonCode::UnknownAttribute,
                "no ingress, source address not known",
            )),
        ));
        Ok(out)
    }

    /// Runs one part in a new arena. A part over the node budget splits on
    /// the first bit of its original requests. A part that cannot split, or
    /// a part over the budget when the query has [`ExecOptions::max_runs`]
    /// runs, gets `Unknown` with the reason `SetBudget`.
    fn run_part(
        &self,
        input: &PacketSet,
        ingress: &Ingress,
        start: &FunctionId,
        q: &Query,
        outs: &mut Vec<RunOut>,
        count: &mut Count,
    ) -> Result<(), ExecError> {
        count.runs += 1;
        let branches = count.branches;
        // Each run has a new arena, so a query that runs again gives the
        // same answer.
        let s = input.copy_to(&self.twin.run_arena(self.opts.node_budget));
        let (state, n) = (FlowState::new(), &mut count.branches);
        let r = fault_of(&s).and_then(|()| self.try_run(&s, ingress, start, q, state, n));
        match r {
            Ok(out) => outs.push(out),
            Err(Stop::Fault(DdError::NodeBudget { budget })) => {
                // The branches of the dropped run do not count.
                count.branches = branches;
                // The arena of the input can have the fault of a run, so
                // the split then works on a copy in an arena with no budget.
                let input = if input.arena().fault().is_some() {
                    input.copy_to(&self.twin.arena(None))
                } else {
                    input.clone()
                };
                let input = &input;
                let split = if count.runs < self.opts.max_runs {
                    input.split_on_first_bit()
                } else {
                    None
                };
                match split {
                    Some((a, b)) => {
                        self.run_part(&a, ingress, start, q, outs, count)?;
                        self.run_part(&b, ingress, start, q, outs, count)?;
                    }
                    None => {
                        let detail = if count.runs < self.opts.max_runs {
                            format!("one original request over the node budget {budget}")
                        } else {
                            format!(
                                "part over the node budget {budget}, {} runs",
                                self.opts.max_runs
                            )
                        };
                        outs.push(ended(
                            input,
                            ingress.clone(),
                            Verdict::Unknown(Reason::new(ReasonCode::SetBudget, detail)),
                        ));
                    }
                }
            }
            Err(Stop::Fault(e)) => return Err(ExecError::PacketSet(e)),
            Err(Stop::Error(e)) => return Err(e),
        }
        Ok(())
    }

    /// Walks the packets of one run from the start function, and runs the
    /// replies in the same arena.
    fn try_run(
        &self,
        s: &PacketSet,
        ingress: &Ingress,
        start: &FunctionId,
        q: &Query,
        state: FlowState,
        branches: &mut usize,
    ) -> Result<RunOut, Stop> {
        let f = self
            .twin
            .function(start)
            .ok_or_else(|| ExecError::UnknownFunction(start.clone()))?;
        let req = f.requires();
        if !req.is_empty() {
            return Err(ExecError::StartRequiresContext(start.clone(), req).into());
        }
        let nodes = self.walk(start, s.clone(), state, branches)?;
        let parts = aggregate(&nodes).map_err(ExecError::Aggregation)?;
        fault_of(s)?;
        if self.opts.check_contract {
            check_parts(&parts, s).map_err(ExecError::Aggregation)?;
            fault_of(s)?;
        }
        let run = Run {
            ingress: ingress.clone(),
            input: s.clone(),
            body: RunBody::Walked(nodes),
        };
        let replies = if q.reply {
            self.replies(&run, q.mode, branches)?
        } else {
            Vec::new()
        };
        Ok(RunOut {
            run,
            parts,
            replies,
        })
    }

    /// Builds the reply of each delivered branch of a run and runs it from
    /// the interface that delivered the forward packets, with the flow state
    /// of that branch.
    fn replies(
        &self,
        run: &Run,
        mode: Mode,
        branches: &mut usize,
    ) -> Result<Vec<(usize, ReplyResult)>, Stop> {
        let mut out = Vec::new();
        for b in run.branches(0) {
            let Verdict::Deliver(d) = b.verdict else {
                continue;
            };
            let result = match d {
                Destination::Endpoint(_) => {
                    match (b.ctx.device.known(), b.ctx.egress_interface.known()) {
                        (Some(dev), Some(iface)) => match self.twin.ingress(dev, iface) {
                            Some(f) => {
                                let ing = Ingress::Found {
                                    device: dev.clone(),
                                    interface: iface.clone(),
                                    function: f.clone(),
                                    basis: IngressBasis::Reply,
                                };
                                let rs = b.packets.reply();
                                fault_of(&rs)?;
                                let q = Query {
                                    ingress: None,
                                    packets: rs.clone(),
                                    reply: false,
                                    mode,
                                };
                                let o =
                                    self.try_run(&rs, &ing, f, &q, b.state.clone(), branches)?;
                                ReplyResult::Ran(Box::new(assemble(mode, &rs, vec![o])))
                            }
                            None => {
                                ReplyResult::NotRun(format!("no ingress function at {dev}/{iface}"))
                            }
                        },
                        _ => ReplyResult::NotRun("delivering interface not known".to_string()),
                    }
                }
                Destination::Device(d) => {
                    ReplyResult::NotRun(format!("reply from device {d} not supported"))
                }
            };
            out.push((b.index, result));
        }
        Ok(out)
    }

    /// The reason of a branch past [`ExecOptions::max_branches`].
    fn branch_limit(&self) -> Reason {
        Reason::new(
            ReasonCode::StepBudget,
            format!("branch limit {} reached", self.opts.max_branches),
        )
    }

    /// Applies one function and opens a frame for its branches.
    #[allow(
        clippy::mutable_key_type,
        reason = "the order of a packet set uses its edge and its arena address, which do not change"
    )]
    fn open(
        &self,
        id: &FunctionId,
        packets: PacketSet,
        ctx: Context,
        state: FlowState,
        nodes: &mut Vec<ExecNode>,
        visited: &mut BTreeSet<StateKey>,
    ) -> Result<Frame, Stop> {
        let f = self
            .twin
            .function(id)
            .ok_or_else(|| ExecError::UnknownFunction(id.clone()))?
            .clone();
        let branches = f.apply(&packets, &ctx, &state);
        fault_of(&packets)?;
        if self.opts.check_contract {
            check_contract(f.as_ref(), &packets, &ctx, &branches)?;
            fault_of(&packets)?;
        }
        let key = StateKey {
            function: id.clone(),
            ctx,
            packets,
            state,
        };
        visited.insert(key.clone());
        nodes.push(ExecNode {
            function: id.clone(),
            edges: Vec::with_capacity(branches.len()),
        });
        Ok(Frame {
            node: nodes.len() - 1,
            f,
            key,
            pending: branches.into_iter(),
        })
    }

    /// Follows every branch from the start function, depth first, in the
    /// order of the branches, and adds each branch to `branches`. The walk
    /// uses an explicit stack, so a long path does not use the call stack.
    #[allow(
        clippy::mutable_key_type,
        reason = "the order of a packet set uses its edge and its arena address, which do not change"
    )]
    fn walk(
        &self,
        start: &FunctionId,
        packets: PacketSet,
        state: FlowState,
        branches: &mut usize,
    ) -> Result<Vec<ExecNode>, Stop> {
        let mut nodes = Vec::new();
        let mut visited = BTreeSet::new();
        let mut stack = vec![self.open(
            start,
            packets,
            Context::default(),
            state,
            &mut nodes,
            &mut visited,
        )?];
        while let Some(top) = stack.last_mut() {
            let Some(b) = top.pending.next() else {
                visited.remove(&top.key);
                stack.pop();
                continue;
            };
            *branches += 1;
            let parent = top.node;
            let step = trace_step(top.f.as_ref(), &top.key.packets, &b);
            fault_of(&top.key.packets)?;
            let depth = stack.len();
            let edge = match &b.outcome {
                Outcome::Forward(next) => {
                    let next_key = StateKey {
                        function: next.clone(),
                        ctx: b.ctx.clone(),
                        packets: b.packets.clone(),
                        state: b.state.clone(),
                    };
                    if visited.contains(&next_key) {
                        terminal(
                            step,
                            Verdict::Drop(Reason::new(ReasonCode::Loop, format!("loop at {next}"))),
                            b,
                        )
                    } else if depth >= self.opts.max_steps {
                        terminal(
                            step,
                            Verdict::Unknown(Reason::new(
                                ReasonCode::StepBudget,
                                format!("step limit {} reached", self.opts.max_steps),
                            )),
                            b,
                        )
                    } else if *branches > self.opts.max_branches {
                        terminal(step, Verdict::Unknown(self.branch_limit()), b)
                    } else {
                        let next = next.clone();
                        let child =
                            self.open(&next, b.packets, b.ctx, b.state, &mut nodes, &mut visited)?;
                        let idx = child.node;
                        stack.push(child);
                        ExecEdge {
                            step,
                            next: Some(idx),
                            end: None,
                        }
                    }
                }
                Outcome::Deliver(d) => {
                    let v = Verdict::Deliver(d.clone());
                    terminal(step, v, b)
                }
                Outcome::Exit(x) => {
                    let v = Verdict::Exit(x.clone());
                    terminal(step, v, b)
                }
                Outcome::Drop => {
                    let v = Verdict::Drop(b.reason.clone());
                    terminal(step, v, b)
                }
                Outcome::Unknown => {
                    let v = Verdict::Unknown(b.reason.clone());
                    terminal(step, v, b)
                }
            };
            nodes[parent].edges.push(edge);
        }
        Ok(nodes)
    }
}

/// A function application whose branches the walk has not all followed.
struct Frame {
    node: usize,
    f: Arc<dyn NetFunction>,
    key: StateKey,
    pending: std::vec::IntoIter<Branch>,
}

/// A run that ended before a function.
fn ended(input: &PacketSet, ingress: Ingress, verdict: Verdict) -> RunOut {
    let summary = Summary::Same(verdict.clone());
    RunOut {
        run: Run {
            ingress,
            input: input.clone(),
            body: RunBody::Ended(Box::new(End {
                verdict,
                ctx: Context::default(),
                state: FlowState::new(),
            })),
        },
        parts: vec![Part {
            packets: input.project_original(),
            summary,
        }],
        replies: Vec::new(),
    }
}

/// The answer of the runs of one query. The branch indexes count over all
/// runs. A path query has 1 summary part: if the parts have different
/// results, the result depends on fields that the query does not state.
fn assemble(mode: Mode, input: &PacketSet, outs: Vec<RunOut>) -> Answer {
    let mut runs = Vec::new();
    let mut parts = Vec::new();
    let mut replies = Vec::new();
    let mut offset = 0;
    for (r, o) in outs.into_iter().enumerate() {
        let n = o.run.branches(r).len();
        for (i, result) in o.replies {
            replies.push(Reply {
                forward_branch: offset + i,
                result,
            });
        }
        offset += n;
        parts.extend(o.parts);
        runs.push(o.run);
    }
    let summary = match mode {
        Mode::Set => parts,
        Mode::Path => {
            let s = match parts.first() {
                Some(first) if parts.iter().all(|p| p.summary == first.summary) => {
                    first.summary.clone()
                }
                _ => Summary::Same(Verdict::Unknown(Reason::new(
                    ReasonCode::MatchUnknown,
                    "result depends on unstated fields",
                ))),
            };
            vec![Part {
                packets: input.project_original(),
                summary: s,
            }]
        }
    };
    Answer {
        mode,
        input: input.clone(),
        runs,
        summary,
        replies,
    }
}

/// Checks that the summary parts are disjoint and cover the input, by
/// original request.
fn check_parts(parts: &[Part], input: &PacketSet) -> Result<(), String> {
    let mut covered = input.empty();
    for p in parts {
        if !covered.intersect(&p.packets).is_empty() {
            return Err("two summary parts hold the same packets".into());
        }
        covered = covered.union(&p.packets);
    }
    if covered != input.project_original() {
        return Err("the summary parts do not cover the input".into());
    }
    Ok(())
}

fn terminal(step: TraceStep, verdict: Verdict, b: Branch) -> ExecEdge {
    ExecEdge {
        step,
        next: None,
        end: Some(End {
            verdict,
            ctx: b.ctx,
            state: b.state,
        }),
    }
}

fn trace_step(f: &dyn NetFunction, input: &PacketSet, b: &Branch) -> TraceStep {
    let mut provenance = f.provenance().to_vec();
    provenance.extend(b.spans.iter().cloned());
    TraceStep {
        function: f.id().clone(),
        kind: f.kind(),
        device: f.device().cloned(),
        input: input.clone(),
        output: b.packets.clone(),
        outcome: b.outcome.clone(),
        reason: b.reason.clone(),
        provenance,
        delay: b.delay.clone(),
        alternative: b.alternative.clone(),
        flood_copy: b.flood_copy.clone(),
        qos: QosView {
            dscp: b.packets.dscp(),
            ecn: b.packets.ecn(),
            traffic_class: b.ctx.traffic_class.clone(),
            drop_precedence: b.ctx.drop_precedence.clone(),
            queue: b.ctx.queue.clone(),
        },
        rate_condition: b.rate_condition.clone(),
        assumption: b.assumption.clone(),
        rib_guard: if f.kind() == FunctionKind::RouteLookup {
            b.rib_guard.unwrap_or(RibGuardFlag::NotChecked)
        } else {
            RibGuardFlag::NotApplicable
        },
    }
}

/// Checks the partition rule and the QoS rule of the function contract.
pub fn check_contract(
    f: &dyn NetFunction,
    input: &PacketSet,
    ctx: &Context,
    branches: &[Branch],
) -> Result<(), ExecError> {
    let violation = |detail: String| ExecError::ContractViolation {
        function: f.id().clone(),
        detail,
    };
    check_partition(input, branches).map_err(violation)?;
    if f.qos_writes().is_empty() {
        let marks = [HeaderField::Dscp, HeaderField::Ecn];
        let before = input.project_with_original(&marks);
        for b in branches {
            if !b.packets.project_with_original(&marks).is_subset(&before) {
                return Err(violation(
                    "the marking changed, and the function declares no QoS write".into(),
                ));
            }
            let provides = f.provides();
            let class_kept = (provides.contains(&ContextAttr::TrafficClass)
                || b.ctx.traffic_class == ctx.traffic_class)
                && (provides.contains(&ContextAttr::DropPrecedence)
                    || b.ctx.drop_precedence == ctx.drop_precedence)
                && (provides.contains(&ContextAttr::Queue) || b.ctx.queue == ctx.queue);
            if !class_kept {
                return Err(violation(
                    "the class changed, and the function does not provide it".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Checks that the branches partition the input: in each alternative of a
/// forwarding choice and in each copy of a flood. The input is compared by
/// original request, because a branch can rewrite the current header.
pub fn check_partition(input: &PacketSet, branches: &[Branch]) -> Result<(), String> {
    let orig = |s: &PacketSet| s.project_original();
    let mut plain = Vec::new();
    let mut groups: BTreeMap<(u8, String, String), BTreeMap<u32, PacketSet>> = BTreeMap::new();
    for b in branches {
        if b.packets.is_empty() {
            return Err("a branch is empty".into());
        }
        if let Some(a) = &b.alternative {
            let g = groups
                .entry((0, a.choice.to_string(), a.key.clone()))
                .or_default()
                .entry(a.index)
                .or_insert_with(|| input.empty());
            if !g.intersect(&orig(&b.packets)).is_empty() {
                return Err(format!(
                    "alternative {} of {} duplicates packets",
                    a.index, a.key
                ));
            }
            *g = g.union(&orig(&b.packets));
        } else if let Some(fc) = &b.flood_copy {
            let g = groups
                .entry((1, fc.flood.to_string(), fc.key.clone()))
                .or_default()
                .entry(fc.index)
                .or_insert_with(|| input.empty());
            if !g.intersect(&orig(&b.packets)).is_empty() {
                return Err(format!("flood copy {} duplicates packets", fc.index));
            }
            *g = g.union(&orig(&b.packets));
        } else {
            plain.push(orig(&b.packets));
        }
    }
    let mut covered = input.empty();
    for p in &plain {
        if !covered.intersect(p).is_empty() {
            return Err("two branches carry the same packets".into());
        }
        covered = covered.union(p);
    }
    for ((_, choice, key), alts) in &groups {
        let mut it = alts.values();
        let first = it.next().expect("a group has a member");
        if it.any(|s| s != first) {
            return Err(format!(
                "the alternatives or copies of {choice} {key} carry different packets"
            ));
        }
        if !covered.intersect(first).is_empty() {
            return Err(format!(
                "{choice} {key} duplicates packets of another branch"
            ));
        }
        covered = covered.union(first);
    }
    if covered != orig(input) {
        return Err("the branches do not cover the input".into());
    }
    Ok(())
}
