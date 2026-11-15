//! The concrete-mode executor.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use rsim_core::{
    Branch, Context, ContextAttr, Destination, EndpointId, FieldValue, FlowState, FunctionId,
    FunctionKind, Header, NetFunction, Outcome, PacketSet, QosView, Reason, ReasonCode,
    RibGuardFlag, TraceStep, Verdict,
};

use crate::answer::{
    Answer, End, ExecEdge, ExecNode, Reply, ReplyResult, aggregate, delivered_endpoint,
};
use crate::twin::Twin;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    pub start: FunctionId,
    pub packets: PacketSet,
    /// Run the return path for each delivered branch.
    pub reply: bool,
}

impl Query {
    /// A query for one packet from an endpoint.
    pub fn from_endpoint(
        twin: &Twin,
        endpoint: &EndpointId,
        header: Header,
    ) -> Result<Query, ExecError> {
        let e = twin
            .endpoint(endpoint)
            .ok_or_else(|| ExecError::UnknownEndpoint(endpoint.clone()))?;
        Ok(Query {
            start: e.attachment.clone(),
            packets: PacketSet::single(header),
            reply: true,
        })
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
}

impl Default for ExecOptions {
    fn default() -> Self {
        ExecOptions {
            check_contract: true,
            max_steps: 10_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecError {
    UnknownFunction(FunctionId),
    UnknownEndpoint(EndpointId),
    /// The start function requires context that a query does not supply.
    StartRequiresContext(FunctionId, Vec<ContextAttr>),
    ContractViolation {
        function: FunctionId,
        detail: String,
    },
    Aggregation(String),
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ExecError {}

/// The full state of a branch at the input of a function. A return to the
/// same full state is a loop.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StateKey {
    function: FunctionId,
    ctx: Context,
    packets: PacketSet,
    state: FlowState,
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
        let mut answer = self.run_one(&q.start, &q.packets, FlowState::new())?;
        if q.reply {
            answer.replies = self.replies(&answer)?;
        }
        Ok(answer)
    }

    fn run_one(
        &self,
        start: &FunctionId,
        packets: &PacketSet,
        state: FlowState,
    ) -> Result<Answer, ExecError> {
        let f = self
            .twin
            .function(start)
            .ok_or_else(|| ExecError::UnknownFunction(start.clone()))?;
        let req = f.requires();
        if !req.is_empty() {
            return Err(ExecError::StartRequiresContext(start.clone(), req));
        }
        let nodes = self.walk(start, packets.clone(), state)?;
        let summary = aggregate(&nodes).map_err(ExecError::Aggregation)?;
        Ok(Answer {
            start: start.clone(),
            input: packets.clone(),
            nodes,
            summary,
            replies: Vec::new(),
        })
    }

    /// Builds the reply of each delivered branch and runs it from the
    /// destination with the flow state of that branch.
    fn replies(&self, forward: &Answer) -> Result<Vec<Reply>, ExecError> {
        let mut out = Vec::new();
        for b in forward.branches() {
            if !matches!(b.verdict, Verdict::Deliver(_)) {
                continue;
            }
            let result = match delivered_endpoint(b.verdict) {
                Some(e) => match self.twin.endpoint(e) {
                    Some(ep) => {
                        let a =
                            self.run_one(&ep.attachment, &b.packets.reply(), b.state.clone())?;
                        ReplyResult::Ran(Box::new(a))
                    }
                    None => ReplyResult::NotRun(format!("endpoint {e} is not in the twin")),
                },
                None => ReplyResult::NotRun(match b.verdict {
                    Verdict::Deliver(Destination::Device(d)) => {
                        format!("reply from device {d} not supported")
                    }
                    _ => unreachable!(),
                }),
            };
            out.push(Reply {
                forward_branch: b.index,
                result,
            });
        }
        Ok(out)
    }

    /// Applies one function and opens a frame for its branches.
    fn open(
        &self,
        id: &FunctionId,
        packets: PacketSet,
        ctx: Context,
        state: FlowState,
        nodes: &mut Vec<ExecNode>,
        visited: &mut BTreeSet<StateKey>,
    ) -> Result<Frame, ExecError> {
        let f = self
            .twin
            .function(id)
            .ok_or_else(|| ExecError::UnknownFunction(id.clone()))?
            .clone();
        let branches = f.apply(&packets, &ctx, &state);
        if self.opts.check_contract {
            check_contract(f.as_ref(), &packets, &ctx, &branches)?;
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
    /// order of the branches. The walk uses an explicit stack, so a long
    /// path does not use the call stack.
    fn walk(
        &self,
        start: &FunctionId,
        packets: PacketSet,
        state: FlowState,
    ) -> Result<Vec<ExecNode>, ExecError> {
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
            let parent = top.node;
            let step = trace_step(top.f.as_ref(), &top.key.packets, &b);
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
                            Verdict::Drop(Reason::new(ReasonCode::Loop, format!("loop · {next}"))),
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
        rib_guard: if f.kind() == FunctionKind::RouteLookup {
            RibGuardFlag::NotChecked
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
        let marks = |s: &PacketSet| -> BTreeSet<(FieldValue<u8>, FieldValue<u8>)> {
            s.members()
                .iter()
                .map(|p| (p.current.dscp, p.current.ecn))
                .collect()
        };
        let before = marks(input);
        for b in branches {
            if !marks(&b.packets).is_subset(&before) {
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
                .or_insert_with(PacketSet::empty);
            if !g.intersect(&orig(&b.packets)).is_empty() {
                return Err(format!(
                    "alternative {} of {} duplicates packets",
                    a.index, a.key
                ));
            }
            *g = g.union(&orig(&b.packets));
        } else if let Some(fc) = &b.flood_copy {
            let g = groups
                .entry((1, fc.flood.to_string(), String::new()))
                .or_default()
                .entry(fc.index)
                .or_insert_with(PacketSet::empty);
            if !g.intersect(&orig(&b.packets)).is_empty() {
                return Err(format!("flood copy {} duplicates packets", fc.index));
            }
            *g = g.union(&orig(&b.packets));
        } else {
            plain.push(orig(&b.packets));
        }
    }
    let mut covered = PacketSet::empty();
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
