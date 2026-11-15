//! The answer of a query (section 4) and the aggregation of verdicts (section 7).

use std::collections::BTreeMap;

use rsim_core::{
    Context, Delay, Destination, FlowState, FunctionId, PacketSet, TraceStep, Verdict, VerdictKind,
};

/// The mode of a query (section 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mode {
    /// `Deliver` if a minimum of one alternative delivers.
    Possible,
    /// `Drop` if a minimum of one alternative drops.
    Guaranteed,
}

/// An assumption that an answer depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Assumption {
    /// The snapshot does not record the hash that spreads flows over the
    /// alternatives of a forwarding choice. The selection is independent for
    /// each device and for each connection.
    IndependentSelection,
}

impl Assumption {
    pub fn text(&self) -> &'static str {
        match self {
            Assumption::IndependentSelection => {
                "the selection among the alternatives of a forwarding choice is independent for each device and for each connection"
            }
        }
    }
}

/// One function application and its branches. The nodes of an answer are
/// in a list; the root is at index 0, and a child has a larger index than
/// its parent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecNode {
    pub function: FunctionId,
    pub edges: Vec<ExecEdge>,
}

/// One branch of a function application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecEdge {
    pub step: TraceStep,
    /// The index of the next function application, for a `Forward` that the
    /// executor followed.
    pub next: Option<usize>,
    /// The verdict, if the branch ends here.
    pub end: Option<End>,
}

/// The end of a branch, with the context and the flow state at the end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct End {
    pub verdict: Verdict,
    pub ctx: Context,
    pub state: FlowState,
}

/// One branch from the start to its end, in depth-first order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchView<'a> {
    pub index: usize,
    pub steps: Vec<&'a TraceStep>,
    pub verdict: &'a Verdict,
    pub ctx: &'a Context,
    pub state: &'a FlowState,
    /// The packets at the end of the branch.
    pub packets: &'a PacketSet,
    pub delay: Delay,
}

/// The answer to the reply of one delivered forward branch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// The index of the forward branch in [`Answer::branches`].
    pub forward_branch: usize,
    pub result: ReplyResult,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplyResult {
    Ran(Box<Answer>),
    /// The reply was not run. The text says why.
    NotRun(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub mode: Mode,
    pub start: FunctionId,
    pub input: PacketSet,
    /// The function applications. The root is at index 0.
    pub nodes: Vec<ExecNode>,
    /// The aggregated verdict of the packet for the mode of the query.
    pub verdict: Verdict,
    pub assumptions: Vec<Assumption>,
    /// The replies, one for each delivered forward branch, in branch order.
    pub replies: Vec<Reply>,
}

impl Answer {
    /// All branches in a fixed depth-first order.
    pub fn branches(&self) -> Vec<BranchView<'_>> {
        let mut out = Vec::new();
        let mut path: Vec<&TraceStep> = Vec::new();
        // (node, next edge). The path holds the step into each open node
        // after the root.
        let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
        while let Some(top) = stack.last_mut() {
            let (n, e) = *top;
            let Some(edge) = self.nodes[n].edges.get(e) else {
                stack.pop();
                if !stack.is_empty() {
                    path.pop();
                }
                continue;
            };
            top.1 += 1;
            path.push(&edge.step);
            if let Some(child) = edge.next {
                stack.push((child, 0));
                continue;
            }
            if let Some(end) = &edge.end {
                let delay = path.iter().fold(Delay::zero(), |d, s| d.add(&s.delay));
                out.push(BranchView {
                    index: out.len(),
                    steps: path.clone(),
                    verdict: &end.verdict,
                    ctx: &end.ctx,
                    state: &end.state,
                    packets: &edge.step.output,
                    delay,
                });
            }
            path.pop();
        }
        out
    }

    pub fn reply_of(&self, branch: usize) -> Option<&Answer> {
        self.replies.iter().find_map(|r| match &r.result {
            ReplyResult::Ran(a) if r.forward_branch == branch => Some(a.as_ref()),
            _ => None,
        })
    }
}

/// Combines the verdicts of the alternatives of a forwarding choice with the
/// mode rule. The first verdict of the selected kind, in the fixed order of
/// the alternatives, gives the reason.
pub fn combine_choice(mode: Mode, verdicts: &[Verdict]) -> Verdict {
    let order = match mode {
        Mode::Possible => [
            VerdictKind::Deliver,
            VerdictKind::Indeterminate,
            VerdictKind::Drop,
        ],
        Mode::Guaranteed => [
            VerdictKind::Drop,
            VerdictKind::Indeterminate,
            VerdictKind::Deliver,
        ],
    };
    pick(&order, verdicts)
}

/// Combines the verdicts of the copies of a flood. The rule is the same in
/// the two modes.
pub fn combine_flood(verdicts: &[Verdict]) -> Verdict {
    pick(
        &[
            VerdictKind::Deliver,
            VerdictKind::Indeterminate,
            VerdictKind::Drop,
        ],
        verdicts,
    )
}

fn pick(order: &[VerdictKind; 3], verdicts: &[Verdict]) -> Verdict {
    for k in order {
        if let Some(v) = verdicts.iter().find(|v| v.kind() == *k) {
            return v.clone();
        }
    }
    unreachable!("a choice or a flood has at least one branch")
}

/// The aggregated verdict of a node for one packet, from the end of the path
/// back to the start.
///
/// Step 1 is concrete mode: the input of each node is one packet, so the
/// edges of a node are one plain branch, the alternatives of one choice, or
/// the copies of one flood. `Err` names a node where this is not true.
pub fn aggregate(nodes: &[ExecNode], mode: Mode) -> Result<Verdict, String> {
    // A child has a larger index than its parent, so the reverse order
    // aggregates each node after all of its children.
    let mut verdicts: Vec<Option<Verdict>> = vec![None; nodes.len()];
    for i in (0..nodes.len()).rev() {
        verdicts[i] = Some(aggregate_node(&nodes[i], &verdicts, mode)?);
    }
    verdicts
        .into_iter()
        .next()
        .flatten()
        .ok_or_else(|| "the answer has no node".to_string())
}

fn aggregate_node(
    node: &ExecNode,
    verdicts: &[Option<Verdict>],
    mode: Mode,
) -> Result<Verdict, String> {
    let mut plain = Vec::new();
    let mut choices: BTreeMap<(FunctionId, String), Vec<Verdict>> = BTreeMap::new();
    let mut floods: BTreeMap<FunctionId, Vec<Verdict>> = BTreeMap::new();
    for e in &node.edges {
        let v = match (&e.end, e.next) {
            (Some(end), _) => end.verdict.clone(),
            (None, Some(n)) => verdicts[n]
                .clone()
                .ok_or_else(|| format!("the child of {} has no verdict", node.function))?,
            (None, None) => return Err(format!("an edge of {} has no end", node.function)),
        };
        if let Some(a) = &e.step.alternative {
            choices
                .entry((a.choice.clone(), a.key.clone()))
                .or_default()
                .push(v);
        } else if let Some(fc) = &e.step.flood_copy {
            floods.entry(fc.flood.clone()).or_default().push(v);
        } else {
            plain.push(v);
        }
    }
    let mut groups: Vec<Verdict> = plain;
    groups.extend(choices.values().map(|vs| combine_choice(mode, vs)));
    groups.extend(floods.values().map(|vs| combine_flood(vs)));
    match groups.as_slice() {
        [one] => Ok(one.clone()),
        _ => Err(format!(
            "{} has {} parts for one packet; the aggregation of parts is step 2",
            node.function,
            groups.len()
        )),
    }
}

/// True if a delivered branch reached an endpoint, with its id.
pub fn delivered_endpoint(v: &Verdict) -> Option<&rsim_core::EndpointId> {
    match v {
        Verdict::Deliver(Destination::Endpoint(e)) => Some(e),
        _ => None,
    }
}
