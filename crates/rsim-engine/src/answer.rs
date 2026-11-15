//! The answer of a query (section 4) and the summary of its paths (section 7).

use std::collections::BTreeMap;

use rsim_core::{
    Context, Delay, Destination, FlowState, FunctionId, PacketSet, TraceStep, Verdict, VerdictKind,
};

/// The result of a query over all of its paths. Each path and its own
/// result are in [`Answer::branches`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Summary {
    /// Every path ends with this verdict.
    Same(Verdict),
    /// Every path ends with this kind of verdict, with different details,
    /// for example different drop reasons.
    SameKind(VerdictKind),
    /// The ECMP paths end differently.
    DependsOnPath,
}

impl Summary {
    /// The verdict, if every path ends with the same verdict.
    pub fn verdict(&self) -> Option<&Verdict> {
        match self {
            Summary::Same(v) => Some(v),
            _ => None,
        }
    }

    /// The kind of verdict, if every path ends with the same kind.
    pub fn kind(&self) -> Option<VerdictKind> {
        match self {
            Summary::Same(v) => Some(v.kind()),
            Summary::SameKind(k) => Some(*k),
            Summary::DependsOnPath => None,
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
    pub start: FunctionId,
    pub input: PacketSet,
    /// The function applications. The root is at index 0.
    pub nodes: Vec<ExecNode>,
    /// The result over all paths.
    pub summary: Summary,
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

    /// The verdict, if every path ends with the same verdict.
    pub fn verdict(&self) -> Option<&Verdict> {
        self.summary.verdict()
    }

    pub fn reply_of(&self, branch: usize) -> Option<&Answer> {
        self.replies.iter().find_map(|r| match &r.result {
            ReplyResult::Ran(a) if r.forward_branch == branch => Some(a.as_ref()),
            _ => None,
        })
    }
}

/// Combines the results of the ECMP paths of one forwarding choice.
pub fn combine_paths(paths: &[Summary]) -> Summary {
    let Some(first) = paths.first() else {
        unreachable!("a forwarding choice has at least one path")
    };
    if paths.iter().all(|p| p == first) {
        return first.clone();
    }
    match first.kind() {
        Some(k) if paths.iter().all(|p| p.kind() == Some(k)) => Summary::SameKind(k),
        _ => Summary::DependsOnPath,
    }
}

/// Combines the results of the copies of a flood: delivered if a minimum of
/// one copy delivers. If not, the result depends on the path if a minimum of
/// one copy depends on the path. If not, `Unknown` if a minimum of one
/// copy is `Unknown`. If not, dropped. The first copy of the selected
/// kind, in the fixed order of the copies, gives the result.
pub fn combine_flood(copies: &[Summary]) -> Summary {
    let rank = |s: &Summary| match s.kind() {
        Some(VerdictKind::Deliver) => 0,
        None => 1,
        Some(VerdictKind::Unknown) => 2,
        Some(VerdictKind::Drop) => 3,
    };
    let Some(best) = copies.iter().map(rank).min() else {
        unreachable!("a flood has at least one copy")
    };
    let Some(first) = copies.iter().find(|c| rank(c) == best) else {
        unreachable!("the minimum comes from a copy")
    };
    first.clone()
}

/// The summary of the answer, from the end of each path back to the start.
///
/// Step 1 is concrete mode: the input of each node is one packet, so the
/// edges of a node are one plain branch, the paths of one forwarding choice,
/// or the copies of one flood. `Err` names a node where this is not true.
pub fn aggregate(nodes: &[ExecNode]) -> Result<Summary, String> {
    // A child has a larger index than its parent, so the reverse order
    // handles each node after all of its children.
    let mut summaries: Vec<Option<Summary>> = vec![None; nodes.len()];
    for i in (0..nodes.len()).rev() {
        summaries[i] = Some(aggregate_node(&nodes[i], &summaries)?);
    }
    summaries
        .into_iter()
        .next()
        .flatten()
        .ok_or_else(|| "the answer has no node".to_string())
}

fn aggregate_node(node: &ExecNode, summaries: &[Option<Summary>]) -> Result<Summary, String> {
    let mut plain = Vec::new();
    let mut choices: BTreeMap<(FunctionId, String), Vec<Summary>> = BTreeMap::new();
    let mut floods: BTreeMap<FunctionId, Vec<Summary>> = BTreeMap::new();
    for e in &node.edges {
        let v = match (&e.end, e.next) {
            (Some(end), _) => Summary::Same(end.verdict.clone()),
            (None, Some(n)) => summaries[n]
                .clone()
                .ok_or_else(|| format!("the child of {} has no summary", node.function))?,
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
    let mut groups: Vec<Summary> = plain;
    groups.extend(choices.values().map(|vs| combine_paths(vs)));
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
