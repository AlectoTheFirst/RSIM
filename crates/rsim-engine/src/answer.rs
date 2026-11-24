//! The answer of a query and the summary of its paths.

use std::collections::{BTreeMap, BTreeSet};

use rsim_core::{
    AlternativeKind, Context, Delay, Destination, DeviceId, FlowState, FunctionId, InterfaceId,
    PacketSet, Reason, ReasonCode, SourceSpan, TraceStep, Verdict, VerdictKind,
};

/// The result of a query over all of its paths for one part of the packets.
/// Each path and its own result are in [`Answer::branches`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

/// One part of the summary: a set of original requests and its summary.
/// The parts of an answer are disjoint, and their union is the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    /// The original requests. Each member has the original request as both
    /// headers.
    pub packets: PacketSet,
    pub summary: Summary,
}

/// One function application and its branches. The nodes of a run are in a
/// list; the root is at index 0, and a child has a larger index than its
/// parent.
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

/// How the ingress of a run was found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressBasis {
    /// The query states the ingress.
    Explicit,
    /// Attachment records of the interface name the source addresses. The
    /// spans are those of the records.
    Attachment(Vec<SourceSpan>),
    /// The source address is on a connected network of an edge interface.
    /// No record confirms the host.
    ConnectedNetwork {
        network: rsim_core::Prefix,
        spans: Vec<SourceSpan>,
    },
    /// The reply starts at the interface that delivered the forward packets.
    Reply,
}

/// The ingress of a run: an interface and its ingress function, or the
/// reason why the ingress is not known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ingress {
    Found {
        device: DeviceId,
        interface: InterfaceId,
        function: FunctionId,
        basis: IngressBasis,
    },
    NotFound(Reason),
}

impl Ingress {
    /// True if the ingress comes only from a connected network.
    pub fn host_confirmed(&self) -> bool {
        !matches!(
            self,
            Ingress::Found {
                basis: IngressBasis::ConnectedNetwork { .. },
                ..
            }
        )
    }
}

/// One run of the executor: a part of the input with one ingress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub ingress: Ingress,
    /// The packets of the run.
    pub input: PacketSet,
    pub body: RunBody,
}

impl Run {
    /// The branches of the run in a fixed depth-first order. The index of a
    /// branch counts in the run, and `run` is the index of the run.
    pub fn branches(&self, run: usize) -> Vec<BranchView<'_>> {
        let mut out = Vec::new();
        match &self.body {
            RunBody::Ended(end) => out.push(BranchView {
                index: 0,
                run,
                steps: Vec::new(),
                verdict: &end.verdict,
                ctx: &end.ctx,
                state: &end.state,
                packets: &self.input,
                delay: Delay::zero(),
            }),
            RunBody::Walked(nodes) => walk_branches(nodes, run, &mut out),
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunBody {
    /// The function applications of the run.
    Walked(Vec<ExecNode>),
    /// The run ended before a function: no ingress, the set budget or the
    /// branch limit.
    Ended(Box<End>),
}

/// One branch from the start to its end, in depth-first order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchView<'a> {
    pub index: usize,
    /// The index of the run of the branch.
    pub run: usize,
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

/// The mode of a query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mode {
    /// A path query: one packet. A field that the query does not state is
    /// not known. The summary has 1 part.
    Path,
    /// A set query: a field with no constraint has all values. The summary
    /// has a part for each different result.
    Set,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub mode: Mode,
    pub input: PacketSet,
    pub runs: Vec<Run>,
    /// The result over all paths, for each part of the input.
    pub summary: Vec<Part>,
    /// The replies, one for each delivered forward branch, in branch order.
    pub replies: Vec<Reply>,
}

impl Answer {
    /// All branches in a fixed depth-first order, run by run.
    pub fn branches(&self) -> Vec<BranchView<'_>> {
        let mut out: Vec<BranchView<'_>> = Vec::new();
        for (r, run) in self.runs.iter().enumerate() {
            for mut b in run.branches(r) {
                b.index = out.len();
                out.push(b);
            }
        }
        out
    }

    /// The verdict, if every part has the same verdict on every path.
    pub fn verdict(&self) -> Option<&Verdict> {
        let first = self.summary.first()?.summary.verdict()?;
        self.summary
            .iter()
            .all(|p| p.summary.verdict() == Some(first))
            .then_some(first)
    }

    /// The summary, if the answer has one part.
    pub fn single_summary(&self) -> Option<&Summary> {
        match self.summary.as_slice() {
            [one] => Some(&one.summary),
            _ => None,
        }
    }

    pub fn reply_of(&self, branch: usize) -> Option<&Answer> {
        self.replies.iter().find_map(|r| match &r.result {
            ReplyResult::Ran(a) if r.forward_branch == branch => Some(a.as_ref()),
            _ => None,
        })
    }
}

fn walk_branches<'a>(nodes: &'a [ExecNode], run: usize, out: &mut Vec<BranchView<'a>>) {
    let mut path: Vec<&TraceStep> = Vec::new();
    // (node, next edge). The path holds the step into each open node
    // after the root.
    let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
    while let Some(top) = stack.last_mut() {
        let (n, e) = *top;
        let Some(edge) = nodes[n].edges.get(e) else {
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
                run,
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

/// Combines the results of the candidates of the selection of `choice`,
/// which is not collected: the common result, or the common kind of
/// result. Candidates with different kinds of result give `Unknown`.
pub fn combine_candidates(choice: &FunctionId, paths: &[Summary]) -> Summary {
    let Some(first) = paths.first() else {
        unreachable!("a selection has at least one candidate")
    };
    if paths.iter().all(|p| p == first) {
        return first.clone();
    }
    match first.kind() {
        Some(k) if paths.iter().all(|p| p.kind() == Some(k)) => Summary::SameKind(k),
        _ => Summary::Same(Verdict::Unknown(Reason::new(
            ReasonCode::SelectionNotCollected,
            format!("the candidates of {choice} end differently"),
        ))),
    }
}

/// Combines the results of the copies of a flood: delivered if a minimum of
/// one copy delivers. If not, an exit if a minimum of one copy leaves the
/// twin. If not, the result depends on the path if a minimum of one copy
/// depends on the path. If not, `Unknown` if a minimum of one copy is
/// `Unknown`. If not, dropped. The first copy of the selected kind, in the
/// fixed order of the copies, gives the result.
pub fn combine_flood(copies: &[Summary]) -> Summary {
    let rank = |s: &Summary| match s.kind() {
        Some(VerdictKind::Deliver) => 0,
        Some(VerdictKind::Exit) => 1,
        None => 2,
        Some(VerdictKind::Unknown) => 3,
        Some(VerdictKind::Drop) => 4,
    };
    let Some(best) = copies.iter().map(rank).min() else {
        unreachable!("a flood has at least one copy")
    };
    let Some(first) = copies.iter().find(|c| rank(c) == best) else {
        unreachable!("the minimum comes from a copy")
    };
    first.clone()
}

/// The summary parts of the nodes of one run, from the end of each path
/// back to the start. Each part holds original requests.
pub fn aggregate(nodes: &[ExecNode]) -> Result<Vec<Part>, String> {
    // A child has a larger index than its parent, so the reverse order
    // handles each node after all of its children.
    let mut parts: Vec<Option<Vec<Part>>> = vec![None; nodes.len()];
    for i in (0..nodes.len()).rev() {
        let p = aggregate_node(&nodes[i], &mut parts)?;
        parts[i] = Some(p);
    }
    parts
        .into_iter()
        .next()
        .flatten()
        .ok_or_else(|| "the run has no node".to_string())
}

/// The parts of one alternative or one copy, combined with the parts of the
/// others by intersection. The parts of each group are disjoint, so a part
/// that is equal to a part of the next group meets no other part of that
/// group.
#[allow(
    clippy::mutable_key_type,
    reason = "the order of a packet set uses its edge and its arena address, which do not change"
)]
fn refine(groups: Vec<Vec<Part>>, combine: &dyn Fn(&[Summary]) -> Summary) -> Vec<Part> {
    let mut acc: Vec<(PacketSet, Vec<Summary>)> = Vec::new();
    for (i, g) in groups.into_iter().enumerate() {
        if i == 0 {
            acc = g
                .into_iter()
                .map(|p| (p.packets, vec![p.summary]))
                .collect();
            continue;
        }
        let index: BTreeMap<&PacketSet, usize> = g
            .iter()
            .enumerate()
            .filter(|(_, p)| !p.packets.is_empty())
            .map(|(j, p)| (&p.packets, j))
            .collect();
        let equal: BTreeSet<usize> = acc
            .iter()
            .filter_map(|(s, _)| index.get(s).copied())
            .collect();
        let mut next = Vec::new();
        for (s, sums) in &acc {
            if let Some(&j) = index.get(s) {
                let mut v = sums.clone();
                v.push(g[j].summary.clone());
                next.push((s.clone(), v));
                continue;
            }
            for (j, p) in g.iter().enumerate() {
                if equal.contains(&j) {
                    continue;
                }
                let inter = s.intersect(&p.packets);
                if !inter.is_empty() {
                    let mut v = sums.clone();
                    v.push(p.summary.clone());
                    next.push((inter, v));
                }
            }
        }
        acc = next;
    }
    acc.into_iter()
        .map(|(packets, sums)| Part {
            packets,
            summary: combine(&sums),
        })
        .collect()
}

/// Joins the parts with the same summary, in the order of the first part
/// of each summary.
pub fn merge(parts: Vec<Part>) -> Vec<Part> {
    let mut out: Vec<Part> = Vec::new();
    let mut at: BTreeMap<Summary, usize> = BTreeMap::new();
    for p in parts {
        match at.get(&p.summary).copied() {
            Some(i) => out[i].packets = out[i].packets.union(&p.packets),
            None => {
                at.insert(p.summary.clone(), out.len());
                out.push(p);
            }
        }
    }
    out
}

/// The parts of each alternative or copy of one decision point, by index.
type Groups = BTreeMap<u32, Vec<Part>>;

/// The parts of one node. It takes the parts of each child from `done`.
fn aggregate_node(node: &ExecNode, done: &mut [Option<Vec<Part>>]) -> Result<Vec<Part>, String> {
    let mut plain = Vec::new();
    let mut choices: BTreeMap<(FunctionId, String), (AlternativeKind, Groups)> = BTreeMap::new();
    let mut floods: BTreeMap<(FunctionId, String), Groups> = BTreeMap::new();
    for e in &node.edges {
        let ps = match (&e.end, e.next) {
            (Some(end), _) => vec![Part {
                packets: e.step.output.project_original(),
                summary: Summary::Same(end.verdict.clone()),
            }],
            (None, Some(n)) => done[n]
                .take()
                .ok_or_else(|| format!("the child of {} has no summary", node.function))?,
            (None, None) => return Err(format!("an edge of {} has no end", node.function)),
        };
        if let Some(a) = &e.step.alternative {
            choices
                .entry((a.choice.clone(), a.key.clone()))
                .or_insert_with(|| (a.kind, BTreeMap::new()))
                .1
                .entry(a.index)
                .or_default()
                .extend(ps);
        } else if let Some(fc) = &e.step.flood_copy {
            floods
                .entry((fc.flood.clone(), fc.key.clone()))
                .or_default()
                .entry(fc.index)
                .or_default()
                .extend(ps);
        } else {
            plain.extend(ps);
        }
    }
    let mut all = plain;
    for ((choice, _), (kind, alts)) in choices {
        let groups = alts.into_values().collect();
        all.extend(match kind {
            AlternativeKind::Choice => refine(groups, &combine_paths),
            AlternativeKind::Candidate => {
                refine(groups, &|s: &[Summary]| combine_candidates(&choice, s))
            }
        });
    }
    for copies in floods.into_values() {
        all.extend(refine(copies.into_values().collect(), &combine_flood));
    }
    Ok(merge(all))
}

/// True if a delivered branch reached an endpoint, with its id.
pub fn delivered_endpoint(v: &Verdict) -> Option<&rsim_core::EndpointId> {
    match v {
        Verdict::Deliver(Destination::Endpoint(e)) => Some(e),
        _ => None,
    }
}
