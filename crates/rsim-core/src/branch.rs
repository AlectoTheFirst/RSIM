//! The branch: one part of the output of a function.

use crate::context::Context;
use crate::delay::Delay;
use crate::flow_state::FlowState;
use crate::id::{FunctionId, PortId};
use crate::outcome::{Outcome, Reason};
use crate::packet_set::PacketSet;
use crate::provenance::SourceSpan;
use crate::trace::RibGuardFlag;

/// How a device uses the alternatives of one decision point.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlternativeKind {
    /// The device sends packets to each alternative, as on equal-cost
    /// paths.
    #[default]
    Choice,
    /// The device sends packets to one or more of the alternatives, and
    /// the selection is not collected.
    Candidate,
}

/// The alternative of a forwarding choice to which a branch belongs.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Alternative {
    pub kind: AlternativeKind,
    /// The function that made the choice.
    pub choice: FunctionId,
    /// The decision point in the function, for example the route prefix.
    /// The function and the key together identify one forwarding choice.
    pub key: String,
    /// The position in the fixed order of the alternatives.
    pub index: u32,
    pub count: u32,
    pub label: String,
}

/// The copy of a flood to which a branch belongs: a layer 2 flood or the
/// copies of a multicast route.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FloodCopy {
    /// The function that made the copies.
    pub flood: FunctionId,
    /// The replication point in the function, for example the multicast
    /// route. The function and the key together identify one flood.
    pub key: String,
    pub port: PortId,
    pub index: u32,
    pub count: u32,
}

/// A condition that depends on the traffic rate. Headers cannot decide it.
/// The branch keeps its outcome and carries the condition.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RateCondition {
    pub function: FunctionId,
    pub rate_bps: Option<u64>,
    pub exceed_action: String,
    pub evaluated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Branch {
    pub packets: PacketSet,
    pub outcome: Outcome,
    pub reason: Reason,
    pub ctx: Context,
    pub state: FlowState,
    pub delay: Delay,
    pub alternative: Option<Alternative>,
    pub flood_copy: Option<FloodCopy>,
    pub rate_condition: Option<RateCondition>,
    /// A statement that the collected data does not prove and on which the
    /// result of the branch depends.
    pub assumption: Option<String>,
    /// The RIB guard result of the routes that decided a route lookup
    /// branch. `None` for each other branch.
    pub rib_guard: Option<RibGuardFlag>,
    /// The source spans of the part of the function that decided this
    /// branch, for example one rule. Empty if the whole function decided it.
    pub spans: Vec<SourceSpan>,
}

impl Branch {
    /// A branch with no alternative, flood copy, rate condition, assumption
    /// or spans.
    pub fn new(
        packets: PacketSet,
        outcome: Outcome,
        reason: Reason,
        ctx: Context,
        state: FlowState,
        delay: Delay,
    ) -> Self {
        Branch {
            packets,
            outcome,
            reason,
            ctx,
            state,
            delay,
            alternative: None,
            flood_copy: None,
            rate_condition: None,
            assumption: None,
            rib_guard: None,
            spans: Vec::new(),
        }
    }

    pub fn with_spans(mut self, spans: Vec<SourceSpan>) -> Self {
        self.spans = spans;
        self
    }

    pub fn with_alternative(mut self, a: Alternative) -> Self {
        self.alternative = Some(a);
        self
    }

    pub fn with_rib_guard(mut self, f: RibGuardFlag) -> Self {
        self.rib_guard = Some(f);
        self
    }

    pub fn with_assumption(mut self, a: impl Into<String>) -> Self {
        self.assumption = Some(a.into());
        self
    }
}
