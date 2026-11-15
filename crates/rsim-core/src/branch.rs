//! The branch: one part of the output of a function (section 5, item 1).

use crate::context::Context;
use crate::delay::Delay;
use crate::flow_state::FlowState;
use crate::id::{FunctionId, PortId};
use crate::outcome::{Outcome, Reason};
use crate::packet_set::PacketSet;
use crate::provenance::SourceSpan;

/// The alternative of a forwarding choice to which a branch belongs.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Alternative {
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

/// The copy of a layer 2 flood to which a branch belongs (section 18).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FloodCopy {
    pub flood: FunctionId,
    pub port: PortId,
    pub index: u32,
    pub count: u32,
}

/// A condition that depends on the traffic rate (section 16). Headers cannot
/// decide it. Its effect on the outcome is an open decision (section 15,
/// item 9), so step 1 only carries it.
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
    /// The source spans of the part of the function that decided this
    /// branch, for example one rule. Empty if the whole function decided it.
    pub spans: Vec<SourceSpan>,
}

impl Branch {
    /// A branch with no alternative, flood copy, rate condition or spans.
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
}
