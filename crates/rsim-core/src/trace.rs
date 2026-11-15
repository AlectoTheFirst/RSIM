//! The trace: the ordered steps of one branch.

use crate::branch::{Alternative, FloodCopy, RateCondition};
use crate::context::Attr;
use crate::delay::Delay;
use crate::field::FieldValue;
use crate::function::FunctionKind;
use crate::id::{DeviceId, FunctionId};
use crate::outcome::{Outcome, Reason};
use crate::packet_set::{PacketSet, Uniform};
use crate::provenance::SourceSpan;

/// The QoS treatment at one step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QosView {
    pub dscp: Uniform<FieldValue<u8>>,
    pub ecn: Uniform<FieldValue<u8>>,
    pub traffic_class: Attr<u8>,
    pub drop_precedence: Attr<u8>,
    pub queue: Attr<u8>,
}

/// The result of the RIB guard for one step: the comparison of the simulated
/// route with the collected route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RibGuardFlag {
    NotApplicable,
    NotChecked,
    MatchesCollected,
    DiffersFromCollected,
}

/// One step: one function applied to one input, and one of its branches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceStep {
    pub function: FunctionId,
    pub kind: FunctionKind,
    pub device: Option<DeviceId>,
    pub input: PacketSet,
    /// The packets of the branch, after any rewrite.
    pub output: PacketSet,
    pub outcome: Outcome,
    pub reason: Reason,
    /// The spans of the function, then the spans of the deciding part.
    pub provenance: Vec<SourceSpan>,
    pub delay: Delay,
    pub alternative: Option<Alternative>,
    pub flood_copy: Option<FloodCopy>,
    /// The QoS treatment of the output.
    pub qos: QosView,
    pub rate_condition: Option<RateCondition>,
    pub rib_guard: RibGuardFlag,
}
