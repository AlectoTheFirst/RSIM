//! Outcomes, verdicts and reasons.

use std::fmt;

use crate::id::{DeviceId, EndpointId, FunctionId, InterfaceId};

/// Where packets were delivered.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Destination {
    Endpoint(EndpointId),
    /// An address of the device itself.
    Device(DeviceId),
}

/// The interface where packets leave the twin: an interface with no link
/// that its device marks as an edge.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExitPoint {
    pub device: DeviceId,
    pub interface: InterfaceId,
}

impl fmt::Display for ExitPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.device, self.interface)
    }
}

/// The outcome of one branch of one function.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// Hand the packets to the named next function.
    Forward(FunctionId),
    /// The packets reached their destination.
    Deliver(Destination),
    /// The packets left the twin on an edge interface.
    Exit(ExitPoint),
    Drop,
    Unknown,
}

impl Outcome {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Outcome::Forward(_))
    }
}

/// The class of a reason. The detail text gives the subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReasonCode {
    // Forward.
    Passed,
    Classified,
    Permitted,
    Translated,
    NotTranslated,
    SessionCreated,
    SessionMatched,
    Routed,
    Resolved,
    LinkHandOff,
    Encapsulated,
    Decapsulated,
    // Deliver.
    Delivered,
    // Exit.
    Exited,
    // Drop.
    Denied,
    NoRoute,
    NullRoute,
    NoNeighbour,
    NotInZone,
    Loop,
    /// The device has no segment for the network identifier of the
    /// tunnel.
    NoSegment,
    // Unknown.
    UnhandledStanza,
    MatchUnknown,
    UnknownAttribute,
    AmbiguousOwner,
    IncompleteTable,
    /// A table that the answer needs was not collected.
    NotCollected,
    /// The candidates of a selection that is not collected end with
    /// different results.
    SelectionNotCollected,
    /// The set of a part of the query was over the node budget, and the
    /// part has one original request.
    SetBudget,
    NoLink,
    /// The packets have an encapsulation already, and a packet has at
    /// most one.
    Nested,
    /// The branch used more steps than the budget of the query. The
    /// executor reports this; it is not a verdict on the packets.
    StepBudget,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reason {
    pub code: ReasonCode,
    pub detail: String,
}

impl Reason {
    pub fn new(code: ReasonCode, detail: impl Into<String>) -> Self {
        Reason {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Debug for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.detail)
    }
}

/// The final outcome of a branch. `Forward` is not a verdict.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    Deliver(Destination),
    /// The packets left the twin on an edge interface. It is a terminal
    /// result like `Deliver` and `Drop`, and it is not `Unknown`.
    Exit(ExitPoint),
    Drop(Reason),
    Unknown(Reason),
}

impl Verdict {
    pub fn kind(&self) -> VerdictKind {
        match self {
            Verdict::Deliver(_) => VerdictKind::Deliver,
            Verdict::Exit(_) => VerdictKind::Exit,
            Verdict::Drop(_) => VerdictKind::Drop,
            Verdict::Unknown(_) => VerdictKind::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerdictKind {
    Deliver,
    Exit,
    Drop,
    Unknown,
}
