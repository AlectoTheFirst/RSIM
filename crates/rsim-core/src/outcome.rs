//! Outcomes, verdicts and reasons.

use std::fmt;

use crate::id::{DeviceId, EndpointId, FunctionId};

/// Where packets were delivered.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Destination {
    Endpoint(EndpointId),
    /// An address of the device itself.
    Device(DeviceId),
}

/// The outcome of one branch of one function.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// Hand the packets to the named next function.
    Forward(FunctionId),
    /// The packets reached their destination.
    Deliver(Destination),
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
    // Deliver.
    Delivered,
    // Drop.
    Denied,
    NoRoute,
    NullRoute,
    NoNeighbour,
    NotInZone,
    Loop,
    // Unknown.
    UnhandledStanza,
    MatchUnknown,
    UnknownAttribute,
    AmbiguousOwner,
    IncompleteTable,
    /// The set of a part of the query was over the node budget, and the
    /// part has one original request.
    SetBudget,
    NoLink,
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
    Drop(Reason),
    Unknown(Reason),
}

impl Verdict {
    pub fn kind(&self) -> VerdictKind {
        match self {
            Verdict::Deliver(_) => VerdictKind::Deliver,
            Verdict::Drop(_) => VerdictKind::Drop,
            Verdict::Unknown(_) => VerdictKind::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerdictKind {
    Deliver,
    Drop,
    Unknown,
}
