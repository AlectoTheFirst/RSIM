//! The difference of a query answer and of a claim between 2 twins.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::claim::{ClaimResult, Evidence};
use crate::json::{DelayJson, PacketSetJson, PartJson, TraceStepJson, VerdictJson};
use crate::table::{DiffCounts, RowChange};
use crate::twin::TwinJson;

/// Changed evidence row
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceChange {
    pub change: RowChange,
    /// The row of the twin, or the row of `against` for a removed row.
    pub row: Evidence,
    /// The row of `against` for a changed row.
    pub before: Option<Evidence>,
}

/// Claim difference
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ClaimDiffOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: TwinJson,
    /// Compared twin
    pub against: TwinJson,
    pub claim: String,
    /// Scope
    pub scope: String,
    pub result: ClaimResult,
    /// Result of the compared twin
    pub before: ClaimResult,
    pub counts: DiffCounts,
    pub rows: Vec<EvidenceChange>,
}

/// Branch of one twin
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BranchSide {
    /// Branch index
    pub index: usize,
    pub verdict: VerdictJson,
    pub packets: PacketSetJson,
    pub delay: DelayJson,
    /// The step at `first_step`, if the branch has it.
    pub step: Option<TraceStepJson>,
}

/// Reply change
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ReplyChange {
    /// Reply ran
    pub ran: bool,
    /// Reply ran on the compared twin
    pub before_ran: bool,
    /// The difference of the 2 reply answers, if both replies have an answer.
    pub diff: Option<Box<AnswerDiff>>,
}

/// Changed branch
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BranchChange {
    pub change: RowChange,
    /// The branch of the twin, or the branch of `against` for a removed branch.
    pub branch: BranchSide,
    /// The branch of `against` for a changed branch.
    pub before: Option<BranchSide>,
    /// The index of the first step that differs, for a changed branch.
    pub first_step: Option<usize>,
    /// The change of the reply, for a changed branch.
    pub reply: Option<ReplyChange>,
}

/// Answer difference
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AnswerDiff {
    /// The summary parts of the twin that `against` does not have.
    pub added_parts: Vec<PartJson>,
    /// The summary parts of `against` that the twin does not have.
    pub removed_parts: Vec<PartJson>,
    pub counts: DiffCounts,
    pub branches: Vec<BranchChange>,
}

/// Query difference
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct QueryDiffOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: TwinJson,
    /// Compared twin
    pub against: TwinJson,
    /// Query identifier
    pub qid: String,
    pub diff: AnswerDiff,
}
