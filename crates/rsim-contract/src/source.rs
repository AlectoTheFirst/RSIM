//! The masked text of the source lines of a source span.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::QueryError;

/// The largest number of lines of one answer. The lines after it are cut.
pub const MAX_LINES: u32 = 200;

/// Source line
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SourceLineJson {
    pub number: u32,
    /// Text
    pub text: String,
}

/// Line range
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LineRangeJson {
    pub first_line: u32,
    pub last_line: u32,
}

/// Source lines
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SourceTextJson {
    pub file: String,
    pub first_line: u32,
    pub last_line: u32,
    pub lines: Vec<SourceLineJson>,
    pub left_out: Vec<LineRangeJson>,
    pub cut: u32,
    pub note: Option<String>,
}

/// Source lines
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SourceLinesOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: crate::twin::TwinJson,
    pub source: SourceTextJson,
}

/// Span source lines
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum StepSourceJson {
    Lines(SourceTextJson),
    Refused {
        file: String,
        first_line: u32,
        last_line: u32,
        error: QueryError,
    },
}
