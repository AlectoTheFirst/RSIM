//! The masked text of the source lines of a source span.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::QueryError;

/// The largest number of lines of one answer. The lines after it are cut.
pub const MAX_LINES: u32 = 200;

/// One source line with its number in the canonical form of its section.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SourceLineJson {
    pub number: u32,
    /// The text of the line with each secret masked as `<secret>`.
    pub text: String,
}

/// An inclusive range of line numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LineRangeJson {
    pub first_line: u32,
    pub last_line: u32,
}

/// The masked lines of one source span: the lines from `first_line` to
/// `last_line` that lie inside a source span of a function of the twin, at
/// most `MAX_LINES` lines from `first_line`. `left_out` lists the ranges of
/// the request that are outside every such span or past the end of the
/// section, so `lines` can be empty; `cut` is the number of
/// lines after the limit that the answer leaves out. A note names both.
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

/// The masked lines of one source span of a twin.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SourceLinesOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: crate::twin::TwinJson,
    pub source: SourceTextJson,
}

/// The source lines of one span of a trace step: the masked lines, or the
/// error that refuses them.
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
