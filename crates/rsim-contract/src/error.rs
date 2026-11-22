//! Query errors and their codes.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Error code
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnknownTopology,
    UnknownIngress,
    InvalidQuery,
    NoSuchStep,
    StartRequiresContext,
    ContractViolation,
    /// Store not readable
    Store,
    UnknownTable,
    InvalidFilter,
    /// No source text
    NoSourceText,
    /// Not masked
    NotMasked,
    /// Not a source span
    NotASourceSpan,
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::UnknownTopology => "unknown_topology",
            ErrorCode::UnknownIngress => "unknown_ingress",
            ErrorCode::InvalidQuery => "invalid_query",
            ErrorCode::NoSuchStep => "no_such_step",
            ErrorCode::StartRequiresContext => "start_requires_context",
            ErrorCode::ContractViolation => "contract_violation",
            ErrorCode::Store => "store",
            ErrorCode::UnknownTable => "unknown_table",
            ErrorCode::InvalidFilter => "invalid_filter",
            ErrorCode::NoSourceText => "no_source_text",
            ErrorCode::NotMasked => "not_masked",
            ErrorCode::NotASourceSpan => "not_a_source_span",
            ErrorCode::Internal => "internal",
        }
    }
}

/// Query error
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueryError {
    pub code: ErrorCode,
    pub detail: String,
}

impl QueryError {
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        QueryError {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error {}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for QueryError {}
