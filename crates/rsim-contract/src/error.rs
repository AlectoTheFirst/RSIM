//! Query errors and their codes.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The code of a query error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnknownTopology,
    UnknownIngress,
    InvalidQuery,
    NoSuchStep,
    StartRequiresContext,
    ContractViolation,
    /// The store of a `store:` topology cannot be read.
    Store,
    UnknownTable,
    InvalidFilter,
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
            ErrorCode::Internal => "internal",
        }
    }
}

/// A query error: the code and a text for persons.
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
