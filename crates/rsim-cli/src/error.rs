//! Query errors and their codes.

use rsim_engine::ExecError;
use serde::Serialize;

/// The code of a query error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnknownTopology,
    UnknownEndpoint,
    InvalidQuery,
    NoSuchStep,
    StartRequiresContext,
    ContractViolation,
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::UnknownTopology => "unknown_topology",
            ErrorCode::UnknownEndpoint => "unknown_endpoint",
            ErrorCode::InvalidQuery => "invalid_query",
            ErrorCode::NoSuchStep => "no_such_step",
            ErrorCode::StartRequiresContext => "start_requires_context",
            ErrorCode::ContractViolation => "contract_violation",
            ErrorCode::Internal => "internal",
        }
    }
}

/// A query error: the code and a text for persons.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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

    pub fn from_exec(e: &ExecError) -> Self {
        match e {
            ExecError::UnknownEndpoint(id) => QueryError::new(
                ErrorCode::UnknownEndpoint,
                format!("endpoint {id} is not in the twin"),
            ),
            ExecError::StartRequiresContext(f, attrs) => QueryError::new(
                ErrorCode::StartRequiresContext,
                format!("start function {f} requires context {attrs:?}"),
            ),
            ExecError::ContractViolation { function, detail } => QueryError::new(
                ErrorCode::ContractViolation,
                format!("{function}: {detail}"),
            ),
            ExecError::UnknownFunction(f) => QueryError::new(
                ErrorCode::Internal,
                format!("function {f} is not in the twin"),
            ),
            ExecError::Aggregation(d) => QueryError::new(ErrorCode::Internal, d.clone()),
        }
    }
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error {}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for QueryError {}
