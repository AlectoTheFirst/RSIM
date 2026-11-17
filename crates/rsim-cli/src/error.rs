//! Query errors and their codes.

use rsim_engine::ExecError;

pub use rsim_contract::error::{ErrorCode, QueryError};

/// The query error of an execution error.
pub fn from_exec(e: &ExecError) -> QueryError {
    match e {
        ExecError::UnknownIngress(d, i) => QueryError::new(
            ErrorCode::UnknownIngress,
            format!("{d}/{i} is not an interface with an ingress function"),
        ),
        ExecError::PacketSet(e) => QueryError::new(ErrorCode::Internal, e.to_string()),
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
