//! The contract of rsim: the types of the JSON output and of the query
//! input, the errors, and the registry of the operations. The CLI, the MCP
//! server and the HTTP API take their schemas from this crate. It has no
//! engine dependency, so a client can use it.

pub mod error;
pub mod json;
pub mod query;
