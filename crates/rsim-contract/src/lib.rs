//! The contract of rsim: the types of the JSON output and of the query
//! input, the errors, and the registry of the operations. The CLI, the MCP
//! server and the HTTP API take their schemas from this crate. It has no
//! engine dependency, so a client can use it.

pub mod args;
pub mod claim;
pub mod diff;
pub mod error;
pub mod json;
pub mod query;
pub mod registry;
pub mod source;
pub mod table;
pub mod topology;
pub mod twin;

/// The JSON Schema of a contract type, in the dialect of JSON Schema
/// 2020-12.
pub fn schema<T: schemars::JsonSchema>() -> serde_json::Value {
    schemars::schema_for!(T).to_value()
}
