//! The library of `rsim` and `rsim-mcp`: the query input, the JSON output of
//! version 2, the text output and the commands.

#![deny(clippy::disallowed_methods, clippy::disallowed_types)]

pub mod args;
pub mod commands;
pub mod error;
pub mod json;
pub mod query;
pub mod text;

pub use commands::StepRef;
pub use error::{ErrorCode, QueryError};
pub use query::{IcmpType, Protocol, QueryInput, TcpFlag};
pub use rsim_engine::Twin;
