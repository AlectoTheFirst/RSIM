//! The Model Context Protocol server of rsim: the protocol code and the
//! tools. The binary `rsim-mcp` serves them on stdio, and `rsim-api` serves
//! them through the Streamable HTTP transport.

#![deny(clippy::disallowed_methods, clippy::disallowed_types)]

pub mod server;
pub mod tools;
