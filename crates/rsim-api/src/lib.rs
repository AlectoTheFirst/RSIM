//! The REST API of rsim: the request handler, the problem details, the
//! query identifiers, the OpenAPI document, the server and the files of
//! the browser UI.

#![deny(clippy::disallowed_methods, clippy::disallowed_types)]

pub mod handler;
pub mod openapi;
pub mod problem;
pub mod qid;
pub mod server;
pub mod ui;
