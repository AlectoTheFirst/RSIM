//! `rsim-mcp`: a Model Context Protocol server on stdio for path queries on
//! the built-in topologies. It writes only protocol messages to stdout and
//! its log to stderr.

#![deny(clippy::disallowed_methods, clippy::disallowed_types)]

mod server;
mod tools;

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "rsim-mcp {}: MCP revisions {} and {} on stdio",
        env!("CARGO_PKG_VERSION"),
        server::MODERN,
        server::LEGACY
    );
    let stdin = std::io::stdin().lock();
    let stdout = std::io::stdout().lock();
    match server::Server::default().serve(stdin, stdout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rsim-mcp: stdio error: {e}");
            ExitCode::FAILURE
        }
    }
}
