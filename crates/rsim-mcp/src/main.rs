//! `rsim-mcp`: a Model Context Protocol server on stdio for path queries on
//! the built-in topologies, and with `--store <data folder>` on the newest
//! snapshot of a store as the topology `store`. It writes only protocol
//! messages to stdout and its log to stderr.

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
    let args: Vec<String> = std::env::args().skip(1).collect();
    let tools = match args.as_slice() {
        [] => tools::Tools::default(),
        [flag, folder] if flag == "--store" => tools::Tools::with_store(folder.clone()),
        _ => {
            eprintln!("usage: rsim-mcp [--store <data folder>]");
            return ExitCode::FAILURE;
        }
    };
    let stdin = std::io::stdin().lock();
    let stdout = std::io::stdout().lock();
    match server::Server::new(tools).serve(stdin, stdout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rsim-mcp: stdio error: {e}");
            ExitCode::FAILURE
        }
    }
}
