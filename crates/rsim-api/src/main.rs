//! `rsim-api`: the REST API of rsim on a loopback address.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use rsim_api::handler::{Settings, State};

const USAGE: &str = "usage: rsim-api [--listen <loopback address:port>] [--store <data folder>] [--allow-origin <origin>]... [--max-body <bytes>] | rsim-api --openapi";

fn main() -> ExitCode {
    let mut listen: SocketAddr = ([127, 0, 0, 1], 8787).into();
    let mut store = None;
    let mut origins = Vec::new();
    let mut max_body = 1 << 20;
    if std::env::args().nth(1).as_deref() == Some("--openapi") {
        let doc = rsim_api::openapi::document();
        match serde_json::to_string_pretty(&doc) {
            Ok(t) => println!("{t}"),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(1);
            }
        }
        return ExitCode::SUCCESS;
    }
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let v = args.next();
        let ok = match (a.as_str(), v) {
            ("--listen", Some(v)) => v.parse().map(|x| listen = x).is_ok(),
            ("--store", Some(v)) => {
                store = Some(v);
                true
            }
            ("--allow-origin", Some(v)) => {
                origins.push(v);
                true
            }
            ("--max-body", Some(v)) => v.parse().map(|x| max_body = x).is_ok(),
            _ => false,
        };
        if !ok {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    }
    if !listen.ip().is_loopback() {
        eprintln!(
            "error: {listen} is not a loopback address; the API has no authentication yet, so it listens only on a loopback address"
        );
        return ExitCode::from(2);
    }
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    let r = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(listen).await?;
        let listen = listener.local_addr()?;
        eprintln!("rsim-api listens on http://{listen}");
        let state = Arc::new(State::new(Settings {
            listen,
            store,
            allow_origins: origins,
            max_body,
        }));
        rsim_api::server::serve(listener, state).await
    });
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}
