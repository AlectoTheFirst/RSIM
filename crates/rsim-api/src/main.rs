//! `rsim-api`: the REST API of rsim on a loopback address.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use rsim_api::handler::{Settings, State};
use rsim_api::inventory::InventoryHandle;

const USAGE: &str = "usage: rsim-api [--listen <loopback address:port>] [--store <data folder>] [--allow-origin <origin>]... [--max-body <bytes>] [--inventory <postgres URL>] [--inventory-ca-file <PEM file>] | rsim-api --openapi";

fn main() -> ExitCode {
    let mut listen: SocketAddr = ([127, 0, 0, 1], 8787).into();
    let mut store = None;
    let mut inventory = std::env::var(rsim_inventory::URL_VAR).ok();
    let mut inventory_ca = std::env::var(rsim_inventory::CA_FILE_VAR).ok();
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
            ("--inventory", Some(v)) => {
                inventory = Some(v);
                true
            }
            ("--inventory-ca-file", Some(v)) => {
                inventory_ca = Some(v);
                true
            }
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
        .enable_all()
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
        let mut state = State::new(Settings {
            listen,
            store,
            allow_origins: origins,
            max_body,
        });
        if let Some(url) = &inventory {
            let ca = inventory_ca
                .as_deref()
                .map(|p| {
                    std::fs::read_to_string(p)
                        .map_err(|e| std::io::Error::other(format!("{p}: {e}")))
                })
                .transpose()?;
            let db = rsim_inventory::Db::new(url, ca.as_deref()).map_err(std::io::Error::other)?;
            for v in db.migrate().await.map_err(std::io::Error::other)? {
                eprintln!("applied inventory migration {v}");
            }
            eprintln!("rsim-api serves the inventory at /v1/inventory");
            state = state.with_inventory(InventoryHandle::new(
                Arc::new(db),
                tokio::runtime::Handle::current(),
            ));
        }
        rsim_api::server::serve(listener, Arc::new(state)).await
    });
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}
