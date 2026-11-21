//! `rsim-api`: the REST API of rsim. With no inventory database it has no
//! sign-in and listens only on a loopback address. With the inventory
//! database, each route except the open routes needs a session or an API
//! token, and the server can listen on any address.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use rsim_api::handler::{Settings, State};
use rsim_api::inventory::InventoryHandle;

const USAGE: &str = "usage: rsim-api [--listen <address:port>] [--store <data folder>] [--allow-origin <origin>]... [--public-origin <origin>]... [--trusted-proxy <address[/length]>]... [--max-body <bytes>] [--inventory <postgres URL>] [--inventory-ca-file <PEM file>] [--env <env file>] | rsim-api --openapi";

/// An origin `scheme://host[:port]` of HTTP or HTTPS with no path, in
/// lower case.
fn origin(v: &str) -> Option<String> {
    let v = v.trim_end_matches('/').to_ascii_lowercase();
    let (scheme, host) = v.split_once("://")?;
    let ok = matches!(scheme, "http" | "https")
        && !host.is_empty()
        && !host.contains(['/', '?', '#', '@', ' ']);
    ok.then_some(v)
}

/// Waits for SIGINT or, on Unix, SIGTERM, the stop signal of a container.
async fn stop_signal() {
    #[cfg(unix)]
    if let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        return;
    }
    let _ = tokio::signal::ctrl_c().await;
}

fn main() -> ExitCode {
    let mut listen: SocketAddr = ([127, 0, 0, 1], 8787).into();
    let mut store = None;
    let mut inventory = std::env::var(rsim_inventory::URL_VAR).ok();
    let mut inventory_ca = std::env::var(rsim_inventory::CA_FILE_VAR).ok();
    let mut env_file = None;
    let mut origins = Vec::new();
    let mut public_origins = Vec::new();
    let mut trusted_proxies = Vec::new();
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
            ("--public-origin", Some(v)) => match origin(&v) {
                Some(o) => {
                    public_origins.push(o);
                    true
                }
                None => false,
            },
            ("--trusted-proxy", Some(v)) => match rsim_api::auth::Prefix::parse(&v) {
                Some(p) => {
                    trusted_proxies.push(p);
                    true
                }
                None => false,
            },
            ("--max-body", Some(v)) => v.parse().map(|x| max_body = x).is_ok(),
            ("--inventory", Some(v)) => {
                inventory = Some(v);
                true
            }
            ("--inventory-ca-file", Some(v)) => {
                inventory_ca = Some(v);
                true
            }
            ("--env", Some(v)) => {
                env_file = Some(v);
                true
            }
            _ => false,
        };
        if !ok {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    }
    if public_origins.iter().any(|o| o.starts_with("https://")) && trusted_proxies.is_empty() {
        eprintln!(
            "error: an https public origin needs --trusted-proxy with the address of the proxy that ends TLS; with no trusted proxy the session cookie is not Secure and each client has the address of the proxy"
        );
        return ExitCode::from(2);
    }
    if !listen.ip().is_loopback() && trusted_proxies.is_empty() {
        eprintln!(
            "warning: {listen} is not a loopback address and no --trusted-proxy is set: the session cookie is not Secure, so publish the port only on a loopback address of the host or put a proxy with TLS in front"
        );
    }
    if !listen.ip().is_loopback() && inventory.is_none() {
        eprintln!(
            "error: {listen} is not a loopback address; with no inventory database the API has no sign-in, so it listens only on a loopback address"
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
            public_origins,
            trusted_proxies,
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
            eprintln!("rsim-api serves the inventory at /v1/inventory, with sign-in");
            if db.setup_open().await.map_err(std::io::Error::other)? {
                eprintln!("no user exists: open the UI to make the first admin");
            }
            let mut handle = InventoryHandle::new(Arc::new(db), tokio::runtime::Handle::current());
            let env = match &env_file {
                Some(p) => rsim_inventory::env::parse_env(
                    &std::fs::read_to_string(p)
                        .map_err(|e| std::io::Error::other(format!("{p}: {e}")))?,
                ),
                None => Default::default(),
            };
            match rsim_inventory::SecretKey::from_env(&env).map_err(std::io::Error::other)? {
                Some(key) => {
                    eprintln!("the managed credentials use the secret key {}", key.id());
                    handle = handle.with_secret_key(key);
                }
                None => eprintln!(
                    "no RSIM_SECRET_KEY: a write of the secret of a managed credential is refused"
                ),
            }
            state = state.with_inventory(handle);
        }
        tokio::select! {
            r = rsim_api::server::serve(listener, Arc::new(state)) => r,
            _ = stop_signal() => {
                eprintln!("rsim-api stops");
                Ok(())
            }
        }
    });
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}
