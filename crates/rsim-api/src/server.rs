//! The HTTP/1.1 server: it reads each request, runs the handler on a
//! worker thread, and writes the response.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::handler::{self, Request, Response, State};
use crate::problem::problem;

/// The number of queries that run at the same time. Above it, a request
/// gets 503 with `Retry-After`.
pub const MAX_PARALLEL: usize = 16;

/// The number of open connections. Above it, the server accepts a new
/// connection only after another connection closes.
pub const MAX_CONNECTIONS: usize = 512;

/// The number of `/readyz` probes that run at the same time. Above it, a
/// probe gets 503.
pub const MAX_PROBES: usize = 2;

/// The longest wait for the head of a request. It also closes an idle
/// connection.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The time to read the body of a request. Above it, the request gets 408.
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The wait before the next accept after an accept error that is not an
/// error of one connection, such as the limit of open files.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The semaphores of the server.
struct Limits {
    queries: Arc<Semaphore>,
    probes: Arc<Semaphore>,
}

fn to_hyper(r: Response) -> hyper::Response<Full<Bytes>> {
    let mut b = hyper::Response::builder().status(r.status);
    for (k, v) in &r.headers {
        b = b.header(k, v);
    }
    b.body(Full::new(Bytes::from(r.body)))
        .unwrap_or_else(|_| hyper::Response::new(Full::new(Bytes::new())))
}

/// True for the resource of a query, `/v1/twins/{twin}/queries/{qid}`,
/// which runs the query or answers 304 from the cache of the client.
fn is_query_answer(req: &Request) -> bool {
    req.method == "GET"
        && matches!(
            req.path
                .trim_start_matches('/')
                .split('/')
                .collect::<Vec<_>>()[..],
            ["v1", "twins", _, "queries", _]
        )
}

/// Adds the `Server-Timing` header to the response of a query resource:
/// `engine;dur=<ms>` with the time of the handler for an answer, or
/// `cache;desc=hit` for 304. The body does not change.
pub fn add_server_timing(req: &Request, res: &mut Response, elapsed: Duration) {
    if !is_query_answer(req) {
        return;
    }
    let value = match res.status {
        200 => format!("engine;dur={:.1}", elapsed.as_secs_f64() * 1000.0),
        304 => "cache;desc=hit".to_string(),
        _ => return,
    };
    res.headers.push(("server-timing".into(), value));
}

fn query_pairs(q: Option<&str>) -> Vec<(String, String)> {
    let hex = |c: u8| char::from(c).to_digit(16).map(|d| d as u8);
    let decode = |s: &str| -> String {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%'
                && i + 2 < b.len()
                && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
            {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
            out.push(if b[i] == b'+' { b' ' } else { b[i] });
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    q.unwrap_or_default()
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect()
}

async fn serve_one(
    state: Arc<State>,
    limits: Arc<Limits>,
    peer: std::net::IpAddr,
    req: hyper::Request<Incoming>,
) -> Result<hyper::Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let max = state.settings.max_body;
    let collect = Limited::new(body, max).collect();
    let body = match tokio::time::timeout(BODY_READ_TIMEOUT, collect).await {
        Ok(Ok(b)) => b.to_bytes().to_vec(),
        Err(_) => {
            let secs = BODY_READ_TIMEOUT.as_secs();
            return Ok(to_hyper(
                problem(
                    408,
                    "request_timeout",
                    format!("the body did not arrive in {secs} s"),
                )
                .response(),
            ));
        }
        Ok(Err(_)) => {
            return Ok(to_hyper(
                problem(
                    413,
                    "too_large",
                    format!("the body is larger than {max} bytes"),
                )
                .response(),
            ));
        }
    };
    if parts.method == hyper::Method::GET && matches!(parts.uri.path(), "/healthz" | "/readyz") {
        let request = Request {
            method: "GET".into(),
            path: parts.uri.path().to_string(),
            peer: Some(peer),
            ..Request::default()
        };
        // `/healthz` reads no database and runs on the connection task.
        if request.path == "/healthz" {
            let mut r =
                crate::auth::probe(&state, &request, false).unwrap_or_else(|p| p.response());
            r.headers
                .push(("x-content-type-options".into(), "nosniff".into()));
            return Ok(to_hyper(r));
        }
        let Ok(permit) = Arc::clone(&limits.probes).try_acquire_owned() else {
            return Ok(to_hyper(
                problem(503, "too_many_probes", "too many probes run now".into()).response(),
            ));
        };
        let r = tokio::task::spawn_blocking(move || {
            let r = handler::handle(&state, &request);
            drop(permit);
            r
        })
        .await
        .unwrap_or_else(|_| problem(500, "internal", "the handler failed".into()).response());
        return Ok(to_hyper(r));
    }
    let Ok(permit) = Arc::clone(&limits.queries).try_acquire_owned() else {
        return Ok(to_hyper(
            problem(503, "too_many_queries", "too many queries run now".into()).response(),
        ));
    };
    let headers: BTreeMap<String, String> = parts
        .headers
        .iter()
        .filter_map(|(k, v)| {
            Some((
                k.as_str().to_ascii_lowercase(),
                v.to_str().ok()?.to_string(),
            ))
        })
        .collect();
    let request = Request {
        method: parts.method.as_str().to_string(),
        path: parts.uri.path().to_string(),
        query: query_pairs(parts.uri.query()),
        headers,
        body,
        peer: Some(peer),
    };
    let r = tokio::task::spawn_blocking(move || {
        let start = Instant::now();
        let mut r = handler::handle(&state, &request);
        add_server_timing(&request, &mut r, start.elapsed());
        drop(permit);
        r
    })
    .await
    .unwrap_or_else(|_| problem(500, "internal", "the handler failed".into()).response());
    Ok(to_hyper(r))
}

/// True for an accept error of one connection. The next accept follows at
/// once.
fn connection_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset | ErrorKind::Interrupted
    )
}

/// Serves the connections of a listener until the process ends. An accept
/// error is logged, and the server goes on. The runtime needs the time
/// driver.
pub async fn serve(listener: TcpListener, state: Arc<State>) -> std::io::Result<()> {
    let limits = Arc::new(Limits {
        queries: Arc::new(Semaphore::new(MAX_PARALLEL)),
        probes: Arc::new(Semaphore::new(MAX_PROBES)),
    });
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let conn = Arc::clone(&connections)
            .acquire_owned()
            .await
            .expect("the connection semaphore is never closed");
        let (stream, addr) = match listener.accept().await {
            Ok(a) => a,
            Err(e) => {
                eprintln!("rsim-api: accept failed: {e}");
                if !connection_error(&e) {
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
                continue;
            }
        };
        let peer = addr.ip();
        let io = TokioIo::new(stream);
        let state = Arc::clone(&state);
        let limits = Arc::clone(&limits);
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                serve_one(Arc::clone(&state), Arc::clone(&limits), peer, req)
            });
            let _ = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .serve_connection(io, svc)
                .await;
            drop(conn);
        });
    }
}
