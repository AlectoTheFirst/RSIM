//! The HTTP/1.1 server: it reads each request, runs the handler on a
//! worker thread, and writes the response.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::handler::{self, Request, Response, State};
use crate::problem::problem;

/// The number of queries that run at the same time. Above it, a request
/// gets 503 with `Retry-After`.
pub const MAX_PARALLEL: usize = 16;

fn to_hyper(r: Response) -> hyper::Response<Full<Bytes>> {
    let mut b = hyper::Response::builder().status(r.status);
    for (k, v) in &r.headers {
        b = b.header(k, v);
    }
    b.body(Full::new(Bytes::from(r.body)))
        .unwrap_or_else(|_| hyper::Response::new(Full::new(Bytes::new())))
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
    limit: Arc<Semaphore>,
    req: hyper::Request<Incoming>,
) -> Result<hyper::Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let max = state.settings.max_body;
    let body = match Limited::new(body, max).collect().await {
        Ok(b) => b.to_bytes().to_vec(),
        Err(_) => {
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
    let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
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
    };
    let r = tokio::task::spawn_blocking(move || {
        let r = handler::handle(&state, &request);
        drop(permit);
        r
    })
    .await
    .unwrap_or_else(|_| problem(500, "internal", "the handler failed".into()).response());
    Ok(to_hyper(r))
}

/// Serves the connections of a listener until the process ends.
pub async fn serve(listener: TcpListener, state: Arc<State>) -> std::io::Result<()> {
    let limit = Arc::new(Semaphore::new(MAX_PARALLEL));
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = Arc::clone(&state);
        let limit = Arc::clone(&limit);
        tokio::spawn(async move {
            let svc = service_fn(move |req| serve_one(Arc::clone(&state), Arc::clone(&limit), req));
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}
