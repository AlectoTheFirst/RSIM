//! The request handler: one request in, one response out, with no socket.
//! The server in `server.rs` reads the request from a connection and
//! writes the response.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rsim_cli::commands::{self, Loaded};
use rsim_cli::{ErrorCode, QueryError, args, claims, tables};
use rsim_contract::args::Form;
use rsim_contract::claim::ClaimArgs;
use rsim_contract::json::{PathBriefOut, SetBriefOut, VERSION, to_text};
use rsim_contract::table::Selection;
use rsim_contract::twin::TwinJson;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::problem::{Problem, problem};
use crate::qid;

/// The version of the contract in an ETag: the crate version and the JSON
/// version.
pub fn contract_version() -> String {
    format!("{}-json{VERSION}", env!("CARGO_PKG_VERSION"))
}

/// One request: the method, the path, the query parameters in their
/// order, the headers with lower-case names, and the body.
#[derive(Clone, Debug, Default)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// One response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The settings of a server.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The listen address, for the check of the `Host` header.
    pub listen: std::net::SocketAddr,
    /// The data folder of the store of the twin `store`, if any.
    pub store: Option<String>,
    /// The origins that a browser can call from.
    pub allow_origins: Vec<String>,
    /// The largest request body in bytes.
    pub max_body: usize,
}

/// The state of a server: the settings, the twins that a request named,
/// and the query texts above the inline limit. It keeps no answer.
pub struct State {
    pub settings: Settings,
    twins: Mutex<BTreeMap<String, Arc<Loaded>>>,
    long_queries: Mutex<BTreeMap<String, String>>,
}

impl State {
    pub fn new(settings: Settings) -> Self {
        State {
            settings,
            twins: Mutex::new(BTreeMap::new()),
            long_queries: Mutex::new(BTreeMap::new()),
        }
    }
}

/// A twin of a request: the topology name of the outputs and the loaded
/// twin.
struct TwinRef {
    topology: String,
    loaded: Arc<Loaded>,
}

enum Resolved {
    Twin(TwinRef),
    /// The alias `store`: the identifier of its snapshot.
    Redirect(String),
}

fn json_response<T: Serialize>(v: &T) -> Response {
    Response {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: to_text(v, false).into_bytes(),
    }
}

fn from_query_error(e: QueryError) -> Problem {
    let status = match e.code {
        ErrorCode::UnknownTopology | ErrorCode::NoSuchStep | ErrorCode::UnknownTable => 404,
        ErrorCode::InvalidQuery
        | ErrorCode::InvalidFilter
        | ErrorCode::UnknownIngress
        | ErrorCode::StartRequiresContext => 422,
        ErrorCode::Store | ErrorCode::ContractViolation | ErrorCode::Internal => 500,
    };
    problem(status, e.code.as_str(), e.detail)
}

impl State {
    fn load(&self, key: &str, source: &str) -> Result<Arc<Loaded>, Problem> {
        let mut twins = self.twins.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(t) = twins.get(key) {
            return Ok(Arc::clone(t));
        }
        let t = Arc::new(commands::load(source).map_err(from_query_error)?);
        twins.insert(key.to_string(), Arc::clone(&t));
        Ok(t)
    }

    /// The twin of a path segment: `builtin.<topology>`, `snap-<cycle>` or
    /// the alias `store`.
    fn twin(&self, segment: &str) -> Result<Resolved, Problem> {
        let unknown = |d: String| problem(404, "unknown_twin", d);
        let store = |s: &Self| -> Result<Arc<Loaded>, Problem> {
            match &s.settings.store {
                Some(folder) => s.load("store", &format!("{}{folder}", commands::STORE_PREFIX)),
                None => Err(unknown("the server has no store".into())),
            }
        };
        if segment == "store" {
            let t = store(self)?;
            return Ok(Resolved::Redirect(t.identity.id.clone()));
        }
        let id = TwinJson::parse(segment).map_err(unknown)?;
        match id.snapshot {
            None => {
                let name = id.id.trim_start_matches("builtin.").to_string();
                if !commands::topology_names().contains(&name.as_str()) {
                    return Err(unknown(format!("{segment} is not a built-in topology")));
                }
                let loaded = self.load(&id.id, &name)?;
                Ok(Resolved::Twin(TwinRef {
                    topology: name,
                    loaded,
                }))
            }
            Some(_) => {
                let t = store(self)?;
                if t.identity.id != id.id {
                    return Err(unknown(format!(
                        "{segment} is not held by the server; the newest snapshot is {}",
                        t.identity.id
                    )));
                }
                Ok(Resolved::Twin(TwinRef {
                    topology: "store".into(),
                    loaded: t,
                }))
            }
        }
    }

    fn remember(&self, text: &str) -> String {
        let id = qid::of(text);
        if id.starts_with('h') {
            let mut m = self.long_queries.lock().unwrap_or_else(|p| p.into_inner());
            m.insert(id.clone(), text.to_string());
        }
        id
    }

    fn recall(&self, id: &str) -> Result<Map<String, Value>, Problem> {
        let bad = || {
            problem(
                404,
                "no_such_query",
                format!("{id} is not a query identifier"),
            )
        };
        let text = match id.split_at_checked(1) {
            Some(("q", b64)) => {
                String::from_utf8(qid::decode(b64).ok_or_else(bad)?).map_err(|_| bad())?
            }
            Some(("h", _)) => self
                .long_queries
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(id)
                .cloned()
                .ok_or_else(bad)?,
            _ => return Err(bad()),
        };
        match serde_json::from_str(&text) {
            Ok(Value::Object(m)) => Ok(m),
            _ => Err(bad()),
        }
    }
}

/// The parameters of a request as a map; a name that is given twice keeps
/// its last value.
fn params(req: &Request) -> BTreeMap<&str, &str> {
    req.query
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

/// The selection of a table request from its parameters.
fn selection(req: &Request) -> Result<Selection, Problem> {
    let mut sel = Selection::default();
    let list = |v: &str| v.split(',').map(str::to_string).collect::<Vec<_>>();
    for (k, v) in &req.query {
        match k.as_str() {
            "columns" => sel.columns = Some(list(v)),
            "sort" => sel.sort = Some(list(v)),
            "limit" => {
                sel.limit = Some(v.parse().map_err(|_| {
                    problem(422, "invalid_filter", format!("limit {v} is not a number"))
                })?);
            }
            "cursor" => sel.cursor = Some(v.clone()),
            "column" | "count" | "ascending" | "address" | "form" | "reply_of" | "device" => {}
            k if k.contains('.') => {
                sel.typed.insert(k.to_string(), v.clone());
            }
            k => {
                sel.filters.insert(k.to_string(), list(v));
            }
        }
    }
    Ok(sel)
}

fn form(req: &Request) -> Result<Form, Problem> {
    match params(req).get("form").copied() {
        None | Some("summary") => Ok(Form::Summary),
        Some("steps") => Ok(Form::Steps),
        Some("full") => Ok(Form::Full),
        Some(f) => Err(problem(
            422,
            "invalid_query",
            format!("form {f} is not summary, steps or full"),
        )),
    }
}

/// The arguments of a stored query with the topology of the twin, and its
/// mode.
fn query_args(mut m: Map<String, Value>, topology: &str) -> (Map<String, Value>, bool) {
    let set = m
        .remove("mode")
        .and_then(|v| v.as_str().map(|s| s == "set"))
        == Some(true);
    m.insert("topology".into(), json!(topology));
    (m, set)
}

/// Handles one request.
pub fn handle(state: &State, req: &Request) -> Response {
    // The checks against DNS rebinding and other origins come first.
    if let Some(p) = check_host(state, req) {
        return p.response();
    }
    let origin = req.headers.get("origin").cloned();
    if let Some(o) = &origin
        && !state.settings.allow_origins.contains(o)
    {
        return problem(
            403,
            "forbidden_origin",
            format!("the origin {o} is not allowed"),
        )
        .response();
    }
    if req.body.len() > state.settings.max_body {
        return problem(
            413,
            "too_large",
            format!("the body is larger than {} bytes", state.settings.max_body),
        )
        .response();
    }
    let mut res = if req.method == "OPTIONS" {
        Response {
            status: 204,
            headers: vec![
                (
                    "access-control-allow-methods".into(),
                    "GET, POST, OPTIONS".into(),
                ),
                (
                    "access-control-allow-headers".into(),
                    "content-type, if-none-match".into(),
                ),
            ],
            body: Vec::new(),
        }
    } else {
        match route(state, req) {
            Ok(r) => r,
            Err(p) => p.response(),
        }
    };
    if let Some(o) = origin {
        res.headers.push(("access-control-allow-origin".into(), o));
        res.headers.push(("vary".into(), "Origin".into()));
    }
    res.headers
        .push(("x-content-type-options".into(), "nosniff".into()));
    res
}

fn check_host(state: &State, req: &Request) -> Option<Problem> {
    let host = req.headers.get("host")?;
    let port = state.settings.listen.port();
    let allowed = [
        format!("{}:{port}", state.settings.listen.ip()),
        format!("localhost:{port}"),
        format!("127.0.0.1:{port}"),
        format!("[::1]:{port}"),
    ];
    (!allowed.iter().any(|a| a.eq_ignore_ascii_case(host))).then(|| {
        problem(
            403,
            "forbidden_host",
            format!("the host {host} is not the address of the server"),
        )
    })
}

/// An answer with its ETag, or 304 if the client has it.
fn cached(req: &Request, etag: String, mut res: Response) -> Response {
    let tag = format!("\"{etag}\"");
    if req.headers.get("if-none-match").map(String::as_str) == Some(tag.as_str()) {
        return Response {
            status: 304,
            headers: vec![("etag".into(), tag)],
            body: Vec::new(),
        };
    }
    res.headers.push(("etag".into(), tag));
    res.headers
        .push(("cache-control".into(), "private, no-cache".into()));
    res
}

fn method(req: &Request, allowed: &str) -> Result<(), Problem> {
    if req.method == allowed {
        Ok(())
    } else {
        Err(problem(
            405,
            "method_not_allowed",
            format!("{} is not allowed; use {allowed}", req.method),
        ))
    }
}

fn route(state: &State, req: &Request) -> Result<Response, Problem> {
    let parts: Vec<&str> = req.path.trim_end_matches('/').split('/').skip(1).collect();
    let contract = contract_version();
    let not_found = || problem(404, "not_found", format!("{} is not a resource", req.path));
    match parts.as_slice() {
        ["v1"] => {
            method(req, "GET")?;
            let body = json!({
                "rsim_json": VERSION,
                "kind": "entry",
                "contract": contract,
                "links": {
                    "openapi": "/v1/openapi.json",
                    "tables": "/v1/tables",
                    "claims": "/v1/claims",
                    "twins": "/v1/twins"
                },
                "limits": {"max_body": state.settings.max_body}
            });
            Ok(cached(req, contract, json_response(&body)))
        }
        ["v1", "openapi.json"] => {
            method(req, "GET")?;
            let doc = crate::openapi::document();
            Ok(cached(req, contract, json_response(&doc)))
        }
        ["v1", "tables"] => {
            method(req, "GET")?;
            Ok(cached(req, contract, json_response(&tables::catalog())))
        }
        ["v1", "claims"] => {
            method(req, "GET")?;
            Ok(cached(req, contract, json_response(&claims::catalog())))
        }
        ["v1", "twins"] => {
            method(req, "GET")?;
            let mut list: Vec<Value> = commands::topology_names()
                .iter()
                .map(|n| json!({"id": format!("builtin.{n}"), "href": format!("/v1/twins/builtin.{n}")}))
                .collect();
            if state.settings.store.is_some() {
                list.push(json!({"id": "store", "href": "/v1/twins/store"}));
            }
            let body = json!({"rsim_json": VERSION, "kind": "twins", "twins": list});
            Ok(json_response(&body))
        }
        ["v1", "twins", twin, rest @ ..] => {
            let t = match state.twin(twin)? {
                Resolved::Twin(t) => t,
                Resolved::Redirect(id) => {
                    let mut location = format!("/v1/twins/{id}");
                    for r in rest {
                        location.push('/');
                        location.push_str(r);
                    }
                    return Ok(Response {
                        status: 307,
                        headers: vec![("location".into(), location)],
                        body: Vec::new(),
                    });
                }
            };
            let etag = format!("{}.{contract}", t.loaded.identity.id);
            let res = twin_route(state, req, &t, rest)?;
            Ok(if res.status == 200 && req.method == "GET" {
                cached(req, etag, res)
            } else {
                res
            })
        }
        _ => Err(not_found()),
    }
}

fn twin_route(
    state: &State,
    req: &Request,
    t: &TwinRef,
    rest: &[&str],
) -> Result<Response, Problem> {
    let top = t.topology.as_str();
    let l = t.loaded.as_ref();
    let p = params(req);
    let err = from_query_error;
    let id = &l.identity.id;
    match rest {
        [] => {
            method(req, "GET")?;
            let body = json!({
                "rsim_json": VERSION,
                "kind": "twin",
                "topology": top,
                "twin": l.identity,
                "links": {
                    "tables": format!("/v1/twins/{id}/tables/{{table}}/rows"),
                    "claims": format!("/v1/twins/{id}/claims/{{claim}}"),
                    "queries": format!("/v1/twins/{id}/queries")
                }
            });
            Ok(json_response(&body))
        }
        ["tables", table, verb] => {
            method(req, "GET")?;
            let sel = selection(req)?;
            let get = |k: &str| p.get(k).map(|s| s.to_string());
            match *verb {
                "rows" => Ok(json_response(
                    &tables::show(top, l, table, &sel).map_err(err)?,
                )),
                "summary" => Ok(json_response(
                    &tables::summarize(top, l, table, &sel).map_err(err)?,
                )),
                "unique" => {
                    let mut s = sel.clone();
                    let cols = s.columns.take().unwrap_or_default();
                    Ok(json_response(
                        &tables::unique(top, l, table, &cols, &s).map_err(err)?,
                    ))
                }
                "top" => Ok(json_response(
                    &tables::top(
                        top,
                        l,
                        table,
                        &get("column").unwrap_or_default(),
                        get("count").and_then(|c| c.parse().ok()).unwrap_or(5),
                        get("ascending").as_deref() == Some("true"),
                        &sel,
                    )
                    .map_err(err)?,
                )),
                "lpm" => Ok(json_response(
                    &tables::lpm(
                        top,
                        l,
                        table,
                        &get("column").unwrap_or_else(|| "prefix".into()),
                        &get("address").unwrap_or_default(),
                        &sel,
                    )
                    .map_err(err)?,
                )),
                _ => Err(problem(
                    404,
                    "not_found",
                    format!("{verb} is not a table verb"),
                )),
            }
        }
        ["queries"] => {
            method(req, "POST")?;
            let body: Value = serde_json::from_slice(&req.body)
                .map_err(|e| problem(400, "invalid_body", format!("the body is not JSON: {e}")))?;
            let Value::Object(mut m) = body else {
                return Err(problem(
                    400,
                    "invalid_body",
                    "the body is not a JSON object".into(),
                ));
            };
            m.remove("topology");
            m.remove("form");
            // Check the query before it gets an identifier.
            let (a, set) = query_args(m.clone(), top);
            if set {
                args::set_query(&a, &[]).map_err(err)?;
            } else {
                args::query(&a, &[]).map_err(err)?;
            }
            let text = Value::Object(m).to_string();
            let q = state.remember(&text);
            let location = format!("/v1/twins/{id}/queries/{q}");
            let body =
                json!({"rsim_json": VERSION, "kind": "query_ref", "qid": q, "href": location});
            let mut r = json_response(&body);
            r.status = 303;
            r.headers.push(("location".into(), location));
            Ok(r)
        }
        ["queries", q] => {
            method(req, "GET")?;
            let (a, set) = query_args(state.recall(q)?, top);
            let f = form(req)?;
            if set {
                let input = args::set_query(&a, &[]).map_err(err)?;
                let o = commands::set(&input, l).map_err(err)?;
                Ok(match f {
                    Form::Full => json_response(&o),
                    f => json_response(&SetBriefOut::from_full(&o, f)),
                })
            } else {
                let input = args::query(&a, &[]).map_err(err)?;
                let o = commands::path(&input, l).map_err(err)?;
                Ok(match f {
                    Form::Full => json_response(&o),
                    f => json_response(&PathBriefOut::from_full(&o, f)),
                })
            }
        }
        ["queries", q, "branches", b, "steps", s] => {
            method(req, "GET")?;
            let (a, set) = query_args(state.recall(q)?, top);
            let num = |x: &str, what: &str| {
                x.parse::<usize>().map_err(|_| {
                    problem(422, "invalid_query", format!("{what} {x} is not a number"))
                })
            };
            let at = rsim_cli::StepRef {
                reply_of: match p.get("reply_of") {
                    Some(r) => Some(num(r, "reply_of")?),
                    None => None,
                },
                branch: num(b, "branch")?,
                step: num(s, "step")?,
            };
            let o = if set {
                let input = args::set_query(&a, &[]).map_err(err)?;
                commands::explain_set(&input, at, l).map_err(err)?
            } else {
                let input = args::query(&a, &[]).map_err(err)?;
                commands::explain(&input, at, l).map_err(err)?
            };
            Ok(json_response(&o))
        }
        ["queries", q, "claims", claim] => {
            method(req, "GET")?;
            let mut m = state.recall(q)?;
            if m.remove("mode")
                .and_then(|v| v.as_str().map(|s| s == "set"))
                == Some(true)
            {
                return Err(problem(
                    422,
                    "invalid_query",
                    "a claim runs on the paths of a path query, not a set query".into(),
                ));
            }
            let a = ClaimArgs {
                topology: top.to_string(),
                claim: claim.to_string(),
                devices: None,
                query: Some(m),
            };
            Ok(json_response(&claims::run(top, l, &a).map_err(err)?))
        }
        ["claims", claim] => {
            method(req, "GET")?;
            let a = ClaimArgs {
                topology: top.to_string(),
                claim: claim.to_string(),
                devices: p
                    .get("device")
                    .map(|d| d.split(',').map(str::to_string).collect()),
                query: None,
            };
            Ok(json_response(&claims::run(top, l, &a).map_err(err)?))
        }
        _ => Err(problem(
            404,
            "not_found",
            format!("{} is not a resource", req.path),
        )),
    }
}
