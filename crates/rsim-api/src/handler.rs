//! The request handler: one request in, one response out, with no socket.
//! The server in `server.rs` reads the request from a connection and
//! writes the response.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rsim_cli::commands::{self, Loaded};
use rsim_cli::{ErrorCode, QueryError, args, claims, tables};
use rsim_contract::args::Form;
use rsim_contract::claim::ClaimArgs;
use rsim_contract::json::{VERSION, to_text};
use rsim_contract::table::{Selection, TableOut};
use rsim_contract::twin::TwinJson;
use rsim_ingest::coverage::State as CoverageState;
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

/// The state of a server: the settings, the tools of the MCP transport
/// with the twins that a request named, and the query texts above the
/// inline limit. The REST routes and the MCP tools share the twins. It
/// keeps no answer.
pub struct State {
    pub settings: Settings,
    mcp: rsim_mcp::tools::Tools,
    long_queries: Mutex<BTreeMap<String, String>>,
}

impl State {
    pub fn new(settings: Settings) -> Self {
        let mcp = match &settings.store {
            Some(folder) => rsim_mcp::tools::Tools::with_store(folder.clone()),
            None => rsim_mcp::tools::Tools::default(),
        };
        State {
            settings,
            mcp,
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
        ErrorCode::UnknownTopology
        | ErrorCode::NoSuchStep
        | ErrorCode::UnknownTable
        | ErrorCode::NoSourceText => 404,
        ErrorCode::NotMasked => 403,
        ErrorCode::InvalidQuery
        | ErrorCode::InvalidFilter
        | ErrorCode::UnknownIngress
        | ErrorCode::StartRequiresContext => 422,
        ErrorCode::Store | ErrorCode::ContractViolation | ErrorCode::Internal => 500,
    };
    problem(status, e.code.as_str(), e.detail)
}

impl State {
    /// The twin of a topology name of the MCP tools.
    fn load(&self, topology: &str) -> Result<Arc<Loaded>, Problem> {
        self.mcp.twin(topology).map_err(from_query_error)
    }

    /// The twin of a path segment: `builtin.<topology>`, `snap-<cycle>` or
    /// the alias `store`.
    fn twin(&self, segment: &str) -> Result<Resolved, Problem> {
        let unknown = |d: String| problem(404, "unknown_twin", d);
        let store = |s: &Self| -> Result<Arc<Loaded>, Problem> {
            match &s.settings.store {
                Some(_) => s.load(rsim_mcp::tools::STORE),
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
                let loaded = self.load(&name)?;
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

/// The selection of a table request from its parameters. The names in
/// `reserved` are the parameters of the verb; each other name is a column
/// filter.
fn selection(req: &Request, reserved: &[&str]) -> Result<Selection, Problem> {
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
            k if reserved.contains(&k) => {}
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
/// mode: true for `set`. A mode other than `path` or `set` is an error.
fn query_args(
    mut m: Map<String, Value>,
    topology: &str,
) -> Result<(Map<String, Value>, bool), Problem> {
    let set = args::mode(&m).map_err(from_query_error)?;
    m.remove("mode");
    m.insert("topology".into(), json!(topology));
    Ok((m, set))
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
        && !own_origin(state, o)
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
                    "content-type, if-none-match, mcp-protocol-version, mcp-method, mcp-name"
                        .into(),
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
        res.headers.push((
            "access-control-expose-headers".into(),
            "Server-Timing".into(),
        ));
        res.headers.push(("vary".into(), "Origin".into()));
    }
    res.headers
        .push(("x-content-type-options".into(), "nosniff".into()));
    res
}

/// The `Host` values of the listen address.
fn own_hosts(state: &State) -> [String; 4] {
    let port = state.settings.listen.port();
    [
        format!("{}:{port}", state.settings.listen.ip()),
        format!("localhost:{port}"),
        format!("127.0.0.1:{port}"),
        format!("[::1]:{port}"),
    ]
}

/// True for the origin of the server itself: the origin of its UI pages.
fn own_origin(state: &State, origin: &str) -> bool {
    origin
        .strip_prefix("http://")
        .is_some_and(|h| own_hosts(state).iter().any(|a| a.eq_ignore_ascii_case(h)))
}

fn check_host(state: &State, req: &Request) -> Option<Problem> {
    let host = req.headers.get("host")?;
    let allowed = own_hosts(state);
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

/// A query parameter in percent encoding: each byte other than a letter, a
/// digit, `-`, `.`, `_`, `~` and `,` is encoded.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b',') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn route(state: &State, req: &Request) -> Result<Response, Problem> {
    let parts: Vec<&str> = req.path.trim_end_matches('/').split('/').skip(1).collect();
    let contract = contract_version();
    let not_found = || problem(404, "not_found", format!("{} is not a resource", req.path));
    match parts.as_slice() {
        [] | ["index.html"] | ["assets", _] | ["fonts", _] => {
            method(req, "GET")?;
            let f = crate::ui::get(&req.path).ok_or_else(not_found)?;
            Ok(Response {
                status: 200,
                headers: vec![
                    ("content-type".into(), f.content_type.into()),
                    ("cache-control".into(), "no-cache".into()),
                    (
                        "content-security-policy".into(),
                        crate::ui::CONTENT_SECURITY_POLICY.into(),
                    ),
                ],
                body: f.body.to_vec(),
            })
        }
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
        ["mcp"] => mcp(state, req),
        ["v1", "twins", twin, rest @ ..] => {
            let t = match state.twin(twin)? {
                Resolved::Twin(t) => t,
                Resolved::Redirect(id) => {
                    let mut location = format!("/v1/twins/{id}");
                    for r in rest {
                        location.push('/');
                        location.push_str(r);
                    }
                    for (i, (k, v)) in req.query.iter().enumerate() {
                        location.push(if i == 0 { '?' } else { '&' });
                        location.push_str(&percent_encode(k));
                        location.push('=');
                        location.push_str(&percent_encode(v));
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

/// The columns of the coverage report: the lines of each state and the
/// unhandled paths of each device.
pub const COVERAGE_COLUMNS: [&str; 6] = [
    "device",
    "handled",
    "irrelevant",
    "unhandled",
    "unhandled_paths",
    "unhandled_stanzas",
];

/// The coverage report of a twin: one row for each device in name order, a
/// page of `limit` rows after `cursor`.
fn coverage_report(top: &str, l: &Loaded, req: &Request) -> Result<TableOut, Problem> {
    let p = params(req);
    let invalid = |m: String| problem(422, "invalid_filter", m);
    let limit = match p.get("limit") {
        None => None,
        Some(v) => match v.parse::<usize>() {
            Ok(0) => return Err(invalid("the limit is 0".into())),
            Ok(n) => Some(n),
            Err(_) => return Err(invalid(format!("limit {v} is not a number"))),
        },
    };
    let total = l.coverage.len();
    let start = match p.get("cursor") {
        None => 0,
        Some(c) => c
            .strip_prefix('o')
            .and_then(|n| n.parse::<usize>().ok())
            .filter(|n| *n <= total)
            .ok_or_else(|| invalid(format!("{c} is not a cursor of the coverage report")))?,
    };
    let end = limit.map_or(total, |n| start.saturating_add(n).min(total));
    let rows = l
        .coverage
        .iter()
        .skip(start)
        .take(end - start)
        .map(|(device, c)| {
            let lines = |s: CoverageState| c.lines.get(&s).copied().unwrap_or(0);
            let stanzas: u32 = c.unhandled.values().map(|(n, _)| n).sum();
            vec![
                json!(device),
                json!(lines(CoverageState::Handled)),
                json!(lines(CoverageState::Irrelevant)),
                json!(lines(CoverageState::Unhandled)),
                json!(c.unhandled.len()),
                json!(stanzas),
            ]
        })
        .collect();
    Ok(TableOut {
        rsim_json: VERSION,
        kind: "coverage_report".into(),
        topology: top.to_string(),
        twin: l.identity.clone(),
        table: "coverage".into(),
        columns: COVERAGE_COLUMNS.iter().map(|c| c.to_string()).collect(),
        rows,
        total,
        next_cursor: (end < total).then(|| format!("o{end}")),
    })
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
                    "queries": format!("/v1/twins/{id}/queries"),
                    "coverage": format!("/v1/twins/{id}/coverage")
                }
            });
            Ok(json_response(&body))
        }
        ["coverage"] => {
            method(req, "GET")?;
            Ok(json_response(&coverage_report(top, l, req)?))
        }
        ["tables", table, verb] => {
            method(req, "GET")?;
            let reserved: &[&str] = match *verb {
                "top" => &["column", "count", "ascending"],
                "lpm" => &["column", "address"],
                _ => &[],
            };
            let sel = selection(req, reserved)?;
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
                        match get("count") {
                            None => 5,
                            Some(c) => c.parse().map_err(|_| {
                                problem(422, "invalid_filter", format!("count {c} is not a number"))
                            })?,
                        },
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
            let (a, set) = query_args(m.clone(), top)?;
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
            let (a, set) = query_args(state.recall(q)?, top)?;
            let f = form(req)?;
            if set {
                let input = args::set_query(&a, &[]).map_err(err)?;
                Ok(match f {
                    Form::Full => json_response(&commands::set(&input, l).map_err(err)?),
                    f => json_response(&commands::set_brief(&input, l, f).map_err(err)?),
                })
            } else {
                let input = args::query(&a, &[]).map_err(err)?;
                Ok(match f {
                    Form::Full => json_response(&commands::path(&input, l).map_err(err)?),
                    f => json_response(&commands::path_brief(&input, l, f).map_err(err)?),
                })
            }
        }
        ["queries", q, "branches", b, "steps", s] => {
            method(req, "GET")?;
            let (a, set) = query_args(state.recall(q)?, top)?;
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
            let mut o = if set {
                let input = args::set_query(&a, &[]).map_err(err)?;
                commands::explain_set(&input, at, l).map_err(err)?
            } else {
                let input = args::query(&a, &[]).map_err(err)?;
                commands::explain(&input, at, l).map_err(err)?
            };
            match p.get("source_lines").copied() {
                None | Some("false") | Some("0") => {}
                Some("true") | Some("1") => rsim_cli::sources::attach(&mut o, l),
                Some(v) => {
                    return Err(problem(
                        422,
                        "invalid_query",
                        format!("source_lines {v} is not true or false"),
                    ));
                }
            }
            Ok(json_response(&o))
        }
        ["queries", q, "claims", claim] => {
            method(req, "GET")?;
            let mut m = state.recall(q)?;
            if args::mode(&m).map_err(err)? {
                return Err(problem(
                    422,
                    "invalid_query",
                    "a claim runs on the paths of a path query, not a set query".into(),
                ));
            }
            m.remove("mode");
            let a = ClaimArgs {
                topology: top.to_string(),
                claim: claim.to_string(),
                devices: None,
                query: Some(m),
            };
            Ok(json_response(&claims::run(top, l, &a).map_err(err)?))
        }
        ["sources"] => {
            method(req, "GET")?;
            let file = p.get("file").copied().ok_or_else(|| {
                problem(422, "invalid_query", "the parameter file is missing".into())
            })?;
            let lines = p.get("lines").copied().ok_or_else(|| {
                problem(
                    422,
                    "invalid_query",
                    "the parameter lines is missing".into(),
                )
            })?;
            let (first, last) = rsim_cli::sources::parse_range(lines).map_err(err)?;
            Ok(json_response(
                &rsim_cli::sources::lines(top, l, file, first, last).map_err(err)?,
            ))
        }
        ["topology"] => {
            method(req, "GET")?;
            let list = |k: &str| p.get(k).map(|v| v.split(',').map(str::to_string).collect());
            let view = rsim_contract::args::TopologyViewArgs {
                topology: top.to_string(),
                level: p.get("level").map(|s| s.to_string()),
                layers: list("layer"),
                devices: list("device"),
                around: p.get("around").map(|s| s.to_string()),
                hops: match p.get("hops") {
                    Some(h) => Some(h.parse().map_err(|_| {
                        problem(422, "invalid_filter", format!("hops {h} is not a number"))
                    })?),
                    None => None,
                },
                claims: list("claims"),
            };
            let out = rsim_cli::topology::topology(top, l, &view).map_err(err)?;
            export(&out, p.get("format").copied())
        }
        ["queries", q, "topology"] => {
            method(req, "GET")?;
            let (a, set) = query_args(state.recall(q)?, top)?;
            let answer = if set {
                commands::run_set(&args::set_query(&a, &[]).map_err(err)?, l).map_err(err)?
            } else {
                commands::run(&args::query(&a, &[]).map_err(err)?, l).map_err(err)?
            };
            export(
                &rsim_cli::topology::drawing(top, l, &answer),
                p.get("format").copied(),
            )
        }
        ["batch"] => {
            method(req, "POST")?;
            batch(state, req, t)
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

/// A topology as JSON, or exported as Mermaid, D2 or GraphML.
fn export(
    out: &rsim_contract::topology::TopologyOut,
    format: Option<&str>,
) -> Result<Response, Problem> {
    let (body, kind) = match format.unwrap_or("json") {
        "json" => return Ok(json_response(out)),
        "mermaid" => (out.mermaid(), "text/plain; charset=utf-8"),
        "d2" => (out.d2(), "text/plain; charset=utf-8"),
        "graphml" => (out.graphml(), "application/graphml+xml"),
        f => {
            return Err(problem(
                422,
                "invalid_query",
                format!("format {f} is not json, mermaid, d2 or graphml"),
            ));
        }
    };
    Ok(Response {
        status: 200,
        headers: vec![("content-type".into(), kind.into())],
        body: body.into_bytes(),
    })
}

/// The largest number of items of a batch.
pub const MAX_BATCH: usize = 100;

/// Runs the items of a batch in order. The body is `{"items": [...]}`;
/// each item is `{"op": "query", "query": {...}, "form": ...}`, `{"op":
/// "claim", "claim": ..., "query": {...} | "devices": [...]}` or `{"op":
/// "table", "table": ..., "verb": ..., ...}`. The answer has one JSON line
/// for each item: its result, or its problem object.
fn batch(state: &State, req: &Request, t: &TwinRef) -> Result<Response, Problem> {
    let top = t.topology.as_str();
    let l = t.loaded.as_ref();
    let body: Value = serde_json::from_slice(&req.body)
        .map_err(|e| problem(400, "invalid_body", format!("the body is not JSON: {e}")))?;
    let items = body["items"]
        .as_array()
        .ok_or_else(|| problem(400, "invalid_body", "the body has no list items".into()))?;
    if items.len() > MAX_BATCH {
        return Err(problem(
            413,
            "too_large",
            format!("a batch has at most {MAX_BATCH} items"),
        ));
    }
    let _ = state;
    let mut out = String::new();
    for item in items {
        let line = (|| -> Result<String, Problem> {
            let err = from_query_error;
            match item["op"].as_str() {
                Some("query") => {
                    let Some(Value::Object(m)) = item.get("query") else {
                        return Err(problem(
                            422,
                            "invalid_query",
                            "the item has no query".into(),
                        ));
                    };
                    let (a, set) = query_args(m.clone(), top)?;
                    let f = match item["form"].as_str() {
                        None | Some("summary") => Form::Summary,
                        Some("steps") => Form::Steps,
                        Some("full") => Form::Full,
                        Some(f) => {
                            return Err(problem(
                                422,
                                "invalid_query",
                                format!("form {f} is not summary, steps or full"),
                            ));
                        }
                    };
                    Ok(if set {
                        let input = args::set_query(&a, &[]).map_err(err)?;
                        match f {
                            Form::Full => to_text(&commands::set(&input, l).map_err(err)?, false),
                            f => to_text(&commands::set_brief(&input, l, f).map_err(err)?, false),
                        }
                    } else {
                        let input = args::query(&a, &[]).map_err(err)?;
                        match f {
                            Form::Full => to_text(&commands::path(&input, l).map_err(err)?, false),
                            f => to_text(&commands::path_brief(&input, l, f).map_err(err)?, false),
                        }
                    })
                }
                Some("claim") => {
                    let mut m = item.as_object().cloned().unwrap_or_default();
                    m.remove("op");
                    m.insert("topology".into(), json!(top));
                    let a: ClaimArgs = serde_json::from_value(Value::Object(m))
                        .map_err(|e| problem(422, "invalid_query", e.to_string()))?;
                    Ok(to_text(&claims::run(top, l, &a).map_err(err)?, false))
                }
                Some("table") => {
                    let mut m = item.as_object().cloned().unwrap_or_default();
                    m.remove("op");
                    m.insert("topology".into(), json!(top));
                    let a: rsim_contract::args::TableQueryArgs =
                        serde_json::from_value(Value::Object(m))
                            .map_err(|e| problem(422, "invalid_query", e.to_string()))?;
                    let s = &a.selection;
                    use rsim_contract::args::TableVerb;
                    Ok(match a.verb.unwrap_or_default() {
                        TableVerb::Show => {
                            to_text(&tables::show(top, l, &a.table, s).map_err(err)?, false)
                        }
                        TableVerb::Summarize => {
                            to_text(&tables::summarize(top, l, &a.table, s).map_err(err)?, false)
                        }
                        TableVerb::Unique => {
                            let mut sel = s.clone();
                            let cols = sel.columns.take().unwrap_or_default();
                            to_text(
                                &tables::unique(top, l, &a.table, &cols, &sel).map_err(err)?,
                                false,
                            )
                        }
                        TableVerb::Top => to_text(
                            &tables::top(
                                top,
                                l,
                                &a.table,
                                a.column.as_deref().unwrap_or_default(),
                                a.count.unwrap_or(5),
                                a.ascending.unwrap_or(false),
                                s,
                            )
                            .map_err(err)?,
                            false,
                        ),
                        TableVerb::Lpm => to_text(
                            &tables::lpm(
                                top,
                                l,
                                &a.table,
                                a.column.as_deref().unwrap_or("prefix"),
                                a.address.as_deref().unwrap_or_default(),
                                s,
                            )
                            .map_err(err)?,
                            false,
                        ),
                    })
                }
                _ => Err(problem(
                    422,
                    "invalid_query",
                    "op is not query, claim or table".into(),
                )),
            }
        })();
        out.push_str(&line.unwrap_or_else(|p| to_text(&p, false)));
        out.push('\n');
    }
    Ok(Response {
        status: 200,
        headers: vec![("content-type".into(), "application/x-ndjson".into())],
        body: out.into_bytes(),
    })
}

/// The MCP protocol revision of the Streamable HTTP transport.
const MCP_REVISION: &str = rsim_mcp::server::MODERN;
/// The JSON-RPC error code of a header that does not match the body.
const HEADER_MISMATCH: i64 = -32020;

fn rpc_error(status: u16, id: &Value, code: i64, message: String) -> Response {
    let body = json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}});
    Response {
        status,
        headers: vec![("content-type".into(), "application/json".into())],
        body: body.to_string().into_bytes(),
    }
}

/// One message of the Streamable HTTP transport of MCP, revision
/// 2026-07-28: one JSON-RPC message in the body of a POST. A request gets
/// its response as JSON; a notification or a response gets 202 with no
/// body. The headers `MCP-Protocol-Version`, `Mcp-Method` and, for a tool
/// call, `Mcp-Name` must agree with the body. The server keeps no session,
/// so `initialize` is not a method.
fn mcp(state: &State, req: &Request) -> Result<Response, Problem> {
    method(req, "POST")?;
    let msg: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return Ok(rpc_error(400, &Value::Null, -32700, "Parse error".into())),
    };
    let id = match msg.get("id") {
        Some(v @ (Value::String(_) | Value::Number(_))) => v.clone(),
        _ => Value::Null,
    };
    let method_name = msg.get("method").and_then(Value::as_str);
    let header = |k: &str| req.headers.get(k).map(String::as_str);
    if let Some(m) = method_name {
        match header("mcp-protocol-version") {
            None => {
                return Ok(rpc_error(
                    400,
                    &id,
                    HEADER_MISMATCH,
                    "MCP-Protocol-Version is not given".into(),
                ));
            }
            Some(v) if v != MCP_REVISION => {
                return Ok(rpc_error(
                    400,
                    &id,
                    -32022,
                    format!("Unsupported protocol version {v}; the server supports {MCP_REVISION}"),
                ));
            }
            Some(_) => {}
        }
        let meta = msg
            .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .and_then(Value::as_str);
        if meta.is_some_and(|v| v != MCP_REVISION) {
            return Ok(rpc_error(
                400,
                &id,
                HEADER_MISMATCH,
                "MCP-Protocol-Version does not match params._meta".into(),
            ));
        }
        if header("mcp-method") != Some(m) {
            return Ok(rpc_error(
                400,
                &id,
                HEADER_MISMATCH,
                format!("Mcp-Method does not match the method {m}"),
            ));
        }
        if m == "tools/call" {
            let name = msg.pointer("/params/name").and_then(Value::as_str);
            if header("mcp-name") != name {
                return Ok(rpc_error(
                    400,
                    &id,
                    HEADER_MISMATCH,
                    "Mcp-Name does not match params.name".into(),
                ));
            }
        }
    }
    let mut server = rsim_mcp::server::Server::without_handshake(state.mcp.clone());
    Ok(match server.handle_line(&req.body) {
        Some(line) => Response {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: line.trim_end().as_bytes().to_vec(),
        },
        None => Response {
            status: 202,
            headers: Vec::new(),
            body: Vec::new(),
        },
    })
}
