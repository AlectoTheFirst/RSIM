//! The sign-in of the API: the gate of each route, the session cookie, the
//! API tokens, the one-time setup of the first admin, the routes
//! `/v1/auth` and `/v1/admin`, the limit of the request rate and the client
//! address. The users, the sessions and the tokens are in the inventory
//! database; with no database the server has no sign-in.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use rsim_contract::schema;
use rsim_inventory::{
    Attempt, AuthEventPage, Principal, Role, SCOPE_ADMIN, SCOPE_INVENTORY_WRITE, SCOPE_READ,
    SESSION_MAX_SECONDS, TOKEN_PREFIX, TokenInfo, User, Via, hash_password, new_secret,
    secret_hash, verify_nothing, verify_password,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::handler::{Request, Response, State};
use crate::inventory::{allow, body, decode, from_error, json_out};
use crate::openapi::Route as ApiRoute;
use crate::problem::{Problem, problem};

/// The session cookie on HTTPS. The prefix `__Host-` binds it to the host
/// and needs `Secure` and the path `/`.
pub const COOKIE_HTTPS: &str = "__Host-rsim_session";
/// The session cookie on plain HTTP to a loopback address.
pub const COOKIE_HTTP: &str = "rsim_session";

/// The requests of one session or token in a burst.
pub const RATE_BURST: f64 = 600.0;
/// The requests of one session or token in each second after a burst.
pub const RATE_PER_SECOND: f64 = 20.0;

/// What a route needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// No sign-in: the UI files, the probes, the sign-in and the setup.
    Open,
    /// A signed-in user, whatever the scopes.
    SignedIn,
    /// A signed-in user from a browser session, not an API token.
    Session,
    /// A user with the scope.
    Scope(&'static str),
}

/// The gate of a method and the segments of a path. A segment of a path
/// template such as `{name}` matches as any other segment.
pub fn gate(method: &str, segs: &[&str]) -> Gate {
    let method = method.to_ascii_uppercase();
    match segs {
        [] | ["index.html"] | ["assets", _] | ["fonts", _] => Gate::Open,
        ["healthz"] | ["readyz"] => Gate::Open,
        ["v1", "auth", "login"] | ["v1", "auth", "setup"] => Gate::Open,
        ["v1", "auth", "logout"] | ["v1", "auth", "me"] => Gate::SignedIn,
        ["v1", "auth", "tokens", ..] => Gate::Session,
        ["v1", "admin", ..] => Gate::Scope(SCOPE_ADMIN),
        ["v1", "inventory", ..] if method == "PUT" || method == "DELETE" || method == "POST" => {
            Gate::Scope(SCOPE_INVENTORY_WRITE)
        }
        _ => Gate::Scope(SCOPE_READ),
    }
}

/// The gate of a route of the OpenAPI document.
pub fn gate_of(r: &ApiRoute) -> Gate {
    let segs: Vec<&str> = r.path.split('/').skip(1).collect();
    gate(r.method, &segs)
}

/// The bucket of the request rate of one session or token.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

/// The request rate of each session and token.
#[derive(Debug, Default)]
pub struct Rate {
    buckets: Mutex<BTreeMap<String, Bucket>>,
}

impl Rate {
    /// Takes one request of a key. Gives the seconds to wait when the
    /// bucket is empty.
    fn take(&self, key: &str) -> Option<u64> {
        let now = Instant::now();
        let mut m = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        if m.len() > 10_000 {
            m.retain(|_, b| now.duration_since(b.at).as_secs() < 600);
        }
        let b = m.entry(key.to_string()).or_insert(Bucket {
            tokens: RATE_BURST,
            at: now,
        });
        let dt = now.duration_since(b.at).as_secs_f64();
        b.tokens = (b.tokens + dt * RATE_PER_SECOND).min(RATE_BURST);
        b.at = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            None
        } else {
            Some(((1.0 - b.tokens) / RATE_PER_SECOND).ceil().max(1.0) as u64)
        }
    }
}

/// An address prefix of a trusted proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl Prefix {
    /// Reads `address` or `address/length`.
    pub fn parse(s: &str) -> Option<Prefix> {
        let (a, l) = match s.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (s, None),
        };
        let addr: IpAddr = a.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = match l {
            Some(l) => l.parse().ok().filter(|n| *n <= max)?,
            None => max,
        };
        Some(Prefix { addr, len })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        match (self.addr, ip) {
            (IpAddr::V4(p), IpAddr::V4(a)) => {
                let mask = if self.len == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.len)
                };
                u32::from(p) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(p), IpAddr::V6(a)) => {
                let mask = if self.len == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.len)
                };
                u128::from(p) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

fn trusted(state: &State, ip: IpAddr) -> bool {
    state
        .settings
        .trusted_proxies
        .iter()
        .any(|p| p.contains(ip))
}

/// True if the connection comes from a trusted proxy.
fn via_proxy(state: &State, req: &Request) -> bool {
    req.peer.is_some_and(|p| trusted(state, p))
}

/// The address of the client: for a connection from a trusted proxy, the
/// last address of `X-Forwarded-For` that is not a trusted proxy, else the
/// address of the connection. An IPv6 client is its /64, the network that
/// one client holds.
pub fn client_addr(state: &State, req: &Request) -> String {
    match client_ip(state, req) {
        Some(IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_none() => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        Some(IpAddr::V6(v6)) => v6
            .to_ipv4_mapped()
            .map_or("unknown".into(), |v4| v4.to_string()),
        Some(ip) => ip.to_string(),
        None => "unknown".into(),
    }
}

fn client_ip(state: &State, req: &Request) -> Option<IpAddr> {
    let peer = req.peer?;
    if trusted(state, peer)
        && let Some(xff) = req.headers.get("x-forwarded-for")
    {
        for a in xff.rsplit(',') {
            match a.trim().parse::<IpAddr>() {
                Ok(ip) if trusted(state, ip) => continue,
                Ok(ip) => return Some(ip),
                Err(_) => return None,
            }
        }
    }
    Some(peer)
}

/// True for a request that reached the server over HTTPS: through a
/// trusted proxy that sets `X-Forwarded-Proto: https`.
pub fn https(state: &State, req: &Request) -> bool {
    via_proxy(state, req)
        && req
            .headers
            .get("x-forwarded-proto")
            .is_some_and(|p| p.eq_ignore_ascii_case("https"))
}

fn cookie_name(state: &State, req: &Request) -> &'static str {
    if https(state, req) {
        COOKIE_HTTPS
    } else {
        COOKIE_HTTP
    }
}

/// The value of the session cookie of the scheme of the request.
fn session_cookie<'a>(state: &State, req: &'a Request) -> Option<&'a str> {
    let name = cookie_name(state, req);
    req.headers.get("cookie")?.split(';').find_map(|c| {
        let (k, v) = c.trim().split_once('=')?;
        (k == name && !v.is_empty()).then_some(v)
    })
}

fn set_cookie(state: &State, req: &Request, value: &str, max_age: u64) -> (String, String) {
    let secure = if https(state, req) { "; Secure" } else { "" };
    (
        "set-cookie".into(),
        format!(
            "{}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}",
            cookie_name(state, req)
        ),
    )
}

/// The credentials that a request presents.
enum Presented<'a> {
    None,
    Bearer(&'a str),
    Cookie(&'a str),
}

fn presented<'a>(state: &State, req: &'a Request) -> Presented<'a> {
    if let Some(a) = req.headers.get("authorization") {
        let t = a
            .strip_prefix("Bearer ")
            .or_else(|| a.strip_prefix("bearer "))
            .unwrap_or("")
            .trim();
        return Presented::Bearer(t);
    }
    match session_cookie(state, req) {
        Some(c) => Presented::Cookie(c),
        None => Presented::None,
    }
}

fn unauthorized(detail: &str) -> Problem {
    problem(401, "unauthorized", detail.to_string())
}

/// The user of a request and its check against the gate of the route.
/// `Ok(None)` for an open route with no credentials. With no inventory
/// database, the server has no sign-in, and each request passes.
pub fn check(state: &State, req: &Request, segs: &[&str]) -> Result<Option<Principal>, Response> {
    let Some(inv) = &state.inventory else {
        return Ok(None);
    };
    let g = gate(&req.method, segs);
    let client = client_addr(state, req);
    let refuse = |actor: Option<&str>, p: Problem| -> Response {
        let _ = inv.run(inv.db().refused(actor, &req.path, &client, &p.detail));
        p.response()
    };
    let user = match presented(state, req) {
        Presented::None => None,
        Presented::Bearer(t) => {
            if !t.starts_with(TOKEN_PREFIX) {
                return Err(unauthorized("the bearer token is not an rsim API token").response());
            }
            match inv.run(inv.db().api_token(&secret_hash(t))) {
                Ok(Some(p)) => Some(p),
                Ok(None) => {
                    return Err(
                        unauthorized("the API token is not known, revoked or expired").response(),
                    );
                }
                Err(e) => return Err(from_error(e).response()),
            }
        }
        Presented::Cookie(c) => match inv.run(inv.db().session(&secret_hash(c))) {
            Ok(p) => p,
            Err(e) => return Err(from_error(e).response()),
        },
    };
    if let Some(u) = &user {
        let key = match u.via {
            Via::Session => format!("s{}", u.user_id),
            Via::Token(id) => format!("t{id}"),
        };
        if let Some(wait) = state.rate.take(&key) {
            let mut r = problem(
                429,
                "too_many_requests",
                format!("too many requests, wait {wait} s"),
            )
            .response();
            r.headers.push(("retry-after".into(), wait.to_string()));
            return Err(r);
        }
    }
    if let Some(u) = &user
        && u.via == Via::Session
        && !matches!(req.method.as_str(), "GET" | "HEAD")
        && !req.headers.contains_key("origin")
    {
        return Err(refuse(
            Some(&u.name),
            problem(403, "forbidden_origin", "no Origin header".into()),
        ));
    }
    let ok = match (g, &user) {
        (Gate::Open, _) => true,
        (_, None) => {
            return Err(unauthorized("sign in, or give an API token").response());
        }
        (Gate::SignedIn, Some(_)) => true,
        (Gate::Session, Some(u)) => u.via == Via::Session,
        (Gate::Scope(s), Some(u)) => u.has(s),
    };
    if !ok {
        let u = user.as_ref().map(|u| u.name.as_str());
        let detail = match g {
            Gate::Session => "this route needs a browser session, not an API token".to_string(),
            Gate::Scope(s) => format!("this route needs the scope {s}"),
            _ => "this route is not allowed".to_string(),
        };
        return Err(refuse(u, problem(403, "forbidden", detail)));
    }
    Ok(user)
}

/// Current user
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MeOut {
    pub name: String,
    pub role: Role,
    pub scopes: Vec<String>,
    /// Sign-in method
    pub via: String,
}

fn me(p: &Principal) -> MeOut {
    MeOut {
        name: p.name.clone(),
        role: p.role,
        scopes: p.scopes.clone(),
        via: match p.via {
            Via::Session => "session".into(),
            Via::Token(_) => "token".into(),
        },
    }
}

/// Sign-in body
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SignInIn {
    pub name: String,
    pub password: String,
}

/// Setup state
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SetupOut {
    /// Setup open
    pub open: bool,
    /// Sign-in
    pub sign_in: bool,
}

/// New API token body
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TokenIn {
    pub name: String,
    pub scopes: Vec<String>,
    /// Days to expiry
    #[serde(default)]
    pub expires_days: Option<u32>,
}

/// New API token
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NewTokenOut {
    pub token: String,
    pub info: TokenInfo,
}

/// API tokens
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TokensOut {
    pub tokens: Vec<TokenInfo>,
}

/// Users
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UsersOut {
    pub users: Vec<User>,
}

/// User body
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UserIn {
    pub role: Role,
    #[serde(default)]
    pub disabled: bool,
    /// Password
    #[serde(default)]
    pub password: Option<String>,
}

/// The routes of the sign-in and of the admin, in a fixed order.
pub const ROUTES: &[ApiRoute] = &[
    ApiRoute {
        method: "post",
        path: "/v1/auth/login",
        id: "signIn",
        summary: "Sign in",
        query: &[],
        body: &[schema::<SignInIn>],
        ok: (200, &[schema::<MeOut>]),
    },
    ApiRoute {
        method: "post",
        path: "/v1/auth/logout",
        id: "signOut",
        summary: "Sign out",
        query: &[],
        body: &[],
        ok: (204, &[]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/auth/me",
        id: "getMe",
        summary: "Current user",
        query: &[],
        body: &[],
        ok: (200, &[schema::<MeOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/auth/setup",
        id: "getSetup",
        summary: "Setup state",
        query: &[],
        body: &[],
        ok: (200, &[schema::<SetupOut>]),
    },
    ApiRoute {
        method: "post",
        path: "/v1/auth/setup",
        id: "setUp",
        summary: "Setup",
        query: &[],
        body: &[schema::<SignInIn>],
        ok: (201, &[schema::<MeOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/auth/tokens",
        id: "listTokens",
        summary: "API tokens",
        query: &[],
        body: &[],
        ok: (200, &[schema::<TokensOut>]),
    },
    ApiRoute {
        method: "post",
        path: "/v1/auth/tokens",
        id: "createToken",
        summary: "New API token",
        query: &[],
        body: &[schema::<TokenIn>],
        ok: (201, &[schema::<NewTokenOut>]),
    },
    ApiRoute {
        method: "delete",
        path: "/v1/auth/tokens/{id}",
        id: "revokeToken",
        summary: "Revoke API token",
        query: &[],
        body: &[],
        ok: (204, &[]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/admin/users",
        id: "listUsers",
        summary: "Users",
        query: &[],
        body: &[],
        ok: (200, &[schema::<UsersOut>]),
    },
    ApiRoute {
        method: "put",
        path: "/v1/admin/users/{name}",
        id: "putUser",
        summary: "Put user",
        query: &[],
        body: &[schema::<UserIn>],
        ok: (200, &[schema::<User>]),
    },
    ApiRoute {
        method: "delete",
        path: "/v1/admin/users/{name}",
        id: "deleteUser",
        summary: "Delete user",
        query: &[],
        body: &[],
        ok: (204, &[]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/admin/events",
        id: "listAuthEvents",
        summary: "Sign-in events",
        query: &[("limit", "Page size"), ("before", "Before id")],
        body: &[],
        ok: (200, &[schema::<AuthEventPage>]),
    },
];

fn no_content() -> Response {
    Response {
        status: 204,
        headers: vec![("cache-control".into(), "no-store".into())],
        body: Vec::new(),
    }
}

fn no_sign_in() -> Problem {
    problem(404, "no_inventory", "no inventory database".into())
}

fn with_status(mut r: Response, status: u16) -> Response {
    r.status = status;
    r
}

/// Handles a request below `/v1/auth`.
pub fn route_auth(
    state: &State,
    req: &Request,
    rest: &[&str],
    user: Option<&Principal>,
) -> Result<Response, Problem> {
    if rest == ["setup"] && req.method == "GET" && state.inventory.is_none() {
        return Ok(json_out(&SetupOut {
            open: false,
            sign_in: false,
        }));
    }
    let inv = state.inventory.as_ref().ok_or_else(no_sign_in)?;
    let db = inv.db();
    let client = client_addr(state, req);
    let signed = || user.ok_or_else(|| unauthorized("sign in"));
    match rest {
        ["login"] => {
            allow(req, &["POST"])?;
            let b: SignInIn = body(req)?;
            let attempt = match inv
                .run(db.begin_sign_in(&b.name, &client))
                .map_err(from_error)?
            {
                Attempt::Go(id) => id,
                Attempt::Wait(wait) => {
                    let mut r = problem(
                        429,
                        "too_many_sign_ins",
                        format!("too many failed sign-ins, wait {wait} s"),
                    )
                    .response();
                    r.headers.push(("retry-after".into(), wait.to_string()));
                    return Ok(r);
                }
            };
            let account = if b.password.chars().count() > rsim_inventory::MAX_PASSWORD {
                None
            } else {
                inv.run(db.account(&b.name)).map_err(from_error)?
            };
            let ok = match &account {
                Some(a) => verify_password(&b.password, &a.password_hash) && !a.disabled,
                None if b.password.chars().count() <= rsim_inventory::MAX_PASSWORD => {
                    verify_nothing(&b.password);
                    false
                }
                None => false,
            };
            let Some(a) = account.filter(|_| ok) else {
                inv.run(db.sign_in_failed(&b.name, &client))
                    .map_err(from_error)?;
                return Err(problem(
                    401,
                    "sign_in_failed",
                    "wrong user name or password".into(),
                ));
            };
            inv.run(db.forget_attempt(attempt)).map_err(from_error)?;
            let (session, hash) = new_secret("").map_err(from_error)?;
            inv.run(db.start_session(a.user_id, &b.name, &hash, &client))
                .map_err(from_error)?;
            let mut r = json_out(&MeOut {
                name: b.name.clone(),
                role: a.role,
                scopes: a.role.scopes().iter().map(|s| s.to_string()).collect(),
                via: "session".into(),
            });
            r.headers
                .push(set_cookie(state, req, &session, SESSION_MAX_SECONDS));
            Ok(r)
        }
        ["logout"] => {
            allow(req, &["POST"])?;
            if let Some(c) = session_cookie(state, req) {
                inv.run(db.end_session(&secret_hash(c), &client))
                    .map_err(from_error)?;
            }
            let mut r = no_content();
            r.headers.push(set_cookie(state, req, "", 0));
            Ok(r)
        }
        ["me"] => {
            allow(req, &["GET"])?;
            Ok(json_out(&me(signed()?)))
        }
        ["setup"] => {
            allow(req, &["GET", "POST"])?;
            if req.method == "GET" {
                let open = inv.run(db.setup_open()).map_err(from_error)?;
                return Ok(json_out(&SetupOut {
                    open,
                    sign_in: true,
                }));
            }
            let b: SignInIn = body(req)?;
            if !inv.run(db.setup_open()).map_err(from_error)? {
                return Err(problem(409, "conflict", "a user exists".into()));
            }
            let hash = hash_password(&b.password).map_err(from_error)?;
            let (session, session_hash) = new_secret("").map_err(from_error)?;
            let p = inv
                .run(db.setup(&b.name, &hash, &session_hash, &client))
                .map_err(from_error)?;
            let mut r = with_status(json_out(&me(&p)), 201);
            r.headers
                .push(set_cookie(state, req, &session, SESSION_MAX_SECONDS));
            Ok(r)
        }
        ["tokens"] => {
            allow(req, &["GET", "POST"])?;
            let u = signed()?;
            if req.method == "GET" {
                let tokens = inv.run(db.tokens(u.user_id)).map_err(from_error)?;
                return Ok(json_out(&TokensOut { tokens }));
            }
            let b: TokenIn = body(req)?;
            let (token, hash) = new_secret(TOKEN_PREFIX).map_err(from_error)?;
            let info = inv
                .run(db.create_token(u, &b.name, &b.scopes, b.expires_days, &hash))
                .map_err(from_error)?;
            Ok(with_status(json_out(&NewTokenOut { token, info }), 201))
        }
        ["tokens", id] => {
            allow(req, &["DELETE"])?;
            let u = signed()?;
            let id: i64 = decode(id)?
                .parse()
                .map_err(|_| problem(404, "not_found", format!("{id} is not a token id")))?;
            inv.run(db.revoke_token(u, id)).map_err(from_error)?;
            Ok(no_content())
        }
        _ => Err(problem(
            404,
            "not_found",
            format!("{} is not a resource", req.path),
        )),
    }
}

/// Handles a request below `/v1/admin`.
pub fn route_admin(
    state: &State,
    req: &Request,
    rest: &[&str],
    user: Option<&Principal>,
) -> Result<Response, Problem> {
    let inv = state.inventory.as_ref().ok_or_else(no_sign_in)?;
    let db = inv.db();
    let actor = user.map_or("rsim-api", |u| u.name.as_str());
    match rest {
        ["users"] => {
            allow(req, &["GET"])?;
            let users = inv.run(db.users()).map_err(from_error)?;
            Ok(json_out(&UsersOut { users }))
        }
        ["users", name] => {
            allow(req, &["PUT", "DELETE"])?;
            let name = decode(name)?;
            if req.method == "DELETE" {
                inv.run(db.delete_user(actor, &name)).map_err(from_error)?;
                return Ok(no_content());
            }
            let b: UserIn = body(req)?;
            let hash = b
                .password
                .as_deref()
                .map(hash_password)
                .transpose()
                .map_err(from_error)?;
            let u = inv
                .run(db.put_user(actor, &name, b.role, b.disabled, hash.as_deref()))
                .map_err(from_error)?;
            Ok(json_out(&u))
        }
        ["events"] => {
            allow(req, &["GET"])?;
            let p: BTreeMap<&str, &str> = req
                .query
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let bad = |n: &str| problem(422, "invalid_filter", format!("{n} is not a number"));
            let limit = match p.get("limit") {
                Some(v) => v.parse().map_err(|_| bad("limit"))?,
                None => 100,
            };
            let before = match p.get("before") {
                Some(v) => Some(v.parse().map_err(|_| bad("before"))?),
                None => None,
            };
            let page = inv.run(db.auth_events(limit, before)).map_err(from_error)?;
            Ok(json_out(&page))
        }
        _ => Err(problem(
            404,
            "not_found",
            format!("{} is not a resource", req.path),
        )),
    }
}

/// The probes of a container platform. `readyz` reads the inventory
/// database when the server has one.
pub fn probe(state: &State, req: &Request, ready: bool) -> Result<Response, Problem> {
    allow(req, &["GET"])?;
    if ready && let Some(inv) = &state.inventory {
        inv.run(inv.db().setup_open()).map_err(from_error)?;
    }
    Ok(Response {
        status: 200,
        headers: vec![
            ("content-type".into(), "text/plain".into()),
            ("cache-control".into(), "no-store".into()),
        ],
        body: b"ok\n".to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes() {
        let p = Prefix::parse("10.42.0.0/16").unwrap();
        assert!(p.contains("10.42.3.4".parse().unwrap()));
        assert!(!p.contains("10.43.0.1".parse().unwrap()));
        assert!(p.contains("::ffff:10.42.0.9".parse().unwrap()));
        let one = Prefix::parse("192.0.2.1").unwrap();
        assert_eq!(one.len, 32);
        assert!(Prefix::parse("10.0.0.0/33").is_none());
        let v6 = Prefix::parse("fd00::/8").unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
    }

    #[test]
    fn gates() {
        assert_eq!(gate("GET", &[]), Gate::Open);
        assert_eq!(gate("POST", &["v1", "auth", "login"]), Gate::Open);
        assert_eq!(gate("GET", &["v1", "auth", "me"]), Gate::SignedIn);
        assert_eq!(gate("POST", &["v1", "auth", "tokens"]), Gate::Session);
        assert_eq!(
            gate("GET", &["v1", "admin", "users"]),
            Gate::Scope(SCOPE_ADMIN)
        );
        assert_eq!(
            gate("put", &["v1", "inventory", "groups", "{name}"]),
            Gate::Scope(SCOPE_INVENTORY_WRITE)
        );
        assert_eq!(
            gate(
                "POST",
                &["v1", "inventory", "devices", "{device}", "collect"]
            ),
            Gate::Scope(SCOPE_INVENTORY_WRITE)
        );
        assert_eq!(gate("GET", &["v1", "inventory"]), Gate::Scope(SCOPE_READ));
        assert_eq!(gate("POST", &["mcp"]), Gate::Scope(SCOPE_READ));
    }
}
