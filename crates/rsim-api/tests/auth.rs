//! The sign-in of the API. The tests with a database need
//! `RSIM_TEST_DATABASE_URL`; with it unset they print that they are skipped
//! and pass.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use rsim_api::auth::{COOKIE_HTTP, COOKIE_HTTPS, Gate, Prefix, gate_of};
use rsim_api::handler::{Request, Response, Settings, State, handle};
use rsim_api::inventory::InventoryHandle;
use rsim_api::openapi::all_routes;
use serde_json::{Value, json};

const PORT: u16 = 8787;
const HOST: &str = "127.0.0.1:8787";
const ORIGIN: &str = "http://127.0.0.1:8787";
const PUBLIC: &str = "https://rsim.example.net";
const PROXY: &str = "10.42.0.7";
const PASSWORD: &str = "a long test password";

fn settings() -> Settings {
    Settings {
        listen: ([127, 0, 0, 1], PORT).into(),
        store: None,
        allow_origins: vec![],
        max_body: 64 * 1024,
        public_origins: vec![PUBLIC.into()],
        trusted_proxies: vec![Prefix::parse("10.42.0.0/16").unwrap()],
    }
}

fn with_db(name: &str) -> Option<(State, tokio::runtime::Runtime)> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let db = rt.block_on(rsim_inventory::test_database(name))?;
    let s = State::new(settings())
        .with_inventory(InventoryHandle::new(Arc::new(db), rt.handle().clone()));
    Some((s, rt))
}

/// A request from a browser on the loopback address.
fn req(method: &str, path: &str) -> Request {
    let mut headers = BTreeMap::from([("host".to_string(), HOST.to_string())]);
    if !matches!(method, "GET" | "HEAD") {
        headers.insert("origin".into(), ORIGIN.into());
    }
    Request {
        method: method.into(),
        path: path.into(),
        query: Vec::new(),
        headers,
        body: Vec::new(),
        peer: Some([127, 0, 0, 1].into()),
    }
}

fn with_body(mut r: Request, v: Value) -> Request {
    r.headers
        .insert("content-type".into(), "application/json".into());
    r.body = v.to_string().into_bytes();
    r
}

fn bearer(mut r: Request, token: &str) -> Request {
    r.headers.remove("origin");
    r.headers
        .insert("authorization".into(), format!("Bearer {token}"));
    r
}

fn cookie(mut r: Request, c: &str) -> Request {
    r.headers.insert("cookie".into(), c.into());
    r
}

fn json(r: &Response) -> Value {
    serde_json::from_slice(&r.body)
        .unwrap_or_else(|e| panic!("{e}: {:?}", String::from_utf8_lossy(&r.body)))
}

/// The `name=value` part of the `Set-Cookie` header.
fn session_of(r: &Response) -> String {
    r.header("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

/// Makes the first admin through the setup route and gives its cookie.
fn setup(s: &State) -> String {
    let r = handle(
        s,
        &with_body(
            req("POST", "/v1/auth/setup"),
            json!({"name": "admin", "password": PASSWORD}),
        ),
    );
    assert_eq!(r.status, 201, "{:?}", String::from_utf8_lossy(&r.body));
    session_of(&r)
}

fn new_token(s: &State, c: &str, scopes: &[&str]) -> String {
    let r = handle(
        s,
        &cookie(
            with_body(
                req("POST", "/v1/auth/tokens"),
                json!({"name": "t", "scopes": scopes}),
            ),
            c,
        ),
    );
    assert_eq!(r.status, 201, "{:?}", String::from_utf8_lossy(&r.body));
    json(&r)["token"].as_str().unwrap().to_string()
}

/// A concrete path of a path template.
fn concrete(path: &str) -> String {
    path.split('/')
        .map(|s| if s.starts_with('{') { "x" } else { s })
        .collect::<Vec<_>>()
        .join("/")
}

#[test]
fn each_route_except_the_open_routes_needs_a_user() {
    let Some((s, _rt)) = with_db("api_auth_gate") else {
        return;
    };
    let mut checked = 0;
    for r in all_routes() {
        let m = r.method.to_ascii_uppercase();
        let res = handle(&s, &req(&m, &concrete(r.path)));
        if gate_of(r) == Gate::Open {
            assert_ne!(res.status, 401, "{m} {}", r.path);
        } else {
            assert_eq!(res.status, 401, "{m} {}", r.path);
            checked += 1;
        }
    }
    assert!(checked > 30, "{checked}");
    let mcp = handle(&s, &req("POST", "/mcp"));
    assert_eq!(mcp.status, 401);
    for open in ["/", "/healthz", "/readyz", "/v1/auth/setup"] {
        assert_ne!(handle(&s, &req("GET", open)).status, 401, "{open}");
    }
}

#[test]
fn the_setup_makes_one_admin_and_then_closes() {
    let Some((s, _rt)) = with_db("api_auth_setup") else {
        return;
    };
    assert_eq!(
        json(&handle(&s, &req("GET", "/v1/auth/setup")))["open"],
        true
    );
    let c = setup(&s);
    assert!(c.starts_with(&format!("{COOKIE_HTTP}=")));
    assert_eq!(
        json(&handle(&s, &req("GET", "/v1/auth/setup")))["open"],
        false
    );
    let again = handle(
        &s,
        &with_body(
            req("POST", "/v1/auth/setup"),
            json!({"name": "second", "password": PASSWORD}),
        ),
    );
    assert_eq!(again.status, 409);
    let me = json(&handle(&s, &cookie(req("GET", "/v1/auth/me"), &c)));
    assert_eq!(me["name"], "admin");
    assert_eq!(me["role"], "admin");
}

#[test]
fn a_sign_in_gives_a_session_that_ends_at_sign_out() {
    let Some((s, _rt)) = with_db("api_auth_sign_in") else {
        return;
    };
    setup(&s);
    let bad = handle(
        &s,
        &with_body(
            req("POST", "/v1/auth/login"),
            json!({"name": "admin", "password": "not the password"}),
        ),
    );
    assert_eq!(bad.status, 401);
    let unknown = handle(
        &s,
        &with_body(
            req("POST", "/v1/auth/login"),
            json!({"name": "nobody", "password": "not the password"}),
        ),
    );
    assert_eq!(json(&unknown)["detail"], json(&bad)["detail"]);
    let ok = handle(
        &s,
        &with_body(
            req("POST", "/v1/auth/login"),
            json!({"name": "admin", "password": PASSWORD}),
        ),
    );
    assert_eq!(ok.status, 200);
    let set = ok.header("set-cookie").unwrap();
    assert!(set.contains("HttpOnly") && set.contains("SameSite=Strict"));
    let c = session_of(&ok);
    assert_eq!(handle(&s, &cookie(req("GET", "/v1/twins"), &c)).status, 200);
    let out = handle(&s, &cookie(req("POST", "/v1/auth/logout"), &c));
    assert_eq!(out.status, 204);
    assert!(out.header("set-cookie").unwrap().contains("Max-Age=0"));
    assert_eq!(handle(&s, &cookie(req("GET", "/v1/twins"), &c)).status, 401);
}

#[test]
fn five_failed_sign_ins_give_429() {
    let Some((s, _rt)) = with_db("api_auth_limit") else {
        return;
    };
    setup(&s);
    let try_once = |pw: &str| {
        handle(
            &s,
            &with_body(
                req("POST", "/v1/auth/login"),
                json!({"name": "admin", "password": pw}),
            ),
        )
    };
    for _ in 0..5 {
        assert_eq!(try_once("wrong password!").status, 401);
    }
    let r = try_once(PASSWORD);
    assert_eq!(r.status, 429);
    let wait: u64 = r.header("retry-after").unwrap().parse().unwrap();
    assert!((1..=900).contains(&wait));
    // The failures of one address leave the name open to another address.
    let mut other = with_body(
        req("POST", "/v1/auth/login"),
        json!({"name": "admin", "password": PASSWORD}),
    );
    other.peer = Some("192.0.2.7".parse::<IpAddr>().unwrap());
    assert_eq!(handle(&s, &other).status, 200);
}

#[test]
fn a_token_has_only_its_scopes_and_cannot_manage_tokens() {
    let Some((s, _rt)) = with_db("api_auth_tokens") else {
        return;
    };
    let c = setup(&s);
    let read = new_token(&s, &c, &["rsim.read"]);
    assert!(read.starts_with("rsim_"));
    assert_eq!(
        handle(&s, &bearer(req("GET", "/v1/twins"), &read)).status,
        200
    );
    let put = handle(
        &s,
        &bearer(
            with_body(
                req("PUT", "/v1/inventory/credentials/x"),
                json!({"source": "env", "key": "X"}),
            ),
            &read,
        ),
    );
    assert_eq!(put.status, 403);
    assert_eq!(json(&put)["code"], "forbidden");
    let mint = handle(
        &s,
        &bearer(
            with_body(
                req("POST", "/v1/auth/tokens"),
                json!({"name": "more", "scopes": ["rsim.read"]}),
            ),
            &read,
        ),
    );
    assert_eq!(mint.status, 403);
    let events = json(&handle(&s, &cookie(req("GET", "/v1/admin/events"), &c)));
    let refused: Vec<&Value> = events["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["event"] == "refused")
        .collect();
    assert_eq!(refused.len(), 2, "{events}");

    let list = json(&handle(&s, &cookie(req("GET", "/v1/auth/tokens"), &c)));
    let id = list["tokens"][0]["id"].as_i64().unwrap();
    assert!(!list.to_string().contains(&read));
    let del = handle(
        &s,
        &cookie(req("DELETE", &format!("/v1/auth/tokens/{id}")), &c),
    );
    assert_eq!(del.status, 204);
    assert_eq!(
        handle(&s, &bearer(req("GET", "/v1/twins"), &read)).status,
        401
    );
    assert_eq!(
        handle(&s, &bearer(req("GET", "/v1/twins"), "not-a-token")).status,
        401
    );
}

#[test]
fn a_disabled_user_loses_the_session_and_the_tokens() {
    let Some((s, _rt)) = with_db("api_auth_disable") else {
        return;
    };
    let c = setup(&s);
    let put = handle(
        &s,
        &cookie(
            with_body(
                req("PUT", "/v1/admin/users/ops"),
                json!({"role": "operator", "password": PASSWORD}),
            ),
            &c,
        ),
    );
    assert_eq!(put.status, 200, "{:?}", String::from_utf8_lossy(&put.body));
    let ok = handle(
        &s,
        &with_body(
            req("POST", "/v1/auth/login"),
            json!({"name": "ops", "password": PASSWORD}),
        ),
    );
    let ops = session_of(&ok);
    let t = new_token(&s, &ops, &["rsim.read", "rsim.scenario.write"]);
    assert_eq!(
        handle(&s, &cookie(req("GET", "/v1/admin/users"), &ops)).status,
        403
    );
    handle(
        &s,
        &cookie(
            with_body(
                req("PUT", "/v1/admin/users/ops"),
                json!({"role": "operator", "disabled": true}),
            ),
            &c,
        ),
    );
    assert_eq!(
        handle(&s, &cookie(req("GET", "/v1/twins"), &ops)).status,
        401
    );
    assert_eq!(handle(&s, &bearer(req("GET", "/v1/twins"), &t)).status, 401);
}

#[test]
fn a_cookie_request_that_changes_data_needs_its_origin() {
    let Some((s, _rt)) = with_db("api_auth_origin") else {
        return;
    };
    let c = setup(&s);
    let mut r = cookie(req("POST", "/v1/auth/logout"), &c);
    r.headers.remove("origin");
    let no_origin = handle(&s, &r);
    assert_eq!(no_origin.status, 403);
    assert_eq!(json(&no_origin)["code"], "forbidden_origin");
    r.headers
        .insert("origin".into(), "https://evil.example".into());
    assert_eq!(handle(&s, &r).status, 403);
}

#[test]
fn behind_a_trusted_proxy_the_cookie_is_secure_and_the_host_is_public() {
    let Some((s, _rt)) = with_db("api_auth_proxy") else {
        return;
    };
    let through = |r: Request, peer: &str| {
        let mut r = r;
        r.peer = Some(peer.parse::<IpAddr>().unwrap());
        r.headers.insert("host".into(), "rsim.example.net".into());
        if r.headers.contains_key("origin") {
            r.headers.insert("origin".into(), PUBLIC.into());
        }
        r.headers.insert("x-forwarded-proto".into(), "https".into());
        r.headers
            .insert("x-forwarded-for".into(), "203.0.113.9, 10.42.0.3".into());
        r
    };
    let body = json!({"name": "admin", "password": PASSWORD});
    let r = handle(
        &s,
        &through(with_body(req("POST", "/v1/auth/setup"), body), PROXY),
    );
    assert_eq!(r.status, 201);
    let set = r.header("set-cookie").unwrap();
    assert!(set.starts_with(&format!("{COOKIE_HTTPS}=")) && set.contains("; Secure"));
    assert!(r.header("strict-transport-security").is_some());
    let c = session_of(&r);
    let me = handle(&s, &through(cookie(req("GET", "/v1/auth/me"), &c), PROXY));
    assert_eq!(me.status, 200);
    let ev = json(&handle(
        &s,
        &through(cookie(req("GET", "/v1/admin/events"), &c), PROXY),
    ));
    assert_eq!(ev["events"][0]["client"], "203.0.113.9");
    // A peer that is not a trusted proxy: no HTTPS, so the secure cookie
    // is not read, and the public host is still a host of the server.
    let direct = handle(
        &s,
        &through(cookie(req("GET", "/v1/auth/me"), &c), "192.0.2.50"),
    );
    assert_eq!(direct.status, 401);
}

#[test]
fn the_probes_accept_each_host_and_other_routes_do_not() {
    let s = State::new(settings());
    let mut r = req("GET", "/healthz");
    r.headers.insert("host".into(), "10.42.1.5:8787".into());
    assert_eq!(handle(&s, &r).status, 200);
    r.path = "/v1/twins".into();
    assert_eq!(handle(&s, &r).status, 403);
    r.headers.insert("host".into(), "rsim.example.net".into());
    assert_eq!(handle(&s, &r).status, 200);
}

#[test]
fn with_no_database_the_server_has_no_sign_in() {
    let s = State::new(settings());
    assert_eq!(handle(&s, &req("GET", "/v1/twins")).status, 200);
    let setup = json(&handle(&s, &req("GET", "/v1/auth/setup")));
    assert_eq!(setup, json!({"open": false, "sign_in": false}));
}
