//! The REST API: the stored answers through the query resources, the
//! caching, the security checks, the problem details, the store alias, the
//! OpenAPI document and one real server on a loopback port.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use rsim_api::handler::{Request, Response, Settings, State, handle};
use serde_json::{Value, json};

#[path = "../../rsim-cli/tests/support/fixture_store.rs"]
mod fixture_store;

const PORT: u16 = 8787;

fn state(store: Option<String>) -> State {
    State::new(Settings {
        listen: ([127, 0, 0, 1], PORT).into(),
        store,
        allow_origins: vec!["http://localhost:3000".into()],
        max_body: 64 * 1024,
    })
}

fn req(method: &str, path: &str) -> Request {
    let (path, q) = path.split_once('?').unwrap_or((path, ""));
    Request {
        method: method.into(),
        path: path.into(),
        query: q
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (k, v) = p.split_once('=').unwrap_or((p, ""));
                (k.to_string(), v.to_string())
            })
            .collect(),
        headers: BTreeMap::from([("host".to_string(), format!("127.0.0.1:{PORT}"))]),
        body: Vec::new(),
    }
}

fn get(s: &State, path: &str) -> Response {
    handle(s, &req("GET", path))
}

fn post(s: &State, path: &str, body: &Value) -> Response {
    let mut r = req("POST", path);
    r.body = body.to_string().into_bytes();
    handle(s, &r)
}

fn json(r: &Response) -> Value {
    serde_json::from_slice(&r.body)
        .unwrap_or_else(|e| panic!("{e}: {:?}", String::from_utf8_lossy(&r.body)))
}

fn golden() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rsim-cli/tests/golden");
    let mut v: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            let n = p.file_name().unwrap().to_string_lossy();
            n.ends_with(".json")
                && !n.ends_with(".summary.json")
                && !n.ends_with(".steps.json")
                && !n.starts_with("claim-")
        })
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read_to_string(&p).unwrap(),
            )
        })
        .collect();
    v.sort();
    v
}

/// The query resource of a stored answer: its location.
fn make_query(s: &State, stored: &Value) -> String {
    let mut body = stored["query"].as_object().unwrap().clone();
    body.retain(|_, v| !v.is_null());
    body.remove("topology");
    if stored["kind"] == "set_answer" {
        body.insert("mode".into(), json!("set"));
    }
    let twin = format!("builtin.{}", stored["topology"].as_str().unwrap());
    let r = post(
        s,
        &format!("/v1/twins/{twin}/queries"),
        &Value::Object(body),
    );
    assert_eq!(r.status, 303, "{}", String::from_utf8_lossy(&r.body));
    r.header("location").unwrap().to_string()
}

#[test]
fn each_stored_query_gives_the_stored_bytes_through_its_resource() {
    let s = state(None);
    let files = golden();
    assert!(files.len() >= 10);
    for (name, text) in files {
        let stored: Value = serde_json::from_str(&text).unwrap();
        let location = make_query(&s, &stored);
        let r = get(&s, &format!("{location}?form=full"));
        assert_eq!(r.status, 200, "{name}");
        assert_eq!(r.header("content-type"), Some("application/json"));
        assert_eq!(
            String::from_utf8(r.body).unwrap(),
            text.trim_end_matches('\n'),
            "{name}"
        );
        // The default form is the summary.
        let r = get(&s, &location);
        assert!(
            json(&r)["kind"].as_str().unwrap().ends_with("_brief"),
            "{name}"
        );
    }
}

#[test]
fn a_step_and_a_claim_have_urls_below_their_query() {
    let s = state(None);
    let stored: Value = serde_json::from_str(
        &golden()
            .into_iter()
            .find(|(n, _)| n == "leaf-spine.json")
            .unwrap()
            .1,
    )
    .unwrap();
    let q = make_query(&s, &stored);
    let step = json(&get(&s, &format!("{q}/branches/0/steps/3")));
    assert_eq!(step["kind"], "step");
    assert_eq!(
        step["trace_step"],
        stored["answer"]["branches"][0]["steps"][3]
    );
    let claim = json(&get(&s, &format!("{q}/claims/no-unknown")));
    assert_eq!(
        (claim["kind"].as_str(), claim["result"].as_str()),
        (Some("claim"), Some("confirmed"))
    );
    let claim = json(&get(&s, "/v1/twins/builtin.leaf-spine/claims/bgp-peers-up"));
    assert_eq!(claim["result"], "unknown");
    let rows = json(&get(
        &s,
        "/v1/twins/builtin.leaf-spine/tables/fib/lpm?address=10.2.0.10&device=leaf1",
    ));
    assert_eq!(rows["rows"][0][2], "10.2.0.0/24");
    // A long query gets a hash identifier, which the server keeps.
    let long = json!({
        "mode": "set",
        "source.ip": (0..120).map(|i| format!("10.1.{i}.0/24")).collect::<Vec<_>>().join(","),
        "destination.ip": "10.2.0.10",
        "network.transport": "tcp"
    });
    let r = post(&s, "/v1/twins/builtin.leaf-spine/queries", &long);
    let loc = r.header("location").unwrap().to_string();
    assert!(loc.rsplit('/').next().unwrap().starts_with('h'), "{loc}");
    assert_eq!(get(&s, &loc).status, 200);
}

#[test]
fn an_equal_etag_gives_304() {
    let s = state(None);
    let r = get(&s, "/v1/twins/builtin.ecmp/tables/devices/rows");
    assert_eq!(r.status, 200);
    let tag = r.header("etag").unwrap().to_string();
    assert!(tag.starts_with("\"builtin.ecmp."), "{tag}");
    let mut again = req("GET", "/v1/twins/builtin.ecmp/tables/devices/rows");
    again.headers.insert("if-none-match".into(), tag);
    let r = handle(&s, &again);
    assert_eq!(r.status, 304);
    assert!(r.body.is_empty());
}

#[test]
fn the_security_checks_refuse_a_foreign_origin_a_foreign_host_and_a_large_body() {
    let s = state(None);
    let mut r = req("GET", "/v1");
    r.headers
        .insert("origin".into(), "http://evil.example".into());
    let res = handle(&s, &r);
    assert_eq!(
        (res.status, json(&res)["code"].as_str()),
        (403, Some("forbidden_origin"))
    );
    r.headers
        .insert("origin".into(), "http://localhost:3000".into());
    let res = handle(&s, &r);
    assert_eq!(res.status, 200);
    assert_eq!(
        res.header("access-control-allow-origin"),
        Some("http://localhost:3000")
    );
    let mut r = req("GET", "/v1");
    r.headers
        .insert("host".into(), "rebind.example:8787".into());
    let res = handle(&s, &r);
    assert_eq!(
        (res.status, json(&res)["code"].as_str()),
        (403, Some("forbidden_host"))
    );
    let mut r = req("POST", "/v1/twins/builtin.ecmp/queries");
    r.body = vec![b' '; 64 * 1024 + 1];
    assert_eq!(handle(&s, &r).status, 413);
}

#[test]
fn errors_are_problem_objects() {
    let s = state(None);
    for (method, path, status, code) in [
        ("GET", "/v1/nothing", 404, "not_found"),
        ("GET", "/v1/twins/builtin.nothing", 404, "unknown_twin"),
        ("GET", "/v1/twins/snap-3", 404, "unknown_twin"),
        ("GET", "/v1/twins/store", 404, "unknown_twin"),
        (
            "GET",
            "/v1/twins/builtin.ecmp/tables/colours/rows",
            404,
            "unknown_table",
        ),
        (
            "GET",
            "/v1/twins/builtin.ecmp/tables/fib/rows?colour=red",
            422,
            "invalid_filter",
        ),
        (
            "GET",
            "/v1/twins/builtin.ecmp/queries/qnotbase64*",
            404,
            "no_such_query",
        ),
        ("POST", "/v1/tables", 405, "method_not_allowed"),
    ] {
        let r = handle(&s, &req(method, path));
        assert_eq!(r.status, status, "{path}");
        assert_eq!(
            r.header("content-type"),
            Some("application/problem+json"),
            "{path}"
        );
        let p = json(&r);
        assert_eq!(p["code"], code, "{path}");
        assert_eq!(p["type"], format!("urn:rsim:error:{code}"), "{path}");
        assert_eq!(p["status"], status, "{path}");
    }
    let r = post(
        &s,
        "/v1/twins/builtin.ecmp/queries",
        &json!({"source.ip": "x"}),
    );
    assert_eq!(
        (r.status, json(&r)["code"].as_str()),
        (422, Some("invalid_query"))
    );
    let mut r = req("POST", "/v1/twins/builtin.ecmp/queries");
    r.body = b"not json".to_vec();
    assert_eq!(handle(&s, &r).status, 400);
}

#[test]
fn the_store_alias_redirects_to_its_snapshot() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("rsim-api-store");
    fixture_store::write(&dir);
    let s = state(Some(dir.display().to_string()));
    let r = get(&s, "/v1/twins/store/tables/devices/rows");
    assert_eq!(r.status, 307);
    let location = r.header("location").unwrap().to_string();
    assert!(location.starts_with("/v1/twins/snap-"), "{location}");
    assert!(location.ends_with("/tables/devices/rows"), "{location}");
    let rows = json(&get(&s, &location));
    assert_eq!(rows["twin"]["id"], location.split('/').nth(3).unwrap());
    assert_eq!(rows["topology"], "store");
    let cov = json(&get(&s, &location.replace("devices", "coverage")));
    assert!(cov["total"].as_u64().unwrap() > 0);
    assert_eq!(
        get(&s, "/v1/twins/snap-999999/tables/devices/rows").status,
        404
    );
}

/// Each `$ref` in `v` names a schema of `components`.
fn refs(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::Object(m) => {
            if let Some(Value::String(r)) = m.get("$ref") {
                out.insert(r.clone());
            }
            m.values().for_each(|c| refs(c, out));
        }
        Value::Array(a) => a.iter().for_each(|c| refs(c, out)),
        _ => {}
    }
}

#[test]
fn the_openapi_document_is_current_and_consistent() {
    let doc = rsim_api::openapi::document();
    let committed =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("openapi.json"))
            .unwrap();
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    assert_eq!(
        text, committed,
        "the OpenAPI document changed; make crates/rsim-api/openapi.json again with the test output"
    );
    assert_eq!(doc["openapi"], "3.1.0");
    // Each reference resolves.
    let mut all = BTreeSet::new();
    refs(&doc, &mut all);
    let schemas = doc["components"]["schemas"].as_object().unwrap();
    for r in &all {
        let name = r
            .strip_prefix("#/components/schemas/")
            .unwrap_or_else(|| panic!("{r}"));
        assert!(schemas.contains_key(name), "{r} does not resolve");
    }
    // Each operation identifier is unique.
    let mut ids = BTreeSet::new();
    for (_, item) in doc["paths"].as_object().unwrap() {
        for (_, op) in item.as_object().unwrap() {
            assert!(ids.insert(op["operationId"].as_str().unwrap().to_string()));
        }
    }
    // Each schema compiles as JSON Schema 2020-12, with the components as
    // its context.
    let mut root = json!({"$schema": "https://json-schema.org/draft/2020-12/schema", "components": doc["components"].clone()});
    root["$id"] = json!("urn:rsim:openapi");
    for name in schemas.keys() {
        let mut schemas_c = boon::Schemas::new();
        let mut compiler = boon::Compiler::new();
        compiler
            .add_resource("urn:rsim:openapi", root.clone())
            .unwrap();
        compiler
            .compile(
                &format!("urn:rsim:openapi#/components/schemas/{name}"),
                &mut schemas_c,
            )
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    // Each operation of the registry with an HTTP path is in the document.
    let paths: Vec<(String, Vec<String>)> = doc["paths"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(p, item)| {
            (
                p.clone(),
                item.as_object().unwrap().keys().cloned().collect(),
            )
        })
        .collect();
    let same = |a: &str, b: &str| {
        let (x, y): (Vec<&str>, Vec<&str>) = (a.split('/').collect(), b.split('/').collect());
        x.len() == y.len()
            && x.iter()
                .zip(&y)
                .all(|(s, t)| s == t || s.starts_with('{') || t.starts_with('{'))
    };
    for op in rsim_contract::registry::OPERATIONS {
        let Some((m, p)) = op.http else { continue };
        let m = format!("{m:?}").to_lowercase();
        assert!(
            paths.iter().any(|(dp, ms)| same(dp, p) && ms.contains(&m)),
            "{} {m} {p} is not in the document",
            op.id
        );
    }
}

#[test]
fn a_listen_address_that_is_not_loopback_is_refused() {
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_rsim-api"))
        .args(["--listen", "0.0.0.0:0"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("not a loopback address"));
}

#[test]
#[allow(clippy::disallowed_types)]
fn a_real_server_answers_on_a_loopback_port() {
    use std::io::{Read, Write};
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .build()
        .unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let s = std::sync::Arc::new(State::new(Settings {
        listen: addr,
        store: None,
        allow_origins: Vec::new(),
        max_body: 1024,
    }));
    rt.spawn(rsim_api::server::serve(listener, s));
    let ask = |text: String| -> String {
        let mut c = std::net::TcpStream::connect(addr).unwrap();
        c.write_all(text.as_bytes()).unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).unwrap();
        out
    };
    let r = ask(format!(
        "GET /v1/twins/builtin.ecmp/tables/devices/rows?columns=device HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    ));
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    assert!(r.contains("\"columns\":[\"device\"]"), "{r}");
    let body = "x".repeat(2048);
    let r = ask(format!(
        "POST /v1/twins/builtin.ecmp/queries HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    assert!(r.starts_with("HTTP/1.1 413"), "{r}");
    // A raw character of more than one byte after a percent sign.
    let r = ask(format!(
        "GET /v1/twins/builtin.ecmp/tables/devices/rows?x=%1\u{e9} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    ));
    assert!(r.starts_with("HTTP/1.1 422"), "{r}");
    rt.shutdown_background();
}

fn stored_api(name: &str) -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/golden")
            .join(name),
    )
    .unwrap()
}

#[test]
fn the_topology_and_the_path_drawing_give_the_stored_files() {
    let s = state(None);
    let r = get(
        &s,
        "/v1/twins/builtin.leaf-spine/topology?claims=link-speed-duplex",
    );
    assert_eq!(r.status, 200);
    assert_eq!(
        String::from_utf8(r.body).unwrap(),
        stored_api("leaf-spine.topology.json")
    );
    let q = post(
        &s,
        "/v1/twins/builtin.leaf-spine/queries",
        &json!({"source.ip": "10.1.0.10", "destination.ip": "10.2.0.10",
                "network.transport": "tcp", "source.port": 40000, "destination.port": 22}),
    );
    let loc = q.header("location").unwrap().to_string();
    let r = get(&s, &format!("{loc}/topology"));
    let body = String::from_utf8(r.body).unwrap();
    assert_eq!(body, stored_api("leaf-spine.path.json"));
    let d: Value = serde_json::from_str(&body).unwrap();
    let edges = d["edges"].as_array().unwrap();
    let overlay: Vec<&Value> = edges.iter().filter(|e| e["layer"] == "overlay").collect();
    assert_eq!(overlay.len(), 1);
    assert_eq!(
        (overlay[0]["from"].as_str(), overlay[0]["to"].as_str()),
        (Some("leaf1"), Some("leaf2"))
    );
    let underlay: Vec<&Value> = edges.iter().filter(|e| e["layer"] == "underlay").collect();
    assert_eq!(underlay.len(), 4);
    assert!(
        underlay
            .iter()
            .all(|e| e["overlay"] == "overlay:leaf1>leaf2")
    );
    // The exports.
    let r = get(
        &s,
        "/v1/twins/builtin.leaf-spine/topology?format=mermaid&layer=overlay",
    );
    assert_eq!(r.header("content-type"), Some("text/plain; charset=utf-8"));
    assert!(
        String::from_utf8(r.body)
            .unwrap()
            .contains("leaf1 -.-> leaf2")
    );
    let r = get(&s, "/v1/twins/builtin.leaf-spine/topology?format=graphml");
    assert!(String::from_utf8(r.body).unwrap().starts_with("<?xml"));
    // A neighbourhood and a filter that the view does not have.
    let r = json(&get(
        &s,
        "/v1/twins/builtin.leaf-spine/topology?around=leaf1&hops=1",
    ));
    assert_eq!(r["nodes"].as_array().unwrap().len(), 3);
    let r = get(&s, "/v1/twins/builtin.leaf-spine/topology?level=site");
    assert_eq!(
        (r.status, json(&r)["code"].as_str()),
        (422, Some("invalid_filter"))
    );
}

#[test]
fn each_underlay_edge_of_a_drawing_names_the_overlay_edge_of_its_own_tunnel() {
    let s = state(None);
    let q = post(
        &s,
        "/v1/twins/builtin.leaf-spine/queries",
        &json!({"mode": "set", "source.ip": "10.1.0.10", "destination.ip": "10.2.0.10,10.3.0.10",
                "network.transport": "tcp", "destination.port": 22}),
    );
    let loc = q.header("location").unwrap().to_string();
    let d = json(&get(&s, &format!("{loc}/topology")));
    let edges = d["edges"].as_array().unwrap();
    let mut overlays: Vec<&str> = edges
        .iter()
        .filter(|e| e["layer"] == "overlay")
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    overlays.sort();
    assert_eq!(overlays, ["overlay:leaf1>leaf2", "overlay:leaf1>leaf3"]);
    let branches = |e: &Value| -> Vec<u64> {
        e["branches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_u64().unwrap())
            .collect()
    };
    let underlay: Vec<&Value> = edges.iter().filter(|e| e["layer"] == "underlay").collect();
    for e in &underlay {
        let Some(o) = e["overlay"].as_str() else {
            continue;
        };
        let o = edges.iter().find(|x| x["id"] == o).unwrap();
        if e["to"] == "leaf2" || e["to"] == "leaf3" {
            assert_eq!(e["to"], o["to"], "{e}");
        }
        assert!(
            branches(e).iter().all(|b| branches(o).contains(b)),
            "{e} {o}"
        );
    }
    // leaf1 to spine1 carries both tunnels: one underlay edge for each.
    let first: Vec<&str> = underlay
        .iter()
        .filter(|e| e["from"] == "leaf1" && e["to"] == "spine1")
        .map(|e| e["overlay"].as_str().unwrap())
        .collect();
    assert_eq!(first.len(), 2, "{first:?}");
    assert_ne!(first[0], first[1]);
    // spine2 drops the tunnel to leaf3: its hop names no overlay edge.
    let dropped = underlay
        .iter()
        .find(|e| e["id"] == "underlay:leaf1>spine2:leaf1")
        .unwrap();
    assert!(dropped["overlay"].is_null());
}

#[test]
fn a_batch_gives_one_line_for_each_item() {
    let s = state(None);
    let r = post(
        &s,
        "/v1/twins/builtin.leaf-spine/batch",
        &json!({"items": [
            {"op": "query", "query": {"source.ip": "10.1.0.10", "destination.ip": "10.3.0.10", "network.transport": "udp", "destination.port": 53}},
            {"op": "claim", "claim": "bgp-peers-up"},
            {"op": "table", "table": "fib", "verb": "lpm", "address": "10.2.0.10", "filters": {"device": ["leaf1"]}},
            {"op": "nothing"}
        ]}),
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("application/x-ndjson"));
    let lines: Vec<Value> = String::from_utf8(r.body)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[0]["kind"], "path_brief");
    assert_eq!(lines[1]["kind"], "claim");
    assert_eq!(lines[2]["rows"][0][2], "10.2.0.0/24");
    assert_eq!(lines[3]["code"], "invalid_query");
    let many: Vec<Value> = (0..101)
        .map(|_| json!({"op": "claim", "claim": "bgp-peers-up"}))
        .collect();
    let r = post(
        &s,
        "/v1/twins/builtin.leaf-spine/batch",
        &json!({"items": many}),
    );
    assert_eq!(r.status, 413);
}

fn mcp(s: &State, body: &Value, headers: &[(&str, &str)]) -> Response {
    let mut r = req("POST", "/mcp");
    r.body = body.to_string().into_bytes();
    for (k, v) in headers {
        r.headers.insert((*k).to_string(), (*v).to_string());
    }
    handle(s, &r)
}

fn meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "rsim-test", "version": "1"}
    })
}

#[test]
fn the_mcp_tools_answer_through_the_streamable_http_transport() {
    let s = state(None);
    let v = "2026-07-28";
    let list =
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": meta()}});
    let r = mcp(
        &s,
        &list,
        &[("mcp-protocol-version", v), ("mcp-method", "tools/list")],
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let names: Vec<String> = json(&r)["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert!(names.contains(&"path_query".to_string()), "{names:?}");
    let call = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "_meta": meta(),
        "name": "table_query",
        "arguments": {"topology": "leaf-spine", "table": "fib", "verb": "lpm", "address": "10.2.0.10", "filters": {"device": ["leaf1"]}}
    }});
    let r = mcp(
        &s,
        &call,
        &[
            ("mcp-protocol-version", v),
            ("mcp-method", "tools/call"),
            ("mcp-name", "table_query"),
        ],
    );
    assert_eq!(r.status, 200);
    let out = json(&r);
    assert_eq!(out["id"], 2);
    assert_eq!(
        out["result"]["structuredContent"]["rows"][0][2],
        "10.2.0.0/24"
    );
    // A notification gets 202 with no body.
    let note =
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"_meta": meta()}});
    let r = mcp(
        &s,
        &note,
        &[
            ("mcp-protocol-version", v),
            ("mcp-method", "notifications/cancelled"),
        ],
    );
    assert_eq!((r.status, r.body.len()), (202, 0));
    // The headers must agree with the body.
    for (headers, code) in [
        (vec![("mcp-method", "tools/list")], -32020),
        (
            vec![
                ("mcp-protocol-version", "2025-11-25"),
                ("mcp-method", "tools/list"),
            ],
            -32022,
        ),
        (
            vec![("mcp-protocol-version", v), ("mcp-method", "tools/call")],
            -32020,
        ),
    ] {
        let r = mcp(&s, &list, &headers);
        assert_eq!(r.status, 400, "{headers:?}");
        assert_eq!(json(&r)["error"]["code"], code, "{headers:?}");
    }
    let r = mcp(
        &s,
        &call,
        &[
            ("mcp-protocol-version", v),
            ("mcp-method", "tools/call"),
            ("mcp-name", "path_query"),
        ],
    );
    assert_eq!(json(&r)["error"]["code"], -32020);
    // GET is not a method of the transport, and the origin check applies.
    assert_eq!(get(&s, "/mcp").status, 405);
    let r = mcp(
        &s,
        &list,
        &[
            ("mcp-protocol-version", v),
            ("mcp-method", "tools/list"),
            ("origin", "http://evil.example"),
        ],
    );
    assert_eq!(r.status, 403);
}

#[test]
fn the_table_verbs_filter_by_device_and_check_their_numbers() {
    let s = state(None);
    let device = |v: &Value| -> Vec<String> {
        let i = v["columns"]
            .as_array()
            .unwrap()
            .iter()
            .position(|c| c == "device")
            .unwrap();
        v["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r[i].as_str().unwrap().to_string())
            .collect()
    };
    let all = json(&get(&s, "/v1/twins/builtin.leaf-spine/tables/fib/rows"));
    let one = json(&get(
        &s,
        "/v1/twins/builtin.leaf-spine/tables/fib/rows?device=leaf1",
    ));
    assert!(one["total"].as_u64().unwrap() < all["total"].as_u64().unwrap());
    assert!(device(&one).iter().all(|d| d == "leaf1"), "{one}");
    let lpm = json(&get(
        &s,
        "/v1/twins/builtin.leaf-spine/tables/fib/lpm?address=10.2.0.10&device=leaf1",
    ));
    assert!(!device(&lpm).is_empty(), "{lpm}");
    assert!(device(&lpm).iter().all(|d| d == "leaf1"), "{lpm}");
    let top = json(&get(
        &s,
        "/v1/twins/builtin.leaf-spine/tables/fib/top?column=prefix&device=leaf2",
    ));
    assert!(!device(&top).is_empty(), "{top}");
    assert!(device(&top).iter().all(|d| d == "leaf2"), "{top}");
    let r = get(
        &s,
        "/v1/twins/builtin.leaf-spine/tables/fib/top?column=prefix&count=abc",
    );
    assert_eq!(
        (r.status, json(&r)["code"].as_str()),
        (422, Some("invalid_filter"))
    );
}

#[test]
fn a_mode_that_is_not_path_or_set_is_refused() {
    let s = state(None);
    let q = |mode: Value| json!({"mode": mode, "source.ip": "10.1.0.10", "destination.ip": "10.2.0.10", "network.transport": "tcp"});
    for mode in [json!("Set"), json!(true)] {
        let r = post(&s, "/v1/twins/builtin.leaf-spine/queries", &q(mode.clone()));
        assert_eq!(
            (r.status, json(&r)["code"].as_str()),
            (422, Some("invalid_query")),
            "{mode}"
        );
        let qid = rsim_api::qid::of(&q(mode.clone()).to_string());
        for tail in ["", "/claims/no-unknown", "/topology", "/branches/0/steps/0"] {
            let r = get(
                &s,
                &format!("/v1/twins/builtin.leaf-spine/queries/{qid}{tail}"),
            );
            assert_eq!(r.status, 422, "{mode} {tail}");
        }
        let body = json!({"items": [{"op": "query", "query": q(mode.clone())}]});
        let r = post(&s, "/v1/twins/builtin.leaf-spine/batch", &body);
        let line: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(line["status"], 422, "{mode}");
    }
    let r = post(
        &s,
        "/v1/twins/builtin.leaf-spine/queries",
        &q(json!("path")),
    );
    assert_eq!(r.status, 303);
}

#[test]
fn the_store_alias_keeps_the_query_of_the_request() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("rsim-api-store-query");
    fixture_store::write(&dir);
    let s = state(Some(dir.display().to_string()));
    let mut r = req("GET", "/v1/twins/store/tables/devices/rows");
    r.query = vec![
        ("limit".into(), "1".into()),
        ("device".into(), "a&b c+=\u{e9}".into()),
    ];
    let res = handle(&s, &r);
    assert_eq!(res.status, 307);
    let location = res.header("location").unwrap();
    let (path, query) = location.split_once('?').unwrap();
    assert!(path.starts_with("/v1/twins/snap-"), "{location}");
    assert_eq!(query, "limit=1&device=a%26b%20c%2B%3D%C3%A9");
    let rows = json(&get(&s, &format!("{path}?limit=1")));
    assert_eq!(rows["rows"].as_array().unwrap().len(), 1);
}

#[test]
#[allow(clippy::disallowed_methods)]
fn the_mcp_tools_and_the_rest_routes_share_the_twins() {
    let base = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    let dir = base.join("rsim-api-store-shared");
    let moved = base.join("rsim-api-store-shared-moved");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&moved);
    fixture_store::write(&dir);
    let s = state(Some(dir.display().to_string()));
    let r = get(&s, "/v1/twins/store");
    assert_eq!(r.status, 307);
    let id = r
        .header("location")
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    // The store folder is gone, so only a twin that the server holds
    // answers.
    std::fs::rename(&dir, &moved).unwrap();
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "_meta": meta(),
        "name": "list_devices",
        "arguments": {"topology": "store"}
    }});
    let r = mcp(
        &s,
        &call,
        &[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/call"),
            ("mcp-name", "list_devices"),
        ],
    );
    let out = json(&r);
    assert_eq!(out["result"]["isError"], false, "{out}");
    assert_eq!(
        out["result"]["structuredContent"]["twin"]["id"],
        id.as_str()
    );
}

#[test]
fn the_mcp_transport_works_from_an_allowed_origin_and_answers_only_its_revision() {
    let s = state(None);
    let mut r = req("OPTIONS", "/mcp");
    r.headers
        .insert("origin".into(), "http://localhost:3000".into());
    let res = handle(&s, &r);
    assert_eq!(res.status, 204);
    let allowed: Vec<String> = res
        .header("access-control-allow-headers")
        .unwrap()
        .split(',')
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    for h in [
        "content-type",
        "mcp-protocol-version",
        "mcp-method",
        "mcp-name",
    ] {
        assert!(allowed.iter().any(|a| a == h), "{h}: {allowed:?}");
    }
    // The transport has no handshake: initialize is not a method.
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}
    }});
    let r = mcp(
        &s,
        &init,
        &[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "initialize"),
        ],
    );
    let out = json(&r);
    assert_eq!(out["error"]["code"], -32601, "{out}");
    assert!(out.get("result").is_none(), "{out}");
    // A header error answers an id that is not a string or a number with
    // null.
    for id in [json!({"x": 1}), json!([1]), json!(true)] {
        let list = json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {"_meta": meta()}});
        let r = mcp(&s, &list, &[("mcp-method", "tools/list")]);
        assert_eq!(r.status, 400);
        assert_eq!(json(&r)["id"], Value::Null, "{id}");
    }
}

#[test]
fn the_tools_refuse_an_argument_that_is_not_in_their_schema() {
    let s = state(None);
    let call = |name: &str, arguments: Value| {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "_meta": meta(), "name": name, "arguments": arguments
        }});
        json(&mcp(
            &s,
            &body,
            &[
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/call"),
                ("mcp-name", name),
            ],
        ))
    };
    let out = call(
        "table_query",
        json!({"topology": "leaf-spine", "table": "fib", "device": ["leaf1"]}),
    );
    assert_eq!(out["result"]["isError"], true, "{out}");
    let out = call(
        "get_topology",
        json!({"topology": "leaf-spine", "device": ["leaf1"]}),
    );
    assert_eq!(out["result"]["isError"], true, "{out}");
    let out = call(
        "table_query",
        json!({"topology": "leaf-spine", "table": "fib", "verb": "show",
            "filters": {"device": ["leaf1"]}, "typed": {"prefix.in_prefix": "10.0.0.0/8"},
            "columns": ["device", "prefix"], "sort": ["prefix"], "limit": 2, "cursor": null}),
    );
    assert_eq!(out["result"]["isError"], false, "{out}");
    let out = call(
        "get_topology",
        json!({"topology": "leaf-spine", "devices": ["leaf1"]}),
    );
    assert_eq!(out["result"]["isError"], false, "{out}");
    let body = json!({"items": [{"op": "table", "table": "fib", "device": ["leaf1"]}]});
    let r = post(&s, "/v1/twins/builtin.leaf-spine/batch", &body);
    let line: Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(line["status"], 422, "{line}");
}

/// Kills the child process when the test ends.
struct Kill(std::process::Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[allow(clippy::disallowed_types)]
fn a_server_on_port_0_accepts_the_host_of_its_port() {
    use std::io::{BufRead, Read, Write};
    let mut child = Kill(
        std::process::Command::new(env!("CARGO_BIN_EXE_rsim-api"))
            .args(["--listen", "127.0.0.1:0"])
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut line = String::new();
    std::io::BufReader::new(child.0.stderr.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let addr = line.trim().rsplit("http://").next().unwrap().to_string();
    let mut c = std::net::TcpStream::connect(&addr).unwrap();
    c.write_all(
        format!("GET /v1 HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .unwrap();
    let mut out = String::new();
    c.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
}
