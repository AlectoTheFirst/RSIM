//! The browser UI: the page and each built file at its path with its media
//! type, the checks of the host and the origin, and the API routes that
//! stay as they are.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rsim_api::handler::{Request, Response, Settings, State, handle};
use serde_json::json;

const PORT: u16 = 8787;

fn state() -> State {
    State::new(Settings {
        listen: ([127, 0, 0, 1], PORT).into(),
        store: None,
        allow_origins: vec!["http://localhost:3000".into()],
        max_body: 64 * 1024,
        public_origins: Vec::new(),
        trusted_proxies: Vec::new(),
    })
}

fn req(method: &str, path: &str) -> Request {
    Request {
        method: method.into(),
        path: path.into(),
        query: Vec::new(),
        headers: BTreeMap::from([("host".to_string(), format!("127.0.0.1:{PORT}"))]),
        body: Vec::new(),
        peer: None,
    }
}

fn get(s: &State, path: &str) -> Response {
    handle(s, &req("GET", path))
}

fn dist() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../ui/dist")
}

fn walk(dir: &Path, base: &Path, out: &mut BTreeSet<String>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            walk(&p, base, out);
        } else {
            let rel = p
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(format!("/{rel}"));
        }
    }
}

fn media_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("ttf") => "font/ttf",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "",
    }
}

#[test]
fn the_page_is_served_at_the_root_with_its_policy() {
    let s = state();
    let r = get(&s, "/");
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"));
    assert_eq!(
        r.header("content-security-policy"),
        Some(rsim_api::ui::CONTENT_SECURITY_POLICY)
    );
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    let body = String::from_utf8(r.body).unwrap();
    assert!(body.contains("<title>rsim</title>"), "{body}");
    assert!(!body.contains("fonts.googleapis.com"), "{body}");
    assert_eq!(get(&s, "/index.html").body, body.as_bytes());
}

#[test]
fn each_built_file_is_served_with_its_media_type() {
    if std::env::var("RSIM_UI_REQUIRED").as_deref() == Ok("1") {
        assert!(rsim_api::ui::built(), "the binary has no built UI");
    }
    if !rsim_api::ui::built() {
        return;
    }
    let s = state();
    let mut built = BTreeSet::new();
    walk(&dist(), &dist(), &mut built);
    let served: BTreeSet<String> = rsim_api::ui::files().map(|f| f.path.to_string()).collect();
    assert_eq!(served, built, "the served files are the files of ui/dist");
    for path in &built {
        let r = get(&s, path);
        assert_eq!(r.status, 200, "{path}");
        assert_eq!(r.header("content-type"), Some(media_type(path)), "{path}");
        let disk = std::fs::read(dist().join(path.trim_start_matches('/'))).unwrap();
        assert_eq!(r.body, disk, "{path}");
    }
    // Each script and style of the page is served, and none is inline.
    let page = String::from_utf8(get(&s, "/").body).unwrap();
    for attr in ["src=\"", "href=\""] {
        for part in page.split(attr).skip(1) {
            let target = part.split('"').next().unwrap();
            assert_eq!(get(&s, target).status, 200, "{target}");
        }
    }
    assert!(!page.contains("<script>"), "{page}");
    assert!(!page.contains("<style"), "{page}");
}

#[test]
fn an_unknown_file_a_foreign_host_and_a_write_are_refused() {
    let s = state();
    assert_eq!(get(&s, "/assets/missing.js").status, 404);
    assert_eq!(get(&s, "/fonts/missing.ttf").status, 404);
    let mut r = req("GET", "/");
    r.headers
        .insert("host".into(), "rebind.example:8787".into());
    assert_eq!(handle(&s, &r).status, 403);
    assert_eq!(handle(&s, &req("POST", "/")).status, 405);
}

#[test]
fn the_page_runs_a_query_from_its_own_origin_and_a_foreign_origin_is_refused() {
    let s = state();
    let body = json!({"source.ip": "10.1.0.10", "destination.ip": "10.2.0.10", "network.transport": "tcp"});
    for (origin, status) in [
        ("http://127.0.0.1:8787", 303),
        ("http://localhost:8787", 303),
        ("http://127.0.0.1:9999", 403),
        ("https://127.0.0.1:8787", 403),
        ("http://evil.example", 403),
    ] {
        let mut r = req("POST", "/v1/twins/builtin.leaf-spine/queries");
        r.headers.insert("origin".into(), origin.into());
        r.body = body.to_string().into_bytes();
        assert_eq!(handle(&s, &r).status, status, "{origin}");
    }
}

#[test]
fn the_contract_has_no_ui_path() {
    let doc = rsim_api::openapi::document();
    let paths = doc["paths"].as_object().unwrap();
    assert!(
        paths.keys().all(|p| p.starts_with("/v1") || p == "/mcp"),
        "{:?}",
        paths.keys().collect::<Vec<_>>()
    );
}

#[test]
fn the_coverage_view_reads_the_report_of_a_twin_and_the_catalog() {
    let s = state();
    let r = get(&s, "/v1/twins/builtin.leaf-spine/coverage");
    assert_eq!(r.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(body["kind"], "coverage_report");
    assert_eq!(body["total"], 0);
    let catalog: serde_json::Value = serde_json::from_slice(&get(&s, "/v1/tables").body).unwrap();
    let coverage = catalog["tables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "coverage")
        .unwrap();
    assert_eq!(coverage["needs"], "a twin of a store snapshot");
}
