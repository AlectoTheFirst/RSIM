//! The inventory routes. The tests with a database need
//! `RSIM_TEST_DATABASE_URL`; with it unset they print that they are skipped
//! and pass.

use std::collections::BTreeMap;
use std::sync::Arc;

use rsim_api::handler::{Request, Response, Settings, State, handle};
use rsim_api::inventory::InventoryHandle;
use serde_json::{Value, json};

const PORT: u16 = 8787;

thread_local! {
    /// The API token of the admin of the database of the test on this
    /// thread, which `call` sends.
    static TOKEN: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

fn state() -> State {
    State::new(Settings {
        listen: ([127, 0, 0, 1], PORT).into(),
        store: None,
        allow_origins: vec![],
        max_body: 64 * 1024,
        public_origins: Vec::new(),
        trusted_proxies: Vec::new(),
    })
}

fn call(s: &State, method: &str, path: &str, body: Option<Value>) -> Response {
    let (path, q) = path.split_once('?').unwrap_or((path, ""));
    let mut r = Request {
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
        body: body.map(|b| b.to_string().into_bytes()).unwrap_or_default(),
        peer: None,
    };
    if let Some(t) = TOKEN.with(|t| t.borrow().clone()) {
        r.headers
            .insert("authorization".into(), format!("Bearer {t}"));
    }
    handle(s, &r)
}

fn json(r: &Response) -> Value {
    serde_json::from_slice(&r.body)
        .unwrap_or_else(|e| panic!("{e}: {:?}", String::from_utf8_lossy(&r.body)))
}

/// A server with the inventory database of a test, and the runtime of its
/// connection.
fn with_db(name: &str) -> Option<(State, tokio::runtime::Runtime)> {
    with_db_key(name, None)
}

/// A server with the inventory database of a test and, if given, the
/// secret key of the managed credentials.
fn with_db_key(name: &str, key: Option<&str>) -> Option<(State, tokio::runtime::Runtime)> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let db = rt.block_on(rsim_inventory::test_database(name))?;
    let token = rt.block_on(async {
        let (password, _) = rsim_inventory::new_secret("").unwrap();
        let hash = rsim_inventory::hash_password(&password).unwrap();
        let (_, session) = rsim_inventory::new_secret("").unwrap();
        let admin = db
            .setup("admin", &hash, &session, "127.0.0.1")
            .await
            .unwrap();
        let (text, th) = rsim_inventory::new_secret(rsim_inventory::TOKEN_PREFIX).unwrap();
        db.create_token(&admin, "test", &admin.scopes, None, &th)
            .await
            .unwrap();
        text
    });
    TOKEN.with(|t| *t.borrow_mut() = Some(token));
    let mut h = InventoryHandle::new(Arc::new(db), rt.handle().clone());
    if let Some(k) = key {
        h = h.with_secret_key(rsim_inventory::SecretKey::parse(k).unwrap());
    }
    let s = state().with_inventory(h);
    Some((s, rt))
}

#[test]
fn a_server_with_no_inventory_says_so() {
    let r = call(&state(), "GET", "/v1/inventory/devices", None);
    assert_eq!(r.status, 404);
    assert_eq!(json(&r)["code"], "no_inventory");
}

#[test]
fn the_vendors_with_a_collector_need_no_database() {
    let r = call(&state(), "GET", "/v1/inventory/vendors", None);
    assert_eq!(r.status, 200);
    let v = json(&r);
    let words: Vec<(&str, &str)> = v["vendors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["vendor"].as_str().unwrap(),
                x["transport"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        words,
        [
            ("equinix", "https"),
            ("iosxe", "ssh"),
            ("iosxr", "ssh"),
            ("nxos", "ssh"),
            ("unifi", "https"),
            ("velocloud", "https"),
            ("vyos", "ssh"),
        ]
    );
    let r = call(&state(), "PUT", "/v1/inventory/vendors", Some(json!({})));
    assert_eq!(r.status, 405);
}

#[test]
fn the_openapi_document_has_the_inventory_routes() {
    let doc = rsim_api::openapi::document();
    let paths = &doc["paths"];
    assert!(paths["/v1/inventory/devices"]["get"].is_object());
    assert!(paths["/v1/inventory/vendors"]["get"].is_object());
    let put = &paths["/v1/inventory/devices/{device}"]["put"];
    assert_eq!(put["security"][0]["session"][0], "rsim.inventory.write");
    assert_eq!(put["security"][1]["token"][0], "rsim.inventory.write");
    assert!(put["requestBody"].is_object());
    assert!(paths["/v1/inventory/audit"]["get"].is_object());
    assert!(
        paths["/v1/inventory/bindings/fabric-ports/{account}/{fabric_port}"]["delete"].is_object()
    );
}

#[test]
fn the_history_setting_reads_and_writes_with_its_range() {
    let put = &rsim_api::openapi::document()["paths"]["/v1/inventory/collection"]["put"];
    assert_eq!(put["security"][0]["session"][0], "rsim.inventory.write");
    let Some((s, _rt)) = with_db("api_collection") else {
        return;
    };
    let r = call(&s, "GET", "/v1/inventory/collection", None);
    assert_eq!(r.status, 200);
    assert_eq!(
        json(&r),
        json!({"version": 0, "collection": {"history_days": 30}})
    );
    let body = |days: u64| Some(json!({ "history_days": days }));
    let r = call(&s, "PUT", "/v1/inventory/collection", body(7));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(json(&r)["version"], 1);
    let inv = json(&call(&s, "GET", "/v1/inventory", None));
    assert_eq!(inv["collection"]["history_days"], 7);
    for days in [0, 3651] {
        let r = call(&s, "PUT", "/v1/inventory/collection", body(days));
        assert_eq!(r.status, 422, "{days}");
    }
    let r = call(&s, "DELETE", "/v1/inventory/collection", None);
    assert_eq!(r.status, 405);
}

#[test]
fn the_inventory_routes_write_with_an_audit_and_resolve_the_devices() {
    let Some((s, _rt)) = with_db("api_inventory_routes") else {
        return;
    };
    let ok = |r: Response| {
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        json(&r)
    };
    ok(call(
        &s,
        "PUT",
        "/v1/inventory/credentials/vyos",
        Some(json!({"source": "env", "key": "VYOS"})),
    ));
    ok(call(
        &s,
        "PUT",
        "/v1/inventory/routes/direct",
        Some(json!({})),
    ));
    ok(call(
        &s,
        "PUT",
        "/v1/inventory/groups/core",
        Some(
            json!({"vendor": "vyos", "settings": {"credential": "vyos", "capture_bgp": "all", "timeout_seconds": 90}}),
        ),
    ));
    let w = ok(call(
        &s,
        "PUT",
        "/v1/inventory/devices/r1",
        Some(
            json!({"group": "core", "address": "192.0.2.1", "site": "ams", "settings": {"route": "direct", "timeout_seconds": 120}}),
        ),
    ));
    assert_eq!(w["version"], 4);

    let d = ok(call(&s, "GET", "/v1/inventory/devices/r1", None));
    assert_eq!(d["vendor"], "vyos");
    assert_eq!(
        d["settings"]["timeout_seconds"],
        json!({"value": 120, "origin": "device"})
    );
    assert_eq!(
        d["settings"]["capture_bgp"],
        json!({"value": "all", "origin": "group"})
    );
    assert_eq!(
        d["settings"]["retries"],
        json!({"value": 0, "origin": "default"})
    );
    assert_eq!(
        d["settings"]["ha"],
        json!({"value": "none", "origin": "default"})
    );
    let all = ok(call(&s, "GET", "/v1/inventory/devices", None));
    assert_eq!(all["version"], 4);
    assert_eq!(all["devices"].as_array().unwrap().len(), 1);

    let audit = ok(call(&s, "GET", "/v1/inventory/audit?limit=2", None));
    let records = audit["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["actor"], "admin");
    assert_eq!(records[0]["kind"], "device");
    assert_eq!(records[0]["action"], "create");
    assert_eq!(records[0]["new"]["address"], "192.0.2.1");
    let next = audit["next_before"].as_i64().unwrap();
    let rest = ok(call(
        &s,
        "GET",
        &format!("/v1/inventory/audit?before={next}"),
        None,
    ));
    assert_eq!(rest["records"].as_array().unwrap().len(), 2);

    let used = call(&s, "DELETE", "/v1/inventory/groups/core", None);
    assert_eq!(used.status, 409);
    assert_eq!(json(&used)["code"], "conflict");
    let bad = call(
        &s,
        "PUT",
        "/v1/inventory/devices/r2",
        Some(json!({"group": "core", "address": "192.0.2.2", "settings": {"timeout_seconds": 0}})),
    );
    assert_eq!(bad.status, 422);
    let mismatch = call(
        &s,
        "PUT",
        "/v1/inventory/devices/r2",
        Some(json!({"name": "r3", "group": "core", "address": "192.0.2.2"})),
    );
    assert_eq!(mismatch.status, 422);
    let unknown_field = call(
        &s,
        "PUT",
        "/v1/inventory/devices/r2",
        Some(json!({"group": "core", "address": "192.0.2.2", "password": "x"})),
    );
    assert_eq!(unknown_field.status, 422);
    let login = call(
        &s,
        "PUT",
        "/v1/inventory/routes/p",
        Some(json!({"proxy": "http://u:p@192.0.2.9:3128"})),
    );
    assert_eq!(login.status, 422);
    assert_eq!(
        call(&s, "GET", "/v1/inventory/devices/nope", None).status,
        404
    );
    assert_eq!(
        call(&s, "POST", "/v1/inventory/devices/r1", None).status,
        405
    );

    let w = ok(call(&s, "DELETE", "/v1/inventory/devices/r1", None));
    assert_eq!(w["version"], 5);
    let inv = ok(call(&s, "GET", "/v1/inventory", None));
    assert_eq!(inv["version"], 5);
    assert!(inv["devices"].as_array().unwrap().is_empty());
}

#[test]
fn the_bindings_routes_take_their_keys_from_the_path() {
    let Some((s, _rt)) = with_db("api_inventory_bindings") else {
        return;
    };
    let put = |path: &str, body: Value| {
        let r = call(&s, "PUT", path, Some(body));
        assert_eq!(
            r.status,
            200,
            "{path}: {}",
            String::from_utf8_lossy(&r.body)
        );
    };
    put("/v1/inventory/groups/eq", json!({"vendor": "equinix"}));
    put("/v1/inventory/groups/core", json!({"vendor": "vyos"}));
    put(
        "/v1/inventory/devices/equinix-main",
        json!({"group": "eq", "address": "api.equinix.com"}),
    );
    put(
        "/v1/inventory/devices/r1",
        json!({"group": "core", "address": "192.0.2.1"}),
    );
    put(
        "/v1/inventory/bindings/fabric-ports/equinix-main/port-1",
        json!({"device": "r1", "port": "eth1"}),
    );
    put(
        "/v1/inventory/bindings/edge-devices/equinix-main/ne-1",
        json!({"device": "r1"}),
    );
    let b = json(&call(&s, "GET", "/v1/inventory/bindings", None));
    assert_eq!(
        b["bindings"]["fabric_ports"][0],
        json!({"account": "equinix-main", "fabric_port": "port-1", "device": "r1", "port": "eth1"})
    );
    assert_eq!(b["bindings"]["edge_devices"][0]["edge_device"], "ne-1");
    assert_eq!(
        call(
            &s,
            "DELETE",
            "/v1/inventory/bindings/fabric-ports/equinix-main/port-1",
            None
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &s,
            "DELETE",
            "/v1/inventory/bindings/fabric-ports/equinix-main/port-1",
            None
        )
        .status,
        404
    );
}

#[test]
fn a_managed_secret_goes_in_and_no_answer_gives_it_back() {
    let key = rsim_inventory::SecretKey::generate().unwrap();
    let Some((s, _rt)) = with_db_key("a_managed_secret_goes_in", Some(&key)) else {
        return;
    };
    let r = call(&s, "GET", "/v1/inventory/secret-key", None);
    assert_eq!(r.status, 200);
    let k = json(&r);
    assert_eq!(k, json!({"present": true}));
    assert!(!String::from_utf8_lossy(&r.body).contains(&key));

    let plain = "s3cret-value-8841";
    let r = call(
        &s,
        "PUT",
        "/v1/inventory/credentials/lab",
        Some(
            json!({"source": "managed", "kind": "password", "user": "ro",
                    "secret": {"value": plain}}),
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));

    let stored =
        json(&call(&s, "GET", "/v1/inventory/credentials", None))["credentials"][0].clone();
    assert_eq!(
        stored,
        json!({"name": "lab", "source": "managed", "kind": "password", "user": "ro",
               "secret_revision": 1})
    );

    // The stored record with one edited field keeps the secret.
    let mut edited = stored.clone();
    edited["description"] = json!("lab routers");
    let r = call(&s, "PUT", "/v1/inventory/credentials/lab", Some(edited));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let c = json(&call(&s, "GET", "/v1/inventory/credentials", None))["credentials"][0].clone();
    assert_eq!(c["secret_revision"], 1);
    assert_eq!(c["description"], "lab routers");

    // A new secret increases the revision.
    let mut next = c.clone();
    next["secret"] = json!({"value": "second-secret"});
    let r = call(&s, "PUT", "/v1/inventory/credentials/lab", Some(next));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let c = json(&call(&s, "GET", "/v1/inventory/credentials", None))["credentials"][0].clone();
    assert_eq!(c["secret_revision"], 2);

    for path in [
        "/v1/inventory",
        "/v1/inventory/credentials",
        "/v1/inventory/audit",
        "/v1/inventory/devices",
    ] {
        let r = call(&s, "GET", path, None);
        assert_eq!(r.status, 200, "{path}");
        let text = String::from_utf8_lossy(&r.body);
        assert!(
            !text.contains(plain) && !text.contains("second-secret"),
            "{path}: {text}"
        );
    }

    // A secret of an env credential, a private key that is not one, and a
    // passphrase of a password are refused.
    for body in [
        json!({"source": "env", "key": "LAB", "secret": {"value": "p"}}),
        json!({"source": "managed", "kind": "ssh-key", "user": "ro", "secret": {"value": "p"}}),
        json!({"source": "managed", "kind": "password", "user": "ro",
               "secret": {"value": "p", "passphrase": "q"}}),
        json!({"source": "managed", "kind": "api-key", "user": "ro", "secret": {"value": "p"}}),
        json!({"source": "managed", "kind": "api-key"}),
    ] {
        let r = call(
            &s,
            "PUT",
            "/v1/inventory/credentials/other",
            Some(body.clone()),
        );
        assert_eq!(
            r.status,
            422,
            "{body}: {}",
            String::from_utf8_lossy(&r.body)
        );
    }
}

#[test]
fn a_server_with_no_secret_key_refuses_a_secret() {
    let Some((s, _rt)) = with_db("a_server_with_no_secret_key") else {
        return;
    };
    let r = call(&s, "GET", "/v1/inventory/secret-key", None);
    assert_eq!(json(&r), json!({"present": false}));
    let r = call(
        &s,
        "PUT",
        "/v1/inventory/credentials/lab",
        Some(json!({"source": "managed", "kind": "api-key", "secret": {"value": "k"}})),
    );
    assert_eq!(r.status, 409);
    assert_eq!(json(&r)["code"], "no_secret_key");
    let r = call(
        &s,
        "PUT",
        "/v1/inventory/credentials/lab",
        Some(json!({"source": "env", "key": "LAB"})),
    );
    assert_eq!(r.status, 200);
}
