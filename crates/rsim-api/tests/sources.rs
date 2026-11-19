//! The route of the masked source lines of a span, on the fixture store and
//! on a store with a section that has no mask.

use std::path::Path;

use rsim_api::handler::{Request, Response, Settings, State, handle};
use rsim_store::{Class, DeviceUpdate, Entropy, Format, Keys, SectionEntry, SectionStatus, Store};
use serde_json::{Value, json};

#[path = "../../rsim-cli/tests/support/fixture_store.rs"]
mod fixture_store;

const PORT: u16 = 8787;

fn state(store: &Path) -> State {
    State::new(Settings {
        listen: ([127, 0, 0, 1], PORT).into(),
        store: Some(store.display().to_string()),
        allow_origins: Vec::new(),
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
        headers: [("host".to_string(), format!("127.0.0.1:{PORT}"))].into(),
        body: Vec::new(),
    }
}

fn get(s: &State, path: &str) -> Response {
    handle(s, &req("GET", path))
}

fn json(r: &Response) -> Value {
    serde_json::from_slice(&r.body).unwrap()
}

/// The identifier of the snapshot twin of the store of a server.
fn twin(s: &State) -> String {
    let r = get(s, "/v1/twins/store");
    assert_eq!(r.status, 307);
    r.header("location")
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string()
}

/// The file name of a section of the newest snapshot of a data folder.
#[allow(clippy::disallowed_methods)]
fn file_of(dir: &Path, device: &str, section: &str) -> String {
    let keys = Keys::from_hex(&std::fs::read_to_string(dir.join("keys")).unwrap()).unwrap();
    let store = Store::open_read(dir.join("store"), keys).unwrap();
    let snap = store.latest().unwrap().unwrap();
    let blob = snap.devices[device].section(section).unwrap().blob.unwrap();
    format!("{device}/{section}@{}", &blob.to_string()[..12])
}

fn fixture_lines(rel: &str) -> usize {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rsim-ingest/tests/fixtures")
        .join(rel);
    let c = rsim_store::canonical(Format::Json, &std::fs::read(p).unwrap()).unwrap();
    String::from_utf8(c).unwrap().lines().count()
}

#[allow(clippy::disallowed_methods)]
fn fixture_dir(name: &str) -> std::path::PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    fixture_store::write(&dir);
    dir
}

/// The served lines of a range of a file, or the code of the refusal.
fn served(s: &State, id: &str, file: &str, first: usize, last: usize) -> Result<Value, String> {
    let r = get(
        s,
        &format!("/v1/twins/{id}/sources?file={file}&lines={first}-{last}"),
    );
    let v = json(&r);
    match r.status {
        200 => Ok(v),
        403 => Err(v["code"].as_str().unwrap().to_string()),
        n => panic!("{n}: {v}"),
    }
}

#[test]
fn the_lines_of_a_vyos_config_have_no_secret_and_the_same_bytes_each_time() {
    let dir = fixture_dir("rsim-api-sources-vyos");
    let s = state(&dir);
    let id = twin(&s);
    let file = file_of(&dir, "r1", "config");
    let n = fixture_lines("vyos/r1-config.json");
    let mut first = 1;
    let mut seen = 0;
    let mut given = 0;
    while first <= n {
        let last = (first + 199).min(n);
        let path = format!("/v1/twins/{id}/sources?file={file}&lines={first}-{last}");
        let r = get(&s, &path);
        assert_eq!(get(&s, &path).body, r.body);
        let text = String::from_utf8(r.body.clone()).unwrap();
        for secret in ["FAKEVYOSPASSWORD", "FAKEPEERGROUPPASSWORD", "BBBB"] {
            assert!(!text.contains(secret), "{secret} in lines {first}-{last}");
        }
        if r.status == 403 {
            assert_eq!(json(&r)["code"], "not_a_source_span");
            first = last + 1;
            continue;
        }
        assert_eq!(r.status, 200, "{text}");
        let v = json(&r);
        assert_eq!(v["kind"], "source_lines");
        assert_eq!(v["source"]["cut"], 0);
        let lines = v["source"]["lines"].as_array().unwrap();
        let left: usize = v["source"]["left_out"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| {
                (x["last_line"].as_u64().unwrap() - x["first_line"].as_u64().unwrap() + 1) as usize
            })
            .sum();
        assert_eq!(lines.len() + left, last - first + 1);
        given += lines.len();
        seen += lines
            .iter()
            .filter(|l| l["text"].as_str().unwrap().contains("<secret>"))
            .count();
        first = last + 1;
    }
    assert!(given > 0);
    assert!(seen >= 1, "{seen} masked lines");
}

#[test]
fn a_long_span_is_cut_with_a_note() {
    let dir = fixture_dir("rsim-api-sources-cut");
    let s = state(&dir);
    let id = twin(&s);
    let file = file_of(&dir, "r1", "config");
    let n = fixture_lines("vyos/r1-config.json");
    assert!(n > 210, "{n}");
    let v = served(&s, &id, &file, 1, n).unwrap();
    let lines = v["source"]["lines"].as_array().unwrap();
    assert!(!lines.is_empty() && lines.len() <= 200);
    assert!(lines.iter().all(|l| l["number"].as_u64().unwrap() <= 200));
    assert_eq!(v["source"]["cut"], n - 200);
    assert!(v["source"]["note"].as_str().unwrap().contains("cut"));
}

#[test]
fn a_span_out_of_order_is_refused() {
    let dir = fixture_dir("rsim-api-sources-range");
    let s = state(&dir);
    let id = twin(&s);
    let file = file_of(&dir, "r1", "config");
    for lines in ["0-3", "9-3", "a-b"] {
        let r = get(
            &s,
            &format!("/v1/twins/{id}/sources?file={file}&lines={lines}"),
        );
        assert_eq!(r.status, 422, "{lines}");
        assert_eq!(json(&r)["code"], "invalid_query", "{lines}");
    }
    // A file that is not a section of the snapshot.
    let other = format!("{}@000000000000", file.split_once('@').unwrap().0);
    let r = get(
        &s,
        &format!("/v1/twins/{id}/sources?file={other}&lines=1-2"),
    );
    assert_eq!(r.status, 404);
    assert_eq!(json(&r)["code"], "no_source_text");
}

#[test]
fn no_answer_gives_the_line_count_of_a_section() {
    let dir = fixture_dir("rsim-api-sources-count");
    let s = state(&dir);
    let id = twin(&s);
    let file = file_of(&dir, "r1", "config");
    let n = fixture_lines("vyos/r1-config.json");
    for (first, last) in [
        (1, 999_999),
        (2, 999_999),
        (n + 1, n + 1000),
        (n + 1, 999_999),
    ] {
        let r = get(
            &s,
            &format!("/v1/twins/{id}/sources?file={file}&lines={first}-{last}"),
        );
        let v = json(&r);
        let text = v.to_string();
        assert!(
            !text.contains(&format!("{n} lines")),
            "{first}-{last}: {text}"
        );
        assert!(!text.contains("beyond"), "{first}-{last}: {text}");
        if first > n {
            assert_eq!(r.status, 403, "{first}-{last}: {text}");
            assert_eq!(v["code"], "not_a_source_span");
            continue;
        }
        assert_eq!(r.status, 200, "{first}-{last}: {text}");
        let lines = v["source"]["lines"].as_array().unwrap();
        assert!(
            lines
                .iter()
                .all(|l| l["number"].as_u64().unwrap() <= n as u64)
        );
        let left_out = v["source"]["left_out"].as_array().unwrap();
        let shown = last.min(first + 199);
        assert!(
            left_out.last().unwrap()["last_line"] == shown,
            "{first}-{last}: {text}"
        );
    }
}

#[test]
fn a_unifi_section_is_not_served_by_its_rows() {
    let dir = fixture_dir("rsim-api-sources-rows");
    let s = state(&dir);
    let id = twin(&s);
    for section in ["devices", "clients", "wlans"] {
        let file = file_of(&dir, "site1", section);
        for (first, last) in [(1, 1), (1, 40), (2, 2)] {
            assert_eq!(
                served(&s, &id, &file, first, last).unwrap_err(),
                "not_a_source_span",
                "{file}:{first}-{last}"
            );
        }
        let r = get(
            &s,
            &format!("/v1/twins/{id}/sources?file={file}%23row&lines=1-1"),
        );
        assert_eq!(r.status, 404, "{file}");
        let r = get(
            &s,
            &format!("/v1/twins/{id}/sources?file={file}#row&lines=1-1"),
        );
        assert_eq!(r.status, 404, "{file}");
        assert_eq!(json(&r)["code"], "no_source_text", "{file}");
    }
}

#[test]
fn a_built_in_topology_has_no_source_text() {
    let dir = fixture_dir("rsim-api-sources-builtin");
    let s = state(&dir);
    let r = get(
        &s,
        "/v1/twins/builtin.leaf-spine/sources?file=leaf1.conf&lines=1-2",
    );
    assert_eq!(r.status, 404);
    assert_eq!(json(&r)["code"], "no_source_text");
}

#[test]
fn a_step_gives_the_masked_lines_of_its_spans_on_request() {
    let dir = fixture_dir("rsim-api-sources-step");
    let s = state(&dir);
    let id = twin(&s);
    let mut r = req("POST", &format!("/v1/twins/{id}/queries"));
    r.body = json!({
        "source.ip": "192.0.2.70",
        "destination.ip": "192.0.2.50",
        "network.transport": "tcp",
        "source.port": 40000,
        "destination.port": 8123
    })
    .to_string()
    .into_bytes();
    let r = handle(&s, &r);
    assert_eq!(r.status, 303, "{}", String::from_utf8_lossy(&r.body));
    let q = r.header("location").unwrap().to_string();
    let answer = json(&get(&s, &format!("{q}?form=full")));
    let steps = answer["answer"]["branches"][0]["steps"].as_array().unwrap();
    let at = steps
        .iter()
        .position(|st| {
            st["provenance"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["file"].as_str().unwrap().starts_with("r1/config@"))
        })
        .expect("a step of the config of r1");
    let plain = json(&get(&s, &format!("{q}/branches/0/steps/{at}")));
    assert!(plain.get("source_lines").is_none());
    let v = json(&get(
        &s,
        &format!("{q}/branches/0/steps/{at}?source_lines=true"),
    ));
    let sources = v["source_lines"].as_array().unwrap();
    assert_eq!(
        sources.len(),
        v["trace_step"]["provenance"].as_array().unwrap().len()
    );
    assert!(
        sources
            .iter()
            .any(|x| x["lines"].as_array().is_some_and(|l| !l.is_empty())),
        "{v}"
    );
}

struct Counter(u8);

impl Entropy for Counter {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            self.0 = self.0.wrapping_add(1);
            *b = self.0;
        }
    }
}

/// A data folder with one device of a vendor with no mask.
#[allow(clippy::disallowed_methods)]
fn no_mask_store(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let (hash, wrap) = ([3u8; 32], [4u8; 32]);
    std::fs::write(
        dir.join("keys"),
        format!("{}\n{}\n", hex(&hash), hex(&wrap)),
    )
    .unwrap();
    let store = Store::open(dir.join("store"), Keys::new(hash, wrap)).unwrap();
    let blob = store
        .put_blob(
            b"config system admin\n  set password FAKEPASSWORD\nend\n",
            &mut Counter(0),
        )
        .unwrap();
    let mut c = store.begin(1).unwrap();
    c.add(DeviceUpdate {
        device: "fw1".into(),
        vendor: "fortios".into(),
        collected_at: 1,
        sections: vec![SectionEntry {
            name: "config".into(),
            command: "show full-configuration".into(),
            class: Class::Configuration,
            format: Format::Text,
            change_hash: Some(blob),
            blob: Some(blob),
            status: SectionStatus::Fresh,
            collected_at: Some(1),
        }],
        tables: Default::default(),
    })
    .unwrap();
    c.prepare().unwrap().unwrap().publish().unwrap();
}

#[test]
fn a_section_of_a_vendor_with_no_mask_is_not_served() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("rsim-api-sources-no-mask");
    no_mask_store(&dir);
    let s = state(&dir);
    let id = twin(&s);
    let file = file_of(&dir, "fw1", "config");
    let r = get(&s, &format!("/v1/twins/{id}/sources?file={file}&lines=1-2"));
    assert_eq!(r.status, 403);
    let v = json(&r);
    // The device is not lowered, so no span names its config and the span
    // gate refuses it before the mask is asked.
    assert_eq!(v["code"], "not_a_source_span", "{v}");
    assert!(!String::from_utf8_lossy(&r.body).contains("FAKEPASSWORD"));
}

/// A data folder with the VyOS router `r1` of the fixture, whose config has
/// a container section, and the canonical lines of that config.
#[allow(clippy::disallowed_methods)]
fn container_store(dir: &Path) -> Vec<String> {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let (hash, wrap) = ([5u8; 32], [6u8; 32]);
    std::fs::write(
        dir.join("keys"),
        format!("{}\n{}\n", hex(&hash), hex(&wrap)),
    )
    .unwrap();
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rsim-ingest/tests/fixtures/vyos/r1-config.json");
    let mut config: Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
    config["container"] = json!({"name": {"app": {
        "image": "registry.example/app:1",
        "environment": {"MODE": {"value": "kept-mode"}},
        "label": {"traefik.example.users": {"value": "admin:$apr1$FAKESALT$FAKEHASH"}}
    }}});
    let bytes = config.to_string().into_bytes();
    let store = Store::open(dir.join("store"), Keys::new(hash, wrap)).unwrap();
    let blob = store.put_blob(&bytes, &mut Counter(0)).unwrap();
    let mut c = store.begin(1).unwrap();
    c.add(DeviceUpdate {
        device: "r1".into(),
        vendor: "vyos".into(),
        collected_at: 1,
        sections: vec![SectionEntry {
            name: "config".into(),
            command: "config".into(),
            class: Class::Configuration,
            format: Format::Json,
            change_hash: Some(blob),
            blob: Some(blob),
            status: SectionStatus::Fresh,
            collected_at: Some(1),
        }],
        tables: Default::default(),
    })
    .unwrap();
    c.prepare().unwrap().unwrap().publish().unwrap();
    let canon = rsim_store::canonical(Format::Json, &bytes).unwrap();
    String::from_utf8(canon)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

/// The first and the last line number of the container section.
fn container_lines(lines: &[String]) -> (usize, usize) {
    let i = lines
        .iter()
        .position(|l| l.trim_start().starts_with("\"container\""))
        .unwrap();
    let indent = lines[i].len() - lines[i].trim_start().len();
    let j = (i + 1..lines.len())
        .find(|&j| {
            let l = &lines[j];
            l.len() - l.trim_start().len() == indent && l.trim_start().starts_with('}')
        })
        .unwrap();
    (i + 1, j + 1)
}

#[test]
fn a_range_outside_every_span_is_refused() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("rsim-api-sources-outside");
    let lines = container_store(&dir);
    let (a, b) = container_lines(&lines);
    let s = state(&dir);
    let id = twin(&s);
    let file = file_of(&dir, "r1", "config");
    assert_eq!(
        served(&s, &id, &file, a, b).unwrap_err(),
        "not_a_source_span"
    );
    for n in a..=b {
        let r = get(&s, &format!("/v1/twins/{id}/sources?file={file}&lines={n}"));
        assert_eq!(r.status, 403, "line {n}");
        let text = String::from_utf8_lossy(&r.body).to_string();
        assert_eq!(json(&r)["code"], "not_a_source_span", "line {n}");
        for word in ["registry.example", "traefik", "kept-mode", "FAKE"] {
            assert!(!text.contains(word), "{word} in line {n}");
        }
    }
}

#[test]
fn a_partly_covered_range_gives_only_the_covered_lines() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("rsim-api-sources-partly");
    let lines = container_store(&dir);
    let (a, b) = container_lines(&lines);
    let s = state(&dir);
    let id = twin(&s);
    let file = file_of(&dir, "r1", "config");
    let k = (b + 1..=lines.len())
        .find(|&k| served(&s, &id, &file, k, k).is_ok())
        .expect("a line of a span after the container section");
    let v = served(&s, &id, &file, a, k).unwrap();
    let got: Vec<usize> = v["source"]["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["number"].as_u64().unwrap() as usize)
        .collect();
    assert_eq!(got, vec![k]);
    assert_eq!(
        v["source"]["left_out"],
        json!([{"first_line": a, "last_line": k - 1}])
    );
    assert!(v["source"]["note"].as_str().unwrap().contains("left out"));
    let text = v.to_string();
    for word in ["registry.example", "traefik", "kept-mode", "FAKE"] {
        assert!(!text.contains(word), "{word}");
    }
}

#[test]
fn each_span_of_a_step_is_served_whole() {
    let dir = fixture_dir("rsim-api-sources-whole");
    let s = state(&dir);
    let id = twin(&s);
    let mut r = req("POST", &format!("/v1/twins/{id}/queries"));
    r.body = json!({
        "source.ip": "192.0.2.70",
        "destination.ip": "192.0.2.50",
        "network.transport": "tcp",
        "source.port": 40000,
        "destination.port": 8123
    })
    .to_string()
    .into_bytes();
    let q = handle(&s, &r).header("location").unwrap().to_string();
    let answer = json(&get(&s, &format!("{q}?form=full")));
    let steps = answer["answer"]["branches"][0]["steps"].as_array().unwrap();
    let mut seen = 0;
    let mut rows = 0;
    for i in 0..steps.len() {
        let v = json(&get(
            &s,
            &format!("{q}/branches/0/steps/{i}?source_lines=true"),
        ));
        for src in v["source_lines"].as_array().unwrap() {
            let file = src["file"].as_str().unwrap();
            if file.ends_with("#row") {
                // A row span names the rows of a table: it stays a label.
                assert_eq!(src["error"]["code"], "no_source_text", "step {i}: {src}");
                assert!(src.get("lines").is_none(), "step {i}: {src}");
                rows += 1;
                continue;
            }
            // The table sections of the fixture store hold no readable text.
            if !file.contains("/config@") {
                continue;
            }
            assert!(src.get("error").is_none(), "step {i}: {src}");
            assert_eq!(src["left_out"], json!([]), "step {i}: {src}");
            let a = src["first_line"].as_u64().unwrap() as usize;
            let b = src["last_line"].as_u64().unwrap() as usize;
            assert_eq!(src["lines"].as_array().unwrap().len(), (b - a + 1).min(200));
            let r = served(&s, &id, file, a, b).unwrap();
            assert_eq!(r["source"], *src);
            seen += 1;
        }
    }
    assert!(seen > 0);
    assert!(rows > 0);
}
