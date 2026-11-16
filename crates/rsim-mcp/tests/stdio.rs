//! The MCP tools work over stdio with the two protocol revisions, the
//! answers are equal to the answers of `rsim`, and the server writes
//! nothing.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

const TOPOLOGIES: [&str; 6] = [
    "mini-enterprise",
    "edge-dnat",
    "ecmp",
    "routing-loop",
    "hairpin",
    "chain",
];

/// An empty folder for one test, below the temporary folder of cargo.
#[allow(clippy::disallowed_methods)]
fn empty_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("rsim-mcp-{name}"));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).unwrap();
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[allow(clippy::disallowed_methods)]
fn remove_dir(dir: &Path) {
    std::fs::remove_dir(dir).unwrap();
}

/// Runs the server in `dir` with `dir` as the temporary folder, sends the
/// messages and gives the response lines.
fn session(dir: &Path, messages: &[Value]) -> Vec<Value> {
    session_with(dir, &[], messages)
}

/// [`session`] with server arguments.
fn session_with(dir: &Path, args: &[&str], messages: &[Value]) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rsim-mcp"))
        .args(args)
        .current_dir(dir)
        .env("TMPDIR", dir)
        .env("TMP", dir)
        .env("TEMP", dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("rsim-mcp starts");
    {
        let mut stdin = child.stdin.take().unwrap();
        for m in messages {
            let line = serde_json::to_string(m).unwrap();
            stdin.write_all(line.as_bytes()).unwrap();
            stdin.write_all(b"\n").unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.is_empty() || text.ends_with('\n'));
    text.lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).expect("each stdout line is JSON");
            assert_eq!(v["jsonrpc"], "2.0", "{l}");
            v
        })
        .collect()
}

/// Runs the server in `dir`, sends each line of bytes as it is and gives
/// the response lines.
fn raw_session(dir: &Path, lines: &[Vec<u8>]) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rsim-mcp"))
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for l in lines {
            stdin.write_all(l).unwrap();
            stdin.write_all(b"\n").unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn stored(topology: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rsim-cli/tests/golden")
        .join(format!("{topology}.json"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The arguments of `path_query` from the query of a stored answer.
fn stored_args(topology: &str) -> Value {
    let v: Value = serde_json::from_str(&stored(topology)).unwrap();
    let mut args = v["query"].as_object().unwrap().clone();
    args.retain(|_, v| !v.is_null());
    Value::Object(args)
}

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "rsim-test", "version": "1"}
    })
}

/// A request. With `modern`, the params carry the request metadata.
fn request(id: u64, method: &str, mut params: Value, modern: bool) -> Value {
    if modern {
        params["_meta"] = modern_meta();
    }
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn call(id: u64, tool: &str, args: Value, modern: bool) -> Value {
    request(
        id,
        "tools/call",
        json!({"name": tool, "arguments": args}),
        modern,
    )
}

/// The tool calls of a session, from id 100.
fn tool_calls(modern: bool) -> Vec<Value> {
    let mut m = Vec::new();
    let mut id = 100;
    for t in TOPOLOGIES {
        m.push(call(id, "list_devices", json!({"topology": t}), modern));
        id += 1;
    }
    for t in TOPOLOGIES {
        m.push(call(id, "path_query", stored_args(t), modern));
        id += 1;
    }
    let mut step = stored_args("edge-dnat");
    step["branch"] = json!(0);
    step["step"] = json!(3);
    m.push(call(id, "explain_step", step.clone(), modern));
    step["reply_of"] = json!(0);
    step["step"] = json!(2);
    m.push(call(id + 1, "explain_step", step, modern));
    let mut bad = stored_args("edge-dnat");
    bad["ingress"] = json!("nobody/eth0");
    m.push(call(id + 2, "path_query", bad, modern));
    let set = stored_args("set-mini-enterprise");
    m.push(call(id + 3, "set_query", set.clone(), modern));
    let mut step = set;
    step["mode"] = json!("set");
    step["branch"] = json!(1);
    step["step"] = json!(7);
    m.push(call(id + 4, "explain_step", step, modern));
    m
}

fn by_id(responses: &[Value], id: u64) -> &Value {
    responses
        .iter()
        .find(|r| r["id"] == id)
        .unwrap_or_else(|| panic!("no response {id}"))
}

/// Checks the results of [`tool_calls`].
fn check_tool_results(responses: &[Value], modern: bool) {
    let mut id = 100;
    for t in TOPOLOGIES {
        let r = &by_id(responses, id)["result"];
        assert_eq!(r["isError"], false, "{t}");
        let text = r["content"][0]["text"].as_str().unwrap();
        assert_eq!(r["content"][0]["type"], "text");
        assert_eq!(
            serde_json::from_str::<Value>(text).unwrap(),
            r["structuredContent"]
        );
        assert_eq!(r["structuredContent"]["kind"], "devices");
        assert_eq!(r["structuredContent"]["topology"], t);
        let twin = rsim_cli::commands::load(t).unwrap();
        assert_eq!(
            text,
            rsim_cli::json::to_text(&rsim_cli::commands::devices(t, &twin), false)
        );
        assert_eq!(r.get("resultType").is_some(), modern);
        id += 1;
    }
    for t in TOPOLOGIES {
        let r = &by_id(responses, id)["result"];
        assert_eq!(r["isError"], false, "{t}");
        let text = r["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            format!("{text}\n"),
            stored(t),
            "{t}: the text item differs from rsim path"
        );
        assert_eq!(
            serde_json::from_str::<Value>(text).unwrap(),
            r["structuredContent"]
        );
        id += 1;
    }
    let answer: Value = serde_json::from_str(&stored("edge-dnat")).unwrap();
    let r = &by_id(responses, id)["result"]["structuredContent"];
    assert_eq!(r["kind"], "step");
    assert_eq!(r["trace_step"], answer["answer"]["branches"][0]["steps"][3]);
    let r = &by_id(responses, id + 1)["result"]["structuredContent"];
    assert_eq!(r["reply_of"], 0);
    assert_eq!(
        r["trace_step"],
        answer["answer"]["replies"][0]["answer"]["branches"][0]["steps"][2]
    );
    let r = &by_id(responses, id + 2)["result"];
    assert_eq!(r["isError"], true);
    assert_eq!(r["structuredContent"]["kind"], "error");
    assert_eq!(r["structuredContent"]["error"]["code"], "unknown_ingress");
    let r = &by_id(responses, id + 3)["result"];
    assert_eq!(r["isError"], false);
    let text = r["content"][0]["text"].as_str().unwrap();
    assert_eq!(format!("{text}\n"), stored("set-mini-enterprise"));
    let set: Value = serde_json::from_str(&stored("set-mini-enterprise")).unwrap();
    let r = &by_id(responses, id + 4)["result"]["structuredContent"];
    assert_eq!(r["kind"], "step");
    assert_eq!(r["trace_step"], set["answer"]["branches"][1]["steps"][7]);
}

fn check_tools_list(r: &Value) {
    let tools = r["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        ["list_devices", "path_query", "set_query", "explain_step"]
    );
    for t in tools {
        assert!(t["description"].is_string());
        assert_eq!(t["inputSchema"]["type"], "object");
        assert_eq!(t["outputSchema"]["type"], "object");
    }
}

#[test]
fn tools_work_over_stdio_with_discover_and_request_metadata() {
    let dir = empty_dir("modern");
    let mut messages = vec![
        request(1, "server/discover", json!({}), true),
        request(2, "tools/list", json!({}), true),
    ];
    messages.extend(tool_calls(true));
    let responses = session(&dir, &messages);
    assert_eq!(responses.len(), messages.len());

    let d = &by_id(&responses, 1)["result"];
    assert_eq!(d["resultType"], "complete");
    assert_eq!(d["supportedVersions"], json!(["2026-07-28", "2025-11-25"]));
    assert_eq!(d["capabilities"], json!({"tools": {"listChanged": false}}));
    assert_eq!(
        d["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "rsim-mcp"
    );
    assert_eq!(d["ttlMs"], 3_600_000);
    assert_eq!(d["cacheScope"], "public");

    let l = &by_id(&responses, 2)["result"];
    assert_eq!(l["resultType"], "complete");
    assert_eq!(l["ttlMs"], 3_600_000);
    assert_eq!(l["cacheScope"], "public");
    check_tools_list(l);
    check_tool_results(&responses, true);

    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "rsim-mcp wrote a file"
    );
    remove_dir(&dir);
}

#[test]
fn tools_work_over_stdio_with_initialize() {
    let dir = empty_dir("legacy");
    let mut messages = vec![
        request(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "rsim-test", "version": "1"}
            }),
            false,
        ),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        request(2, "ping", json!({}), false),
        request(3, "tools/list", json!({}), false),
    ];
    messages.extend(tool_calls(false));
    messages.push(request(4, "server/discover", json!({}), true));
    messages.push(request(5, "tools/list", json!({}), true));
    let responses = session(&dir, &messages);
    assert_eq!(
        responses.len(),
        messages.len() - 1,
        "a notification has no response"
    );

    let i = &by_id(&responses, 1)["result"];
    assert_eq!(i["protocolVersion"], "2025-11-25");
    assert_eq!(i["capabilities"], json!({"tools": {"listChanged": false}}));
    assert_eq!(i["serverInfo"]["name"], "rsim-mcp");
    assert_eq!(by_id(&responses, 2)["result"], json!({}));
    let l = &by_id(&responses, 3)["result"];
    assert!(l.get("resultType").is_none());
    assert!(l.get("ttlMs").is_none());
    assert!(l.get("cacheScope").is_none());
    check_tools_list(l);
    check_tool_results(&responses, false);
    assert_eq!(
        by_id(&responses, 4)["error"]["code"],
        -32601,
        "server/discover is not a method after initialize"
    );
    let l = &by_id(&responses, 5)["result"];
    assert!(
        l.get("resultType").is_none(),
        "_meta is ignored after initialize"
    );
    check_tools_list(l);

    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "rsim-mcp wrote a file"
    );
    remove_dir(&dir);
}

#[test]
fn initialize_with_another_revision_gets_2025_11_25() {
    let dir = empty_dir("other-revision");
    let r = session(
        &dir,
        &[request(
            1,
            "initialize",
            json!({"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "rsim-test", "version": "1"}}),
            false,
        )],
    );
    assert_eq!(r[0]["result"]["protocolVersion"], "2025-11-25");
    remove_dir(&dir);
}

#[test]
fn protocol_faults_give_json_rpc_errors() {
    let dir = empty_dir("faults");
    let meta_old = json!({
        "io.modelcontextprotocol/protocolVersion": "2025-11-25",
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let lines = [
        "not json".to_string(),
        "[1,2]".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#.to_string(),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list",
               "params": {"_meta": meta_old}})
        .to_string(),
        call(4, "no_such_tool", json!({}), true).to_string(),
        call(5, "path_query", json!({"topology": "ecmp"}), true).to_string(),
        request(6, "ping", json!({}), true).to_string(),
    ];
    let mut bytes: Vec<Vec<u8>> = lines.iter().map(|l| l.clone().into_bytes()).collect();
    bytes.insert(1, vec![0xff, 0xfe]);
    let r = raw_session(&dir, &bytes);
    assert_eq!(r.len(), bytes.len());
    assert_eq!(r[0]["error"]["code"], -32700);
    assert_eq!(r[0]["id"], Value::Null);
    assert_eq!(r[1]["error"]["code"], -32700, "a line that is not UTF-8");
    assert_eq!(r[2]["error"]["code"], -32600);
    assert_eq!(r[3]["error"]["code"], -32601);
    assert_eq!(r[4]["error"]["code"], -32602);
    assert_eq!(r[5]["error"]["code"], -32022);
    assert_eq!(
        r[5]["error"]["data"],
        json!({"supported": ["2026-07-28"], "requested": "2025-11-25"})
    );
    assert_eq!(r[6]["error"]["code"], -32602);
    assert_eq!(r[7]["result"]["isError"], true);
    assert_eq!(
        r[7]["result"]["structuredContent"]["error"]["code"],
        "invalid_query"
    );
    assert_eq!(
        r[8]["error"]["code"], -32601,
        "ping is not a method of 2026-07-28"
    );
    remove_dir(&dir);
}

#[path = "../../rsim-cli/tests/support/fixture_store.rs"]
mod fixture_store;

#[test]
fn the_store_topology_answers_a_path_query_and_writes_nothing() {
    let data = Path::new(env!("CARGO_TARGET_TMPDIR")).join("rsim-mcp-store-data");
    fixture_store::write(&data);
    let dir = empty_dir("store");
    let folder = data.display().to_string();
    let args = json!({
        "topology": "store",
        "source.ip": "192.0.2.70",
        "destination.ip": "192.0.2.50",
        "network.transport": "tcp",
        "source.port": 40000,
        "destination.port": 8123
    });
    let messages = vec![
        request(1, "server/discover", json!({}), true),
        request(2, "tools/list", json!({}), true),
        call(3, "path_query", args, true),
        call(
            4,
            "list_devices",
            json!({"topology": "store:/elsewhere"}),
            true,
        ),
    ];
    let r = session_with(&dir, &["--store", &folder], &messages);
    let tools = by_id(&r, 2)["result"]["tools"].as_array().unwrap();
    let names = tools[1]["inputSchema"]["properties"]["topology"]["enum"].to_string();
    assert!(names.contains("\"store\""), "{names}");
    let answer = by_id(&r, 3)["result"].to_string();
    assert!(answer.contains("r1/handoff/eth0"), "{answer}");
    assert!(answer.contains("h1-005351"), "{answer}");
    assert_eq!(by_id(&r, 4)["result"]["isError"], true);
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "the server wrote a file"
    );
    remove_dir(&dir);
}
