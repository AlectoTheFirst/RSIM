//! The command `rsim`: each built-in topology loads by name, a path query
//! for one packet with its reply gives the stored JSON, the same query
//! gives the same bytes, and the errors give their codes and exit codes.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::thread;

use rsim_cli::{QueryInput, commands, json};
use serde_json::Value;

/// One stated query for each built-in topology, as `rsim path` arguments.
const QUERIES: [(&str, &[&str]); 6] = [
    (
        "mini-enterprise",
        &[
            "--source.ip",
            "172.31.10.20",
            "--destination.ip",
            "10.20.0.53",
            "--network.transport",
            "udp",
            "--source.port",
            "40000",
            "--destination.port",
            "53",
        ],
    ),
    (
        "edge-dnat",
        &[
            "--source.ip",
            "198.51.100.7",
            "--destination.ip",
            "203.0.113.10",
            "--network.transport",
            "tcp",
            "--source.port",
            "51000",
            "--destination.port",
            "443",
            "--tcp_flags",
            "syn",
        ],
    ),
    (
        "ecmp",
        &[
            "--source.ip",
            "10.1.0.10",
            "--destination.ip",
            "10.4.0.10",
            "--network.transport",
            "tcp",
            "--source.port",
            "40000",
            "--destination.port",
            "22",
        ],
    ),
    (
        "routing-loop",
        &[
            "--source.ip",
            "10.1.0.10",
            "--destination.ip",
            "10.9.0.1",
            "--network.transport",
            "tcp",
            "--source.port",
            "40000",
            "--destination.port",
            "80",
        ],
    ),
    (
        "hairpin",
        &[
            "--source.ip",
            "10.1.0.10",
            "--destination.ip",
            "10.9.0.10",
            "--network.transport",
            "tcp",
            "--source.port",
            "40000",
            "--destination.port",
            "80",
        ],
    ),
    (
        "chain",
        &[
            "--source.ip",
            "10.254.0.10",
            "--destination.ip",
            "10.255.0.10",
            "--network.transport",
            "tcp",
            "--source.port",
            "40000",
            "--destination.port",
            "443",
        ],
    ),
];

fn rsim(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rsim"))
        .args(args)
        .output()
        .expect("rsim runs")
}

fn path_args<'a>(topology: &'a str, flags: &[&'a str]) -> Vec<&'a str> {
    let mut a = vec!["path", topology];
    a.extend_from_slice(flags);
    a.extend_from_slice(&["--format", "json"]);
    a
}

fn stored(topology: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{topology}.json"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).expect("UTF-8")
}

fn json_of(o: &Output) -> Value {
    serde_json::from_slice(&o.stdout).expect("JSON output")
}

/// The query input of a stored answer.
fn stored_input(topology: &str) -> QueryInput {
    let v: Value = serde_json::from_str(&stored(topology)).unwrap();
    let mut args = v["query"].as_object().unwrap().clone();
    args.retain(|_, v| !v.is_null());
    rsim_cli::args::query(&args, &[]).expect("stored query is valid")
}

#[test]
fn each_builtin_topology_loads_by_name() {
    let o = rsim(&["topologies", "--format", "json"]);
    assert!(o.status.success());
    let names: Vec<&str> = QUERIES.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        json_of(&o),
        serde_json::json!({"rsim_json": 2, "kind": "topologies", "topologies": names})
    );
    for name in names {
        let o = rsim(&["devices", name, "--format", "json"]);
        assert_eq!(o.status.code(), Some(0), "{name}");
        let v = json_of(&o);
        assert_eq!(v["kind"], "devices");
        assert_eq!(v["topology"], name);
        assert!(!v["devices"].as_array().unwrap().is_empty(), "{name}");
        assert!(!v["endpoints"].as_array().unwrap().is_empty(), "{name}");
        let twin = commands::load(name).unwrap();
        let lib = json::to_text(&commands::devices(name, &twin), false) + "\n";
        assert_eq!(stdout(&o), lib, "{name}");
        let text = rsim(&["devices", name]);
        assert!(text.status.success());
    }
}

#[test]
fn a_path_query_with_its_reply_gives_the_stored_json() {
    for (topology, flags) in QUERIES {
        let o = rsim(&path_args(topology, flags));
        assert_eq!(o.status.code(), Some(0), "{topology}");
        assert_eq!(
            stdout(&o),
            stored(topology),
            "{topology} differs from its file"
        );
        let v = json_of(&o);
        let replies = v["answer"]["replies"].as_array().unwrap();
        let delivered = v["answer"]["branches"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|b| b["verdict"]["kind"] == "deliver")
            .count();
        assert_eq!(replies.len(), delivered, "{topology}");
        let mut text = path_args(topology, flags);
        text.truncate(text.len() - 2);
        assert!(rsim(&text).status.success(), "{topology}");
    }
}

#[test]
fn the_same_query_gives_the_same_bytes() {
    for (topology, flags) in QUERIES {
        let want = stored(topology);
        for _ in 0..2 {
            assert_eq!(
                stdout(&rsim(&path_args(topology, flags))),
                want,
                "{topology}"
            );
        }
        let input = stored_input(topology);
        let twin = commands::load(topology).unwrap();
        let outputs: Vec<String> = thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| json::to_text(&commands::path(&input, &twin).unwrap(), false) + "\n")
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        for o in outputs {
            assert_eq!(o, want, "{topology} in a thread");
        }
    }
}

#[test]
fn explain_gives_the_step_of_the_answer() {
    let (topology, flags) = QUERIES[1];
    let answer: Value = serde_json::from_str(&stored(topology)).unwrap();
    let mut args = vec!["explain", topology];
    args.extend_from_slice(flags);
    args.extend_from_slice(&["--branch", "0", "--step", "3", "--format", "json"]);
    let v = json_of(&rsim(&args));
    assert_eq!(v["kind"], "step");
    assert_eq!(v["reply_of"], Value::Null);
    assert_eq!(v["query"], answer["query"]);
    assert_eq!(v["trace_step"], answer["answer"]["branches"][0]["steps"][3]);

    let mut args = vec!["explain", topology];
    args.extend_from_slice(flags);
    args.extend_from_slice(&[
        "--reply-of",
        "0",
        "--branch",
        "0",
        "--step",
        "2",
        "--format",
        "json",
    ]);
    let v = json_of(&rsim(&args));
    assert_eq!(v["reply_of"], 0);
    assert_eq!(
        v["trace_step"],
        answer["answer"]["replies"][0]["answer"]["branches"][0]["steps"][2]
    );
}

#[test]
fn an_index_that_is_not_in_the_answer_is_no_such_step() {
    let (topology, flags) = QUERIES[1];
    for idx in [
        &["--branch", "1", "--step", "0"][..],
        &["--branch", "0", "--step", "999"],
        &["--reply-of", "5", "--branch", "0", "--step", "0"],
    ] {
        let mut args = vec!["explain", topology];
        args.extend_from_slice(flags);
        args.extend_from_slice(idx);
        args.extend_from_slice(&["--format", "json"]);
        let o = rsim(&args);
        assert_eq!(o.status.code(), Some(1), "{idx:?}");
        assert_eq!(json_of(&o)["error"]["code"], "no_such_step", "{idx:?}");
    }
}

#[test]
fn query_errors_give_the_error_object_and_exit_code_1() {
    let base = ["--destination.ip", "203.0.113.10"];
    let src = ["--source.ip", "198.51.100.7"];
    let cases: [(&str, &[&str], &str); 11] = [
        (
            "nowhere",
            &["--network.transport", "tcp"],
            "unknown_topology",
        ),
        (
            "edge-dnat",
            &["--network.transport", "tcp", "--ingress", "nobody/eth0"],
            "unknown_ingress",
        ),
        (
            "edge-dnat",
            &["--network.transport", "tcp", "--source.ip", "2001:db8::1"],
            "invalid_query",
        ),
        (
            "edge-dnat",
            &["--network.transport", "icmp", "--destination.port", "1"],
            "invalid_query",
        ),
        (
            "edge-dnat",
            &["--network.transport", "udp", "--tcp_flags", "syn"],
            "invalid_query",
        ),
        (
            "edge-dnat",
            &["--network.transport", "tcp", "--icmp_code", "0"],
            "invalid_query",
        ),
        (
            "edge-dnat",
            &[
                "--network.transport",
                "tcp",
                "--destination.port",
                "443",
                "--fragment",
                "later",
            ],
            "invalid_query",
        ),
        (
            "edge-dnat",
            &["--network.iana_number", "47", "--source.port", "1"],
            "invalid_query",
        ),
        (
            "edge-dnat",
            &["--network.iana_number", "6", "--network.transport", "udp"],
            "invalid_query",
        ),
        ("edge-dnat", &[], "invalid_query"),
        (
            "edge-dnat",
            &["--network.transport", "tcp", "--l2_priority", "3"],
            "invalid_query",
        ),
    ];
    for (topology, extra, code) in cases {
        let mut args = vec!["path", topology];
        args.extend_from_slice(&base);
        if !extra.contains(&"--source.ip") {
            args.extend_from_slice(&src);
        }
        args.extend_from_slice(extra);
        let mut json_args = args.clone();
        json_args.extend_from_slice(&["--format", "json"]);
        let o = rsim(&json_args);
        assert_eq!(o.status.code(), Some(1), "{extra:?}");
        let v = json_of(&o);
        assert_eq!(v["rsim_json"], 2);
        assert_eq!(v["kind"], "error");
        assert_eq!(v["error"]["code"], code, "{extra:?}");
        let t = rsim(&args);
        assert_eq!(t.status.code(), Some(1));
        assert!(t.stdout.is_empty());
        let err = String::from_utf8(t.stderr).unwrap();
        assert!(err.starts_with(&format!("error {code}: ")), "{err}");
    }
}

#[test]
fn usage_errors_give_exit_code_2() {
    let q = |extra: &[&'static str]| -> Vec<&'static str> {
        let mut v = vec![
            "path",
            "edge-dnat",
            "--source.ip",
            "198.51.100.7",
            "--destination.ip",
            "1.2.3.4",
            "--network.transport",
            "tcp",
        ];
        v.extend_from_slice(extra);
        v
    };
    let missing_source = vec![
        "path",
        "edge-dnat",
        "--destination.ip",
        "203.0.113.10",
        "--network.transport",
        "tcp",
    ];
    for args in [
        missing_source,
        vec![
            "path",
            "edge-dnat",
            "--source.ip",
            "198.51.100.7",
            "--destination.ip",
            "x",
        ],
        vec![
            "path",
            "edge-dnat",
            "--source.ip",
            "198.51.100.7",
            "--destination.ip",
            "1.2.3.4",
            "--network.transport",
            "xyz",
        ],
        q(&["--destination.port", "70000"]),
        q(&["--dscp", "64"]),
        q(&["--fragment", "middle"]),
        q(&["--network.vlan.id", "4096"]),
        q(&["--source.mac", "00:11"]),
        // The flags of the language of source and destination only.
        q(&["--from", "client"]),
        q(&["--dst", "1.2.3.4"]),
        vec!["nothing"],
    ] {
        assert_eq!(rsim(&args).status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn the_query_echo_is_normalized_and_lists_each_field() {
    let q = |extra: serde_json::Value| {
        let mut v = serde_json::json!({
            "topology": "edge-dnat", "source.ip": "198.51.100.7",
            "destination.ip": "203.0.113.10"
        });
        v.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        rsim_cli::args::query(v.as_object().unwrap(), &[]).unwrap()
    };
    let a = q(serde_json::json!({"network.iana_number": 6, "tcp_flags": ["ack", "syn", "ack"]}));
    let b = q(serde_json::json!({"network.transport": "tcp", "tcp_flags": ["syn", "ack"]}));
    assert_eq!(a.echo(), b.echo());
    let v = serde_json::to_value(a.echo()).unwrap();
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    let mut want = rsim_cli::args::QUERY_FIELDS.to_vec();
    want.sort();
    assert_eq!(keys, want);
    assert_eq!(v["network.iana_number"], 6);
    assert_eq!(v["network.transport"], "tcp");
    assert_eq!(v["tcp_flags"], serde_json::json!(["syn", "ack"]));
    assert_eq!(v["reply"], Value::Null);

    let icmp = q(serde_json::json!({"network.transport": "icmp", "icmp_type": "echo-request"}));
    assert_eq!(serde_json::to_value(icmp.echo()).unwrap()["icmp_type"], 8);
}

#[test]
fn unknown_drop_and_a_reply_that_did_not_run_are_answers_with_exit_code_0() {
    let o = rsim(&[
        "path",
        "edge-dnat",
        "--source.ip",
        "198.51.100.7",
        "--destination.ip",
        "203.0.113.10",
        "--network.transport",
        "tcp",
        "--format",
        "json",
    ]);
    assert_eq!(o.status.code(), Some(0));
    let v = json_of(&o);
    let result = &v["answer"]["summary"][0]["result"];
    assert_eq!(result["kind"], "same");
    assert_eq!(result["verdict_kind"], "unknown");
    assert_eq!(result["verdict"]["reason"]["code"], "match_unknown");
    // The branches are exact: the destination port 443 is translated, and
    // the other ports are not.
    let branches = v["answer"]["branches"].as_array().unwrap();
    assert!(branches.len() >= 2, "{branches:?}");

    let o = rsim(&[
        "path",
        "mini-enterprise",
        "--source.ip",
        "172.31.10.20",
        "--destination.ip",
        "10.20.0.254",
        "--network.transport",
        "udp",
        "--destination.port",
        "53",
        "--format",
        "json",
    ]);
    assert_eq!(o.status.code(), Some(0));
    let v = json_of(&o);
    assert_eq!(
        v["answer"]["branches"][0]["verdict"]["destination"],
        serde_json::json!({"endpoint": null, "device": "fra01-fgt-01"})
    );
    let reply = &v["answer"]["replies"][0];
    assert_eq!(reply["forward_branch"], 0);
    assert_eq!(reply["ran"], false);
    assert!(
        reply["not_run_reason"]
            .as_str()
            .unwrap()
            .contains("fra01-fgt-01")
    );
    assert_eq!(reply["answer"], Value::Null);

    let o = rsim(&[
        "path",
        "edge-dnat",
        "--source.ip",
        "198.51.100.7",
        "--destination.ip",
        "203.0.113.10",
        "--network.transport",
        "icmp",
        "--icmp_type",
        "echo-request",
        "--icmp_code",
        "0",
        "--format",
        "json",
    ]);
    assert_eq!(o.status.code(), Some(0));
    let v = json_of(&o);
    let current = &v["answer"]["input"]["members"][0]["current"];
    assert_eq!(
        current["network.iana_number"],
        serde_json::json!({"known": 1})
    );
    assert_eq!(current["icmp_type"], serde_json::json!({"known": 8}));
    assert_eq!(current["source.port"], "absent");
    assert_eq!(v["answer"]["branches"][0]["verdict"]["kind"], "drop");
    assert_eq!(v["query"]["icmp_type"], 8);
}

#[test]
fn pretty_json_is_the_same_object() {
    let (topology, flags) = QUERIES[0];
    let mut args = path_args(topology, flags);
    args.push("--pretty");
    let o = rsim(&args);
    assert!(stdout(&o).lines().count() > 1);
    let compact: Value = serde_json::from_str(&stored(topology)).unwrap();
    assert_eq!(json_of(&o), compact);
}

/// The set query of the stored set answer.
const SET_QUERY: [&str; 9] = [
    "mini-enterprise",
    "--source.ip",
    "172.31.10.20",
    "--destination.ip",
    "10.20.0.53",
    "--network.transport",
    "udp",
    "--destination.port",
    "53,80",
];

fn set_args(extra: &[&'static str]) -> Vec<&'static str> {
    let mut a = vec!["set"];
    a.extend_from_slice(&SET_QUERY);
    a.extend_from_slice(extra);
    a
}

#[test]
fn a_set_query_gives_the_stored_json_and_the_same_bytes() {
    let want = stored("set-mini-enterprise");
    for _ in 0..2 {
        let o = rsim(&set_args(&["--format", "json"]));
        assert_eq!(o.status.code(), Some(0));
        assert_eq!(stdout(&o), want);
    }
    let v: Value = serde_json::from_str(&want).unwrap();
    assert_eq!(v["kind"], "set_answer");
    assert_eq!(v["answer"]["mode"], "set");
    // The source ports 0 to 1023 are denied by the IPS, the other source
    // ports to port 53 are delivered, and port 80 is denied by the policy.
    let parts = v["answer"]["summary"].as_array().unwrap();
    assert_eq!(parts.len(), 3, "{parts:?}");
    assert!(rsim(&set_args(&[])).status.success());
}

#[test]
fn explain_set_gives_the_step_of_the_set_answer() {
    let answer: Value = serde_json::from_str(&stored("set-mini-enterprise")).unwrap();
    let mut args = vec!["explain-set"];
    args.extend_from_slice(&SET_QUERY);
    args.extend_from_slice(&["--branch", "1", "--step", "7", "--format", "json"]);
    let v = json_of(&rsim(&args));
    assert_eq!(v["kind"], "step");
    assert_eq!(v["query"], answer["query"]);
    assert_eq!(v["trace_step"], answer["answer"]["branches"][1]["steps"][7]);
}

#[test]
fn set_query_errors_and_the_source_of_an_ingress() {
    // A set with no packet: ICMP with ports.
    let o = rsim(&[
        "set",
        "mini-enterprise",
        "--network.transport",
        "icmp",
        "--destination.port",
        "53",
        "--format",
        "json",
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(json_of(&o)["error"]["code"], "invalid_query");
    let o = rsim(&[
        "set",
        "mini-enterprise",
        "--ingress",
        "x/y",
        "--format",
        "json",
    ]);
    assert_eq!(json_of(&o)["error"]["code"], "unknown_ingress");
    for bad in [
        &["set", "mini-enterprise", "--destination.port", "9-1"][..],
        &["set", "mini-enterprise", "--source.ip", "10.0.0.0/33"],
        &["set", "mini-enterprise", "--tcp_flags", "syn+nope"],
    ] {
        assert_eq!(rsim(bad).status.code(), Some(2), "{bad:?}");
    }
    // Without source.ip, the source addresses are the attached addresses of
    // the ingress.
    let o = rsim(&[
        "set",
        "mini-enterprise",
        "--ingress",
        "fra01-fgt-01/port2",
        "--destination.ip",
        "10.20.0.53",
        "--network.transport",
        "udp",
        "--destination.port",
        "53",
        "--source.port",
        "40000",
        "--no-reply",
        "--format",
        "json",
    ]);
    assert_eq!(o.status.code(), Some(0));
    let v = json_of(&o);
    let m = &v["answer"]["input"]["members"][0]["original"];
    assert_eq!(m["source.ip"], serde_json::json!({"known": "172.31.10.20"}));
}

#[path = "support/fixture_store.rs"]
mod fixture_store;

/// A path query on a store: a guest on an SSID reaches a LAN host through
/// the access point, the switch and the router, and the JSON is the same in
/// 2 runs.
#[test]
fn a_path_query_on_a_store_crosses_layer_2_and_the_router() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("rsim-cli-store");
    fixture_store::write(&dir);
    let topology = format!("store:{}", dir.display());
    let args = path_args(
        &topology,
        &[
            "--source.ip",
            "192.0.2.70",
            "--destination.ip",
            "192.0.2.50",
            "--network.transport",
            "tcp",
            "--source.port",
            "40000",
            "--destination.port",
            "8123",
        ],
    );
    let a = rsim(&args);
    assert!(a.status.success(), "{}", String::from_utf8_lossy(&a.stderr));
    let b = rsim(&args);
    assert_eq!(a.stdout, b.stdout);
    let v: Value = serde_json::from_slice(&a.stdout).unwrap();
    let text = v.to_string();
    for f in [
        "ap1/wlan/guest/in",
        "sw1/port/3/in",
        "r1/handoff/eth0",
        "r1/policy",
        "sw1/port/2/out",
    ] {
        assert!(text.contains(f), "{f} not in the answer");
    }
    assert!(
        text.contains("h1-005351"),
        "the answer does not deliver to h1"
    );

    let bad = rsim(&path_args(
        "store:/nonexistent-rsim-store",
        &[
            "--source.ip",
            "192.0.2.70",
            "--destination.ip",
            "192.0.2.50",
        ],
    ));
    assert!(!bad.status.success());
    let e: Value = serde_json::from_slice(&bad.stdout).unwrap_or(Value::Null);
    let shown = format!("{e}{}", String::from_utf8_lossy(&bad.stderr));
    assert!(shown.contains("store"), "{shown}");
}
