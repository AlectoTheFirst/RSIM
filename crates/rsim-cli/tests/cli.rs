//! The command `rsim`: each built-in topology loads by name, a path query
//! for one packet with its reply gives the stored JSON, the same query
//! gives the same bytes, and the errors give their codes and exit codes.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::thread;

use rsim_cli::{QueryInput, commands, json};
use serde_json::Value;

/// One stated query for each built-in topology, as `rsim path` arguments.
const QUERIES: [(&str, &[&str]); 7] = [
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
    (
        "leaf-spine",
        &[
            "--source.ip",
            "10.1.0.10",
            "--destination.ip",
            "10.2.0.10",
            "--network.transport",
            "tcp",
            "--source.port",
            "40000",
            "--destination.port",
            "22",
        ],
    ),
];

/// More stated queries of the topology `leaf-spine`: the name of the stored
/// file and the `rsim path` arguments.
const FABRIC_QUERIES: [(&str, &[&str]); 2] = [
    (
        "leaf-spine-acl",
        &[
            "--source.ip",
            "10.1.0.10",
            "--destination.ip",
            "10.3.0.10",
            "--network.transport",
            "udp",
            "--source.port",
            "40000",
            "--destination.port",
            "53",
        ],
    ),
    (
        "leaf-spine-no-route",
        &[
            "--source.ip",
            "10.1.0.10",
            "--destination.ip",
            "10.4.0.10",
            "--network.transport",
            "udp",
            "--source.port",
            "40000",
            "--destination.port",
            "53",
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
fn the_brief_forms_give_the_stored_json() {
    let (_, flags) = QUERIES.iter().find(|(t, _)| *t == "leaf-spine").unwrap();
    for form in ["summary", "steps"] {
        let mut a = path_args("leaf-spine", flags);
        a.extend_from_slice(&["--form", form]);
        let o = rsim(&a);
        assert_eq!(o.status.code(), Some(0), "{form}");
        assert_eq!(stdout(&o), stored(&format!("leaf-spine.{form}")), "{form}");
    }
    let a = set_args(&["--format", "json", "--form", "summary"]);
    let o = rsim(&a);
    assert_eq!(stdout(&o), stored("set-mini-enterprise.summary"));
}

#[test]
fn the_fabric_queries_give_the_stored_json() {
    for (file, flags) in FABRIC_QUERIES {
        let o = rsim(&path_args("leaf-spine", flags));
        assert_eq!(o.status.code(), Some(0), "{file}");
        assert_eq!(stdout(&o), stored(file), "{file} differs from its file");
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
    // `unstated` and the fields of the TPIDs and of the inner tag are in the
    // echo only when the query gives them.
    let only_given = [
        "unstated",
        "network.vlan.tpid",
        "network.inner.vlan.id",
        "inner_l2_priority",
        "network.inner.vlan.tpid",
    ];
    let mut want: Vec<&str> = rsim_cli::args::QUERY_FIELDS
        .into_iter()
        .filter(|k| !only_given.contains(k))
        .collect();
    want.sort();
    assert_eq!(keys, want);
    let t = q(serde_json::json!({
        "network.transport": "tcp", "network.vlan.id": 10, "network.vlan.tpid": 34984,
        "network.inner.vlan.id": 20, "inner_l2_priority": 3, "network.inner.vlan.tpid": 33024
    }));
    let t = serde_json::to_value(t.echo()).unwrap();
    assert_eq!(t["network.vlan.tpid"], 34984);
    assert_eq!(t["network.inner.vlan.id"], 20);
    assert_eq!(t["inner_l2_priority"], 3);
    assert_eq!(t["network.inner.vlan.tpid"], 33024);
    let d = q(serde_json::json!({"network.transport": "tcp", "unstated": "defaults"}));
    assert_eq!(
        serde_json::to_value(d.echo()).unwrap()["unstated"],
        "defaults"
    );
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
    // The answer names the snapshot cycle of the store.
    let cycle = v["twin"]["snapshot"].as_u64().expect("a snapshot cycle");
    assert_eq!(
        v["twin"],
        serde_json::json!({
            "id": format!("snap-{cycle}"),
            "base": format!("snap-{cycle}"),
            "snapshot": cycle,
            "layers": []
        })
    );
    // The coverage table of a store twin has the unhandled stanzas.
    let cov = rsim(&[topology.as_str(), "coverage", "--format", "json"]);
    assert_eq!(cov.status.code(), Some(0));
    let cov: Value = serde_json::from_slice(&cov.stdout).unwrap();
    assert_eq!(cov["kind"], "table_rows");
    assert!(cov["total"].as_u64().unwrap() > 0, "{cov}");
    // The fixture store has no LLDP or CDP section, so no neighbour is seen.
    let seen = rsim(&[topology.as_str(), "neighbours", "--format", "json"]);
    assert_eq!(seen.status.code(), Some(0));
    let seen: Value = serde_json::from_slice(&seen.stdout).unwrap();
    assert_eq!(seen["total"], 0, "{seen}");
    // The BGP peers of a store twin: the configured neighbours joined with
    // the session rows, the listen range, the dynamic peer of the range and
    // the observed peers with no neighbour.
    let bgp = rsim(&[topology.as_str(), "bgp-sessions", "--format", "json"]);
    assert_eq!(bgp.status.code(), Some(0));
    let bgp: Value = serde_json::from_slice(&bgp.stdout).unwrap();
    let cols: Vec<&str> = bgp["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    let col = |row: &Value, name: &str| row[cols.iter().position(|c| *c == name).unwrap()].clone();
    let rows = bgp["rows"].as_array().unwrap();
    let by_peer: BTreeMap<String, &Value> = rows
        .iter()
        .map(|r| (col(r, "peer").as_str().unwrap().to_string(), r))
        .collect();
    let source = |p: &str| col(by_peer[p], "source");
    assert_eq!(source("192.0.2.2"), "configured");
    assert_eq!(col(by_peer["192.0.2.2"], "established"), true);
    assert_eq!(col(by_peer["192.0.2.2"], "peer_asn"), 64501);
    assert_eq!(
        col(by_peer["192.0.2.2"], "local_asn"),
        serde_json::json!(["64505"])
    );
    assert_eq!(col(by_peer["192.0.2.2"], "outcome"), "complete");
    assert_eq!(source("198.51.100.6"), "configured");
    assert_eq!(col(by_peer["198.51.100.6"], "state"), serde_json::json!([]));
    assert_eq!(col(by_peer["198.51.100.6"], "in_scope"), true);
    assert_eq!(source("198.51.100.2"), "configured");
    assert_eq!(col(by_peer["198.51.100.2"], "shutdown"), true);
    assert_eq!(source("203.0.113.0/28"), "listen-range");
    assert_eq!(source("203.0.113.5"), "dynamic");
    assert_eq!(col(by_peer["203.0.113.5"], "range"), "203.0.113.0/28");
    assert_eq!(source("192.0.2.9"), "observed");
    assert_eq!(source("2001:db8::2"), "observed");
    assert_eq!(rows.len(), 7, "{bgp}");
    assert!(!bgp.to_string().contains("FAKE"), "{bgp}");
    // The provenance of each row lists each span once.
    for r in rows {
        let spans = col(r, "provenance");
        let spans = spans.as_array().unwrap();
        let unique: std::collections::BTreeSet<String> =
            spans.iter().map(Value::to_string).collect();
        assert_eq!(unique.len(), spans.len(), "{r}");
    }
    // The devices of a store twin with their facts: the router from its
    // version section and its manifest, and each device record of the UniFi
    // console, the gateway record too, which the site lowering does not
    // lower.
    let dev = rsim(&[topology.as_str(), "devices", "--format", "json"]);
    assert_eq!(dev.status.code(), Some(0));
    let dev: Value = serde_json::from_slice(&dev.stdout).unwrap();
    let cols: Vec<&str> = dev["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    let by_device: BTreeMap<&str, BTreeMap<&str, &Value>> = dev["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let r: BTreeMap<&str, &Value> =
                cols.iter().copied().zip(r.as_array().unwrap()).collect();
            (r["device"].as_str().unwrap(), r)
        })
        .collect();
    assert_eq!(
        by_device.keys().copied().collect::<Vec<_>>(),
        ["ap1", "gw1", "r1", "sw1"]
    );
    let r1 = &by_device["r1"];
    assert_eq!(*r1["vendor"], "vyos");
    assert_eq!(*r1["platform"], "Fake Router 1000");
    assert_eq!(*r1["os_version"], "1.4.0");
    assert_eq!(*r1["serial"], "FAKER10001");
    assert_eq!(*r1["serial_reason"], Value::Null);
    assert_eq!(*r1["management_address"], "192.0.2.254");
    assert_eq!(*r1["collected_at"], "1970-01-01T00:00:00Z");
    assert_eq!(*r1["store_device"], "r1");
    let spans = r1["provenance"].as_array().unwrap();
    assert_eq!(spans.len(), 3, "{spans:?}");
    assert!(
        spans
            .iter()
            .all(|s| s.as_str().unwrap().starts_with("r1/version@"))
    );
    let sw1 = &by_device["sw1"];
    assert_eq!(*sw1["vendor"], "unifi");
    assert_eq!(*sw1["serial"], "FAKESW0001");
    assert_eq!(*sw1["management_address"], "198.51.100.11");
    assert_eq!(*sw1["store_device"], "site1");
    // The 4 facts of a UniFi record share the row span of the record.
    assert_eq!(sw1["provenance"].as_array().unwrap().len(), 1, "{sw1:?}");
    assert_eq!(*by_device["ap1"]["serial"], Value::Null);
    assert_eq!(*by_device["ap1"]["serial_reason"], "not_read");
    assert_eq!(*by_device["gw1"]["platform_reason"], "not_read");
    // The BGP claims of a store twin: the peers of the one router are
    // outside the twin, except the dynamic peer of the listen range, and a
    // neighbour has shutdown. bgp-peers-up checks the peers outside the twin
    // from the session state: 198.51.100.6 is not in the complete session
    // table.
    let claim = |name: &str| {
        let c = rsim(&[topology.as_str(), "claim", "run", name, "--format", "json"]);
        serde_json::from_slice::<Value>(&c.stdout).unwrap()
    };
    let up = claim("bgp-peers-up");
    assert_eq!(up["result"], "refuted", "{up}");
    let rows: Vec<(&str, &str)> = up["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["subject"].as_str().unwrap(),
                e["result"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            ("r1 vrf default neighbour 192.0.2.2", "confirmed"),
            ("r1 vrf default neighbour 198.51.100.6", "refuted"),
            ("r1 vrf default neighbour 203.0.113.5", "confirmed"),
        ]
    );
    assert_eq!(up["evidence"][1]["detail"], "not in session table");
    assert_eq!(up["detail"], "left out: 1 with shutdown");
    let agree = claim("bgp-peers-agree");
    assert_eq!(agree["result"], "unknown", "{agree}");
    assert_eq!(
        agree["detail"],
        "no BGP neighbour in scope; left out: 1 with shutdown, 2 with the peer outside the twin"
    );
    // The links of a store twin have collected facts for the claim.
    let c = rsim(&[
        topology.as_str(),
        "claim",
        "run",
        "link-speed-duplex",
        "--format",
        "json",
    ]);
    let c: Value = serde_json::from_slice(&c.stdout).unwrap();
    assert_eq!(c["kind"], "claim", "{c}");
    assert!(!c["evidence"].as_array().unwrap().is_empty(), "{c}");
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

#[test]
fn a_table_query_gives_rows_pages_and_the_bytes_of_the_library() {
    let o = rsim(&[
        "leaf-spine",
        "fib",
        "lpm",
        "10.2.0.10",
        "--device",
        "leaf1",
        "--format",
        "json",
    ]);
    assert_eq!(o.status.code(), Some(0));
    let v = json_of(&o);
    assert_eq!(v["kind"], "table_rows");
    assert_eq!(v["twin"]["id"], "builtin.leaf-spine");
    assert_eq!(v["rows"].as_array().unwrap().len(), 1);
    assert_eq!(v["rows"][0][2], "10.2.0.0/24");

    // The library gives the same bytes.
    let twin = commands::load("leaf-spine").unwrap();
    let mut sel = rsim_contract::table::Selection::default();
    sel.filters.insert("device".into(), vec!["leaf1".into()]);
    let lib =
        rsim_cli::tables::lpm("leaf-spine", &twin, "fib", "prefix", "10.2.0.10", &sel).unwrap();
    assert_eq!(stdout(&o), json::to_text(&lib, false) + "\n");

    // The joined pages are the rows with no pages.
    let all = json_of(&rsim(&["mini-enterprise", "functions", "--format", "json"]));
    let mut joined = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut a = vec![
            "mini-enterprise",
            "functions",
            "--limit",
            "7",
            "--format",
            "json",
        ];
        if let Some(c) = &cursor {
            a.extend_from_slice(&["--cursor", c.as_str()]);
        }
        let page = json_of(&rsim(&a));
        joined.extend(page["rows"].as_array().unwrap().iter().cloned());
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    assert_eq!(Value::from(joined), all["rows"]);
    assert_eq!(all["total"], all["rows"].as_array().unwrap().len());

    // Text output has one header line and one line for each row.
    let t = stdout(&rsim(&["leaf-spine", "devices"]));
    assert!(t.starts_with("device"), "{t}");
    assert_eq!(t.lines().count(), 7, "{t}");
    // A built-in topology has no collection, so each fact of a device is
    // not collected.
    let d = json_of(&rsim(&[
        "leaf-spine",
        "devices",
        "--device",
        "leaf1",
        "--format",
        "json",
    ]));
    let row: BTreeMap<&str, &Value> = d["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .zip(d["rows"][0].as_array().unwrap())
        .collect();
    for fact in [
        "vendor",
        "platform",
        "os_version",
        "serial",
        "management_address",
        "collected_at",
    ] {
        assert_eq!(*row[fact], Value::Null, "{fact}");
        assert_eq!(*row[format!("{fact}_reason").as_str()], "not_collected");
    }

    // Errors.
    let o = rsim(&["leaf-spine", "colours", "--format", "json"]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(json_of(&o)["error"]["code"], "unknown_table");
    let o = rsim(&["leaf-spine", "fib", "--colour", "red", "--format", "json"]);
    assert_eq!(json_of(&o)["error"]["code"], "invalid_filter");
    // A built-in topology has no coverage report.
    let o = rsim(&["leaf-spine", "coverage", "--format", "json"]);
    assert_eq!(json_of(&o)["total"], 0);
}

#[test]
fn a_claim_gives_its_result_its_evidence_and_its_exit_code() {
    let path = [
        "--source.ip",
        "10.1.0.10",
        "--destination.ip",
        "10.2.0.10",
        "--network.transport",
        "tcp",
        "--destination.port",
        "22",
    ];
    let run = |twin: &str, claim: &str, extra: &[&str]| {
        let mut a = vec![twin, "claim", "run", claim];
        a.extend_from_slice(extra);
        a.extend_from_slice(&["--format", "json"]);
        rsim(&a)
    };
    let o = run("leaf-spine", "no-unknown", &path);
    assert_eq!(o.status.code(), Some(0));
    let v = json_of(&o);
    assert_eq!(
        (v["kind"].as_str(), v["result"].as_str()),
        (Some("claim"), Some("confirmed"))
    );
    assert_eq!(v["scope"], "query");
    assert_eq!(v["counts"]["confirmed"], 6);

    // With no port, the result of ecmp depends on a field that the query
    // does not state, so the claim is refuted.
    let o = run(
        "ecmp",
        "no-unknown",
        &[
            "--source.ip",
            "10.1.0.10",
            "--destination.ip",
            "10.4.0.10",
            "--network.transport",
            "tcp",
        ],
    );
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(json_of(&o)["result"], "refuted");

    // Data that is not collected gives unknown, never confirmed.
    let o = run("leaf-spine", "link-speed-duplex", &[]);
    assert_eq!(o.status.code(), Some(3));
    let v = json_of(&o);
    assert_eq!(v["result"], "unknown");
    assert_eq!(v["evidence"][0]["reason"], "not_collected");
    // A built-in topology has no BGP neighbour, so the BGP claims are
    // unknown with no row.
    for claim in ["bgp-peers-up", "bgp-peers-agree"] {
        let o = run("leaf-spine", claim, &[]);
        assert_eq!(o.status.code(), Some(3), "{claim}");
        let v = json_of(&o);
        assert_eq!(v["result"], "unknown", "{claim}");
        assert_eq!(v["evidence"], serde_json::json!([]), "{claim}");
        assert_eq!(v["detail"], "no BGP neighbour in scope", "{claim}");
    }

    // The claim no-unknown needs a query.
    let o = run("leaf-spine", "no-unknown", &[]);
    assert_eq!(json_of(&o)["error"]["code"], "invalid_query");
    let o = rsim(&["leaf-spine", "claim", "list", "--format", "json"]);
    assert_eq!(json_of(&o)["claims"][0]["name"], "link-speed-duplex");
}

#[test]
fn unstated_defaults_give_the_answer_of_the_stated_defaults_and_a_note() {
    let flags = QUERIES[0].1;
    let mut a = path_args("mini-enterprise", flags);
    a.extend_from_slice(&["--unstated", "defaults"]);
    let defaults = json_of(&rsim(&a));
    let note = defaults["notes"][0].as_str().expect("a note");
    assert_eq!(note, "defaults: dscp 0, ecn 0, no VLAN");
    assert_eq!(defaults["query"]["unstated"], "defaults");

    // The same answer as the query with each default stated.
    let twin = commands::load("mini-enterprise").unwrap();
    let mut input = stored_input("mini-enterprise");
    let mut h = input.header().unwrap();
    h.vlan = rsim_core::FieldValue::Absent;
    h.l2_priority = rsim_core::FieldValue::Absent;
    h = h.with_dscp(0).with_ecn(0);
    let stated = rsim_engine::Executor::new(&twin)
        .run(&rsim_engine::Query::path(&twin, &h))
        .unwrap();
    assert_eq!(
        serde_json::to_value(
            <rsim_contract::json::AnswerJson as rsim_cli::json::FromEngine<_>>::new(&stated)
        )
        .unwrap(),
        defaults["answer"]
    );

    // `all` is the default: the same answer as no setting, with no note.
    input.unstated = Some(rsim_cli::query::Unstated::All);
    let all = serde_json::to_value(commands::path(&input, &twin).unwrap()).unwrap();
    let golden: Value = serde_json::from_str(&stored("mini-enterprise")).unwrap();
    assert_eq!(all["answer"], golden["answer"]);
    assert!(all.get("notes").is_none());
    assert_eq!(all["query"]["unstated"], "all");
    assert!(golden["query"].get("unstated").is_none());

    // A set query does not take the setting.
    let o = rsim(&[
        "set",
        "mini-enterprise",
        "--source.ip",
        "172.31.10.20",
        "--unstated",
        "defaults",
    ]);
    assert!(!o.status.success());
}

/// The answer of a path query with the defaults stated by hand: the header
/// with each value, and the source port range in the packet set.
fn answer_with_stated_defaults(
    twin: &rsim_cli::commands::Loaded,
    h: &rsim_core::Header,
    source_ports: Option<(u16, u16)>,
) -> Value {
    let mut q = rsim_engine::Query::path(twin, h);
    if let Some(r) = source_ports {
        let spec = rsim_core::SetSpec {
            src_port: Some(vec![r]),
            ..Default::default()
        };
        q.packets = q
            .packets
            .intersect(&rsim_core::PacketSet::from_spec(q.packets.arena(), &spec));
    }
    let a = rsim_engine::Executor::new(twin).run(&q).unwrap();
    serde_json::to_value(
        <rsim_contract::json::AnswerJson as rsim_cli::json::FromEngine<_>>::new(&a),
    )
    .unwrap()
}

#[test]
fn unstated_defaults_give_an_ephemeral_source_port_range_with_the_destination_port_stated() {
    let flags = [
        "--source.ip",
        "172.31.10.20",
        "--destination.ip",
        "10.20.0.53",
        "--network.transport",
        "udp",
        "--destination.port",
        "53",
        "--unstated",
        "defaults",
    ];
    let out = json_of(&rsim(&path_args("mini-enterprise", &flags)));
    assert_eq!(
        out["notes"][0],
        "defaults: dscp 0, ecn 0, no VLAN, source.port 49152-65535"
    );
    let twin = commands::load("mini-enterprise").unwrap();
    let mut h = stored_input("mini-enterprise").header().unwrap();
    h.src_port = rsim_core::FieldValue::Unstated;
    h.vlan = rsim_core::FieldValue::Absent;
    h.l2_priority = rsim_core::FieldValue::Absent;
    h = h.with_dscp(0).with_ecn(0);
    assert_eq!(
        answer_with_stated_defaults(&twin, &h, Some((49152, 65535))),
        out["answer"]
    );
    // The range keeps the answer exact: the result of the port 40000.
    let golden: Value = serde_json::from_str(&stored("mini-enterprise")).unwrap();
    assert_eq!(
        out["answer"]["summary"][0]["result"],
        golden["answer"]["summary"][0]["result"]
    );
    assert_eq!(
        out["answer"]["replies"][0]["ran"],
        golden["answer"]["replies"][0]["ran"]
    );
}

#[test]
fn unstated_defaults_give_tcp_syn_and_the_reply_syn_ack() {
    let flags = [
        "--source.ip",
        "198.51.100.7",
        "--destination.ip",
        "203.0.113.10",
        "--network.transport",
        "tcp",
        "--destination.port",
        "443",
        "--unstated",
        "defaults",
    ];
    let out = json_of(&rsim(&path_args("edge-dnat", &flags)));
    assert_eq!(
        out["notes"][0],
        "defaults: dscp 0, ecn 0, no VLAN, tcp syn, source.port 49152-65535"
    );
    let golden: Value = serde_json::from_str(&stored("edge-dnat")).unwrap();
    assert_eq!(
        out["answer"]["summary"][0]["result"],
        golden["answer"]["summary"][0]["result"]
    );
    let text = serde_json::to_string(&out["answer"]["replies"]).unwrap();
    // SYN and ACK: 0x12.
    assert!(text.contains(r#""tcp_flags":{"known":18}"#), "{text}");
    let request = serde_json::to_string(&out["answer"]["summary"]).unwrap();
    assert!(request.contains(r#""tcp_flags":{"known":2}"#), "{request}");
}

#[test]
fn unstated_defaults_give_an_icmp_echo_request() {
    let flags = [
        "--source.ip",
        "172.31.10.20",
        "--destination.ip",
        "10.20.0.53",
        "--network.transport",
        "icmp",
        "--unstated",
        "defaults",
    ];
    let out = json_of(&rsim(&path_args("mini-enterprise", &flags)));
    assert_eq!(
        out["notes"][0],
        "defaults: dscp 0, ecn 0, no VLAN, icmp_type echo-request, icmp_code 0"
    );
    let twin = commands::load("mini-enterprise").unwrap();
    let mut input = stored_input("mini-enterprise");
    input.transport = None;
    input.source_port = None;
    input.destination_port = None;
    input.iana_number = Some(1);
    let mut h = input.header().unwrap();
    h.vlan = rsim_core::FieldValue::Absent;
    h.l2_priority = rsim_core::FieldValue::Absent;
    h = h.with_dscp(0).with_ecn(0);
    h.icmp_type = rsim_core::FieldValue::Known(8);
    h.icmp_code = rsim_core::FieldValue::Known(0);
    assert_eq!(answer_with_stated_defaults(&twin, &h, None), out["answer"]);
}

/// Each header object of a JSON answer: an object with `network.vlan.id`.
fn headers(v: &Value, out: &mut Vec<serde_json::Map<String, Value>>) {
    match v {
        Value::Object(o) => {
            if o.contains_key("network.vlan.id") && o.contains_key("source.ip") {
                out.push(o.clone());
            }
            o.values().for_each(|x| headers(x, out));
        }
        Value::Array(a) => a.iter().for_each(|x| headers(x, out)),
        _ => {}
    }
}

fn tag_headers(v: &Value) -> Vec<serde_json::Map<String, Value>> {
    let mut out = Vec::new();
    headers(&v["answer"], &mut out);
    assert!(!out.is_empty());
    out
}

#[test]
fn a_query_with_2_tags_shows_the_inner_tag_and_a_tpid_that_is_not_802_1q() {
    let mut a = path_args("mini-enterprise", QUERIES[0].1);
    a.extend_from_slice(&[
        "--network.vlan.id",
        "10",
        "--network.vlan.tpid",
        "34984",
        "--network.inner.vlan.id",
        "20",
        "--inner_l2_priority",
        "3",
    ]);
    let v = json_of(&rsim(&a));
    assert_eq!(v["query"]["network.vlan.tpid"], 34984);
    assert_eq!(v["query"]["network.inner.vlan.id"], 20);
    assert!(v["query"].get("network.inner.vlan.tpid").is_none());
    let first = &v["answer"]["branches"][0]["steps"][0]["input"]["members"][0]["original"];
    assert_eq!(
        first["network.vlan.tpid"],
        serde_json::json!({"known": 34984})
    );
    assert_eq!(
        first["network.inner.vlan.id"],
        serde_json::json!({"known": 20})
    );
    assert_eq!(first["inner_l2_priority"], serde_json::json!({"known": 3}));
    // The inner TPID is 0x8100, so the answer does not show it.
    for h in tag_headers(&v) {
        assert!(!h.contains_key("network.inner.vlan.tpid"), "{h:?}");
    }
    // With one tag, no header shows a TPID or an inner tag.
    let mut one = path_args("mini-enterprise", QUERIES[0].1);
    one.extend_from_slice(&["--network.vlan.id", "10"]);
    for h in tag_headers(&json_of(&rsim(&one))) {
        for k in [
            "network.vlan.tpid",
            "network.inner.vlan.id",
            "inner_l2_priority",
            "network.inner.vlan.tpid",
        ] {
            assert!(!h.contains_key(k), "{k} in {h:?}");
        }
    }
}

#[test]
fn a_tag_field_needs_the_tag_above_it() {
    let base = path_args("mini-enterprise", QUERIES[0].1);
    for (extra, detail) in [
        (
            &["--network.inner.vlan.id", "20"][..],
            "network.inner.vlan.id is given and network.vlan.id is not",
        ),
        (
            &["--network.vlan.tpid", "34984"][..],
            "network.vlan.tpid is given and network.vlan.id is not",
        ),
        (
            &["--network.vlan.id", "10", "--inner_l2_priority", "3"][..],
            "inner_l2_priority is given and network.inner.vlan.id is not",
        ),
        (
            &[
                "--network.vlan.id",
                "10",
                "--network.inner.vlan.tpid",
                "33024",
            ][..],
            "network.inner.vlan.tpid is given and network.inner.vlan.id is not",
        ),
    ] {
        let mut a = base.clone();
        a.extend_from_slice(extra);
        let o = rsim(&a);
        assert_eq!(o.status.code(), Some(1), "{extra:?}");
        let v = json_of(&o);
        assert_eq!(v["error"]["code"], "invalid_query", "{v}");
        assert_eq!(v["error"]["detail"], detail);
    }
}

#[test]
fn unstated_defaults_give_a_stated_inner_tag_the_outer_tpid_of_802_1ad() {
    let mut a = path_args("mini-enterprise", QUERIES[0].1);
    a.extend_from_slice(&[
        "--unstated",
        "defaults",
        "--network.vlan.id",
        "10",
        "--network.inner.vlan.id",
        "20",
    ]);
    let v = json_of(&rsim(&a));
    assert_eq!(
        v["notes"][0],
        "defaults: dscp 0, ecn 0, network.vlan.tpid 0x88a8"
    );
    let first = &v["answer"]["branches"][0]["steps"][0]["input"]["members"][0]["original"];
    assert_eq!(
        first["network.vlan.tpid"],
        serde_json::json!({"known": 34984})
    );
    // A stated outer TPID keeps its value, and with `all` the TPID is 0x8100.
    let mut stated = a.clone();
    stated.extend_from_slice(&["--network.vlan.tpid", "37120"]);
    let v = json_of(&rsim(&stated));
    assert_eq!(v["notes"][0], "defaults: dscp 0, ecn 0");
    let all: Vec<&str> = a
        .iter()
        .copied()
        .filter(|s| *s != "--unstated" && *s != "defaults")
        .collect();
    for h in tag_headers(&json_of(&rsim(&all))) {
        assert!(!h.contains_key("network.vlan.tpid"), "{h:?}");
    }
}

#[test]
fn a_set_query_with_an_inner_tag_holds_only_frames_with_2_tags() {
    let v = json_of(&rsim(&set_args(&[
        "--network.vlan.id",
        "10",
        "--network.inner.vlan.id",
        "20-21",
        "--format",
        "json",
    ])));
    assert_eq!(v["query"]["network.inner.vlan.id"], "20-21");
    let o = rsim(&set_args(&[
        "--network.inner.vlan.id",
        "20",
        "--format",
        "json",
    ]));
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(
        json_of(&o)["error"]["detail"],
        "network.inner.vlan.id is given and network.vlan.id is not"
    );
    assert!(v["query"].get("network.vlan.tpid").is_none());
    let first = &v["answer"]["branches"][0]["steps"][0]["input"]["members"];
    for m in first.as_array().unwrap() {
        assert_eq!(
            m["original"]["network.vlan.id"],
            serde_json::json!({"known": 10})
        );
        assert!(m["original"].get("network.inner.vlan.id").is_some(), "{m}");
    }
}
