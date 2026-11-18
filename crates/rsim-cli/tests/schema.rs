//! Each stored JSON answer is valid against the schema of its kind, and it
//! keeps its bytes after a round trip through the contract types.

use std::path::PathBuf;

use rsim_cli::json::{PathAnswerOut, PathBriefOut, SetAnswerOut, SetBriefOut, to_text};
use rsim_contract::claim::ClaimOut;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

fn golden() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let mut v: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
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

fn check(schema: Value, instance: &Value, name: &str) -> Result<(), String> {
    let mut schemas = boon::Schemas::new();
    let mut compiler = boon::Compiler::new();
    compiler
        .add_resource("urn:rsim:schema", schema)
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    let idx = compiler
        .compile("urn:rsim:schema", &mut schemas)
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    schemas.validate(instance, idx).map_err(|e| e.to_string())
}

fn validate(schema: Value, instance: &Value, name: &str) {
    if let Err(e) = check(schema, instance, name) {
        panic!("{name} is not valid against its schema: {e}");
    }
}

fn round_trip<T: DeserializeOwned + Serialize>(text: &str, name: &str) {
    let v: T = serde_json::from_str(text).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(
        to_text(&v, false) + "\n",
        text,
        "{name} changes in a round trip"
    );
}

#[test]
fn each_stored_answer_is_valid_and_keeps_its_bytes() {
    let files = golden();
    assert!(files.len() >= 8, "{files:?}");
    for (name, text) in files {
        let v: Value = serde_json::from_str(&text).unwrap();
        match v["kind"].as_str() {
            Some("path_answer") => {
                validate(rsim_contract::schema::<PathAnswerOut>(), &v, &name);
                round_trip::<PathAnswerOut>(&text, &name);
            }
            Some("set_answer") => {
                validate(rsim_contract::schema::<SetAnswerOut>(), &v, &name);
                round_trip::<SetAnswerOut>(&text, &name);
            }
            Some("path_brief") => {
                validate(rsim_contract::schema::<PathBriefOut>(), &v, &name);
                round_trip::<PathBriefOut>(&text, &name);
            }
            Some("set_brief") => {
                validate(rsim_contract::schema::<SetBriefOut>(), &v, &name);
                round_trip::<SetBriefOut>(&text, &name);
            }
            Some("claim") => {
                validate(rsim_contract::schema::<ClaimOut>(), &v, &name);
                round_trip::<ClaimOut>(&text, &name);
            }
            k => panic!("{name}: kind {k:?}"),
        }
    }
}

#[test]
fn a_changed_answer_is_not_valid() {
    let (name, text) = golden()
        .into_iter()
        .find(|(n, _)| n == "ecmp.json")
        .unwrap();
    let schema = rsim_contract::schema::<PathAnswerOut>();
    let mut v: Value = serde_json::from_str(&text).unwrap();
    v["answer"]["mode"] = Value::from(5);
    assert!(check(schema.clone(), &v, &name).is_err());
    let mut v: Value = serde_json::from_str(&text).unwrap();
    v["answer"]["branches"][0]["steps"][0]["qos"]["dscp"] = Value::from("sometimes");
    assert!(check(schema.clone(), &v, &name).is_err());
    let mut v: Value = serde_json::from_str(&text).unwrap();
    v["answer"]["input"]["members"][0]["original"]["dscp"] = serde_json::json!({"known": "x"});
    assert!(check(schema, &v, &name).is_err());
}

/// The flags of a command, from its help text.
fn flags(command: &str) -> Vec<String> {
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_rsim"))
        .args([command, "--help"])
        .output()
        .unwrap();
    let mut v: Vec<String> = String::from_utf8(o.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("--"))
        .map(|l| l.split_whitespace().next().unwrap().to_string())
        .collect();
    v.sort();
    v
}

#[test]
fn the_flags_of_the_query_commands_are_the_fields_of_the_registry() {
    for (command, schema) in [
        (
            "path",
            rsim_contract::schema::<rsim_contract::args::PathQueryArgs>(),
        ),
        (
            "set",
            rsim_contract::schema::<rsim_contract::args::SetQueryArgs>(),
        ),
    ] {
        let op = rsim_contract::registry::OPERATIONS
            .iter()
            .find(|o| o.command == Some(command))
            .unwrap();
        assert!(op.input.is_some(), "{command}");
        let mut fields: Vec<String> = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(|k| match k.as_str() {
                // The topology is the positional argument, and the reply
                // is on unless --no-reply is given.
                "reply" => "no-reply".to_string(),
                k => k.to_string(),
            })
            .filter(|k| k != "topology")
            .collect();
        // The output flags of the command line.
        fields.extend(["format".to_string(), "pretty".to_string()]);
        fields.sort();
        assert_eq!(flags(command), fields, "{command}");
    }
}
