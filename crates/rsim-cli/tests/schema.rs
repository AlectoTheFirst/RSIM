//! Each stored JSON answer is valid against the schema of its kind, and it
//! keeps its bytes after a round trip through the contract types.

use std::path::PathBuf;

use rsim_cli::json::{PathAnswerOut, SetAnswerOut, to_text};
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
