//! The records of the engine against the records of Python textfsm 2.1.0.
//!
//! Each input `<group>/<case>.txt` has `<case>.json` beside it, written by
//! `tests/fixtures/conformance/expected.py`. In `conformance/` the group is a
//! template that the crate carries, and the expected records come from the
//! template as ntc-templates or HST ship it. In `language/` the group holds
//! its own `template.textfsm`.

use std::fs;
use std::path::{Path, PathBuf};

use rsim_textfsm::{Field, Item, Library, ParseError, Table, Template};
use serde_json::{Value, json};

/// The templates that differ from the template that gives the expected
/// records. Their rules are numbered in another way, so an error is compared
/// by its input line only.
const CHANGED: &[&str] = &["cisco_ios_show_ip_access-lists.textfsm"];

fn fixtures(group: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(group)
}

/// The inputs of a fixture folder, sorted.
fn cases(root: &Path) -> Vec<PathBuf> {
    let mut cases = Vec::new();
    for group in fs::read_dir(root).unwrap() {
        let group = group.unwrap().path();
        if !group.is_dir() {
            continue;
        }
        for case in fs::read_dir(&group).unwrap() {
            let case = case.unwrap().path();
            if case.extension().is_some_and(|e| e == "txt") {
                cases.push(case);
            }
        }
    }
    cases.sort();
    cases
}

fn to_json(table: &Table) -> Value {
    let records: Vec<Value> = table
        .records
        .iter()
        .map(|record| record.iter().map(field_json).collect())
        .collect();
    json!({ "header": table.header, "records": records })
}

fn field_json(field: &Field) -> Value {
    match field {
        Field::Text(text) => json!(text),
        Field::List(items) => items
            .iter()
            .map(|item| match item {
                Item::Text(text) => json!(text),
                Item::Missing => Value::Null,
                Item::Map(groups) => groups
                    .iter()
                    .map(|(name, text)| (name.clone(), json!(text)))
                    .collect::<serde_json::Map<_, _>>()
                    .into(),
            })
            .collect(),
    }
}

/// Compares one input with its expected result; `None` when they agree.
fn check(case: &Path, template: Result<&Template, String>, changed: bool) -> Option<String> {
    let expected: Value =
        serde_json::from_str(&fs::read_to_string(case.with_extension("json")).unwrap()).unwrap();
    let input = fs::read_to_string(case).unwrap();
    let name = case.display();
    if let Some(error) = expected.get("template_error") {
        return template
            .is_ok()
            .then(|| format!("{name}: the template reads, Python says {error}"));
    }
    let template = match template {
        Ok(template) => template,
        Err(error) => return Some(format!("{name}: {error}")),
    };
    match (template.parse_text(&input), expected.get("error")) {
        (Ok(table), None) => {
            let got = to_json(&table);
            let want = json!({ "header": expected["header"], "records": expected["records"] });
            (got != want).then(|| format!("{name}: records differ\n got {got}\nwant {want}"))
        }
        (Err(error), Some(Value::String(want))) => {
            let agrees = match &error {
                ParseError::Rule { input, .. } if changed => {
                    want.contains(&format!("Input Line: {input}"))
                }
                _ => &error.to_string() == want,
            };
            (!agrees).then(|| format!("{name}: error {error}, Python says {want}"))
        }
        (Ok(_), Some(want)) => Some(format!("{name}: parses, Python says {want}")),
        (Err(error), _) => Some(format!("{name}: {error}, Python parses")),
    }
}

#[test]
fn the_carried_templates_give_the_records_of_python_textfsm() {
    let library = Library::builtin().unwrap();
    let cases = cases(&fixtures("conformance"));
    let mut failures = Vec::new();
    let mut covered = std::collections::BTreeSet::new();
    for case in &cases {
        let file = format!(
            "{}.textfsm",
            case.parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
        );
        let template = library
            .template(&file)
            .ok_or_else(|| format!("no template {file}"));
        failures.extend(check(case, template, CHANGED.contains(&file.as_str())));
        covered.insert(file);
    }
    for (file, _) in rsim_textfsm::BUILTIN_TEMPLATES {
        if !covered.contains(*file) {
            failures.push(format!("{file}: no conformance input"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(cases.len() >= 50, "{} inputs", cases.len());
}

#[test]
fn the_language_features_behave_as_in_python_textfsm() {
    let cases = cases(&fixtures("language"));
    let mut failures = Vec::new();
    for case in &cases {
        let text = fs::read_to_string(case.parent().unwrap().join("template.textfsm")).unwrap();
        let template = Template::parse(&text).map_err(|e| e.to_string());
        failures.extend(check(case, template.as_ref().map_err(Clone::clone), false));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(cases.len() >= 15, "{} inputs", cases.len());
}

#[test]
fn the_index_selects_the_template_of_each_command_of_hst() {
    let library = Library::builtin().unwrap();
    let commands = [
        ("cisco_xr", "show version", "cisco_xr_show_version.textfsm"),
        (
            "cisco_xr",
            "show inventory",
            "cisco_xr_admin_show_inventory.textfsm",
        ),
        (
            "cisco_xr",
            "show vrf all detail",
            "cisco_xr_show_vrf_all_detail.textfsm",
        ),
        (
            "cisco_xr",
            "show interfaces",
            "cisco_xr_show_interfaces.textfsm",
        ),
        (
            "cisco_xr",
            "show lldp neighbors detail",
            "cisco_xr_show_lldp_neighbors_detail.textfsm",
        ),
        (
            "cisco_xr",
            "show cdp neighbors detail",
            "cisco_xr_show_cdp_neighbors_detail.textfsm",
        ),
        (
            "cisco_xr",
            "show route vrf all ipv4",
            "cisco_xr_show_ip_route.textfsm",
        ),
        ("cisco_xr", "show arp vrf all", "cisco_xr_show_arp.textfsm"),
        ("cisco_xr", "show arp", "cisco_xr_show_arp.textfsm"),
        ("cisco_xr", "show hsrp", "cisco_xr_show_hsrp.textfsm"),
        (
            "cisco_xr",
            "show ospf neighbor",
            "cisco_xr_show_ospf_neighbor.textfsm",
        ),
        (
            "cisco_ios",
            "show version",
            "cisco_ios_show_version.textfsm",
        ),
        ("cisco_ios", "show vrf", "cisco_ios_show_vrf.textfsm"),
        (
            "cisco_ios",
            "show vrf detail",
            "cisco_ios_show_vrf_detail.textfsm",
        ),
        (
            "cisco_ios",
            "show interfaces",
            "cisco_ios_show_interfaces.textfsm",
        ),
        (
            "cisco_ios",
            "show lldp neighbors detail",
            "cisco_ios_show_lldp_neighbors_detail.textfsm",
        ),
        (
            "cisco_ios",
            "show cdp neighbors detail",
            "cisco_ios_show_cdp_neighbors_detail.textfsm",
        ),
        (
            "cisco_ios",
            "show ip route vrf *",
            "cisco_ios_show_ip_route.textfsm",
        ),
        ("cisco_ios", "show ip arp", "cisco_ios_show_ip_arp.textfsm"),
        (
            "cisco_ios",
            "show ip arp vrf BLUE",
            "cisco_ios_show_ip_arp.textfsm",
        ),
        (
            "cisco_ios",
            "show ip access-lists",
            "cisco_ios_show_ip_access-lists.textfsm",
        ),
        (
            "cisco_ios",
            "show standby brief",
            "cisco_ios_show_standby_brief.textfsm",
        ),
        (
            "cisco_ios",
            "show vrrp brief",
            "cisco_ios_show_vrrp_brief.textfsm",
        ),
        (
            "cisco_ios",
            "show ip ospf neighbor",
            "cisco_ios_show_ip_ospf_neighbor.textfsm",
        ),
        (
            "cisco_ios",
            "show ip ospf database router",
            "cisco_ios_show_ip_ospf_database_router.textfsm",
        ),
        (
            "cisco_ios",
            "show ip ospf database network",
            "cisco_ios_show_ip_ospf_database_network.textfsm",
        ),
        (
            "cisco_ios",
            "show ip bgp summary",
            "cisco_ios_show_ip_bgp_summary.textfsm",
        ),
    ];
    for (platform, command, want) in commands {
        let found = library.find(platform, command).map(|(name, _)| name);
        assert_eq!(found, Some(want), "{platform} {command}");
    }
    assert!(library.find("cisco_xr", "show bgp summary").is_none());
}
