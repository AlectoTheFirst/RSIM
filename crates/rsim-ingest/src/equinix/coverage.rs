//! The classification of the items of the sections of an account. The path
//! of a stanza has `*` for each element of an array. A path of the report
//! is `<section>/<path>`, each key through the mask of the URLs.

use crate::coverage::{Coverage, Reach, State, Table};
use crate::stanza::{Body, Stanza};
use crate::velocloud::json::Parsed;
use crate::velocloud::mask::report_key;

use Reach::{Node as N, Subtree as S};
use State::{Handled as H, Irrelevant as I};

type Rows = &'static [(&'static str, State, Reach)];

const PORTS: Rows = &[
    ("*", H, N),
    ("*/uuid", H, S),
    ("*/name", H, S),
    ("*/state", H, S),
    ("*/bandwidth", H, S),
    ("*/physicalPortsSpeed", I, S),
    ("*/encapsulation", H, N),
    ("*/encapsulation/type", H, S),
    ("*/encapsulation/tagProtocolId", H, S),
    ("*/location", H, N),
    ("*/location/ibx", H, S),
    ("*/location/metroCode", H, S),
    ("*/location/metroName", I, S),
    ("*/location/region", I, S),
    ("*/redundancy", I, S),
    ("*/lag", H, N),
    ("*/lag/enabled", I, S),
    ("*/lag/name", H, S),
    ("*/physicalPorts", H, N),
    ("*/physicalPorts/*", H, N),
    ("*/physicalPorts/*/tether", H, N),
    ("*/physicalPorts/*/tether/crossConnectId", H, S),
    ("*/href", I, S),
    ("*/type", I, S),
    ("*/changeLog", I, S),
    ("*/account", I, S),
    ("*/order", I, S),
    ("*/notifications", I, S),
    ("*/project", I, S),
    ("*/package", I, S),
    ("*/operation/opStatusChangedAt", I, S),
];

const SIDE: Rows = &[
    ("", H, N),
    ("accessPoint", H, N),
    ("accessPoint/type", H, S),
    ("accessPoint/port", H, N),
    ("accessPoint/port/uuid", H, S),
    ("accessPoint/port/name", I, S),
    ("accessPoint/port/href", I, S),
    ("accessPoint/linkProtocol", H, N),
    ("accessPoint/linkProtocol/type", H, S),
    ("accessPoint/linkProtocol/vlanTag", H, S),
    ("accessPoint/linkProtocol/vlanSTag", H, S),
    ("accessPoint/linkProtocol/vlanCTag", H, S),
    ("accessPoint/profile", H, N),
    ("accessPoint/profile/uuid", H, S),
    ("accessPoint/profile/name", H, S),
    ("accessPoint/profile/type", I, S),
    ("accessPoint/profile/href", I, S),
    ("accessPoint/location", I, S),
];

const CONNECTIONS: Rows = &[
    ("*", H, N),
    ("*/uuid", H, S),
    ("*/name", H, S),
    ("*/type", H, S),
    ("*/state", H, S),
    ("*/bandwidth", H, S),
    ("*/href", I, S),
    ("*/changeLog", I, S),
    ("*/account", I, S),
    ("*/order", I, S),
    ("*/notifications", I, S),
    ("*/project", I, S),
    ("*/redundancy", I, S),
    ("*/direction", I, S),
    ("*/isRemote", I, S),
    ("*/operation/opStatusChangedAt", I, S),
];

/// The classification table of a section. The Network Edge sections have
/// no entry, so each of their stanzas is unhandled.
pub fn table(section: &str) -> Table {
    let mut t = Table::new(&[]);
    match section {
        "ports" => {
            for (p, s, r) in PORTS {
                t.push(p, *s, *r);
            }
        }
        "connections" => {
            for (p, s, r) in CONNECTIONS {
                t.push(p, *s, *r);
            }
            for side in ["aSide", "zSide"] {
                for (p, s, r) in SIDE {
                    let path = if p.is_empty() {
                        format!("*/{side}")
                    } else {
                        format!("*/{side}/{p}")
                    };
                    t.push(&path, *s, *r);
                }
            }
        }
        _ => {}
    }
    t
}

/// The coverage of the sections of an account, with the path of each
/// unhandled stanza under the name of its section.
pub fn classify(p: &Parsed) -> Coverage {
    let mut cov = Coverage::default();
    for (name, section) in &p.sections {
        let t = table(name);
        let mut path = Vec::new();
        for c in section.doc.root.children() {
            let key = match &section.doc.root.body {
                Body::Array(_) => "*".to_string(),
                _ => c.key.clone(),
            };
            path.push(key);
            walk(c, name, &t, &mut path, &mut cov, false);
            path.pop();
        }
    }
    cov
}

fn walk(
    s: &Stanza,
    section: &str,
    t: &Table,
    path: &mut Vec<String>,
    cov: &mut Coverage,
    inside: bool,
) {
    let refs: Vec<&str> = path.iter().map(String::as_str).collect();
    let state = t.state(&refs);
    if state == State::Unhandled && !inside {
        let keys: Vec<String> = path.iter().map(|k| report_key(k.as_str())).collect();
        let e = cov
            .unhandled
            .entry(format!("{section}/{}", keys.join("/")))
            .or_default();
        e.0 += 1;
        e.1 += s.last_line - s.first_line + 1;
    }
    let child_lines: u32 = s
        .children()
        .iter()
        .map(|c| c.last_line - c.first_line + 1)
        .sum();
    *cov.lines.entry(state).or_default() += s.last_line - s.first_line + 1 - child_lines;
    for c in s.children() {
        let key = match &s.body {
            Body::Array(_) => "*".to_string(),
            _ => c.key.clone(),
        };
        path.push(key);
        walk(c, section, t, path, cov, state == State::Unhandled);
        path.pop();
    }
}
