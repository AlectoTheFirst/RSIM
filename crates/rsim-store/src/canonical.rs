//! The canonical form of a section and its change hash.
//!
//! The canonical form of a JSON section has sorted keys, an indentation of
//! 2 spaces and one member or element on each line. The canonical form of a
//! text section has `\n` line ends. The parsers and the line ranges of the
//! provenance use the canonical form.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Hash, Keys, StoreError};

/// The format of a section.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Json,
    Text,
}

/// The canonical form of the section bytes.
pub fn canonical(format: Format, bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
    match format {
        Format::Json => {
            let v: Value = serde_json::from_slice(bytes)?;
            Ok(json_text(&v).into_bytes())
        }
        Format::Text => Ok(text(bytes)),
    }
}

/// The section bytes without the volatile parts.
///
/// For JSON, each pattern is a path of keys separated by `/`, for example
/// `/data/*/uptime`. The segment `*` matches each member of an object and
/// each element of an array. In a longer segment, `*` matches any text, so
/// `*_bytes` matches `rx_bytes` and `tx_bytes`. The last segment names the
/// removed members.
///
/// For text, a pattern is one of these, and each applies after the leading
/// spaces of a line:
///
/// - A plain pattern is a line prefix. A line that starts with it is
///   removed.
/// - `=shape` removes a line that starts with the shape.
/// - `~shape` removes each word of a line that is the shape. A word is a
///   run of text between spaces, without a final comma. The words that
///   stay are joined with one space.
///
/// In a shape, `#` matches one or more digits and `*` matches any text.
pub fn strip_volatile(
    format: Format,
    bytes: &[u8],
    volatile: &[&str],
) -> Result<Vec<u8>, StoreError> {
    match format {
        Format::Json => {
            let mut v: Value = serde_json::from_slice(bytes)?;
            for p in volatile {
                let segs: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
                remove(&mut v, &segs);
            }
            Ok(json_text(&v).into_bytes())
        }
        Format::Text => {
            let t = text(bytes);
            let s = String::from_utf8_lossy(&t);
            let mut out = String::with_capacity(s.len());
            let words: Vec<&str> = volatile
                .iter()
                .filter_map(|p| p.strip_prefix('~'))
                .collect();
            for line in s.split_inclusive('\n') {
                let body = line.trim_start();
                let gone = volatile.iter().any(|p| match p.strip_prefix('=') {
                    Some(shape) => starts_with_shape(shape.as_bytes(), body.as_bytes()),
                    None => !p.starts_with('~') && body.starts_with(p),
                });
                if gone {
                    continue;
                }
                if words.is_empty() {
                    out.push_str(line);
                    continue;
                }
                let kept: Vec<&str> = body
                    .split_whitespace()
                    .filter(|w| {
                        let w = w.strip_suffix(',').unwrap_or(w);
                        !words
                            .iter()
                            .any(|shape| shape_is(shape.as_bytes(), w.as_bytes()))
                    })
                    .collect();
                out.push_str(&kept.join(" "));
                out.push('\n');
            }
            Ok(out.into_bytes())
        }
    }
}

/// The keyed hash of the canonical form without the volatile parts.
pub fn change_hash(
    keys: &Keys,
    format: Format,
    bytes: &[u8],
    volatile: &[&str],
) -> Result<Hash, StoreError> {
    Ok(keys.hash(&strip_volatile(format, bytes, volatile)?))
}

/// The hash of the change detection over the kept members of a JSON
/// section only. Refer to [`keep_only`]. With no keep pattern, it is
/// [`change_hash`].
pub fn change_hash_kept(
    keys: &Keys,
    format: Format,
    bytes: &[u8],
    volatile: &[&str],
    keep: &[&str],
) -> Result<Hash, StoreError> {
    if keep.is_empty() || format != Format::Json {
        return change_hash(keys, format, bytes, volatile);
    }
    let stripped = strip_volatile(format, bytes, volatile)?;
    let v: Value = serde_json::from_slice(&stripped)?;
    Ok(keys.hash(json_text(&keep_only(&v, keep)).as_bytes()))
}

/// The members of a JSON value that a keep pattern names, with the objects
/// and arrays on their paths. A pattern is a path of keys separated by `/`,
/// as in [`strip_volatile`]. A member that a pattern names is kept whole. An
/// object or an array on the path of a pattern keeps only its parts on a
/// path. Each other member goes.
pub fn keep_only(v: &Value, keep: &[&str]) -> Value {
    let pats: Vec<Vec<&str>> = keep
        .iter()
        .map(|p| p.split('/').filter(|s| !s.is_empty()).collect())
        .collect();
    let refs: Vec<&[&str]> = pats.iter().map(Vec::as_slice).collect();
    keep_walk(v, &refs).unwrap_or(Value::Null)
}

fn keep_walk(v: &Value, pats: &[&[&str]]) -> Option<Value> {
    if pats.iter().any(|p| p.is_empty()) {
        return Some(v.clone());
    }
    match v {
        Value::Object(m) => {
            let mut out = serde_json::Map::new();
            for (k, c) in m {
                let rest: Vec<&[&str]> = pats
                    .iter()
                    .filter(|p| glob(p[0], k))
                    .map(|p| &p[1..])
                    .collect();
                if !rest.is_empty()
                    && let Some(x) = keep_walk(c, &rest)
                {
                    out.insert(k.clone(), x);
                }
            }
            Some(Value::Object(out))
        }
        Value::Array(a) => {
            let mut out = Vec::new();
            for (i, c) in a.iter().enumerate() {
                let idx = i.to_string();
                let rest: Vec<&[&str]> = pats
                    .iter()
                    .filter(|p| p[0] == "*" || p[0] == idx)
                    .map(|p| &p[1..])
                    .collect();
                if !rest.is_empty()
                    && let Some(x) = keep_walk(c, &rest)
                {
                    out.push(x);
                }
            }
            Some(Value::Array(out))
        }
        _ => None,
    }
}

fn remove(v: &mut Value, segs: &[&str]) {
    let Some((first, rest)) = segs.split_first() else {
        return;
    };
    match v {
        Value::Object(m) if rest.is_empty() => m.retain(|k, _| !glob(first, k)),
        Value::Object(m) => m
            .iter_mut()
            .filter(|(k, _)| glob(first, k))
            .for_each(|(_, c)| remove(c, rest)),
        Value::Array(a) if *first == "*" && rest.is_empty() => a.clear(),
        Value::Array(a) if *first == "*" => a.iter_mut().for_each(|c| remove(c, rest)),
        Value::Array(a) if !rest.is_empty() => {
            if let Some(c) = first.parse::<usize>().ok().and_then(|i| a.get_mut(i)) {
                remove(c, rest);
            }
        }
        _ => {}
    }
}

/// True if `key` matches `pattern`, in which `*` matches any text.
/// True if the whole text is the shape: `#` is one or more digits, `*` is
/// any text and each other byte is itself.
fn shape_is(shape: &[u8], text: &[u8]) -> bool {
    match shape.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) => (0..=text.len()).any(|i| shape_is(rest, &text[i..])),
        Some((b'#', rest)) => {
            let digits = text.iter().take_while(|c| c.is_ascii_digit()).count();
            (1..=digits).rev().any(|i| shape_is(rest, &text[i..]))
        }
        Some((c, rest)) => text.first() == Some(c) && shape_is(rest, &text[1..]),
    }
}

/// True if the text starts with the shape.
fn starts_with_shape(shape: &[u8], text: &[u8]) -> bool {
    let mut open = shape.to_vec();
    open.push(b'*');
    shape_is(&open, text)
}

fn glob(pattern: &str, key: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == key;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if key.len() < first.len() + last.len() || !key.starts_with(first) || !key.ends_with(last) {
        return false;
    }
    let mut rest = &key[first.len()..key.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    true
}

fn text(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn json_text(v: &Value) -> String {
    let mut out = String::new();
    write_json(v, 0, &mut out);
    out.push('\n');
    out
}

fn indent(depth: usize, out: &mut String) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn write_json(v: &Value, depth: usize, out: &mut String) {
    match v {
        Value::Object(m) if m.is_empty() => out.push_str("{}"),
        Value::Array(a) if a.is_empty() => out.push_str("[]"),
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push_str("{\n");
            for (i, k) in keys.iter().enumerate() {
                indent(depth + 1, out);
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push_str(": ");
                write_json(&m[k.as_str()], depth + 1, out);
                if i + 1 < keys.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(depth, out);
            out.push('}');
        }
        Value::Array(a) => {
            out.push_str("[\n");
            for (i, e) in a.iter().enumerate() {
                indent(depth + 1, out);
                write_json(e, depth + 1, out);
                if i + 1 < a.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(depth, out);
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kept_members_decide_the_change_hash() {
        let keys = Keys::from_hex(&format!("{}\n{}\n", "11".repeat(32), "22".repeat(32))).unwrap();
        let a =
            br#"{"T":{"R":[{"name":"e1","state":"up","in_pkts":5,"sub":{"x":1,"y":2}}]},"top":1}"#;
        let b =
            br#"{"T":{"R":[{"name":"e1","state":"up","in_pkts":9,"sub":{"x":1,"y":3}}]},"top":2}"#;
        let c = br#"{"T":{"R":[{"name":"e1","state":"down","in_pkts":9}]}}"#;
        let keep = ["/T/R/*/name", "/T/R/*/state", "/T/R/*/sub/x"];
        let h = |x: &[u8]| change_hash_kept(&keys, Format::Json, x, &[], &keep).unwrap();
        assert_eq!(h(a), h(b));
        assert_ne!(h(a), h(c));
        let v: Value = serde_json::from_slice(a).unwrap();
        assert_eq!(
            json_text(&keep_only(&v, &keep)),
            json_text(&serde_json::json!({"T":{"R":[{"name":"e1","state":"up","sub":{"x":1}}]}}))
        );
        assert_eq!(
            change_hash_kept(&keys, Format::Json, a, &[], &[]).unwrap(),
            change_hash(&keys, Format::Json, a, &[]).unwrap()
        );
    }

    #[test]
    fn json_has_one_canonical_form() {
        let a = br#"{"b":1,"a":[{"y":2,"x":"s"}],"e":{},"f":[]}"#;
        let b = b"{ \"a\" : [ { \"x\":\"s\", \"y\":2 } ],\r\n \"f\":[], \"e\":{}, \"b\":1 }";
        let ca = canonical(Format::Json, a).unwrap();
        assert_eq!(ca, canonical(Format::Json, b).unwrap());
        let want = "{\n  \"a\": [\n    {\n      \"x\": \"s\",\n      \"y\": 2\n    }\n  ],\n  \"b\": 1,\n  \"e\": {},\n  \"f\": []\n}\n";
        assert_eq!(String::from_utf8(ca).unwrap(), want);
        assert!(canonical(Format::Json, b"{").is_err());
    }

    #[test]
    fn volatile_json_fields_do_not_change_the_hash() {
        let keys = Keys::new([1; 32], [2; 32]);
        let vol = ["/data/*/uptime", "/meta/time"];
        let a =
            br#"{"data":[{"mac":"02:00:00:00:00:01","uptime":10}],"meta":{"rc":"ok","time":1}}"#;
        let b =
            br#"{"data":[{"mac":"02:00:00:00:00:01","uptime":99}],"meta":{"rc":"ok","time":7}}"#;
        let c =
            br#"{"data":[{"mac":"02:00:00:00:00:02","uptime":10}],"meta":{"rc":"ok","time":1}}"#;
        let h = |x: &[u8]| change_hash(&keys, Format::Json, x, &vol).unwrap();
        assert_eq!(h(a), h(b));
        assert_ne!(h(a), h(c));
        assert_ne!(keys.hash(a), keys.hash(b));
    }

    #[test]
    fn a_key_pattern_removes_each_matching_member() {
        let v = br#"{"d":[{"rx_bytes":1,"tx_bytes":2,"bytes":3,"bytes_r":4,"mac":"x"}]}"#;
        let out = strip_volatile(Format::Json, v, &["/d/*/*_bytes", "/d/*/bytes*"]).unwrap();
        let want = canonical(Format::Json, br#"{"d":[{"mac":"x"}]}"#).unwrap();
        assert_eq!(out, want);
        assert!(glob("*", "anything"));
        assert!(glob("a*b*c", "aXbYc"));
        assert!(!glob("a*b*c", "aXc"));
        assert!(!glob("ab*ba", "aba"));
    }

    #[test]
    fn volatile_text_lines_do_not_change_the_hash() {
        let keys = Keys::new([1; 32], [2; 32]);
        let a = b"Version: VyOS 1.4.0\r\nUptime: 1 day\n";
        let b = b"Version: VyOS 1.4.0\n  Uptime: 9 days\n";
        let h = |x: &[u8]| change_hash(&keys, Format::Text, x, &["Uptime:"]).unwrap();
        assert_eq!(h(a), h(b));
        assert_ne!(h(a), h(b"Version: VyOS 1.5.0\n"));
    }

    #[test]
    fn volatile_shapes_remove_counter_lines_and_age_words() {
        let keys = Keys::new([1; 32], [2; 32]);
        let p = &["=# packets input", "=*uptime is", "~#w#d", "~#:#:#"];
        let h = |x: &str| change_hash(&keys, Format::Text, x.as_bytes(), p).unwrap();
        let a = "r1 uptime is 3 weeks\n  1234 packets input, 9 bytes\nS 0.0.0.0/0 via 192.0.2.1, 3w2d\nC 192.0.2.0/24 is directly connected, 00:01:23, Gi0\n";
        let b = "r1 uptime is 4 weeks\n  99 packets input, 1 bytes\nS 0.0.0.0/0 via 192.0.2.1, 4w1d\nC 192.0.2.0/24 is directly connected, 01:02:03, Gi0\n";
        assert_eq!(h(a), h(b));
        assert_ne!(h(a), h(&a.replace("192.0.2.1,", "192.0.2.9,")));
        assert_ne!(h(a), h(&a.replace("Gi0", "Gi1")));
        assert!(shape_is(b"#:#:#", b"00:01:23"));
        assert!(!shape_is(b"#:#:#", b"2001:db8::1"));
        assert!(!shape_is(b"#w#d", b"3w"));
    }
}
