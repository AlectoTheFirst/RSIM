//! The JSON reader: a tree of stanzas with the line ranges of the canonical
//! form of `rsim-store`.
//!
//! The canonical form has sorted keys and an indentation of 2 spaces. Each
//! member of an object and each element of an array starts on its own line.
//! An empty object or array is on the line of its key.

use serde_json::Value;

/// The value of a stanza.
#[derive(Clone, Debug, PartialEq)]
pub enum Body {
    /// An object with its members as child stanzas, in key order.
    Object(Vec<Stanza>),
    /// An array with its elements as child stanzas. The key of an element
    /// is its index.
    Array(Vec<Stanza>),
    /// A string, a number, a boolean or null, in its JSON text form. A
    /// string is without its quotes.
    Scalar(String),
}

/// A member of an object or an element of an array.
#[derive(Clone, Debug, PartialEq)]
pub struct Stanza {
    pub key: String,
    /// The first line of the stanza in the canonical form, from 1.
    pub first_line: u32,
    /// The last line of the stanza in the canonical form.
    pub last_line: u32,
    pub body: Body,
}

impl Stanza {
    /// The child stanzas of an object or an array.
    pub fn children(&self) -> &[Stanza] {
        match &self.body {
            Body::Object(c) | Body::Array(c) => c,
            Body::Scalar(_) => &[],
        }
    }

    /// The child with a key.
    pub fn get(&self, key: &str) -> Option<&Stanza> {
        match &self.body {
            Body::Object(c) => c.iter().find(|s| s.key == key),
            _ => None,
        }
    }

    /// The stanza at a path of keys below this stanza.
    pub fn at(&self, path: &[&str]) -> Option<&Stanza> {
        path.iter().try_fold(self, |s, k| s.get(k))
    }

    /// The text of a scalar.
    pub fn text(&self) -> Option<&str> {
        match &self.body {
            Body::Scalar(s) => Some(s),
            _ => None,
        }
    }

    /// The texts of a scalar, or of the scalar elements of an array. A
    /// VyOS multi-value node is an array; a single value is a scalar.
    pub fn texts(&self) -> Vec<&str> {
        match &self.body {
            Body::Scalar(s) => vec![s.as_str()],
            Body::Array(c) => c.iter().filter_map(Stanza::text).collect(),
            Body::Object(_) => Vec::new(),
        }
    }
}

/// The root stanza of a JSON section, and the number of lines of its
/// canonical form.
#[derive(Clone, Debug, PartialEq)]
pub struct Document {
    pub root: Stanza,
    pub lines: u32,
}

/// Reads a JSON section.
pub fn read_json(bytes: &[u8]) -> Result<Document, String> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let mut line = 1;
    let root = build(String::new(), &v, &mut line);
    Ok(Document { root, lines: line })
}

/// Builds the stanza of `v`, which starts on `*line`. At the end, `*line` is
/// the last line of the stanza.
fn build(key: String, v: &Value, line: &mut u32) -> Stanza {
    let first = *line;
    let body = match v {
        Value::Object(m) if !m.is_empty() => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut children = Vec::with_capacity(keys.len());
            for k in keys {
                *line += 1;
                children.push(build(k.clone(), &m[k.as_str()], line));
            }
            *line += 1;
            Body::Object(children)
        }
        Value::Array(a) if !a.is_empty() => {
            let mut children = Vec::with_capacity(a.len());
            for (i, x) in a.iter().enumerate() {
                *line += 1;
                children.push(build(i.to_string(), x, line));
            }
            *line += 1;
            Body::Array(children)
        }
        Value::Object(_) => Body::Object(Vec::new()),
        Value::Array(_) => Body::Array(Vec::new()),
        Value::String(s) => Body::Scalar(s.clone()),
        other => Body::Scalar(other.to_string()),
    };
    Stanza {
        key,
        first_line: first,
        last_line: *line,
        body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsim_store::{Format, canonical};

    fn check(text: &str) {
        let canon = String::from_utf8(canonical(Format::Json, text.as_bytes()).unwrap()).unwrap();
        let doc = read_json(text.as_bytes()).unwrap();
        let lines: Vec<&str> = canon.lines().collect();
        assert_eq!(doc.lines as usize, lines.len(), "{canon}");
        fn walk(s: &Stanza, lines: &[&str]) {
            let first = lines[s.first_line as usize - 1].trim_start();
            if !s.key.is_empty() && !s.key.chars().all(|c| c.is_ascii_digit()) {
                assert!(first.starts_with(&format!("\"{}\"", s.key)), "{first}");
            }
            let last = lines[s.last_line as usize - 1].trim_end_matches(',');
            match &s.body {
                Body::Object(c) if !c.is_empty() => assert!(last.trim() == "}", "{last}"),
                Body::Array(c) if !c.is_empty() => assert!(last.trim() == "]", "{last}"),
                _ => assert_eq!(s.first_line, s.last_line),
            }
            for c in s.children() {
                walk(c, lines);
            }
        }
        walk(&doc.root, &lines);
    }

    #[test]
    fn the_line_ranges_match_the_canonical_form() {
        check(r#"{"b": {"y": 1, "x": [1, {"k": "v"}, []]}, "a": {}, "c": "s", "d": null}"#);
        check(
            r#"{"interfaces": {"ethernet": {"eth0": {"address": ["192.0.2.1/24", "dhcp"], "vif": {"10": {"address": "198.51.100.1/24"}}}}}}"#,
        );
        check("[]");
        check("{}");
    }

    #[test]
    fn a_path_finds_its_stanza() {
        let d = read_json(br#"{"a": {"b": {"c": ["x", "y"]}, "s": "t"}}"#).unwrap();
        assert_eq!(d.root.at(&["a", "b", "c"]).unwrap().texts(), ["x", "y"]);
        assert_eq!(d.root.at(&["a", "s"]).unwrap().texts(), ["t"]);
        assert!(d.root.at(&["a", "z"]).is_none());
    }
}
