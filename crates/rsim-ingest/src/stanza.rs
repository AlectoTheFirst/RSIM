//! The structural readers: JSON and indented config text. Each gives a tree
//! of stanzas with the line ranges of the canonical form of `rsim-store`.
//!
//! The canonical JSON form has sorted keys and an indentation of 2 spaces.
//! Each member of an object and each element of an array starts on its own
//! line. An empty object or array is on the line of its key.
//!
//! The canonical text form is the text with each CRLF changed to LF.

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

/// Reads indented config text, for example a Cisco running config. Each
/// line is a stanza with its trimmed text as its key and the lines that are
/// indented deeper below it as its children, in the order of the text. A
/// line is indented deeper than another if it starts with more spaces; the
/// step width does not matter. An empty line and a line that starts with
/// `!` belong to no stanza. A stanza ends at its last child.
pub fn read_indented(text: &str) -> Document {
    struct Open {
        indent: usize,
        stanza: Stanza,
    }
    fn close(stack: &mut Vec<Open>) {
        let done = stack.pop().expect("the root is never closed");
        let parent = stack.last_mut().expect("the root is never closed");
        parent.stanza.last_line = parent.stanza.last_line.max(done.stanza.last_line);
        if let Body::Object(c) = &mut parent.stanza.body {
            c.push(done.stanza);
        }
    }
    let mut stack = vec![Open {
        indent: 0,
        stanza: Stanza {
            key: String::new(),
            first_line: 1,
            last_line: 1,
            body: Body::Object(Vec::new()),
        },
    }];
    let lines = u32::try_from(text.lines().count()).expect("fewer than 4 billion lines");
    for (i, raw) in text.lines().enumerate() {
        let n = u32::try_from(i + 1).expect("fewer than 4 billion lines");
        let body = raw.trim();
        if body.is_empty() || body.starts_with('!') {
            continue;
        }
        let indent = raw.len() - raw.trim_start_matches(' ').len();
        while stack.len() > 1 && indent <= stack.last().expect("not empty").indent {
            close(&mut stack);
        }
        stack.push(Open {
            indent,
            stanza: Stanza {
                key: body.to_string(),
                first_line: n,
                last_line: n,
                body: Body::Object(Vec::new()),
            },
        });
    }
    while stack.len() > 1 {
        close(&mut stack);
    }
    let mut root = stack.pop().expect("the root").stanza;
    root.last_line = lines.max(1);
    Document { root, lines }
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
    fn indented_text_gives_a_tree_with_line_ranges() {
        let text = "!Command: show running-config\r\nversion 9.3(8)\r\nfeature ospf\r\n\r\ninterface Ethernet1/1\r\n  description uplink\r\n  ip address 192.0.2.1/24\r\n  ip router ospf 1 area 0\r\n\r\nrouter ospf 1\r\n  vrf RED\r\n    area 0 stub\r\n  log-adjacency-changes\r\n!\r\nline vty\r\n";
        let canon = String::from_utf8(canonical(Format::Text, text.as_bytes()).unwrap()).unwrap();
        let d = read_indented(&canon);
        assert_eq!(d.lines as usize, canon.lines().count());
        let keys: Vec<&str> = d.root.children().iter().map(|s| s.key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "version 9.3(8)",
                "feature ospf",
                "interface Ethernet1/1",
                "router ospf 1",
                "line vty"
            ]
        );
        let eth = d.root.get("interface Ethernet1/1").unwrap();
        assert_eq!((eth.first_line, eth.last_line), (5, 8));
        assert_eq!(eth.children().len(), 3);
        let ospf = d.root.get("router ospf 1").unwrap();
        assert_eq!((ospf.first_line, ospf.last_line), (10, 13));
        let vrf = ospf.get("vrf RED").unwrap();
        assert_eq!((vrf.first_line, vrf.last_line), (11, 12));
        assert_eq!(vrf.children()[0].key, "area 0 stub");
        assert_eq!(
            d.root
                .at(&["router ospf 1", "log-adjacency-changes"])
                .unwrap()
                .first_line,
            13
        );
        let lines: Vec<&str> = canon.lines().collect();
        fn walk(s: &Stanza, lines: &[&str]) {
            assert_eq!(lines[s.first_line as usize - 1].trim(), s.key);
            for c in s.children() {
                assert!(c.first_line > s.first_line && c.last_line <= s.last_line);
                walk(c, lines);
            }
        }
        for c in d.root.children() {
            walk(c, &lines);
        }
    }

    #[test]
    fn an_uneven_indent_still_nests() {
        let d = read_indented("a\n   b\n     c\n  d\ne\n");
        let a = d.root.get("a").unwrap();
        let kids: Vec<&str> = a.children().iter().map(|s| s.key.as_str()).collect();
        assert_eq!(kids, ["b", "d"]);
        assert_eq!(a.get("b").unwrap().children()[0].key, "c");
        assert_eq!((a.first_line, a.last_line), (1, 4));
        assert_eq!(d.lines, 5);
        assert_eq!(read_indented("").root.children().len(), 0);
    }

    #[test]
    fn a_path_finds_its_stanza() {
        let d = read_json(br#"{"a": {"b": {"c": ["x", "y"]}, "s": "t"}}"#).unwrap();
        assert_eq!(d.root.at(&["a", "b", "c"]).unwrap().texts(), ["x", "y"]);
        assert_eq!(d.root.at(&["a", "s"]).unwrap().texts(), ["t"]);
        assert!(d.root.at(&["a", "z"]).is_none());
    }
}
