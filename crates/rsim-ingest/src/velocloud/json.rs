//! The JSON sections of an enterprise. Each value comes with its stanza, so
//! a value that the reader takes keeps the lines of its source.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::SourceSpan;
use serde_json::Value;

use crate::stanza::{Document, Stanza, read_json};

/// A section: its value, its stanzas and its file name.
#[derive(Clone, Debug)]
pub struct Section {
    pub value: Value,
    pub doc: Document,
    pub file: String,
}

/// The parsed sections of an enterprise, by section name.
#[derive(Clone, Debug, Default)]
pub struct Parsed {
    pub sections: BTreeMap<String, Section>,
    /// Each section that is not JSON, with the error.
    pub notes: Vec<String>,
}

impl Parsed {
    /// Parses the sections, each given as its bytes and its file name.
    pub fn new(sections: &BTreeMap<String, (Vec<u8>, String)>) -> Parsed {
        let mut out = Parsed::default();
        for (name, (bytes, file)) in sections {
            let read = serde_json::from_slice::<Value>(bytes)
                .map_err(|e| e.to_string())
                .and_then(|v| read_json(bytes).map(|d| (v, d)));
            match read {
                Ok((value, doc)) => {
                    out.sections.insert(
                        name.clone(),
                        Section {
                            value,
                            doc,
                            file: file.clone(),
                        },
                    );
                }
                Err(e) => out.notes.push(format!("{name}: not JSON: {e}")),
            }
        }
        out
    }

    /// The root of a section.
    pub fn root(&self, name: &str) -> Option<J<'_>> {
        let s = self.sections.get(name)?;
        Some(J {
            v: &s.value,
            s: &s.doc.root,
            file: &s.file,
        })
    }
}

/// A JSON value with its stanza and the file name of its section.
#[derive(Clone, Copy, Debug)]
pub struct J<'a> {
    pub v: &'a Value,
    pub s: &'a Stanza,
    pub file: &'a str,
}

impl<'a> J<'a> {
    /// The member `key` of an object.
    pub fn get(self, key: &str) -> Option<J<'a>> {
        let v = self.v.as_object()?.get(key)?;
        let s = self.s.get(key)?;
        Some(J {
            v,
            s,
            file: self.file,
        })
    }

    /// The member `key` when it is an object.
    pub fn obj(self, key: &str) -> Option<J<'a>> {
        self.get(key).filter(|j| j.v.is_object())
    }

    /// The elements of an array.
    pub fn elems(self) -> Vec<J<'a>> {
        match self.v {
            Value::Array(a) => a
                .iter()
                .zip(self.s.children())
                .map(|(v, s)| J {
                    v,
                    s,
                    file: self.file,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The object rows of an answer: the objects of an array, or of the
    /// `data` array of an object.
    pub fn rows(self) -> Vec<J<'a>> {
        let all = match self.v {
            Value::Object(_) => self.get("data").map(J::elems).unwrap_or_default(),
            _ => self.elems(),
        };
        all.into_iter().filter(|j| j.v.is_object()).collect()
    }

    /// The objects of the array `key`.
    pub fn list(self, key: &str) -> Vec<J<'a>> {
        self.get(key)
            .map(J::elems)
            .unwrap_or_default()
            .into_iter()
            .filter(|j| j.v.is_object())
            .collect()
    }

    /// The members of an object, in key order.
    pub fn members(self) -> Vec<(&'a str, J<'a>)> {
        let Value::Object(m) = self.v else {
            return Vec::new();
        };
        self.s
            .children()
            .iter()
            .filter_map(|s| {
                let v = m.get(s.key.as_str())?;
                Some((
                    s.key.as_str(),
                    J {
                        v,
                        s,
                        file: self.file,
                    },
                ))
            })
            .collect()
    }

    /// The string `key` when it is not empty.
    pub fn str(self, key: &str) -> Option<&'a str> {
        self.v.get(key)?.as_str().filter(|s| !s.is_empty())
    }

    /// The text of the string or number `key`.
    pub fn text(self, key: &str) -> Option<String> {
        text(self.v.get(key)?)
    }

    pub fn bool(self, key: &str) -> Option<bool> {
        self.v.get(key)?.as_bool()
    }

    /// The whole number or numeric string `key`.
    pub fn int(self, key: &str) -> Option<i64> {
        int(self.v.get(key)?)
    }

    /// The lines of the value.
    pub fn span(self) -> SourceSpan {
        SourceSpan::new(self.file, self.s.first_line, self.s.last_line)
    }
}

/// The text of a string that is not empty, or of a number.
pub fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// A whole number, a whole float such as `12.0`, or a numeric string.
pub fn int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| {
            n.as_f64()
                .filter(|f| f.fract() == 0.0 && f.abs() < 9.0e15)
                .map(|f| f as i64)
        }),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// A numeric id of the orchestrator: a whole number above 0, as an integer
/// or a whole float. A boolean, 0, a negative number and a string are not
/// ids.
pub fn numeric_id(v: &Value) -> Option<u64> {
    let Value::Number(n) = v else {
        return None;
    };
    n.as_u64().filter(|x| *x > 0).or_else(|| {
        n.as_f64()
            .filter(|f| *f > 0.0 && f.fract() == 0.0 && *f < 9.0e15)
            .map(|f| f as u64)
    })
}

/// An AS number: a number or a numeric string above 0.
pub fn asn_of(v: &Value) -> Option<u32> {
    u32::try_from(int(v)?).ok().filter(|a| *a > 0)
}

/// The logicalId of a linked resource: its `logicalId`, else the last part
/// of its `_href`.
pub fn ref_id(j: J<'_>) -> Option<String> {
    if let Some(id) = j.text("logicalId") {
        return Some(id);
    }
    let href = j.str("_href")?;
    href.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// True for a value that leaves a field open: none, null, -1, an empty
/// string, `any`, an empty array or an empty object.
pub fn open(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => {
            let t = s.trim();
            t.is_empty() || t == "-1" || t.eq_ignore_ascii_case("any")
        }
        Some(Value::Number(n)) => n.as_i64() == Some(-1),
        Some(Value::Array(a)) => a.is_empty(),
        Some(Value::Object(m)) => m.is_empty(),
        Some(Value::Bool(_)) => false,
    }
}

/// The trimmed text when it is not empty.
pub fn trimmed(text: Option<&str>) -> Option<String> {
    text.map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
}

/// The address of a text, with or without a prefix length.
pub fn address(text: &str) -> Option<IpAddr> {
    text.split('/').next()?.trim().parse().ok()
}

/// The longest prefix length of an address family.
pub fn max_len(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

/// The prefix length of a contiguous netmask such as `255.255.255.0`.
pub fn netmask_len(mask: IpAddr) -> Option<u8> {
    let bits = match mask {
        IpAddr::V4(a) => u128::from(u32::from(a)) << 96,
        IpAddr::V6(a) => u128::from(a),
    };
    let ones = bits.leading_ones();
    let rest = if ones >= 128 { 0 } else { bits << ones };
    if rest != 0 {
        return None;
    }
    u8::try_from(ones).ok()
}

/// The prefix length of a netmask or of a length such as `24` or `/24`.
pub fn mask_len(text: &str) -> Option<u8> {
    let t = text.trim().trim_start_matches('/');
    if let Ok(n) = t.parse::<u8>() {
        return (n <= 128).then_some(n);
    }
    netmask_len(t.parse().ok()?)
}

/// The address and prefix length of an object with `cidrIp`,
/// `interfaceAddress` or `ipAddress`, and with `cidrPrefix` or `netmask`.
/// With neither, the length of the address text, else a host length.
pub fn interface_address(j: J<'_>) -> Option<(IpAddr, u8)> {
    let ip = ["cidrIp", "interfaceAddress", "ipAddress"]
        .iter()
        .find_map(|k| j.str(k))?;
    let addr = address(ip)?;
    let len = match (j.int("cidrPrefix"), j.str("netmask")) {
        (Some(n), _) => u8::try_from(n).ok()?,
        (None, Some(m)) => mask_len(m)?,
        (None, None) => match ip.split_once('/') {
            Some((_, l)) => l.trim().parse().ok()?,
            None => max_len(addr),
        },
    };
    (len <= max_len(addr)).then_some((addr, len))
}

/// The segment id of a block: its `segmentId`, else the `segmentId` of its
/// nested `segment` object. A WAN interface has -1, which is no segment.
pub fn segment_id(j: J<'_>) -> Option<u32> {
    let own = j.int("segmentId");
    let nested = j.obj("segment").and_then(|s| s.int("segmentId"));
    own.or(nested).and_then(|n| u32::try_from(n).ok())
}

/// The module `name` of a profile row, of a configuration scope of a
/// listing row or of a module answer: a member with the name, else the
/// element of `modules` with the name.
pub fn module<'a>(source: J<'a>, name: &str) -> Option<J<'a>> {
    if let Some(m) = source.obj(name) {
        return Some(m);
    }
    source
        .list("modules")
        .into_iter()
        .find(|m| m.str("name") == Some(name))
}

/// The body of a module: its `data` object, else the module itself.
pub fn body(module: J<'_>) -> J<'_> {
    module.obj("data").unwrap_or(module)
}
