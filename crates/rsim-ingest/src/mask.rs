//! The masked lines of a section: each line of the canonical form of a
//! section, with the secrets masked by the mask of its vendor and format.
//!
//! A JSON section is masked by its keys: the value of a secret key is
//! masked whole, with each key and each value below it, so a secret that
//! is the key of an object (a VyOS SNMP community, the name of a pre-shared
//! key) goes with it. The masked lines keep the lines of the canonical form
//! of `rsim-store`: a line with no secret is the same text. Below a subtree
//! of the mask of a vendor, a part of the config in which the user names
//! the secret, each value is masked and the keys stay. A record below a
//! key of the value records of a mask has its `value` masked. The userinfo
//! of a URL (`scheme://user:password@host`), the form `user:password@host`
//! and the value of a secret query parameter are masked in each key and
//! value (`url_secrets`). A text section is masked line by line by the line
//! mask of its vendor.

use rsim_store::Format;
use serde_json::Value;

use crate::{iosxe, iosxr, nxos, unifi, vyos};

/// The text that takes the place of a masked key or value.
pub const MASKED: &str = "<secret>";

/// Why the lines of a section are not given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The vendor has no mask for a section of this format.
    NoMask { vendor: String, format: Format },
    /// The section bytes do not have the form of their format.
    Unreadable(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::NoMask { vendor, format } => {
                let format = match format {
                    Format::Json => "JSON",
                    Format::Text => "text",
                };
                write!(
                    f,
                    "the vendor {vendor} has no mask of the secrets of a {format} section"
                )
            }
            Refusal::Unreadable(e) => write!(f, "the section is not readable: {e}"),
        }
    }
}

/// The rule of a JSON mask: true for a key whose value is a secret. `snmp`
/// is true below a key that names SNMP.
pub type SecretKey = fn(key: &str, snmp: bool) -> bool;

/// The mask of the JSON sections of a vendor.
pub struct JsonMask {
    /// The rule of the secret keys.
    pub key: SecretKey,
    /// The paths of the subtrees whose values are all masked, by their
    /// object keys from the root; `*` is any key. The keys below a subtree
    /// stay.
    pub subtrees: &'static [&'static [&'static str]],
    /// True for the key of a list of records, or of one record, whose
    /// `value` is a secret, such as the UniFi WAN DHCP options. Below such
    /// a key, the `value` of each record and each string are masked; the
    /// keys, the numbers and the booleans stay.
    pub value_records: fn(key: &str) -> bool,
}

/// The rule of a mask with no value records.
pub fn no_value_records(_key: &str) -> bool {
    false
}

/// The schemes whose user name with no `:` stays, such as `ssh://git@host`.
const USER_SCHEMES: &[&str] = &["ssh", "git"];

/// The names of query parameters whose value is a secret, besides the
/// secret keys of the common rule.
const SECRET_PARAMS: &[&str] = &[
    "access_token",
    "apikey",
    "auth",
    "key",
    "pass",
    "password",
    "pwd",
    "secret",
    "sig",
    "signature",
    "token",
];

/// The text with the secrets of each URL masked, or `None` for a text with
/// none. A word is a run of text with no white space, with no quote at its
/// ends. The word is read whole, and each part of it between commas is
/// read alone too. In a word or a part,
/// the text before the first `://` becomes `<secret>` up to its last `@`
/// when it holds a `:` before that `@`, the form `user:password@host`.
/// After `scheme://`, the userinfo up to the last `@` of the word or part becomes
/// `<secret>`, except a user name with no `:` for the schemes `ssh` and
/// `git`. After the userinfo of the word and of each part, the value of a
/// query parameter
/// after the next `?` of the word, whose name is a word of `SECRET_PARAMS`,
/// ends with `sig` or `signature`, or is a secret key of the common rule,
/// becomes `<secret>` up to the next `&`, `;` or `#`.
pub fn url_secrets(text: &str) -> Option<String> {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut start = None;
    for (i, c) in text.char_indices().chain([(text.len(), ' ')]) {
        match (start, c.is_whitespace()) {
            (None, false) => start = Some(i),
            (Some(s), true) => {
                word_secrets(text, s, i, &mut ranges);
                start = None;
            }
            _ => {}
        }
    }
    if ranges.is_empty() {
        return None;
    }
    let mut out = String::new();
    let mut done = 0;
    for (a, b) in ranges {
        out.push_str(&text[done..a]);
        out.push_str(MASKED);
        done = b;
    }
    out.push_str(&text[done..]);
    Some(out)
}

/// Adds the ranges of the secrets of the word `text[s..e]`, in order.
fn word_secrets(text: &str, s: usize, e: usize, ranges: &mut Vec<(usize, usize)>) {
    let quote = |c: char| matches!(c, '"' | '\'');
    let s = s + (text[s..e].len() - text[s..e].trim_start_matches(quote).len());
    let e = s + text[s..e].trim_end_matches(quote).len();
    let word = &text[s..e];
    let mut found = Vec::new();
    let host = userinfo(word, 0, &mut found);
    query_secrets(word, host, &mut found);
    let mut part = 0;
    for piece in word.split(',') {
        let host = part + userinfo(piece, part, &mut found);
        query_secrets(word, host, &mut found);
        part += piece.len() + 1;
    }
    found.sort_unstable();
    for (a, b) in found {
        match ranges.last_mut() {
            Some(last) if s + a <= last.1 => last.1 = last.1.max(s + b),
            _ => ranges.push((s + a, s + b)),
        }
    }
}

/// Adds the userinfo range of the part `piece` of a word, which starts at
/// `at` in the word, and gives the position of the host in the part. The
/// text before the first `://` is the form `user:password@host` when it
/// has a `@` with a `:` before it; after the first `://`, the text up to
/// the last `@` is the userinfo of a URL.
fn userinfo(piece: &str, at: usize, found: &mut Vec<(usize, usize)>) -> usize {
    let mut host = 0;
    let scheme_at = piece.find("://");
    let head = &piece[..scheme_at.unwrap_or(piece.len())];
    if let Some(a) = head.rfind('@')
        && head[..a].contains(':')
    {
        found.push((at, at + a));
        host = a + 1;
    }
    if let Some(i) = scheme_at {
        let scheme = piece[..i]
            .rsplit(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let from = i + 3;
        if let Some(a) = piece[from..].rfind('@').map(|a| from + a) {
            let user = &piece[from..a];
            let kept = !user.contains(':') && USER_SCHEMES.contains(&scheme.as_str());
            if !user.is_empty() && !kept {
                found.push((at + from, at + a));
            }
            host = a + 1;
        }
    }
    host
}

/// Adds the ranges of the values of the secret query parameters after the
/// first `?` from `host` in the word.
fn query_secrets(word: &str, host: usize, found: &mut Vec<(usize, usize)>) {
    let Some(q) = word[host..].find('?').map(|q| host + q) else {
        return;
    };
    let mut p = q + 1;
    while p < word.len() {
        let end = word[p..]
            .find(['&', ';', '#'])
            .map_or(word.len(), |x| p + x);
        if let Some(eq) = word[p..end].find('=') {
            let name = word[p..p + eq].to_ascii_lowercase();
            let secret = SECRET_PARAMS.contains(&name.as_str())
                || name.ends_with("signature")
                || name.ends_with("sig")
                || secret_key(&name, false);
            if secret && p + eq + 1 < end {
                found.push((p + eq + 1, end));
            }
        }
        if word[end..].starts_with('#') {
            break;
        }
        p = end + 1;
    }
}

/// The masked lines of the canonical form of a section of a vendor, from
/// line 1. A vendor and format with no mask give `Refusal::NoMask`.
pub fn section_lines(vendor: &str, format: Format, bytes: &[u8]) -> Result<Vec<String>, Refusal> {
    match (vendor, format) {
        ("vyos", Format::Json) => json_lines(bytes, &vyos::mask::MASK),
        ("unifi", Format::Json) => json_lines(bytes, &unifi::mask::MASK),
        ("nxos", Format::Json) => json_lines(bytes, &nxos::JSON_MASK),
        ("nxos", Format::Text) => text_lines(bytes, nxos::mask),
        ("iosxr", Format::Text) => text_lines(bytes, iosxr::mask),
        ("iosxe", Format::Text) => text_lines(bytes, iosxe::mask),
        _ => Err(Refusal::NoMask {
            vendor: vendor.to_string(),
            format,
        }),
    }
}

/// The keys whose whole name, in lower case, names a secret.
pub const SECRET_KEYS: &[&str] = &[
    "access_token",
    "api-key",
    "api_key",
    "apikey",
    "authorization",
    "cak",
    "ckn",
    "client_secret",
    "cookie",
    "jwt",
    "key",
    "pass",
    "passphrase",
    "passwd",
    "password",
    "provisioning-key",
    "provisioning_key",
    "provisioningkey",
    "pwd",
    "refresh_token",
    "secret",
    "session",
    "sessionid",
    "sid",
    "token",
];

/// The words that name a secret anywhere in a key, in lower case without
/// `_`, `-`, `.` and spaces.
pub const SECRET_WORDS: &[&str] = &[
    "accesskey",
    "apikey",
    "authenticationkey",
    "authkey",
    "credential",
    "encryptionkey",
    "iappkey",
    "licensekey",
    "passphrase",
    "passwd",
    "password",
    "privatekey",
    "privkey",
    "provisioningkey",
    "psk",
    "secret",
    "sharedkey",
    "token",
    "vendorconfig",
    "vwirekey",
];

/// The key in lower case without `_`, `-`, `.` and spaces.
pub fn normalized(key: &str) -> String {
    key.chars()
        .filter(|c| !matches!(c, '_' | '-' | '.') && !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

/// The common rule of the JSON masks: a key of `SECRET_KEYS`, a key with a
/// word of `SECRET_WORDS`, or an SNMP community: a key with `communit`
/// below a key that names SNMP, or a key that names both.
pub fn secret_key(key: &str, snmp: bool) -> bool {
    let lower = key.to_lowercase();
    if SECRET_KEYS.contains(&lower.as_str()) {
        return true;
    }
    let n = normalized(key);
    SECRET_WORDS.iter().any(|w| n.contains(w))
        || (n.contains("communit") && (snmp || n.contains("snmp")))
}

/// True for a key that ends with `key` or `keys` and is not a public key.
pub fn key_like(key: &str) -> bool {
    let n = normalized(key);
    (n.ends_with("key") || n.ends_with("keys")) && !n.starts_with("public")
}

/// The fields of a record that holds a setting by its name, with the
/// setting in `value`.
const SETTING_NAMES: &[&str] = &["name", "key", "setting", "parameter"];

/// The masked lines of a JSON section.
pub fn json_lines(bytes: &[u8], mask: &JsonMask) -> Result<Vec<String>, Refusal> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| Refusal::Unreadable(e.to_string()))?;
    let mut out = String::new();
    let mut w = Writer {
        mask,
        path: Vec::new(),
        out: &mut out,
    };
    w.write(&v, 0, Masked::No, false);
    Ok(out.lines().map(str::to_string).collect())
}

/// How much of a JSON value is masked.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Masked {
    No,
    /// Each string; the keys and the other values stay.
    Strings,
    /// Each value; the keys stay.
    Values,
    /// Each key and each value.
    All,
}

fn indent(depth: usize, out: &mut String) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn masked_text() -> String {
    Value::String(MASKED.into()).to_string()
}

/// The JSON text of a string, with the password of each URL masked.
fn plain_text(s: &str) -> String {
    Value::String(url_secrets(s).unwrap_or_else(|| s.to_string())).to_string()
}

/// The writer of the masked canonical form of a JSON value.
struct Writer<'a> {
    mask: &'a JsonMask,
    /// The object keys from the root to the value.
    path: Vec<&'a str>,
    out: &'a mut String,
}

impl<'a> Writer<'a> {
    /// True if the path is a subtree of the mask.
    fn in_subtree(&self) -> bool {
        self.mask.subtrees.iter().any(|t| {
            t.len() == self.path.len() && t.iter().zip(&self.path).all(|(p, k)| *p == "*" || p == k)
        })
    }

    /// Writes `v` in the canonical form of `rsim-store`, masked by `masked`
    /// and by the rules of the mask below it. `snmp` is true below a key
    /// that names SNMP.
    fn write(&mut self, v: &'a Value, depth: usize, masked: Masked, snmp: bool) {
        let rule = self.mask.key;
        match v {
            Value::Object(m) if m.is_empty() => self.out.push_str("{}"),
            Value::Array(a) if a.is_empty() => self.out.push_str("[]"),
            Value::Object(m) => {
                let named = m.contains_key("value")
                    && (self
                        .path
                        .last()
                        .is_some_and(|k| (self.mask.value_records)(k))
                        || SETTING_NAMES.iter().any(|f| {
                            m.get(*f)
                                .and_then(Value::as_str)
                                .is_some_and(|s| rule(s, snmp))
                        }));
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                self.out.push_str("{\n");
                for (i, k) in keys.iter().enumerate() {
                    indent(depth + 1, self.out);
                    if masked == Masked::All {
                        self.out.push_str(&masked_text());
                    } else {
                        self.out.push_str(&plain_text(k));
                    }
                    self.out.push_str(": ");
                    self.path.push(k.as_str());
                    let below = if masked == Masked::All
                        || rule(k, snmp)
                        || (named && k.as_str() == "value")
                    {
                        Masked::All
                    } else if masked == Masked::Values || self.in_subtree() {
                        Masked::Values
                    } else if masked == Masked::Strings || (self.mask.value_records)(k) {
                        Masked::Strings
                    } else {
                        Masked::No
                    };
                    let snmp_below = snmp || k.to_lowercase().contains("snmp");
                    self.write(&m[k.as_str()], depth + 1, below, snmp_below);
                    self.path.pop();
                    if i + 1 < keys.len() {
                        self.out.push(',');
                    }
                    self.out.push('\n');
                }
                indent(depth, self.out);
                self.out.push('}');
            }
            Value::Array(a) => {
                self.out.push_str("[\n");
                for (i, e) in a.iter().enumerate() {
                    indent(depth + 1, self.out);
                    self.write(e, depth + 1, masked, snmp);
                    if i + 1 < a.len() {
                        self.out.push(',');
                    }
                    self.out.push('\n');
                }
                indent(depth, self.out);
                self.out.push(']');
            }
            Value::String(s) if hash_like(s) => self.out.push_str(&masked_text()),
            Value::String(_) if masked != Masked::No => self.out.push_str(&masked_text()),
            _ if matches!(masked, Masked::Values | Masked::All) => {
                self.out.push_str(&masked_text())
            }
            Value::String(s) => self.out.push_str(&plain_text(s)),
            other => self.out.push_str(&other.to_string()),
        }
    }
}

/// True for a text with the form of a crypt hash, such as `$6$salt$hash`.
fn hash_like(s: &str) -> bool {
    s.starts_with('$') && s[1..].contains('$')
}

/// The masked lines of a text section, with the line mask of its vendor.
/// A line that the mask does not change keeps its spaces; a masked line
/// keeps its indentation.
pub fn text_lines(bytes: &[u8], mask: fn(&str) -> String) -> Result<Vec<String>, Refusal> {
    let canon = rsim_store::canonical(Format::Text, bytes)
        .map_err(|e| Refusal::Unreadable(e.to_string()))?;
    let text = String::from_utf8_lossy(&canon);
    Ok(text.lines().map(|l| masked_line(l, mask)).collect())
}

/// The number of words that stay in a Cisco config line whose secret
/// follows words that are not secret words, or `None` for another line:
/// 3 in a line that starts with `snmp-server host`, 2 in a line that starts
/// with `host`, the trap host of the `snmp-server vrf` submode of IOS-XR,
/// because the community follows the host, and 4 in a line that starts with
/// `event manager environment`, whose value can be a credential.
pub fn cisco_kept_words(words: &[&str]) -> Option<usize> {
    let is = |i: usize, w: &str| words.get(i).is_some_and(|x| x.eq_ignore_ascii_case(w));
    if words.len() > 3 && is(0, "snmp-server") && is(1, "host") {
        Some(3)
    } else if words.len() > 2 && is(0, "host") {
        Some(2)
    } else if words.len() > 4 && is(0, "event") && is(1, "manager") && is(2, "environment") {
        Some(4)
    } else {
        None
    }
}

/// The number of the words of a Cisco line before its masked rest: the
/// words up to and with the first word of `secret_words`, or the words
/// before the first word `name=value` whose name is a word of
/// `secret_words` or a secret key of the common rule; a name with `://` or
/// `?` is a part of a URL, for `url_secrets`. Each word and each name is
/// read in lower case with the quotes and the punctuation at its
/// ends trimmed. A line with no such word keeps each word.
pub fn cisco_secret_start(words: &[&str], secret_words: &[&str]) -> usize {
    let trim = |w: &str| {
        w.trim_matches(|c: char| !c.is_ascii_alphanumeric())
            .to_ascii_lowercase()
    };
    for (i, w) in words.iter().enumerate() {
        match w.split_once('=') {
            Some((name, _)) if name.contains("://") || name.contains('?') => {}
            Some((name, _)) => {
                let name = trim(name);
                if secret_words.contains(&name.as_str()) || secret_key(&name, false) {
                    return i;
                }
            }
            None => {
                if secret_words.contains(&trim(w).as_str()) {
                    return i + 1;
                }
            }
        }
    }
    words.len()
}

fn masked_line(line: &str, mask: fn(&str) -> String) -> String {
    let m = mask(line);
    let plain = line.split_whitespace().collect::<Vec<_>>().join(" ");
    if m == plain {
        line.to_string()
    } else {
        let lead = &line[..line.len() - line.trim_start().len()];
        format!("{lead}{m}")
    }
}

/// The checks of the tests of the masks.
#[cfg(test)]
pub(crate) mod check {
    use super::*;

    /// The masked lines of a section, after the checks that the section has
    /// the lines of its canonical form, that no line holds a text with
    /// `FAKE` or a text of `secrets`, and that each text of `kept` stays.
    pub(crate) fn masked(
        vendor: &str,
        format: Format,
        bytes: &[u8],
        secrets: &[&str],
        kept: &[&str],
    ) -> Vec<String> {
        let got = section_lines(vendor, format, bytes).unwrap();
        let canon = rsim_store::canonical(format, bytes).unwrap();
        assert_eq!(got.len(), String::from_utf8_lossy(&canon).lines().count());
        let text = got.join("\n");
        assert!(!text.contains("FAKE"), "{text}");
        for s in secrets {
            assert!(!text.contains(s), "{s}: {text}");
        }
        for k in kept {
            assert!(text.contains(k), "{k}: {text}");
        }
        got
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The URLs with a fake secret in each form of `url_secrets`.
    const URLS: &[(&str, &str)] = &[
        (
            "sftp://backup:FAKEURLPW@192.0.2.5/cfg",
            "sftp://<secret>@192.0.2.5/cfg",
        ),
        (
            "https://ghp_FAKETOKEN@github.com/org/cfg.git",
            "https://<secret>@github.com/org/cfg.git",
        ),
        ("ftp://u:p@FAKEAT@192.0.2.5/x", "ftp://<secret>@192.0.2.5/x"),
        (
            "sftp://backup:ab/FAKE+cd@192.0.2.5/cfg",
            "sftp://<secret>@192.0.2.5/cfg",
        ),
        (
            "https://192.0.2.5/upload?token=FAKEQTOKEN&password=FAKEQPW&mode=x",
            "https://192.0.2.5/upload?token=<secret>&password=<secret>&mode=x",
        ),
        (
            "ssh://git:FAKESSHPW@192.0.2.10/repo",
            "ssh://<secret>@192.0.2.10/repo",
        ),
        ("admin:FAKEMAILPW@192.0.2.25", "<secret>@192.0.2.25"),
    ];

    #[test]
    fn the_secrets_of_a_url_are_masked_in_each_json_mask() {
        let v = json!({
            "system": {"config-management": {"commit-archive": {
                "location": URLS.iter().map(|(u, _)| *u).collect::<Vec<_>>(),
                "source": {"scp://w:FAKEKEYURL@192.0.2.8/c": {"url": "ftp://u:FAKEFTP@192.0.2.6/a ftp://v:FAKESECOND@192.0.2.7/b"}}
            }}},
            "kept": ["http://192.0.2.9:8080/path", "http://[2001:db8::1]:80/", "ssh://git@192.0.2.10/repo", "a@example.com"]
        });
        let bytes = v.to_string();
        let mut kept: Vec<&str> = URLS.iter().map(|(_, m)| *m).collect();
        kept.extend([
            "ftp://<secret>@192.0.2.6/a ftp://<secret>@192.0.2.7/b",
            "scp://<secret>@192.0.2.8/c",
            "http://192.0.2.9:8080/path",
            "http://[2001:db8::1]:80/",
            "ssh://git@192.0.2.10/repo",
            "a@example.com",
        ]);
        for vendor in ["vyos", "unifi", "nxos"] {
            check::masked(vendor, Format::Json, bytes.as_bytes(), &["ghp_"], &kept);
        }
    }

    #[test]
    fn the_userinfo_and_secret_parameters_of_a_url_are_masked() {
        let masked = [
            ("ftp://:FAKE@192.0.2.5", "ftp://<secret>@192.0.2.5"),
            ("x http://u:FA:KE@h", "x http://<secret>@h"),
            ("http://u:@h", "http://<secret>@h"),
            ("http://u:p/x@h", "http://<secret>@h"),
            ("http://token@h/x", "http://<secret>@h/x"),
            ("tftp://FAKE@h", "tftp://<secret>@h"),
            ("git+https://FAKE@h", "git+https://<secret>@h"),
            (
                "sftp://backup:FA'KE@192.0.2.5/cfg",
                "sftp://<secret>@192.0.2.5/cfg",
            ),
            ("scp://u:FA\"KE@h", "scp://<secret>@h"),
            ("'scp://u:FAKE@h'", "'scp://<secret>@h'"),
            (
                "http://h/x?X-Amz-Signature=FAKE&auth_sig=FAKE",
                "http://h/x?X-Amz-Signature=<secret>&auth_sig=<secret>",
            ),
            ("scp://u:FA@KE@h/x", "scp://<secret>@h/x"),
            (
                "http://h:80/ and ftp://u:FAKE@h",
                "http://h:80/ and ftp://<secret>@h",
            ),
            (
                "a://u:FAKE1@h b://v:FAKE2@k",
                "a://<secret>@h b://<secret>@k",
            ),
            (
                "\"admin:FAKE@192.0.2.25\" to a@example.com",
                "\"<secret>@192.0.2.25\" to a@example.com",
            ),
            (
                "http://h/x?key=FAKE1;sig=FAKE2#f",
                "http://h/x?key=<secret>;sig=<secret>#f",
            ),
            (
                "http://h/x?a=1&API_KEY=FAKE&Signature=FAKE&access_token=FAKE",
                "http://h/x?a=1&API_KEY=<secret>&Signature=<secret>&access_token=<secret>",
            ),
            (
                "http://h/x?auth=FAKE&pwd=FAKE&pass=FAKE&secret=FAKE&apikey=FAKE",
                "http://h/x?auth=<secret>&pwd=<secret>&pass=<secret>&secret=<secret>&apikey=<secret>",
            ),
        ];
        for (text, want) in URLS.iter().copied().chain(masked) {
            assert_eq!(url_secrets(text).as_deref(), Some(want), "{text}");
        }
        for text in [
            "http://192.0.2.9:8080/path",
            "http://[2001:db8::1]:80/",
            "ssh://git@192.0.2.10",
            "git://anonymous@192.0.2.10/repo",
            "SSH://git@192.0.2.10",
            "http://h/x?mode=1&id=2",
            "a@example.com",
            "git@github.com:org/repo.git",
            "no url",
            "://",
        ] {
            assert_eq!(url_secrets(text), None, "{text}");
        }
    }

    #[test]
    fn the_secrets_of_a_url_are_masked_in_each_text_mask() {
        let mut t = String::from("archive\n url http://192.0.2.9:8080/x\n");
        for (u, _) in URLS {
            t.push_str(&format!(" path {u}\n"));
        }
        let kept: Vec<String> = URLS
            .iter()
            .map(|(_, m)| format!(" path {m}"))
            .chain([" url http://192.0.2.9:8080/x".to_string()])
            .collect();
        let kept: Vec<&str> = kept.iter().map(String::as_str).collect();
        for vendor in ["nxos", "iosxr", "iosxe"] {
            check::masked(vendor, Format::Text, t.as_bytes(), &["ghp_"], &kept);
        }
    }

    const COMMON: JsonMask = JsonMask {
        key: secret_key,
        subtrees: &[],
        value_records: no_value_records,
    };

    fn lines(v: &Value) -> Vec<String> {
        json_lines(v.to_string().as_bytes(), &COMMON).unwrap()
    }

    fn canonical_lines(v: &Value) -> Vec<String> {
        let c = rsim_store::canonical(Format::Json, v.to_string().as_bytes()).unwrap();
        String::from_utf8(c)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn a_json_section_with_no_secret_is_its_canonical_form() {
        let v = json!({
            "interfaces": {"ethernet": {"eth0": {"address": ["192.0.2.1/24"], "mtu": 1500, "x": {}, "y": []}}},
            "name": "a \"quoted\" name",
            "on": true,
            "none": null
        });
        assert_eq!(lines(&v), canonical_lines(&v));
    }

    #[test]
    fn a_masked_json_section_keeps_the_lines_of_the_canonical_form() {
        let v = json!({
            "a": {"password": {"x": ["FAKE1", "FAKE2"], "y": {"FAKE3": 1}}},
            "b": "kept"
        });
        let got = lines(&v);
        let canon = canonical_lines(&v);
        assert_eq!(got.len(), canon.len());
        // The lines outside the value of the secret key are the same.
        for (g, c) in got.iter().zip(&canon) {
            let inside = c.contains("FAKE")
                || ["\"x\"", "\"y\""]
                    .iter()
                    .any(|k| c.trim_start().starts_with(k));
            if !inside {
                assert_eq!(g, c);
            }
        }
        let text = got.join("\n");
        assert!(!text.contains("FAKE"), "{text}");
        assert!(text.contains("\"b\": \"kept\""), "{text}");
    }

    #[test]
    fn each_secret_key_and_word_is_masked() {
        let keys = SECRET_KEYS
            .iter()
            .flat_map(|w| [w.to_string(), w.to_uppercase()])
            .chain(
                SECRET_WORDS
                    .iter()
                    .flat_map(|w| [w.to_string(), w.to_uppercase(), format!("my-{w}-field")]),
            );
        for key in keys {
            let v = json!({"outer": {key.clone(): "FAKESECRET"}});
            let text = lines(&v).join("\n");
            assert!(!text.contains("FAKESECRET"), "{key}: {text}");
        }
    }

    #[test]
    fn a_short_key_name_is_a_secret_only_by_its_whole_name() {
        let v = json!({"keepalive": 30, "aside": "a", "key-id": 1});
        assert_eq!(lines(&v), canonical_lines(&v));
    }

    #[test]
    fn an_snmp_community_is_masked_and_a_bgp_community_is_not() {
        let v = json!({
            "snmp": {"community": {"FAKECOMMUNITY": {"authorization": "ro"}}},
            "bgp": {"community": "65000:1"}
        });
        let text = lines(&v).join("\n");
        assert!(!text.contains("FAKECOMMUNITY"), "{text}");
        assert!(text.contains("65000:1"), "{text}");
    }

    #[test]
    fn a_setting_record_masks_its_value_by_its_name() {
        let v = json!({"settings": [{"name": "x_passphrase", "value": "FAKEVALUE"}, {"name": "mtu", "value": 1500}]});
        let text = lines(&v).join("\n");
        assert!(!text.contains("FAKEVALUE"), "{text}");
        assert!(text.contains("1500"), "{text}");
    }

    #[test]
    fn a_crypt_hash_is_masked_under_any_key() {
        let v = json!({"login": {"hash": "$6$FAKESALT$FAKEHASH"}});
        let text = lines(&v).join("\n");
        assert!(!text.contains("FAKEHASH"), "{text}");
    }

    #[test]
    fn a_text_line_with_no_secret_keeps_its_spaces() {
        let t = b"interface Ethernet1/1\r\n  description  uplink   x\r\n  key-string 7 FAKEKEY\r\n";
        let got = text_lines(t, nxos::mask).unwrap();
        assert_eq!(
            got,
            vec![
                "interface Ethernet1/1",
                "  description  uplink   x",
                "  key-string <secret>"
            ]
        );
    }

    #[test]
    fn the_cts_manual_pairwise_master_key_is_masked() {
        let nxos = b"interface Ethernet1/1\n  ip address 192.0.2.1/30\n  cts manual\n    sap pmk FAKEPMK0123456789 modelist gcm-encrypt\n    sap pmk encrypted FAKEENCPMK modelist gcm-encrypt\n";
        let got = check::masked(
            "nxos",
            Format::Text,
            nxos,
            &[],
            &["ip address 192.0.2.1/30"],
        );
        assert_eq!(got[3], "    sap pmk <secret>");
        assert_eq!(got[4], "    sap pmk <secret>");
        let short =
            b"interface TenGigE0/0/0/1\n cts manual\n  sap pmk FEDBAA mode-list gcm-encrypt\n";
        for vendor in ["iosxr", "iosxe"] {
            let got = check::masked(vendor, Format::Text, short, &["FEDBAA"], &["cts manual"]);
            assert_eq!(got[2], "  sap pmk <secret>", "{vendor}");
        }
    }

    #[test]
    fn a_vendor_and_format_with_no_mask_is_refused() {
        for (vendor, format) in [
            ("vyos", Format::Text),
            ("unifi", Format::Text),
            ("iosxr", Format::Json),
            ("iosxe", Format::Json),
            ("fortios", Format::Text),
        ] {
            assert!(
                matches!(
                    section_lines(vendor, format, b"{}"),
                    Err(Refusal::NoMask { .. })
                ),
                "{vendor}"
            );
        }
    }

    #[test]
    fn the_userinfo_of_each_part_of_a_word_is_masked() {
        for (text, want) in [
            (
                "admin:FAKEPW@192.0.2.25/?next=http://x",
                "<secret>@192.0.2.25/?next=http://x",
            ),
            ("b:FAKE2@h2,ftp://h3/x", "<secret>@h2,ftp://h3/x"),
            ("ftp://h3/x,b:FAKE2@h2", "ftp://<secret>@h2"),
            ("ftp://u:FAKE1@h1,b:FAKE2@h2", "ftp://<secret>@h2"),
            ("http://h/?token=FAKE1,u:FAKE2@h2", "http://<secret>"),
            ("ftp://u:FA,KE@192.0.2.5/x", "ftp://<secret>@192.0.2.5/x"),
            ("u:FA,KE@192.0.2.5", "<secret>@192.0.2.5"),
            ("x,u:FAKE@h/?next=ftp://y", "<secret>@h/?next=ftp://y"),
        ] {
            assert_eq!(url_secrets(text).as_deref(), Some(want), "{text}");
        }
    }
}
