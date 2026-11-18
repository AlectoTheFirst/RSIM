//! The masked lines of a section: each line of the canonical form of a
//! section, with the secrets masked by the mask of its vendor and format.
//!
//! A JSON section is masked by its keys: the value of a secret key is
//! masked whole, with each key and each value below it, so a secret that
//! is the key of an object (a VyOS SNMP community, the name of a pre-shared
//! key) goes with it. The masked lines keep the lines of the canonical form
//! of `rsim-store`: a line with no secret is the same text. A text section
//! is masked line by line by the line mask of its vendor.

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

/// The masked lines of the canonical form of a section of a vendor, from
/// line 1. A vendor and format with no mask give `Refusal::NoMask`.
pub fn section_lines(vendor: &str, format: Format, bytes: &[u8]) -> Result<Vec<String>, Refusal> {
    match (vendor, format) {
        ("vyos", Format::Json) => json_lines(bytes, vyos::mask::secret_key),
        ("unifi", Format::Json) => json_lines(bytes, unifi::mask::secret_key),
        ("nxos", Format::Json) => json_lines(bytes, secret_key),
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
pub fn json_lines(bytes: &[u8], rule: SecretKey) -> Result<Vec<String>, Refusal> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| Refusal::Unreadable(e.to_string()))?;
    let mut out = String::new();
    write(&v, 0, false, false, rule, &mut out);
    Ok(out.lines().map(str::to_string).collect())
}

fn indent(depth: usize, out: &mut String) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn masked_text() -> String {
    Value::String(MASKED.into()).to_string()
}

/// Writes `v` in the canonical form of `rsim-store`, with each key and each
/// value below a secret key masked. `masked` is true below a secret key.
fn write(v: &Value, depth: usize, masked: bool, snmp: bool, rule: SecretKey, out: &mut String) {
    match v {
        Value::Object(m) if m.is_empty() => out.push_str("{}"),
        Value::Array(a) if a.is_empty() => out.push_str("[]"),
        Value::Object(m) => {
            let named = m.contains_key("value")
                && SETTING_NAMES.iter().any(|f| {
                    m.get(*f)
                        .and_then(Value::as_str)
                        .is_some_and(|s| rule(s, snmp))
                });
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push_str("{\n");
            for (i, k) in keys.iter().enumerate() {
                indent(depth + 1, out);
                if masked {
                    out.push_str(&masked_text());
                } else {
                    out.push_str(&Value::String((*k).clone()).to_string());
                }
                out.push_str(": ");
                let below = masked || rule(k, snmp) || (named && k.as_str() == "value");
                let snmp_below = snmp || k.to_lowercase().contains("snmp");
                write(&m[k.as_str()], depth + 1, below, snmp_below, rule, out);
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
                write(e, depth + 1, masked, snmp, rule, out);
                if i + 1 < a.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(depth, out);
            out.push(']');
        }
        Value::String(s) if hash_like(s) => out.push_str(&masked_text()),
        _ if masked => out.push_str(&masked_text()),
        other => out.push_str(&other.to_string()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn lines(v: &Value, rule: SecretKey) -> Vec<String> {
        json_lines(v.to_string().as_bytes(), rule).unwrap()
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
        assert_eq!(lines(&v, secret_key), canonical_lines(&v));
    }

    #[test]
    fn a_masked_json_section_keeps_the_lines_of_the_canonical_form() {
        let v = json!({
            "a": {"password": {"x": ["FAKE1", "FAKE2"], "y": {"FAKE3": 1}}},
            "b": "kept"
        });
        let got = lines(&v, secret_key);
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
            let text = lines(&v, secret_key).join("\n");
            assert!(!text.contains("FAKESECRET"), "{key}: {text}");
        }
    }

    #[test]
    fn a_short_key_name_is_a_secret_only_by_its_whole_name() {
        let v = json!({"keepalive": 30, "aside": "a", "key-id": 1});
        assert_eq!(lines(&v, secret_key), canonical_lines(&v));
    }

    #[test]
    fn an_snmp_community_is_masked_and_a_bgp_community_is_not() {
        let v = json!({
            "snmp": {"community": {"FAKECOMMUNITY": {"authorization": "ro"}}},
            "bgp": {"community": "65000:1"}
        });
        let text = lines(&v, secret_key).join("\n");
        assert!(!text.contains("FAKECOMMUNITY"), "{text}");
        assert!(text.contains("65000:1"), "{text}");
    }

    #[test]
    fn a_setting_record_masks_its_value_by_its_name() {
        let v = json!({"settings": [{"name": "x_passphrase", "value": "FAKEVALUE"}, {"name": "mtu", "value": 1500}]});
        let text = lines(&v, secret_key).join("\n");
        assert!(!text.contains("FAKEVALUE"), "{text}");
        assert!(text.contains("1500"), "{text}");
    }

    #[test]
    fn a_crypt_hash_is_masked_under_any_key() {
        let v = json!({"login": {"hash": "$6$FAKESALT$FAKEHASH"}});
        let text = lines(&v, secret_key).join("\n");
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
}
