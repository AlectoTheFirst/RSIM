//! The removal of the secrets of a JSON answer before the hash and the
//! store, a port of the HST redaction.

use serde_json::Value;

/// The value of a secret in the stored sections.
pub const REDACTED: &str = "[redacted]";

/// The keys whose whole name, in any case, names a secret.
const SECRET_KEYS: &[&str] = &[
    "pass",
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "client_secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "api-key",
    "apikey",
    "key",
    "provisioning_key",
    "provisioning-key",
    "provisioningkey",
    "sid",
    "session",
    "sessionid",
    "jwt",
    "cookie",
    "authorization",
    "cak",
    "ckn",
];

/// The words that name a secret in a key in lower case with no `_`, `-`,
/// `.` and spaces. `activationkey` is the activation key of an edge.
const SECRET_WORDS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "privatekey",
    "privkey",
    "authkey",
    "authenticationkey",
    "encryptionkey",
    "accesskey",
    "apikey",
    "sharedkey",
    "licensekey",
    "psk",
    "vendorconfig",
    "provisioningkey",
    "iappkey",
    "vwirekey",
    "credential",
    "activationkey",
];

/// The fields of a setting record that name the setting of its `value`.
const SETTING_NAMES: [&str; 4] = ["name", "key", "setting", "parameter"];

/// True if a key names a secret. Below a key that names SNMP, a community
/// is a secret.
fn is_secret_key(key: &str, snmp: bool) -> bool {
    let lower = key.to_ascii_lowercase();
    if SECRET_KEYS.contains(&lower.as_str()) {
        return true;
    }
    let norm: String = lower
        .chars()
        .filter(|c| !matches!(c, '_' | '-' | '.') && !c.is_whitespace())
        .collect();
    SECRET_WORDS.iter().any(|w| norm.contains(w))
        || (norm.contains("communit") && (snmp || norm.contains("snmp")))
}

/// Replaces the value of each secret key, at each depth, with
/// [`REDACTED`]. The keys stay. A record `{name, value}` whose name names a
/// secret has its value replaced.
pub fn redact(v: &mut Value) {
    redact_below(v, false);
}

fn redact_below(v: &mut Value, snmp: bool) {
    match v {
        Value::Object(m) => {
            let named = m.contains_key("value")
                && SETTING_NAMES.iter().any(|f| {
                    m.get(*f)
                        .and_then(Value::as_str)
                        .is_some_and(|n| is_secret_key(n, snmp))
                });
            for (k, c) in m.iter_mut() {
                if (named && k == "value") || is_secret_key(k, snmp) {
                    *c = Value::String(REDACTED.to_string());
                } else {
                    let below = snmp || k.to_ascii_lowercase().contains("snmp");
                    redact_below(c, below);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|c| redact_below(c, snmp)),
        _ => {}
    }
}
