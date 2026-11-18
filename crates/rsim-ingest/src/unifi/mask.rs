//! The mask of the secrets in a UniFi section.

use crate::mask::{key_like, normalized, secret_key as common};

/// The words of UniFi keys that name a secret anywhere in a key, in lower
/// case without `_`, `-`, `.` and spaces: the WLAN passphrases, the
/// passwords, the keys, the tokens and the RADIUS secrets.
pub const SECRET_WORDS: &[&str] = &[
    "authkey",
    "passphrase",
    "password",
    "psk",
    "radiussecret",
    "secret",
    "token",
    "wepkey",
];

/// True for a UniFi key whose value is a secret: a key of the common rule
/// of `crate::mask`, a key with a word of `SECRET_WORDS`, a key that ends
/// with `key` or `keys` and is not a public key, or an `x_` key, in which
/// the controller keeps its credentials. `x_fingerprint` and the `x_has_`
/// keys are secrets only by the other rules.
pub fn secret_key(key: &str, snmp: bool) -> bool {
    let n = normalized(key);
    let lower = key.to_lowercase();
    let x = lower.starts_with("x_") && lower != "x_fingerprint" && !lower.starts_with("x_has_");
    x || common(key, snmp) || SECRET_WORDS.iter().any(|w| n.contains(w)) || key_like(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mask::json_lines;
    use serde_json::json;

    #[test]
    fn a_masked_unifi_section_shows_no_secret() {
        let v = json!({"data": [
            {
                "name": "guest",
                "x_passphrase": "FAKEPASSPHRASE",
                "x_iapp_key": "FAKEIAPP",
                "x_fingerprint": "kept-fingerprint",
                "x_has_password": true,
                "radius_secret": "FAKERADIUS",
                "auth_servers": [{"ip": "192.0.2.10", "port": 1812, "x_secret": "FAKEAUTHSERVER"}],
                "keys": ["FAKEKEY1", "FAKEKEY2"],
                "token": "FAKETOKEN",
                "wpa_psk": "FAKEPSK"
            },
            {"name": "admin", "x_password": "FAKEPASSWORD", "x_ssh_password": "FAKESSH", "x_authkey": "FAKEAUTHKEY"}
        ]});
        let text = json_lines(v.to_string().as_bytes(), secret_key)
            .unwrap()
            .join("\n");
        assert!(!text.contains("FAKE"), "{text}");
        assert!(text.contains("kept-fingerprint"), "{text}");
        assert!(text.contains("192.0.2.10"), "{text}");
    }

    #[test]
    fn each_word_of_the_unifi_list_is_masked() {
        for w in SECRET_WORDS {
            let v = json!({"a": {format!("my_{w}"): "FAKESECRET", *w: "FAKESECRET"}});
            let text = json_lines(v.to_string().as_bytes(), secret_key)
                .unwrap()
                .join("\n");
            assert!(!text.contains("FAKESECRET"), "{w}: {text}");
        }
    }
}
