//! The mask of the secrets in a VyOS config section.

use crate::mask::{key_like, normalized, secret_key as common};

/// The words of VyOS keys that name a secret anywhere in a key, in lower
/// case without `_`, `-`, `.` and spaces: the WireGuard private and
/// pre-shared keys, the PPPoE and authentication passwords, the encrypted
/// and plaintext passwords of the users, the RADIUS and TACACS keys, the
/// IPsec pre-shared secrets and the OSPF and VRRP keys.
pub const SECRET_WORDS: &[&str] = &[
    "authenticationkey",
    "encryptedpassword",
    "md5key",
    "password",
    "plaintextpassword",
    "presharedkey",
    "presharedsecret",
    "privatekey",
    "psk",
    "secret",
    "sharedsecretkey",
];

/// True for a VyOS key whose value is a secret: a key of the common rule of
/// `crate::mask`, a key with a word of `SECRET_WORDS`, a key that ends with
/// `key` or `keys` and is not a public key, or a `community` below `snmp`.
pub fn secret_key(key: &str, snmp: bool) -> bool {
    let n = normalized(key);
    common(key, snmp) || SECRET_WORDS.iter().any(|w| n.contains(w)) || key_like(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mask::{MASKED, json_lines};
    use serde_json::json;

    /// A VyOS config with fake secrets in each place of a secret.
    fn config() -> serde_json::Value {
        json!({
            "interfaces": {
                "wireguard": {"wg0": {
                    "address": ["192.0.2.1/30"],
                    "private-key": "FAKEWGPRIVATE",
                    "peer": {"site2": {"public-key": "PUBLICKEY", "preshared-key": "FAKEWGPSK"}}
                }},
                "pppoe": {"pppoe0": {"authentication": {"username": "user", "password": "FAKEPPPOE"}}},
                "ethernet": {"eth0": {"address": ["192.0.2.65/26"]}}
            },
            "system": {
                "login": {
                    "user": {"admin": {"authentication": {
                        "encrypted-password": "$6$FAKESALT$FAKEHASH",
                        "plaintext-password": "FAKEPLAIN"
                    }}},
                    "radius": {"server": {"192.0.2.10": {"key": "FAKERADIUS"}}},
                    "tacacs": {"server": {"192.0.2.11": {"key": "FAKETACACS"}}}
                }
            },
            "service": {"snmp": {
                "community": {"FAKECOMMUNITY": {"authorization": "ro"}},
                "v3": {"user": {"u1": {
                    "auth": {"plaintext-password": "FAKEV3AUTH"},
                    "privacy": {"encrypted-password": "FAKEV3PRIV"}
                }}}
            }},
            "vpn": {"ipsec": {"authentication": {"psk": {"FAKEPSKNAME": {"id": ["198.51.100.1"], "secret": "FAKEIPSEC"}}}}},
            "protocols": {
                "ospf": {"interface": {"eth0": {"authentication": {"md5": {"key-id": {"1": {"md5-key": "FAKEOSPF"}}}}}}},
                "bgp": {"neighbor": {"192.0.2.2": {"password": "FAKEBGP", "remote-as": "65001"}}}
            },
            "high-availability": {"vrrp": {"group": {"g1": {"authentication": {"password": "FAKEVRRP", "type": "plaintext-password"}}}}}
        })
    }

    #[test]
    fn a_masked_vyos_config_shows_no_secret() {
        let text = json_lines(config().to_string().as_bytes(), secret_key)
            .unwrap()
            .join("\n");
        assert!(!text.contains("FAKE"), "{text}");
        assert!(text.contains(MASKED));
        assert!(text.contains("192.0.2.65/26"), "{text}");
        assert!(text.contains("PUBLICKEY"), "{text}");
        assert!(text.contains("\"remote-as\": \"65001\""), "{text}");
    }

    #[test]
    fn each_word_of_the_vyos_list_is_masked() {
        for w in SECRET_WORDS {
            let v = json!({"a": {format!("x-{w}"): "FAKESECRET", *w: "FAKESECRET"}});
            let text = json_lines(v.to_string().as_bytes(), secret_key)
                .unwrap()
                .join("\n");
            assert!(!text.contains("FAKESECRET"), "{w}: {text}");
        }
    }
}
