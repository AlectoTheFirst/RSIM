//! The mask of the secrets in a VyOS config section.

use crate::mask::{JsonMask, key_like, normalized, secret_key as common};

/// The mask of a VyOS config section.
pub const MASK: JsonMask = JsonMask {
    key: secret_key,
    subtrees: SUBTREES,
    value_records: crate::mask::no_value_records,
};

/// The parts of a VyOS config in which the user names the secret, so its
/// values are all masked: the environment variables, the arguments, the
/// command, the entry point and the labels of a container, the environment variables
/// and the arguments of the script of an event handler, the arguments of a
/// scheduled task, the free options of an OpenVPN interface and the
/// authentication secret of an NHRP tunnel of VyOS 1.5.
pub const SUBTREES: &[&[&str]] = &[
    &["container", "name", "*", "environment"],
    &["container", "name", "*", "arguments"],
    &["container", "name", "*", "command"],
    &["container", "name", "*", "entrypoint"],
    &["container", "name", "*", "label"],
    &[
        "service",
        "event-handler",
        "event",
        "*",
        "script",
        "environment",
    ],
    &[
        "service",
        "event-handler",
        "event",
        "*",
        "script",
        "arguments",
    ],
    &[
        "system",
        "task-scheduler",
        "task",
        "*",
        "executable",
        "arguments",
    ],
    &["interfaces", "openvpn", "*", "openvpn-option"],
    &["protocols", "nhrp", "tunnel", "*", "authentication"],
];

/// The words of VyOS keys that name a secret anywhere in a key, in lower
/// case without `_`, `-`, `.` and spaces: the WireGuard private and
/// pre-shared keys, the PPPoE and authentication passwords, the encrypted
/// and plaintext passwords of the users, the RADIUS and TACACS keys, the
/// IPsec pre-shared secrets, the NHRP secrets of VyOS 1.4 and the OSPF and
/// VRRP keys.
pub const SECRET_WORDS: &[&str] = &[
    "authenticationkey",
    "ciscoauthentication",
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
    use crate::mask::{MASKED, check, json_lines};
    use rsim_store::Format;
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
                "bgp": {"neighbor": {"192.0.2.2": {"password": "FAKEBGP", "remote-as": "65001"}}},
                "nhrp": {"tunnel": {
                    "tun0": {"cisco-authentication": "FAKENHRP", "holding-time": "300"},
                    "tun1": {"authentication": "FAKENHRP15", "holding-time": "600"}
                }}
            },
            "high-availability": {"vrrp": {"group": {"g1": {"authentication": {"password": "FAKEVRRP", "type": "plaintext-password"}}}}}
        })
    }

    #[test]
    fn a_masked_vyos_config_shows_no_secret() {
        let text = json_lines(config().to_string().as_bytes(), &MASK)
            .unwrap()
            .join("\n");
        assert!(!text.contains("FAKE"), "{text}");
        assert!(text.contains(MASKED));
        assert!(text.contains("192.0.2.65/26"), "{text}");
        assert!(text.contains("PUBLICKEY"), "{text}");
        assert!(text.contains("\"remote-as\": \"65001\""), "{text}");
        assert!(text.contains("\"username\": \"user\""), "{text}");
        assert!(text.contains("\"holding-time\": \"600\""), "{text}");
    }

    /// The places of a VyOS config in which the user names the secret.
    fn user_named() -> serde_json::Value {
        json!({
            "container": {"name": {"db": {
                "image": "registry.example/db:1",
                "environment": {"DB_PASS": {"value": "FAKEDBPASS"}, "AUTH": {"value": "FAKEAUTH"}},
                "arguments": "--user admin --pw FAKEARGS",
                "command": "run --token=FAKECOMMAND",
                "entrypoint": "/bin/sh -c 'login FAKEENTRY'"
            }}},
            "service": {"event-handler": {"event": {"e1": {
                "filter": {"pattern": "kept-pattern"},
                "script": {
                    "path": "/config/scripts/e1.sh",
                    "arguments": "FAKEEVENTARGS",
                    "environment": {"API_AUTH": {"value": "FAKEEVENTENV"}}
                }
            }}}},
            "system": {
                "task-scheduler": {"task": {"t1": {
                    "interval": "1h",
                    "executable": {"path": "/config/scripts/t1.sh", "arguments": "--pw FAKETASKARGS"}
                }}},
                "config-management": {"commit-archive": {
                    "location": ["sftp://backup:FAKEURLPW@192.0.2.5/cfg"],
                    "source": {"s1": {"url": "scp://backup:FAKEURL15@192.0.2.5/archive"}}
                }}
            },
            "interfaces": {"openvpn": {"vtun0": {
                "mode": "client",
                "openvpn-option": ["--auth-user-pass FAKEOVPNOPT", "--http-proxy 192.0.2.6 8080 FAKEPROXY"]
            }}}
        })
    }

    #[test]
    fn a_secret_that_the_user_names_is_masked() {
        let bytes = user_named().to_string();
        check::masked(
            "vyos",
            Format::Json,
            bytes.as_bytes(),
            &[],
            &[
                "\"DB_PASS\"",
                "registry.example/db:1",
                "kept-pattern",
                "/config/scripts/t1.sh",
                "sftp://<secret>@192.0.2.5/cfg",
                "\"mode\": \"client\"",
            ],
        );
    }

    #[test]
    fn every_listed_place_of_a_vyos_config_is_masked() {
        let mut v = config();
        let user = user_named();
        for (k, x) in user.as_object().unwrap() {
            v.as_object_mut()
                .unwrap()
                .entry(k.clone())
                .or_insert(json!({}));
            merge(&mut v[k.as_str()], x);
        }
        let mut listed = serde_json::Map::new();
        for (i, w) in crate::mask::SECRET_KEYS.iter().enumerate() {
            listed.insert(w.to_string(), json!(format!("FAKEK{i}")));
        }
        for (i, w) in crate::mask::SECRET_WORDS
            .iter()
            .chain(SECRET_WORDS)
            .enumerate()
        {
            listed.insert(
                format!("x-{w}-y"),
                json!({"FAKENAME": [format!("FAKEW{i}")]}),
            );
        }
        v["listed"] = serde_json::Value::Object(listed);
        for (i, path) in SUBTREES.iter().enumerate() {
            let mut at = &mut v;
            for k in *path {
                let k = if *k == "*" { "x" } else { k };
                if !at.is_object() {
                    *at = json!({});
                }
                at = at
                    .as_object_mut()
                    .unwrap()
                    .entry(k.to_string())
                    .or_insert(json!({}));
            }
            *at = json!(format!("FAKESUB{i}"));
        }
        let bytes = v.to_string();
        check::masked(
            "vyos",
            Format::Json,
            bytes.as_bytes(),
            &[],
            &[
                "192.0.2.65/26",
                "PUBLICKEY",
                "\"remote-as\": \"65001\"",
                "kept-pattern",
            ],
        );
    }

    fn merge(a: &mut serde_json::Value, b: &serde_json::Value) {
        match (a, b) {
            (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
                for (k, x) in b {
                    match a.get_mut(k) {
                        Some(y) => merge(y, x),
                        None => {
                            a.insert(k.clone(), x.clone());
                        }
                    }
                }
            }
            (a, b) => *a = b.clone(),
        }
    }

    #[test]
    fn each_word_of_the_vyos_list_is_masked() {
        for w in SECRET_WORDS {
            let v = json!({"a": {format!("x-{w}"): "FAKESECRET", *w: "FAKESECRET"}});
            let text = json_lines(v.to_string().as_bytes(), &MASK)
                .unwrap()
                .join("\n");
            assert!(!text.contains("FAKESECRET"), "{w}: {text}");
        }
    }

    #[test]
    fn a_container_label_value_is_masked() {
        let v = json!({"container": {"name": {"app": {
            "image": "registry.example/app:1",
            "label": {"traefik.http.middlewares.a.basicauth.users": {"value": "admin:$apr1$FAKESALT$FAKEHASH"}}
        }}}});
        check::masked(
            "vyos",
            Format::Json,
            v.to_string().as_bytes(),
            &[],
            &[
                "traefik.http.middlewares.a.basicauth.users",
                "registry.example/app:1",
            ],
        );
    }

    #[test]
    fn the_fixture_config_of_r1_shows_no_secret() {
        let bytes = include_bytes!("../../tests/fixtures/vyos/r1-config.json");
        let lines = check::masked(
            "vyos",
            Format::Json,
            bytes,
            &["FAKEVYOSPASSWORD", "FAKEPEERGROUPPASSWORD", "BBBB"],
            &[],
        );
        assert!(lines.iter().filter(|l| l.contains(MASKED)).count() >= 3);
    }
}
