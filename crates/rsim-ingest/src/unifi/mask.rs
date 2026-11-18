//! The mask of the secrets in a UniFi section.

use crate::mask::{JsonMask, key_like, normalized, secret_key as common};

/// The mask of a UniFi section.
pub const MASK: JsonMask = JsonMask {
    key: secret_key,
    subtrees: &[],
    value_records,
};

/// True for the key of a list of DHCP options, such as `wan_dhcp_options`
/// with its `{optionNumber, value}` records: the value of an option can be
/// the credential of an ISP.
pub fn value_records(key: &str) -> bool {
    let n = normalized(key);
    n.contains("dhcp") && n.contains("option")
}

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
/// with `key` or `keys` and is not a public key, an `x_` key, in which the
/// controller keeps its credentials, or a key of the file of a VPN client:
/// a key with `configuration_file` or a key that ends with
/// `_configuration`, such as `openvpn_configuration` and
/// `wireguard_client_configuration_file`. `x_fingerprint` and the `x_has_`
/// keys are secrets only by the other rules.
pub fn secret_key(key: &str, snmp: bool) -> bool {
    let n = normalized(key);
    let lower = key.to_lowercase();
    let x = lower.starts_with("x_") && lower != "x_fingerprint" && !lower.starts_with("x_has_");
    let file = n.contains("configurationfile") || lower.ends_with("_configuration");
    x || file || common(key, snmp) || SECRET_WORDS.iter().any(|w| n.contains(w)) || key_like(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mask::{check, json_lines};
    use rsim_store::Format;
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
        let text = json_lines(v.to_string().as_bytes(), &MASK)
            .unwrap()
            .join("\n");
        assert!(!text.contains("FAKE"), "{text}");
        assert!(text.contains("kept-fingerprint"), "{text}");
        assert!(text.contains("192.0.2.10"), "{text}");
    }

    /// A networkconf answer with the files of the VPN clients.
    fn vpn_clients() -> serde_json::Value {
        json!({"data": [
            {
                "name": "vpn-out",
                "purpose": "vpn-client",
                "vpn_type": "openvpn-client",
                "openvpn_configuration": "client\nremote vpn.example 1194\n<key>\n-----BEGIN PRIVATE KEY-----\nFAKEOVPNKEY\n-----END PRIVATE KEY-----\n</key>\n<tls-auth>FAKETLSAUTH</tls-auth>",
                "openvpn_configuration_filename": "FAKEFILENAME.ovpn",
                "x_openvpn_password": "FAKEOVPNPASSWORD"
            },
            {
                "name": "wg-out",
                "purpose": "vpn-client",
                "vpn_type": "wireguard-client",
                "wireguard_client_configuration_file": "[Interface]\nPrivateKey = FAKEWGFILEKEY\n",
                "wireguard_client_configuration_filename": "FAKEWG.conf",
                "x_wireguard_private_key": "FAKEWGPRIVATE",
                "ip_subnet": "192.0.2.1/24"
            }
        ]})
    }

    #[test]
    fn the_files_of_a_vpn_client_are_masked() {
        let bytes = vpn_clients().to_string();
        let got = check::masked(
            "unifi",
            Format::Json,
            bytes.as_bytes(),
            &["PRIVATE KEY", "PrivateKey"],
            &["\"vpn_type\": \"openvpn-client\"", "192.0.2.1/24"],
        );
        assert!(
            got.iter()
                .any(|l| l.trim_start().starts_with("\"openvpn_configuration\": "))
        );
    }

    #[test]
    fn every_listed_place_of_a_unifi_section_is_masked() {
        let mut v = vpn_clients();
        let mut listed = serde_json::Map::new();
        for (i, w) in crate::mask::SECRET_KEYS.iter().enumerate() {
            listed.insert(w.to_string(), json!(format!("FAKEK{i}")));
        }
        for (i, w) in crate::mask::SECRET_WORDS
            .iter()
            .chain(SECRET_WORDS)
            .enumerate()
        {
            listed.insert(format!("my_{w}_x"), json!([format!("FAKEW{i}")]));
        }
        for (i, k) in [
            "x_iapp_key",
            "x_ssh_password",
            "x_anything",
            "dpi_key",
            "site_configuration",
            "a_configuration_file",
        ]
        .iter()
        .enumerate()
        {
            listed.insert(k.to_string(), json!(format!("FAKEX{i}")));
        }
        listed.insert("url".into(), json!("https://admin:FAKEURLPW@192.0.2.5/x"));
        listed.insert(
            "wan_dhcp_options".into(),
            json!([{"optionNumber": 90, "value": "FAKEOPT90AUTH"}]),
        );
        listed.insert(
            "dhcpd_options".into(),
            json!([{"optionNumber": 43, "value": "FAKEOPT43"}]),
        );
        listed.insert("x_fingerprint".into(), json!("kept-fingerprint"));
        v["data"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::Value::Object(listed));
        let bytes = v.to_string();
        check::masked(
            "unifi",
            Format::Json,
            bytes.as_bytes(),
            &["PRIVATE KEY", "PrivateKey"],
            &[
                "kept-fingerprint",
                "192.0.2.1/24",
                "https://<secret>@192.0.2.5/x",
                "\"optionNumber\": 90",
            ],
        );
    }

    #[test]
    fn the_value_of_a_wan_dhcp_option_is_masked() {
        let v = json!({"data": [{
            "name": "wan",
            "wan_dhcp_options": [
                {"optionNumber": 90, "value": "FAKEOPT90AUTH"},
                {"optionNumber": 60, "value": "FAKEVENDORCLASS"}
            ],
            "dhcpd_enabled": true
        }]});
        let bytes = v.to_string();
        check::masked(
            "unifi",
            Format::Json,
            bytes.as_bytes(),
            &[],
            &["\"optionNumber\": 90", "\"dhcpd_enabled\": true"],
        );
    }

    #[test]
    fn each_word_of_the_unifi_list_is_masked() {
        for w in SECRET_WORDS {
            let v = json!({"a": {format!("my_{w}"): "FAKESECRET", *w: "FAKESECRET"}});
            let text = json_lines(v.to_string().as_bytes(), &MASK)
                .unwrap()
                .join("\n");
            assert!(!text.contains("FAKESECRET"), "{w}: {text}");
        }
    }
}
