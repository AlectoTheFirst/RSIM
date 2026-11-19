//! The mask of the secrets in a line of an NX-OS config and in an NX-OS
//! JSON section.

use crate::mask::{JsonMask, normalized, secret_key};

/// The mask of an NX-OS JSON section.
pub const JSON: JsonMask = JsonMask {
    key: json_key,
    subtrees: &[],
    value_records: crate::mask::no_value_records,
};

/// True for a key of an NX-OS JSON section whose value is a secret: a key
/// of the common rule of `crate::mask`, or a key with `auth` or
/// `keystring`, such as the authentication text of an HSRP or VRRP group,
/// except a key that ends with `type` or `mode`.
pub fn json_key(key: &str, snmp: bool) -> bool {
    let n = normalized(key);
    let auth = (n.contains("auth") || n.contains("keystring"))
        && !n.ends_with("type")
        && !n.ends_with("mode");
    auth || secret_key(key, snmp)
}

/// The words after which the rest of a line can be a secret, with the
/// options of a container and the keys of a wireless network.
const SECRET_WORDS: &[&str] = &[
    "area-password",
    "auth",
    "authentication",
    "authentication-key",
    "community",
    "community-map",
    "docker-run-cmd",
    "docker-run-opts",
    "domain-password",
    "encrypted",
    "encrypted-password",
    "hello-authentication",
    "hex-key",
    "key",
    "key-octet-string",
    "key-string",
    "localizedkey",
    "md5",
    "message-digest-key",
    "passphrase",
    "password",
    "pin",
    "plaintext-password",
    "pmk",
    "pre-shared-key",
    "prepend-pkg-opts",
    "priv",
    "private-key",
    "psk",
    "run-opts",
    "secret",
    "server-key",
    "set-key",
    "sha",
    "sha1",
    "sha256",
    "text-authentication",
    "user-pin",
    "wpa-psk",
];

/// The text that takes the place of the masked words.
const MASKED: &str = "<secret>";

/// The report form of a line of an NX-OS config. The words up to the first
/// secret word stay, and the rest becomes `<secret>`, by
/// `crate::mask::cisco_secret_start`. In a line of
/// `crate::mask::cisco_kept_words`, such as `snmp-server host`, a trap host
/// of `snmp-server vrf` or `event manager environment`, the words after its
/// kept words become `<secret>`. Each word with the form of a hash becomes
/// `<secret>` too, and the secrets of a URL in a word that stays
/// (`crate::mask::url_secrets`). The words of the result have 1 space
/// between them.
pub fn mask(line: &str) -> String {
    let words: Vec<&str> = line.split_whitespace().collect();
    let keep = crate::mask::cisco_kept_words(&words)
        .unwrap_or_else(|| crate::mask::cisco_secret_start(&words, SECRET_WORDS));
    let mut out: Vec<String> = words[..keep]
        .iter()
        .map(|w| {
            if hash_like(w) {
                MASKED.to_string()
            } else {
                crate::mask::url_secrets(w).unwrap_or_else(|| w.to_string())
            }
        })
        .collect();
    if keep < words.len() {
        out.push(MASKED.to_string());
    }
    out.join(" ")
}

/// True for a word with the form of a password hash or a key: a crypt
/// hash such as `$5$salt$hash`, or a long hexadecimal value with `0x`.
fn hash_like(word: &str) -> bool {
    let w = word.trim_matches('"');
    let crypt = w.starts_with('$') && w[1..].contains('$');
    let hex = w.len() > 10
        && (w.starts_with("0x") || w.starts_with("0X"))
        && w[2..].chars().all(|c| c.is_ascii_hexdigit());
    crypt || hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mask::check;
    use rsim_store::Format;

    #[test]
    fn each_secret_word_masks_the_rest_of_the_line() {
        for w in SECRET_WORDS {
            for line in [
                format!("x {w} FAKESECRET"),
                format!("x {} 7 FAKESECRET", w.to_uppercase()),
            ] {
                let got = mask(&line);
                assert!(!got.contains("FAKESECRET"), "{w}: {got}");
            }
        }
    }

    #[test]
    fn a_secret_word_masks_the_rest_of_the_line() {
        let cases = [
            (
                "username admin password 5 $5$abc$def role network-admin",
                "username admin password <secret>",
            ),
            (
                "tacacs-server key 7 \"fake7key\"",
                "tacacs-server key <secret>",
            ),
            (
                "radius-server host 192.0.2.10 key 7 \"fake\" authentication",
                "radius-server host 192.0.2.10 key <secret>",
            ),
            (
                "snmp-server user admin network-admin auth md5 0xabc priv 0xdef localizedkey",
                "snmp-server user admin network-admin auth <secret>",
            ),
            (
                "snmp-server community fakecommunity group network-operator",
                "snmp-server community <secret>",
            ),
            (
                "snmp-server host 192.0.2.20 traps version 2c fakecommunity",
                "snmp-server host 192.0.2.20 <secret>",
            ),
            (
                "ip ospf message-digest-key 1 md5 3 fakekey",
                "ip ospf message-digest-key <secret>",
            ),
            ("key-string 7 fakekeystring", "key-string <secret>"),
            ("authentication text fakeauth", "authentication <secret>"),
            (
                "neighbor 192.0.2.1 password 3 fake",
                "neighbor 192.0.2.1 password <secret>",
            ),
        ];
        for (line, want) in cases {
            assert_eq!(mask(line), want, "{line}");
        }
    }

    #[test]
    fn the_new_secret_words_mask_the_rest_of_the_line() {
        let cases = [
            (
                "key-octet-string 7 075E731F1A5C4F524D5B5C50 cryptographic-algorithm AES_256_CMAC",
                "key-octet-string <secret>",
            ),
            (
                "ip pim hello-authentication ah-md5 3 FAKEPIMKEY",
                "ip pim hello-authentication <secret>",
            ),
            (
                "snmp-server mib community-map FAKECOMM context c1",
                "snmp-server mib community-map <secret>",
            ),
            (
                "client 192.0.2.1 server-key 7 0822455D0A",
                "client 192.0.2.1 server-key <secret>",
            ),
        ];
        for (line, want) in cases {
            assert_eq!(mask(line), want, "{line}");
        }
    }

    /// An NX-OS running config with fake secrets in each listed place.
    const CONFIG: &str = "\
username admin password 5 $5$FAKESALT$FAKEHASH role network-admin
key chain KC macsec
  key 1000
    key-octet-string 7 075E731F1A5C4F524D5B5C50 cryptographic-algorithm AES_256_CMAC
    key-octet-string 0 FAKECAK cryptographic-algorithm AES_128_CMAC
key chain K1
  key 1
    key-string 7 FAKEKEYSTRING
interface Ethernet1/1
  ip address 192.0.2.1/30
  ip pim hello-authentication ah-md5 3 FAKEPIMKEY
  ip ospf message-digest-key 1 md5 3 FAKEOSPF
  hsrp 10
    authentication text FAKEHSRP
  vrrp 50
    authentication text FAKEVRRP
snmp-server mib community-map FAKECOMMMAP context c1
snmp-server community FAKECOMM group network-operator
snmp-server host 192.0.2.20 traps version 2c FAKEHOSTCOMM
snmp-server user u1 network-admin auth sha FAKEAUTH priv aes-128 FAKEPRIV
radius-server host 192.0.2.10 key 7 \"FAKERAD\" authentication
tacacs-server key 7 \"FAKETAC\"
aaa server radius dynamic-author
  client 192.0.2.1 server-key 0 FAKESERVERKEY
  client 192.0.2.2 server-key 7 0822455D0A
router bgp 65000
  neighbor 192.0.2.2
    password 3 FAKEBGP
callhome
  transport http proxy server http://u:FAKEPROXY@192.0.2.6
event manager environment _email_pass \"FAKEEEMPW\"
event manager environment _email_server admin:FAKEMAILPW@192.0.2.25
event manager applet MAIL
  action 1.0 mail server \"admin:FAKEAPPLETPW@192.0.2.25\" to a@example.com from b@example.com subject x body y
";

    #[test]
    fn every_listed_place_of_an_nxos_config_is_masked() {
        let mut config = CONFIG.to_string();
        for (i, w) in SECRET_WORDS.iter().enumerate() {
            config.push_str(&format!("x {w} FAKEWORD{i}\n"));
        }
        check::masked(
            "nxos",
            Format::Text,
            config.as_bytes(),
            &["075E731F1A5C4F524D5B5C50", "0822455D0A"],
            &[
                "  ip address 192.0.2.1/30",
                "    key-octet-string <secret>",
                "  ip pim hello-authentication <secret>",
                "  transport http proxy server http://<secret>@192.0.2.6",
                "event manager environment _email_pass <secret>",
                "  action 1.0 mail server \"<secret>@192.0.2.25\" to a@example.com",
            ],
        );
    }

    /// The `hsrp` and `vrrp` sections with groups with an authentication text.
    fn groups() -> serde_json::Value {
        serde_json::json!({
            "TABLE_grp_detail": {"ROW_grp_detail": [{
                "sh_if_index": "Vlan10", "sh_group_num": 10, "sh_vip": "192.0.2.1",
                "sh_authentication_type": "text",
                "sh_authentication_data": "FAKEHSRPDATA",
                "sh_auth_text": "FAKEHSRPTEXT",
                "sh_auth_string": "FAKEHSRPSTRING",
                "sh_keystring": "FAKEKEYSTRING"
            }]},
            "TABLE_vrrp_group": {"ROW_vrrp_group": [{
                "sh_if_name": "Vlan50", "sh_group_id": 50, "sh_vip_addr": "203.0.113.2",
                "sh_auth_text": "FAKEVRRPTEXT",
                "sh_authtext": "FAKEVRRPTEXT2"
            }]}
        })
    }

    #[test]
    fn the_authentication_text_of_an_nxos_group_is_masked() {
        let bytes = groups().to_string();
        check::masked(
            "nxos",
            Format::Json,
            bytes.as_bytes(),
            &[],
            &["192.0.2.1", "203.0.113.2", "\"sh_group_num\": 10"],
        );
    }

    #[test]
    fn every_listed_place_of_an_nxos_json_section_is_masked() {
        let mut v = groups();
        let mut listed = serde_json::Map::new();
        for (i, w) in crate::mask::SECRET_KEYS.iter().enumerate() {
            listed.insert(w.to_string(), serde_json::json!(format!("FAKEK{i}")));
        }
        for (i, w) in crate::mask::SECRET_WORDS.iter().enumerate() {
            listed.insert(format!("sh_{w}_x"), serde_json::json!(format!("FAKEW{i}")));
        }
        listed.insert("snmp_community".into(), serde_json::json!("FAKECOMM"));
        listed.insert(
            "url".into(),
            serde_json::json!("scp://u:FAKEURL@192.0.2.5/x"),
        );
        v["listed"] = serde_json::Value::Object(listed);
        let bytes = v.to_string();
        check::masked(
            "nxos",
            Format::Json,
            bytes.as_bytes(),
            &[],
            &["\"sh_vip\": \"192.0.2.1\"", "scp://<secret>@192.0.2.5/x"],
        );
    }

    #[test]
    fn a_line_with_no_secret_word_stays() {
        assert_eq!(mask("interface  Ethernet1/1"), "interface Ethernet1/1");
        assert_eq!(
            mask("snmp-server host 192.0.2.20"),
            "snmp-server host 192.0.2.20"
        );
        assert_eq!(
            mask("ip route 0.0.0.0/0 192.0.2.1"),
            "ip route 0.0.0.0/0 192.0.2.1"
        );
    }

    #[test]
    fn a_hash_is_masked_with_no_secret_word() {
        assert_eq!(mask("enable $1$salt$hash"), "enable <secret>");
        assert_eq!(mask("value 0x1234567890abcdef"), "value <secret>");
        assert_eq!(mask("value 0x12"), "value 0x12");
    }

    #[test]
    fn the_options_of_a_container_are_masked() {
        for line in [
            "run-opts 1 \"--restart=unless-stopped -e API_TOKEN=FAKETOKEN -e DB_PASSWORD=FAKEPW\"",
            "prepend-pkg-opts \"-e X=FAKEX\"",
            "activate type docker source tg docker-run-opts \"-itd --net=host -e PASSWORD=FAKEPW\"",
            "activate type docker source tg docker-run-cmd \"/bin/app --pw FAKECMD\"",
        ] {
            let got = mask(line);
            assert!(!got.contains("FAKE"), "{line}: {got}");
        }
        assert_eq!(mask("run-opts 1 \"-e A=FAKE\""), "run-opts <secret>");
    }

    #[test]
    fn a_wireless_key_is_masked() {
        assert_eq!(
            mask("priority 0 set-key ascii 0 FAKEMPSK"),
            "priority 0 set-key <secret>"
        );
        assert_eq!(
            mask("mpsk-key 0 priority 0 set-key ascii 0 FAKEMPSK"),
            "mpsk-key 0 priority 0 set-key <secret>"
        );
        assert_eq!(mask("wpa-psk ascii 7 FAKEPSK"), "wpa-psk <secret>");
    }

    #[test]
    fn a_secret_word_with_quotes_or_punctuation_is_found() {
        for (line, want) in [
            (
                "action 2.0 cli command \"key 7 FAKETACKEY\"",
                "action 2.0 cli command \"key <secret>",
            ),
            (
                "action 3.0 cli command \"username u password FAKEPW\"",
                "action 3.0 cli command \"username u password <secret>",
            ),
            (
                "action 1 cli command \"key-string FAKE\"",
                "action 1 cli command \"key-string <secret>",
            ),
            (
                "action 1 cli command 'password' FAKE",
                "action 1 cli command 'password' <secret>",
            ),
            (
                "description (password: FAKE)",
                "description (password: <secret>",
            ),
            ("x --password=FAKE y", "x <secret>"),
            ("x DB_PASSWORD=FAKE y", "x <secret>"),
        ] {
            assert_eq!(mask(line), want, "{line}");
        }
        assert_eq!(
            mask("description \"uplink to core\""),
            "description \"uplink to core\""
        );
    }
}
