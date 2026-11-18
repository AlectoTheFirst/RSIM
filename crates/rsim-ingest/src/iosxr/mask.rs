//! The mask of the secrets in a line of an IOS-XR config.

/// The words after which the rest of a line can be a secret.
const SECRET_WORDS: &[&str] = &[
    "area-password",
    "auth",
    "authentication",
    "authentication-key",
    "community",
    "community-map",
    "domain-password",
    "encrypted",
    "hello-authentication",
    "hello-password",
    "hmac-md5",
    "key",
    "key-octet-string",
    "key-string",
    "lsp-password",
    "md5",
    "message-digest-key",
    "passphrase",
    "password",
    "pre-shared-key",
    "priv",
    "pin",
    "private-key",
    "psk",
    "secret",
    "server-key",
    "sha",
    "sha1",
    "sha256",
    "text-authentication",
    "user-pin",
];

/// The text that takes the place of the masked words.
const MASKED: &str = "<secret>";

/// The report form of a line of an IOS-XR config. The words up to the first
/// secret word stay, and the rest becomes `<secret>`. In a line of
/// `crate::mask::cisco_kept_words`, such as `snmp-server host`, a trap host
/// of `snmp-server vrf` or `event manager environment`, the words after its
/// kept words become `<secret>`. Each word with the form of a hash becomes
/// `<secret>` too, and the secrets of a URL in a word that stays
/// (`crate::mask::url_secrets`). The words of the result have 1 space
/// between them.
pub fn mask(line: &str) -> String {
    let words: Vec<&str> = line.split_whitespace().collect();
    let keep = crate::mask::cisco_kept_words(&words).unwrap_or_else(|| {
        words
            .iter()
            .position(|w| {
                let w = w.to_ascii_lowercase();
                SECRET_WORDS.contains(&w.as_str())
            })
            .map_or(words.len(), |i| i + 1)
    });
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
/// hash such as `$6$salt$hash`, a hexadecimal value with `0x`, or a run of
/// at least 12 hexadecimal digits, the form of a type 7 password.
fn hash_like(word: &str) -> bool {
    let w = word.trim_matches('"');
    let crypt = w.starts_with('$') && w[1..].contains('$');
    let hex0x = w.len() > 10
        && (w.starts_with("0x") || w.starts_with("0X"))
        && w[2..].chars().all(|c| c.is_ascii_hexdigit());
    let hex = w.len() >= 12 && w.chars().all(|c| c.is_ascii_hexdigit());
    crypt || hex0x || hex
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
            ("secret 10 $6$fakesalt$fakehash", "secret <secret>"),
            (
                "username admin secret 10 $6$fakesalt$fakehash",
                "username admin secret <secret>",
            ),
            ("password 7 FAKE", "password <secret>"),
            ("key 7 FAKETACACSKEY", "key <secret>"),
            (
                "tacacs-server host 192.0.2.5 port 49 key 7 FAKE",
                "tacacs-server host 192.0.2.5 port 49 key <secret>",
            ),
            (
                "radius-server host 192.0.2.6 auth-port 1812 key 7 FAKE",
                "radius-server host 192.0.2.6 auth-port 1812 key <secret>",
            ),
            ("key-string password FAKEKEYSTRING", "key-string <secret>"),
            (
                "snmp-server community FAKECOMMUNITY RO",
                "snmp-server community <secret>",
            ),
            (
                "snmp-server host 192.0.2.7 traps version 2c FAKECOMMUNITYHOST",
                "snmp-server host 192.0.2.7 <secret>",
            ),
            (
                "snmp-server user u1 g1 v3 auth sha encrypted FAKE priv aes 128 encrypted FAKE",
                "snmp-server user u1 g1 v3 auth <secret>",
            ),
            (
                "message-digest-key 1 md5 encrypted FAKE",
                "message-digest-key <secret>",
            ),
            (
                "lsp-password hmac-md5 encrypted FAKE",
                "lsp-password <secret>",
            ),
            (
                "ftp client password encrypted FAKE",
                "ftp client password <secret>",
            ),
            (
                "neighbor-password encrypted FAKE",
                "neighbor-password encrypted <secret>",
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
                "client 192.0.2.1 server-key 0 FAKESERVERKEY",
                "client 192.0.2.1 server-key <secret>",
            ),
            (
                "client 192.0.2.1 server-key 7 0822455D0A",
                "client 192.0.2.1 server-key <secret>",
            ),
            ("server-key FAKESK", "server-key <secret>"),
            ("area-password FAKEISISAREA", "area-password <secret>"),
            ("domain-password FAKEISISDOM", "domain-password <secret>"),
            (
                "text-authentication FAKEVRRP",
                "text-authentication <secret>",
            ),
            (
                "snmp-server community-map FAKECOMM context c1",
                "snmp-server community-map <secret>",
            ),
            (
                "key-octet-string 0 FAKECAK cryptographic-algorithm AES_256_CMAC",
                "key-octet-string <secret>",
            ),
        ];
        for (line, want) in cases {
            assert_eq!(mask(line), want, "{line}");
        }
    }

    #[test]
    fn the_hosts_of_submodes_eem_values_and_pins_are_masked() {
        let cases = [
            (
                "host 192.0.2.7 traps version 2c FAKECOMMUNITY",
                "host 192.0.2.7 <secret>",
            ),
            (
                "event manager environment _email_pass FAKEEEMPW",
                "event manager environment _email_pass <secret>",
            ),
            (
                "event manager environment _email_server admin:FAKEMAILPW@192.0.2.25",
                "event manager environment _email_server <secret>",
            ),
            (
                "action 1.0 mail server \"admin:FAKEMAILPW@192.0.2.25\" to a@example.com from b@example.com subject x body y",
                "action 1.0 mail server \"<secret>@192.0.2.25\" to a@example.com from b@example.com subject x body y",
            ),
            (
                "crypto pki token default user-pin 0 FAKEPIN",
                "crypto pki token default user-pin <secret>",
            ),
            ("pin 1234", "pin <secret>"),
        ];
        for (line, want) in cases {
            assert_eq!(mask(line), want, "{line}");
        }
    }

    /// An IOS-XR running config with fake secrets in each listed place.
    const CONFIG: &str = "\
username admin
 secret 10 $6$FAKESALT$FAKEHASH
 password 7 FAKEPASSWORD
interface GigabitEthernet0/0/0/0
 ipv4 address 192.0.2.1 255.255.255.0
aaa server radius dynamic-author
 client 192.0.2.1 server-key 0 FAKESERVERKEY
 client 192.0.2.2 server-key 7 0822455D0A
 server-key FAKESK
router isis core
 lsp-password hmac-md5 encrypted FAKELSP
 interface GigabitEthernet0/0/0/0
  hello-password hmac-md5 encrypted FAKEHELLO
router vrrp
 interface GigabitEthernet0/0/0/0
  address-family ipv4
   vrrp 1
    text-authentication FAKEVRRP
router hsrp
 interface GigabitEthernet0/0/0/0
  address-family ipv4
   hsrp 1
    authentication FAKEHSRP
snmp-server community-map FAKECOMMMAP context c1
snmp-server community FAKECOMMUNITY RO
snmp-server host 192.0.2.7 traps version 2c FAKECOMMUNITYHOST
snmp-server user u1 g1 v3 auth sha encrypted FAKEAUTH priv aes 128 encrypted FAKEPRIV
tacacs-server host 192.0.2.5 port 49
 key 7 FAKETACACS
key chain KC
 key 1
  key-string password FAKEKEYSTRING
router ospf 1
 area 0
  interface GigabitEthernet0/0/0/0
   message-digest-key 1 md5 encrypted FAKEOSPF
router bgp 65000
 neighbor 192.0.2.2
  password encrypted FAKEBGP
crypto ca trustpoint tp1
 enrollment url http://u:FAKEENR@192.0.2.9
snmp-server vrf MGMT
 host 192.0.2.7 traps version 2c FAKEVRFCOMMUNITY
event manager environment _email_pass FAKEEEMPW
event manager environment _email_server admin:FAKEMAILPW@192.0.2.25
crypto pki token default user-pin 0 FAKEPIN
";

    #[test]
    fn every_listed_place_of_an_iosxr_config_is_masked() {
        let mut config = CONFIG.to_string();
        for (i, w) in SECRET_WORDS.iter().enumerate() {
            config.push_str(&format!("x {w} FAKEWORD{i}\n"));
        }
        check::masked(
            "iosxr",
            Format::Text,
            config.as_bytes(),
            &["0822455D0A"],
            &[
                " ipv4 address 192.0.2.1 255.255.255.0",
                "    text-authentication <secret>",
                " enrollment url http://<secret>@192.0.2.9",
                " host 192.0.2.7 <secret>",
                "event manager environment _email_pass <secret>",
            ],
        );
    }

    #[test]
    fn a_line_with_no_secret_word_stays() {
        assert_eq!(
            mask("interface  GigabitEthernet0/0/0/0"),
            "interface GigabitEthernet0/0/0/0"
        );
        assert_eq!(
            mask("ipv4 address 192.0.2.1 255.255.255.0"),
            "ipv4 address 192.0.2.1 255.255.255.0"
        );
        assert_eq!(
            mask("snmp-server host 192.0.2.7"),
            "snmp-server host 192.0.2.7"
        );
        assert_eq!(mask("router bgp 4200000000"), "router bgp 4200000000");
        assert_eq!(mask("host 192.0.2.7"), "host 192.0.2.7");
        assert_eq!(
            mask("event manager environment _email_to"),
            "event manager environment _email_to"
        );
        assert_eq!(
            mask("mac-address 0000.5e00.5301"),
            "mac-address 0000.5e00.5301"
        );
    }

    #[test]
    fn a_hash_is_masked_with_no_secret_word() {
        assert_eq!(mask("enable $1$salt$hash"), "enable <secret>");
        assert_eq!(mask("value 0x1234567890abcdef"), "value <secret>");
        assert_eq!(mask("value 0822455D0A16"), "value <secret>");
        assert_eq!(mask("value 0x12"), "value 0x12");
    }
}
