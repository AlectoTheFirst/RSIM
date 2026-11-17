//! The mask of the secrets in a line of an IOS-XR config.

/// The words after which the rest of a line can be a secret.
const SECRET_WORDS: &[&str] = &[
    "auth",
    "authentication",
    "authentication-key",
    "community",
    "encrypted",
    "hello-password",
    "hmac-md5",
    "key",
    "key-string",
    "lsp-password",
    "md5",
    "message-digest-key",
    "passphrase",
    "password",
    "pre-shared-key",
    "priv",
    "private-key",
    "psk",
    "secret",
    "sha",
    "sha1",
    "sha256",
];

/// The text that takes the place of the masked words.
const MASKED: &str = "<secret>";

/// The report form of a line of an IOS-XR config. The words up to the first
/// secret word stay, and the rest becomes `<secret>`. In a line that starts
/// with `snmp-server host`, the words after the host become `<secret>`,
/// because the community follows them. Each word with the form of a hash
/// becomes `<secret>` too. The words of the result have 1 space between
/// them.
pub fn mask(line: &str) -> String {
    let words: Vec<&str> = line.split_whitespace().collect();
    let keep = if words.len() > 3
        && words[0].eq_ignore_ascii_case("snmp-server")
        && words[1].eq_ignore_ascii_case("host")
    {
        3
    } else {
        words
            .iter()
            .position(|w| {
                let w = w.to_ascii_lowercase();
                SECRET_WORDS.contains(&w.as_str())
            })
            .map_or(words.len(), |i| i + 1)
    };
    let mut out: Vec<&str> = words[..keep]
        .iter()
        .map(|w| if hash_like(w) { MASKED } else { *w })
        .collect();
    if keep < words.len() {
        out.push(MASKED);
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
