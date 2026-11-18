//! The mask of the secrets in a line of an NX-OS config.

/// The words after which the rest of a line can be a secret.
const SECRET_WORDS: &[&str] = &[
    "auth",
    "authentication",
    "authentication-key",
    "community",
    "encrypted-password",
    "hex-key",
    "key",
    "key-string",
    "localizedkey",
    "md5",
    "message-digest-key",
    "passphrase",
    "password",
    "plaintext-password",
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

/// The report form of a line of an NX-OS config. The words up to the first
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
}
