//! The mask of the secrets in a line of an IOS-XE config.

/// The report form of a line of an IOS-XE config: the mask of IOS-XR, whose
/// secret words (`secret`, `password`, `key`, `key-string`, `community`,
/// `pre-shared-key`, `authentication` and the others), the rule of
/// `snmp-server host` and the hash forms are the same in IOS-XE. The words
/// up to the first secret word stay, and the rest becomes `<secret>`.
pub fn mask(line: &str) -> String {
    crate::iosxr::mask(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_secrets_of_ios_xe_lines_are_masked() {
        let cases = [
            (
                "enable secret 9 $9$FAKESALT$FAKEHASH",
                "enable secret <secret>",
            ),
            ("enable password 7 0822455D0A16", "enable password <secret>"),
            (
                "username admin privilege 15 secret 9 $9$FAKESALT$FAKEHASH",
                "username admin privilege 15 secret <secret>",
            ),
            (
                "username netops privilege 15 password 0 FAKEPLAIN",
                "username netops privilege 15 password <secret>",
            ),
            ("key 7 FAKETACACSKEY", "key <secret>"),
            (
                "tacacs-server host 192.0.2.5 key 7 FAKE",
                "tacacs-server host 192.0.2.5 key <secret>",
            ),
            (
                "radius-server key 7 FAKERADIUSKEY",
                "radius-server key <secret>",
            ),
            ("key-string 7 FAKEKEYSTRING", "key-string <secret>"),
            (
                "snmp-server community FAKECOMMUNITY RO",
                "snmp-server community <secret>",
            ),
            (
                "snmp-server host 192.0.2.7 version 2c FAKECOMMUNITYHOST",
                "snmp-server host 192.0.2.7 <secret>",
            ),
            (
                "snmp-server user u1 g1 v3 auth sha FAKEAUTH priv aes 128 FAKEPRIV",
                "snmp-server user u1 g1 v3 auth <secret>",
            ),
            (
                "crypto isakmp key FAKEISAKMPKEY address 198.51.100.200",
                "crypto isakmp key <secret>",
            ),
            (
                "pre-shared-key address 198.51.100.200 key FAKEPSK",
                "pre-shared-key <secret>",
            ),
            (
                "standby 1 authentication md5 key-string FAKEHSRPKEY",
                "standby 1 authentication <secret>",
            ),
            (
                "neighbor 198.51.100.1 password 7 FAKEBGPPASSWORD",
                "neighbor 198.51.100.1 password <secret>",
            ),
            (
                "ip ospf message-digest-key 1 md5 7 FAKEOSPFKEY",
                "ip ospf message-digest-key <secret>",
            ),
            (
                "ntp authentication-key 1 md5 FAKENTPKEY 7",
                "ntp authentication-key <secret>",
            ),
        ];
        for (line, want) in cases {
            assert_eq!(mask(line), want, "{line}");
        }
    }

    #[test]
    fn a_line_with_no_secret_stays() {
        for line in [
            "interface GigabitEthernet0/0/1.100",
            "ip address 192.0.2.2 255.255.255.192 secondary",
            "standby 2 mac-address 0000.5e00.53a2",
            "ip route vrf RED 0.0.0.0 0.0.0.0 198.51.100.1 global",
            "access-list 101 permit tcp 192.0.2.0 0.0.0.63 any eq www",
        ] {
            assert_eq!(mask(line), line);
        }
    }
}
