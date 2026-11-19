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
    use crate::mask::check;
    use rsim_store::Format;

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

    /// An IOS-XE running config with fake secrets in each listed place.
    const CONFIG: &str = "\
enable secret 9 $9$FAKESALT$FAKEHASH
enable password 7 0822455D0A16
username netops privilege 15 password 0 FAKEPLAIN
aaa server radius dynamic-author
 client 192.0.2.1 server-key 0 FAKESERVERKEY
 client 192.0.2.2 server-key 7 0822455D0A
 server-key FAKESK
router isis
 area-password FAKEISISAREA
 domain-password FAKEISISDOM
interface GigabitEthernet0/0/1
 ip address 192.0.2.2 255.255.255.192
 standby 1 authentication md5 key-string FAKEHSRPKEY
 vrrp 2 authentication text FAKEVRRPTEXT
 ip ospf message-digest-key 1 md5 7 FAKEOSPFKEY
 isis password FAKEISISIF
snmp mib community-map FAKECOMMMAP context c1
snmp-server community FAKECOMMUNITY RO
snmp-server host 192.0.2.7 version 2c FAKECOMMUNITYHOST
snmp-server user u1 g1 v3 auth sha FAKEAUTH priv aes 128 FAKEPRIV
tacacs server t1
 key 7 FAKETACACSKEY
radius-server key 7 FAKERADIUSKEY
crypto isakmp key FAKEISAKMPKEY address 198.51.100.200
crypto keyring kr1
 pre-shared-key address 198.51.100.200 key FAKEPSK
key chain KC macsec
 key 01
  key-string 7 FAKEKEYSTRING
ntp authentication-key 1 md5 FAKENTPKEY 7
archive
 path scp://admin:FAKEURLPW@192.0.2.5/backup/$h
crypto pki trustpoint tp1
 enrollment url http://u:FAKEENR@192.0.2.9
router bgp 65000
 neighbor 198.51.100.1 password 7 FAKEBGPPASSWORD
crypto pki token default user-pin 0 FAKEPIN
crypto pki token usb0 user-pin 7 0822455D0A
event manager environment _email_pass FAKEEEMPW
event manager environment _email_server admin:FAKEMAILPW@192.0.2.25
event manager applet MAIL
 action 1.0 mail server \"admin:FAKEAPPLETPW@192.0.2.25\" to a@example.com from b@example.com subject x body y
snmp-server vrf MGMT
 host 192.0.2.8 version 2c FAKEVRFCOMMUNITY
";

    #[test]
    fn every_listed_place_of_an_iosxe_config_is_masked() {
        check::masked(
            "iosxe",
            Format::Text,
            CONFIG.as_bytes(),
            &["0822455D0A"],
            &[
                " ip address 192.0.2.2 255.255.255.192",
                " area-password <secret>",
                " client 192.0.2.2 server-key <secret>",
                "snmp mib community-map <secret>",
                " path scp://<secret>@192.0.2.5/backup/$h",
                "crypto pki token default user-pin <secret>",
                "event manager environment _email_server <secret>",
                " action 1.0 mail server \"<secret>@192.0.2.25\" to a@example.com",
            ],
        );
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
