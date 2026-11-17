//! The vendor behaviour profile of IOS-XR.

use rsim_core::{Mac, SourceSpan, VrfId};
use rsim_functions::{PortTranslation, RuleAction, UnzonedInterface, VendorProfile};

use crate::nxos::names::Types;

/// The VRF of an interface with no `vrf` line, and the VRF name of the
/// global table in `show route vrf all ipv4`.
pub const DEFAULT_VRF: &str = "default";

/// Cisco IOS-XR on an ASR 9000 or an NCS router.
///
/// - `acl_default`: a packet that matches no entry of an IPv4 access list
///   is denied. The chapter "Implementing Access Lists and Prefix Lists" of
///   the IOS XR IP addresses and services configuration guide gives the
///   implicit deny.
/// - The router has no NAT and no session state on the forwarding path.
/// - The VRF of an interface with no `vrf` line is `default`.
///
/// None of the values is confirmed against a device.
pub fn profile() -> VendorProfile {
    VendorProfile {
        name: "iosxr".to_string(),
        acl_default: RuleAction::Deny,
        firewall_default: RuleAction::Deny,
        unzoned_interface: UnzonedInterface::Unknown,
        snat_port: PortTranslation::Preserve,
        intra_zone_default: None,
        default_vrf: Some(VrfId::new(DEFAULT_VRF)),
        processing_delay_ns: None,
        source: vec![SourceSpan::line(
            "Cisco IOS XR IP Addresses and Services Configuration Guide: Implementing Access Lists and Prefix Lists",
            1,
        )],
    }
}

/// The interface types of IOS-XR with their short forms, in lower case.
pub const INTERFACE_TYPES: Types = &[
    ("gigabitethernet", &["gi", "gige", "ge"]),
    ("tengige", &["te", "tengigabitethernet"]),
    ("twentyfivegige", &["tf"]),
    ("fortygige", &["fo"]),
    ("fiftygige", &["fi"]),
    ("hundredgige", &["hu"]),
    ("fourhundredgige", &["fh"]),
    ("bundle-ether", &["be"]),
    ("loopback", &["lo"]),
    ("mgmteth", &["mg"]),
    ("bvi", &["bv"]),
    ("tunnel-ip", &["ti"]),
    ("tunnel-te", &["tt"]),
    ("null", &["nu"]),
];

/// An interface with no `shutdown` line is administratively up: the running
/// config of IOS-XR prints `shutdown` for each interface that is down. Not
/// confirmed against a device.
pub const UP_WITHOUT_SHUTDOWN: bool = true;

/// The keyword of an ACL entry for all IPv4 protocols.
pub const ALL_IPV4: &str = "ipv4";

/// The route codes of `show route` that the lowering reads: a local address
/// and a connected network. Each other code is a route with next hops. A
/// trailing `*` marks a candidate default route.
pub const LOCAL_CODE: &str = "L";
pub const CONNECTED_CODE: &str = "C";

/// The marker of a backup path (LFA or PIC) in `show route`. A backup path
/// does not forward while the primary path is up.
pub const BACKUP_MARK: &str = "(!)";

/// The words of `show interfaces`: the interface state and the line
/// protocol state.
pub const STATE_UP: &str = "up";
pub const STATE_DOWN: &str = "down";
pub const STATE_ADMIN_DOWN: &str = "administratively down";

/// The ARP state of an address of the router itself in `show arp`. Such a
/// row is not a neighbour.
pub const ARP_OWN: &str = "Interface";

/// The platform name of IOS-XR in the template index.
pub const PLATFORM: &str = "cisco_xr";

/// The HSRP state word of the active router in `show hsrp`, in lower case.
pub const HSRP_ACTIVE: &str = "active";

/// The HSRP state words of a router that is not the active router, in
/// lower case. Each other word is a state that is not known.
pub const HSRP_NOT_ACTIVE: &[&str] = &["standby", "speak", "listen", "init"];

/// The HSRP version of a group with no `version` on its `hsrp` line. Not
/// confirmed against a device.
pub const HSRP_DEFAULT_VERSION: u8 = 1;

/// The virtual MAC of an HSRP group with no `mac-address` line:
/// `0000.0c07.acXX` for version 1 and the groups 0 to 255, and
/// `0000.0c9f.fXXX` for version 2 and the groups 0 to 4095. RFC 2281 gives
/// the MAC of version 1. Not confirmed against a device.
pub fn hsrp_vmac(version: u8, group: u32) -> Option<Mac> {
    match (version, u8::try_from(group), u16::try_from(group)) {
        (1, Ok(g), _) => Some(Mac([0x00, 0x00, 0x0c, 0x07, 0xac, g])),
        (2, _, Ok(g)) if g <= 0x0fff => {
            let [hi, lo] = g.to_be_bytes();
            Some(Mac([0x00, 0x00, 0x0c, 0x9f, 0xf0 | hi, lo]))
        }
        _ => None,
    }
}
