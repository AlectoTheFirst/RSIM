//! The vendor behaviour profile of IOS-XR.

use rsim_core::{SourceSpan, VrfId};
use rsim_functions::{PortTranslation, RouteProtocol, RuleAction, UnzonedInterface, VendorProfile};

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

/// The name of the chassis row of `show inventory`, whose PID is the
/// platform and whose serial is the serial of the router.
pub const CHASSIS_ENTRY: &str = "Rack 0";

/// The HSRP state word of the active router in `show hsrp`, in lower case.
pub const HSRP_ACTIVE: &str = "active";

/// The HSRP state words of a router that is not the active router, in
/// lower case. Each other word is a state that is not known.
pub const HSRP_NOT_ACTIVE: &[&str] = &["standby", "speak", "listen", "init"];

/// The route codes of `show route` of a route that a routing protocol gave.
/// The codes are case-sensitive. Each code that is not here and not in
/// [`STATIC_CODES`] is a learned route of another protocol.
pub const LEARNED_CODES: &[(&str, RouteProtocol)] = &[
    ("B", RouteProtocol::Bgp),
    ("O", RouteProtocol::Ospf),
    ("i", RouteProtocol::Isis),
    ("D", RouteProtocol::Eigrp),
    ("R", RouteProtocol::Rip),
];

/// The route codes of a route that no routing protocol gave: `S`, a static
/// route, and `U`, a per-user static route.
pub const STATIC_CODES: &[&str] = &["S", "U"];

/// True if the next hop of a computed route resolves through a default
/// route. The value comes from the name of the IOS-XR command `nexthop
/// resolution allow-default`, which turns the resolution on; no document or
/// device confirms it. A collected route resolves the way the device shows
/// it.
pub const COMPUTED_THROUGH_DEFAULT: bool = false;

/// The bytes of the Ethernet header that the MTU of `show interfaces`
/// holds on top of the layer 3 packet, for the encapsulation `ARPA`. Not
/// confirmed against a device.
pub const ETHERNET_HEADER_BYTES: u64 = 14;

/// The bytes of one 802.1Q tag that the MTU of `show interfaces` holds on
/// top of the Ethernet header, for the encapsulation `802.1Q Virtual LAN`
/// with one VLAN. Not confirmed against a device.
pub const DOT1Q_TAG_BYTES: u64 = 4;

/// The encapsulation words of `show interfaces`.
pub const ENCAP_ARPA: &str = "ARPA";
pub const ENCAP_DOT1Q: &str = "802.1Q Virtual LAN";
