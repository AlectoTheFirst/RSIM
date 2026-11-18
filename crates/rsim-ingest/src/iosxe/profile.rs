//! The vendor behaviour profile of IOS-XE.

use rsim_core::{SourceSpan, VrfId};
use rsim_functions::{PortTranslation, RouteProtocol, RuleAction, UnzonedInterface, VendorProfile};

use crate::nxos::names::Types;

/// The VRF of an interface with no `vrf forwarding` line, and of the global
/// table of `show ip route vrf *`.
pub const DEFAULT_VRF: &str = "default";

/// Cisco IOS-XE on a router.
///
/// - `acl_default`: a packet that matches no entry of an IPv4 access list
///   is denied. The chapter "IP Access List Overview" of the IOS XE security
///   configuration guide gives the implicit deny.
/// - `snat_port`: a NAT rule with no `overload` translates the address and
///   keeps the port. A rule with `overload` allocates a port; the lowering
///   sets it for each rule.
/// - The order of the ACLs, the route lookup and the NAT is the order of the
///   Cisco IOS document "NAT Order of Operation".
/// - The VRF of an interface with no `vrf forwarding` line is `default`.
///
/// None of the values is confirmed against a device.
pub fn profile() -> VendorProfile {
    VendorProfile {
        name: "iosxe".to_string(),
        acl_default: RuleAction::Deny,
        firewall_default: RuleAction::Deny,
        unzoned_interface: UnzonedInterface::Unknown,
        snat_port: PortTranslation::Preserve,
        intra_zone_default: None,
        default_vrf: Some(VrfId::new(DEFAULT_VRF)),
        processing_delay_ns: None,
        source: vec![
            SourceSpan::line(
                "Cisco IOS XE Security Configuration Guide: IP Access List Overview",
                1,
            ),
            SourceSpan::line(
                "https://www.cisco.com/c/en/us/support/docs/ip/network-address-translation-nat/6209-5.html",
                1,
            ),
        ],
    }
}

/// The platform name of IOS-XE in the template index.
pub const PLATFORM: &str = "cisco_ios";

/// The interface types of IOS-XE with their short forms, in lower case.
pub const INTERFACE_TYPES: Types = &[
    ("gigabitethernet", &["gi", "gig", "ge"]),
    ("twogigabitethernet", &["tw"]),
    ("fivegigabitethernet", &["fi"]),
    ("tengigabitethernet", &["te", "ten"]),
    ("twentyfivegige", &["twe"]),
    ("fortygigabitethernet", &["fo"]),
    ("hundredgige", &["hu"]),
    ("fastethernet", &["fa"]),
    ("appgigabitethernet", &["ap"]),
    ("port-channel", &["po"]),
    ("loopback", &["lo"]),
    ("vlan", &["vl"]),
    ("tunnel", &["tu"]),
    ("bdi", &["bd"]),
    ("null", &["nu"]),
];

/// An interface with no `shutdown` line is administratively up: the running
/// config of IOS-XE prints `shutdown` for each interface that is down and
/// prints no `no shutdown`. Not confirmed against a device.
pub const UP_WITHOUT_SHUTDOWN: bool = true;

/// IOS-XE with no zone-based firewall keeps state only for a NAT
/// translation: a flow that no rule translates gets no session. Not
/// confirmed against a device.
pub const KEEPS_UNTRANSLATED_FLOWS: bool = false;

/// The words of `show interfaces`: the interface state and the line
/// protocol state.
pub const STATE_UP: &str = "up";
pub const STATE_DOWN: &str = "down";
pub const STATE_ADMIN_DOWN: &str = "administratively down";

/// The age of an ARP row of an address of the router itself in
/// `show ip arp`. Such a row is not a neighbour.
pub const ARP_OWN_AGE: &str = "-";

/// The flags of a route line of `show ip route` that the lowering does not
/// model: a next hop override and an override from PfR. The route of such a
/// line is not read.
pub const ROUTE_FLAGS_NOT_LOWERED: &[&str] = &["%", "p"];

/// The header line of the route table of a VRF in `show ip route vrf *`.
/// The routes before the first such line are the global table.
pub const VRF_HEADER: &str = "Routing Table:";

/// The lines that start the header of a route table: the code legend and
/// the gateway of last resort.
pub const TABLE_HEADERS: &[&str] = &["Codes:", "Gateway of last resort"];

/// The HSRP state word of the active router in `show standby` and
/// `show standby brief`, in lower case.
pub const HSRP_ACTIVE: &str = "active";

/// The HSRP state words of a router that is not the active router, in lower
/// case. Each other word is a state that is not known.
pub const HSRP_NOT_ACTIVE: &[&str] = &["standby", "speak", "listen", "init"];

/// The VRRP state word of the master in `show vrrp` and `show vrrp brief`,
/// in lower case.
pub const VRRP_MASTER: &str = "master";

/// The VRRP state words of a router that is not the master, in lower case.
/// Each other word is a state that is not known.
pub const VRRP_NOT_MASTER: &[&str] = &["backup", "init"];

/// The interface types that cannot end a link, in lower case.
pub const NO_LINK: &[&str] = &["loopback", "null", "tunnel", "vlan", "bdi"];

/// VLAN 1 is the default VLAN of a Catalyst switch: it exists with no
/// `vlan` line. Not confirmed against a device.
pub const DEFAULT_VLAN: u16 = 1;

/// The VTP modes in which the running config holds the VLANs of a switch.
/// In the modes `server` and `client`, and with no `vtp mode` line, the
/// VLANs are in the VLAN database and not in the running config: the
/// section `vlans` (`show vlan brief`) gives them, and with no such section
/// the VLANs of a switch port are not known. Not confirmed against a
/// device.
pub const VTP_MODES_WITH_VLAN_LINES: &[&str] = &["transparent", "off"];

/// The status word of a VLAN that forwards in `show vlan brief`, in lower
/// case. A VLAN with another status, such as `act/lshut` or `suspended`,
/// except [`VLAN_UNSUPPORTED`], makes each port that carries it `Unknown`.
/// Not confirmed against a device.
pub const VLAN_ACTIVE: &str = "active";

/// The status word in `show vlan brief` of a reserved VLAN that the switch
/// does not support, such as 1002 to 1005. Such a VLAN is not a VLAN of the
/// switch, so a trunk with no allowed list does not carry it. Not confirmed
/// against a device.
pub const VLAN_UNSUPPORTED: &str = "act/unsup";

/// The port state words of `show spanning-tree` of a port that forwards,
/// in lower case.
pub const STP_FORWARDING: &[&str] = &["fwd"];

/// The port state words of `show spanning-tree` of a port that does not
/// forward: blocking, listening, learning, broken and disabled, in lower
/// case. Each other word is a state that is not known. Not confirmed
/// against a device.
pub const STP_NOT_FORWARDING: &[&str] = &["blk", "lis", "lrn", "bkn", "dis"];

/// The start of the header of an MST instance in `show spanning-tree`. The
/// section does not give the VLANs of an instance.
pub const STP_MST_HEADER: &str = "MST";

/// The word of `show standby` for the router itself as the active router.
pub const HSRP_LOCAL: &str = "local";

/// The line before the answer of a VRF in the section `arp_vrfs`, and the
/// end of that line for a VRF whose command failed.
pub const ARP_VRF_LINE: &str = "VRF: ";
pub const ARP_VRF_FAILED: &str = " failed";

/// A switch port with a `switchport` line and no `switchport mode` line
/// negotiates its mode with its neighbour (DTP), so its mode is not known.
/// Not confirmed against a device.
pub const MODE_WITHOUT_LINE: &str = "no switchport mode line, so the mode is negotiated";

/// The route codes of `show ip route` of a route that a routing protocol
/// gave. The codes are case-sensitive: `o` is ODR, a learned route of
/// another protocol. Each code that is not here and not in
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
/// route. No document or device confirms the value for IOS-XE. A collected
/// route resolves the way the device shows it.
pub const COMPUTED_THROUGH_DEFAULT: bool = true;
