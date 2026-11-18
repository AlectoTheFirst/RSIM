//! The vendor behaviour profile of IOS-XE.

use rsim_core::{SourceSpan, VrfId};
use rsim_functions::{PortTranslation, RuleAction, UnzonedInterface, VendorProfile};

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
