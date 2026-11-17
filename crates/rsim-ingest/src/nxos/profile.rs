//! The vendor behaviour profile of NX-OS.

use rsim_core::{SourceSpan, VrfId};
use rsim_functions::{PortTranslation, RuleAction, UnzonedInterface, VendorProfile};

/// Cisco NX-OS on a Nexus switch.
///
/// - `acl_default`: a packet that matches no entry of an IP ACL is denied.
///   The section "Implicit Rules for IP and MAC ACLs" of the NX-OS security
///   configuration guide gives the implicit rules.
/// - `snat_port`: a NAT rule with no `overload` translates the address and
///   keeps the port. A rule with `overload` allocates a port; the lowering
///   sets it for each rule.
/// - The order of the ACLs, the route lookup and the NAT is the order of the
///   Cisco IOS document "NAT Order of Operation". No NX-OS document gives
///   it.
/// - The VRF of an interface with no `vrf member` is `default`.
///
/// None of the values is confirmed against a device.
pub fn profile() -> VendorProfile {
    VendorProfile {
        name: "nxos".to_string(),
        acl_default: RuleAction::Deny,
        firewall_default: RuleAction::Deny,
        unzoned_interface: UnzonedInterface::Unknown,
        snat_port: PortTranslation::Preserve,
        intra_zone_default: None,
        default_vrf: Some(VrfId::new("default")),
        processing_delay_ns: None,
        source: vec![
            SourceSpan::line(
                "Cisco Nexus 9000 NX-OS Security Configuration Guide: Implicit Rules for IP and MAC ACLs",
                1,
            ),
            SourceSpan::line(
                "https://www.cisco.com/c/en/us/support/docs/ip/network-address-translation-nat/6209-5.html",
                1,
            ),
        ],
    }
}

/// The VLAN of an access port with no `switchport access vlan`. The
/// section "Default Settings" of the NX-OS Layer 2 switching configuration
/// guide gives VLAN 1. Not confirmed against a device.
pub const ACCESS_VLAN: u16 = 1;

/// The native VLAN of a trunk port with no `switchport trunk native vlan`.
/// The same section gives VLAN 1, and all VLANs allowed. Not confirmed
/// against a device.
pub const NATIVE_VLAN: u16 = 1;

/// The mode of a switch port with `switchport` and no `switchport mode` is
/// access. A trunk drops untagged frames when its native VLAN is not
/// allowed. No source states these 2 rules; they are not confirmed against
/// a device.
pub const DEFAULT_MODE_IS_ACCESS: bool = true;

/// The Cisco guide "Design and Configuration Guide: Best Practices for
/// Virtual Port Channels (vPC) on Cisco Nexus Series Switches", the source of
/// the vPC rules: the loop avoidance rule (page 7), HSRP and VRRP in the
/// active-active mode of the data plane (page 86), and `peer-gateway`
/// (page 118). Not confirmed against a device.
pub const VPC_GUIDE: &str = "https://www.cisco.com/c/dam/en/us/td/docs/switches/datacenter/sw/design/vpc_design/vpc_best_practices_design_guide.pdf";

/// The status words that the lowering reads: the vPC peer status `peer-ok`,
/// the HSRP states `Active` and `Standby`, and the VRRP states `Master` and
/// `Backup`. No source confirms these words in the JSON of NX-OS. Each other
/// word gives `Unknown`.
pub const STATE_WORDS: [&str; 5] = ["peer-ok", "active", "standby", "master", "backup"];
