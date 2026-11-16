//! The vendor behaviour profile of VyOS.

use rsim_core::{SourceSpan, VrfId};
use rsim_functions::{PortTranslation, RuleAction, UnzonedInterface, VendorProfile};

/// VyOS 1.4 and 1.5.
///
/// - `firewall_default`: the default action of a zone is `drop`.
/// - `snat_port`: masquerade keeps the source port when it is free.
/// - `unzoned_interface`: the traffic between a zone and an interface in no
///   zone is not confirmed, so it is unknown.
///
/// The values come from the VyOS documentation of the zone-based firewall
/// and of NAT. They are not confirmed against a device.
pub fn profile() -> VendorProfile {
    VendorProfile {
        name: "vyos".to_string(),
        acl_default: RuleAction::Deny,
        firewall_default: RuleAction::Deny,
        unzoned_interface: UnzonedInterface::Unknown,
        snat_port: PortTranslation::Preserve,
        default_vrf: Some(VrfId::new("default")),
        processing_delay_ns: None,
        source: vec![SourceSpan::line(
            "profiles/vyos: VyOS documentation, zone-based firewall and NAT",
            1,
        )],
    }
}
