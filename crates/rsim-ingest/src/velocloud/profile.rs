//! The vendor behaviour profile of a VeloCloud edge.

use rsim_core::SourceSpan;
use rsim_functions::{PortTranslation, RuleAction, UnzonedInterface, VendorProfile};

/// A VeloCloud edge of release 6.4 or later.
///
/// - `acl_default`: the rule list of each firewall ends with an unhandled
///   rule, so the default action decides no packet.
/// - `snat_port`: NAT Direct allocates the source port.
///
/// The values come from the Administration Guide 7.0.1, sections 22 and 23.
/// They are not confirmed against an edge.
pub fn profile() -> VendorProfile {
    VendorProfile {
        name: "velocloud".to_string(),
        acl_default: RuleAction::Deny,
        firewall_default: RuleAction::Deny,
        unzoned_interface: UnzonedInterface::Unknown,
        snat_port: PortTranslation::Allocate,
        intra_zone_default: None,
        default_vrf: None,
        processing_delay_ns: None,
        source: vec![SourceSpan::line(
            "VC-SD-WAN-7.0.1-Administration-Guide.pdf",
            1,
        )],
    }
}
