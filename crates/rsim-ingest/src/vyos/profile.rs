//! The vendor behaviour profile of VyOS.

use rsim_core::{SourceSpan, VrfId};
use rsim_functions::{PortTranslation, RuleAction, UnzonedInterface, VendorProfile};

/// VyOS 1.4 and 1.5.
///
/// - `firewall_default`: the default action of a zone is `drop`.
/// - `snat_port`: masquerade keeps the source port when it is free.
/// - `intra_zone_default`: traffic between 2 interfaces of one zone with no
///   `intra-zone-filtering` is accepted. The documentation of 1.5 says
///   "allowed by default", and the zone template of `vyos-1x` returns these
///   packets to the forward hook, which accepts them.
/// - `unzoned_interface`: unknown. The documentation says that traffic
///   between a zone member and an interface in no zone cannot flow, and the
///   zone template does not enforce this.
///
/// The values come from the VyOS documentation of the zone-based firewall
/// and of NAT, and from the nftables zone template of `vyos-1x` on the
/// branches `sagitta` and `circinus`. They are not confirmed against a
/// device.
pub fn profile() -> VendorProfile {
    VendorProfile {
        name: "vyos".to_string(),
        acl_default: RuleAction::Deny,
        firewall_default: RuleAction::Deny,
        unzoned_interface: UnzonedInterface::Unknown,
        snat_port: PortTranslation::Preserve,
        intra_zone_default: Some(RuleAction::Permit),
        default_vrf: Some(VrfId::new("default")),
        processing_delay_ns: None,
        source: vec![
            SourceSpan::line(
                "https://docs.vyos.io/en/latest/configuration/firewall/zone.html",
                1,
            ),
            SourceSpan::line(
                "https://github.com/vyos/vyos-1x/blob/circinus/data/templates/firewall/nftables-zone.j2",
                1,
            ),
        ],
    }
}
