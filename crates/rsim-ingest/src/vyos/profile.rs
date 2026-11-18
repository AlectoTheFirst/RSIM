//! The vendor behaviour profile of VyOS.

use rsim_core::{SourceSpan, VrfId};
use rsim_functions::{PortTranslation, RouteProtocol, RuleAction, UnzonedInterface, VendorProfile};

/// VyOS 1.4 and 1.5.
///
/// - `firewall_default`: the default action of a zone is `drop`.
/// - `snat_port`: masquerade keeps the source port when it is free.
/// - `intra_zone_default`: traffic between 2 interfaces of one zone with no
///   `intra-zone-filtering` is accepted. The documentation of 1.5 says
///   "allowed by default", and the zone template of `vyos-1x` returns these
///   packets to the forward hook, which accepts them.
/// - An interface in no zone: the lowering puts it in the zone `(no zone)`.
///   Traffic from it to a zone member gets the default action of the zone
///   of the member, because it enters that zone chain and matches no rule
///   set. Traffic to it enters no zone chain, and the forward hook accepts
///   it. The documentation says that this traffic cannot flow; that holds
///   only with a global forward filter, which the templates of `vyos-1x`
///   show. `unzoned_interface` stays unknown for an interface that the
///   lowering does not know.
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

/// The protocol words of a route of FRR, `show ip route json`, that a
/// routing protocol gave. Each word that is not here and not in
/// [`STATIC_WORDS`] is a learned route of another protocol.
pub const LEARNED_WORDS: &[(&str, RouteProtocol)] = &[
    ("bgp", RouteProtocol::Bgp),
    ("ospf", RouteProtocol::Ospf),
    ("isis", RouteProtocol::Isis),
    ("eigrp", RouteProtocol::Eigrp),
    ("rip", RouteProtocol::Rip),
];

/// The protocol words of FRR for a route that no routing protocol gave:
/// `static`, `kernel` for a route that another process installed, for
/// example PPPoE or DHCP, and `table` for a route of another kernel table.
pub const STATIC_WORDS: &[&str] = &["static", "kernel", "table"];
