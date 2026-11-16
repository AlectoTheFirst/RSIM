//! Vendor behaviour profiles: vendor defaults, tie-breakers and implicit
//! rules as data.

use rsim_core::{SourceSpan, VrfId};

/// The action of a permit or deny rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleAction {
    Permit,
    Deny,
}

/// What a zone lookup does with an interface that is in no zone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnzonedInterface {
    /// The device drops the packets.
    Drop,
    /// The behaviour is not known for the platform.
    Unknown,
}

/// What source NAT does with the source port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PortTranslation {
    /// The port stays the same.
    Preserve,
    /// The device selects a port. The snapshot does not record it, so the
    /// port becomes unknown.
    Allocate,
    /// The port changes to a fixed value.
    To(u16),
}

/// The behaviour of one vendor platform. The values come from the vendor
/// documentation or from device conformance tests, never from engine code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VendorProfile {
    pub name: String,
    /// The action when no rule of an ACL matches.
    pub acl_default: RuleAction,
    /// The action when no rule of a firewall policy matches.
    pub firewall_default: RuleAction,
    /// What a zone lookup does with an interface in no zone.
    pub unzoned_interface: UnzonedInterface,
    /// The port behaviour of source NAT.
    pub snat_port: PortTranslation,
    /// The action for traffic between 2 interfaces of one zone when the
    /// zone has no intra-zone setting. `None` if the platform has no
    /// documented default.
    pub intra_zone_default: Option<RuleAction>,
    /// The VRF of an interface with no VRF statement.
    pub default_vrf: Option<VrfId>,
    /// The processing delay of a function. `None` if there is no data.
    pub processing_delay_ns: Option<u64>,
    /// Where the profile values came from.
    pub source: Vec<SourceSpan>,
}
