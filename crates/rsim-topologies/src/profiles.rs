//! Vendor behaviour profiles of the topologies.
//!
//! All values are hand-built test data. They are not confirmed against a
//! device.

use rsim_core::{SourceSpan, VrfId};
use rsim_functions::{PortTranslation, RuleAction, UnzonedInterface, VendorProfile};

fn profile(name: &str, acl_default: RuleAction, default_vrf: &str) -> VendorProfile {
    VendorProfile {
        name: name.to_string(),
        acl_default,
        firewall_default: RuleAction::Deny,
        unzoned_interface: UnzonedInterface::Drop,
        snat_port: PortTranslation::Preserve,
        default_vrf: Some(VrfId::new(default_vrf)),
        processing_delay_ns: None,
        source: vec![SourceSpan::line(format!("profiles/{name}.test-data"), 1)],
    }
}

/// FortiOS: implicit deny at the end of the policy; the source port is kept
/// by source NAT where it is free.
pub fn fortios() -> VendorProfile {
    profile("fortios", RuleAction::Deny, "root")
}

/// An inline IPS: traffic that no filter blocks passes.
pub fn tippingpoint() -> VendorProfile {
    profile("tippingpoint", RuleAction::Permit, "default")
}

/// NX-OS: implicit deny at the end of an ACL.
pub fn nxos() -> VendorProfile {
    profile("nxos", RuleAction::Deny, "default")
}

/// A generic stateful router: implicit deny at the end of an ACL. The
/// session lookup undoes a translation before the ACL, so the ACL sees the
/// reply with the public address.
pub fn generic_router() -> VendorProfile {
    profile("generic-router", RuleAction::Deny, "default")
}
