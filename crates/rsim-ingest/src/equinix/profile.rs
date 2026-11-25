//! The vendor behaviour profile of an Equinix Fabric account.

use rsim_core::SourceSpan;
use rsim_functions::{PortTranslation, RuleAction, UnzonedInterface, VendorProfile};

/// An Equinix Fabric account.
///
/// - The handled port state is `ACTIVE`, and the handled circuit state is
///   `ACTIVE`. `DEPROVISIONED`, `DELETED` and `CANCELLED` end a circuit.
/// - The handled circuit type is `EVPL_VC`.
/// - The link protocols `UNTAGGED` and `NULL` are port-based.
/// - A `VD` end with no link protocol carries untagged frames on its
///   Network Edge interface.
/// - The handled state of a device link group is `PROVISIONED`.
/// - A device link group of more than 2 members sends a frame to the member
///   with its destination MAC and floods a broadcast frame.
///
/// The values come from HST `reasoner/_constants.py`, the HST fixtures in
/// `tests/test_equinix_network_edge.py` and the decisions of the owner. No
/// capture of an account confirms them.
pub fn profile() -> VendorProfile {
    VendorProfile {
        name: "equinix".to_string(),
        acl_default: RuleAction::Deny,
        firewall_default: RuleAction::Deny,
        unzoned_interface: UnzonedInterface::Unknown,
        snat_port: PortTranslation::Preserve,
        intra_zone_default: None,
        default_vrf: None,
        processing_delay_ns: None,
        source: vec![SourceSpan::line("hst/reasoner/_constants.py", 1)],
    }
}
