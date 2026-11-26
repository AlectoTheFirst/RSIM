//! The MTU of the interfaces of the twin devices that have no collected
//! `links` rows.

use std::collections::BTreeMap;

use rsim_core::SourceSpan;

/// The MTU of an interface: the largest layer 3 packet in bytes, with the
/// span of the value that gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceMtu {
    pub bytes: u64,
    pub span: SourceSpan,
}

/// The MTU of each interface, by twin device and interface.
pub type Mtus = BTreeMap<(String, String), InterfaceMtu>;
