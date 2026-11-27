//! Cisco IOS-XR: the running config as indented text, and the collected
//! text sections through the TextFSM templates.

pub mod bgp;
pub mod config;
pub mod lower;
mod mask;
pub(crate) mod profile;
pub mod state;
mod table;

use std::collections::BTreeSet;

use crate::coverage::Table;
use crate::stanza::{Document, read_indented};
pub use config::{Config, read};
pub use lower::{interface_states, lower};
pub use mask::mask;
pub use profile::profile;
pub use state::rib_vrfs;
pub use table::{dynamic_vrfs, table};

/// The text sections of a router that the lowering reads.
pub const SECTIONS: &[&str] = &["interfaces", "vrfs", "rib", "arp", "lldp", "cdp", "hsrp"];

pub use profile::INTERFACE_TYPES;

/// The resolver of the interface names of the sections to the names of the
/// config.
pub fn names(cfg: &Config) -> crate::nxos::names::Names {
    crate::nxos::names::Names::with_types(
        profile::INTERFACE_TYPES,
        cfg.interfaces.iter().map(|i| i.name.as_str()),
    )
}

/// Reads the bytes of a running config into a stanza tree. A byte sequence
/// that is not UTF-8 becomes the replacement character.
pub fn read_text(bytes: &[u8]) -> Document {
    read_indented(&String::from_utf8_lossy(bytes))
}

/// The paths of the handled stanzas that no handler read, each key through
/// the mask. A correct handler set gives an empty list.
pub fn unread(doc: &Document, table: &Table, read: &BTreeSet<u32>) -> Vec<String> {
    crate::coverage::unread(doc, table, read)
}
