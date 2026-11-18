//! Cisco NX-OS: the running config as indented text.

pub mod config;
pub(crate) mod layer2;
pub mod lower;
mod mask;
mod mcast;
pub mod names;
mod profile;
pub mod state;
mod table;
mod vxlan;

use std::collections::BTreeSet;

use crate::coverage::Table;
use crate::stanza::{Document, read_indented};
pub use config::{Config, read};
pub use lower::lower;
pub use mask::mask;
pub use profile::profile;
pub use table::table;

/// The JSON sections of a switch that the lowering reads.
pub const SECTIONS: &[&str] = &[
    "interfaces",
    "hsrp",
    "vrrp",
    "lldp",
    "cdp",
    "version",
    "vpc",
    "nve_peers",
    "nve_vnis",
    "rib",
    "mroutes",
    "mac_table",
];

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
