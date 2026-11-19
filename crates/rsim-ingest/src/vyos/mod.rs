//! VyOS 1.4 and 1.5.

pub mod bgp;
pub mod config;
pub mod lower;
pub mod mask;
mod profile;
mod table;

use std::collections::BTreeSet;

use crate::coverage::Table;
use crate::stanza::Document;
pub use config::{Config, read};
pub use lower::{
    Layer2Links, Lowered, interface_addresses, interface_facts, interface_mac, link_summary, lower,
    physical,
};
pub use profile::profile;
pub use table::{dynamic_vrfs, table};

/// The paths of the handled stanzas that no handler read. A correct handler
/// set gives an empty list.
pub fn unread(doc: &Document, table: &Table, read: &BTreeSet<u32>) -> Vec<String> {
    crate::coverage::unread(doc, table, read)
}
