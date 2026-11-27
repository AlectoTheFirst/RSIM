//! The ingestion of rsim. It reads the snapshot store and gives the function
//! instances of the twin. It has no network code, no async runtime, no
//! clock and no randomness.

pub mod bgp;
pub mod bgp_peers;
pub mod collected;
pub mod coverage;
pub mod equinix;
pub mod estate;
pub mod facts;
pub mod iosxe;
pub mod iosxr;
pub mod links;
pub mod mask;
pub mod mtu;
pub mod nxos;
pub mod ospf;
pub mod resolve;
pub mod route_tables;
pub mod stanza;
pub mod unifi;
pub mod velocloud;
pub mod vyos;

pub use coverage::{Coverage, Entry, Reach, State, Table, classify, unread};
pub use stanza::{Body, Document, Stanza, read_indented, read_json};
