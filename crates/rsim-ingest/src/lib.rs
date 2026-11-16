//! The ingestion of rsim. It reads the snapshot store and gives the function
//! instances of the twin. It has no network code, no async runtime, no
//! clock and no randomness.

pub mod collected;
pub mod coverage;
pub mod stanza;
pub mod vyos;

pub use coverage::{Coverage, Entry, Reach, State, Table, classify};
pub use stanza::{Body, Document, Stanza, read_json};
