//! The device collectors of rsim. This is the only crate that talks to
//! devices.
//!
//! A collection cycle runs as stages with bounded channels between them:
//! schedule, fetch, classify and hash, extract, and store. A full channel
//! stops the stage before it. A cycle writes one snapshot to the store, and
//! a cycle with no change writes nothing.

mod classify;
mod device;
pub mod fake;
#[cfg(feature = "https")]
pub mod https;
mod pipeline;
mod schedule;
mod source;
#[cfg(feature = "ssh")]
pub mod ssh;
mod transport;
mod trust;
#[cfg(feature = "unifi")]
pub mod unifi;
#[cfg(feature = "vyos")]
pub mod vyos;

pub use classify::{Classified, classify};
pub use device::{Device, Inventory, Vendor};
pub use pipeline::{
    Clock, CollectError, Collector, CycleReport, Limits, OsEntropy, Sink, TokioClock,
};
pub use schedule::{Due, Schedule, Scheduler};
pub use source::{Capture, Extract, RawSection, SectionSpec, Source, fetch_sections};
pub use transport::{BoxFuture, Https, Ssh, TransportError};
pub use trust::{
    Credential, Credentials, MemoryCredentials, PinKind, PinPolicy, Secret, TrustStore,
};
