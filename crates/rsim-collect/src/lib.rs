//! The device collectors of rsim. This is the only crate that talks to
//! devices.
//!
//! A collection cycle runs as stages with bounded channels between them:
//! schedule, fetch, classify and hash, extract, and store. A full channel
//! stops the stage before it. A cycle writes one snapshot to the store, and
//! a cycle with no change writes nothing.

mod classify;
pub mod cli;
mod device;
pub mod fake;
#[cfg(feature = "https")]
pub mod https;
#[cfg(feature = "iosxe")]
pub mod iosxe;
#[cfg(feature = "iosxr")]
pub mod iosxr;
#[cfg(feature = "nxos")]
pub mod nxos;
mod path;
mod pipeline;
mod schedule;
mod source;
#[cfg(feature = "ssh")]
pub mod ssh;
mod transport;
mod trust;
#[cfg(feature = "ssh")]
mod tunnel;
#[cfg(feature = "unifi")]
pub mod unifi;
#[cfg(feature = "vyos")]
pub mod vyos;

pub use classify::{Classified, classify};
pub use device::{Device, Inventory, Vendor};
pub use path::{Algorithms, Jump, Proxy, ProxyLogin, Route};
pub use pipeline::{
    Clock, CollectError, Collector, CycleReport, Limits, OsEntropy, Sink, TokioClock,
};
pub use schedule::{Due, Schedule, Scheduler};
pub use source::{Capture, Extract, RawSection, SectionSpec, Source, fetch_sections};
pub use transport::{BoxFuture, Https, Ssh, TransportError};
pub use trust::{
    Credential, Credentials, MemoryCredentials, PinKind, PinPolicy, Secret, TrustStore,
};
