//! The device collectors of rsim. This is the only crate that talks to
//! devices.
//!
//! A collection cycle runs as stages with bounded channels between them:
//! schedule, fetch, classify and hash, extract, and store. A full channel
//! stops the stage before it. A cycle writes one snapshot to the store, and
//! a cycle with no change writes nothing.

#[cfg(feature = "ssh")]
pub mod bgp;
mod classify;
pub mod cli;
#[cfg(all(feature = "nxos", feature = "iosxe", feature = "iosxr"))]
pub mod demo;
mod device;
#[cfg(feature = "equinix")]
pub mod equinix;
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
#[cfg(feature = "https")]
pub mod redact;
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
#[cfg(feature = "velocloud")]
pub mod velocloud;
#[cfg(feature = "vyos")]
pub mod vyos;

pub use classify::{Classified, classify};
pub use device::{CaptureBgp, DEFAULT_INTERVAL, Device, Inventory, InventoryList, Vendor};
pub use path::{Algorithms, Jump, Proxy, ProxyLogin, Route};
pub use pipeline::{
    Clock, CollectError, Collector, CycleReport, DEFAULT_HISTORY, Limits, OsEntropy,
    PRUNE_INTERVAL, Sink, TimeLimits, TokioClock, WAKE_LIMIT,
};
pub use schedule::{Due, Schedule, Scheduler};
pub use source::{Capture, Extract, RawSection, SectionSpec, Source, Timeouts, fetch_sections};
pub use transport::{
    BoxFuture, ERROR_TEXT_CHARS, HttpReply, Https, Ssh, TransportError, error_text,
};
pub use trust::{
    Credential, Credentials, MemoryCredentials, PinKind, PinPolicy, Secret, TrustStore,
};
