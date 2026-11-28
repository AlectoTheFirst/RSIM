//! The routing calculation: the route table of each device and VRF.

pub mod bgp;
pub mod install;
pub mod ospf;
pub mod platform;

pub use install::{Candidate, install};
pub use platform::{Origin, Platform, UNKNOWN_DISTANCE};
