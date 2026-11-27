//! The routing calculation: the route table of each device and VRF.

pub mod ospf;
pub mod platform;

pub use platform::{Origin, Platform, UNKNOWN_DISTANCE};
