//! The routing stages and the objects that they read.

use std::collections::BTreeSet;
use std::net::IpAddr;

use super::RouteKey;
use crate::platform::Platform;

/// An object that a stage reads. A change of the object invalidates the
/// results of the stages that read it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectRef {
    /// The routing profile of a platform. `None` for a platform with no
    /// profile.
    Profile(Option<Platform>),
    /// The AS, the router ID, the cluster, the confederation and the options
    /// of a process.
    Process { device: String, vrf: String },
    Neighbor {
        device: String,
        vrf: String,
        address: IpAddr,
    },
    Policy {
        device: String,
        vrf: String,
        name: String,
    },
    PrefixList {
        device: String,
        vrf: String,
        name: String,
    },
    CommunityList {
        device: String,
        vrf: String,
        name: String,
    },
    AsPathList {
        device: String,
        vrf: String,
        name: String,
    },
    /// The candidate paths of a route at a process.
    Candidates {
        device: String,
        vrf: String,
        key: RouteKey,
    },
}

/// A routing stage: a pure function over route data with the objects that
/// it reads.
pub trait RoutingStage {
    type Input;
    type Output;

    /// The name of the stage in a trace.
    fn name(&self) -> &'static str;

    /// The objects that [`RoutingStage::run`] reads.
    fn reads(&self) -> BTreeSet<ObjectRef>;

    fn run(&self, input: &Self::Input) -> Self::Output;
}
