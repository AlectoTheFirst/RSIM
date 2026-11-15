//! The function contract.

use std::fmt::Debug;

use crate::branch::Branch;
use crate::context::{Context, ContextAttr};
use crate::flow_state::FlowState;
use crate::header::HeaderField;
use crate::id::{DeviceId, FunctionId, InterfaceId, ObjectId, VrfId};
use crate::packet_set::PacketSet;
use crate::provenance::SourceSpan;

/// The function types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FunctionKind {
    // Forwarding.
    Ingress,
    VrfSelection,
    ZoneLookup,
    AclMatch,
    FirewallPolicy,
    FirewallSession,
    SourceNat,
    DestinationNat,
    RouteLookup,
    NextHopResolution,
    Egress,
    // QoS.
    Classification,
    Marking,
    Policing,
    Shaping,
    QueueSelection,
    // Layer 2.
    PortIngress,
    BridgeDomainSelection,
    MacLookup,
    Flood,
    PortEgress,
    WirelessAttachment,
    Layer3HandOff,
}

/// An object that a function reads. Delta recompilation uses it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dependency {
    Object(ObjectId),
    Interface(DeviceId, InterfaceId),
    RouteTable(DeviceId, VrfId),
    NeighbourTable(DeviceId),
    VendorProfile(String),
}

/// A network function.
///
/// Invariants:
/// - The branches partition the input. No packet is lost and no packet is
///   duplicated. At a forwarding choice, the rule applies in each
///   alternative, and the alternatives of one choice carry the same packets.
///   At a flood, the rule applies in each copy.
/// - The function is deterministic and has no side effects. Flow state goes
///   in and comes out as a value.
/// - A function with no declared QoS write passes the marking and the class
///   unchanged.
/// - If part of the function came from an unhandled stanza, the affected
///   packets get `Unknown`.
pub trait NetFunction: Debug + Send + Sync {
    fn id(&self) -> &FunctionId;
    fn kind(&self) -> FunctionKind;
    fn device(&self) -> Option<&DeviceId>;
    /// The context attributes that must be set before this function.
    fn requires(&self) -> Vec<ContextAttr>;
    /// The context attributes that are set after this function.
    fn provides(&self) -> Vec<ContextAttr>;
    /// True if the function clears the context when packets enter a device.
    /// Only the attributes in [`ContextAttr::CROSS_DEVICE`] and the provided
    /// attributes are then set.
    fn enters_device(&self) -> bool {
        false
    }
    fn reads(&self) -> Vec<Dependency>;
    fn qos_reads(&self) -> Vec<HeaderField>;
    fn qos_writes(&self) -> Vec<HeaderField>;
    fn provenance(&self) -> &[SourceSpan];
    /// All functions that a `Forward` outcome of this function can name.
    fn successors(&self) -> Vec<FunctionId>;
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch>;
}
