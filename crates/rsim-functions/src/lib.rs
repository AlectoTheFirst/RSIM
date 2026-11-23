//! The network function library of rsim: ingress, VRF selection, zone lookup,
//! ACL match, firewall policy, firewall session, source NAT, destination NAT,
//! route lookup, next-hop resolution, egress, the tunnel ends and the overlay
//! of an SD-WAN.

pub mod common;
pub mod fib;
pub mod forwarding;
pub mod layer2;
pub mod multicast;
pub mod nat;
pub mod policy;
pub mod profile;
pub mod qos;
pub mod routing;
pub mod rules;
pub mod sdwan;
pub mod session;
pub mod tunnel;

pub use common::Meta;
pub use fib::{Fib, GroupRoutes, NextHopGroup};
pub use forwarding::{
    DeviceDelivery, Egress, EgressMode, ExitMark, Ingress, Link, LocalInput, Tag, VrfSelection,
    ZoneLookup, ZoneRole,
};
pub use layer2::{
    BROADCAST, Flood, HostMac, HostResolution, Layer3HandOff, LinkEnd, LinkFacts, MacEntry,
    MacLookup, PortEgress, PortIngress, PortPeer, Unplaced, WirelessAttachment,
};
pub use multicast::{McastRoute, MulticastLookup, group_mac};
pub use nat::{DestinationNat, NatAction, NatScope, SourceNat};
pub use policy::{AclMatch, ConnState, FirewallPolicy, ZoneScope};
pub use profile::{PortTranslation, RuleAction, UnzonedInterface, VendorProfile};
pub use qos::QosNotEvaluated;
pub use routing::{
    Neighbour, NextHopResolution, PolicyRoute, Route, RouteKind, RouteLookup, RouteNextHop,
    RouteProtocol,
};
pub use rules::{Rule, RuleBody};
pub use sdwan::{OverlaySelect, OverlayTunnel, TunnelState, VCMP_PORT, VcmpDecap, VcmpEncap};
pub use session::{SessionCommit, SessionLookup, StateAction, StateActions};
pub use tunnel::{
    OuterFields, Segment, TunnelPeer, Unmatched, VxlanDecap, VxlanEncap, WireguardEncap,
    WireguardPeer, WireguardSettings,
};
