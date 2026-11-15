//! The context: attributes derived along the path that later functions need.

use std::net::IpAddr;

use crate::id::{
    ApplicationId, BridgeDomainId, DeviceId, EndpointId, InterfaceId, PortId, VrfId, ZoneId,
};
use crate::packet_set::PacketSet;

/// The value of one context attribute.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Attr<T> {
    /// No function set the attribute on this path.
    #[default]
    Unset,
    Known(T),
    /// A function set the attribute, but its value is not known.
    Unknown,
}

impl<T> Attr<T> {
    pub fn known(&self) -> Option<&T> {
        match self {
            Attr::Known(v) => Some(v),
            _ => None,
        }
    }

    pub fn is_set(&self) -> bool {
        !matches!(self, Attr::Unset)
    }
}

/// The names of the context attributes. Functions declare which attributes
/// they require and which they provide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContextAttr {
    Device,
    IngressInterface,
    Vrf,
    SrcZone,
    DstZone,
    Session,
    EgressInterface,
    NextHop,
    NeighbourTarget,
    Application,
    // QoS.
    TrafficClass,
    DropPrecedence,
    Queue,
    // Layer 2.
    IngressPort,
    BridgeDomain,
}

impl ContextAttr {
    /// The attributes that stay valid across a hand-off to another device.
    /// An ingress function clears all other attributes.
    pub const CROSS_DEVICE: [ContextAttr; 3] = [
        ContextAttr::TrafficClass,
        ContextAttr::DropPrecedence,
        ContextAttr::Queue,
    ];
}

/// The next hop that a route selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NextHop {
    /// The destination is on a connected network. The next hop is the
    /// destination address of each packet.
    Connected,
    Gateway(IpAddr),
}

/// The neighbour that next-hop resolution found.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NeighbourTarget {
    /// The neighbour is an endpoint. The egress function delivers to it.
    Endpoint(EndpointId),
    /// The neighbour is behind the link of the egress interface.
    Link,
}

/// The firewall session state of the packets at this device.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SessionMatch {
    /// No session matched. `entry` is the packet set at the session lookup,
    /// before any translation on this device.
    New { entry: PacketSet },
    /// A session matched in the forward direction.
    Forward { device: DeviceId, index: u32 },
    /// A session matched in the reply direction.
    Reply { device: DeviceId, index: u32 },
}

/// The context of a packet set at one point on the path.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Context {
    pub device: Attr<DeviceId>,
    pub ingress_interface: Attr<InterfaceId>,
    pub vrf: Attr<VrfId>,
    pub src_zone: Attr<ZoneId>,
    pub dst_zone: Attr<ZoneId>,
    pub session: Attr<SessionMatch>,
    pub egress_interface: Attr<InterfaceId>,
    pub next_hop: Attr<NextHop>,
    pub neighbour: Attr<NeighbourTarget>,
    pub application: Attr<ApplicationId>,
    pub traffic_class: Attr<u8>,
    pub drop_precedence: Attr<u8>,
    pub queue: Attr<u8>,
    pub ingress_port: Attr<PortId>,
    pub bridge_domain: Attr<BridgeDomainId>,
}

impl Context {
    /// The context when packets enter a device. The attributes in
    /// [`ContextAttr::CROSS_DEVICE`] stay. All others are cleared.
    pub fn enter_device(&self, device: DeviceId, interface: InterfaceId) -> Context {
        Context {
            device: Attr::Known(device),
            ingress_interface: Attr::Known(interface),
            traffic_class: self.traffic_class.clone(),
            drop_precedence: self.drop_precedence.clone(),
            queue: self.queue.clone(),
            ..Context::default()
        }
    }

    /// True if the attribute has a value or is unknown.
    pub fn is_set(&self, a: ContextAttr) -> bool {
        match a {
            ContextAttr::Device => self.device.is_set(),
            ContextAttr::IngressInterface => self.ingress_interface.is_set(),
            ContextAttr::Vrf => self.vrf.is_set(),
            ContextAttr::SrcZone => self.src_zone.is_set(),
            ContextAttr::DstZone => self.dst_zone.is_set(),
            ContextAttr::Session => self.session.is_set(),
            ContextAttr::EgressInterface => self.egress_interface.is_set(),
            ContextAttr::NextHop => self.next_hop.is_set(),
            ContextAttr::NeighbourTarget => self.neighbour.is_set(),
            ContextAttr::Application => self.application.is_set(),
            ContextAttr::TrafficClass => self.traffic_class.is_set(),
            ContextAttr::DropPrecedence => self.drop_precedence.is_set(),
            ContextAttr::Queue => self.queue.is_set(),
            ContextAttr::IngressPort => self.ingress_port.is_set(),
            ContextAttr::BridgeDomain => self.bridge_domain.is_set(),
        }
    }
}
