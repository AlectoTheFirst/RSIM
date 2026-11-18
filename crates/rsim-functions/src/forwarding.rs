//! Ingress, VRF selection, zone lookup and egress.

use std::collections::BTreeMap;

use rsim_core::{
    Attr, Branch, Context, ContextAttr, Delay, DelayGap, Dependency, Destination, ExitPoint,
    FlowState, FunctionId, FunctionKind, InterfaceId, NeighbourTarget, NetFunction, Outcome,
    PacketSet, Reason, ReasonCode, Rewrite, SourceSpan, VrfId, ZoneId,
};

use crate::common::Meta;
use crate::profile::UnzonedInterface;

macro_rules! meta_methods {
    ($kind:expr) => {
        fn id(&self) -> &FunctionId {
            &self.meta.id
        }
        fn kind(&self) -> FunctionKind {
            $kind
        }
        fn device(&self) -> Option<&rsim_core::DeviceId> {
            Some(&self.meta.device)
        }
        fn provenance(&self) -> &[rsim_core::SourceSpan] {
            &self.meta.provenance
        }
        fn qos_reads(&self) -> Vec<rsim_core::HeaderField> {
            Vec::new()
        }
        fn qos_writes(&self) -> Vec<rsim_core::HeaderField> {
            Vec::new()
        }
    };
}
pub(crate) use meta_methods;

/// Packets enter a device on an interface.
#[derive(Clone, Debug)]
pub struct Ingress {
    pub meta: Meta,
    pub interface: InterfaceId,
    pub next: FunctionId,
}

impl NetFunction for Ingress {
    meta_methods!(FunctionKind::Ingress);

    fn requires(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::Device, ContextAttr::IngressInterface]
    }
    fn enters_device(&self) -> bool {
        true
    }
    fn ingress_interface(&self) -> Option<&InterfaceId> {
        Some(&self.interface)
    }
    fn reads(&self) -> Vec<Dependency> {
        vec![Dependency::Interface(
            self.meta.device.clone(),
            self.interface.clone(),
        )]
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let c = ctx.enter_device(self.meta.device.clone(), self.interface.clone());
        vec![self.meta.forward(
            input.clone(),
            &self.next,
            ReasonCode::Passed,
            format!("enter {} on {}", self.meta.device, self.interface),
            c,
            state,
        )]
    }
}

/// Selects the VRF from the ingress interface.
#[derive(Clone, Debug)]
pub struct VrfSelection {
    pub meta: Meta,
    pub by_interface: BTreeMap<InterfaceId, VrfId>,
    /// From the vendor profile: the VRF of an interface with no VRF statement.
    pub default_vrf: Option<VrfId>,
    pub next: FunctionId,
}

impl NetFunction for VrfSelection {
    meta_methods!(FunctionKind::VrfSelection);

    fn requires(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::IngressInterface]
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::Vrf]
    }
    fn reads(&self) -> Vec<Dependency> {
        self.by_interface
            .keys()
            .map(|i| Dependency::Interface(self.meta.device.clone(), i.clone()))
            .collect()
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let Some(iface) = ctx.ingress_interface.known() else {
            return vec![self.meta.unknown(
                input.clone(),
                ReasonCode::UnknownAttribute,
                "the ingress interface is not known",
                ctx,
                state,
            )];
        };
        let vrf = self.by_interface.get(iface).or(self.default_vrf.as_ref());
        match vrf {
            Some(v) => {
                let mut c = ctx.clone();
                c.vrf = Attr::Known(v.clone());
                vec![self.meta.forward(
                    input.clone(),
                    &self.next,
                    ReasonCode::Classified,
                    format!("interface {iface} is in VRF {v}"),
                    c,
                    state,
                )]
            }
            None => vec![self.meta.unknown(
                input.clone(),
                ReasonCode::IncompleteTable,
                format!("no VRF · interface {iface}"),
                ctx,
                state,
            )],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZoneRole {
    /// The zone of the ingress interface.
    Source,
    /// The zone of the egress interface.
    Destination,
}

/// Finds the firewall zone of an interface.
#[derive(Clone, Debug)]
pub struct ZoneLookup {
    pub meta: Meta,
    pub role: ZoneRole,
    pub by_interface: BTreeMap<InterfaceId, ZoneId>,
    /// From the vendor profile.
    pub unzoned: UnzonedInterface,
    pub next: FunctionId,
}

impl NetFunction for ZoneLookup {
    meta_methods!(FunctionKind::ZoneLookup);

    fn requires(&self) -> Vec<ContextAttr> {
        match self.role {
            ZoneRole::Source => vec![ContextAttr::IngressInterface],
            ZoneRole::Destination => vec![ContextAttr::EgressInterface],
        }
    }
    fn provides(&self) -> Vec<ContextAttr> {
        match self.role {
            ZoneRole::Source => vec![ContextAttr::SrcZone],
            ZoneRole::Destination => vec![ContextAttr::DstZone],
        }
    }
    fn reads(&self) -> Vec<Dependency> {
        self.by_interface
            .keys()
            .map(|i| Dependency::Interface(self.meta.device.clone(), i.clone()))
            .collect()
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let iface = match self.role {
            ZoneRole::Source => &ctx.ingress_interface,
            ZoneRole::Destination => &ctx.egress_interface,
        };
        let mut c = ctx.clone();
        let slot = match self.role {
            ZoneRole::Source => &mut c.src_zone,
            ZoneRole::Destination => &mut c.dst_zone,
        };
        match iface {
            Attr::Known(i) => match self.by_interface.get(i) {
                Some(z) => {
                    *slot = Attr::Known(z.clone());
                    vec![self.meta.forward(
                        input.clone(),
                        &self.next,
                        ReasonCode::Classified,
                        format!("interface {i} is in zone {z}"),
                        c,
                        state,
                    )]
                }
                None => match self.unzoned {
                    UnzonedInterface::Drop => vec![self.meta.drop(
                        input.clone(),
                        ReasonCode::NotInZone,
                        format!("interface {i} is in no zone"),
                        ctx,
                        state,
                    )],
                    UnzonedInterface::Unknown => vec![self.meta.unknown(
                        input.clone(),
                        ReasonCode::NotInZone,
                        format!("no zone, not in vendor profile · interface {i}"),
                        ctx,
                        state,
                    )],
                },
            },
            _ => {
                *slot = Attr::Unknown;
                vec![self.meta.forward(
                    input.clone(),
                    &self.next,
                    ReasonCode::Classified,
                    "the interface is not known, so the zone is unknown",
                    c,
                    state,
                )]
            }
        }
    }
}

/// The physical or logical link after an egress interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    /// The ingress function at the other end. `None` for a link to an
    /// endpoint, where the packets are delivered.
    pub peer: Option<FunctionId>,
    /// The link delay in nanoseconds. `None` if there is no data.
    pub delay_ns: Option<u64>,
    pub provenance: Vec<SourceSpan>,
    /// The physical facts of the link.
    pub facts: Option<crate::layer2::LinkFacts>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressMode {
    /// The neighbour comes from next-hop resolution.
    Routed,
    /// An inline device: the packets always go to the link.
    Transparent,
}

/// Packets leave a device on an interface.
#[derive(Clone, Debug)]
pub struct Egress {
    pub meta: Meta,
    pub interface: InterfaceId,
    pub mode: EgressMode,
    pub link: Option<Link>,
    /// The rewrite of the frames that leave on the link, for example the
    /// source MAC of the interface.
    pub rewrite: Rewrite,
    /// The 802.1Q tag of the frames that leave on the link.
    pub tag: Tag,
    /// Why the interface is an edge of the twin, if it is one. With no
    /// link, the packets of an edge leave the twin; the packets of an
    /// interface that is not an edge are unknown.
    pub exit: Option<ExitMark>,
}

/// Why an interface with no link is an edge of the twin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExitMark {
    /// An access link to a provider, for example PPPoE.
    AccessLink,
    /// The interface carries a default route to a next hop outside the
    /// twin.
    DefaultRoute,
    /// The owner marks the interface as an edge.
    Owner,
}

impl ExitMark {
    fn text(self) -> &'static str {
        match self {
            ExitMark::AccessLink => "access link",
            ExitMark::DefaultRoute => "default route",
            ExitMark::Owner => "marked by the owner",
        }
    }
}

/// What an egress does with the 802.1Q tag.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tag {
    /// The tag stays as it is.
    #[default]
    Keep,
    /// The frames leave without a tag.
    Untagged,
    /// The frames leave with this VLAN.
    Vlan(u16),
}

impl Egress {
    fn link_delay(&self) -> Delay {
        Delay::from_option(
            self.link.as_ref().and_then(|l| l.delay_ns),
            DelayGap::Link(self.meta.id.clone()),
        )
    }

    fn to_link(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Branch {
        match self
            .link
            .as_ref()
            .and_then(|l| l.peer.as_ref().map(|p| (l, p)))
        {
            Some((l, peer)) => {
                let facts = l
                    .facts
                    .as_ref()
                    .map_or(String::new(), |f| format!(" · {}", f.text()));
                let mut b = self.meta.forward(
                    match self.tag {
                        Tag::Keep => input.rewrite(&self.rewrite),
                        Tag::Untagged => input.rewrite(&self.rewrite).set_vlan(None),
                        Tag::Vlan(v) => input.rewrite(&self.rewrite).set_vlan(Some(v)),
                    },
                    peer,
                    ReasonCode::LinkHandOff,
                    format!("leave on {} to {peer}{facts}", self.interface),
                    ctx.clone(),
                    state,
                );
                b.delay = b.delay.add(&self.link_delay());
                b.spans = l.provenance.clone();
                if let Some(f) = &l.facts {
                    b.spans.extend(f.spans());
                }
                b
            }
            None => match self.exit {
                Some(mark) => {
                    let at = ExitPoint {
                        device: self.meta.device.clone(),
                        interface: self.interface.clone(),
                    };
                    let detail = format!("exit at {at} · {}", mark.text());
                    self.meta.branch(
                        input.clone(),
                        Outcome::Exit(at),
                        Reason::new(ReasonCode::Exited, detail),
                        ctx.clone(),
                        state,
                    )
                }
                None => self.meta.unknown(
                    input.clone(),
                    ReasonCode::NoLink,
                    format!("no link · interface {}", self.interface),
                    ctx,
                    state,
                ),
            },
        }
    }
}

impl NetFunction for Egress {
    meta_methods!(FunctionKind::Egress);

    fn requires(&self) -> Vec<ContextAttr> {
        match self.mode {
            EgressMode::Routed => vec![ContextAttr::NeighbourTarget],
            EgressMode::Transparent => Vec::new(),
        }
    }
    fn provides(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn reads(&self) -> Vec<Dependency> {
        vec![Dependency::Interface(
            self.meta.device.clone(),
            self.interface.clone(),
        )]
    }
    fn successors(&self) -> Vec<FunctionId> {
        self.link.iter().filter_map(|l| l.peer.clone()).collect()
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        match self.mode {
            EgressMode::Transparent => vec![self.to_link(input, ctx, state)],
            EgressMode::Routed => match &ctx.neighbour {
                Attr::Known(NeighbourTarget::Endpoint(e)) => {
                    let mut b = self.meta.branch(
                        input.clone(),
                        Outcome::Deliver(Destination::Endpoint(e.clone())),
                        Reason::new(
                            ReasonCode::Delivered,
                            format!("deliver to {e} on {}", self.interface),
                        ),
                        ctx.clone(),
                        state,
                    );
                    b.delay = b.delay.add(&self.link_delay());
                    vec![b]
                }
                Attr::Known(NeighbourTarget::Link) => vec![self.to_link(input, ctx, state)],
                _ => vec![self.meta.unknown(
                    input.clone(),
                    ReasonCode::UnknownAttribute,
                    "the neighbour is not known",
                    ctx,
                    state,
                )],
            },
        }
    }
}

/// Packets to an address of the device itself, before the input policy.
/// It sets the destination zone to the zone of the device, if it has one.
#[derive(Clone, Debug)]
pub struct LocalInput {
    pub meta: Meta,
    pub zone: Option<ZoneId>,
    pub next: FunctionId,
}

impl NetFunction for LocalInput {
    meta_methods!(FunctionKind::ZoneLookup);

    fn requires(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::DstZone]
    }
    fn reads(&self) -> Vec<Dependency> {
        Vec::new()
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let mut c = ctx.clone();
        let detail = match &self.zone {
            Some(z) => {
                c.dst_zone = Attr::Known(z.clone());
                format!("to the device · zone {z}")
            }
            None => "to the device".to_string(),
        };
        vec![self.meta.forward(
            input.clone(),
            &self.next,
            ReasonCode::Classified,
            detail,
            c,
            state,
        )]
    }
}

/// Delivers the packets to the device itself.
#[derive(Clone, Debug)]
pub struct DeviceDelivery {
    pub meta: Meta,
}

impl NetFunction for DeviceDelivery {
    meta_methods!(FunctionKind::Egress);

    fn requires(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn provides(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn reads(&self) -> Vec<Dependency> {
        Vec::new()
    }
    fn successors(&self) -> Vec<FunctionId> {
        Vec::new()
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        vec![self.meta.branch(
            input.clone(),
            Outcome::Deliver(Destination::Device(self.meta.device.clone())),
            Reason::new(ReasonCode::Delivered, format!("to {}", self.meta.device)),
            ctx.clone(),
            state,
        )]
    }
}
