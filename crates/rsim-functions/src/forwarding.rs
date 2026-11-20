//! Ingress, VRF selection, zone lookup and egress.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{
    Attr, Branch, Context, ContextAttr, Delay, DelayGap, Dependency, Destination, ExitPoint,
    FlowState, FunctionId, FunctionKind, InterfaceId, NeighbourTarget, NetFunction, NextHop,
    Outcome, PacketSet, Reason, ReasonCode, Rewrite, SourceSpan, VrfId, ZoneId,
};

use crate::common::{Meta, push_nonempty};
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
    /// interface that is not an edge, and the packets of a default route
    /// edge with another next hop, are unknown.
    pub exit: Option<ExitMark>,
}

/// Why an interface with no link is an edge of the twin.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExitMark {
    /// An access link to a provider, for example PPPoE.
    AccessLink,
    /// The interface carries a default route to the next hops `gateways`,
    /// which are outside the twin. Only the packets whose next hop is one
    /// of them leave the twin.
    DefaultRoute { gateways: BTreeSet<IpAddr> },
    /// The owner marks the interface as an edge.
    Owner,
}

impl ExitMark {
    fn text(&self) -> &'static str {
        match self {
            ExitMark::AccessLink => "access link",
            ExitMark::DefaultRoute { .. } => "default route",
            ExitMark::Owner => "marked by the owner",
        }
    }

    /// Whether the packets with the next hop `next_hop` leave the twin.
    fn exits(&self, next_hop: &Attr<NextHop>) -> bool {
        match self {
            ExitMark::AccessLink | ExitMark::Owner => true,
            ExitMark::DefaultRoute { gateways } => {
                matches!(next_hop, Attr::Known(NextHop::Gateway(g)) if gateways.contains(g))
            }
        }
    }
}

/// What an egress does with the VLAN tags.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tag {
    /// The tags stay as they are.
    #[default]
    Keep,
    /// The frames leave without a tag.
    Untagged,
    /// The frames leave with this VLAN and no inner tag.
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
                        Tag::Vlan(v) => input
                            .rewrite(&self.rewrite)
                            .set_vlan(Some(v))
                            .clear_inner_vlan(),
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
            None => match &self.exit {
                Some(mark) if mark.exits(&ctx.next_hop) => {
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
                _ => self.meta.unknown(
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

    fn each_span(&self, f: &mut dyn FnMut(&rsim_core::SourceSpan)) {
        for s in &self.meta.provenance {
            f(s);
        }
        if let Some(l) = &self.link {
            for s in &l.provenance {
                f(s);
            }
            for s in l.facts.iter().flat_map(crate::layer2::LinkFacts::spans) {
                f(&s);
            }
        }
    }

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

/// Delivers the packets to the device itself. An encapsulated packet that
/// reaches it is unknown: the device has no decapsulation for it here, and
/// what the inner packet does after a decapsulation is not modelled.
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
        let plain = input.decapsulate().plain;
        let encapsulated = input.difference(&plain);
        let wireguard = encapsulated.wireguard();
        let other = encapsulated.difference(&wireguard);
        let dev = &self.meta.device;
        let mut out = Vec::new();
        push_nonempty(
            &mut out,
            self.meta.branch(
                plain,
                Outcome::Deliver(Destination::Device(dev.clone())),
                Reason::new(ReasonCode::Delivered, format!("to {dev}")),
                ctx.clone(),
                state,
            ),
        );
        for (set, what) in [(wireguard, "WireGuard"), (other, "encapsulated")] {
            push_nonempty(
                &mut out,
                self.meta.unknown(
                    set,
                    ReasonCode::UnhandledStanza,
                    format!("{what} packet reaches {dev}; decapsulation is not modelled"),
                    ctx,
                    state,
                ),
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use rsim_core::{Encap, FieldValue, Fragment, Header, PROTO_UDP, SetArena};

    use super::*;

    fn deliver() -> DeviceDelivery {
        DeviceDelivery {
            meta: Meta {
                id: FunctionId::new("r1/deliver"),
                device: rsim_core::DeviceId::new("r1"),
                provenance: Vec::new(),
                processing_delay_ns: None,
                profile: "test".to_string(),
            },
        }
    }

    #[test]
    fn an_encapsulated_packet_at_the_delivery_is_unknown() {
        let arena = SetArena::standalone();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let inner = PacketSet::single(
            &arena,
            &Header::request(ip("192.0.2.10"), ip("192.0.2.200"), PROTO_UDP).with_dst_port(53),
        );
        let src = ip("198.51.100.1");
        let dst = ip("198.51.100.2");
        let mut outer = Header::request(src, dst, PROTO_UDP)
            .with_src_port(51820)
            .with_dst_port(51820);
        outer.dscp = FieldValue::Known(0);
        outer.ecn = FieldValue::Unknown;
        outer.fragment = FieldValue::Known(Fragment::Unfragmented);
        outer.src_mac = FieldValue::Unknown;
        outer.dst_mac = FieldValue::Unknown;
        outer = outer.untagged();
        outer.encap = vec![Encap::Wireguard { src, dst }];
        let plain = PacketSet::single(
            &arena,
            &Header::request(ip("192.0.2.11"), dst, PROTO_UDP).with_dst_port(53),
        );
        let input = inner.encapsulate(&outer).done.union(&plain);
        let out = deliver().apply(&input, &Context::default(), &FlowState::default());
        assert_eq!(out.len(), 2, "{out:?}");
        assert_eq!(out[0].packets, plain);
        assert!(
            matches!(out[0].outcome, Outcome::Deliver(_)),
            "{:?}",
            out[0].outcome
        );
        assert_eq!(out[1].packets, input.difference(&plain));
        assert_eq!(out[1].outcome, Outcome::Unknown);
        assert_eq!(
            out[1].reason.detail,
            "WireGuard packet reaches r1; decapsulation is not modelled"
        );
    }
}
