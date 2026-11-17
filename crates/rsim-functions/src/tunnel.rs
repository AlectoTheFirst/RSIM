//! VXLAN encapsulation and decapsulation.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{
    Attr, Branch, BridgeDomainId, Context, ContextAttr, Dependency, Destination, Encap, FieldValue,
    FlowState, Fragment, FunctionId, FunctionKind, Header, HeaderField, NetFunction, NextHop,
    Outcome, PROTO_UDP, PacketSet, PortId, Reason, ReasonCode, VrfId,
};

use crate::common::{Meta, push_nonempty};

/// The identity methods of a tunnel function. A tunnel end writes the
/// marking: the outer header has its own DSCP and ECN.
macro_rules! tunnel_methods {
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
        fn qos_reads(&self) -> Vec<HeaderField> {
            Vec::new()
        }
        fn qos_writes(&self) -> Vec<HeaderField> {
            vec![HeaderField::Dscp, HeaderField::Ecn]
        }
    };
}

/// The segment of a VNI on a device: a VRF for a layer 3 VNI, a bridge
/// domain for a layer 2 VNI.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Segment {
    Vrf(VrfId),
    BridgeDomain(BridgeDomainId),
}

impl std::fmt::Display for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Segment::Vrf(v) => write!(f, "VRF {v}"),
            Segment::BridgeDomain(b) => write!(f, "bridge domain {b}"),
        }
    }
}

/// Where the encapsulation finds the remote tunnel end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelPeer {
    /// The gateway of the next hop that the route lookup selected.
    NextHop,
    /// One fixed peer, for example the tunnel end of a MAC table row.
    Fixed(IpAddr),
}

/// The fields of the outer header that the device sets. Each value is
/// stated; a value that the device calculates for each packet is unknown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OuterFields {
    /// The UDP destination port of the tunnel.
    pub udp_port: u16,
    /// The UDP source port. The device usually calculates it from the inner
    /// header for each packet.
    pub src_port: FieldValue<u16>,
    pub dscp: FieldValue<u8>,
    pub ecn: FieldValue<u8>,
}

impl OuterFields {
    /// The outer header from `src` to `dst` with the network identifier
    /// `vni`. The MAC addresses are unknown until the next-hop resolution of
    /// the underlay; the outer header has no 802.1Q tag.
    pub fn header(&self, src: IpAddr, dst: IpAddr, vni: u32) -> Header {
        let mut h = Header::request(src, dst, PROTO_UDP).with_dst_port(self.udp_port);
        h.src_port = self.src_port;
        h.dscp = self.dscp;
        h.ecn = self.ecn;
        h.fragment = FieldValue::Known(Fragment::Unfragmented);
        h.src_mac = FieldValue::Unknown;
        h.dst_mac = FieldValue::Unknown;
        h.vlan = FieldValue::Absent;
        h.l2_priority = FieldValue::Absent;
        h.encap = vec![Encap::Vxlan { src, dst, vni }];
        h
    }
}

/// Puts the packets of a segment into a VXLAN tunnel to a peer tunnel end.
/// The encapsulated packets continue in the VRF of the underlay.
#[derive(Clone, Debug)]
pub struct VxlanEncap {
    pub meta: Meta,
    /// The local tunnel end.
    pub source: IpAddr,
    pub peer: TunnelPeer,
    /// The VNI of each segment.
    pub vnis: BTreeMap<Segment, u32>,
    pub outer: OuterFields,
    /// The VRF of the underlay.
    pub underlay: VrfId,
    /// The route lookup of the underlay.
    pub next: FunctionId,
}

impl VxlanEncap {
    fn segment(&self, ctx: &Context) -> Option<Segment> {
        if self
            .vnis
            .keys()
            .any(|s| matches!(s, Segment::BridgeDomain(_)))
            && let Some(b) = ctx.bridge_domain.known()
        {
            return Some(Segment::BridgeDomain(b.clone()));
        }
        ctx.vrf.known().map(|v| Segment::Vrf(v.clone()))
    }
}

impl NetFunction for VxlanEncap {
    tunnel_methods!(FunctionKind::Encapsulation);
    fn requires(&self) -> Vec<ContextAttr> {
        let mut v = Vec::new();
        if !self.vnis.is_empty() && self.vnis.keys().all(|s| matches!(s, Segment::Vrf(_))) {
            v.push(ContextAttr::Vrf);
        }
        if self.peer == TunnelPeer::NextHop {
            v.push(ContextAttr::NextHop);
        }
        v
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::Device, ContextAttr::Vrf]
    }
    fn reads(&self) -> Vec<Dependency> {
        vec![Dependency::Object(rsim_core::ObjectId::new(format!(
            "{}/vxlan",
            self.meta.device
        )))]
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let peer = match (&self.peer, &ctx.next_hop) {
            (TunnelPeer::Fixed(p), _) => *p,
            (TunnelPeer::NextHop, Attr::Known(NextHop::Gateway(g))) => *g,
            (TunnelPeer::NextHop, _) => {
                return vec![self.meta.unknown(
                    input.clone(),
                    ReasonCode::UnknownAttribute,
                    "the peer tunnel end is not known",
                    ctx,
                    state,
                )];
            }
        };
        let Some(segment) = self.segment(ctx) else {
            return vec![self.meta.unknown(
                input.clone(),
                ReasonCode::UnknownAttribute,
                "the segment of the packets is not known",
                ctx,
                state,
            )];
        };
        let Some(&vni) = self.vnis.get(&segment) else {
            return vec![self.meta.unknown(
                input.clone(),
                ReasonCode::IncompleteTable,
                format!("no VNI · {segment}"),
                ctx,
                state,
            )];
        };
        if peer.is_ipv6() != self.source.is_ipv6() {
            return vec![self.meta.unknown(
                input.clone(),
                ReasonCode::IncompleteTable,
                format!(
                    "the peer {peer} and the source {} have different address families",
                    self.source
                ),
                ctx,
                state,
            )];
        }
        let e = input.encapsulate(&self.outer.header(self.source, peer, vni));
        let mut c = ctx.clone();
        c.device = Attr::Known(self.meta.device.clone());
        c.vrf = Attr::Known(self.underlay.clone());
        c.egress_interface = Attr::Unset;
        c.next_hop = Attr::Unset;
        c.neighbour = Attr::Unset;
        let mut out = Vec::new();
        push_nonempty(
            &mut out,
            self.meta.forward(
                e.done,
                &self.next,
                ReasonCode::Encapsulated,
                format!("VXLAN VNI {vni} from {} to {peer} · {segment}", self.source),
                c,
                state,
            ),
        );
        push_nonempty(
            &mut out,
            self.meta.unknown(
                e.nested,
                ReasonCode::Nested,
                "the packets have an encapsulation already",
                ctx,
                state,
            ),
        );
        out
    }
}

/// Takes the VXLAN packets to a local tunnel end out of the tunnel. The VNI
/// selects the segment. Packets with no encapsulation are for the device
/// itself.
#[derive(Clone, Debug)]
pub struct VxlanDecap {
    pub meta: Meta,
    /// The segment and the next function of each VNI.
    pub vnis: BTreeMap<u32, (Segment, FunctionId)>,
    /// The function that gets the packets with no encapsulation. `None`
    /// delivers them to the device.
    pub plain: Option<FunctionId>,
    /// The port of the tunnel in a bridge domain. A frame out of the tunnel
    /// comes in on it.
    pub port: Option<PortId>,
    /// The result of a VNI that is not in `vnis`: `None` drops the packets,
    /// and a text gives `Unknown` with that reason.
    pub unmatched: Option<String>,
}

impl NetFunction for VxlanDecap {
    tunnel_methods!(FunctionKind::Decapsulation);
    fn requires(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn provides(&self) -> Vec<ContextAttr> {
        let mut v: Vec<ContextAttr> = self
            .vnis
            .values()
            .map(|(s, _)| match s {
                Segment::Vrf(_) => ContextAttr::Vrf,
                Segment::BridgeDomain(_) => ContextAttr::BridgeDomain,
            })
            .collect();
        v.sort();
        v.dedup();
        // Each branch sets one of them, so only an attribute that each
        // branch sets is provided.
        if v.len() > 1 { Vec::new() } else { v }
    }
    fn reads(&self) -> Vec<Dependency> {
        vec![Dependency::Object(rsim_core::ObjectId::new(format!(
            "{}/vxlan",
            self.meta.device
        )))]
    }
    fn successors(&self) -> Vec<FunctionId> {
        let mut v: Vec<FunctionId> = self
            .vnis
            .values()
            .map(|(_, n)| n.clone())
            .chain(self.plain.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let d = input.decapsulate();
        let encapsulated = input.difference(&d.plain);
        let mut out = Vec::new();
        let mut rest = encapsulated;
        for (&vni, (segment, next)) in &self.vnis {
            let part = rest.vxlan_vni(vni);
            if part.is_empty() {
                continue;
            }
            rest = rest.difference(&part);
            let mut c = ctx.clone();
            match segment {
                Segment::Vrf(v) => c.vrf = Attr::Known(v.clone()),
                Segment::BridgeDomain(b) => {
                    c.bridge_domain = Attr::Known(b.clone());
                    if let Some(p) = &self.port {
                        c.ingress_port = Attr::Known(p.clone());
                    }
                }
            }
            c.egress_interface = Attr::Unset;
            c.next_hop = Attr::Unset;
            c.neighbour = Attr::Unset;
            out.push(self.meta.forward(
                part.decapsulate().done,
                next,
                ReasonCode::Decapsulated,
                format!("VXLAN VNI {vni} · {segment}"),
                c,
                state,
            ));
        }
        let other = match &self.unmatched {
            None => self.meta.drop(
                rest,
                ReasonCode::NoSegment,
                format!("no VNI of the packets on {}", self.meta.device),
                ctx,
                state,
            ),
            Some(why) => {
                self.meta
                    .unknown(rest, ReasonCode::UnhandledStanza, why.clone(), ctx, state)
            }
        };
        push_nonempty(&mut out, other);
        let plain = match &self.plain {
            Some(next) => self.meta.forward(
                d.plain,
                next,
                ReasonCode::Passed,
                "no encapsulation",
                ctx.clone(),
                state,
            ),
            None => self.meta.branch(
                d.plain,
                Outcome::Deliver(Destination::Device(self.meta.device.clone())),
                Reason::new(ReasonCode::Delivered, format!("to {}", self.meta.device)),
                ctx.clone(),
                state,
            ),
        };
        push_nonempty(&mut out, plain);
        out
    }
}
