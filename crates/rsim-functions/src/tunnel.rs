//! VXLAN encapsulation and decapsulation, and the WireGuard encapsulation.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{
    AddrField, Attr, Branch, BridgeDomainId, Context, ContextAttr, Dependency, Destination, Encap,
    FieldValue, FlowState, Fragment, FunctionId, FunctionKind, Header, HeaderField, InterfaceId,
    NetFunction, NextHop, Outcome, PROTO_UDP, PacketSet, PortId, Prefix, PrefixTable, Reason,
    ReasonCode, SessionMatch, SourceSpan, TriePrefixTable, VrfId, ZoneId,
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
    /// What happens to the packets of a VNI that is not in `vnis`.
    pub unmatched: Unmatched,
}

/// What a decapsulation does with the packets of a VNI that it does not
/// have.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unmatched {
    Drop,
    /// The packets are `Unknown` with this reason.
    Unknown(String),
    /// The packets go on, still encapsulated, to this function, for
    /// example a decapsulation of the VNIs of another kind.
    Next(FunctionId),
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
            .chain(match &self.unmatched {
                Unmatched::Next(n) => Some(n.clone()),
                _ => None,
            })
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
            Unmatched::Drop => self.meta.drop(
                rest,
                ReasonCode::NoSegment,
                format!("no VNI of the packets on {}", self.meta.device),
                ctx,
                state,
            ),
            Unmatched::Unknown(why) => {
                self.meta
                    .unknown(rest, ReasonCode::UnhandledStanza, why.clone(), ctx, state)
            }
            Unmatched::Next(next) => self.meta.forward(
                rest,
                next,
                ReasonCode::Passed,
                "another VNI",
                ctx.clone(),
                state,
            ),
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

/// A peer of a WireGuard interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireguardPeer {
    pub name: String,
    /// The allowed IPs of the peer.
    pub allowed: Vec<Prefix>,
    /// The address and the UDP port of the endpoint of the peer. `None` for
    /// a peer whose endpoint the device learns at run time.
    pub endpoint: Option<(IpAddr, u16)>,
    /// The source address of the outer header toward the endpoint, or the
    /// reason why it is not known.
    pub source: Result<IpAddr, String>,
    /// The interface whose address is the source.
    pub source_interface: Option<InterfaceId>,
    pub spans: Vec<SourceSpan>,
}

/// Puts the packets that a device routes to a WireGuard interface into the
/// tunnel to one peer. The peer is the peer with the longest allowed IP
/// that contains the destination. When more than one peer has that allowed
/// IP, the device gives it to one of them by an order that is not
/// collected, so its packets are unknown. A destination that no allowed IP
/// contains is dropped. The encapsulated packets are packets of
/// the device itself: they continue at the route lookup of the underlay
/// with the source zone of the device, and the inner header stays as the
/// inner level.
#[derive(Clone, Debug)]
pub struct WireguardEncap {
    pub meta: Meta,
    pub interface: InterfaceId,
    peers: Vec<WireguardPeer>,
    /// The peers of each allowed IP, by their index in `peers`.
    allowed: TriePrefixTable<Vec<usize>>,
    /// The UDP source port of the outer header: the listen port of the
    /// interface. `None` if the device picks it at run time.
    pub listen_port: Option<u16>,
    /// A reason that makes each encapsulated packet `Unknown`, for example
    /// a filter of the packets of the device itself that is not lowered.
    pub unknown: Option<String>,
    /// The source zone of the packets of the device itself.
    pub src_zone: Attr<ZoneId>,
    /// The VRF of the underlay.
    pub underlay: VrfId,
    /// The route lookup of the underlay.
    pub next: FunctionId,
}

/// The settings of a WireGuard encapsulation other than its peers.
#[derive(Clone, Debug)]
pub struct WireguardSettings {
    pub listen_port: Option<u16>,
    pub unknown: Option<String>,
    pub src_zone: Attr<ZoneId>,
    pub underlay: VrfId,
    pub next: FunctionId,
}

impl WireguardEncap {
    pub fn new(
        meta: Meta,
        interface: InterfaceId,
        peers: Vec<WireguardPeer>,
        s: WireguardSettings,
    ) -> Self {
        let mut by_prefix: BTreeMap<Prefix, Vec<usize>> = BTreeMap::new();
        for (i, p) in peers.iter().enumerate() {
            for a in &p.allowed {
                let v = by_prefix.entry(*a).or_default();
                if !v.contains(&i) {
                    v.push(i);
                }
            }
        }
        let mut allowed = TriePrefixTable::new();
        for (a, v) in by_prefix {
            allowed.insert(a, v);
        }
        WireguardEncap {
            meta,
            interface,
            peers,
            allowed,
            listen_port: s.listen_port,
            unknown: s.unknown,
            src_zone: s.src_zone,
            underlay: s.underlay,
            next: s.next,
        }
    }

    pub fn peers(&self) -> &[WireguardPeer] {
        &self.peers
    }

    fn outer(&self, src: IpAddr, dst: IpAddr, port: u16) -> Header {
        let mut h = Header::request(src, dst, PROTO_UDP).with_dst_port(port);
        h.src_port = self
            .listen_port
            .map_or(FieldValue::Unknown, FieldValue::Known);
        // The outer header has DSCP 0. The device copies the ECN of each
        // inner packet, so the ECN of the outer header is unknown here.
        h.dscp = FieldValue::Known(0);
        h.ecn = FieldValue::Unknown;
        h.fragment = FieldValue::Known(Fragment::Unfragmented);
        h.src_mac = FieldValue::Unknown;
        h.dst_mac = FieldValue::Unknown;
        h.vlan = FieldValue::Absent;
        h.l2_priority = FieldValue::Absent;
        h.encap = vec![Encap::Wireguard { src, dst }];
        h
    }

    fn to_peer(
        &self,
        out: &mut Vec<Branch>,
        peer: &WireguardPeer,
        set: PacketSet,
        ctx: &Context,
        state: &FlowState,
    ) {
        let unknown = |out: &mut Vec<Branch>, set: PacketSet, code: ReasonCode, why: String| {
            let mut b = self.meta.unknown(set, code, why, ctx, state);
            b.spans = peer.spans.clone();
            push_nonempty(out, b);
        };
        let Some((dst, port)) = peer.endpoint else {
            unknown(
                out,
                set,
                ReasonCode::IncompleteTable,
                format!("WireGuard peer endpoint not known · peer {}", peer.name),
            );
            return;
        };
        let src = match &peer.source {
            Ok(s) if s.is_ipv6() == dst.is_ipv6() => *s,
            Ok(s) => {
                let why = format!(
                    "the source {s} and the endpoint {dst} have different address families"
                );
                unknown(out, set, ReasonCode::IncompleteTable, why);
                return;
            }
            Err(why) => {
                unknown(out, set, ReasonCode::IncompleteTable, why.clone());
                return;
            }
        };
        let e = set.encapsulate(&self.outer(src, dst, port));
        let detail = format!(
            "WireGuard {} peer {} from {src} to {dst} port {port}",
            self.interface, peer.name
        );
        match &self.unknown {
            Some(why) => unknown(
                out,
                e.done,
                ReasonCode::UnhandledStanza,
                format!("{detail} · {why}"),
            ),
            None => {
                let mut c = ctx.clone();
                c.device = Attr::Known(self.meta.device.clone());
                c.ingress_interface = Attr::Unset;
                c.vrf = Attr::Known(self.underlay.clone());
                c.src_zone = self.src_zone.clone();
                c.dst_zone = Attr::Unset;
                // The outer flow is new or established: its state depends on
                // which end started it, which is not collected.
                c.session = Attr::Known(SessionMatch::Untracked {
                    entry: e.done.clone(),
                });
                c.egress_interface = Attr::Unset;
                c.next_hop = Attr::Unset;
                c.neighbour = Attr::Unset;
                c.ingress_port = Attr::Unset;
                c.bridge_domain = Attr::Unset;
                let mut b = self.meta.forward(
                    e.done,
                    &self.next,
                    ReasonCode::Encapsulated,
                    detail,
                    c,
                    state,
                );
                b.spans = peer.spans.clone();
                push_nonempty(out, b);
            }
        }
        push_nonempty(
            out,
            self.meta.unknown(
                e.nested,
                ReasonCode::Nested,
                "the packets have an encapsulation already",
                ctx,
                state,
            ),
        );
    }
}

impl NetFunction for WireguardEncap {
    tunnel_methods!(FunctionKind::Encapsulation);
    fn requires(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![
            ContextAttr::Device,
            ContextAttr::Vrf,
            ContextAttr::SrcZone,
            ContextAttr::Session,
        ]
    }
    fn reads(&self) -> Vec<Dependency> {
        let dev = &self.meta.device;
        let mut ifaces: Vec<&InterfaceId> = std::iter::once(&self.interface)
            .chain(
                self.peers
                    .iter()
                    .filter_map(|p| p.source_interface.as_ref()),
            )
            .collect();
        ifaces.sort();
        ifaces.dedup();
        ifaces
            .into_iter()
            .map(|i| Dependency::Interface(dev.clone(), i.clone()))
            .chain([Dependency::RouteTable(dev.clone(), self.underlay.clone())])
            .collect()
    }
    fn each_span(&self, f: &mut dyn FnMut(&SourceSpan)) {
        for s in self
            .meta
            .provenance
            .iter()
            .chain(self.peers.iter().flat_map(|p| p.spans.iter()))
        {
            f(s);
        }
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let part = input.partition_by_prefix(AddrField::Dst, &self.allowed);
        let mut by_peer: BTreeMap<usize, PacketSet> = BTreeMap::new();
        let mut out = Vec::new();
        for (prefix, owners, set) in part.matched {
            let [i] = owners[..] else {
                let mut b = self.meta.unknown(
                    set,
                    ReasonCode::AmbiguousOwner,
                    format!("more than one WireGuard peer allows {prefix}"),
                    ctx,
                    state,
                );
                b.spans = owners
                    .iter()
                    .flat_map(|&i| self.peers[i].spans.iter().cloned())
                    .collect();
                push_nonempty(&mut out, b);
                continue;
            };
            let s = match by_peer.remove(&i) {
                Some(s) => s.union(&set),
                None => set,
            };
            by_peer.insert(i, s);
        }
        for (i, set) in by_peer {
            self.to_peer(&mut out, &self.peers[i], set, ctx, state);
        }
        push_nonempty(
            &mut out,
            self.meta.drop(
                part.unmatched,
                ReasonCode::NoRoute,
                format!(
                    "no WireGuard peer of {} allows the destination",
                    self.interface
                ),
                ctx,
                state,
            ),
        );
        push_nonempty(
            &mut out,
            self.meta.unknown(
                part.uncertain,
                ReasonCode::UnknownAttribute,
                "the destination address is not known",
                ctx,
                state,
            ),
        );
        out
    }
}
