//! The overlay of an SD-WAN: the selection of the tunnels to a far end, and
//! the VCMP encapsulation and decapsulation.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{
    Alternative, AlternativeKind, Attr, Branch, Context, ContextAttr, Dependency, Destination,
    Encap, FieldValue, FlowState, Fragment, FunctionId, FunctionKind, Header, HeaderField,
    InterfaceId, NetFunction, NextHop, ObjectId, Outcome, PROTO_UDP, PacketSet, Reason, ReasonCode,
    RulePredicate, SourceSpan, Tri, VrfId,
};

use crate::common::{Meta, push_nonempty};
use crate::forwarding::meta_methods;
use crate::rules::{Decision, Rule, RuleBody, RuleRef, UnknownCause, evaluate};

/// The UDP port of VCMP.
pub const VCMP_PORT: u16 = 2426;

/// The identity methods of a VCMP tunnel end. A tunnel end writes the
/// marking: the outer header has its own DSCP and ECN.
macro_rules! vcmp_methods {
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
        fn provenance(&self) -> &[SourceSpan] {
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

/// The object of the overlay of a device.
fn overlay_object(meta: &Meta) -> Dependency {
    Dependency::Object(ObjectId::new(format!("{}/sdwan", meta.device)))
}

/// The collected state of a tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TunnelState {
    Up,
    Down,
    NotCollected,
}

/// One tunnel to a far end: a pair of WAN links.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayTunnel {
    /// The local WAN link.
    pub link: String,
    /// The WAN link of the far end.
    pub far_link: String,
    pub state: TunnelState,
    /// The encapsulation of the tunnel.
    pub next: FunctionId,
    pub spans: Vec<SourceSpan>,
}

impl OverlayTunnel {
    /// The 2 links of the tunnel.
    pub fn label(&self) -> String {
        format!("{}~{}", self.link, self.far_link)
    }
}

/// Selects the tunnels that carry the packets to one far end of the
/// overlay. The device sends a flow on one or more of the tunnels that are
/// up, and the selection is not collected, so each such tunnel is a
/// candidate. A steering rule keeps only the tunnels of its local links.
#[derive(Clone, Debug)]
pub struct OverlaySelect {
    pub meta: Meta,
    /// The far edge or gateway of the tunnels.
    pub far: String,
    pub tunnels: Vec<OverlayTunnel>,
    /// The rules that pin their packets to local links, in rule order. The
    /// action of a rule is the set of the links. The packets of a rule
    /// with no tunnel up on its links are dropped.
    pub steering: Vec<Rule<BTreeSet<String>>>,
}

impl OverlaySelect {
    /// The branches of the packets `set`, which the steering rule `rule`
    /// pins to `links`. With no rule, `links` is empty and each tunnel is
    /// kept.
    fn select(
        &self,
        set: PacketSet,
        links: &BTreeSet<String>,
        rule: Option<&str>,
        ctx: &Context,
        state: &FlowState,
        out: &mut Vec<Branch>,
    ) {
        let kept: Vec<&OverlayTunnel> = self
            .tunnels
            .iter()
            .filter(|t| rule.is_none() || links.contains(&t.link))
            .collect();
        let by = match rule {
            Some(r) => format!("steering rule {r}"),
            None => "no steering rule".to_string(),
        };
        if kept.iter().any(|t| t.state == TunnelState::NotCollected) {
            out.push(self.meta.unknown(
                set,
                ReasonCode::NotCollected,
                format!("tunnel state to {} not collected", self.far),
                ctx,
                state,
            ));
            return;
        }
        let up: Vec<&OverlayTunnel> = kept
            .into_iter()
            .filter(|t| t.state == TunnelState::Up)
            .collect();
        match up.as_slice() {
            [] if rule.is_some() => out.push(self.meta.drop(
                set,
                ReasonCode::NoNeighbour,
                format!("no tunnel to {} is up on the links of {by}", self.far),
                ctx,
                state,
            )),
            [] => out.push(self.meta.unknown(
                set,
                ReasonCode::IncompleteTable,
                format!("no tunnel to {} is up", self.far),
                ctx,
                state,
            )),
            [t] => out.push(
                self.meta
                    .forward(
                        set,
                        &t.next,
                        ReasonCode::Routed,
                        format!("tunnel {} to {}, {by}", t.label(), self.far),
                        ctx.clone(),
                        state,
                    )
                    .with_spans(t.spans.clone()),
            ),
            many => {
                let count = u32::try_from(many.len()).expect("too many tunnels");
                for (i, t) in many.iter().enumerate() {
                    out.push(
                        self.meta
                            .forward(
                                set.clone(),
                                &t.next,
                                ReasonCode::Routed,
                                format!("tunnel {} to {}, {by}", t.label(), self.far),
                                ctx.clone(),
                                state,
                            )
                            .with_spans(t.spans.clone())
                            .with_alternative(Alternative {
                                kind: AlternativeKind::Candidate,
                                choice: self.meta.id.clone(),
                                key: format!("{}, {by}", self.far),
                                index: u32::try_from(i).expect("too many tunnels"),
                                count,
                                label: t.label(),
                            })
                            .with_assumption(format!(
                                "{} sends the flow on one or more of its {count} tunnels to {}",
                                self.meta.device, self.far
                            )),
                    );
                }
            }
        }
    }
}

impl NetFunction for OverlaySelect {
    meta_methods!(FunctionKind::TunnelSelection);

    fn each_span(&self, f: &mut dyn FnMut(&SourceSpan)) {
        for s in &self.meta.provenance {
            f(s);
        }
        for s in self.tunnels.iter().flat_map(|t| &t.spans) {
            f(s);
        }
        for s in self.steering.iter().flat_map(|r| &r.spans) {
            f(s);
        }
    }

    fn requires(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn provides(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn reads(&self) -> Vec<Dependency> {
        vec![overlay_object(&self.meta)]
    }
    fn predicates(&self) -> Vec<&RulePredicate> {
        self.steering
            .iter()
            .filter_map(|r| match &r.body {
                RuleBody::Handled { predicate, .. } => Some(predicate),
                RuleBody::Unhandled => None,
            })
            .collect()
    }
    fn successors(&self) -> Vec<FunctionId> {
        let mut v: Vec<FunctionId> = self.tunnels.iter().map(|t| t.next.clone()).collect();
        v.sort();
        v.dedup();
        v
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let each = BTreeSet::new();
        let mut out = Vec::new();
        for (set, decision) in evaluate(&self.steering, &each, input, &|_| Tri::True) {
            match decision {
                Decision::Action { action, decided_by } => {
                    let rule = match decided_by.first() {
                        Some(RuleRef::Rule(i)) => Some(self.steering[*i].name.as_str()),
                        _ => None,
                    };
                    self.select(set, &action, rule, ctx, state, &mut out);
                }
                Decision::Unknown { cause } => {
                    let (code, detail) = match cause {
                        UnknownCause::Unhandled { rule } => (
                            ReasonCode::UnhandledStanza,
                            format!("steering rule {} not handled", self.steering[rule].name),
                        ),
                        UnknownCause::Uncertain { rule } => (
                            ReasonCode::MatchUnknown,
                            format!(
                                "steering rule {}, match not known",
                                self.steering[rule].name
                            ),
                        ),
                    };
                    out.push(self.meta.unknown(set, code, detail, ctx, state));
                }
            }
        }
        out
    }
}

/// Puts the packets of a segment into the VCMP tunnel of one pair of WAN
/// links. The encapsulated packets leave on the WAN interface of the local
/// link, in the VRF of the underlay.
#[derive(Clone, Debug)]
pub struct VcmpEncap {
    pub meta: Meta,
    /// The address of the local WAN link.
    pub source: IpAddr,
    /// The address of the WAN link of the far end.
    pub peer: IpAddr,
    /// The segment of each VRF.
    pub segments: BTreeMap<VrfId, u32>,
    /// The UDP source port of the outer header.
    pub src_port: FieldValue<u16>,
    pub dscp: FieldValue<u8>,
    pub ecn: FieldValue<u8>,
    /// The VRF of the underlay.
    pub underlay: VrfId,
    /// The WAN interface of the local link.
    pub interface: InterfaceId,
    /// The next hop of the outer packets on the WAN interface.
    pub gateway: NextHop,
    /// The next-hop resolution of the underlay.
    pub next: FunctionId,
}

impl VcmpEncap {
    /// The outer header of the segment `segment`. The MAC addresses are
    /// unknown until the next-hop resolution of the underlay; the outer
    /// header has no 802.1Q tag.
    fn outer(&self, segment: u32) -> Header {
        let mut h = Header::request(self.source, self.peer, PROTO_UDP).with_dst_port(VCMP_PORT);
        h.src_port = self.src_port;
        h.dscp = self.dscp;
        h.ecn = self.ecn;
        h.fragment = FieldValue::Known(Fragment::Unfragmented);
        h.src_mac = FieldValue::Unknown;
        h.dst_mac = FieldValue::Unknown;
        h = h.untagged();
        h.encap = vec![Encap::Vcmp {
            src: self.source,
            dst: self.peer,
            segment,
        }];
        h
    }
}

impl NetFunction for VcmpEncap {
    vcmp_methods!(FunctionKind::Encapsulation);
    fn requires(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::Vrf]
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![
            ContextAttr::Device,
            ContextAttr::Vrf,
            ContextAttr::EgressInterface,
            ContextAttr::NextHop,
        ]
    }
    fn reads(&self) -> Vec<Dependency> {
        vec![overlay_object(&self.meta)]
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let Some(vrf) = ctx.vrf.known() else {
            return vec![self.meta.unknown(
                input.clone(),
                ReasonCode::UnknownAttribute,
                "segment not known",
                ctx,
                state,
            )];
        };
        let Some(&segment) = self.segments.get(vrf) else {
            return vec![self.meta.unknown(
                input.clone(),
                ReasonCode::IncompleteTable,
                format!("no segment of VRF {vrf}"),
                ctx,
                state,
            )];
        };
        if self.peer.is_ipv6() != self.source.is_ipv6() {
            return vec![self.meta.unknown(
                input.clone(),
                ReasonCode::IncompleteTable,
                format!(
                    "peer {} and source {} in different address families",
                    self.peer, self.source
                ),
                ctx,
                state,
            )];
        }
        let e = input.encapsulate(&self.outer(segment));
        let mut c = ctx.clone();
        c.device = Attr::Known(self.meta.device.clone());
        c.vrf = Attr::Known(self.underlay.clone());
        c.egress_interface = Attr::Known(self.interface.clone());
        c.next_hop = Attr::Known(self.gateway);
        c.neighbour = Attr::Unset;
        let mut out = Vec::new();
        push_nonempty(
            &mut out,
            self.meta.forward(
                e.done,
                &self.next,
                ReasonCode::Encapsulated,
                format!(
                    "VCMP segment {segment} from {} to {} on {}",
                    self.source, self.peer, self.interface
                ),
                c,
                state,
            ),
        );
        push_nonempty(
            &mut out,
            self.meta.unknown(
                e.nested,
                ReasonCode::Nested,
                "packets already encapsulated",
                ctx,
                state,
            ),
        );
        out
    }
}

/// Takes the VCMP packets to a WAN link of the device out of the tunnel.
/// The segment selects the VRF. Packets with no VCMP encapsulation are for
/// the device itself.
#[derive(Clone, Debug)]
pub struct VcmpDecap {
    pub meta: Meta,
    /// The VRF and the next function of each segment.
    pub segments: BTreeMap<u32, (VrfId, FunctionId)>,
    /// The function that gets the packets with no VCMP encapsulation.
    /// `None` delivers them to the device.
    pub plain: Option<FunctionId>,
}

impl NetFunction for VcmpDecap {
    vcmp_methods!(FunctionKind::Decapsulation);
    fn requires(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn provides(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn reads(&self) -> Vec<Dependency> {
        vec![overlay_object(&self.meta)]
    }
    fn successors(&self) -> Vec<FunctionId> {
        let mut v: Vec<FunctionId> = self
            .segments
            .values()
            .map(|(_, n)| n.clone())
            .chain(self.plain.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let vcmp = input.vcmp();
        let plain = input.difference(&vcmp);
        let mut out = Vec::new();
        let mut rest = vcmp;
        for (&segment, (vrf, next)) in &self.segments {
            let part = rest.vcmp_segment(segment);
            if part.is_empty() {
                continue;
            }
            rest = rest.difference(&part);
            let mut c = ctx.clone();
            c.vrf = Attr::Known(vrf.clone());
            c.egress_interface = Attr::Unset;
            c.next_hop = Attr::Unset;
            c.neighbour = Attr::Unset;
            out.push(self.meta.forward(
                part.decapsulate().done,
                next,
                ReasonCode::Decapsulated,
                format!("VCMP segment {segment}, VRF {vrf}"),
                c,
                state,
            ));
        }
        push_nonempty(
            &mut out,
            self.meta.drop(
                rest,
                ReasonCode::NoSegment,
                format!("no segment of the packets on {}", self.meta.device),
                ctx,
                state,
            ),
        );
        let other = match &self.plain {
            Some(next) => self.meta.forward(
                plain,
                next,
                ReasonCode::Passed,
                "no VCMP encapsulation",
                ctx.clone(),
                state,
            ),
            None => self.meta.branch(
                plain,
                Outcome::Deliver(Destination::Device(self.meta.device.clone())),
                Reason::new(ReasonCode::Delivered, format!("to {}", self.meta.device)),
                ctx.clone(),
                state,
            ),
        };
        push_nonempty(&mut out, other);
        out
    }
}
