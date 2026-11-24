//! A point-to-point circuit of a provider and the push and the pop of one
//! VLAN tag.

use rsim_core::bits::TPID_8021Q;
use rsim_core::{
    Attr, Branch, Context, ContextAttr, Delay, DelayGap, Dependency, FlowState, FunctionId,
    FunctionKind, Match, NetFunction, PacketSet, PortCond, PortId, ReasonCode, RulePredicate,
    SourceSpan,
};

use crate::common::{Meta, push_nonempty};
use crate::forwarding::meta_methods;

/// One VLAN tag: the VLAN and the TPID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VlanTag {
    pub vlan: u16,
    pub tpid: u16,
}

impl VlanTag {
    /// A tag with the TPID of IEEE 802.1Q.
    pub fn dot1q(vlan: u16) -> Self {
        VlanTag {
            vlan,
            tpid: TPID_8021Q,
        }
    }

    /// The tag as text: the VLAN, and the TPID when it is not `0x8100`.
    pub fn text(&self) -> String {
        if self.tpid == TPID_8021Q {
            format!("VLAN {}", self.vlan)
        } else {
            format!("VLAN {} TPID {:#06x}", self.vlan, self.tpid)
        }
    }
}

/// The tags of a frame at one end of a circuit: one tag, or an outer tag
/// and an inner tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tags {
    pub outer: VlanTag,
    pub inner: Option<VlanTag>,
}

impl Tags {
    pub fn one(outer: VlanTag) -> Self {
        Tags { outer, inner: None }
    }

    pub fn two(outer: VlanTag, inner: VlanTag) -> Self {
        Tags {
            outer,
            inner: Some(inner),
        }
    }

    /// The tags as text, the outer tag first.
    pub fn text(&self) -> String {
        match &self.inner {
            None => self.outer.text(),
            Some(i) => format!("{}, inner {}", self.outer.text(), i.text()),
        }
    }

    /// The predicate on the VLANs and the TPIDs of the tags. It does not
    /// read whether a frame has an inner tag.
    pub fn predicate(&self) -> RulePredicate {
        let mut m = Match {
            vlan: PortCond::one(self.outer.vlan),
            vlan_tpid: PortCond::one(self.outer.tpid),
            ..Match::any()
        };
        if let Some(i) = &self.inner {
            m.inner_vlan = PortCond::one(i.vlan);
            m.inner_vlan_tpid = PortCond::one(i.tpid);
        }
        RulePredicate::exact(m)
    }

    /// The frames with exactly these tags, the other frames, and the frames
    /// whose tags are not known.
    fn split(&self, input: &PacketSet) -> (PacketSet, PacketSet, PacketSet) {
        let (two, one) = input.split_inner_vlan();
        let (scope, other) = match self.inner {
            None => (one, two),
            Some(_) => (two, one),
        };
        let s = scope.split(&self.predicate());
        (s.matched, s.unmatched.union(&other), s.uncertain)
    }

    /// The frames with their tags replaced by these tags. Each tag gets an
    /// unknown layer 2 priority.
    fn put(&self, input: &PacketSet) -> PacketSet {
        let mut s = input.set_vlan(None);
        if let Some(i) = &self.inner {
            s = s.push_vlan(i.vlan, i.tpid).done;
        }
        s.push_vlan(self.outer.vlan, self.outer.tpid).done
    }
}

/// The far end of a circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FarEnd {
    /// A port of the provider: the frames leave it with its tags to the
    /// ingress function of its link peer.
    Port {
        port: PortId,
        tags: Tags,
        peer: FunctionId,
    },
    /// A function that gives the result of an end that the twin does not
    /// follow, for example a service profile of another party.
    Sink(FunctionId),
}

/// One circuit at one port: the tags of its near end and its far end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitLeg {
    pub circuit: String,
    pub near: Tags,
    pub far: FarEnd,
    pub spans: Vec<SourceSpan>,
    /// True for a port-based circuit: each frame of the port goes into the
    /// circuit, and the frame leaves the far end with its tags unchanged.
    /// `near` and the tags of a far port are then not read.
    pub port_based: bool,
}

/// The circuits of a provider port. A frame with exactly the tags of the
/// near end of a circuit leaves the far end with the tags of the far end,
/// or goes to the sink of the far end. Each other frame is unknown. The
/// circuit gives no link delay.
#[derive(Clone, Debug)]
pub struct Circuit {
    pub meta: Meta,
    /// The port where the frames enter.
    pub port: PortId,
    pub legs: Vec<CircuitLeg>,
}

impl NetFunction for Circuit {
    meta_methods!(FunctionKind::Circuit);

    fn each_span(&self, f: &mut dyn FnMut(&SourceSpan)) {
        for s in self
            .meta
            .provenance
            .iter()
            .chain(self.legs.iter().flat_map(|l| &l.spans))
        {
            f(s);
        }
    }

    fn requires(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::Device, ContextAttr::IngressPort]
    }
    fn reads(&self) -> Vec<Dependency> {
        Vec::new()
    }
    fn successors(&self) -> Vec<FunctionId> {
        let mut v: Vec<FunctionId> = self
            .legs
            .iter()
            .map(|l| match &l.far {
                FarEnd::Port { peer, .. } => peer.clone(),
                FarEnd::Sink(sink) => sink.clone(),
            })
            .collect();
        v.sort();
        v.dedup();
        v
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let mut c = ctx.clone();
        c.device = Attr::Known(self.meta.device.clone());
        c.ingress_port = Attr::Known(self.port.clone());
        c.bridge_domain = Attr::Unset;
        let mut out = Vec::new();
        let mut rest = input.clone();
        let mut unclear = input.empty();
        for leg in &self.legs {
            if rest.is_empty() {
                break;
            }
            let (matched, other, uncertain) = if leg.port_based {
                (rest.clone(), input.empty(), input.empty())
            } else {
                leg.near.split(&rest)
            };
            rest = other;
            unclear = unclear.union(&uncertain);
            if matched.is_empty() {
                continue;
            }
            let near = if leg.port_based {
                "each frame".to_string()
            } else {
                leg.near.text()
            };
            let from = format!("circuit {} from port {} {near}", leg.circuit, self.port);
            let b = match &leg.far {
                FarEnd::Port { port, tags, peer } => {
                    let (out, text) = if leg.port_based {
                        (matched, "with its tags".to_string())
                    } else {
                        (tags.put(&matched), tags.text())
                    };
                    let mut b = self.meta.forward(
                        out,
                        peer,
                        ReasonCode::LinkHandOff,
                        format!("{from} to port {port} {text}, to {peer}"),
                        c.clone(),
                        state,
                    );
                    b.delay = b.delay.add(&Delay::from_option(
                        None,
                        DelayGap::Link(self.meta.id.clone()),
                    ));
                    b
                }
                FarEnd::Sink(sink) => self.meta.forward(
                    matched,
                    sink,
                    ReasonCode::Classified,
                    format!("{from} to {sink}"),
                    c.clone(),
                    state,
                ),
            };
            out.push(b.with_spans(leg.spans.clone()));
        }
        push_nonempty(
            &mut out,
            self.meta.unknown(
                rest,
                ReasonCode::UnknownAttribute,
                format!("no circuit for the frame tags on port {}", self.port),
                &c,
                state,
            ),
        );
        push_nonempty(
            &mut out,
            self.meta.unknown(
                unclear,
                ReasonCode::UnknownAttribute,
                "frame tags not known",
                &c,
                state,
            ),
        );
        out
    }
}

/// The change of a [`TagStack`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagOp {
    /// Push a new outer tag. The outer tag of a frame with one tag becomes
    /// its inner tag.
    Push(VlanTag),
    /// Pop the outer tag of a frame with 2 tags whose outer tag is this
    /// tag.
    Pop(VlanTag),
}

/// Pushes or pops one VLAN tag on a port, for example the service tag of
/// a QinQ port. A frame that the change does not fit is unknown.
#[derive(Clone, Debug)]
pub struct TagStack {
    pub meta: Meta,
    pub port: PortId,
    pub op: TagOp,
    pub next: FunctionId,
}

impl NetFunction for TagStack {
    meta_methods!(FunctionKind::TagStack);

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
        vec![self.next.clone()]
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let mut out = Vec::new();
        match self.op {
            TagOp::Push(t) => {
                let p = input.push_vlan(t.vlan, t.tpid);
                push_nonempty(
                    &mut out,
                    self.meta.forward(
                        p.done,
                        &self.next,
                        ReasonCode::Passed,
                        format!("push {} on port {}", t.text(), self.port),
                        ctx.clone(),
                        state,
                    ),
                );
                push_nonempty(
                    &mut out,
                    self.meta.unknown(
                        p.full,
                        ReasonCode::UnknownAttribute,
                        format!("2 VLAN tags before the push on port {}", self.port),
                        ctx,
                        state,
                    ),
                );
            }
            TagOp::Pop(t) => {
                let (two, one) = input.split_inner_vlan();
                let s = two.split(&Tags::one(t).predicate());
                push_nonempty(
                    &mut out,
                    self.meta.forward(
                        s.matched.pop_vlan(),
                        &self.next,
                        ReasonCode::Classified,
                        format!("pop {} on port {}", t.text(), self.port),
                        ctx.clone(),
                        state,
                    ),
                );
                push_nonempty(
                    &mut out,
                    self.meta.unknown(
                        s.unmatched.union(&one),
                        ReasonCode::UnknownAttribute,
                        format!(
                            "frame tags not {} over an inner tag on port {}",
                            t.text(),
                            self.port
                        ),
                        ctx,
                        state,
                    ),
                );
                push_nonempty(
                    &mut out,
                    self.meta.unknown(
                        s.uncertain,
                        ReasonCode::UnknownAttribute,
                        "frame tags not known",
                        ctx,
                        state,
                    ),
                );
            }
        }
        out
    }
}
