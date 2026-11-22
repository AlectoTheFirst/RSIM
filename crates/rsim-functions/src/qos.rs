//! A QoS stanza that the engine does not evaluate yet.

use rsim_core::{
    Attr, Branch, Context, ContextAttr, Dependency, FieldValue, FlowState, FunctionId,
    FunctionKind, HeaderField, NetFunction, ObjectId, PacketSet, ReasonCode, Rewrite,
};

use crate::common::{Meta, push_nonempty};

/// Forwards the packets and makes the DSCP, the ECN, the traffic class and
/// the queue unknown. It stands for a QoS stanza that is not evaluated, so
/// the trace names the stanza. A later function that reads the marking uses
/// the match bounds.
#[derive(Clone, Debug)]
pub struct QosNotEvaluated {
    pub meta: Meta,
    /// The QoS policy or stanza.
    pub stanza: ObjectId,
    pub next: FunctionId,
}

impl NetFunction for QosNotEvaluated {
    fn id(&self) -> &FunctionId {
        &self.meta.id
    }
    fn kind(&self) -> FunctionKind {
        FunctionKind::Shaping
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
    fn requires(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::TrafficClass, ContextAttr::Queue]
    }
    fn reads(&self) -> Vec<Dependency> {
        vec![Dependency::Object(self.stanza.clone())]
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let rewrite = Rewrite {
            dscp: Some(FieldValue::Unknown),
            ecn: Some(FieldValue::Unknown),
            ..Rewrite::default()
        };
        let mut ctx = ctx.clone();
        ctx.traffic_class = Attr::Unknown;
        ctx.queue = Attr::Unknown;
        let mut out = Vec::new();
        push_nonempty(
            &mut out,
            self.meta.forward(
                input.rewrite(&rewrite),
                &self.next,
                ReasonCode::Passed,
                format!(
                    "QoS {} not evaluated, marking and class unknown",
                    self.stanza
                ),
                ctx,
                state,
            ),
        );
        out
    }
}
