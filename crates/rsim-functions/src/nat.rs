//! Source NAT and destination NAT with ordered rules.

use std::collections::BTreeSet;
use std::net::IpAddr;

use rsim_core::{
    Attr, Branch, Context, ContextAttr, Dependency, FieldValue, FlowState, FunctionId,
    FunctionKind, InterfaceId, NetFunction, ObjectId, PacketSet, ReasonCode, Rewrite,
    RulePredicate, SessionMatch, Tri,
};

use crate::common::{Meta, push_nonempty};
use crate::forwarding::meta_methods;
use crate::profile::PortTranslation;
use crate::rules::{
    Decision, Rule, UnknownCause, describe_all, evaluate, explain, predicates_of, spans_of,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatAction {
    NoTranslate,
    Translate { addr: IpAddr, port: PortTranslation },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Source,
    Destination,
}

fn rewrite_for(side: Side, addr: IpAddr, port: PortTranslation) -> Rewrite {
    let port = match port {
        PortTranslation::Preserve => None,
        PortTranslation::Allocate => Some(FieldValue::Unknown),
        PortTranslation::To(p) => Some(FieldValue::Known(p)),
    };
    match side {
        Side::Source => Rewrite {
            src_ip: Some(FieldValue::Known(addr)),
            src_port: port,
            ..Rewrite::default()
        },
        Side::Destination => Rewrite {
            dst_ip: Some(FieldValue::Known(addr)),
            dst_port: port,
            ..Rewrite::default()
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn nat_apply(
    meta: &Meta,
    side: Side,
    table: &ObjectId,
    rules: &[Rule<NatAction>],
    scope: &dyn Fn(usize) -> Tri,
    next: &FunctionId,
    input: &PacketSet,
    ctx: &Context,
    state: &FlowState,
) -> Vec<Branch> {
    let what = match side {
        Side::Source => format!("source NAT {table}"),
        Side::Destination => format!("destination NAT {table}"),
    };
    if let Attr::Known(SessionMatch::Forward { .. } | SessionMatch::Reply { .. }) = &ctx.session {
        return vec![meta.forward(
            input.clone(),
            next,
            ReasonCode::NotTranslated,
            format!("translated by session · {what}"),
            ctx.clone(),
            state,
        )];
    }
    let mut out = Vec::new();
    for (set, d) in evaluate(rules, &NatAction::NoTranslate, input, scope) {
        let b = match d {
            Decision::Action { action, decided_by } => {
                let by = describe_all(rules, &what, &decided_by);
                let spans = spans_of(rules, &decided_by);
                match action {
                    NatAction::NoTranslate => meta.forward(
                        set,
                        next,
                        ReasonCode::NotTranslated,
                        format!("not translated · {by}"),
                        ctx.clone(),
                        state,
                    ),
                    NatAction::Translate { addr, port } => meta.forward(
                        set.rewrite(&rewrite_for(side, addr, port)),
                        next,
                        ReasonCode::Translated,
                        format!("translated to {addr} · {by}"),
                        ctx.clone(),
                        state,
                    ),
                }
                .with_spans(spans)
            }
            Decision::Unknown { cause } => {
                let (text, spans) = explain(rules, &what, &cause, &set);
                let code = match cause {
                    UnknownCause::Unhandled { .. } => ReasonCode::UnhandledStanza,
                    UnknownCause::Uncertain { .. } => ReasonCode::MatchUnknown,
                };
                meta.unknown(set, code, text, ctx, state).with_spans(spans)
            }
        };
        push_nonempty(&mut out, b);
    }
    out
}

/// Source NAT. A rule can be limited to egress interfaces.
#[derive(Clone, Debug)]
pub struct SourceNat {
    pub meta: Meta,
    pub table: ObjectId,
    /// The egress interfaces of each rule. `None` means any interface.
    scopes: Vec<Option<BTreeSet<InterfaceId>>>,
    rules: Vec<Rule<NatAction>>,
    pub next: FunctionId,
}

impl SourceNat {
    pub fn new(
        meta: Meta,
        table: ObjectId,
        rules: Vec<(Option<BTreeSet<InterfaceId>>, Rule<NatAction>)>,
        next: FunctionId,
    ) -> Self {
        let (scopes, rules) = rules.into_iter().unzip();
        SourceNat {
            meta,
            table,
            scopes,
            rules,
            next,
        }
    }
}

impl NetFunction for SourceNat {
    meta_methods!(FunctionKind::SourceNat);

    fn requires(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::Session, ContextAttr::EgressInterface]
    }
    fn provides(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn reads(&self) -> Vec<Dependency> {
        vec![Dependency::Object(self.table.clone())]
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn predicates(&self) -> Vec<&RulePredicate> {
        predicates_of(&self.rules)
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let scope = |i: usize| match &self.scopes[i] {
            None => Tri::True,
            Some(s) => match &ctx.egress_interface {
                Attr::Known(e) => Tri::from(s.contains(e)),
                _ => Tri::Unknown,
            },
        };
        nat_apply(
            &self.meta,
            Side::Source,
            &self.table,
            &self.rules,
            &scope,
            &self.next,
            input,
            ctx,
            state,
        )
    }
}

/// Destination NAT.
#[derive(Clone, Debug)]
pub struct DestinationNat {
    pub meta: Meta,
    pub table: ObjectId,
    pub rules: Vec<Rule<NatAction>>,
    pub next: FunctionId,
}

impl NetFunction for DestinationNat {
    meta_methods!(FunctionKind::DestinationNat);

    fn requires(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::Session]
    }
    fn provides(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn reads(&self) -> Vec<Dependency> {
        vec![Dependency::Object(self.table.clone())]
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn predicates(&self) -> Vec<&RulePredicate> {
        predicates_of(&self.rules)
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        nat_apply(
            &self.meta,
            Side::Destination,
            &self.table,
            &self.rules,
            &|_| Tri::True,
            &self.next,
            input,
            ctx,
            state,
        )
    }
}
