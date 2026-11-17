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

/// The interfaces of a NAT rule. `None` means any interface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NatScope {
    pub ingress: Option<BTreeSet<InterfaceId>>,
    pub egress: Option<BTreeSet<InterfaceId>>,
}

/// True if the interface of the context is in the set. An interface that
/// the context does not know gives `Unknown`.
fn in_scope(set: Option<&BTreeSet<InterfaceId>>, attr: &Attr<InterfaceId>) -> Tri {
    match set {
        None => Tri::True,
        Some(s) => match attr {
            Attr::Known(i) => Tri::from(s.contains(i)),
            _ => Tri::Unknown,
        },
    }
}

/// Source NAT. A rule can be limited to ingress and egress interfaces.
#[derive(Clone, Debug)]
pub struct SourceNat {
    pub meta: Meta,
    pub table: ObjectId,
    scopes: Vec<NatScope>,
    rules: Vec<Rule<NatAction>>,
    pub next: FunctionId,
}

impl SourceNat {
    /// A source NAT whose rules are limited to egress interfaces.
    pub fn new(
        meta: Meta,
        table: ObjectId,
        rules: Vec<(Option<BTreeSet<InterfaceId>>, Rule<NatAction>)>,
        next: FunctionId,
    ) -> Self {
        let rules = rules
            .into_iter()
            .map(|(egress, r)| {
                (
                    NatScope {
                        ingress: None,
                        egress,
                    },
                    r,
                )
            })
            .collect();
        Self::with_scopes(meta, table, rules, next)
    }

    /// A source NAT with the ingress and the egress interfaces of each rule.
    pub fn with_scopes(
        meta: Meta,
        table: ObjectId,
        rules: Vec<(NatScope, Rule<NatAction>)>,
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
        let mut v = vec![ContextAttr::Session, ContextAttr::EgressInterface];
        if self.scopes.iter().any(|s| s.ingress.is_some()) {
            v.push(ContextAttr::IngressInterface);
        }
        v
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
        let scope = |i: usize| {
            let s = &self.scopes[i];
            in_scope(s.ingress.as_ref(), &ctx.ingress_interface)
                .and(in_scope(s.egress.as_ref(), &ctx.egress_interface))
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

/// Destination NAT. A rule can be limited to ingress interfaces.
#[derive(Clone, Debug)]
pub struct DestinationNat {
    pub meta: Meta,
    pub table: ObjectId,
    pub rules: Vec<Rule<NatAction>>,
    /// The ingress interfaces of each rule, by the index of the rule. A rule
    /// with no entry, or with `None`, applies on each interface.
    pub ingress: Vec<Option<BTreeSet<InterfaceId>>>,
    pub next: FunctionId,
}

impl NetFunction for DestinationNat {
    meta_methods!(FunctionKind::DestinationNat);

    fn requires(&self) -> Vec<ContextAttr> {
        let mut v = vec![ContextAttr::Session];
        if self.ingress.iter().any(Option::is_some) {
            v.push(ContextAttr::IngressInterface);
        }
        v
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
        let scope = |i: usize| {
            in_scope(
                self.ingress.get(i).and_then(Option::as_ref),
                &ctx.ingress_interface,
            )
        };
        nat_apply(
            &self.meta,
            Side::Destination,
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
