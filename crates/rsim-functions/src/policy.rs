//! ACL match and firewall policy.

use std::collections::BTreeSet;

use rsim_core::{
    Attr, Branch, Context, ContextAttr, Dependency, FlowState, FunctionId, FunctionKind,
    HeaderField, NetFunction, ObjectId, PacketSet, ReasonCode, SessionMatch, SourceSpan, Tri,
    ZoneId,
};

use crate::common::{Meta, push_nonempty};
use crate::profile::RuleAction;
use crate::rules::{Decision, Rule, describe, evaluate, explain, spans_of};

fn qos_reads_of(rules: &[Rule<RuleAction>]) -> Vec<HeaderField> {
    let mut v: Vec<HeaderField> = rules
        .iter()
        .flat_map(|r| match &r.body {
            crate::rules::RuleBody::Handled { predicate, .. } => predicate.reads(),
            crate::rules::RuleBody::Unhandled => Vec::new(),
        })
        .filter(|f| HeaderField::QOS.contains(f))
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Turns the decisions of ordered permit or deny rules into branches.
fn branches_of(
    meta: &Meta,
    rules: &[Rule<RuleAction>],
    what: &str,
    parts: Vec<(PacketSet, Decision<RuleAction>)>,
    next: &FunctionId,
    ctx: &Context,
    state: &FlowState,
) -> Vec<Branch> {
    let mut out = Vec::new();
    for (set, d) in parts {
        let b = match d {
            Decision::Action { action, decided_by } => {
                let by: Vec<String> = decided_by.iter().map(|r| describe(rules, *r)).collect();
                let spans = spans_of(rules, &decided_by);
                match action {
                    RuleAction::Permit => meta
                        .forward(
                            set,
                            next,
                            ReasonCode::Permitted,
                            format!("{what}: permitted by {}", by.join(" or ")),
                            ctx.clone(),
                            state,
                        )
                        .with_spans(spans),
                    RuleAction::Deny => meta
                        .drop(
                            set,
                            ReasonCode::Denied,
                            format!("{what}: denied by {}", by.join(" or ")),
                            ctx,
                            state,
                        )
                        .with_spans(spans),
                }
            }
            Decision::Indeterminate { cause } => {
                let (text, spans) = explain(rules, &cause);
                let code = match cause {
                    crate::rules::IndeterminateCause::Unhandled { .. } => {
                        ReasonCode::UnhandledStanza
                    }
                    crate::rules::IndeterminateCause::Uncertain { .. } => {
                        ReasonCode::UncertainMatch
                    }
                };
                meta.indeterminate(set, code, format!("{what}: {text}"), ctx, state)
                    .with_spans(spans)
            }
        };
        push_nonempty(&mut out, b);
    }
    out
}

/// A stateless ACL with ordered rules.
#[derive(Clone, Debug)]
pub struct AclMatch {
    pub meta: Meta,
    pub acl: ObjectId,
    pub rules: Vec<Rule<RuleAction>>,
    /// From the vendor profile.
    pub default: RuleAction,
    pub next: FunctionId,
}

impl NetFunction for AclMatch {
    fn id(&self) -> &FunctionId {
        &self.meta.id
    }
    fn kind(&self) -> FunctionKind {
        FunctionKind::AclMatch
    }
    fn device(&self) -> Option<&rsim_core::DeviceId> {
        Some(&self.meta.device)
    }
    fn provenance(&self) -> &[SourceSpan] {
        &self.meta.provenance
    }
    fn qos_reads(&self) -> Vec<HeaderField> {
        qos_reads_of(&self.rules)
    }
    fn qos_writes(&self) -> Vec<HeaderField> {
        Vec::new()
    }
    fn requires(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn provides(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn reads(&self) -> Vec<Dependency> {
        vec![
            Dependency::Object(self.acl.clone()),
            Dependency::VendorProfile(self.meta.profile.clone()),
        ]
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let parts = evaluate(&self.rules, &self.default, input, &|_| Tri::True);
        branches_of(
            &self.meta,
            &self.rules,
            &format!("ACL {}", self.acl),
            parts,
            &self.next,
            ctx,
            state,
        )
    }
}

/// The zones to which a firewall rule applies. `None` means any zone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZoneScope {
    pub from: Option<BTreeSet<ZoneId>>,
    pub to: Option<BTreeSet<ZoneId>>,
}

impl ZoneScope {
    pub fn between(from: &str, to: &str) -> Self {
        ZoneScope {
            from: Some([ZoneId::new(from)].into_iter().collect()),
            to: Some([ZoneId::new(to)].into_iter().collect()),
        }
    }

    fn eval(&self, ctx: &Context) -> Tri {
        fn one(scope: &Option<BTreeSet<ZoneId>>, z: &Attr<ZoneId>) -> Tri {
            match scope {
                None => Tri::True,
                Some(s) => match z {
                    Attr::Known(z) => Tri::from(s.contains(z)),
                    _ => Tri::Unknown,
                },
            }
        }
        one(&self.from, &ctx.src_zone).and(one(&self.to, &ctx.dst_zone))
    }
}

/// A stateful firewall policy between zones. Packets of an existing session
/// pass without a policy check.
#[derive(Clone, Debug)]
pub struct FirewallPolicy {
    pub meta: Meta,
    pub policy: ObjectId,
    /// The zone scope of each rule, at the same position as the rule.
    scopes: Vec<ZoneScope>,
    rules: Vec<Rule<RuleAction>>,
    /// From the vendor profile.
    pub default: RuleAction,
    pub next: FunctionId,
}

impl FirewallPolicy {
    pub fn new(
        meta: Meta,
        policy: ObjectId,
        rules: Vec<(ZoneScope, Rule<RuleAction>)>,
        default: RuleAction,
        next: FunctionId,
    ) -> Self {
        let (scopes, rules) = rules.into_iter().unzip();
        FirewallPolicy {
            meta,
            policy,
            scopes,
            rules,
            default,
            next,
        }
    }
}

impl NetFunction for FirewallPolicy {
    fn id(&self) -> &FunctionId {
        &self.meta.id
    }
    fn kind(&self) -> FunctionKind {
        FunctionKind::FirewallPolicy
    }
    fn device(&self) -> Option<&rsim_core::DeviceId> {
        Some(&self.meta.device)
    }
    fn provenance(&self) -> &[SourceSpan] {
        &self.meta.provenance
    }
    fn qos_reads(&self) -> Vec<HeaderField> {
        qos_reads_of(&self.rules)
    }
    fn qos_writes(&self) -> Vec<HeaderField> {
        Vec::new()
    }

    fn requires(&self) -> Vec<ContextAttr> {
        vec![
            ContextAttr::SrcZone,
            ContextAttr::DstZone,
            ContextAttr::Session,
        ]
    }
    fn provides(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn reads(&self) -> Vec<Dependency> {
        vec![
            Dependency::Object(self.policy.clone()),
            Dependency::VendorProfile(self.meta.profile.clone()),
        ]
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        if let Attr::Known(
            SessionMatch::Forward { index, .. } | SessionMatch::Reply { index, .. },
        ) = &ctx.session
        {
            return vec![self.meta.forward(
                input.clone(),
                &self.next,
                ReasonCode::SessionMatched,
                format!("policy {}: packets of session {index} pass", self.policy),
                ctx.clone(),
                state,
            )];
        }
        let parts = evaluate(&self.rules, &self.default, input, &|i| {
            self.scopes[i].eval(ctx)
        });
        branches_of(
            &self.meta,
            &self.rules,
            &format!("policy {}", self.policy),
            parts,
            &self.next,
            ctx,
            state,
        )
    }
}
