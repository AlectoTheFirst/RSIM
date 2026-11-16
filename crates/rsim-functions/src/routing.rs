//! Route lookup and next-hop resolution.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{
    AddrField, Alternative, Attr, Branch, Context, ContextAttr, Dependency, Destination, FlowState,
    FunctionId, FunctionKind, InterfaceId, NeighbourTarget, NetFunction, NextHop, ObjectId,
    Outcome, PacketSet, Prefix, PrefixTable, Reason, ReasonCode, RulePredicate, SourceSpan, Tri,
    TriePrefixTable, VrfId,
};

use crate::common::{Meta, push_nonempty};
use crate::forwarding::meta_methods;
use crate::rules::{Decision, Rule, RuleBody, RuleRef, UnknownCause, evaluate};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteKind {
    Connected,
    Static,
    /// An address of the device itself.
    Local,
    /// A discard route.
    Null,
}

/// One next hop of a route.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteNextHop {
    pub interface: InterfaceId,
    /// `None` for a connected network.
    pub gateway: Option<IpAddr>,
    /// The function that comes next for this egress interface.
    pub next: FunctionId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub kind: RouteKind,
    /// The next hops in the fixed order of the alternatives: sorted by
    /// interface, then by gateway.
    next_hops: Vec<RouteNextHop>,
    pub spans: Vec<SourceSpan>,
}

impl Route {
    pub fn new(kind: RouteKind, mut next_hops: Vec<RouteNextHop>, spans: Vec<SourceSpan>) -> Self {
        next_hops.sort();
        next_hops.dedup();
        Route {
            kind,
            next_hops,
            spans,
        }
    }

    pub fn next_hops(&self) -> &[RouteNextHop] {
        &self.next_hops
    }
}

/// Longest-prefix match in the FIB of the VRF. Equal-cost next hops are a
/// forwarding choice.
#[derive(Clone, Debug)]
pub struct RouteLookup {
    pub meta: Meta,
    pub tables: BTreeMap<VrfId, TriePrefixTable<Route>>,
    /// The function that gets the packets with no route, for example the
    /// lookup of the main table after a policy route table. `None` drops
    /// them.
    pub fallback: Option<FunctionId>,
    /// The function that gets the packets of a local route, for example the
    /// input policy of the device. `None` delivers them to the device.
    pub local: Option<FunctionId>,
}

impl RouteLookup {
    pub fn heap_bytes(&self) -> usize {
        self.tables.values().map(TriePrefixTable::heap_bytes).sum()
    }
}

impl NetFunction for RouteLookup {
    meta_methods!(FunctionKind::RouteLookup);

    fn requires(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::Vrf]
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::EgressInterface, ContextAttr::NextHop]
    }
    fn reads(&self) -> Vec<Dependency> {
        self.tables
            .keys()
            .map(|v| Dependency::RouteTable(self.meta.device.clone(), v.clone()))
            .collect()
    }
    fn successors(&self) -> Vec<FunctionId> {
        let mut v: Vec<FunctionId> = self
            .tables
            .values()
            .flat_map(|t| {
                t.entries()
                    .into_iter()
                    .flat_map(|(_, r)| r.next_hops.iter().map(|n| n.next.clone()))
                    .collect::<Vec<_>>()
            })
            .chain(self.fallback.clone())
            .chain(self.local.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let Some(vrf) = ctx.vrf.known() else {
            return vec![self.meta.unknown(
                input.clone(),
                ReasonCode::UnknownAttribute,
                "the VRF is not known",
                ctx,
                state,
            )];
        };
        let Some(table) = self.tables.get(vrf) else {
            return vec![self.meta.unknown(
                input.clone(),
                ReasonCode::IncompleteTable,
                format!("no FIB · VRF {vrf}"),
                ctx,
                state,
            )];
        };
        let part = input.partition_by_prefix(AddrField::Dst, table);
        let mut out = Vec::new();
        for (prefix, route, set) in part.matched {
            self.route_branches(&mut out, vrf, prefix, route, set, ctx, state);
        }
        let no_route = match &self.fallback {
            Some(next) => self.meta.forward(
                part.unmatched,
                next,
                ReasonCode::NoRoute,
                format!("no route in VRF {vrf} · next table"),
                ctx.clone(),
                state,
            ),
            None => self.meta.drop(
                part.unmatched,
                ReasonCode::NoRoute,
                format!("no route in VRF {vrf}"),
                ctx,
                state,
            ),
        };
        push_nonempty(&mut out, no_route);
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

impl RouteLookup {
    #[allow(clippy::too_many_arguments)]
    fn route_branches(
        &self,
        out: &mut Vec<Branch>,
        vrf: &VrfId,
        prefix: Prefix,
        route: &Route,
        set: PacketSet,
        ctx: &Context,
        state: &FlowState,
    ) {
        match route.kind {
            RouteKind::Local => {
                if let Some(next) = &self.local {
                    out.push(
                        self.meta
                            .forward(
                                set,
                                next,
                                ReasonCode::Routed,
                                format!("{prefix} is an address of {}", self.meta.device),
                                ctx.clone(),
                                state,
                            )
                            .with_spans(route.spans.clone()),
                    );
                    return;
                }
                out.push(
                    self.meta
                        .branch(
                            set,
                            Outcome::Deliver(Destination::Device(self.meta.device.clone())),
                            Reason::new(
                                ReasonCode::Delivered,
                                format!("{prefix} is an address of {}", self.meta.device),
                            ),
                            ctx.clone(),
                            state,
                        )
                        .with_spans(route.spans.clone()),
                );
                return;
            }
            RouteKind::Null => {
                out.push(
                    self.meta
                        .drop(
                            set,
                            ReasonCode::NullRoute,
                            format!("discard route {prefix} in VRF {vrf}"),
                            ctx,
                            state,
                        )
                        .with_spans(route.spans.clone()),
                );
                return;
            }
            RouteKind::Connected | RouteKind::Static => {}
        }
        let count = u32::try_from(route.next_hops.len()).expect("too many next hops");
        if count == 0 {
            out.push(
                self.meta
                    .unknown(
                        set,
                        ReasonCode::IncompleteTable,
                        format!("route {prefix} in VRF {vrf} has no next hop"),
                        ctx,
                        state,
                    )
                    .with_spans(route.spans.clone()),
            );
            return;
        }
        for (i, nh) in route.next_hops.iter().enumerate() {
            let mut c = ctx.clone();
            c.egress_interface = Attr::Known(nh.interface.clone());
            c.next_hop = Attr::Known(match nh.gateway {
                Some(g) => NextHop::Gateway(g),
                None => NextHop::Connected,
            });
            let via = match nh.gateway {
                Some(g) => format!("via {g} on {}", nh.interface),
                None => format!("connected on {}", nh.interface),
            };
            let mut b = self
                .meta
                .forward(
                    set.clone(),
                    &nh.next,
                    ReasonCode::Routed,
                    format!("{prefix} in VRF {vrf} {via}"),
                    c,
                    state,
                )
                .with_spans(route.spans.clone());
            if count > 1 {
                b = b.with_alternative(Alternative {
                    choice: self.meta.id.clone(),
                    key: format!("{vrf} {prefix}"),
                    index: u32::try_from(i).expect("too many next hops"),
                    count,
                    label: via,
                });
            }
            out.push(b);
        }
    }
}

/// One neighbour entry, from the collected ARP or neighbour table.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Neighbour {
    pub interface: InterfaceId,
    pub target: NeighbourTarget,
    /// The owner, for the reason text when two owners exist.
    pub owner: String,
    pub spans: Vec<SourceSpan>,
}

/// Resolves the next-hop address to a neighbour on the egress interface.
#[derive(Clone, Debug)]
pub struct NextHopResolution {
    pub meta: Meta,
    /// Host prefixes to neighbour entries.
    pub neighbours: TriePrefixTable<Vec<Neighbour>>,
    /// True if the neighbour table was collected completely. Only a complete
    /// table can prove that a neighbour does not exist.
    pub complete: bool,
    /// The egress function of each interface.
    pub egress: BTreeMap<InterfaceId, FunctionId>,
}

impl NextHopResolution {
    #[allow(clippy::too_many_arguments)]
    fn resolve(
        &self,
        out: &mut Vec<Branch>,
        addr: String,
        entries: &[Neighbour],
        iface: &InterfaceId,
        set: PacketSet,
        ctx: &Context,
        state: &FlowState,
    ) {
        let mut owners: Vec<&Neighbour> =
            entries.iter().filter(|n| &n.interface == iface).collect();
        // Two entries are one owner only if the target and the owner are the
        // same. Two owners behind one link are still two owners.
        owners.sort_by(|a, b| (&a.target, &a.owner).cmp(&(&b.target, &b.owner)));
        owners.dedup_by(|a, b| a.target == b.target && a.owner == b.owner);
        match owners.as_slice() {
            [] if self.complete => push_nonempty(
                out,
                self.meta.drop(
                    set,
                    ReasonCode::NoNeighbour,
                    format!("no neighbour {addr} on {iface}"),
                    ctx,
                    state,
                ),
            ),
            [] => push_nonempty(
                out,
                self.meta.unknown(
                    set,
                    ReasonCode::IncompleteTable,
                    format!("neighbour {addr} not in table, table incomplete · {iface}"),
                    ctx,
                    state,
                ),
            ),
            [one] => {
                let Some(next) = self.egress.get(iface) else {
                    push_nonempty(
                        out,
                        self.meta.unknown(
                            set,
                            ReasonCode::IncompleteTable,
                            format!("no egress function · {iface}"),
                            ctx,
                            state,
                        ),
                    );
                    return;
                };
                let mut c = ctx.clone();
                c.neighbour = Attr::Known(one.target.clone());
                push_nonempty(
                    out,
                    self.meta
                        .forward(
                            set,
                            next,
                            ReasonCode::Resolved,
                            format!("{addr} is {} on {iface}", one.owner),
                            c,
                            state,
                        )
                        .with_spans(one.spans.clone()),
                );
            }
            many => {
                let names: Vec<&str> = many.iter().map(|n| n.owner.as_str()).collect();
                let spans = many.iter().flat_map(|n| n.spans.iter().cloned()).collect();
                push_nonempty(
                    out,
                    self.meta
                        .unknown(
                            set,
                            ReasonCode::AmbiguousOwner,
                            format!(
                                "{addr} has {} owners: {} · {iface}",
                                names.len(),
                                names.join(", ")
                            ),
                            ctx,
                            state,
                        )
                        .with_spans(spans),
                );
            }
        }
    }
}

impl NetFunction for NextHopResolution {
    meta_methods!(FunctionKind::NextHopResolution);

    fn requires(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::EgressInterface, ContextAttr::NextHop]
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::NeighbourTarget]
    }
    fn reads(&self) -> Vec<Dependency> {
        vec![Dependency::NeighbourTable(self.meta.device.clone())]
    }
    fn successors(&self) -> Vec<FunctionId> {
        self.egress.values().cloned().collect()
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let (Some(iface), Some(nh)) = (ctx.egress_interface.known(), ctx.next_hop.known()) else {
            return vec![self.meta.unknown(
                input.clone(),
                ReasonCode::UnknownAttribute,
                "the egress interface or the next hop is not known",
                ctx,
                state,
            )];
        };
        let mut out = Vec::new();
        match nh {
            NextHop::Gateway(g) => {
                let entries = self
                    .neighbours
                    .get(&Prefix::host(*g))
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                self.resolve(
                    &mut out,
                    g.to_string(),
                    entries,
                    iface,
                    input.clone(),
                    ctx,
                    state,
                );
            }
            NextHop::Connected => {
                let part = input.partition_by_prefix(AddrField::Dst, &self.neighbours);
                for (p, entries, set) in part.matched {
                    self.resolve(
                        &mut out,
                        p.addr().to_string(),
                        entries,
                        iface,
                        set,
                        ctx,
                        state,
                    );
                }
                self.resolve(
                    &mut out,
                    "the destination".to_string(),
                    &[],
                    iface,
                    part.unmatched,
                    ctx,
                    state,
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
            }
        }
        out
    }
}

/// Policy routing: ordered rules that select a route table for the packets
/// that they match. The packets of no rule go to the main route lookup.
///
/// The action of a rule is the route lookup of its table. A rule applies
/// only to the packets of its ingress interfaces, or to all packets if it
/// has no interface set.
#[derive(Clone, Debug)]
pub struct PolicyRoute {
    pub meta: Meta,
    pub policy: ObjectId,
    scopes: Vec<Option<BTreeSet<InterfaceId>>>,
    rules: Vec<Rule<FunctionId>>,
    main: FunctionId,
}

impl PolicyRoute {
    pub fn new(
        meta: Meta,
        policy: ObjectId,
        rules: Vec<(Option<BTreeSet<InterfaceId>>, Rule<FunctionId>)>,
        main: FunctionId,
    ) -> Self {
        let (scopes, rules) = rules.into_iter().unzip();
        PolicyRoute {
            meta,
            policy,
            scopes,
            rules,
            main,
        }
    }

    pub fn rules(&self) -> &[Rule<FunctionId>] {
        &self.rules
    }
}

impl NetFunction for PolicyRoute {
    meta_methods!(FunctionKind::RouteLookup);

    fn requires(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::IngressInterface]
    }
    fn provides(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn reads(&self) -> Vec<Dependency> {
        vec![Dependency::Object(self.policy.clone())]
    }
    fn successors(&self) -> Vec<FunctionId> {
        let mut v: Vec<FunctionId> = self
            .rules
            .iter()
            .filter_map(|r| match &r.body {
                RuleBody::Handled { action, .. } => Some(action.clone()),
                RuleBody::Unhandled => None,
            })
            .chain([self.main.clone()])
            .collect();
        v.sort();
        v.dedup();
        v
    }
    fn predicates(&self) -> Vec<&RulePredicate> {
        self.rules
            .iter()
            .filter_map(|r| match &r.body {
                RuleBody::Handled { predicate, .. } => Some(predicate),
                RuleBody::Unhandled => None,
            })
            .collect()
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let scope = |i: usize| match &self.scopes[i] {
            None => Tri::True,
            Some(s) => match &ctx.ingress_interface {
                Attr::Known(e) => Tri::from(s.contains(e)),
                _ => Tri::Unknown,
            },
        };
        let mut out = Vec::new();
        for (set, decision) in evaluate(&self.rules, &self.main, input, &scope) {
            let b = match decision {
                Decision::Action { action, decided_by } => {
                    let detail = match decided_by.first() {
                        Some(RuleRef::Rule(i)) => format!(
                            "policy {} rule {} · table {action}",
                            self.policy, self.rules[*i].name
                        ),
                        _ => format!("policy {} · no rule · main table", self.policy),
                    };
                    self.meta.forward(
                        set,
                        &action,
                        ReasonCode::Classified,
                        detail,
                        ctx.clone(),
                        state,
                    )
                }
                Decision::Unknown { cause } => {
                    let (code, detail) = match cause {
                        UnknownCause::Unhandled { rule } => (
                            ReasonCode::UnhandledStanza,
                            format!(
                                "policy {} rule {} is not handled",
                                self.policy, self.rules[rule].name
                            ),
                        ),
                        UnknownCause::Uncertain { rule } => (
                            ReasonCode::MatchUnknown,
                            format!(
                                "policy {} rule {} may match",
                                self.policy, self.rules[rule].name
                            ),
                        ),
                    };
                    self.meta.unknown(set, code, detail, ctx, state)
                }
            };
            push_nonempty(&mut out, b);
        }
        out
    }
}
