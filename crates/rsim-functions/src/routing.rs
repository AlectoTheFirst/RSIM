//! Route lookup and next-hop resolution.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{
    AddrCond, AddrField, Alternative, AlternativeKind, Attr, Branch, Context, ContextAttr,
    Dependency, Destination, FieldValue, FlowState, FunctionId, FunctionKind, InterfaceId, Mac,
    Match, NeighbourTarget, NetFunction, NextHop, ObjectId, Outcome, PacketSet, Prefix,
    PrefixTable, Reason, ReasonCode, Rewrite, RibGuardFlag, RulePredicate, SourceSpan, Tri,
    TriePrefixTable, VrfId,
};

use crate::common::{Meta, push_nonempty};
use crate::fib::{Fib, GroupRoutes};
use crate::forwarding::meta_methods;
use crate::rules::{Decision, Rule, RuleBody, RuleRef, UnknownCause, evaluate};

/// The routing protocol of a learned route. The vendor word stays in the
/// collected row and in the span of the route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RouteProtocol {
    Bgp,
    Ospf,
    Isis,
    Eigrp,
    Rip,
    /// A route of another device that the overlay of an SD-WAN gave.
    Overlay,
    Other,
}

impl RouteProtocol {
    /// The name in the tables and in the step text, for example `bgp`.
    pub fn name(self) -> &'static str {
        match self {
            RouteProtocol::Bgp => "bgp",
            RouteProtocol::Ospf => "ospf",
            RouteProtocol::Isis => "isis",
            RouteProtocol::Eigrp => "eigrp",
            RouteProtocol::Rip => "rip",
            RouteProtocol::Overlay => "overlay",
            RouteProtocol::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RouteKind {
    Connected,
    Static,
    /// An address of the device itself.
    Local,
    /// A discard route.
    Null,
    /// A route that a routing protocol gave.
    Learned(RouteProtocol),
}

impl RouteKind {
    /// The name in the tables: `connected`, `static`, `local`, `null` or
    /// the name of the protocol of a learned route.
    pub fn name(self) -> &'static str {
        match self {
            RouteKind::Connected => "connected",
            RouteKind::Static => "static",
            RouteKind::Local => "local",
            RouteKind::Null => "null",
            RouteKind::Learned(p) => p.name(),
        }
    }

    /// The kind that decides the forwarding. A learned route forwards as a
    /// static route with the same next hops.
    pub fn forwarding(self) -> RouteKind {
        match self {
            RouteKind::Learned(_) => RouteKind::Static,
            k => k,
        }
    }

    /// The protocol of a learned route.
    pub fn protocol(self) -> Option<RouteProtocol> {
        match self {
            RouteKind::Learned(p) => Some(p),
            _ => None,
        }
    }
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
    /// The code and the text of the reason of a route with no next hop.
    /// `None` gives the reason that the route has no next hop.
    unknown: Option<(ReasonCode, String)>,
}

impl Route {
    pub fn new(kind: RouteKind, mut next_hops: Vec<RouteNextHop>, spans: Vec<SourceSpan>) -> Self {
        next_hops.sort();
        next_hops.dedup();
        Route {
            kind,
            next_hops,
            spans,
            unknown: None,
        }
    }

    /// A route with no next hop whose packets are unknown for the reason
    /// `why`, with the code `IncompleteTable`.
    pub fn unknown(kind: RouteKind, why: impl Into<String>, spans: Vec<SourceSpan>) -> Self {
        Route::unknown_with(kind, ReasonCode::IncompleteTable, why, spans)
    }

    /// A route with no next hop whose packets are unknown for the reason
    /// `why`, with the code `code`.
    pub fn unknown_with(
        kind: RouteKind,
        code: ReasonCode,
        why: impl Into<String>,
        spans: Vec<SourceSpan>,
    ) -> Self {
        Route {
            kind,
            next_hops: Vec::new(),
            spans,
            unknown: Some((code, why.into())),
        }
    }

    pub fn next_hops(&self) -> &[RouteNextHop] {
        &self.next_hops
    }

    /// The reason of a route with no next hop, if it has one.
    pub fn unknown_reason(&self) -> Option<&str> {
        self.unknown.as_ref().map(|(_, why)| why.as_str())
    }

    /// The code and the text of the reason of a route with no next hop, if
    /// it has one.
    pub fn unknown_code(&self) -> Option<(ReasonCode, &str)> {
        self.unknown.as_ref().map(|(c, why)| (*c, why.as_str()))
    }
}

/// Longest-prefix match in the FIB of the VRF. Equal-cost next hops are a
/// forwarding choice.
#[derive(Clone, Debug)]
pub struct RouteLookup {
    pub meta: Meta,
    pub tables: BTreeMap<VrfId, Fib>,
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
        self.tables.values().map(Fib::heap_bytes).sum()
    }
}

impl NetFunction for RouteLookup {
    meta_methods!(FunctionKind::RouteLookup);

    fn each_span(&self, f: &mut dyn FnMut(&rsim_core::SourceSpan)) {
        for s in &self.meta.provenance {
            f(s);
        }
        for t in self.tables.values() {
            t.each_span(f);
        }
    }

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
                t.groups()
                    .iter()
                    .flat_map(|g| g.next_hops.iter().map(|n| n.next.clone()))
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
                "VRF not known",
                ctx,
                state,
            )];
        };
        let Some(table) = self.tables.get(vrf) else {
            return vec![self.meta.unknown(
                input.clone(),
                ReasonCode::IncompleteTable,
                format!("no FIB of VRF {vrf}"),
                ctx,
                state,
            )];
        };
        let (groups, unmatched, uncertain) = table.split(input, SAMPLE);
        let mut out = Vec::new();
        for g in groups {
            self.route_branches(&mut out, vrf, g, ctx, state);
        }
        let no_route = match &self.fallback {
            Some(next) => self.meta.forward(
                unmatched.clone(),
                next,
                ReasonCode::NoRoute,
                format!("no route in VRF {vrf}, next table"),
                ctx.clone(),
                state,
            ),
            None => self.meta.drop(
                unmatched,
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
                uncertain,
                ReasonCode::UnknownAttribute,
                "destination address not known",
                ctx,
                state,
            ),
        );
        out
    }
}

/// The number of routes that a step names for a group of routes.
const SAMPLE: usize = 5;

impl RouteLookup {
    /// The branches of one next-hop group. A group with one route names its
    /// prefix; a group with more routes names their number and the first of
    /// them.
    fn route_branches(
        &self,
        out: &mut Vec<Branch>,
        vrf: &VrfId,
        g: GroupRoutes<'_>,
        ctx: &Context,
        state: &FlowState,
    ) {
        let flag = group_guard(&g);
        let start = out.len();
        self.group_branches(out, vrf, g, ctx, state);
        for b in &mut out[start..] {
            b.rib_guard = Some(flag);
        }
    }

    fn group_branches(
        &self,
        out: &mut Vec<Branch>,
        vrf: &VrfId,
        g: GroupRoutes<'_>,
        ctx: &Context,
        state: &FlowState,
    ) {
        let list: Vec<String> = g
            .sample
            .iter()
            .zip(&g.protocols)
            .map(|(p, proto)| match proto {
                Some(x) => format!("{p} ({})", x.name()),
                None => p.to_string(),
            })
            .collect();
        let what = if g.count == 1 && g.exact && !list.is_empty() {
            list[0].clone()
        } else if g.exact {
            let more = g.count.saturating_sub(list.len());
            if more > 0 {
                format!("{} routes ({} and {more} more)", g.count, list.join(", "))
            } else {
                format!("{} routes ({})", g.count, list.join(", "))
            }
        } else {
            format!("up to {} routes ({} and others)", g.count, list.join(", "))
        };
        let set = g.packets;
        let spans = g.spans;
        match g.group.kind {
            RouteKind::Local => {
                let detail = format!("{what}, address of {}", self.meta.device);
                if let Some(next) = &self.local {
                    out.push(
                        self.meta
                            .forward(set, next, ReasonCode::Routed, detail, ctx.clone(), state)
                            .with_spans(spans),
                    );
                    return;
                }
                out.push(
                    self.meta
                        .branch(
                            set,
                            Outcome::Deliver(Destination::Device(self.meta.device.clone())),
                            Reason::new(ReasonCode::Delivered, detail),
                            ctx.clone(),
                            state,
                        )
                        .with_spans(spans),
                );
                return;
            }
            RouteKind::Null => {
                out.push(
                    self.meta
                        .drop(
                            set,
                            ReasonCode::NullRoute,
                            format!("discard route {what} in VRF {vrf}"),
                            ctx,
                            state,
                        )
                        .with_spans(spans),
                );
                return;
            }
            RouteKind::Connected | RouteKind::Static | RouteKind::Learned(_) => {}
        }
        let hops = &g.group.next_hops;
        let count = u32::try_from(hops.len()).expect("too many next hops");
        if count == 0 {
            let (code, detail) = match &g.group.unknown {
                Some((code, why)) => (*code, format!("route {what} in VRF {vrf}, {why}")),
                None => (
                    ReasonCode::IncompleteTable,
                    format!("route {what} in VRF {vrf}, no next hop"),
                ),
            };
            out.push(
                self.meta
                    .unknown(set, code, detail, ctx, state)
                    .with_spans(spans),
            );
            return;
        }
        // The key of the choice comes from the content of the group, so it
        // is the same in each run.
        let key = if g.count == 1 && g.exact {
            format!("{vrf} {what}")
        } else {
            let vias: Vec<String> = hops
                .iter()
                .map(|nh| match nh.gateway {
                    Some(gw) => format!("{gw}@{}", nh.interface),
                    None => nh.interface.to_string(),
                })
                .collect();
            format!("{vrf} group {}", vias.join(","))
        };
        for (i, nh) in hops.iter().enumerate() {
            let mut c = ctx.clone();
            c.egress_interface = Attr::Known(nh.interface.clone());
            c.next_hop = Attr::Known(match nh.gateway {
                Some(gw) => NextHop::Gateway(gw),
                None => NextHop::Connected,
            });
            let via = match nh.gateway {
                Some(gw) => format!("via {gw} on {}", nh.interface),
                None => format!("connected on {}", nh.interface),
            };
            let mut b = self
                .meta
                .forward(
                    set.clone(),
                    &nh.next,
                    ReasonCode::Routed,
                    format!("{what} in VRF {vrf} {via}"),
                    c,
                    state,
                )
                .with_spans(spans.clone());
            if count > 1 {
                b = b.with_alternative(Alternative {
                    kind: AlternativeKind::Choice,
                    choice: self.meta.id.clone(),
                    key: key.clone(),
                    index: u32::try_from(i).expect("too many next hops"),
                    count,
                    label: via,
                });
            }
            out.push(b);
        }
    }
}

/// The RIB guard result of a group: `DiffersFromCollected` if a route of
/// the sample differs, `MatchesCollected` if the sample holds each route
/// of the group and each matches, else `NotChecked`.
fn group_guard(g: &GroupRoutes<'_>) -> RibGuardFlag {
    if g.guards.contains(&RibGuardFlag::DiffersFromCollected) {
        return RibGuardFlag::DiffersFromCollected;
    }
    let whole = g.exact && g.count == g.guards.len() && !g.guards.is_empty();
    if whole
        && g.guards
            .iter()
            .all(|f| *f == RibGuardFlag::MatchesCollected)
    {
        RibGuardFlag::MatchesCollected
    } else {
        RibGuardFlag::NotChecked
    }
}

/// The destination address of a set whose members all have the same known
/// destination address.
fn single_destination(set: &PacketSet) -> Option<IpAddr> {
    let FieldValue::Known(addr) = set.witness()?.current.dst_ip else {
        return None;
    };
    let split = set.split(&RulePredicate::exact(Match {
        dst_ip: AddrCond::In(vec![Prefix::host(addr)]),
        ..Match::any()
    }));
    (split.unmatched.is_empty() && split.uncertain.is_empty()).then_some(addr)
}

/// One neighbour entry, from the collected ARP or neighbour table.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Neighbour {
    pub interface: InterfaceId,
    pub target: NeighbourTarget,
    /// The owner, for the reason text when two owners exist.
    pub owner: String,
    /// The MAC of the neighbour. The resolution sets it as the destination
    /// MAC.
    pub mac: Option<Mac>,
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
    /// The point-to-point interfaces, for example PPPoE or a tunnel, with
    /// the owner of the peer. The next hop on such an interface is always
    /// the peer, so it needs no neighbour entry.
    pub point_to_point: BTreeMap<InterfaceId, String>,
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
            [] => {
                let table = match addr.parse::<IpAddr>() {
                    Ok(IpAddr::V4(_)) => "ARP table",
                    Ok(IpAddr::V6(_)) => "neighbour table",
                    Err(_) => "ARP or neighbour table",
                };
                push_nonempty(
                    out,
                    self.meta.unknown(
                        set,
                        ReasonCode::IncompleteTable,
                        format!(
                            "{addr} not in the {table} of {} on {iface}, table incomplete",
                            self.meta.device
                        ),
                        ctx,
                        state,
                    ),
                );
            }
            [one] => {
                let Some(next) = self.egress.get(iface) else {
                    push_nonempty(
                        out,
                        self.meta.unknown(
                            set,
                            ReasonCode::IncompleteTable,
                            format!("no egress function of {iface}"),
                            ctx,
                            state,
                        ),
                    );
                    return;
                };
                let set = match one.mac {
                    Some(m) => set.rewrite(&Rewrite {
                        dst_mac: Some(FieldValue::Known(m)),
                        ..Rewrite::default()
                    }),
                    None => set,
                };
                let mut c = ctx.clone();
                c.neighbour = Attr::Known(one.target.clone());
                let detail = if self.point_to_point.contains_key(iface) {
                    format!("next hop of {iface}, {}", one.owner)
                } else {
                    format!("{addr}, {} on {iface}", one.owner)
                };
                push_nonempty(
                    out,
                    self.meta
                        .forward(set, next, ReasonCode::Resolved, detail, c, state)
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
                                "{addr} on {iface}, {} owners: {}",
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

    fn each_span(&self, f: &mut dyn FnMut(&rsim_core::SourceSpan)) {
        for s in &self.meta.provenance {
            f(s);
        }
        for (_, v) in self.neighbours.entries() {
            for s in v.iter().flat_map(|n| &n.spans) {
                f(s);
            }
        }
    }

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
                "egress interface or next hop not known",
                ctx,
                state,
            )];
        };
        let mut out = Vec::new();
        if let Some(owner) = self.point_to_point.get(iface) {
            let peer = Neighbour {
                interface: iface.clone(),
                target: NeighbourTarget::Link,
                owner: owner.clone(),
                mac: None,
                spans: self.meta.provenance.clone(),
            };
            self.resolve(
                &mut out,
                "the peer".to_string(),
                &[peer],
                iface,
                input.clone(),
                ctx,
                state,
            );
            return out;
        }
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
                let dest = single_destination(&part.unmatched)
                    .map_or_else(|| "destination".to_string(), |a| a.to_string());
                self.resolve(&mut out, dest, &[], iface, part.unmatched, ctx, state);
                push_nonempty(
                    &mut out,
                    self.meta.unknown(
                        part.uncertain,
                        ReasonCode::UnknownAttribute,
                        "destination address not known",
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
                            "policy {} rule {}, table {action}",
                            self.policy, self.rules[*i].name
                        ),
                        _ => format!("policy {}, no rule, main table", self.policy),
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
                                "policy {} rule {} not handled",
                                self.policy, self.rules[rule].name
                            ),
                        ),
                        UnknownCause::Uncertain { rule } => (
                            ReasonCode::MatchUnknown,
                            format!(
                                "policy {} rule {}, match not known",
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
