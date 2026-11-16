//! Lowering of a VyOS configuration and its collected state into function
//! instances.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use rsim_core::{
    AddrCond, FieldValue, FunctionId, InterfaceId, Mac, Match, NeighbourTarget, NetFunction,
    ObjectId, PortCond, Prefix, PrefixTable, Rewrite, RulePredicate, SourceSpan, TriePrefixTable,
    ValueCond, VrfId, ZoneId,
};
use rsim_engine::EdgeInterface;
use rsim_functions::{
    DestinationNat, DeviceDelivery, Egress, EgressMode, FirewallPolicy, Ingress, Layer3HandOff,
    Link, LocalInput, Meta, NatAction, Neighbour, NextHopResolution, PolicyRoute, QosNotEvaluated,
    Route, RouteKind, RouteLookup, RouteNextHop, Rule as FRule, RuleAction, SessionCommit,
    SessionLookup, SourceNat, Tag, VendorProfile, VrfSelection, ZoneLookup, ZoneRole, ZoneScope,
};

use crate::collected::Collected;
use crate::vyos::config::{Action, Config, Family, Interface, Kind, Lines, RuleMatch, Side};

/// The VRF of all interfaces. VRFs are unhandled.
const VRF: &str = "default";

/// The function instances, the edge interfaces and the notes of one device.
#[derive(Default)]
pub struct Lowered {
    pub functions: Vec<Arc<dyn NetFunction>>,
    pub edges: Vec<EdgeInterface>,
    /// The parts that lowering could not change into a definite function,
    /// with the reason.
    pub notes: Vec<String>,
}

struct L<'a> {
    dev: &'a str,
    file: &'a str,
    profile: &'a VendorProfile,
    cfg: &'a Config,
    out: Lowered,
}

impl L<'_> {
    fn id(&self, f: &str) -> FunctionId {
        FunctionId::new(format!("{}/{f}", self.dev))
    }
    fn span(&self, l: Lines) -> SourceSpan {
        SourceSpan::new(self.file, l.first.max(1), l.last.max(l.first).max(1))
    }
    fn meta(&self, f: &str, spans: Vec<SourceSpan>) -> Meta {
        let mut m = Meta::new(self.id(f), self.dev, self.profile);
        m.provenance = spans;
        m
    }
    fn add(&mut self, f: impl NetFunction + 'static) {
        self.out.functions.push(Arc::new(f));
    }
    fn note(&mut self, s: String) {
        self.out.notes.push(s);
    }
}

/// The addresses of each interface, each with its prefix length and the
/// span of its collected row.
type Addrs = BTreeMap<String, Vec<(IpAddr, u8, Option<SourceSpan>)>>;

/// An interface address: the address and the prefix length.
fn iface_addr(s: &str) -> Option<(IpAddr, u8)> {
    let (a, l) = s.split_once('/')?;
    Some((a.parse().ok()?, l.parse().ok()?))
}

fn max_len(a: IpAddr) -> u8 {
    if a.is_ipv4() { 32 } else { 128 }
}

/// The addresses of each interface: the config, then the collected rows.
fn addresses(cfg: &Config, col: &Collected) -> Addrs {
    let mut m: Addrs = BTreeMap::new();
    for i in &cfg.interfaces {
        let v = m.entry(i.name.clone()).or_default();
        for a in &i.addresses {
            if let Some((ip, len)) = iface_addr(a) {
                v.push((ip, len, None));
            }
        }
    }
    for row in &col.addresses {
        if let Some((ip, len)) = iface_addr(&row.prefix) {
            let v = m.entry(row.interface.clone()).or_default();
            if !v.iter().any(|(a, _, _)| *a == ip) {
                v.push((ip, len, Some(row.span.clone())));
            }
        }
    }
    m
}

/// The layer 2 peer of each physical interface: the ingress function of
/// the switch port on the other end of the link, and the provenance of the
/// link.
pub type Layer2Links = BTreeMap<String, (FunctionId, Vec<SourceSpan>)>;

/// The physical interface and the VLAN of an interface name such as
/// `eth0.10`.
pub fn physical(name: &str) -> (&str, Option<u16>) {
    match name.split_once('.') {
        Some((p, v)) => (p, v.parse().ok()),
        None => (name, None),
    }
}

/// Lowers one VyOS device. `l2` gives the switch port of each physical
/// interface with a layer 2 link.
pub fn lower(
    device: &str,
    file: &str,
    profile: &VendorProfile,
    cfg: &Config,
    col: &Collected,
    l2: &Layer2Links,
) -> Lowered {
    let mut l = L {
        dev: device,
        file,
        profile,
        cfg,
        out: Lowered::default(),
    };
    let active: Vec<&Interface> = cfg
        .interfaces
        .iter()
        .filter(|i| !i.disabled && i.name != "lo")
        .collect();
    let addrs = addresses(cfg, col);
    let local_zone = cfg.zones.iter().find(|z| z.local).map(|z| z.name.clone());
    let has_pbr = cfg.policy_routes.iter().any(|p| !p.rules.is_empty());
    let after_nat = if has_pbr { "pbr" } else { "route" };

    // Ingress, VRF and source zone.
    for i in &active {
        let span = l.span(i.lines);
        let meta = l.meta(&format!("in/{}", i.name), vec![span]);
        l.add(Ingress {
            meta,
            interface: InterfaceId::new(&i.name),
            next: l.id("vrf"),
        });
    }
    let vrf_meta = l.meta("vrf", Vec::new());
    l.add(VrfSelection {
        meta: vrf_meta,
        by_interface: active
            .iter()
            .map(|i| (InterfaceId::new(&i.name), VrfId::new(VRF)))
            .collect(),
        default_vrf: profile.default_vrf.clone(),
        next: l.id("zone-src"),
    });
    let zone_of: BTreeMap<InterfaceId, ZoneId> = cfg
        .zones
        .iter()
        .flat_map(|z| {
            z.members
                .iter()
                .map(move |m| (InterfaceId::new(m), ZoneId::new(&z.name)))
        })
        .collect();
    let zone_spans: Vec<SourceSpan> = cfg.zones.iter().map(|z| l.span(z.lines)).collect();
    for (name, role, next) in [
        ("zone-src", ZoneRole::Source, "session-lookup"),
        ("zone-dst", ZoneRole::Destination, "policy"),
    ] {
        let meta = l.meta(name, zone_spans.clone());
        l.add(ZoneLookup {
            meta,
            role,
            by_interface: zone_of.clone(),
            unzoned: profile.unzoned_interface,
            next: l.id(next),
        });
    }
    let sp = l.span(cfg.state_policy.lines);
    let meta = l.meta("session-lookup", vec![sp.clone()]);
    l.add(SessionLookup {
        meta,
        next: l.id("dnat"),
    });

    // Destination NAT.
    let mut dnat = Vec::new();
    for r in cfg.destination_nat.iter().filter(|r| !r.disabled) {
        let name = format!("dnat/{}", r.number);
        let span = l.span(r.lines);
        if r.matches.inbound_interface.is_some() {
            l.note(format!("{name}: inbound-interface is not lowered"));
            dnat.push(FRule::unhandled(name, span));
            continue;
        }
        let addr = r
            .translation_address
            .as_deref()
            .and_then(|a| a.parse::<IpAddr>().ok());
        match (addr, &r.translation_port) {
            (Some(a), None) => {
                let p = l.predicate(&r.matches, &r.unhandled, None, &name);
                dnat.push(
                    FRule::new(
                        name,
                        p,
                        NatAction::Translate {
                            addr: a,
                            port: rsim_functions::PortTranslation::Preserve,
                        },
                    )
                    .with_span(span),
                );
            }
            _ => {
                l.note(format!("{name}: the translation is not lowered"));
                dnat.push(FRule::unhandled(name, span));
            }
        }
    }
    let meta = l.meta("dnat", Vec::new());
    l.add(DestinationNat {
        meta,
        table: ObjectId::new(format!("{device}:nat:destination")),
        rules: dnat,
        next: l.id(after_nat),
    });

    // Policy routes and route tables.
    let main = l.id("route");
    let mut tables: BTreeSet<String> = BTreeSet::new();
    if has_pbr {
        let mut rules = Vec::new();
        let mut spans = Vec::new();
        for p in &cfg.policy_routes {
            spans.push(l.span(p.lines));
            let scope: BTreeSet<InterfaceId> = p.interfaces.iter().map(InterfaceId::new).collect();
            for r in p.rules.iter().filter(|r| !r.disabled) {
                let name = format!("{}/{}", p.name, r.number);
                let span = l.span(r.lines);
                let target = match r.table.as_deref() {
                    Some("main") => Some(main.clone()),
                    Some(t) if t.parse::<u32>().is_ok() => {
                        tables.insert(t.to_string());
                        Some(l.id(&format!("route-table-{t}")))
                    }
                    _ => None,
                };
                let rule = match target {
                    Some(t) => {
                        let pr = l.predicate(&r.matches, &r.unhandled, None, &name);
                        FRule::new(name, pr, t).with_span(span)
                    }
                    None => {
                        l.note(format!("{name}: the action is not a route table"));
                        FRule::unhandled(name, span)
                    }
                };
                rules.push((Some(scope.clone()), rule));
            }
        }
        let meta = l.meta("pbr", spans);
        l.add(PolicyRoute::new(
            meta,
            ObjectId::new(format!("{device}:policy:route")),
            rules,
            main.clone(),
        ));
    }
    let local_routes = local_routes(&addrs);
    let main_fib = l.main_fib(col, &addrs, &local_routes);
    let local_id = l.id("local");
    let meta = l.meta("route", Vec::new());
    l.add(RouteLookup {
        meta,
        tables: BTreeMap::from([(VrfId::new(VRF), main_fib)]),
        fallback: None,
        local: Some(local_id.clone()),
    });
    for t in &tables {
        let fib = l.table_fib(t, &addrs, &local_routes);
        let meta = l.meta(&format!("route-table-{t}"), Vec::new());
        l.add(RouteLookup {
            meta,
            tables: BTreeMap::from([(VrfId::new(VRF), fib)]),
            fallback: Some(main.clone()),
            local: Some(local_id.clone()),
        });
    }

    // Zone policy, the local input and the delivery to the router.
    let (forward_rules, local_rules) = l.zone_rules(local_zone.as_deref());
    let meta = l.meta("policy", zone_spans.clone());
    l.add(FirewallPolicy::new(
        meta,
        ObjectId::new(format!("{device}:firewall:zone")),
        forward_rules,
        profile.firewall_default,
        l.id("snat"),
    ));
    let meta = l.meta("local", zone_spans.clone());
    l.add(LocalInput {
        meta,
        zone: local_zone.as_deref().map(ZoneId::new),
        next: l.id(if local_zone.is_some() {
            "policy-local"
        } else {
            "deliver"
        }),
    });
    if local_zone.is_some() {
        let meta = l.meta("policy-local", zone_spans);
        l.add(FirewallPolicy::new(
            meta,
            ObjectId::new(format!("{device}:firewall:zone:local")),
            local_rules,
            profile.firewall_default,
            l.id("deliver"),
        ));
    }
    let meta = l.meta("deliver", Vec::new());
    l.add(DeviceDelivery { meta });

    // Source NAT.
    let mut snat = Vec::new();
    for r in cfg.source_nat.iter().filter(|r| !r.disabled) {
        let name = format!("snat/{}", r.number);
        let span = l.span(r.lines);
        let out_if = r.matches.outbound_interface.clone();
        let addr = match r.translation_address.as_deref() {
            Some("masquerade") => out_if.as_ref().and_then(|i| {
                addrs
                    .get(i)
                    .and_then(|v| v.iter().find(|(a, _, _)| a.is_ipv4()).map(|x| x.0))
            }),
            Some(a) => a.parse::<IpAddr>().ok(),
            None => None,
        };
        let scope = out_if
            .as_ref()
            .map(|i| BTreeSet::from([InterfaceId::new(i)]));
        let rule = match addr {
            Some(a) if r.translation_port.is_none() => {
                let mut m = r.matches.clone();
                m.outbound_interface = None;
                let p = l.predicate(&m, &r.unhandled, Some(Family::V4), &name);
                FRule::new(
                    name,
                    p,
                    NatAction::Translate {
                        addr: a,
                        port: profile.snat_port,
                    },
                )
                .with_span(span)
            }
            _ => {
                l.note(format!(
                    "{name}: the translation address of {} is not known",
                    out_if.as_deref().unwrap_or("the rule")
                ));
                FRule::unhandled(name, span)
            }
        };
        snat.push((scope, rule));
    }
    let meta = l.meta("snat", Vec::new());
    l.add(SourceNat::new(
        meta,
        ObjectId::new(format!("{device}:nat:source")),
        snat,
        l.id("session-commit"),
    ));
    let meta = l.meta("session-commit", vec![sp]);
    l.add(SessionCommit {
        meta,
        next: l.id("nexthop"),
    });

    // Next hops, QoS and egress.
    let mut neighbours: TriePrefixTable<Vec<Neighbour>> = TriePrefixTable::new();
    for n in &col.neighbours {
        let failed = n
            .state
            .as_deref()
            .is_some_and(|s| s.contains("FAILED") || s.contains("INCOMPLETE"));
        let Ok(ip) = n.ip.parse::<IpAddr>() else {
            continue;
        };
        if failed || n.mac.is_none() {
            continue;
        }
        let p = Prefix::host(ip);
        let mut v = neighbours.get(&p).cloned().unwrap_or_default();
        v.push(Neighbour {
            interface: InterfaceId::new(&n.interface),
            target: NeighbourTarget::Link,
            owner: n.mac.clone().unwrap_or_default(),
            mac: n.mac.as_deref().and_then(|m| m.parse().ok()),
            spans: vec![n.span.clone()],
        });
        neighbours.insert(p, v);
    }
    let qos: BTreeMap<&str, &crate::vyos::config::Qos> = cfg
        .qos
        .iter()
        .filter(|q| q.direction == "egress")
        .map(|q| (q.interface.as_str(), q))
        .collect();
    let meta = l.meta("nexthop", Vec::new());
    l.add(NextHopResolution {
        meta,
        neighbours,
        complete: false,
        egress: active
            .iter()
            .map(|i| {
                let f = if qos.contains_key(i.name.as_str()) {
                    format!("qos/{}", i.name)
                } else {
                    format!("out/{}", i.name)
                };
                (InterfaceId::new(&i.name), l.id(&f))
            })
            .collect(),
        point_to_point: active
            .iter()
            .filter(|i| matches!(i.kind, Kind::Pppoe | Kind::Wireguard))
            .map(|i| (InterfaceId::new(&i.name), format!("the peer of {}", i.name)))
            .collect(),
    });
    for i in &active {
        if let Some(q) = qos.get(i.name.as_str()) {
            let span = l.span(q.lines);
            let meta = l.meta(&format!("qos/{}", i.name), vec![span]);
            l.add(QosNotEvaluated {
                meta,
                stanza: ObjectId::new(format!("{device}:qos:{}", q.policy)),
                next: l.id(&format!("out/{}", i.name)),
            });
        }
        let span = l.span(i.lines);
        let meta = l.meta(&format!("out/{}", i.name), vec![span]);
        let (phys, vlan) = physical(&i.name);
        let joined = l2.get(phys).zip(interface_mac(col, phys));
        let (link, rewrite, tag) = match joined {
            Some(((peer, prov), m)) => (
                Some(Link {
                    peer: Some(peer.clone()),
                    delay_ns: None,
                    provenance: prov.clone(),
                }),
                Rewrite {
                    src_mac: Some(FieldValue::Known(m)),
                    ..Rewrite::default()
                },
                vlan.map_or(Tag::Untagged, Tag::Vlan),
            ),
            None => (None, Rewrite::default(), Tag::Keep),
        };
        l.add(Egress {
            meta,
            interface: InterfaceId::new(&i.name),
            mode: EgressMode::Routed,
            link,
            rewrite,
            tag,
        });
    }
    for (phys, (_, prov)) in l2 {
        let Some(m) = interface_mac(col, phys) else {
            l.note(format!(
                "{phys}: no collected MAC, so the layer 2 link is not lowered"
            ));
            continue;
        };
        let has = |n: &str| active.iter().any(|i| i.name == n);
        let meta = l.meta(&format!("handoff/{phys}"), prov.clone());
        l.add(Layer3HandOff {
            meta,
            macs: BTreeSet::from([m]),
            untagged: has(phys).then(|| l.id(&format!("in/{phys}"))),
            tagged: active
                .iter()
                .filter_map(|i| match physical(&i.name) {
                    (p, Some(v)) if p == phys => Some((v, l.id(&format!("in/{}", i.name)))),
                    _ => None,
                })
                .collect(),
        });
    }

    // Edge interfaces: each interface with a connected network.
    for i in &active {
        let nets: Vec<Prefix> = addrs
            .get(&i.name)
            .map(|v| {
                v.iter()
                    .filter(|(a, len, _)| *len < max_len(*a))
                    .map(|(a, len, _)| Prefix::new(*a, *len))
                    .collect()
            })
            .unwrap_or_default();
        if !nets.is_empty() {
            l.out.edges.push(EdgeInterface {
                device: device.into(),
                interface: InterfaceId::new(&i.name),
                networks: nets,
                provenance: vec![l.span(i.lines)],
            });
        }
    }
    l.out
}

/// The addresses of each interface with their prefix length: the config,
/// then the collected rows.
pub fn interface_addresses(cfg: &Config, col: &Collected) -> BTreeMap<String, Vec<(IpAddr, u8)>> {
    addresses(cfg, col)
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().map(|(a, l, _)| (a, l)).collect()))
        .collect()
}

/// The collected MAC of an interface.
pub fn interface_mac(col: &Collected, iface: &str) -> Option<Mac> {
    col.links
        .iter()
        .find(|r| r.interface == iface)
        .and_then(|r| r.mac.as_deref())
        .and_then(|m| m.parse().ok())
}

/// The local routes: one host route for each interface address.
fn local_routes(addrs: &Addrs) -> Vec<(Prefix, Route)> {
    let mut v = Vec::new();
    for list in addrs.values() {
        for (a, _, span) in list {
            v.push((
                Prefix::host(*a),
                Route::new(RouteKind::Local, Vec::new(), span.iter().cloned().collect()),
            ));
        }
    }
    v
}

impl L<'_> {
    fn hop(&self, interface: &str, gateway: Option<IpAddr>) -> RouteNextHop {
        RouteNextHop {
            interface: InterfaceId::new(interface),
            gateway,
            next: self.id("zone-dst"),
        }
    }

    fn connected(&self, t: &mut TriePrefixTable<Route>, addrs: &Addrs) {
        for (iface, list) in addrs {
            for (a, len, span) in list {
                if *len < max_len(*a) {
                    t.insert(
                        Prefix::new(*a, *len),
                        Route::new(
                            RouteKind::Connected,
                            vec![self.hop(iface, None)],
                            span.iter().cloned().collect(),
                        ),
                    );
                }
            }
        }
    }

    /// The main FIB: the collected RIB, or else the connected and static
    /// routes of the config. The local routes are always in it.
    fn main_fib(
        &mut self,
        col: &Collected,
        addrs: &Addrs,
        locals: &[(Prefix, Route)],
    ) -> TriePrefixTable<Route> {
        let mut t = TriePrefixTable::new();
        let rib: Vec<_> = col
            .routes
            .iter()
            .filter(|r| r.selected && r.vrf == VRF)
            .collect();
        if rib.is_empty() {
            self.connected(&mut t, addrs);
            let statics: Vec<_> = self
                .cfg
                .static_routes
                .iter()
                .filter(|r| r.table.is_none())
                .cloned()
                .collect();
            for r in &statics {
                self.static_route(&mut t, r, addrs);
            }
        } else {
            let mut by_prefix: BTreeMap<String, Vec<&crate::collected::RouteRow>> = BTreeMap::new();
            for r in rib {
                by_prefix.entry(r.prefix.clone()).or_default().push(r);
            }
            for (prefix, rows) in by_prefix {
                let Ok(p) = prefix.parse::<Prefix>() else {
                    self.note(format!("route {prefix}: the prefix is not valid"));
                    continue;
                };
                let spans: Vec<SourceSpan> = rows.iter().map(|r| r.span.clone()).collect();
                let kind = match rows[0].protocol.as_str() {
                    "connected" => RouteKind::Connected,
                    "local" => RouteKind::Local,
                    _ => RouteKind::Static,
                };
                if kind == RouteKind::Local {
                    t.insert(p, Route::new(kind, Vec::new(), spans));
                    continue;
                }
                let hops: Vec<RouteNextHop> = rows
                    .iter()
                    .filter_map(|r| {
                        let gw = r.next_hop.as_deref().and_then(|g| g.parse().ok());
                        r.interface.as_deref().map(|i| self.hop(i, gw))
                    })
                    .collect();
                if hops.is_empty() {
                    self.note(format!("route {prefix}: no next hop with an interface"));
                    continue;
                }
                t.insert(p, Route::new(kind, hops, spans));
            }
        }
        for (p, r) in locals {
            t.insert(*p, r.clone());
        }
        t
    }

    /// The FIB of a policy route table: its static routes and the local
    /// routes.
    fn table_fib(
        &mut self,
        table: &str,
        addrs: &Addrs,
        locals: &[(Prefix, Route)],
    ) -> TriePrefixTable<Route> {
        let mut t = TriePrefixTable::new();
        let statics: Vec<_> = self
            .cfg
            .static_routes
            .iter()
            .filter(|r| r.table.as_deref() == Some(table))
            .cloned()
            .collect();
        for r in &statics {
            self.static_route(&mut t, r, addrs);
        }
        for (p, r) in locals {
            t.insert(*p, r.clone());
        }
        t
    }

    fn static_route(
        &mut self,
        t: &mut TriePrefixTable<Route>,
        r: &crate::vyos::config::StaticRoute,
        addrs: &Addrs,
    ) {
        let Ok(p) = r.prefix.parse::<Prefix>() else {
            self.note(format!(
                "static route {}: the prefix is not valid",
                r.prefix
            ));
            return;
        };
        let span = vec![self.span(r.lines)];
        if !r.unhandled.is_empty() {
            self.note(format!(
                "static route {}: options not lowered: {}",
                r.prefix,
                r.unhandled.join(", ")
            ));
        }
        if r.blackhole {
            t.insert(p, Route::new(RouteKind::Null, Vec::new(), span));
            return;
        }
        let mut hops: Vec<RouteNextHop> = r.interfaces.iter().map(|i| self.hop(i, None)).collect();
        for g in &r.gateways {
            let Ok(gw) = g.parse::<IpAddr>() else {
                continue;
            };
            let iface = addrs.iter().find(|(_, v)| {
                v.iter()
                    .any(|(a, len, _)| *len < max_len(*a) && Prefix::new(*a, *len).contains(gw))
            });
            match iface {
                Some((i, _)) => hops.push(self.hop(i, Some(gw))),
                None => self.note(format!(
                    "static route {}: gateway {gw} is on no connected network",
                    r.prefix
                )),
            }
        }
        if !hops.is_empty() {
            t.insert(p, Route::new(RouteKind::Static, hops, span));
        }
    }

    /// The rules of the zone policy: the forward rules and the rules to the
    /// local zone.
    #[allow(clippy::type_complexity)]
    fn zone_rules(
        &mut self,
        local: Option<&str>,
    ) -> (
        Vec<(ZoneScope, FRule<RuleAction>)>,
        Vec<(ZoneScope, FRule<RuleAction>)>,
    ) {
        let mut forward = Vec::new();
        let mut to_local = Vec::new();
        let zones = self.cfg.zones.clone();
        for to in &zones {
            let out = if Some(to.name.as_str()) == local {
                &mut to_local
            } else {
                &mut forward
            };
            let mut pairs = Vec::new();
            for f in &to.from {
                let scope = ZoneScope::between(&f.from, &to.name);
                for (family, name) in [(Family::V4, &f.ipv4), (Family::V6, &f.ipv6)] {
                    match name {
                        Some(n) => pairs.extend(self.rule_set(family, n).into_iter().map(
                            |(ingress, egress, r)| {
                                let s = ZoneScope {
                                    ingress,
                                    egress,
                                    ..scope.clone()
                                };
                                (s, r)
                            },
                        )),
                        None => {
                            // No rule set for this family: the zone default.
                            let name =
                                format!("zone {} from {} {family:?} default", to.name, f.from);
                            let r = self.zone_default(to, &name, Some(family));
                            pairs.push((scope.clone(), r));
                        }
                    }
                }
            }
            if !to.local {
                let scope = ZoneScope::between(&to.name, &to.name);
                let name = format!("zone {} intra-zone", to.name);
                let span = self.span(to.lines);
                let r = match &to.intra_zone {
                    Some(Action::Accept) => {
                        FRule::new(name, RulePredicate::exact(Match::any()), RuleAction::Permit)
                            .with_span(span)
                    }
                    Some(Action::Drop | Action::Reject) => {
                        FRule::new(name, RulePredicate::exact(Match::any()), RuleAction::Deny)
                            .with_span(span)
                    }
                    Some(Action::Other(a)) => {
                        self.note(format!("{name}: action {a} is not lowered"));
                        FRule::unhandled(name, span)
                    }
                    None => match self.profile.intra_zone_default {
                        Some(a) => {
                            FRule::new(name, RulePredicate::exact(Match::any()), a).with_span(span)
                        }
                        None => {
                            self.note(format!("{name}: the action is not known"));
                            FRule::unhandled(name, span)
                        }
                    },
                };
                pairs.push((scope, r));
            }
            // The packets of the other source zones: the zone default.
            let scope = ZoneScope {
                from: None,
                to: Some(BTreeSet::from([ZoneId::new(&to.name)])),
                ingress: None,
                egress: None,
            };
            let name = format!("zone {} default", to.name);
            let r = self.zone_default(to, &name, None);
            pairs.push((scope, r));
            out.extend(pairs);
        }
        (forward, to_local)
    }

    fn zone_default(
        &mut self,
        zone: &crate::vyos::config::Zone,
        name: &str,
        family: Option<Family>,
    ) -> FRule<RuleAction> {
        let span = self.span(zone.lines);
        let action = match &zone.default_action {
            Some(Action::Accept) => RuleAction::Permit,
            Some(Action::Drop | Action::Reject) => RuleAction::Deny,
            Some(Action::Other(a)) => {
                self.note(format!("{name}: action {a} is not lowered"));
                return FRule::unhandled(name.to_string(), span);
            }
            None => self.profile.firewall_default,
        };
        FRule::new(
            name.to_string(),
            RulePredicate::exact(family_match(family)),
            action,
        )
        .with_span(span)
    }

    /// The rules of a rule set, with its default action as the last rule.
    /// Each rule has the ingress and the egress interfaces of its
    /// `inbound-interface` and `outbound-interface` options.
    fn rule_set(&mut self, family: Family, name: &str) -> Vec<ScopedRule> {
        let Some(rs) = self.cfg.rule_set(family, name).cloned() else {
            let msg = format!("rule set {name} does not exist");
            self.note(msg.clone());
            return vec![(
                None,
                None,
                FRule::unhandled(msg, SourceSpan::new(self.file, 1, 1)),
            )];
        };
        let mut out = Vec::new();
        for r in rs.rules.iter().filter(|r| !r.disabled) {
            let rname = format!("{name}/{}", r.number);
            let span = self.span(r.lines);
            if !r.matches.state.is_empty() && !r.matches.state.iter().any(|s| s == "new") {
                // The rule matches only packets of a session. The session
                // lookup passes these before the policy.
                continue;
            }
            let action = match r.action {
                Some(Action::Accept) => RuleAction::Permit,
                Some(Action::Drop | Action::Reject) => RuleAction::Deny,
                ref a => {
                    self.note(format!("{rname}: action {a:?} is not lowered"));
                    out.push((None, None, FRule::unhandled(rname, span)));
                    continue;
                }
            };
            let mut m = r.matches.clone();
            let ingress = interface_scope(&mut m.inbound_interface);
            let egress = interface_scope(&mut m.outbound_interface);
            let p = self.predicate(&m, &r.unhandled, Some(family), &rname);
            out.push((
                ingress,
                egress,
                FRule::new(rname, p, action).with_span(span),
            ));
        }
        let dname = format!("{name}/default");
        let span = self.span(rs.lines);
        let all = RulePredicate::exact(family_match(Some(family)));
        let rule = match rs.default_action {
            Some(Action::Accept) => FRule::new(dname, all, RuleAction::Permit).with_span(span),
            Some(Action::Drop | Action::Reject) => {
                FRule::new(dname, all, RuleAction::Deny).with_span(span)
            }
            _ => {
                self.note(format!("{dname}: the default action is not known"));
                FRule::unhandled(dname, span)
            }
        };
        out.push((None, None, rule));
        out
    }

    /// The predicate of a rule. An option that cannot be lowered gives match
    /// bounds: the rule matches nothing for certain, and at most the packets
    /// of its other options.
    fn predicate(
        &mut self,
        m: &RuleMatch,
        unhandled: &[String],
        family: Option<Family>,
        name: &str,
    ) -> RulePredicate {
        let mut problems: Vec<String> = unhandled.to_vec();
        let mut upper = family_match(family);
        let mut set = |r: Result<(), String>| {
            if let Err(e) = r {
                problems.push(e);
            }
        };
        set(protocol(m.protocol.as_deref()).map(|v| upper.protocol = v));
        set(self.side_addr(&m.source).map(|v| {
            if let Some(v) = v {
                upper.src_ip = v;
            }
        }));
        set(self.side_addr(&m.destination).map(|v| {
            if let Some(v) = v {
                upper.dst_ip = v;
            }
        }));
        set(self.side_port(&m.source).map(|v| upper.src_port = v));
        set(self.side_port(&m.destination).map(|v| upper.dst_port = v));
        if m.inbound_interface.is_some() {
            problems.push("inbound-interface".into());
        }
        if m.outbound_interface.is_some() {
            problems.push("outbound-interface".into());
        }
        if m.icmp_type_name.is_some() {
            problems.push("icmp type-name".into());
        }
        if problems.is_empty() {
            RulePredicate::exact(upper)
        } else {
            self.note(format!("{name}: match bounds for {}", problems.join(", ")));
            let nothing = Match {
                src_ip: AddrCond::In(Vec::new()),
                ..Match::any()
            };
            RulePredicate::bounded(nothing, upper)
        }
    }

    fn side_addr(&self, s: &Side) -> Result<Option<AddrCond>, String> {
        let mut items: Vec<String> = Vec::new();
        let mut any = false;
        if let Some(a) = &s.address {
            items.push(a.clone());
            any = true;
        }
        for (g, map) in [
            (&s.address_group, &self.cfg.address_groups),
            (&s.network_group, &self.cfg.network_groups),
        ] {
            if let Some(g) = g {
                if any {
                    return Err("an address and a group".into());
                }
                any = true;
                items.extend(
                    map.get(g)
                        .ok_or_else(|| format!("group {g} does not exist"))?
                        .iter()
                        .cloned(),
                );
            }
        }
        if !any {
            return Ok(None);
        }
        let mut prefixes = Vec::new();
        for i in items {
            prefixes.extend(address_spec(&i)?);
        }
        Ok(Some(AddrCond::In(prefixes)))
    }

    fn side_port(&self, s: &Side) -> Result<PortCond, String> {
        let mut items: Vec<String> = Vec::new();
        if let Some(p) = &s.port {
            items.extend(p.split(',').map(str::to_string));
        }
        if let Some(g) = &s.port_group {
            items.extend(
                self.cfg
                    .port_groups
                    .get(g)
                    .ok_or_else(|| format!("port group {g} does not exist"))?
                    .iter()
                    .cloned(),
            );
        }
        if items.is_empty() {
            return Ok(PortCond::Any);
        }
        let mut ranges = Vec::new();
        for i in items {
            let i = i.trim();
            let (a, b) = i.split_once('-').unwrap_or((i, i));
            let a: u16 = a.parse().map_err(|_| format!("port {i}"))?;
            let b: u16 = b.parse().map_err(|_| format!("port {i}"))?;
            ranges.push((a.min(b), a.max(b)));
        }
        Ok(PortCond::In(ranges))
    }
}

/// A rule with its ingress and egress interfaces.
type ScopedRule = (
    Option<BTreeSet<InterfaceId>>,
    Option<BTreeSet<InterfaceId>>,
    FRule<RuleAction>,
);

/// The interface set of an `inbound-interface` or `outbound-interface`
/// option, which it takes from the match. A name with a wildcard stays in
/// the match, where it gives match bounds.
fn interface_scope(name: &mut Option<String>) -> Option<BTreeSet<InterfaceId>> {
    let n = name.as_deref()?;
    if n.contains(['*', '+', '!']) {
        return None;
    }
    let set = BTreeSet::from([InterfaceId::new(n)]);
    *name = None;
    Some(set)
}

/// A match of all packets of a family, or of all packets.
fn family_match(family: Option<Family>) -> Match {
    let all = |s: &str| AddrCond::In(vec![s.parse().expect("a valid prefix")]);
    match family {
        Some(Family::V4) => Match {
            src_ip: all("0.0.0.0/0"),
            ..Match::any()
        },
        Some(Family::V6) => Match {
            src_ip: all("::/0"),
            ..Match::any()
        },
        None => Match::any(),
    }
}

fn protocol(p: Option<&str>) -> Result<ValueCond, String> {
    let set = |v: &[u8]| Ok(ValueCond::In(v.iter().copied().collect()));
    match p {
        None | Some("all") => Ok(ValueCond::Any),
        Some("tcp") => set(&[6]),
        Some("udp") => set(&[17]),
        Some("tcp_udp") => set(&[6, 17]),
        Some("icmp") => set(&[1]),
        Some("ipv6-icmp" | "icmpv6") => set(&[58]),
        Some("gre") => set(&[47]),
        Some("esp") => set(&[50]),
        Some(other) => other
            .parse::<u8>()
            .map(|n| ValueCond::In([n].into_iter().collect()))
            .map_err(|_| format!("protocol {other}")),
    }
}

/// The prefixes of an address, a prefix or a range `a-b`.
fn address_spec(s: &str) -> Result<Vec<Prefix>, String> {
    if s.starts_with('!') {
        return Err(format!("negated address {s}"));
    }
    if let Some((a, b)) = s.split_once('-') {
        let a: IpAddr = a.parse().map_err(|_| format!("address {s}"))?;
        let b: IpAddr = b.parse().map_err(|_| format!("address {s}"))?;
        return range_prefixes(a, b).ok_or_else(|| format!("address range {s}"));
    }
    s.parse::<Prefix>()
        .map(|p| vec![p])
        .map_err(|_| format!("address {s}"))
}

/// The smallest set of prefixes that covers the addresses from `a` to `b`.
fn range_prefixes(a: IpAddr, b: IpAddr) -> Option<Vec<Prefix>> {
    let (lo, hi, bits, v4) = match (a, b) {
        (IpAddr::V4(x), IpAddr::V4(y)) => (
            u128::from(u32::from(x)),
            u128::from(u32::from(y)),
            32u32,
            true,
        ),
        (IpAddr::V6(x), IpAddr::V6(y)) => (u128::from(x), u128::from(y), 128u32, false),
        _ => return None,
    };
    if lo > hi {
        return None;
    }
    let mut out = Vec::new();
    let mut cur = lo;
    loop {
        let mut size = if cur == 0 {
            bits
        } else {
            cur.trailing_zeros().min(bits)
        };
        while size > 0 && (size >= 128 || cur + ((1u128 << size) - 1) > hi) {
            size -= 1;
        }
        let addr = if v4 {
            IpAddr::V4(std::net::Ipv4Addr::from(u32::try_from(cur).ok()?))
        } else {
            IpAddr::V6(std::net::Ipv6Addr::from(cur))
        };
        out.push(Prefix::new(addr, u8::try_from(bits - size).ok()?));
        let step = if size >= 128 {
            return Some(out);
        } else {
            1u128 << size
        };
        match cur.checked_add(step) {
            Some(n) if n <= hi => cur = n,
            _ => break,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_gives_the_covering_prefixes() {
        let p = |v: Vec<Prefix>| {
            v.iter()
                .map(|p| format!("{}/{}", p.addr(), p.len()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            p(address_spec("192.0.2.20-192.0.2.23").unwrap()),
            ["192.0.2.20/30"]
        );
        assert_eq!(
            p(address_spec("192.0.2.1-192.0.2.6").unwrap()),
            [
                "192.0.2.1/32",
                "192.0.2.2/31",
                "192.0.2.4/31",
                "192.0.2.6/32"
            ]
        );
        assert_eq!(p(address_spec("192.0.2.9").unwrap()), ["192.0.2.9/32"]);
        assert!(address_spec("!192.0.2.9").is_err());
        assert!(address_spec("192.0.2.9-192.0.2.1").is_err());
    }
}
