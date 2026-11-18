//! Lowering of a VyOS configuration and its collected state into function
//! instances.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use rsim_core::{
    AddrCond, Attr, FieldValue, FunctionId, InterfaceId, Mac, Match, NeighbourTarget, NetFunction,
    ObjectId, PortCond, Prefix, PrefixTable, Rewrite, RulePredicate, SourceSpan, TriePrefixTable,
    ValueCond, VrfId, ZoneId,
};
use rsim_engine::EdgeInterface;
use rsim_functions::{
    ConnState, DestinationNat, DeviceDelivery, Egress, EgressMode, ExitMark, Fib, FirewallPolicy,
    Ingress, Layer3HandOff, Link, LinkEnd, LinkFacts, LocalInput, Meta, NatAction, Neighbour,
    NextHopResolution, PolicyRoute, QosNotEvaluated, Route, RouteKind, RouteLookup, RouteNextHop,
    Rule as FRule, RuleAction, SessionCommit, SessionLookup, SourceNat, StateAction, StateActions,
    Tag, VendorProfile, VrfSelection, WireguardEncap, WireguardPeer, WireguardSettings, ZoneLookup,
    ZoneRole, ZoneScope,
};

use crate::collected::Collected;
use crate::resolve::{Origin, Path, Resolver, Target, through_default};
use crate::route_tables::{TABLE_NOT_COLLECTED, route_kind};
use crate::vyos::config::{Action, Config, Family, Interface, Kind, Lines, RuleMatch, Side};

/// The default VRF. It is the only VRF with a route table, so the packets
/// of an interface in another VRF are unknown at the route lookup.
const VRF: &str = "default";

/// The zone of an interface that is in no firewall zone.
pub const NO_ZONE: &str = "(no zone)";

/// The function instances, the edge interfaces, the endpoints, the
/// attachment records and the notes of one device.
#[derive(Default)]
pub struct Lowered {
    pub functions: Vec<Arc<dyn NetFunction>>,
    pub edges: Vec<EdgeInterface>,
    pub endpoints: Vec<rsim_engine::Endpoint>,
    pub attachments: Vec<rsim_engine::AttachmentRecord>,
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
/// the switch port on the other end of the link, the provenance of the
/// link, and the physical facts of the switch port.
pub type Layer2Links = BTreeMap<String, (FunctionId, Vec<SourceSpan>, Option<LinkEnd>)>;

/// The physical facts of an interface from the collected link speeds.
pub fn interface_facts(col: &Collected, iface: &str) -> Option<LinkEnd> {
    let r = col.speeds.iter().find(|r| r.interface == iface)?;
    Some(LinkEnd {
        speed_mbps: r.mbps,
        full_duplex: r.duplex.as_deref().map(|d| d == "full"),
        media: None,
        spans: vec![r.span.clone()],
    })
}

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
    twin: &BTreeSet<IpAddr>,
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
    // The addresses of the interfaces of the default VRF.
    let main_addrs: Addrs = addrs
        .iter()
        .filter(|(n, _)| {
            !cfg.interfaces
                .iter()
                .any(|i| i.name == **n && i.vrf.is_some())
        })
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect();
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
            .map(|i| {
                let vrf = i.vrf.as_deref().unwrap_or(VRF);
                (InterfaceId::new(&i.name), VrfId::new(vrf))
            })
            .collect(),
        default_vrf: profile.default_vrf.clone(),
        next: l.id("zone-src"),
    });
    let mut zone_of: BTreeMap<InterfaceId, ZoneId> = cfg
        .zones
        .iter()
        .flat_map(|z| {
            z.members
                .iter()
                .map(move |m| (InterfaceId::new(m), ZoneId::new(&z.name)))
        })
        .collect();
    // An interface of a VRF that a zone names with `member vrf` gets no
    // zone, so its zone is unknown.
    let zone_vrfs: BTreeSet<&str> = cfg
        .zones
        .iter()
        .flat_map(|z| z.member_vrfs.iter().map(String::as_str))
        .collect();
    for i in &active {
        if i.vrf.as_deref().is_some_and(|v| zone_vrfs.contains(v)) {
            l.note(format!(
                "{}: the zone of VRF {} is not lowered",
                i.name,
                i.vrf.as_deref().unwrap_or_default()
            ));
            continue;
        }
        zone_of
            .entry(InterfaceId::new(&i.name))
            .or_insert_with(|| ZoneId::new(NO_ZONE));
    }
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
    let states = l.state_actions();
    let meta = l.meta("session-lookup", vec![sp.clone()]);
    l.add(SessionLookup {
        meta,
        next: l.id("dnat"),
        states,
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
        ingress: Vec::new(),
        next: l.id(after_nat),
    });

    // Policy routes and route tables.
    let main = l.id("route");
    let mut tables: BTreeSet<String> = BTreeSet::new();
    if has_pbr {
        let mut rules = Vec::new();
        let mut spans = Vec::new();
        for p in cfg.policy_routes.iter().filter(|p| p.family == Family::V4) {
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
                        let pr = l.predicate(&r.matches, &r.unhandled, Some(Family::V4), &name);
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
        // An IPv6 policy is not lowered: the IPv4 packets of its interfaces
        // go on to the main table, and its IPv6 packets are unknown.
        for p in cfg
            .policy_routes
            .iter()
            .filter(|p| p.family == Family::V6 && !p.rules.is_empty())
        {
            let span = l.span(p.lines);
            spans.push(span.clone());
            l.note(format!("policy route6 {}: not lowered", p.name));
            let scope: BTreeSet<InterfaceId> = p.interfaces.iter().map(InterfaceId::new).collect();
            let v4 = RulePredicate::exact(family_match(Some(Family::V4)));
            let name = format!("route6 {}", p.name);
            rules.push((
                Some(scope.clone()),
                FRule::new(format!("{name} IPv4"), v4, main.clone()).with_span(span.clone()),
            ));
            rules.push((Some(scope), FRule::unhandled(name, span)));
        }
        let meta = l.meta("pbr", spans);
        l.add(PolicyRoute::new(
            meta,
            ObjectId::new(format!("{device}:policy:route")),
            rules,
            main.clone(),
        ));
    }
    let local_routes = local_routes(&main_addrs);
    let main_fib = l.main_fib(col, &main_addrs, &local_routes);
    let exits = exit_marks(&active, &main_fib, twin, &addrs);
    let wireguard: Vec<WireguardEncap> = active
        .iter()
        .filter(|i| i.kind == Kind::Wireguard)
        .map(|i| l.wireguard(i, &main_fib, &main_addrs, local_zone.as_deref()))
        .collect();
    let local_id = l.id("local");
    let meta = l.meta("route", Vec::new());
    l.add(RouteLookup {
        meta,
        tables: BTreeMap::from([(VrfId::new(VRF), main_fib)]),
        fallback: None,
        local: Some(local_id.clone()),
    });
    for t in &tables {
        let fib = l.table_fib(t, &main_addrs, &local_routes);
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
    // With no action of the state policy for established packets, the
    // rules evaluate the packets of a session.
    let evaluate = |p: FirewallPolicy| {
        if states.established == StateAction::Continue {
            p.evaluating_sessions()
        } else {
            p
        }
    };
    let meta = l.meta("policy", zone_spans.clone());
    l.add(evaluate(FirewallPolicy::new(
        meta,
        ObjectId::new(format!("{device}:firewall:zone")),
        forward_rules,
        profile.firewall_default,
        l.id("snat"),
    )));
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
        l.add(evaluate(FirewallPolicy::new(
            meta,
            ObjectId::new(format!("{device}:firewall:zone:local")),
            local_rules,
            profile.firewall_default,
            l.id("deliver"),
        )));
    }
    let meta = l.meta("deliver", Vec::new());
    l.add(DeviceDelivery { meta });

    // Source NAT.
    let mut snat = Vec::new();
    for r in cfg.source_nat.iter().filter(|r| !r.disabled) {
        let name = format!("snat/{}", r.number);
        let span = l.span(r.lines);
        let mut m = r.matches.clone();
        let scope = interface_scope(&mut m.outbound_interface);
        let out_if = scope
            .as_ref()
            .and_then(|_| r.matches.outbound_interface.clone());
        let addr = match r.translation_address.as_deref() {
            Some("masquerade") => out_if.as_ref().and_then(|i| {
                addrs
                    .get(i)
                    .and_then(|v| v.iter().find(|(a, _, _)| a.is_ipv4()).map(|x| x.0))
            }),
            Some(a) => a.parse::<IpAddr>().ok(),
            None => None,
        };
        let rule = match addr {
            Some(a) if r.translation_port.is_none() => {
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
        keep_untranslated: true,
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
                    out_name(i)
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
                next: l.id(&out_name(i)),
            });
        }
        if i.kind == Kind::Wireguard {
            continue;
        }
        let span = l.span(i.lines);
        let meta = l.meta(&format!("out/{}", i.name), vec![span]);
        let (phys, vlan) = physical(&i.name);
        let joined = l2.get(phys).zip(interface_mac(col, phys));
        let (link, rewrite, tag) = match joined {
            Some(((peer, prov, remote), m)) => (
                Some(Link {
                    peer: Some(peer.clone()),
                    delay_ns: None,
                    provenance: prov.clone(),
                    facts: Some(LinkFacts {
                        local: interface_facts(col, phys).unwrap_or_default(),
                        remote: remote.clone(),
                    }),
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
            exit: exits.get(i.name.as_str()).cloned(),
        });
    }
    for w in wireguard {
        l.add(w);
    }
    for (phys, (_, prov, _)) in l2 {
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

/// The name of the function after the next-hop resolution and the QoS of
/// an interface: the egress, or the encapsulation of a WireGuard interface.
fn out_name(i: &Interface) -> String {
    match i.kind {
        Kind::Wireguard => format!("wireguard/{}", i.name),
        _ => format!("out/{}", i.name),
    }
}

/// The edge interfaces of the twin. A PPPoE interface is an access link.
/// An interface of a next hop of the default route of the main table is a
/// default route edge for the gateways of that route that are not
/// addresses of a device of the twin (`twin`) or of the router itself. A
/// next hop with no gateway, a link-local gateway and a WireGuard interface
/// give no mark. The packets of an edge with no link leave the twin.
fn exit_marks<'a>(
    active: &[&'a Interface],
    main: &Fib,
    twin: &BTreeSet<IpAddr>,
    own: &Addrs,
) -> BTreeMap<&'a str, ExitMark> {
    let mine: BTreeSet<IpAddr> = own.values().flatten().map(|(a, _, _)| *a).collect();
    let mut gateways: BTreeMap<&'a str, BTreeSet<IpAddr>> = BTreeMap::new();
    for all in ["0.0.0.0/0", "::/0"] {
        let p: Prefix = all.parse().expect("a valid prefix");
        let Some(r) = main.get(&p) else {
            continue;
        };
        for h in r.next_hops() {
            let Some(g) = h.gateway else {
                continue;
            };
            let link_local = match g {
                IpAddr::V4(v) => v.is_link_local(),
                IpAddr::V6(v) => v.is_unicast_link_local(),
            };
            if link_local || twin.contains(&g) || mine.contains(&g) {
                continue;
            }
            if let Some(i) = active
                .iter()
                .find(|i| i.name == h.interface.as_str() && i.kind != Kind::Wireguard)
            {
                gateways.entry(i.name.as_str()).or_default().insert(g);
            }
        }
    }
    let mut out: BTreeMap<&'a str, ExitMark> = gateways
        .into_iter()
        .map(|(i, gateways)| (i, ExitMark::DefaultRoute { gateways }))
        .collect();
    for i in active.iter().filter(|i| i.kind == Kind::Pppoe) {
        out.insert(i.name.as_str(), ExitMark::AccessLink);
    }
    out
}

/// The source address of the packets of the router to `endpoint` and its
/// interface: the one address of the family of the endpoint on the one
/// interface of the route of the main table to it.
fn tunnel_source<'a>(
    main: &'a Fib,
    addrs: &Addrs,
    endpoint: IpAddr,
) -> Result<(IpAddr, &'a str), String> {
    let not_known = |why: String| Err(format!("the WireGuard source address is not known: {why}"));
    let Some((p, g)) = main.lookup(endpoint) else {
        return not_known(format!("no route to {endpoint}"));
    };
    if g.unknown.is_some() {
        return not_known(format!("the route {p} is not known"));
    }
    let ifaces: BTreeSet<&str> = g.next_hops.iter().map(|h| h.interface.as_str()).collect();
    let [iface] = ifaces.into_iter().collect::<Vec<_>>()[..] else {
        return not_known(format!("the route {p} has no single interface"));
    };
    let mine: Vec<IpAddr> = addrs
        .get(iface)
        .map(|v| {
            v.iter()
                .map(|(a, _, _)| *a)
                .filter(|a| a.is_ipv6() == endpoint.is_ipv6())
                .collect()
        })
        .unwrap_or_default();
    match mine[..] {
        [a] => Ok((a, iface)),
        [] => not_known(format!(
            "{iface} has no address of the family of {endpoint}"
        )),
        _ => not_known(format!("{iface} has more than one address")),
    }
}

/// The addresses of each interface with their prefix length: the config,
/// then the collected rows.
pub fn interface_addresses(cfg: &Config, col: &Collected) -> BTreeMap<String, Vec<(IpAddr, u8)>> {
    addresses(cfg, col)
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().map(|(a, l, _)| (a, l)).collect()))
        .collect()
}

/// The summary of a router for the join of the links: each physical
/// interface with a collected MAC can end a link, and a frame enters it at
/// its layer 3 hand-off. The source row of an interface is the first row of
/// the links table with its MAC. Its layer 3 addresses are the addresses of
/// the interface and of its VLAN subinterfaces. A router has no neighbour
/// section.
pub fn link_summary(device: &str, cfg: &Config, col: &Collected) -> crate::links::Summary {
    let mut s = crate::links::Summary::default();
    let addrs = interface_addresses(cfg, col);
    let mut by_prefix: BTreeMap<String, Vec<&crate::collected::RouteRow>> = BTreeMap::new();
    for r in col.routes.iter().filter(|r| r.selected && r.vrf == VRF) {
        by_prefix.entry(r.prefix.clone()).or_default().push(r);
    }
    s.routes = resolver(&by_prefix, &[]);
    for l in col.links.iter().filter(|l| l.parent.is_none()) {
        let Some(m) = l.mac.as_deref().and_then(|m| m.parse::<Mac>().ok()) else {
            continue;
        };
        let iface = l.interface.clone();
        s.entries.insert(
            iface.clone(),
            FunctionId::new(format!("{device}/handoff/{iface}")),
        );
        s.port_macs.insert(iface.clone(), m);
        if let Some(row) = col
            .links
            .iter()
            .find(|r| r.mac.as_deref().and_then(|x| x.parse::<Mac>().ok()) == Some(m))
        {
            s.port_spans.insert(iface.clone(), row.span.clone());
        }
        if let Some(f) = interface_facts(col, &iface) {
            s.facts.insert(iface.clone(), f);
        }
        let mut vlans = BTreeMap::new();
        for (i, list) in &addrs {
            let (p, vlan) = physical(i);
            if p == iface {
                vlans.insert(vlan, list.clone());
            }
        }
        s.l3.insert(iface, vlans);
    }
    s
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
    /// The WireGuard encapsulation of an interface. The outer source address
    /// toward a peer is the address of the interface of the route of the
    /// main table to the endpoint of the peer; with no such route, or with
    /// more than one interface or address of that family, it is not known.
    /// The encapsulated packets are packets of the router: they go to the
    /// route lookup of the main table, with the local zone as their source
    /// zone.
    fn wireguard(
        &mut self,
        i: &Interface,
        main: &Fib,
        addrs: &Addrs,
        local_zone: Option<&str>,
    ) -> WireguardEncap {
        let mut peers = Vec::new();
        for p in &i.peers {
            let mut allowed = Vec::new();
            for a in &p.allowed_ips {
                match a.parse::<Prefix>() {
                    Ok(x) => allowed.push(x),
                    Err(_) => self.note(format!(
                        "{} peer {}: the allowed IP {a} is not valid",
                        i.name, p.name
                    )),
                }
            }
            let endpoint = p
                .address
                .as_deref()
                .and_then(|a| a.parse::<IpAddr>().ok())
                .zip(p.port.as_deref().and_then(|x| x.parse::<u16>().ok()));
            let (source, source_interface) = match endpoint {
                Some((ep, _)) => match tunnel_source(main, addrs, ep) {
                    Ok((a, i)) => (Ok(a), Some(InterfaceId::new(i))),
                    Err(why) => (Err(why), None),
                },
                None => (Err("WireGuard peer endpoint not known".to_string()), None),
            };
            peers.push(WireguardPeer {
                name: p.name.clone(),
                allowed,
                endpoint,
                source,
                source_interface,
                spans: vec![self.span(p.lines)],
            });
        }
        let unknown = if self.cfg.output_filter {
            Some("the global output filter is not lowered".to_string())
        } else if self.cfg.local_route {
            Some("the policy routes of the router itself are not lowered".to_string())
        } else {
            None
        };
        let src_zone = match local_zone {
            Some(z) => Attr::Known(ZoneId::new(z)),
            None if self.cfg.zones.is_empty() => Attr::Known(ZoneId::new(NO_ZONE)),
            None => Attr::Unknown,
        };
        let name = format!("wireguard/{}", i.name);
        let meta = self.meta(&name, vec![self.span(i.lines)]);
        WireguardEncap::new(
            meta,
            InterfaceId::new(&i.name),
            peers,
            WireguardSettings {
                listen_port: i.port.as_deref().and_then(|x| x.parse().ok()),
                unknown,
                src_zone,
                underlay: VrfId::new(VRF),
                next: self.id("route"),
            },
        )
    }

    fn hop(&self, interface: &str, gateway: Option<IpAddr>) -> RouteNextHop {
        RouteNextHop {
            interface: InterfaceId::new(interface),
            gateway,
            next: self.id("zone-dst"),
        }
    }

    fn connected(&self, t: &mut Fib, addrs: &Addrs) {
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

    /// The main FIB: the collected route rows of the main VRF, or else the
    /// connected and static routes of the config. The local routes are
    /// always in it.
    fn main_fib(&mut self, col: &Collected, addrs: &Addrs, locals: &[(Prefix, Route)]) -> Fib {
        let mut t = Fib::new();
        let rib: Vec<_> = col
            .routes
            .iter()
            .filter(|r| r.selected && r.vrf == VRF)
            .collect();
        if !col.routes.iter().any(|r| r.vrf == VRF) {
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
            // A routing protocol can add a longer route for each address,
            // so only the connected and the local routes stay definite.
            let protocols = self.cfg.routing_protocols.clone();
            if !protocols.is_empty() {
                let names: Vec<&str> = protocols.iter().map(|(n, _)| n.as_str()).collect();
                self.note(format!(
                    "protocols {} not lowered and no collected RIB: the routes other than the connected and local routes are unknown",
                    names.join(", ")
                ));
                let spans: Vec<SourceSpan> = protocols.iter().map(|(_, l)| self.span(*l)).collect();
                for (p, r) in t.entries() {
                    if r.kind != RouteKind::Connected {
                        let mut s = r.spans.clone();
                        s.extend(spans.iter().cloned());
                        t.insert(
                            p,
                            Route::unknown_with(
                                RouteKind::Static,
                                rsim_core::ReasonCode::NotCollected,
                                TABLE_NOT_COLLECTED,
                                s,
                            ),
                        );
                    }
                }
                for all in ["0.0.0.0/0", "::/0"] {
                    let p: Prefix = all.parse().expect("a valid prefix");
                    if t.get(&p).is_none() {
                        t.insert(
                            p,
                            Route::unknown_with(
                                RouteKind::Static,
                                rsim_core::ReasonCode::NotCollected,
                                TABLE_NOT_COLLECTED,
                                spans.clone(),
                            ),
                        );
                    }
                }
            }
        } else {
            let mut by_prefix: BTreeMap<String, Vec<&crate::collected::RouteRow>> = BTreeMap::new();
            for r in rib {
                by_prefix.entry(r.prefix.clone()).or_default().push(r);
            }
            let resolver = resolver(&by_prefix, locals);
            for (prefix, rows) in by_prefix {
                let Ok(p) = prefix.parse::<Prefix>() else {
                    self.note(format!("route {prefix}: the prefix is not valid"));
                    continue;
                };
                let spans: Vec<SourceSpan> = rows.iter().map(|r| r.span.clone()).collect();
                let kind = match rows[0].protocol.as_str() {
                    "connected" => RouteKind::Connected,
                    "local" => RouteKind::Local,
                    word => route_kind(
                        word,
                        super::profile::LEARNED_WORDS,
                        super::profile::STATIC_WORDS,
                    ),
                };
                if kind == RouteKind::Local {
                    t.insert(p, Route::new(kind, Vec::new(), spans));
                    continue;
                }
                // A route whose next hop does not resolve stays in the table
                // with no next hop, so its packets are unknown and do not
                // fall to a shorter prefix.
                let paths: Vec<Path> = forwarding_rows(&rows).iter().map(|r| path_of(r)).collect();
                let through =
                    through_default(Origin::Collected, super::profile::COMPUTED_THROUGH_DEFAULT);
                match resolver.resolve(VRF, &paths, through) {
                    Ok((found, more)) => {
                        let hops: Vec<RouteNextHop> = found
                            .iter()
                            .map(|h| self.hop(&h.interface, h.gateway))
                            .collect();
                        let mut all = spans;
                        all.extend(more);
                        t.insert(p, Route::new(kind, hops, all));
                    }
                    Err(u) => {
                        self.note(format!("route {prefix}: {}", u.why));
                        let mut all = spans;
                        all.extend(u.spans);
                        t.insert(p, Route::unknown(kind, u.reason, all));
                    }
                }
            }
        }
        for (p, r) in locals {
            t.insert(*p, r.clone());
        }
        t
    }

    /// The FIB of a policy route table: its static routes and the local
    /// routes.
    fn table_fib(&mut self, table: &str, addrs: &Addrs, locals: &[(Prefix, Route)]) -> Fib {
        let mut t = Fib::new();
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

    fn static_route(&mut self, t: &mut Fib, r: &crate::vyos::config::StaticRoute, addrs: &Addrs) {
        let Ok(p) = r.prefix.parse::<Prefix>() else {
            self.note(format!(
                "static route {}: the prefix is not valid",
                r.prefix
            ));
            return;
        };
        let span = vec![self.span(r.lines)];
        // A route that is not fully lowered stays in the table with no next
        // hop, so its packets are unknown and do not fall to a shorter
        // prefix.
        let unknown = Route::new(RouteKind::Static, Vec::new(), span.clone());
        if !r.unhandled.is_empty() {
            self.note(format!(
                "static route {}: options not lowered: {}",
                r.prefix,
                r.unhandled.join(", ")
            ));
            t.insert(p, unknown);
            return;
        }
        if r.blackhole {
            t.insert(p, Route::new(RouteKind::Null, Vec::new(), span));
            return;
        }
        let mut hops: Vec<RouteNextHop> = r.interfaces.iter().map(|i| self.hop(i, None)).collect();
        for g in &r.gateways {
            let iface = g.parse::<IpAddr>().ok().and_then(|gw| {
                addrs
                    .iter()
                    .find(|(_, v)| {
                        v.iter().any(|(a, len, _)| {
                            *len < max_len(*a) && Prefix::new(*a, *len).contains(gw)
                        })
                    })
                    .map(|(i, _)| (i, gw))
            });
            match iface {
                Some((i, gw)) => hops.push(self.hop(i, Some(gw))),
                None => {
                    self.note(format!(
                        "static route {}: gateway {g} is on no connected network",
                        r.prefix
                    ));
                    t.insert(p, unknown);
                    return;
                }
            }
        }
        if hops.is_empty() {
            self.note(format!("static route {}: no next hop", r.prefix));
            t.insert(p, unknown);
            return;
        }
        t.insert(p, Route::new(RouteKind::Static, hops, span));
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
                            |(ingress, egress, states, r)| {
                                let s = ZoneScope {
                                    ingress,
                                    egress,
                                    states,
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
                states: None,
            };
            let name = format!("zone {} default", to.name);
            let r = self.zone_default(to, &name, None);
            pairs.push((scope, r));
            out.extend(pairs);
        }
        // Traffic to an interface in no zone enters no zone chain, and the
        // forward hook accepts it.
        let span = self.profile.source.last().cloned();
        let mut r = FRule::new(
            format!("to {NO_ZONE}"),
            RulePredicate::exact(Match::any()),
            RuleAction::Permit,
        );
        if let Some(s) = span {
            r = r.with_span(s);
        }
        forward.push((
            ZoneScope {
                from: None,
                to: Some(BTreeSet::from([ZoneId::new(NO_ZONE)])),
                ingress: None,
                egress: None,
                states: None,
            },
            r,
        ));
        // A global filter that the handlers do not read comes first, so the
        // policy is unknown for each packet.
        let whole = SourceSpan::new(self.file, 1, 1);
        if self.cfg.forward_filter {
            self.note("the global forward filter is not lowered".into());
            forward.insert(
                0,
                (
                    ZoneScope::default(),
                    FRule::unhandled("firewall forward filter", whole.clone()),
                ),
            );
        }
        if self.cfg.input_filter {
            self.note("the global input filter is not lowered".into());
            to_local.insert(
                0,
                (
                    ZoneScope::default(),
                    FRule::unhandled("firewall input filter", whole),
                ),
            );
        }
        (forward, to_local)
    }

    /// The actions of the global state policy. A state with no action goes
    /// on to the zone policy.
    fn state_actions(&mut self) -> StateActions {
        let sp = self.cfg.state_policy.clone();
        let mut one = |state: &str, a: &Option<Action>| match a {
            None => StateAction::Continue,
            Some(Action::Accept) => StateAction::Accept,
            Some(Action::Drop | Action::Reject) => StateAction::Drop,
            Some(Action::Other(x)) => {
                self.note(format!("state-policy {state}: action {x} is not lowered"));
                StateAction::Unknown
            }
        };
        StateActions {
            established: one("established", &sp.established),
            related: one("related", &sp.related),
            invalid: one("invalid", &sp.invalid),
        }
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
                None,
                FRule::unhandled(msg, SourceSpan::new(self.file, 1, 1)),
            )];
        };
        let mut out = Vec::new();
        for r in rs.rules.iter().filter(|r| !r.disabled) {
            let rname = format!("{name}/{}", r.number);
            let span = self.span(r.lines);
            let states = match conn_states(&r.matches.state) {
                Ok(s) => s,
                Err(e) => {
                    self.note(format!("{rname}: state {e} is not lowered"));
                    out.push((None, None, None, FRule::unhandled(rname, span)));
                    continue;
                }
            };
            let action = match r.action {
                Some(Action::Accept) => RuleAction::Permit,
                Some(Action::Drop | Action::Reject) => RuleAction::Deny,
                ref a => {
                    self.note(format!("{rname}: action {a:?} is not lowered"));
                    out.push((None, None, None, FRule::unhandled(rname, span)));
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
                states,
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
        out.push((None, None, None, rule));
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
        set(self.side_addr(&m.source, family).map(|v| {
            if let Some(v) = v {
                upper.src_ip = v;
            }
        }));
        set(self.side_addr(&m.destination, family).map(|v| {
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

    /// The addresses of a side. The groups of an IPv6 rule are the
    /// `ipv6-address-group` and `ipv6-network-group` groups.
    fn side_addr(&self, s: &Side, family: Option<Family>) -> Result<Option<AddrCond>, String> {
        let mut items: Vec<String> = Vec::new();
        let mut any = false;
        if let Some(a) = &s.address {
            items.push(a.clone());
            any = true;
        }
        let (addresses, networks) = match family {
            Some(Family::V6) => (&self.cfg.ipv6_address_groups, &self.cfg.ipv6_network_groups),
            _ => (&self.cfg.address_groups, &self.cfg.network_groups),
        };
        for (g, map) in [(&s.address_group, addresses), (&s.network_group, networks)] {
            if let Some(g) = g {
                if any {
                    return Err("an address and a group".into());
                }
                any = true;
                items.extend(
                    map.get(g)
                        .ok_or_else(|| format!("group {g} does not exist"))?
                        .clone()?,
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
                    .clone()?,
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

/// A rule with its ingress and egress interfaces and its connection states.
type ScopedRule = (
    Option<BTreeSet<InterfaceId>>,
    Option<BTreeSet<InterfaceId>>,
    Option<BTreeSet<ConnState>>,
    FRule<RuleAction>,
);

/// The connection states of the `state` option of a rule, `None` for no
/// option. `Err` names a state that is not known.
fn conn_states(names: &[String]) -> Result<Option<BTreeSet<ConnState>>, String> {
    if names.is_empty() {
        return Ok(None);
    }
    names
        .iter()
        .map(|n| match n.as_str() {
            "new" => Ok(ConnState::New),
            "established" => Ok(ConnState::Established),
            "related" => Ok(ConnState::Related),
            "invalid" => Ok(ConnState::Invalid),
            other => Err(other.to_string()),
        })
        .collect::<Result<BTreeSet<_>, _>>()
        .map(Some)
}

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

/// The path of a collected route row: its interface and its next hop.
fn path_of(r: &crate::collected::RouteRow) -> Path {
    Path {
        interface: r.interface.clone(),
        gateway: r.next_hop.as_deref().and_then(|g| g.parse().ok()),
        vrf: None,
    }
}

/// The rows of a route that forward. FRR gives a recursive next hop as a
/// row with no interface, followed by a row with an interface for each
/// next hop that resolves it; the rows with an interface are the next hops
/// that the device uses. Only a route with no such row resolves its next
/// hops.
fn forwarding_rows<'a>(
    rows: &[&'a crate::collected::RouteRow],
) -> Vec<&'a crate::collected::RouteRow> {
    if rows.iter().any(|r| r.interface.is_some()) {
        rows.iter()
            .copied()
            .filter(|r| r.interface.is_some())
            .collect()
    } else {
        rows.to_vec()
    }
}

/// The collected routes of the main VRF and the addresses of the device for
/// the resolution of a next hop: a local route gives no next hop.
fn resolver(
    by_prefix: &BTreeMap<String, Vec<&crate::collected::RouteRow>>,
    locals: &[(Prefix, Route)],
) -> Resolver {
    let mut out = Resolver::new();
    for (p, r) in locals {
        out.add(VRF, *p, Target::Local, r.spans.clone());
    }
    for (prefix, rows) in by_prefix {
        let Ok(p) = prefix.parse::<Prefix>() else {
            continue;
        };
        let spans: Vec<SourceSpan> = rows.iter().map(|r| r.span.clone()).collect();
        let target = if rows[0].protocol == "local" {
            Target::Local
        } else {
            Target::Paths(forwarding_rows(rows).iter().map(|r| path_of(r)).collect())
        };
        out.add(VRF, p, target, spans);
    }
    out
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
