//! The lowering of the edges of an enterprise into function instances, and
//! the transport networks between their WAN links.
//!
//! An edge is one twin device. The packets of a LAN interface go through the
//! VRF of its segment, the session lookup, the firewall and the route lookup
//! of the segment. An overlay route goes to the tunnel selection of its far
//! edge, and the default route goes to the business policy of the segment.
//! A tunnel puts the packets into VCMP on a WAN link, and the outer packets
//! go through the transport network of the link to the far edge, where the
//! decapsulation gives them to the route lookup of their segment.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use rsim_core::{
    AddrCond, FieldValue, FunctionId, InterfaceId, Match, NetFunction, NextHop, ObjectId, PortCond,
    Prefix, ReasonCode, RulePredicate, SourceSpan, TriePrefixTable, ValueCond, VrfId,
};
use rsim_engine::EdgeInterface;
use rsim_functions::{
    AclMatch, DestinationNat, DeviceDelivery, Egress, EgressMode, ExitMark, Fib, Ingress, Link,
    Meta, NatAction, NextHopResolution, OverlaySelect, OverlayTunnel, PolicyRoute, PortTranslation,
    QosNotEvaluated, Route, RouteKind, RouteLookup, RouteNextHop, RouteProtocol, Rule as FRule,
    RuleAction, SessionCommit, SessionLookup, SourceNat, StateActions, TransportLookup,
    TunnelState, VCMP_PORT, VcmpDecap, VcmpEncap, VendorProfile, VrfSelection,
};

use super::reader::{
    Edge, EdgeSegment, Enterprise, HubRef, Interface, InterfaceKind, LinkKind, Peers, StaticRoute,
    WanLink,
};
use super::routes::{RouteClass, order};
use super::rules::{
    AddrEntry, AddrMatch, BusinessAction, FirewallAction, Inbound, InboundKind, IpVersion,
    LinkPolicy, Match as RuleMatch, Policy, PortMatch, RouteAction, RoutePolicy, Rule, Target,
    Word,
};

/// The VRF of the WAN links of an edge.
pub const UNDERLAY: &str = "wan";

/// The VRF of each transport network.
const TRANSPORT_VRF: &str = "default";

/// The action when the hub of a branch in a cluster is not collected.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HubChoice {
    /// The packets to the cluster are unknown.
    #[default]
    None,
    /// Each hub of the cluster is a candidate.
    All,
    /// The first hub of the cluster by logicalId.
    One,
}

/// The function instances, the edge interfaces and the notes of the edges
/// and the transport networks of an enterprise.
#[derive(Default)]
pub struct Lowered {
    pub functions: Vec<Arc<dyn NetFunction>>,
    pub edges: Vec<EdgeInterface>,
    /// The notes of each twin device.
    pub notes: BTreeMap<String, Vec<String>>,
}

/// A WAN link of an edge in a transport network.
#[derive(Clone, Debug)]
struct Member {
    edge: String,
    /// The WAN interface of the edge.
    interface: String,
    /// The interface of the transport network, `<edge>:<link>`.
    port: String,
    address: Option<IpAddr>,
    spans: Vec<SourceSpan>,
}

/// A transport network: the WAN links of its edges and the gateways that
/// the tunnels of the edges reach through it.
#[derive(Default)]
struct Transport {
    members: Vec<Member>,
    gateways: BTreeMap<String, (IpAddr, SourceSpan)>,
}

/// A far end of the tunnels of a segment.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Far {
    Edge(String),
    /// The hubs of a cluster, each a candidate.
    Cluster {
        id: String,
        hubs: Vec<String>,
    },
    /// The gateways of the segment.
    Gateways,
}

impl Far {
    fn name(&self) -> &str {
        match self {
            Far::Edge(e) => e,
            Far::Cluster { id, .. } => id,
            Far::Gateways => "gateways",
        }
    }
}

/// The default routes of IPv4 and IPv6.
fn defaults() -> [Prefix; 2] {
    [
        Prefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        Prefix::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    ]
}

/// The VRF of a segment: its name, and its name with its id when the name
/// is the name of the underlay.
fn vrf_of(s: &EdgeSegment) -> VrfId {
    if s.name == UNDERLAY {
        VrfId::new(format!("{} {}", s.name, s.id))
    } else {
        VrfId::new(&s.name)
    }
}

/// The interface of a WAN link: its interface, else its logicalId.
fn wan_iface(l: &WanLink) -> String {
    l.interface.clone().unwrap_or_else(|| l.logical_id.clone())
}

/// The address of a WAN link in the transport network: the listing
/// address, else the address of its interface.
fn link_address(l: &WanLink) -> Option<IpAddr> {
    l.address.or(l.local)
}

/// The state of a WAN link from `edge_state`: up, down, or not known.
fn link_up(state: Option<&str>) -> Option<bool> {
    match state {
        Some("STABLE" | "UNSTABLE") => Some(true),
        Some("DISCONNECTED") => Some(false),
        _ => None,
    }
}

/// True if 2 WAN links can form a tunnel: 2 public links, or 2 private
/// links of the same private network.
fn pairable(a: &WanLink, b: &WanLink) -> bool {
    match (&a.kind, &b.kind) {
        (LinkKind::Public { .. }, LinkKind::Public { .. }) => true,
        (LinkKind::Private { network: Some(x) }, LinkKind::Private { network: Some(y) }) => x == y,
        _ => false,
    }
}

/// The function id of the tunnel selection of a segment to a far end.
fn select_id(segment: u32, far: &Far) -> String {
    format!("sdwan/select/{segment}/{}", far.name())
}

/// A match that no packet meets.
fn nothing() -> Match {
    Match {
        src_ip: AddrCond::In(Vec::new()),
        ..Match::any()
    }
}

/// The prefix of all addresses of a family.
fn family_all(v4: bool) -> Prefix {
    if v4 { defaults()[0] } else { defaults()[1] }
}

/// The definite and the upper address condition of one side of a rule. An
/// open field of one family beside a set field of the other family, with no
/// stated IP version, is a bound.
fn side(v4: &AddrMatch, v6: &AddrMatch, version: Option<IpVersion>) -> (AddrCond, AddrCond) {
    let allow4 = version != Some(IpVersion::V6);
    let allow6 = version != Some(IpVersion::V4);
    if *v4 == AddrMatch::Any && *v6 == AddrMatch::Any && allow4 && allow6 {
        return (AddrCond::Any, AddrCond::Any);
    }
    let mut definite = Vec::new();
    let mut upper = Vec::new();
    for (m, other, allow, is4) in [(v4, v6, allow4, true), (v6, v4, allow6, false)] {
        if !allow {
            continue;
        }
        match m {
            AddrMatch::Any => {
                upper.push(family_all(is4));
                if version.is_some() || *other == AddrMatch::Any {
                    definite.push(family_all(is4));
                }
            }
            AddrMatch::Set(entries) => {
                for e in entries {
                    match e {
                        AddrEntry::Prefix(p) => {
                            definite.push(*p);
                            upper.push(*p);
                        }
                        AddrEntry::Wildcard { .. } => upper.push(family_all(is4)),
                    }
                }
            }
        }
    }
    (AddrCond::In(definite), AddrCond::In(upper))
}

/// The port condition of a port match and the protocols of its ranges.
fn ports(p: &PortMatch) -> (PortCond, BTreeSet<Option<u8>>) {
    match p {
        PortMatch::Any => (PortCond::Any, BTreeSet::new()),
        PortMatch::Set(rs) => (
            PortCond::In(rs.iter().map(|r| (r.low, r.high)).collect()),
            rs.iter().map(|r| r.protocol).collect(),
        ),
    }
}

/// The predicate of the match of a rule. A bound of the rule, a source
/// interface, a source VLAN, a wildcard address and port ranges of
/// different protocols make the definite match set empty.
pub fn predicate(m: &RuleMatch) -> RulePredicate {
    let src = side(&m.source, &m.source_v6, m.ip_version);
    let dst = side(&m.destination, &m.destination_v6, m.ip_version);
    let (src_port, sp) = ports(&m.source_ports);
    let (dst_port, dp) = ports(&m.destination_ports);
    let protos: BTreeSet<Option<u8>> = sp.union(&dp).copied().collect();
    let named: BTreeSet<u8> = protos.iter().flatten().copied().collect();
    let mut bounded =
        !m.bounds.is_empty() || m.source_interface.is_some() || m.source_vlan.is_some();
    let protocol = match m.protocol {
        Some(p) => {
            if named.iter().any(|q| *q != p) {
                bounded = true;
            }
            ValueCond::one(p)
        }
        None => match (named.first(), named.len(), protos.contains(&None)) {
            (None, _, _) => ValueCond::Any,
            (Some(q), 1, false) => ValueCond::one(*q),
            (Some(_), _, true) => {
                bounded = true;
                ValueCond::Any
            }
            (Some(_), _, false) => {
                bounded = true;
                ValueCond::In(named.clone())
            }
        },
    };
    let upper = Match {
        src_ip: src.1,
        dst_ip: dst.1,
        protocol,
        src_port,
        dst_port,
        dscp: m.dscp.map_or(ValueCond::Any, ValueCond::one),
        ..Match::any()
    };
    let definite = if bounded {
        nothing()
    } else {
        Match {
            src_ip: src.0,
            dst_ip: dst.0,
            ..upper.clone()
        }
    };
    RulePredicate::bounded(definite, upper)
}

/// A route of one prefix of a segment, with its place in the route order.
struct Candidate {
    class: RouteClass,
    route: Route,
}

/// The lowering of one edge.
struct L<'a> {
    ent: &'a Enterprise,
    e: &'a Edge,
    profile: &'a VendorProfile,
    hubs: HubChoice,
    functions: Vec<Arc<dyn NetFunction>>,
    edges: Vec<EdgeInterface>,
    notes: Vec<String>,
    /// The WAN links with a known interface, one for each interface.
    wan: Vec<&'a WanLink>,
    selects: BTreeSet<(u32, Far)>,
    /// The direct exits of each segment: all public links, or one link.
    directs: BTreeSet<(u32, Option<String>)>,
    /// The tunnel ends: the local link and the address of the far link, by
    /// function name.
    encaps: BTreeMap<String, (String, IpAddr)>,
    /// The number of the last function with a serial name.
    serial: usize,
    members: Vec<(String, Member)>,
    gateways: Vec<(String, String, IpAddr, SourceSpan)>,
}

impl<'a> L<'a> {
    fn id(&self, f: &str) -> FunctionId {
        FunctionId::new(format!("{}/{f}", self.e.device))
    }

    fn meta(&self, f: &str, spans: Vec<SourceSpan>) -> Meta {
        let mut m = Meta::new(self.id(f), self.e.device.as_str(), self.profile);
        m.provenance = spans;
        m
    }

    fn add(&mut self, f: impl NetFunction + 'static) {
        self.functions.push(Arc::new(f));
    }

    fn note(&mut self, s: String) {
        if !self.notes.contains(&s) {
            self.notes.push(s);
        }
    }

    fn span(&self) -> Vec<SourceSpan> {
        vec![self.e.span.clone()]
    }

    fn nh(&self, iface: &str, gateway: Option<IpAddr>, next: &str) -> RouteNextHop {
        RouteNextHop {
            interface: InterfaceId::new(iface),
            gateway,
            next: self.id(next),
        }
    }

    fn segment(&self, id: u32) -> Option<&'a EdgeSegment> {
        let e = self.e;
        e.segments.iter().find(|s| s.id == id)
    }

    /// The segment of an interface that is not a WAN interface.
    fn segment_of(&self, i: &Interface) -> Option<&'a EdgeSegment> {
        let e = self.e;
        let global = e.segments.iter().find(|s| s.global).map(|s| s.id);
        let id = i.segment.or(global)?;
        self.segment(id)
    }

    /// The transport network of a WAN link.
    fn transport(&self, l: &WanLink) -> Option<String> {
        let store = &self.ent.store_device;
        match &l.kind {
            LinkKind::Public { .. } => Some(format!("{store}/transport/public")),
            LinkKind::Private { network: Some(n) } => {
                Some(format!("{store}/transport/private/{n}"))
            }
            _ => None,
        }
    }

    fn lower(&mut self) {
        let e = self.e;
        let mut seen = BTreeSet::new();
        for l in &e.links {
            if l.ambiguous.is_some() {
                continue;
            }
            let i = wan_iface(l);
            if e.interfaces.iter().any(|x| !x.wan && x.name == i) {
                self.note(format!(
                    "link {}: interface {i} is a LAN interface",
                    l.logical_id
                ));
                continue;
            }
            if !seen.insert(i.clone()) {
                self.note(format!(
                    "link {}: interface {i} of another link",
                    l.logical_id
                ));
                continue;
            }
            self.wan.push(l);
        }

        // The LAN interfaces with their segments.
        let mut lan: Vec<(&'a Interface, &'a EdgeSegment)> = Vec::new();
        for i in &e.interfaces {
            if i.wan || i.kind == InterfaceKind::Loopback {
                continue;
            }
            match self.segment_of(i) {
                Some(s) => lan.push((i, s)),
                None => self.note(format!("interface {}: segment not known", i.name)),
            }
        }
        for (i, s) in &lan {
            let meta = self.meta(&format!("in/{}", i.name), vec![i.span.clone()]);
            self.add(Ingress {
                meta,
                interface: InterfaceId::new(&i.name),
                next: self.id(&format!("vrf/{}", s.id)),
            });
            if let Some((a, len)) = i.address {
                self.edges.push(EdgeInterface {
                    device: e.device.as_str().into(),
                    interface: InterfaceId::new(&i.name),
                    networks: vec![Prefix::new(a, len)],
                    provenance: vec![i.span.clone()],
                });
            }
        }
        for s in &e.segments {
            let ifs: Vec<&Interface> = lan
                .iter()
                .filter(|(_, x)| x.id == s.id)
                .map(|(i, _)| *i)
                .collect();
            if !ifs.is_empty() {
                self.lan_chain(s, &ifs);
            }
        }

        // The route lookup of the segments and the delivery to the edge.
        let mut tables = BTreeMap::new();
        for s in &e.segments {
            let ifs: Vec<&Interface> = lan
                .iter()
                .filter(|(_, x)| x.id == s.id)
                .map(|(i, _)| *i)
                .collect();
            let fib = self.fib(s, &ifs);
            tables.insert(vrf_of(s), fib);
        }
        let meta = self.meta("route", self.span());
        self.add(RouteLookup {
            meta,
            tables,
            fallback: None,
            local: Some(self.id("deliver")),
        });
        let meta = self.meta("deliver", self.span());
        self.add(DeviceDelivery { meta });

        // The next hops and the egress of the LAN interfaces.
        let meta = self.meta("nexthop", self.span());
        let egress: BTreeMap<InterfaceId, FunctionId> = lan
            .iter()
            .map(|(i, _)| {
                (
                    InterfaceId::new(&i.name),
                    self.id(&format!("out/{}", i.name)),
                )
            })
            .collect();
        self.add(NextHopResolution {
            meta,
            neighbours: TriePrefixTable::new(),
            complete: false,
            egress,
            point_to_point: BTreeMap::new(),
        });
        for (i, _) in &lan {
            let meta = self.meta(&format!("out/{}", i.name), vec![i.span.clone()]);
            self.add(Egress {
                meta,
                interface: InterfaceId::new(&i.name),
                mode: EgressMode::Routed,
                link: None,
                rewrite: Default::default(),
                tag: Default::default(),
                exit: None,
            });
        }

        for s in &e.segments {
            self.policy(s);
        }
        self.wan_side();
        let selects = std::mem::take(&mut self.selects);
        for (sid, far) in &selects {
            if let Some(s) = self.segment(*sid) {
                self.select(s, far);
            }
        }
        self.encaps();
        self.directs();
    }

    /// The VRF, the session lookup and the firewall of the LAN interfaces of
    /// a segment.
    fn lan_chain(&mut self, s: &EdgeSegment, ifs: &[&Interface]) {
        let sid = s.id;
        let firewall = self.firewall(s);
        let meta = self.meta(&format!("vrf/{sid}"), self.span());
        self.add(VrfSelection {
            meta,
            by_interface: ifs
                .iter()
                .map(|i| (InterfaceId::new(&i.name), vrf_of(s)))
                .collect(),
            default_vrf: None,
            next: self.id(&format!("session/{sid}")),
        });
        let after_session = match &firewall {
            Some(_) => format!("firewall/{sid}"),
            None => "route".to_string(),
        };
        let meta = self.meta(&format!("session/{sid}"), self.span());
        self.add(SessionLookup {
            meta,
            next: self.id(&after_session),
            states: StateActions::default(),
        });
        let Some(rules) = firewall else {
            return;
        };
        let meta = self.meta(&format!("firewall/{sid}"), self.span());
        self.add(AclMatch {
            meta,
            acl: ObjectId::new(format!("{}:firewall:{sid}", self.e.device)),
            rules,
            default: self.profile.acl_default,
            next: self.id("route"),
        });
    }

    /// True if the firewall of the edge, or of one of its segments, is
    /// stateful.
    fn stateful(&self) -> bool {
        match &self.e.firewall {
            Policy::Read(fw) => {
                fw.enabled != Some(false)
                    && (fw.stateful == Some(true)
                        || fw.segments.iter().any(|s| s.stateful == Some(true)))
            }
            Policy::NotRead(_) => false,
        }
    }

    /// The outbound rules of the firewall of a segment. `None` when the
    /// firewall is off. The list ends with an unhandled rule.
    fn firewall(&mut self, s: &EdgeSegment) -> Option<Vec<FRule<RuleAction>>> {
        let e = self.e;
        let fw = match &e.firewall {
            Policy::NotRead(r) => {
                return Some(vec![FRule::unhandled(
                    format!("firewall, {r}"),
                    e.span.clone(),
                )]);
            }
            Policy::Read(f) => f,
        };
        if fw.enabled == Some(false) {
            return None;
        }
        let set = fw.segments.iter().find(|x| x.segment == Some(s.id));
        let mut rules = Vec::new();
        for r in set.map(|x| x.rules.as_slice()).unwrap_or_default() {
            let action = match &r.action {
                FirewallAction::Allow => Some(RuleAction::Permit),
                FirewallAction::Deny | FirewallAction::Drop | FirewallAction::Reject => {
                    Some(RuleAction::Deny)
                }
                FirewallAction::Skip | FirewallAction::NotStated | FirewallAction::Other(_) => None,
            };
            match action {
                Some(a) => rules.push(
                    FRule::new(r.id.clone(), predicate(&r.matches), a).with_span(r.span.clone()),
                ),
                None => {
                    self.note(format!(
                        "firewall rule {}: action {:?} not lowered",
                        r.id, r.action
                    ));
                    rules.push(FRule::unhandled(r.id.clone(), r.span.clone()));
                }
            }
        }
        let tail = set
            .and_then(|x| x.unknown_tail.clone())
            .or_else(|| fw.unknown_tail.clone());
        if let Some(t) = tail {
            rules.push(FRule::unhandled(
                format!("profile rules, {t}"),
                e.span.clone(),
            ));
        }
        rules.push(FRule::unhandled("firewall default", e.span.clone()));
        Some(rules)
    }

    /// A static route of a segment, through the LAN interface that it names
    /// or the LAN interface whose network holds its gateway.
    fn static_route(&self, st: &StaticRoute, ifs: &[&Interface]) -> Route {
        let spans = vec![st.span.clone()];
        let named = st
            .interface
            .as_deref()
            .and_then(|n| ifs.iter().copied().find(|i| i.name == n));
        let iface = named.or_else(|| {
            let g = st.gateway?;
            ifs.iter().copied().find(|i| {
                i.address
                    .is_some_and(|(a, l)| Prefix::new(a, l).contains(g))
            })
        });
        match (iface, st.gateway) {
            (Some(i), g) => Route::new(
                RouteKind::Static,
                vec![self.nh(&i.name, g, "nexthop")],
                spans,
            ),
            (None, Some(g)) => Route::unknown(
                RouteKind::Static,
                format!("next hop not resolved: {g}"),
                spans,
            ),
            (None, None) => Route::unknown(
                RouteKind::Static,
                "static route with no gateway and no LAN interface",
                spans,
            ),
        }
    }

    /// The route table of a segment: one winner for each prefix by the route
    /// order, the addresses of the edge, and the default route to the
    /// business policy.
    fn fib(&mut self, s: &EdgeSegment, ifs: &[&Interface]) -> Fib {
        let e = self.e;
        let ent = self.ent;
        let mut cands: BTreeMap<Prefix, Vec<Candidate>> = BTreeMap::new();
        for i in ifs {
            if let Some((a, len)) = i.address {
                cands
                    .entry(Prefix::new(a, len))
                    .or_default()
                    .push(Candidate {
                        class: RouteClass::LocalConnected,
                        route: Route::new(
                            RouteKind::Connected,
                            vec![self.nh(&i.name, None, "nexthop")],
                            vec![i.span.clone()],
                        ),
                    });
            }
        }
        for st in &s.statics {
            cands.entry(st.prefix).or_default().push(Candidate {
                class: st.class(),
                route: self.static_route(st, ifs),
            });
        }
        let mut own = 0;
        if let Some(t) = &ent.overlay {
            for row in t.rows.iter().filter(|r| r.segment == s.id) {
                if row.edge == e.logical_id {
                    own += 1;
                    continue;
                }
                let route = if ent.edge(&row.edge).is_some() {
                    let far = Far::Edge(row.edge.clone());
                    let next = select_id(s.id, &far);
                    self.selects.insert((s.id, far));
                    Route::new(
                        RouteKind::Learned(RouteProtocol::Overlay),
                        vec![self.nh("overlay", None, &next)],
                        vec![row.span.clone()],
                    )
                } else {
                    Route::unknown(
                        RouteKind::Learned(RouteProtocol::Overlay),
                        format!("edge {} not in the enterprise", row.edge),
                        vec![row.span.clone()],
                    )
                };
                cands.entry(row.prefix).or_default().push(Candidate {
                    class: row.class(&e.logical_id),
                    route,
                });
            }
        }
        if own > 0 {
            self.note(format!(
                "segment {}: {own} overlay rows of the edge itself not lowered",
                s.name
            ));
        }
        let mut fib = Fib::new();
        for (p, cs) in &cands {
            fib.insert(*p, winner(*p, cs));
        }
        for p in defaults() {
            if cands.contains_key(&p) {
                continue;
            }
            let route = if ent.overlay.is_none() {
                Route::unknown_with(
                    RouteKind::Static,
                    ReasonCode::NotCollected,
                    "overlay route table not collected",
                    self.span(),
                )
            } else {
                Route::new(
                    RouteKind::Static,
                    vec![self.nh("policy", None, &format!("policy/{}", s.id))],
                    self.span(),
                )
            };
            fib.insert(p, route);
        }
        // The addresses of the edge in the segment, and in the Global
        // Segment the addresses of the WAN links.
        let mut local: Vec<(IpAddr, SourceSpan)> = e
            .interfaces
            .iter()
            .filter(|i| !i.wan && self.segment_of(i).is_some_and(|x| x.id == s.id))
            .filter_map(|i| Some((i.address?.0, i.span.clone())))
            .collect();
        if s.global {
            for l in &e.links {
                let span = l.spans.first().cloned().unwrap_or_else(|| e.span.clone());
                for a in [l.address, l.local].into_iter().flatten() {
                    local.push((a, span.clone()));
                }
            }
        }
        for (a, span) in local {
            fib.insert(
                Prefix::host(a),
                Route::new(RouteKind::Local, Vec::new(), vec![span]),
            );
        }
        fib
    }

    /// A function that makes each packet of a segment unknown.
    fn unknown_target(&mut self, s: &EdgeSegment, code: ReasonCode, why: String) -> FunctionId {
        self.serial += 1;
        let name = format!("unknown/{}/{}", s.id, self.serial);
        let mut fib = Fib::new();
        for p in defaults() {
            fib.insert(
                p,
                Route::unknown_with(RouteKind::Static, code, why.clone(), self.span()),
            );
        }
        let meta = self.meta(&name, self.span());
        self.add(RouteLookup {
            meta,
            tables: BTreeMap::from([(vrf_of(s), fib)]),
            fallback: None,
            local: None,
        });
        self.id(&name)
    }

    /// The business policy of a segment: each rule sends its packets to its
    /// route action for internet traffic. The list ends with an unhandled
    /// rule.
    fn policy(&mut self, s: &EdgeSegment) {
        let e = self.e;
        let sid = s.id;
        let mut rules: Vec<FRule<FunctionId>> = Vec::new();
        match &e.business {
            Policy::NotRead(r) => {
                rules.push(FRule::unhandled(
                    format!("business policy, {r}"),
                    e.span.clone(),
                ));
            }
            Policy::Read(b) => {
                let set = b.segments.iter().find(|x| x.segment == Some(sid));
                for r in set.map(|x| x.rules.as_slice()).unwrap_or_default() {
                    match self.policy_target(s, r) {
                        Ok(next) => rules.push(
                            FRule::new(r.id.clone(), predicate(&r.matches), next)
                                .with_span(r.span.clone()),
                        ),
                        Err(why) => {
                            self.note(format!("business rule {}: {why}", r.id));
                            rules.push(FRule::unhandled(r.id.clone(), r.span.clone()));
                        }
                    }
                }
                let tail = set
                    .and_then(|x| x.unknown_tail.clone())
                    .or_else(|| b.unknown_tail.clone());
                if let Some(t) = tail {
                    rules.push(FRule::unhandled(
                        format!("profile rules, {t}"),
                        e.span.clone(),
                    ));
                }
                rules.push(FRule::unhandled("business policy default", e.span.clone()));
            }
        }
        let meta = self.meta(&format!("policy/{sid}"), self.span());
        self.add(PolicyRoute::new(
            meta,
            ObjectId::new(format!("{}:business:{sid}", e.device)),
            rules.into_iter().map(|r| (None, r)).collect(),
            self.id("deliver"),
        ));
    }

    /// The next function of a business rule for internet traffic: the
    /// direct exit, the gateways or a backhaul hub, after the QoS stanza of
    /// the rule.
    fn policy_target(
        &mut self,
        s: &EdgeSegment,
        r: &Rule<BusinessAction>,
    ) -> Result<FunctionId, String> {
        if r.action.nat {
            return Err("NAT action not lowered".to_string());
        }
        let a = r
            .action
            .routes
            .iter()
            .find(|a| a.target == Target::Cloud)
            .ok_or_else(|| "no route action for internet traffic".to_string())?;
        let next = match &a.route_policy {
            Word::Known(RoutePolicy::Direct) => self.direct(s, a),
            Word::Known(RoutePolicy::Gateway) => {
                let any = self.e.gateways.iter().any(|g| g.segments.contains(&s.id));
                if !any {
                    return Err("no gateway of the segment".to_string());
                }
                let far = Far::Gateways;
                let id = select_id(s.id, &far);
                self.selects.insert((s.id, far));
                self.id(&id)
            }
            Word::Known(RoutePolicy::Backhaul) => {
                let first = a
                    .backhaul
                    .first()
                    .ok_or_else(|| "backhaul with no hub".to_string())?;
                self.hub_target(s, first)?
            }
            Word::Known(RoutePolicy::Auto) => return Err("route policy auto not lowered".into()),
            Word::NotStated => return Err("route policy not stated".to_string()),
            Word::Other(t) => return Err(format!("route policy {t} not known")),
        };
        let Some(q) = &r.action.qos else {
            return Ok(next);
        };
        self.serial += 1;
        let name = format!("policy/{}/qos/{}", s.id, self.serial);
        let meta = self.meta(&name, vec![r.span.clone()]);
        let text = [
            q.class.as_ref().map(|c| format!("service class {c}")),
            q.priority_tx.as_ref().map(|p| format!("priority {p}")),
            q.cap_tx.map(|c| format!("rate limit {c} %")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");
        let stanza = if text.is_empty() {
            format!("{}:business:{}:{}", self.e.device, s.id, r.id)
        } else {
            format!("{}:business:{}:{}: {text}", self.e.device, s.id, r.id)
        };
        self.add(QosNotEvaluated {
            meta,
            stanza: ObjectId::new(stanza),
            next,
        });
        Ok(self.id(&name))
    }

    /// The local WAN links that a route action with the link policy `fixed`
    /// names by its WAN link, its internal id or its interface.
    fn pinned_links(&self, a: &RouteAction) -> Option<BTreeSet<String>> {
        if a.link_policy != Word::Known(LinkPolicy::Fixed) {
            return None;
        }
        let found: BTreeSet<String> = self
            .e
            .links
            .iter()
            .filter(|l| {
                a.wanlink
                    .as_deref()
                    .is_some_and(|w| w == l.logical_id || l.internal_id.as_deref() == Some(w))
                    || a.link_internal
                        .as_deref()
                        .is_some_and(|w| l.internal_id.as_deref() == Some(w))
                    || a.interface
                        .as_deref()
                        .is_some_and(|w| l.interface.as_deref() == Some(w))
            })
            .map(|l| l.logical_id.clone())
            .collect();
        (!found.is_empty()).then_some(found)
    }

    /// The direct exit of a segment.
    fn direct(&mut self, s: &EdgeSegment, a: &RouteAction) -> FunctionId {
        let link = self.pinned_links(a).and_then(|p| p.into_iter().next());
        let name = match &link {
            Some(l) => format!("direct/{}/{l}", s.id),
            None => format!("direct/{}", s.id),
        };
        self.directs.insert((s.id, link));
        self.id(&name)
    }

    /// The tunnel selection to a backhaul hub. A cluster whose hub is not
    /// collected follows the hub choice.
    fn hub_target(&mut self, s: &EdgeSegment, r: &HubRef) -> Result<FunctionId, String> {
        let e = self.e;
        let label = r.name.clone().or_else(|| r.id.clone()).unwrap_or_default();
        let far = match r.edges.as_slice() {
            [] => return Err(format!("hub {label} names no edge")),
            [one] if *one == e.logical_id => return Err("backhaul to the edge itself".into()),
            [one] => Far::Edge(one.clone()),
            many => {
                let cluster = r.cluster.clone().unwrap_or_else(|| label.clone());
                match &e.peers {
                    Peers::Read(rows) => {
                        let live: Vec<String> = many
                            .iter()
                            .filter(|m| {
                                rows.iter().any(|p| {
                                    p.logical_id.as_deref() == Some(m.as_str())
                                        && p.paths.stable.unwrap_or(0)
                                            + p.paths.unstable.unwrap_or(0)
                                            > 0
                                })
                            })
                            .cloned()
                            .collect();
                        match live.as_slice() {
                            [] => {
                                return Ok(self.unknown_target(
                                    s,
                                    ReasonCode::IncompleteTable,
                                    format!("no hub of cluster {cluster} has a path"),
                                ));
                            }
                            [one] => Far::Edge(one.clone()),
                            _ => Far::Cluster {
                                id: cluster,
                                hubs: live,
                            },
                        }
                    }
                    Peers::NotCollected | Peers::Gap(_) => match self.hubs {
                        HubChoice::None => {
                            return Ok(self.unknown_target(
                                s,
                                ReasonCode::NotCollected,
                                format!("hub of cluster {cluster} not collected"),
                            ));
                        }
                        HubChoice::All => Far::Cluster {
                            id: cluster,
                            hubs: many.to_vec(),
                        },
                        HubChoice::One => {
                            self.note(format!("cluster {cluster}: hub {} assumed", many[0]));
                            Far::Edge(many[0].clone())
                        }
                    },
                }
            }
        };
        let id = select_id(s.id, &far);
        self.selects.insert((s.id, far));
        Ok(self.id(&id))
    }

    /// The state of each tunnel to a far end: down when a link is down, and
    /// up when the paths of the peer that are up are the tunnels whose links
    /// are up. The links of a tunnel are up (`Some(true)`), down or not
    /// known.
    fn states(&self, far: &str, links: &[Option<bool>]) -> (Vec<TunnelState>, Vec<SourceSpan>) {
        let Peers::Read(rows) = &self.e.peers else {
            let st = links
                .iter()
                .map(|p| match p {
                    Some(false) => TunnelState::Down,
                    _ => TunnelState::NotCollected,
                })
                .collect();
            return (st, Vec::new());
        };
        let Some(row) = rows.iter().find(|r| r.logical_id.as_deref() == Some(far)) else {
            return (vec![TunnelState::Down; links.len()], Vec::new());
        };
        let live = match (row.paths.stable, row.paths.unstable) {
            (None, None) => None,
            (a, b) => Some(a.unwrap_or(0) + b.unwrap_or(0)),
        };
        let up = links.iter().filter(|p| **p == Some(true)).count();
        let known = links.iter().all(Option::is_some);
        let st = links
            .iter()
            .map(|p| match (live, p) {
                (_, Some(false)) | (Some(0), _) => TunnelState::Down,
                (Some(n), Some(true)) if known && usize::try_from(n).ok() == Some(up) => {
                    TunnelState::Up
                }
                _ => TunnelState::NotCollected,
            })
            .collect();
        (st, vec![row.span.clone()])
    }

    /// The tunnels from the WAN links of the edge to the WAN links of a far
    /// edge.
    fn edge_tunnels(&mut self, far: &str, out: &mut Vec<OverlayTunnel>) {
        let ent = self.ent;
        let Some(fe) = ent.edge(far) else {
            return;
        };
        let wan = self.wan.clone();
        let mut pairs: Vec<(&WanLink, &WanLink, IpAddr)> = Vec::new();
        for l in wan.iter().copied() {
            for fl in fe.links.iter().filter(|f| f.ambiguous.is_none()) {
                if !pairable(l, fl) {
                    continue;
                }
                match (link_address(l), link_address(fl)) {
                    (Some(_), Some(peer)) => pairs.push((l, fl, peer)),
                    _ => self.note(format!(
                        "tunnel {}~{far}:{}: address not known",
                        l.logical_id, fl.logical_id
                    )),
                }
            }
        }
        let links: Vec<Option<bool>> = pairs
            .iter()
            .map(
                |(l, fl, _)| match (link_up(l.state.as_deref()), link_up(fl.state.as_deref())) {
                    (Some(false), _) | (_, Some(false)) => Some(false),
                    (Some(true), Some(true)) => Some(true),
                    _ => None,
                },
            )
            .collect();
        let (states, peer_spans) = self.states(far, &links);
        for ((l, fl, peer), state) in pairs.into_iter().zip(states) {
            let far_link = format!("{far}:{}", fl.logical_id);
            let name = format!("vcmp/{}~{far_link}", l.logical_id);
            self.encaps
                .insert(name.clone(), (l.logical_id.clone(), peer));
            let mut spans = l.spans.clone();
            spans.extend(fl.spans.iter().cloned());
            spans.extend(peer_spans.iter().cloned());
            out.push(OverlayTunnel {
                link: l.logical_id.clone(),
                far_link,
                state,
                next: self.id(&name),
                spans,
            });
        }
    }

    /// The tunnels from the public WAN links of the edge to the gateways of
    /// a segment.
    fn gateway_tunnels(&mut self, s: &EdgeSegment, out: &mut Vec<OverlayTunnel>) {
        let e = self.e;
        let public: Vec<&WanLink> = self
            .wan
            .iter()
            .copied()
            .filter(|l| matches!(l.kind, LinkKind::Public { .. }) && link_address(l).is_some())
            .collect();
        for g in e.gateways.iter().filter(|g| g.segments.contains(&s.id)) {
            let Some(addr) = g.address else {
                self.note(format!("gateway {}: address not known", g.id));
                continue;
            };
            let links: Vec<Option<bool>> =
                public.iter().map(|l| link_up(l.state.as_deref())).collect();
            let (states, peer_spans) = self.states(&g.id, &links);
            for (l, state) in public.iter().zip(states) {
                let far_link = format!("gateway/{}", g.id);
                let name = format!("vcmp/{}~{far_link}", l.logical_id);
                self.encaps
                    .insert(name.clone(), (l.logical_id.clone(), addr));
                if let Some(t) = self.transport(l) {
                    self.gateways.push((t, g.id.clone(), addr, g.span.clone()));
                }
                let mut spans = l.spans.clone();
                spans.push(g.span.clone());
                spans.extend(peer_spans.iter().cloned());
                out.push(OverlayTunnel {
                    link: l.logical_id.clone(),
                    far_link,
                    state,
                    next: self.id(&name),
                    spans,
                });
            }
        }
    }

    /// The steering rules of the tunnels to a far end: the business rules of
    /// the segment in order, each with the links that it pins with the link
    /// policy `fixed`, else with each link. With no pinned link, the
    /// selection has no steering rule.
    fn steering(
        &self,
        s: &EdgeSegment,
        far: &Far,
        tunnels: &[OverlayTunnel],
    ) -> Vec<FRule<BTreeSet<String>>> {
        let e = self.e;
        let (rules, tail): (&[Rule<BusinessAction>], Option<String>) = match &e.business {
            Policy::NotRead(r) => {
                return vec![FRule::unhandled(
                    format!("business policy, {r}"),
                    e.span.clone(),
                )];
            }
            Policy::Read(b) => match b.segments.iter().find(|x| x.segment == Some(s.id)) {
                Some(x) => (
                    x.rules.as_slice(),
                    x.unknown_tail.clone().or_else(|| b.unknown_tail.clone()),
                ),
                None => (&[], b.unknown_tail.clone()),
            },
        };
        let targets = if *far == Far::Gateways {
            [Target::Cloud, Target::Edge]
        } else {
            [Target::Edge, Target::Cloud]
        };
        let all: BTreeSet<String> = tunnels.iter().map(|t| t.link.clone()).collect();
        let mut pinned = false;
        let mut out = Vec::new();
        for r in rules {
            let action = targets
                .iter()
                .find_map(|t| r.action.routes.iter().find(|a| a.target == *t));
            let links = match action.and_then(|a| self.pinned_links(a)) {
                Some(l) => {
                    pinned = true;
                    l
                }
                None => all.clone(),
            };
            out.push(
                FRule::new(r.id.clone(), predicate(&r.matches), links).with_span(r.span.clone()),
            );
        }
        if let Some(t) = tail {
            pinned = true;
            out.push(FRule::unhandled(
                format!("profile rules, {t}"),
                e.span.clone(),
            ));
        }
        if pinned { out } else { Vec::new() }
    }

    /// The tunnel selection of a segment to a far end.
    fn select(&mut self, s: &EdgeSegment, far: &Far) {
        let mut tunnels = Vec::new();
        match far {
            Far::Edge(x) => self.edge_tunnels(x, &mut tunnels),
            Far::Cluster { hubs, .. } => {
                for h in hubs {
                    self.edge_tunnels(h, &mut tunnels);
                }
            }
            Far::Gateways => self.gateway_tunnels(s, &mut tunnels),
        }
        let steering = self.steering(s, far, &tunnels);
        let meta = self.meta(&select_id(s.id, far), self.span());
        self.add(OverlaySelect {
            meta,
            far: far.name().to_string(),
            tunnels,
            steering,
        });
    }

    /// The VCMP encapsulation of each tunnel.
    fn encaps(&mut self) {
        let e = self.e;
        let segments: BTreeMap<VrfId, u32> = e.segments.iter().map(|s| (vrf_of(s), s.id)).collect();
        let encaps = std::mem::take(&mut self.encaps);
        for (name, (lid, peer)) in encaps {
            let Some(l) = self.wan.iter().copied().find(|l| l.logical_id == lid) else {
                continue;
            };
            let Some(source) = link_address(l) else {
                continue;
            };
            let meta = self.meta(&name, l.spans.clone());
            self.add(VcmpEncap {
                meta,
                source,
                peer,
                segments: segments.clone(),
                src_port: FieldValue::Known(VCMP_PORT),
                dscp: FieldValue::Unknown,
                ecn: FieldValue::Unknown,
                underlay: VrfId::new(UNDERLAY),
                interface: InterfaceId::new(wan_iface(l)),
                gateway: match l.gateway {
                    Some(g) => NextHop::Gateway(g),
                    None => NextHop::Connected,
                },
                next: self.id("nexthop/wan"),
            });
        }
    }

    /// The direct exits: a default route of each family through the public
    /// WAN links, or through the pinned link, then the source NAT, the
    /// session commit, the next hop and an egress that leaves the twin. With
    /// a stateless firewall, the commit keeps a session only for a
    /// translated flow.
    fn directs(&mut self) {
        let e = self.e;
        let directs = std::mem::take(&mut self.directs);
        if directs.is_empty() {
            return;
        }
        for (sid, link) in &directs {
            let Some(s) = self.segment(*sid) else {
                continue;
            };
            let links: Vec<&WanLink> = self
                .wan
                .iter()
                .copied()
                .filter(|l| match link {
                    Some(x) => l.logical_id == *x,
                    None => matches!(l.kind, LinkKind::Public { .. }),
                })
                .collect();
            let mut fib = Fib::new();
            for (p, v4) in defaults().into_iter().zip([true, false]) {
                let hops: Vec<RouteNextHop> = links
                    .iter()
                    .filter(|l| l.gateway.map_or(v4, |g| g.is_ipv4() == v4))
                    .map(|l| self.nh(&wan_iface(l), l.gateway, "snat"))
                    .collect();
                let spans: Vec<SourceSpan> = links.iter().flat_map(|l| l.spans.clone()).collect();
                let route = if hops.is_empty() {
                    Route::unknown(
                        RouteKind::Static,
                        "no WAN link for direct traffic",
                        self.span(),
                    )
                } else {
                    Route::new(RouteKind::Static, hops, spans)
                };
                fib.insert(p, route);
            }
            let name = match link {
                Some(l) => format!("direct/{sid}/{l}"),
                None => format!("direct/{sid}"),
            };
            let meta = self.meta(&name, self.span());
            self.add(RouteLookup {
                meta,
                tables: BTreeMap::from([(vrf_of(s), fib)]),
                fallback: None,
                local: None,
            });
        }
        let mut rules = Vec::new();
        for l in self.wan.clone() {
            let iface = wan_iface(l);
            let own = e.interfaces.iter().find(|i| i.wan && i.name == iface);
            let scope = Some(BTreeSet::from([InterfaceId::new(&iface)]));
            let name = format!("nat-direct/{iface}");
            let span = own.map_or_else(|| e.span.clone(), |i| i.span.clone());
            let rule = match (own.and_then(|i| i.nat_direct), own.and_then(|i| i.address)) {
                (Some(true), Some((addr, _))) => FRule::new(
                    name,
                    RulePredicate::exact(Match::any()),
                    NatAction::Translate {
                        addr,
                        port: self.profile.snat_port,
                    },
                )
                .with_span(span),
                (Some(false), _) => FRule::new(
                    name,
                    RulePredicate::exact(Match::any()),
                    NatAction::NoTranslate,
                )
                .with_span(span),
                _ => {
                    self.note(format!("interface {iface}: NAT Direct not known"));
                    FRule::unhandled(name, span)
                }
            };
            rules.push((scope, rule));
        }
        let meta = self.meta("snat", self.span());
        self.add(SourceNat::new(
            meta,
            ObjectId::new(format!("{}:nat-direct", e.device)),
            rules,
            self.id("commit"),
        ));
        let meta = self.meta("commit", self.span());
        let keep_untranslated = self.stateful();
        self.add(SessionCommit {
            meta,
            next: self.id("nexthop/direct"),
            keep_untranslated,
        });
        let meta = self.meta("nexthop/direct", self.span());
        let mut egress = BTreeMap::new();
        let mut p2p = BTreeMap::new();
        for l in self.wan.clone() {
            let iface = wan_iface(l);
            let owner = l
                .isp
                .clone()
                .or_else(|| l.name.clone())
                .unwrap_or_else(|| "provider".to_string());
            egress.insert(InterfaceId::new(&iface), self.id(&format!("exit/{iface}")));
            p2p.insert(InterfaceId::new(&iface), owner);
        }
        self.add(NextHopResolution {
            meta,
            neighbours: TriePrefixTable::new(),
            complete: false,
            egress,
            point_to_point: p2p,
        });
        for l in self.wan.clone() {
            let iface = wan_iface(l);
            let meta = self.meta(&format!("exit/{iface}"), l.spans.clone());
            self.add(Egress {
                meta,
                interface: InterfaceId::new(&iface),
                mode: EgressMode::Routed,
                link: None,
                rewrite: Default::default(),
                tag: Default::default(),
                exit: Some(ExitMark::AccessLink),
            });
        }
    }

    /// The WAN side: the ingress, the route lookup of the underlay, the
    /// decapsulation, the inbound rules, the next hop and the egress of each
    /// WAN link.
    fn wan_side(&mut self) {
        let e = self.e;
        let wan = self.wan.clone();
        let mut underlay = Fib::new();
        let mut vrf = BTreeMap::new();
        let mut egress = BTreeMap::new();
        let mut p2p = BTreeMap::new();
        for l in &wan {
            let iface = wan_iface(l);
            let meta = self.meta(&format!("in/{iface}"), l.spans.clone());
            self.add(Ingress {
                meta,
                interface: InterfaceId::new(&iface),
                next: self.id("wan/vrf"),
            });
            vrf.insert(InterfaceId::new(&iface), VrfId::new(UNDERLAY));
            for a in [l.address, l.local].into_iter().flatten() {
                underlay.insert(
                    Prefix::host(a),
                    Route::new(RouteKind::Local, Vec::new(), l.spans.clone()),
                );
            }
            let transport = self.transport(l);
            let owner = transport.clone().unwrap_or_else(|| "provider".to_string());
            egress.insert(InterfaceId::new(&iface), self.id(&format!("out/{iface}")));
            p2p.insert(InterfaceId::new(&iface), owner);
            let port = format!("{}:{}", e.logical_id, l.logical_id);
            let link = transport.as_ref().map(|t| Link {
                peer: Some(FunctionId::new(format!("{t}/in/{port}"))),
                delay_ns: None,
                provenance: l.spans.clone(),
                facts: None,
            });
            match &transport {
                Some(t) => self.members.push((
                    t.clone(),
                    Member {
                        edge: e.device.clone(),
                        interface: iface.clone(),
                        port,
                        address: link_address(l),
                        spans: l.spans.clone(),
                    },
                )),
                None => self.note(format!(
                    "link {}: no transport network for its kind",
                    l.logical_id
                )),
            }
            let meta = self.meta(&format!("out/{iface}"), l.spans.clone());
            self.add(Egress {
                meta,
                interface: InterfaceId::new(&iface),
                mode: EgressMode::Routed,
                link,
                rewrite: Default::default(),
                tag: Default::default(),
                exit: None,
            });
        }
        if wan.is_empty() {
            return;
        }
        let meta = self.meta("wan/vrf", self.span());
        self.add(VrfSelection {
            meta,
            by_interface: vrf,
            default_vrf: None,
            next: self.id("wan/route"),
        });
        let meta = self.meta("wan/route", self.span());
        self.add(RouteLookup {
            meta,
            tables: BTreeMap::from([(VrfId::new(UNDERLAY), underlay)]),
            fallback: None,
            local: Some(self.id("vcmp/decap")),
        });
        let meta = self.meta("nexthop/wan", self.span());
        self.add(NextHopResolution {
            meta,
            neighbours: TriePrefixTable::new(),
            complete: false,
            egress,
            point_to_point: p2p,
        });
        let plain = self.inbound();
        let next = self.id("overlay/session");
        let segments = e
            .segments
            .iter()
            .map(|s| (s.id, (vrf_of(s), next.clone())))
            .collect();
        let meta = self.meta("vcmp/decap", self.span());
        self.add(VcmpDecap {
            meta,
            segments,
            plain,
        });
        let meta = self.meta("overlay/session", self.span());
        self.add(SessionLookup {
            meta,
            next: self.id("route"),
            states: StateActions::default(),
        });
    }

    /// The inbound rules of the firewall: port forwarding and 1:1 NAT of
    /// the packets with no VCMP encapsulation, into the Global Segment. With
    /// no inbound rule, the packets are for the edge.
    fn inbound(&mut self) -> Option<FunctionId> {
        let e = self.e;
        let global = e.segments.iter().find(|s| s.global)?;
        let mut rules: Vec<FRule<NatAction>> = Vec::new();
        let mut scopes = Vec::new();
        match &e.firewall {
            Policy::NotRead(r) => {
                rules.push(FRule::unhandled(format!("firewall, {r}"), e.span.clone()));
                scopes.push(None);
            }
            Policy::Read(fw) => {
                for r in fw.inbound.iter().chain(&fw.inbound_v6) {
                    scopes.push(
                        r.action
                            .interface
                            .as_ref()
                            .map(|i| BTreeSet::from([InterfaceId::new(i)])),
                    );
                    match inbound_action(&r.action) {
                        Some(a) => rules.push(
                            FRule::new(r.id.clone(), predicate(&r.matches), a)
                                .with_span(r.span.clone()),
                        ),
                        None => {
                            self.note(format!("inbound rule {}: action not lowered", r.id));
                            rules.push(FRule::unhandled(r.id.clone(), r.span.clone()));
                        }
                    }
                }
                if let Some(t) = &fw.unknown_tail {
                    rules.push(FRule::unhandled(
                        format!("profile rules, {t}"),
                        e.span.clone(),
                    ));
                    scopes.push(None);
                }
            }
        }
        if rules.is_empty() {
            return None;
        }
        let meta = self.meta("inbound/session", self.span());
        self.add(SessionLookup {
            meta,
            next: self.id("inbound/dnat"),
            states: StateActions::default(),
        });
        let meta = self.meta("inbound/dnat", self.span());
        self.add(DestinationNat {
            meta,
            table: ObjectId::new(format!("{}:firewall:inbound", e.device)),
            rules,
            ingress: scopes,
            next: self.id("inbound/commit"),
        });
        let meta = self.meta("inbound/commit", self.span());
        self.add(SessionCommit {
            meta,
            next: self.id("inbound/vrf"),
            keep_untranslated: true,
        });
        let meta = self.meta("inbound/vrf", self.span());
        self.add(VrfSelection {
            meta,
            by_interface: BTreeMap::new(),
            default_vrf: Some(vrf_of(global)),
            next: self.id("route"),
        });
        Some(self.id("inbound/session"))
    }
}

/// The translation of an inbound rule: port forwarding to the LAN address
/// and port, or 1:1 NAT to the LAN address.
fn inbound_action(a: &Inbound) -> Option<NatAction> {
    let addr = a.lan_ip?;
    match a.kind {
        Word::Known(InboundKind::PortForwarding) => Some(NatAction::Translate {
            addr,
            port: a
                .lan_port
                .map_or(PortTranslation::Preserve, PortTranslation::To),
        }),
        Word::Known(InboundKind::OneToOneNat) => Some(NatAction::Translate {
            addr,
            port: PortTranslation::Preserve,
        }),
        _ => None,
    }
}

/// The route of a prefix from its candidates: the candidate that the route
/// order puts before each other candidate, or the next hops of the
/// candidates of the same place. A pair of candidates whose order is not
/// known gives a route whose packets are unknown.
fn winner(p: Prefix, cs: &[Candidate]) -> Route {
    let beaten = |i: usize| {
        cs.iter()
            .enumerate()
            .any(|(j, o)| j != i && order((p, o.class), (p, cs[i].class)) == Some(Ordering::Less))
    };
    let best: Vec<&Candidate> = cs
        .iter()
        .enumerate()
        .filter(|(i, _)| !beaten(*i))
        .map(|(_, c)| c)
        .collect();
    let spans: Vec<SourceSpan> = best.iter().flat_map(|c| c.route.spans.clone()).collect();
    if let [one] = best.as_slice() {
        return one.route.clone();
    }
    let equal = !best.is_empty()
        && best.iter().all(|a| {
            best.iter()
                .all(|b| order((p, a.class), (p, b.class)) == Some(Ordering::Equal))
        });
    if !equal {
        let spans = cs.iter().flat_map(|c| c.route.spans.clone()).collect();
        return Route::unknown(
            RouteKind::Static,
            format!("route order of {p} not known"),
            spans,
        );
    }
    if best.iter().any(|c| c.route.next_hops().is_empty()) {
        return Route::unknown(
            RouteKind::Static,
            format!("a route of {p} not known"),
            spans,
        );
    }
    let kind = best.first().map_or(RouteKind::Static, |c| c.route.kind);
    let hops: Vec<RouteNextHop> = best
        .iter()
        .flat_map(|c| c.route.next_hops().to_vec())
        .collect();
    Route::new(kind, hops, spans)
}

/// Lowers the edges of an enterprise and the transport networks between
/// their WAN links. `hubs` gives the hub of a cluster whose hub is not
/// collected.
pub fn lower(ent: &Enterprise, profile: &VendorProfile, hubs: HubChoice) -> Lowered {
    let mut out = Lowered::default();
    let mut transports: BTreeMap<String, Transport> = BTreeMap::new();
    for e in &ent.edges {
        let mut l = L {
            ent,
            e,
            profile,
            hubs,
            functions: Vec::new(),
            edges: Vec::new(),
            notes: e.notes.clone(),
            wan: Vec::new(),
            selects: BTreeSet::new(),
            directs: BTreeSet::new(),
            encaps: BTreeMap::new(),
            serial: 0,
            members: Vec::new(),
            gateways: Vec::new(),
        };
        l.lower();
        out.functions.extend(l.functions);
        out.edges.extend(l.edges);
        for (t, m) in l.members {
            transports.entry(t).or_default().members.push(m);
        }
        for (t, id, addr, span) in l.gateways {
            transports
                .entry(t)
                .or_default()
                .gateways
                .entry(id)
                .or_insert((addr, span));
        }
        out.notes.insert(e.device.clone(), l.notes);
    }
    for (name, t) in &transports {
        let notes = transport(name, t, profile, &mut out.functions);
        if !notes.is_empty() {
            out.notes.insert(name.clone(), notes);
        }
    }
    if !ent.notes.is_empty() {
        out.notes
            .entry(ent.store_device.clone())
            .or_default()
            .extend(ent.notes.iter().cloned());
    }
    out.functions = reachable(std::mem::take(&mut out.functions));
    out
}

/// The functions that a packet can reach from an ingress function.
fn reachable(functions: Vec<Arc<dyn NetFunction>>) -> Vec<Arc<dyn NetFunction>> {
    let by_id: BTreeMap<FunctionId, usize> = functions
        .iter()
        .enumerate()
        .map(|(i, f)| (f.id().clone(), i))
        .collect();
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let mut todo: Vec<usize> = functions
        .iter()
        .enumerate()
        .filter(|(_, f)| f.ingress_interface().is_some())
        .map(|(i, _)| i)
        .collect();
    while let Some(i) = todo.pop() {
        if !seen.insert(i) {
            continue;
        }
        for s in functions[i].successors() {
            if let Some(j) = by_id.get(&s) {
                todo.push(*j);
            }
        }
    }
    functions
        .into_iter()
        .enumerate()
        .filter(|(i, _)| seen.contains(i))
        .map(|(_, f)| f)
        .collect()
}

/// An end of a host route of a transport network: the interface, the
/// gateway and the spans.
type HostEnd = (String, Option<IpAddr>, Vec<SourceSpan>);

/// The functions of a transport network: an ingress and an egress for each
/// WAN link, a host route to each link address, and a host route to each
/// gateway with an egress that leaves the twin.
fn transport(
    name: &str,
    t: &Transport,
    profile: &VendorProfile,
    functions: &mut Vec<Arc<dyn NetFunction>>,
) -> Vec<String> {
    let id = |f: &str| FunctionId::new(format!("{name}/{f}"));
    let meta = |f: &str, spans: Vec<SourceSpan>| {
        let mut m = Meta::new(id(f), name, profile);
        m.provenance = spans;
        m
    };
    let mut notes = Vec::new();
    let all: Vec<SourceSpan> = t.members.iter().flat_map(|m| m.spans.clone()).collect();
    let mut hosts: BTreeMap<Prefix, Vec<HostEnd>> = BTreeMap::new();
    let mut vrf = BTreeMap::new();
    let mut egress = BTreeMap::new();
    let mut p2p = BTreeMap::new();
    for m in &t.members {
        functions.push(Arc::new(Ingress {
            meta: meta(&format!("in/{}", m.port), m.spans.clone()),
            interface: InterfaceId::new(&m.port),
            next: id("vrf"),
        }));
        vrf.insert(InterfaceId::new(&m.port), VrfId::new(TRANSPORT_VRF));
        egress.insert(InterfaceId::new(&m.port), id(&format!("out/{}", m.port)));
        p2p.insert(InterfaceId::new(&m.port), m.edge.clone());
        functions.push(Arc::new(Egress {
            meta: meta(&format!("out/{}", m.port), m.spans.clone()),
            interface: InterfaceId::new(&m.port),
            mode: EgressMode::Routed,
            link: Some(Link {
                peer: Some(FunctionId::new(format!("{}/in/{}", m.edge, m.interface))),
                delay_ns: None,
                provenance: m.spans.clone(),
                facts: None,
            }),
            rewrite: Default::default(),
            tag: Default::default(),
            exit: None,
        }));
        match m.address {
            Some(a) => hosts.entry(Prefix::host(a)).or_default().push((
                m.port.clone(),
                None,
                m.spans.clone(),
            )),
            None => notes.push(format!("{}: address not known", m.port)),
        }
    }
    for (g, (addr, span)) in &t.gateways {
        let port = format!("gateway/{g}");
        egress.insert(InterfaceId::new(&port), id(&format!("out/{port}")));
        p2p.insert(InterfaceId::new(&port), format!("gateway {g}"));
        functions.push(Arc::new(Egress {
            meta: meta(&format!("out/{port}"), vec![span.clone()]),
            interface: InterfaceId::new(&port),
            mode: EgressMode::Routed,
            link: None,
            rewrite: Default::default(),
            tag: Default::default(),
            exit: Some(ExitMark::AccessLink),
        }));
        hosts
            .entry(Prefix::host(*addr))
            .or_default()
            .push((port, Some(*addr), vec![span.clone()]));
    }
    let mut fib = Fib::new();
    for (p, ends) in &hosts {
        let spans: Vec<SourceSpan> = ends.iter().flat_map(|e| e.2.clone()).collect();
        let route = match ends.as_slice() {
            [(port, gateway, _)] => Route::new(
                RouteKind::Connected,
                vec![RouteNextHop {
                    interface: InterfaceId::new(port),
                    gateway: *gateway,
                    next: id("nexthop"),
                }],
                spans,
            ),
            _ => {
                let ports: Vec<&str> = ends.iter().map(|e| e.0.as_str()).collect();
                notes.push(format!("{}: address of {}", p.addr(), ports.join(", ")));
                Route::unknown(
                    RouteKind::Connected,
                    format!("{} links with the address", ends.len()),
                    spans,
                )
            }
        };
        fib.insert(*p, route);
    }
    functions.push(Arc::new(VrfSelection {
        meta: meta("vrf", all.clone()),
        by_interface: vrf,
        default_vrf: Some(VrfId::new(TRANSPORT_VRF)),
        next: id("route"),
    }));
    functions.push(Arc::new(TransportLookup {
        lookup: RouteLookup {
            meta: meta("route", all.clone()),
            tables: BTreeMap::from([(VrfId::new(TRANSPORT_VRF), fib)]),
            fallback: None,
            local: None,
        },
    }));
    functions.push(Arc::new(NextHopResolution {
        meta: meta("nexthop", all),
        neighbours: TriePrefixTable::new(),
        complete: false,
        egress,
        point_to_point: p2p,
    }));
    notes
}
