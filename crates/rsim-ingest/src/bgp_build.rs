//! The BGP calculation of the twin: the processes of the lowered devices,
//! the sessions between them from the far ends of the link join, the seeds
//! from the peers outside the twin, the IGP view of the computed route
//! tables with no BGP candidate, the gaps and the BGP routes of each device
//! and VRF for the RIB guard.
//!
//! A configured neighbour with a peer address is one of 3 things. With a
//! paired far end whose neighbour is lowered too, it is one end of a
//! session. With a far end outside the twin, it gives seeds from one
//! source: the paths of its received table of the section `bgp_routes`,
//! which go through the import policy, else the paths of its accepted
//! table, else the collected BGP routes of its VRF whose next hop is its
//! address, with attributes that are not collected. A table is a source
//! only when it is read whole and holds each collected BGP route of the VRF
//! whose next hop is the address of the neighbour. The router ID of a seed
//! is the router ID of the neighbour of the section `bgp_neighbors`, else
//! not known. Each other neighbour is a gap of its VRF.
//!
//! A gap covers each process in the component of its VRF over the sessions
//! and the far ends of the neighbours, for the families of the gap. A
//! computed BGP route under a gap is unknown with the reason of the gap,
//! and a collected BGP route under a gap is not computed, unless it is
//! seeded. A collected BGP route is seeded when each of its next hops is a
//! peer outside the twin. A collected BGP route of a key of a group whose
//! convergence is unknown is not computed with the reason of the group.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use rsim_core::{Prefix, SourceSpan};
use rsim_functions::{Fib, Route, RouteKind, RouteProtocol};
use rsim_guard::Class;
use rsim_routing::bgp::{
    AsPath, BgpInput, BgpPath, BgpProcess, BgpResult, Convergence, Event, Family, IgpView, Peer,
    Resolution, RouteAt, RouteKey, RouteState, Seed, Session, SessionEnd, SessionKind,
    install_candidates,
};
use rsim_routing::{Candidate, Origin, Platform};

use crate::bgp_config::{DeviceBgp, GAP, Gap, UNICAST};
use crate::bgp_peers::DEFAULT_VRF;
use crate::links::{BgpFar, BgpPeer, BgpPeerFact, FarSide, PeerSource};
use crate::scenario::NOT_RECOMPUTED;

/// The device and the VRF of a process.
type Node = (String, String);

/// An edge between 2 processes of the components of the gaps.
type Edge = (Node, Node);

/// The kind of a BGP route.
pub const BGP: RouteKind = RouteKind::Learned(RouteProtocol::Bgp);

/// The IGP view of a VRF: the computed route table of the install stage
/// with no BGP candidate, the metric of each computed OSPF route, and the
/// reason why the OSPF of a family is not computed in full.
#[derive(Clone, Debug, Default)]
pub struct IgpTable {
    pub routes: BTreeMap<Prefix, Route>,
    /// The metric of each computed OSPF route, or the reason why the route
    /// is unknown.
    pub ospf: BTreeMap<Prefix, Result<u32, String>>,
    /// The reason of each family, `true` for IPv4, whose OSPF version runs
    /// in the VRF and is not computed in full.
    pub incomplete: BTreeMap<bool, String>,
}

/// True if a route of the computed table is unknown.
fn unknown_route(r: &Route) -> bool {
    r.unknown_reason().is_some()
        || (r.next_hops().is_empty() && !matches!(r.kind, RouteKind::Local | RouteKind::Null))
}

impl IgpTable {
    /// The longest route that holds `addr`. A default route resolves no
    /// next hop.
    pub fn lookup(&self, addr: IpAddr) -> Option<(Prefix, &Route)> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (1..=max).rev().find_map(|len| {
            let p = Prefix::new(addr, len);
            self.routes.get(&p).map(|r| (p, r))
        })
    }

    /// The resolution of `addr`. A connected or a local route gives the
    /// cost 0. With the OSPF of the family not computed in full, each other
    /// lookup is unknown. A static route gives the cost 0 and an OSPF route
    /// its metric. Each other route, an unknown route and no route give an
    /// unknown resolution.
    pub fn resolve(&self, addr: IpAddr) -> Resolution {
        let found = self.lookup(addr);
        if let Some((_, r)) = found
            && matches!(r.kind, RouteKind::Connected | RouteKind::Local)
            && !unknown_route(r)
        {
            return Resolution::Resolved { cost: 0 };
        }
        if let Some(why) = self.incomplete.get(&addr.is_ipv4()) {
            return Resolution::Unknown(why.clone());
        }
        let Some((p, r)) = found else {
            return Resolution::Unknown("no computed route".to_string());
        };
        if unknown_route(r) {
            let why = r.unknown_reason().unwrap_or("a route with no next hop");
            return Resolution::Unknown(format!("route {p} unknown: {why}"));
        }
        match r.kind {
            RouteKind::Static => Resolution::Resolved { cost: 0 },
            RouteKind::Learned(RouteProtocol::Ospf) => match self.ospf.get(&p) {
                Some(Ok(m)) => Resolution::Resolved { cost: *m },
                Some(Err(why)) => Resolution::Unknown(format!("route {p} unknown: {why}")),
                None => Resolution::Unknown(format!("no OSPF metric of route {p}")),
            },
            RouteKind::Null => Resolution::Unknown(format!("route {p} is a discard route")),
            k => Resolution::Unknown(format!("cost of the {} route {p} not known", k.name())),
        }
    }

    /// Whether the computed table holds a route of `prefix`. With the OSPF
    /// of the family not computed in full, only a connected or a local route
    /// gives an answer.
    pub fn has_route(&self, prefix: Prefix) -> Option<bool> {
        let r = self.routes.get(&prefix);
        if let Some(r) = r
            && matches!(r.kind, RouteKind::Connected | RouteKind::Local)
            && !unknown_route(r)
        {
            return Some(true);
        }
        if self.incomplete.contains_key(&prefix.is_ipv4()) {
            return None;
        }
        match r {
            Some(r) if unknown_route(r) => None,
            Some(_) => Some(true),
            None => Some(false),
        }
    }
}

/// The IGP view of the BGP calculation over the computed tables of each
/// device and VRF. A next hop inside a BGP prefix of `bgp` that is longer
/// than the route of the computed table has an unknown resolution.
pub struct Igp<'a> {
    pub tables: &'a BTreeMap<(String, String), IgpTable>,
    /// The prefixes of the collected BGP routes of each device and VRF and
    /// the keys of the BGP calculation of its component.
    pub bgp: &'a BTreeMap<(String, String), BTreeSet<Prefix>>,
}

impl IgpView for Igp<'_> {
    fn resolve(&self, device: &str, vrf: &str, next_hop: IpAddr) -> Resolution {
        let at = (device.to_string(), vrf.to_string());
        let Some(t) = self.tables.get(&at) else {
            return Resolution::Unknown("no computed route table of the VRF".to_string());
        };
        let len = t.lookup(next_hop).map_or(0, |(p, _)| p.len());
        if let Some(q) = self.bgp.get(&at).and_then(|s| {
            s.iter()
                .filter(|q| q.len() > len && q.contains(next_hop))
                .max_by_key(|q| q.len())
        }) {
            return Resolution::Unknown(format!("next hop inside the bgp prefix {q}"));
        }
        t.resolve(next_hop)
    }

    fn has_route(&self, device: &str, vrf: &str, prefix: Prefix) -> Option<bool> {
        self.tables
            .get(&(device.to_string(), vrf.to_string()))?
            .has_route(prefix)
    }
}

/// A collected BGP route of a VRF with its next hops.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectedBgp {
    pub vrf: String,
    pub prefix: Prefix,
    pub next_hops: Vec<IpAddr>,
    pub spans: Vec<SourceSpan>,
}

/// The input of one lowered device.
#[derive(Clone, Debug)]
pub struct DeviceInput {
    pub platform: Platform,
    pub bgp: DeviceBgp,
    /// The computed IGP table of each VRF.
    pub igp: BTreeMap<String, IgpTable>,
    pub collected: Vec<CollectedBgp>,
    /// The tables of the neighbours of the section `bgp_routes`.
    pub tables: Vec<crate::bgp_routes::Table>,
    /// The router ID of each neighbour by VRF and address, from the section
    /// `bgp_neighbors`.
    pub router_ids: BTreeMap<(String, IpAddr), Ipv4Addr>,
}

/// The BGP routes of one device and VRF for the RIB guard.
#[derive(Clone, Debug, Default)]
pub struct VrfBgp {
    /// The install candidates of the computed BGP routes.
    pub candidates: Vec<Candidate>,
    /// The class of each collected BGP route that is not compared.
    pub classes: BTreeMap<Prefix, Class>,
    /// The class of a collected BGP route that `classes` does not hold;
    /// `None` for a compared route.
    pub otherwise: Option<Class>,
}

impl VrfBgp {
    /// The class of the collected BGP route of `prefix`.
    pub fn class(&self, prefix: Prefix) -> Class {
        self.classes
            .get(&prefix)
            .cloned()
            .or_else(|| self.otherwise.clone())
            .unwrap_or(Class::Compared)
    }

    /// The BGP routes of a VRF in a scenario: an unknown candidate with the
    /// reason [`NOT_RECOMPUTED`] for each BGP route of the computed table of
    /// the base, with the distance `distance`, and each collected BGP route
    /// not computed with that reason.
    pub fn scenario(base: &Fib, distance: u8) -> VrfBgp {
        let candidates = base
            .entries()
            .into_iter()
            .filter(|(_, r)| r.kind == BGP)
            .map(|(p, r)| Candidate::new(p, distance, Route::unknown(BGP, NOT_RECOMPUTED, r.spans)))
            .collect();
        VrfBgp {
            candidates,
            classes: BTreeMap::new(),
            otherwise: Some(Class::NotComputed(NOT_RECOMPUTED.to_string())),
        }
    }
}

/// The BGP calculation of the twin with its input.
#[derive(Clone, Debug)]
pub struct BgpBuild {
    pub input: BgpInput,
    /// The computed IGP table of each device and VRF.
    pub igp: BTreeMap<(String, String), IgpTable>,
    /// The BGP prefixes of each device and VRF of the IGP view.
    pub bgp_prefixes: BTreeMap<(String, String), BTreeSet<Prefix>>,
    /// The result, or the reason why the calculation did not run. `None`
    /// with no process.
    pub result: Option<Result<BgpResult, String>>,
    /// The BGP routes of each device and VRF.
    pub vrfs: BTreeMap<String, BTreeMap<String, VrfBgp>>,
    /// The gaps of each device with their reasons.
    pub gaps: BTreeMap<String, Vec<String>>,
    /// The notes of each device, and of the estate under `estate`.
    pub notes: BTreeMap<String, Vec<String>>,
}

/// The reason of a gap of a device.
pub fn reason(device: &str, g: &Gap) -> String {
    if g.vrf == DEFAULT_VRF {
        format!("{GAP}: {} on {device}", g.text)
    } else {
        format!("{GAP}: {} in vrf {} on {device}", g.text, g.vrf)
    }
}

fn family(p: Prefix) -> Family {
    if p.is_ipv4() {
        Family::Ipv4Unicast
    } else {
        Family::Ipv6Unicast
    }
}

/// The session between the neighbour `a` of the process `d` `v` and the
/// neighbour `x` of the process `fd` `fv`, with the lower end first.
fn session(d: &str, v: &str, a: IpAddr, fd: &str, fv: &str, x: IpAddr) -> Session {
    let one = SessionEnd {
        device: d.to_string(),
        vrf: v.to_string(),
        neighbor: a,
    };
    let two = SessionEnd {
        device: fd.to_string(),
        vrf: fv.to_string(),
        neighbor: x,
    };
    if one <= two {
        Session { a: one, b: two }
    } else {
        Session { a: two, b: one }
    }
}

/// The components of the processes over the edges, with the gaps of each.
struct Components {
    root: BTreeMap<(String, String), usize>,
    /// The gaps of each component, by device, VRF and text.
    gaps: BTreeMap<usize, Vec<(String, Gap)>>,
}

impl Components {
    fn new(
        nodes: impl IntoIterator<Item = (String, String)>,
        edges: &[Edge],
        gaps: &[(String, Gap)],
    ) -> Components {
        let mut ids: BTreeMap<(String, String), usize> = BTreeMap::new();
        let all = nodes
            .into_iter()
            .chain(edges.iter().flat_map(|(a, b)| [a.clone(), b.clone()]))
            .chain(gaps.iter().map(|(d, g)| (d.clone(), g.vrf.clone())));
        for n in all {
            let next = ids.len();
            ids.entry(n).or_insert(next);
        }
        let mut parent: Vec<usize> = (0..ids.len()).collect();
        fn find(parent: &mut [usize], mut i: usize) -> usize {
            while parent[i] != i {
                parent[i] = parent[parent[i]];
                i = parent[i];
            }
            i
        }
        for (a, b) in edges {
            let (x, y) = (find(&mut parent, ids[a]), find(&mut parent, ids[b]));
            if x != y {
                parent[x.max(y)] = x.min(y);
            }
        }
        let root: BTreeMap<(String, String), usize> = ids
            .iter()
            .map(|(k, i)| (k.clone(), find(&mut parent, *i)))
            .collect();
        let mut by: BTreeMap<usize, Vec<(String, Gap)>> = BTreeMap::new();
        for (d, g) in gaps {
            by.entry(root[&(d.clone(), g.vrf.clone())])
                .or_default()
                .push((d.clone(), g.clone()));
        }
        for list in by.values_mut() {
            list.sort();
        }
        Components { root, gaps: by }
    }

    /// The component of `d` `v`.
    fn of(&self, d: &str, v: &str) -> Option<usize> {
        self.root.get(&(d.to_string(), v.to_string())).copied()
    }

    /// The reason of the first gap of the component of `d` `v` that
    /// reaches `f`.
    fn cover(&self, d: &str, v: &str, f: Family) -> Option<String> {
        let r = self.root.get(&(d.to_string(), v.to_string()))?;
        self.gaps
            .get(r)?
            .iter()
            .find(|(_, g)| g.families.contains(&f))
            .map(|(dev, g)| reason(dev, g))
    }
}

/// The text of a convergence result.
fn describe(c: &Convergence) -> String {
    match c {
        Convergence::Converged { note: None } => "converged".to_string(),
        Convergence::Converged { note: Some(n) } => format!("converged, {}", n.text),
        Convergence::MultipleStableOutcomes { outcomes } => {
            format!("multiple stable outcomes: {}", outcomes.len())
        }
        Convergence::NoConvergence { cycle } => format!(
            "no convergence: a cycle of {} rounds from round {}",
            cycle.length, cycle.first_round
        ),
        Convergence::Unknown { reason } => format!("unknown: {reason}"),
    }
}

/// The BGP calculation of the lowered devices with the BGP peer facts of
/// the link join.
pub fn build(
    devices: &BTreeMap<String, DeviceInput>,
    facts: &BTreeMap<String, Vec<BgpPeerFact>>,
) -> BgpBuild {
    let mut processes: Vec<BgpProcess> = Vec::new();
    let mut gaps: Vec<(String, Gap)> = Vec::new();
    let mut igp = BTreeMap::new();
    for (d, x) in devices {
        for p in &x.bgp.processes {
            let mut p = p.clone();
            p.device.clone_from(d);
            processes.push(p);
        }
        for g in &x.bgp.gaps {
            gaps.push((d.clone(), g.clone()));
        }
        for (vrf, t) in &x.igp {
            igp.insert((d.clone(), vrf.clone()), t.clone());
        }
    }
    let index: BTreeMap<(String, String), usize> = processes
        .iter()
        .enumerate()
        .map(|(i, p)| ((p.device.clone(), p.vrf.clone()), i))
        .collect();
    let has = |d: &str, v: &str, a: IpAddr| {
        index
            .get(&(d.to_string(), v.to_string()))
            .is_some_and(|&i| processes[i].neighbors.contains_key(&a))
    };
    let mut edges: Vec<Edge> = Vec::new();
    let mut sessions: BTreeSet<Session> = BTreeSet::new();
    let mut outside: BTreeSet<(String, String, IpAddr)> = BTreeSet::new();
    for (d, list) in facts {
        if !devices.contains_key(d) {
            continue;
        }
        for f in list {
            let (PeerSource::Configured, BgpPeer::Address(a), Some(far)) =
                (&f.source, &f.peer, &f.far)
            else {
                continue;
            };
            let near = (d.clone(), f.vrf.clone());
            let gap = |why: String| Gap {
                vrf: f.vrf.clone(),
                families: UNICAST.into_iter().collect(),
                text: format!("neighbor {a}: {why}"),
                spans: f.spans.clone(),
            };
            match far {
                BgpFar::Outside => {
                    outside.insert((d.clone(), f.vrf.clone(), *a));
                }
                BgpFar::Ambiguous(ends) => {
                    gaps.push((
                        d.clone(),
                        gap("peer address on more than one device or VRF".to_string()),
                    ));
                    for e in ends {
                        edges.push((near.clone(), e.clone()));
                    }
                }
                BgpFar::Device {
                    device: fd,
                    vrf: fv,
                    side,
                } => {
                    edges.push((near.clone(), (fd.clone(), fv.clone())));
                    let why = match side {
                        FarSide::Paired(i) => match facts.get(fd).and_then(|l| l.get(*i)) {
                            Some(g) => match (&g.source, &g.peer) {
                                (PeerSource::Configured, BgpPeer::Address(x)) => {
                                    if !devices.contains_key(fd) {
                                        Some(format!("far end {fd} not lowered"))
                                    } else {
                                        if has(d, &f.vrf, *a) && has(fd, fv, *x) {
                                            sessions.insert(session(d, &f.vrf, *a, fd, fv, *x));
                                        }
                                        None
                                    }
                                }
                                _ => Some(format!(
                                    "far end {fd} pairs with a listen range or a dynamic peer"
                                )),
                            },
                            None => Some(format!("far end {fd} not found")),
                        },
                        FarSide::SourceMismatch(_) => Some(format!(
                            "source address is not the neighbor address of {fd}"
                        )),
                        FarSide::OtherAddress(_) => {
                            Some(format!("{fd} names another address of {d}"))
                        }
                        FarSide::Absent { .. } => {
                            Some(format!("no neighbor of {fd} for the source address"))
                        }
                        FarSide::Unresolved(r) => Some(r.clone()),
                    };
                    if let Some(w) = why {
                        gaps.push((d.clone(), gap(w)));
                    }
                }
            }
        }
    }
    let mut seeds = Vec::new();
    // The neighbours outside the twin whose seeds come from a table.
    let mut from_tables: BTreeSet<(String, String, IpAddr)> = BTreeSet::new();
    for (d, x) in devices {
        for (vrf, nh) in outside
            .iter()
            .filter(|(od, ..)| od == d)
            .map(|(_, v, a)| (v.clone(), *a))
        {
            let Some(&i) = index.get(&(d.clone(), vrf.clone())) else {
                continue;
            };
            let p = &processes[i];
            let Some(n) = p.neighbors.get(&nh) else {
                continue;
            };
            if n.shutdown {
                continue;
            }
            // The collected BGP routes through the neighbour, which a table
            // of the neighbour must hold to be a source.
            let through: Vec<Prefix> = x
                .collected
                .iter()
                .filter(|c| c.vrf == vrf && c.next_hops.contains(&nh))
                .map(|c| c.prefix)
                .collect();
            let table = |dir: crate::bgp_routes::Direction| {
                x.tables.iter().find(|t| {
                    t.vrf == vrf
                        && t.peer == nh
                        && t.direction == dir
                        && t.complete()
                        && through
                            .iter()
                            .all(|p| t.rows.iter().any(|r| r.prefix == *p))
                })
            };
            let (t, received) = match (
                table(crate::bgp_routes::Direction::Received),
                table(crate::bgp_routes::Direction::Accepted),
            ) {
                (Some(t), _) => (t, true),
                (None, Some(t)) => (t, false),
                (None, None) => continue,
            };
            from_tables.insert((d.clone(), vrf.clone(), nh));
            let kind = p.session_kind(n);
            let router_id = x.router_ids.get(&(vrf.clone(), nh)).copied();
            for r in &t.rows {
                let peer = Peer {
                    address: Some(nh),
                    router_id,
                    asn: n.remote_as,
                    kind,
                };
                let next_hop = r.next_hop.filter(|h| !h.is_unspecified()).or(Some(nh));
                let as_path = r.as_path.clone().unwrap_or_default();
                let mut path = BgpPath::new(peer, next_hop, as_path);
                if let Some(o) = r.origin {
                    path.origin = o;
                }
                path.med = r.med;
                path.local_pref = r.local_pref;
                if !received {
                    path.weight = r.weight.unwrap_or(0);
                }
                if let Some(c) = &r.communities {
                    path.communities.clone_from(c);
                }
                path.attributes_collected =
                    r.as_path.is_some() && r.origin.is_some() && r.communities.is_some();
                path.spans = vec![r.span.clone()];
                seeds.push(Seed {
                    device: d.clone(),
                    vrf: vrf.clone(),
                    neighbor: nh,
                    key: RouteKey::unicast(r.prefix),
                    path,
                    received,
                });
            }
        }
    }
    for (d, x) in devices {
        for c in &x.collected {
            let Some(&i) = index.get(&(d.clone(), c.vrf.clone())) else {
                continue;
            };
            let p = &processes[i];
            for nh in &c.next_hops {
                if !outside.contains(&(d.clone(), c.vrf.clone(), *nh))
                    || from_tables.contains(&(d.clone(), c.vrf.clone(), *nh))
                {
                    continue;
                }
                let Some(n) = p.neighbors.get(nh) else {
                    continue;
                };
                if n.shutdown {
                    continue;
                }
                let kind = p.session_kind(n);
                let router_id = x.router_ids.get(&(c.vrf.clone(), *nh)).copied();
                let as_path = if kind == SessionKind::Ebgp {
                    AsPath::sequence(&[n.remote_as.0])
                } else {
                    AsPath::default()
                };
                let peer = Peer {
                    address: Some(*nh),
                    router_id,
                    asn: n.remote_as,
                    kind,
                };
                let mut path = BgpPath::new(peer, Some(*nh), as_path);
                path.attributes_collected = false;
                path.spans.clone_from(&c.spans);
                seeds.push(Seed {
                    device: d.clone(),
                    vrf: c.vrf.clone(),
                    neighbor: *nh,
                    key: RouteKey::unicast(c.prefix),
                    path,
                    received: false,
                });
            }
        }
    }
    let comps = Components::new(index.keys().cloned(), &edges, &gaps);
    // The keys of the BGP calculation of each component, and the BGP
    // prefixes of each process for the IGP view.
    let mut comp_keys: BTreeMap<usize, BTreeSet<Prefix>> = BTreeMap::new();
    for p in &processes {
        if let Some(r) = comps.of(&p.device, &p.vrf) {
            let keys = comp_keys.entry(r).or_default();
            keys.extend(p.networks.iter().map(|n| n.key.prefix));
            keys.extend(p.aggregates.iter().map(|a| a.key.prefix));
        }
    }
    for s in &seeds {
        if let Some(r) = comps.of(&s.device, &s.vrf) {
            comp_keys.entry(r).or_default().insert(s.key.prefix);
        }
    }
    let mut bgp_prefixes: BTreeMap<(String, String), BTreeSet<Prefix>> = BTreeMap::new();
    for (d, v) in index.keys() {
        let mut set: BTreeSet<Prefix> = comps
            .of(d, v)
            .and_then(|r| comp_keys.get(&r))
            .cloned()
            .unwrap_or_default();
        if let Some(x) = devices.get(d) {
            set.extend(x.collected.iter().filter(|c| &c.vrf == v).map(|c| c.prefix));
        }
        bgp_prefixes.insert((d.clone(), v.clone()), set);
    }
    let input = BgpInput {
        processes,
        sessions: sessions.into_iter().collect(),
        seeds,
    };
    let result = (!input.processes.is_empty()).then(|| {
        rsim_routing::bgp::compute(
            &input,
            &Igp {
                tables: &igp,
                bgp: &bgp_prefixes,
            },
        )
        .map_err(|e| e.to_string())
    });
    // The reason of each key of a group whose convergence is unknown.
    let mut unknown_keys: BTreeMap<Prefix, String> = BTreeMap::new();
    if let Some(Ok(r)) = &result {
        for g in &r.groups {
            if let Convergence::Unknown { reason } = &g.convergence {
                for k in &g.keys {
                    unknown_keys.insert(k.prefix, reason.to_string());
                }
            }
        }
    }
    let mut vrfs: BTreeMap<String, BTreeMap<String, VrfBgp>> = BTreeMap::new();
    if let Some(Ok(r)) = &result {
        for ((d, v), cands) in install_candidates(r, &input.processes) {
            let entry = vrfs
                .entry(d.clone())
                .or_default()
                .entry(v.clone())
                .or_default();
            for c in cands {
                match comps.cover(&d, &v, family(c.prefix)) {
                    Some(why) => entry.candidates.push(Candidate::new(
                        c.prefix,
                        c.distance,
                        Route::unknown(BGP, why, c.route.spans.clone()),
                    )),
                    None => entry.candidates.push(c),
                }
            }
        }
    }
    for (d, x) in devices {
        for c in &x.collected {
            let entry = vrfs
                .entry(d.clone())
                .or_default()
                .entry(c.vrf.clone())
                .or_default();
            let seeded = !c.next_hops.is_empty()
                && c.next_hops
                    .iter()
                    .all(|h| outside.contains(&(d.clone(), c.vrf.clone(), *h)));
            let class = if seeded {
                Class::Seeded
            } else if let Some(why) = comps.cover(d, &c.vrf, family(c.prefix)) {
                Class::NotComputed(why)
            } else if !index.contains_key(&(d.clone(), c.vrf.clone())) {
                Class::NotComputed("no bgp process of the vrf".to_string())
            } else {
                match &result {
                    Some(Ok(r)) => {
                        let at = RouteAt {
                            device: d.clone(),
                            vrf: c.vrf.clone(),
                            key: RouteKey::unicast(c.prefix),
                        };
                        match (r.routes.get(&at), unknown_keys.get(&c.prefix)) {
                            (Some(RouteState::Unknown(u)), _) => Class::NotComputed(u.to_string()),
                            (_, Some(why)) => Class::NotComputed(why.clone()),
                            _ => Class::Compared,
                        }
                    }
                    Some(Err(e)) => Class::NotComputed(format!("bgp calculation not run: {e}")),
                    None => Class::NotComputed("no bgp process".to_string()),
                }
            };
            if class != Class::Compared {
                entry.classes.insert(c.prefix, class);
            }
        }
    }
    let mut notes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (d, x) in devices {
        for t in x.tables.iter().filter(|t| !t.complete()) {
            notes.entry(d.clone()).or_default().push(format!(
                "bgp table {} of {} in vrf {}: {}{}",
                t.direction.word(),
                t.peer,
                t.vrf,
                t.outcome.name(),
                t.detail
                    .as_deref()
                    .map(|x| format!(", {x}"))
                    .unwrap_or_default()
            ));
        }
    }
    let mut gap_texts: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (d, g) in &gaps {
        gap_texts.entry(d.clone()).or_default().push(reason(d, g));
    }
    for list in gap_texts.values_mut() {
        list.sort();
        list.dedup();
    }
    match &result {
        Some(Ok(r)) => {
            // The rounds and the changed routes of each group at each device.
            let mut rounds: BTreeMap<(String, usize), (usize, usize)> = BTreeMap::new();
            for e in &r.events {
                match e {
                    Event::Round { group, changed, .. } => {
                        let mut per: BTreeMap<&str, usize> = BTreeMap::new();
                        for at in changed {
                            *per.entry(at.device.as_str()).or_default() += 1;
                        }
                        for (d, n) in per {
                            let x = rounds.entry((d.to_string(), *group)).or_default();
                            x.0 += 1;
                            x.1 += n;
                        }
                    }
                    Event::Search {
                        group,
                        outcomes,
                        result,
                    } => notes.entry("estate".to_string()).or_default().push(format!(
                        "bgp group {group}: search with {outcomes} stable outcomes, {result:?}"
                    )),
                }
            }
            for ((d, g), (n, changed)) in rounds {
                notes.entry(d).or_default().push(format!(
                    "bgp group {g}: {n} rounds with a change, {changed} route changes"
                ));
            }
            for (i, g) in r.groups.iter().enumerate() {
                if !matches!(g.convergence, Convergence::Converged { note: None }) {
                    notes.entry("estate".to_string()).or_default().push(format!(
                        "bgp group {i} of {} keys: {}",
                        g.keys.len(),
                        describe(&g.convergence)
                    ));
                }
            }
        }
        Some(Err(e)) => notes
            .entry("estate".to_string())
            .or_default()
            .push(format!("bgp calculation not run: {e}")),
        None => {}
    }
    BgpBuild {
        input,
        igp,
        bgp_prefixes,
        result,
        vrfs,
        gaps: gap_texts,
        notes,
    }
}

/// The distance of an unknown BGP candidate of a platform: its eBGP
/// distance.
pub fn unknown_distance(platform: Platform) -> u8 {
    platform.distance(Origin::Ebgp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsim_core::{FunctionId, InterfaceId};
    use rsim_functions::RouteNextHop;
    use rsim_routing::install;

    const OSPF: RouteKind = RouteKind::Learned(RouteProtocol::Ospf);

    fn pfx(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn hop(i: &str, gw: Option<&str>) -> RouteNextHop {
        RouteNextHop {
            interface: InterfaceId::new(i),
            gateway: gw.map(ip),
            next: FunctionId::new("r1/next"),
        }
    }

    fn connected(p: &str, i: &str) -> Candidate {
        Candidate::new(
            pfx(p),
            0,
            Route::new(RouteKind::Connected, vec![hop(i, None)], Vec::new()),
        )
    }

    fn ospf(p: &str, gw: &str) -> Candidate {
        Candidate::new(
            pfx(p),
            110,
            Route::new(OSPF, vec![hop("eth1", Some(gw))], Vec::new()),
        )
    }

    /// The IGP view of the install stage of `cands`, with the OSPF metrics
    /// `metrics`.
    fn table(cands: Vec<Candidate>, metrics: &[(&str, u32)]) -> IgpTable {
        IgpTable {
            routes: install(cands, false).entries().into_iter().collect(),
            ospf: metrics.iter().map(|(p, m)| (pfx(p), Ok(*m))).collect(),
            incomplete: BTreeMap::new(),
        }
    }

    #[test]
    fn a_floating_static_route_leaves_the_ospf_route_and_its_metric() {
        let floating = Candidate::new(
            pfx("10.1.0.0/16"),
            250,
            Route::new(RouteKind::Static, vec![hop("eth0", None)], Vec::new()),
        );
        let cands = vec![
            connected("192.0.2.0/30", "eth1"),
            floating.clone(),
            ospf("10.1.0.0/16", "192.0.2.2"),
        ];
        let t = table(cands, &[("10.1.0.0/16", 30)]);
        assert_eq!(t.resolve(ip("10.1.2.3")), Resolution::Resolved { cost: 30 });
        let t = table(vec![connected("192.0.2.0/30", "eth1"), floating], &[]);
        assert_eq!(t.resolve(ip("10.1.2.3")), Resolution::Resolved { cost: 0 });
    }

    #[test]
    fn a_static_route_whose_next_hop_does_not_resolve_is_not_in_the_view() {
        let cands = vec![
            connected("192.0.2.0/30", "eth1"),
            Candidate::via(
                pfx("10.2.0.0/16"),
                1,
                RouteKind::Static,
                vec![ip("198.51.100.99")],
                Vec::new(),
            ),
            ospf("10.2.0.0/16", "192.0.2.2"),
        ];
        let t = table(cands, &[("10.2.0.0/16", 20)]);
        assert_eq!(t.resolve(ip("10.2.0.1")), Resolution::Resolved { cost: 20 });
        let cands = vec![
            connected("192.0.2.0/30", "eth1"),
            Candidate::via(
                pfx("10.2.0.0/16"),
                1,
                RouteKind::Static,
                vec![ip("198.51.100.99")],
                Vec::new(),
            ),
        ];
        let t = table(cands, &[]);
        assert!(matches!(t.resolve(ip("10.2.0.1")), Resolution::Unknown(_)));
        assert_eq!(t.has_route(pfx("10.2.0.0/16")), Some(false));
    }

    #[test]
    fn an_ospf_version_not_computed_in_full_leaves_only_the_connected_and_local_routes() {
        let covering = Candidate::new(
            pfx("10.0.0.0/16"),
            1,
            Route::new(
                RouteKind::Static,
                vec![hop("eth1", Some("192.0.2.2"))],
                Vec::new(),
            ),
        );
        let mut t = table(vec![connected("192.0.2.0/30", "eth1"), covering], &[]);
        assert_eq!(t.resolve(ip("10.0.1.1")), Resolution::Resolved { cost: 0 });
        assert_eq!(t.has_route(pfx("10.0.0.0/16")), Some(true));
        t.incomplete
            .insert(true, "ospfv2 database not read in full".to_string());
        assert_eq!(
            t.resolve(ip("10.0.1.1")),
            Resolution::Unknown("ospfv2 database not read in full".to_string())
        );
        assert_eq!(t.resolve(ip("192.0.2.2")), Resolution::Resolved { cost: 0 });
        assert_eq!(t.has_route(pfx("10.0.0.0/16")), None);
        assert_eq!(t.has_route(pfx("10.9.0.0/16")), None);
        assert_eq!(t.has_route(pfx("192.0.2.0/30")), Some(true));
    }

    #[test]
    fn a_collected_ospf_route_that_is_not_computed_inside_a_connected_route_is_unknown() {
        let lo = pfx("10.0.5.5/32");
        let mut collected = Fib::new();
        collected.insert(
            lo,
            Route::new(OSPF, vec![hop("eth1", Some("10.0.0.2"))], Vec::new()),
        );
        let routes = BTreeMap::from([(
            lo,
            rsim_guard::CollectedRoute {
                protocol: "ospf".to_string(),
                class: Class::NotComputed("ospfv2 database not read in full".to_string()),
            },
        )]);
        let view = |routes: &BTreeMap<Prefix, rsim_guard::CollectedRoute>| IgpTable {
            routes: crate::guard::igp(
                vec![connected("10.0.0.0/16", "eth1")],
                routes,
                &collected,
                rsim_routing::Platform::Iosxr,
                false,
            )
            .entries()
            .into_iter()
            .collect(),
            ospf: BTreeMap::new(),
            incomplete: BTreeMap::new(),
        };
        assert!(matches!(
            view(&routes).resolve(ip("10.0.5.5")),
            Resolution::Unknown(_)
        ));
        assert_eq!(
            view(&BTreeMap::new()).resolve(ip("10.0.5.5")),
            Resolution::Resolved { cost: 0 }
        );
    }

    #[test]
    fn a_next_hop_inside_a_longer_bgp_prefix_has_an_unknown_resolution() {
        let t = table(
            vec![
                connected("192.0.2.0/30", "eth1"),
                ospf("10.0.0.0/8", "192.0.2.2"),
            ],
            &[("10.0.0.0/8", 40)],
        );
        let at = ("r1".to_string(), "default".to_string());
        let tables = BTreeMap::from([(at.clone(), t)]);
        let bgp = BTreeMap::from([(at.clone(), BTreeSet::from([pfx("10.1.1.0/24")]))]);
        let view = Igp {
            tables: &tables,
            bgp: &bgp,
        };
        assert_eq!(
            view.resolve("r1", "default", ip("10.1.1.1")),
            Resolution::Unknown("next hop inside the bgp prefix 10.1.1.0/24".to_string())
        );
        assert_eq!(
            view.resolve("r1", "default", ip("10.2.0.1")),
            Resolution::Resolved { cost: 40 }
        );
        let bgp = BTreeMap::from([(at, BTreeSet::from([pfx("10.0.0.0/8")]))]);
        let view = Igp {
            tables: &tables,
            bgp: &bgp,
        };
        assert_eq!(
            view.resolve("r1", "default", ip("10.1.1.1")),
            Resolution::Resolved { cost: 40 }
        );
    }
}
