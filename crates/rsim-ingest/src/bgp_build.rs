//! The BGP calculation of the twin: the processes of the lowered devices,
//! the sessions between them from the far ends of the link join, the seeds
//! from the peers outside the twin, the IGP view of the computed connected,
//! static and OSPF routes, the gaps and the BGP routes of each device and
//! VRF for the RIB guard.
//!
//! A configured neighbour with a peer address is one of 3 things. With a
//! paired far end whose neighbour is lowered too, it is one end of a
//! session. With a far end outside the twin, the collected BGP routes of
//! its VRF whose next hop is its address are seeds with attributes that are
//! not collected. Each other neighbour is a gap of its VRF.
//!
//! A gap covers each process in the component of its VRF over the sessions
//! and the far ends of the neighbours, for the families of the gap. A
//! computed BGP route under a gap is unknown with the reason of the gap,
//! and a collected BGP route under a gap is not computed, unless it is a
//! seed.

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

/// A route of the computed IGP table of a VRF: its administrative distance
/// and its metric, or the reason why the route is not known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IgpRoute {
    pub distance: u8,
    pub metric: Result<u32, String>,
}

/// The computed connected, static and OSPF routes of a VRF.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IgpTable {
    pub routes: BTreeMap<Prefix, IgpRoute>,
}

impl IgpTable {
    /// Adds a route of a prefix. The route with the lowest distance stays,
    /// and an unknown route stays over a known route of the same distance.
    pub fn add(&mut self, prefix: Prefix, distance: u8, metric: Result<u32, String>) {
        let keep = self.routes.get(&prefix).is_some_and(|r| {
            r.distance < distance || (r.distance == distance && r.metric.is_err())
        });
        if !keep {
            self.routes.insert(prefix, IgpRoute { distance, metric });
        }
    }

    /// The longest route that holds `addr`. A default route resolves no
    /// next hop.
    pub fn lookup(&self, addr: IpAddr) -> Option<(Prefix, &IgpRoute)> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (1..=max).rev().find_map(|len| {
            let p = Prefix::new(addr, len);
            self.routes.get(&p).map(|r| (p, r))
        })
    }
}

/// The IGP view of the BGP calculation over the computed tables of each
/// device and VRF. The IGP cost of a next hop is the metric of the route
/// that it resolves through: 0 for a connected or a static route, the cost
/// of an OSPF route. A next hop with no such route, or with an unknown one,
/// has an unknown resolution.
pub struct Igp<'a> {
    pub tables: &'a BTreeMap<(String, String), IgpTable>,
}

impl IgpView for Igp<'_> {
    fn resolve(&self, device: &str, vrf: &str, next_hop: IpAddr) -> Resolution {
        let Some(t) = self.tables.get(&(device.to_string(), vrf.to_string())) else {
            return Resolution::Unknown("no computed route table of the VRF".to_string());
        };
        match t.lookup(next_hop) {
            Some((_, IgpRoute { metric: Ok(m), .. })) => Resolution::Resolved { cost: *m },
            Some((
                p,
                IgpRoute {
                    metric: Err(why), ..
                },
            )) => Resolution::Unknown(format!("route {p} unknown: {why}")),
            None => Resolution::Unknown("no computed connected, static or OSPF route".to_string()),
        }
    }

    fn has_route(&self, device: &str, vrf: &str, prefix: Prefix) -> Option<bool> {
        let t = self.tables.get(&(device.to_string(), vrf.to_string()))?;
        match t.routes.get(&prefix) {
            Some(IgpRoute { metric: Ok(_), .. }) => Some(true),
            Some(_) => None,
            None => Some(false),
        }
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
    let mut seeded: BTreeSet<(String, String, Prefix)> = BTreeSet::new();
    for (d, x) in devices {
        for c in &x.collected {
            let Some(&i) = index.get(&(d.clone(), c.vrf.clone())) else {
                continue;
            };
            let p = &processes[i];
            for nh in &c.next_hops {
                if !outside.contains(&(d.clone(), c.vrf.clone(), *nh)) {
                    continue;
                }
                let Some(n) = p.neighbors.get(nh) else {
                    continue;
                };
                if n.shutdown {
                    continue;
                }
                let kind = p.session_kind(n);
                let router_id = match nh {
                    IpAddr::V4(v) => *v,
                    IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
                };
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
                seeded.insert((d.clone(), c.vrf.clone(), c.prefix));
            }
        }
    }
    let comps = Components::new(index.keys().cloned(), &edges, &gaps);
    let input = BgpInput {
        processes,
        sessions: sessions.into_iter().collect(),
        seeds,
    };
    let result = (!input.processes.is_empty()).then(|| {
        rsim_routing::bgp::compute(&input, &Igp { tables: &igp }).map_err(|e| e.to_string())
    });
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
            let class = if seeded.contains(&(d.clone(), c.vrf.clone(), c.prefix)) {
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
                        match r.routes.get(&at) {
                            Some(RouteState::Unknown(u)) => Class::NotComputed(u.to_string()),
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
