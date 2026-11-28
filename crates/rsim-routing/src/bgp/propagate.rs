//! The propagation: the input of the BGP calculation, the local
//! originations, and the candidates and the selection of each route at each
//! process for a given best path at each other process.
//!
//! A variable is one route key at one process. An EVPN IP prefix key has a
//! variable only at a process of the default VRF with a neighbour that
//! activates the EVPN family or with a leak, in the component over the
//! sessions of these processes that holds the device of the route
//! distinguisher of the key. A unicast key has a variable only at a process
//! of a VRF other than the default VRF, or at a process with a neighbour
//! whose families are not known or hold a unicast family, an origination, a
//! redistribution, a seed or a leak into it. The candidates of a variable
//! are its `network` path, its aggregate path, its redistributed paths, its
//! seeds, the accepted paths of each session to the process, the seeds and
//! the sessions by the neighbour address, and the paths of each leak to the
//! process from another process of the device. When the best path depends
//! on the order of receipt, each path that is the best path in some order
//! is a tied path of the selection.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use rsim_core::{Prefix, SourceSpan};

use super::decision::{Decision, decide, multipath_for, order_winners};
use super::leak::{LeakKind, evpn_export, evpn_import, vrf_leak};
use super::policy::{Direction, PolicyContext, PolicyResult, evaluate, policy_reads};
use super::process::{Aggregate, BgpProcess, Network};
use super::profile::{BgpProfile, UndefinedPolicy};
use super::redistribute::{IgpRoute, redistribute_offer};
use super::session::{Offer, Session, export, receive};
use super::stage::{ObjectRef, RoutingStage};
use super::{
    AsPath, AsSegment, Asn, BgpOrigin, BgpPath, DEFAULT_VRF, Family, LocalOrigin, Peer, Reason,
    RouteDistinguisher, RouteKey, SegmentKind, SessionKind, Unknown,
};

/// The resolution of a next hop in the route table of a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    Resolved {
        cost: u32,
    },
    Unresolved,
    /// The route table does not settle the resolution, with the reason.
    Unknown(String),
}

/// The route table that the BGP calculation reads: the resolution of the
/// next hops and the routes of the `network` statements.
///
/// A next hop that resolves only through a BGP route gives
/// `Resolution::Unknown`. `Resolution::Unresolved` removes the path as a
/// candidate.
pub trait IgpView {
    fn resolve(&self, device: &str, vrf: &str, next_hop: IpAddr) -> Resolution;

    /// True if the route table holds `prefix` exactly. `None` when it is
    /// not known.
    fn has_route(&self, device: &str, vrf: &str, prefix: Prefix) -> Option<bool>;
}

/// A path that a process receives from a peer outside the twin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seed {
    pub device: String,
    pub vrf: String,
    /// The neighbour of the process that sends the path.
    pub neighbor: IpAddr,
    pub key: RouteKey,
    /// The path as the peer sends it. `peer.router_id` is the router ID of
    /// the peer.
    pub path: BgpPath,
    /// True for a path of the received table: the receipt checks and the
    /// import policy run on it. False for an accepted path, which is a
    /// candidate as it is.
    pub received: bool,
}

/// The input of the BGP calculation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BgpInput {
    pub processes: Vec<BgpProcess>,
    /// The sessions with both ends in the twin.
    pub sessions: Vec<Session>,
    pub seeds: Vec<Seed>,
    /// The installed routes other than BGP routes that the `redistribute`
    /// statements read. A route of a VRF with no process is not read.
    pub igp_routes: Vec<IgpRoute>,
}

/// An input that the calculation cannot read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputError {
    DuplicateProcess {
        device: String,
        vrf: String,
    },
    MissingProcess {
        device: String,
        vrf: String,
    },
    MissingNeighbor {
        device: String,
        vrf: String,
        neighbor: IpAddr,
    },
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputError::DuplicateProcess { device, vrf } => {
                write!(f, "more than one bgp process at {device} {vrf}")
            }
            InputError::MissingProcess { device, vrf } => {
                write!(f, "no bgp process at {device} {vrf}")
            }
            InputError::MissingNeighbor {
                device,
                vrf,
                neighbor,
            } => write!(f, "no neighbor {neighbor} at {device} {vrf}"),
        }
    }
}

impl std::error::Error for InputError {}

/// The best path of a route at a process.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(
    clippy::large_enum_variant,
    reason = "the path variant is the common value, and a box adds an allocation to each copy"
)]
pub enum BestPath {
    None,
    Path(BgpPath),
    Unknown(Unknown),
}

/// The selection of a route: the best path and the paths that the
/// multipath installs with it, the best path first.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Selection {
    pub best: BgpPath,
    pub multipath: Vec<BgpPath>,
}

fn local_peer(p: &BgpProcess, origin: LocalOrigin) -> Peer {
    Peer {
        address: None,
        router_id: p.router_id,
        asn: p.asn,
        kind: SessionKind::Local(origin),
    }
}

fn local_path(p: &BgpProcess, origin: LocalOrigin, spans: &[SourceSpan]) -> BgpPath {
    let mut path = BgpPath::new(local_peer(p, origin), None, AsPath::default());
    path.weight = p.profile().map_or(0, |pr| pr.local_weight);
    path.spans = spans.to_vec();
    path
}

/// The path of the `network` statement `n` of `process`. `route_present`
/// tells whether the route table holds the prefix. With the option
/// `network_import_check` `Some(false)`, the statement originates the path
/// with no route. The route-map of the statement runs on the path.
pub fn network_offer(process: &BgpProcess, n: &Network, route_present: Option<bool>) -> Offer {
    let Some(profile) = process.profile() else {
        return Offer::Unknown(Unknown::new(Reason::NoBgpProfile, process.device.clone()));
    };
    let route_present = if process.options.network_import_check == Some(false) {
        Some(true)
    } else {
        route_present
    };
    match route_present {
        Some(true) => {}
        Some(false) => return Offer::None,
        None => {
            return Offer::Unknown(Unknown::new(
                Reason::OriginationNotKnown,
                format!(
                    "network {} at {} {}",
                    n.key.prefix, process.device, process.vrf
                ),
            ));
        }
    }
    let path = local_path(process, LocalOrigin::Network, &n.spans);
    let Some(name) = &n.policy else {
        return Offer::Path(path);
    };
    let Some(policy) = process.policy.policies.get(name) else {
        return match profile.undefined_policy {
            UndefinedPolicy::Deny => Offer::None,
            UndefinedPolicy::NoPolicy => Offer::Path(path),
        };
    };
    let ctx = PolicyContext {
        set: &process.policy,
        direction: Direction::Import,
        local_address: None,
        peer_address: None,
        default_local_pref: profile.default_local_pref(&process.options),
        match_reads: profile.match_reads,
    };
    match evaluate(policy, &n.key, &path, &ctx) {
        PolicyResult::Permit(p) => Offer::Path(p),
        PolicyResult::Deny => Offer::None,
        PolicyResult::Unknown(u) => Offer::Unknown(u),
    }
}

fn origin_rank(o: BgpOrigin) -> u8 {
    match o {
        BgpOrigin::Igp => 0,
        BgpOrigin::Egp => 1,
        BgpOrigin::Incomplete => 2,
    }
}

/// The path of the aggregate `a` of `process` from the best paths of the
/// routes inside it at the process. The aggregate is active when one of
/// them has a path. Without `as_set` the path has the empty AS path and the
/// origin IGP. With `as_set` it has the worst origin and the union of the
/// communities of these paths, and the AS path of [`aggregate_as_path`].
pub fn aggregate_offer(process: &BgpProcess, a: &Aggregate, contributors: &[BestPath]) -> Offer {
    let paths: Vec<&BgpPath> = contributors
        .iter()
        .filter_map(|b| match b {
            BestPath::Path(p) => Some(p),
            _ => None,
        })
        .collect();
    let unknown = contributors.iter().find_map(|b| match b {
        BestPath::Unknown(u) => Some(u),
        _ => None,
    });
    if let Some(u) = unknown
        && (paths.is_empty() || a.as_set)
    {
        return Offer::Unknown(u.clone());
    }
    if paths.is_empty() {
        return Offer::None;
    }
    let mut path = local_path(process, LocalOrigin::Aggregate, &a.spans);
    if a.as_set {
        let as_paths: Vec<&AsPath> = paths.iter().map(|p| &p.as_path).collect();
        path.as_path = aggregate_as_path(&as_paths);
        path.origin = paths
            .iter()
            .map(|p| p.origin)
            .max_by_key(|o| origin_rank(*o))
            .unwrap_or(BgpOrigin::Igp);
        for p in &paths {
            path.communities.extend(p.communities.iter().copied());
        }
    }
    Offer::Path(path)
}

/// The AS path of an as-set aggregate of the paths `as_paths`
/// (RFC 4271 9.2.2.2 and appendix F.6): an AS_CONFED_SET of the ASs of
/// the confederation segments, the longest leading AS_SEQUENCE that each
/// path starts with after its confederation segments, and an AS_SET of
/// the other ASs that the sequence does not hold. An empty segment is left
/// out.
pub fn aggregate_as_path(as_paths: &[&AsPath]) -> AsPath {
    let confed =
        |s: &AsSegment| matches!(s.kind, SegmentKind::ConfedSequence | SegmentKind::ConfedSet);
    let leading = |p: &AsPath| -> Vec<Asn> {
        match p.segments.iter().find(|s| !confed(s)) {
            Some(s) if s.kind == SegmentKind::Sequence => s.asns.clone(),
            _ => Vec::new(),
        }
    };
    let mut common: Vec<Asn> = match as_paths.first() {
        Some(p) => leading(p),
        None => Vec::new(),
    };
    for p in as_paths.iter().skip(1) {
        let l = leading(p);
        let n = common.iter().zip(&l).take_while(|(a, b)| a == b).count();
        common.truncate(n);
    }
    let mut confed_asns = BTreeSet::new();
    let mut rest = BTreeSet::new();
    for p in as_paths {
        let mut skip = common.len();
        let mut first = true;
        for s in &p.segments {
            if confed(s) {
                confed_asns.extend(s.asns.iter().copied());
                continue;
            }
            let from = if first && s.kind == SegmentKind::Sequence {
                skip.min(s.asns.len())
            } else {
                0
            };
            first = false;
            skip = 0;
            rest.extend(s.asns[from..].iter().copied());
        }
    }
    for a in &common {
        rest.remove(a);
    }
    let mut segments = Vec::new();
    for (kind, asns) in [
        (SegmentKind::ConfedSet, confed_asns.into_iter().collect()),
        (SegmentKind::Sequence, common),
        (SegmentKind::Set, rest.into_iter().collect()),
    ] {
        if !asns.is_empty() {
            segments.push(AsSegment { kind, asns });
        }
    }
    AsPath { segments }
}

/// True if `inner` is a more specific route of `outer`: the same family and
/// route distinguisher, and a longer prefix inside it.
pub(crate) fn inside(inner: &RouteKey, outer: &RouteKey) -> bool {
    inner.family == outer.family
        && inner.rd == outer.rd
        && inner.prefix.len() > outer.prefix.len()
        && outer.prefix.contains(inner.prefix.addr())
}

/// The input of [`OriginateStage`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginateInput {
    /// True if the route table holds the prefix of the key.
    pub route_present: Option<bool>,
    /// The best paths of the routes inside the key at the process.
    pub contributors: Vec<BestPath>,
}

/// The origination stage of one route at one process: the paths of its
/// `network` statements and of its aggregates.
pub struct OriginateStage<'a> {
    pub process: &'a BgpProcess,
    pub key: RouteKey,
}

impl RoutingStage for OriginateStage<'_> {
    type Input = OriginateInput;
    type Output = Vec<Offer>;

    fn name(&self) -> &'static str {
        "bgp originate"
    }

    /// The profile, the process, the route-maps of the `network`
    /// statements, the route table entry of the prefix and the selections
    /// of the routes inside it.
    fn reads(&self) -> BTreeSet<ObjectRef> {
        let p = self.process;
        let mut out = BTreeSet::from([
            ObjectRef::Profile(p.platform),
            ObjectRef::Process {
                device: p.device.clone(),
                vrf: p.vrf.clone(),
            },
            ObjectRef::IgpRoute {
                device: p.device.clone(),
                vrf: p.vrf.clone(),
                prefix: self.key.prefix,
            },
            ObjectRef::Contributors {
                device: p.device.clone(),
                vrf: p.vrf.clone(),
                key: self.key,
            },
        ]);
        for n in p.networks.iter().filter(|n| n.key == self.key) {
            if let Some(name) = &n.policy {
                policy_reads(&p.policy, name, &p.device, &p.vrf, &mut out);
            }
        }
        out
    }

    fn run(&self, input: &OriginateInput) -> Vec<Offer> {
        let p = self.process;
        let mut out: Vec<Offer> = p
            .networks
            .iter()
            .filter(|n| n.key == self.key)
            .map(|n| network_offer(p, n, input.route_present))
            .collect();
        out.extend(
            p.aggregates
                .iter()
                .filter(|a| a.key == self.key)
                .map(|a| aggregate_offer(p, a, &input.contributors)),
        );
        out
    }
}

/// One direction of a session between 2 processes, by index.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Link {
    pub to: usize,
    /// The neighbour address at the receiver: the address of the sender.
    pub to_neighbor: IpAddr,
    pub from: usize,
    /// The neighbour address at the sender: the address of the receiver.
    pub from_neighbor: IpAddr,
}

/// A transfer between 2 processes of one device, by index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LeakLink {
    pub from: usize,
    pub to: usize,
    pub kind: LeakKind,
}

/// The checked input with the processes in the order of device and VRF.
pub(crate) struct Net<'a> {
    pub procs: Vec<&'a BgpProcess>,
    pub links: Vec<Link>,
    /// The seeds in the order of device, VRF, neighbour and key.
    pub seeds: Vec<&'a Seed>,
    /// The leaks in the order of the processes.
    pub leaks: Vec<LeakLink>,
    /// The installed route of each process and prefix.
    pub igp_routes: BTreeMap<(usize, rsim_core::Prefix), &'a IgpRoute>,
    /// The component over the sessions of each process that holds the EVPN
    /// IP prefix keys, `None` for another process.
    pub evpn: Vec<Option<usize>>,
    /// The component of the process of the default VRF of the device of
    /// each route distinguisher of an EVPN export.
    pub rd_component: BTreeMap<RouteDistinguisher, usize>,
    /// True for a process that holds the unicast keys.
    pub unicast: Vec<bool>,
    pub igp: &'a dyn IgpView,
}

impl<'a> Net<'a> {
    pub fn new(input: &'a BgpInput, igp: &'a dyn IgpView) -> Result<Net<'a>, InputError> {
        let mut procs: Vec<&BgpProcess> = input.processes.iter().collect();
        procs.sort_by(|a, b| (&a.device, &a.vrf).cmp(&(&b.device, &b.vrf)));
        for w in procs.windows(2) {
            if (&w[0].device, &w[0].vrf) == (&w[1].device, &w[1].vrf) {
                return Err(InputError::DuplicateProcess {
                    device: w[0].device.clone(),
                    vrf: w[0].vrf.clone(),
                });
            }
        }
        let find = |device: &str, vrf: &str, neighbor: IpAddr| -> Result<usize, InputError> {
            let i = procs
                .binary_search_by(|p| (p.device.as_str(), p.vrf.as_str()).cmp(&(device, vrf)))
                .map_err(|_| InputError::MissingProcess {
                    device: device.to_string(),
                    vrf: vrf.to_string(),
                })?;
            if !procs[i].neighbors.contains_key(&neighbor) {
                return Err(InputError::MissingNeighbor {
                    device: device.to_string(),
                    vrf: vrf.to_string(),
                    neighbor,
                });
            }
            Ok(i)
        };
        let mut links = BTreeSet::new();
        for s in &input.sessions {
            let a = find(&s.a.device, &s.a.vrf, s.a.neighbor)?;
            let b = find(&s.b.device, &s.b.vrf, s.b.neighbor)?;
            links.insert(Link {
                to: b,
                to_neighbor: s.b.neighbor,
                from: a,
                from_neighbor: s.a.neighbor,
            });
            links.insert(Link {
                to: a,
                to_neighbor: s.a.neighbor,
                from: b,
                from_neighbor: s.b.neighbor,
            });
        }
        let mut seeds: Vec<&Seed> = input.seeds.iter().collect();
        for s in &seeds {
            find(&s.device, &s.vrf, s.neighbor)?;
        }
        seeds.sort_by(|a, b| {
            (&a.device, &a.vrf, a.neighbor, a.key, &a.path, a.received)
                .cmp(&(&b.device, &b.vrf, b.neighbor, b.key, &b.path, b.received))
        });
        let index_of = |device: &str, vrf: &str| {
            procs
                .binary_search_by(|p| (p.device.as_str(), p.vrf.as_str()).cmp(&(device, vrf)))
                .ok()
        };
        let mut leaks = BTreeSet::new();
        for (i, p) in procs.iter().enumerate() {
            if p.vrf != DEFAULT_VRF
                && let Some(d) = index_of(&p.device, DEFAULT_VRF)
            {
                if p.targets.advertise_evpn && p.targets.rd.is_some() {
                    leaks.insert(LeakLink {
                        from: i,
                        to: d,
                        kind: LeakKind::EvpnExport,
                    });
                }
                if !p.targets.evpn_import.is_empty() {
                    leaks.insert(LeakLink {
                        from: d,
                        to: i,
                        kind: LeakKind::EvpnImport,
                    });
                }
            }
            for (j, q) in procs.iter().enumerate() {
                if i != j
                    && p.device == q.device
                    && !p.targets.export.is_disjoint(&q.targets.import)
                {
                    leaks.insert(LeakLink {
                        from: i,
                        to: j,
                        kind: LeakKind::Vrf,
                    });
                }
            }
        }
        let leaks: Vec<LeakLink> = leaks.into_iter().collect();
        let mut igp_routes = BTreeMap::new();
        for r in &input.igp_routes {
            if let Some(i) = index_of(&r.device, &r.vrf) {
                igp_routes.insert((i, r.prefix), r);
            }
        }
        let holds: Vec<bool> = procs
            .iter()
            .enumerate()
            .map(|(i, p)| {
                p.vrf == DEFAULT_VRF
                    && (p
                        .neighbors
                        .values()
                        .any(|n| n.activated.contains(&Family::EvpnIpPrefix))
                        || leaks.iter().any(|l| l.from == i || l.to == i))
            })
            .collect();
        let links: Vec<Link> = links.into_iter().collect();
        let mut parent: Vec<usize> = (0..procs.len()).collect();
        fn root(parent: &mut [usize], mut i: usize) -> usize {
            while parent[i] != i {
                parent[i] = parent[parent[i]];
                i = parent[i];
            }
            i
        }
        for l in links.iter().filter(|l| holds[l.from] && holds[l.to]) {
            let (a, b) = (root(&mut parent, l.from), root(&mut parent, l.to));
            if a != b {
                parent[a.max(b)] = a.min(b);
            }
        }
        let evpn: Vec<Option<usize>> = (0..procs.len())
            .map(|i| holds[i].then(|| root(&mut parent, i)))
            .collect();
        let mut rd_component = BTreeMap::new();
        for l in leaks.iter().filter(|l| l.kind == LeakKind::EvpnExport) {
            if let (Some(rd), Some(c)) = (procs[l.from].targets.rd, evpn[l.to]) {
                rd_component.insert(rd, c);
            }
        }
        let unicast = procs
            .iter()
            .enumerate()
            .map(|(i, p)| {
                p.vrf != DEFAULT_VRF
                    || p.neighbors.values().any(|n| {
                        p.families(n)
                            .is_none_or(|f| f.iter().any(|x| *x != Family::EvpnIpPrefix))
                    })
                    || !p.networks.is_empty()
                    || !p.aggregates.is_empty()
                    || !p.redistributions.is_empty()
                    || seeds.iter().any(|s| s.device == p.device && s.vrf == p.vrf)
                    || leaks
                        .iter()
                        .any(|l| l.to == i && l.kind != LeakKind::EvpnExport)
            })
            .collect();
        Ok(Net {
            procs,
            links,
            seeds,
            leaks,
            igp_routes,
            evpn,
            rd_component,
            unicast,
            igp,
        })
    }

    pub fn proc_index(&self, device: &str, vrf: &str) -> Option<usize> {
        self.procs
            .binary_search_by(|p| (p.device.as_str(), p.vrf.as_str()).cmp(&(device, vrf)))
            .ok()
    }

    /// The keys of the originations, the installed routes of the processes
    /// with a `redistribute` statement and the seeds, and the EVPN IP prefix
    /// keys of each VRF that advertises its routes as EVPN routes. A VRF
    /// with a session, a seed or a leak from another VRF advertises a key
    /// of each unicast key. Another VRF advertises a key of each prefix
    /// that it originates.
    pub fn keys(&self) -> BTreeSet<RouteKey> {
        let mut out = BTreeSet::new();
        for p in &self.procs {
            out.extend(p.networks.iter().map(|n| n.key));
            out.extend(p.aggregates.iter().map(|a| a.key));
        }
        for &(i, prefix) in self.igp_routes.keys() {
            if !self.procs[i].redistributions.is_empty() {
                out.insert(RouteKey::unicast(prefix));
            }
        }
        out.extend(self.seeds.iter().map(|s| s.key));
        let unicast: Vec<RouteKey> = out
            .iter()
            .filter(|k| k.family != Family::EvpnIpPrefix)
            .copied()
            .collect();
        for l in self.leaks.iter().filter(|l| l.kind == LeakKind::EvpnExport) {
            let i = l.from;
            let p = self.procs[i];
            let Some(rd) = p.targets.rd else {
                continue;
            };
            let open = self.links.iter().any(|x| x.to == i)
                || self
                    .seeds
                    .iter()
                    .any(|s| s.device == p.device && s.vrf == p.vrf)
                || self
                    .leaks
                    .iter()
                    .any(|x| x.to == i && x.kind == LeakKind::Vrf);
            let own: BTreeSet<rsim_core::Prefix> = p
                .networks
                .iter()
                .map(|n| n.key.prefix)
                .chain(p.aggregates.iter().map(|a| a.key.prefix))
                .chain(
                    self.igp_routes
                        .keys()
                        .filter(|(x, _)| *x == i && !p.redistributions.is_empty())
                        .map(|(_, q)| *q),
                )
                .collect();
            out.extend(
                unicast
                    .iter()
                    .filter(|k| open || own.contains(&k.prefix))
                    .map(|k| RouteKey::evpn_ip_prefix(rd, k.prefix)),
            );
        }
        out
    }

    /// True if process `i` has a variable of `key`.
    pub fn holds(&self, i: usize, key: &RouteKey) -> bool {
        if key.family != Family::EvpnIpPrefix {
            return self.unicast[i];
        }
        match (
            self.evpn[i],
            key.rd.and_then(|rd| self.rd_component.get(&rd)),
        ) {
            (Some(c), Some(r)) => c == *r,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    /// The addresses that can be a next hop: the session addresses, the
    /// next hops of the seeds and the next hops that a policy sets.
    pub fn next_hop_addresses(&self) -> BTreeSet<IpAddr> {
        use super::policy::{NextHopSet, PolicyBody, SetAction, Statement};
        let mut out = BTreeSet::new();
        for l in &self.links {
            out.insert(l.to_neighbor);
            out.insert(l.from_neighbor);
        }
        out.extend(self.seeds.iter().filter_map(|s| s.path.next_hop));
        out.extend(self.procs.iter().filter_map(|p| p.targets.evpn_next_hop));
        fn stmts(s: &[Statement], out: &mut BTreeSet<IpAddr>) {
            for st in s {
                match st {
                    Statement::Set(SetAction::NextHop(NextHopSet::Address(a))) => {
                        out.insert(*a);
                    }
                    Statement::If {
                        branches,
                        otherwise,
                    } => {
                        for (_, b) in branches {
                            stmts(b, out);
                        }
                        stmts(otherwise, out);
                    }
                    _ => {}
                }
            }
        }
        for p in &self.procs {
            for policy in p.policy.policies.values() {
                match &policy.body {
                    PolicyBody::RouteMap(clauses) => {
                        for c in clauses {
                            for a in &c.sets {
                                if let SetAction::NextHop(NextHopSet::Address(x)) = a {
                                    out.insert(*x);
                                }
                            }
                        }
                    }
                    PolicyBody::Rpl(s) => stmts(s, &mut out),
                }
            }
        }
        out
    }
}

/// The source of a candidate at a variable, in the order of the decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Source {
    Network,
    Aggregate,
    /// An index into the `redistribute` statements of the process.
    Redistribute(usize),
    /// An index into `Net::seeds`.
    Seed(usize),
    /// An index into `Net::links`.
    Link(usize),
    /// An index into `Net::leaks`.
    Leak(usize),
}

/// A candidate of a variable.
#[derive(Clone, Debug)]
pub(crate) struct Cand {
    pub source: Source,
    pub offer: Result<BgpPath, Unknown>,
}

/// The selection of a variable from its candidates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Choice {
    None,
    Best(Source, Box<Selection>),
    /// The decision reaches a tie, or more than 1 path is the best path in
    /// some order of receipt. Each tied path with its multipath.
    Tie(Vec<(Source, Selection)>),
    Unknown(Unknown),
}

impl Choice {
    /// The best path that the forward pass takes: the first tied path for
    /// a tie.
    pub fn pick(&self) -> BestPath {
        match self {
            Choice::None => BestPath::None,
            Choice::Best(_, s) => BestPath::Path(s.best.clone()),
            Choice::Tie(t) => BestPath::Path(t[0].1.best.clone()),
            Choice::Unknown(u) => BestPath::Unknown(u.clone()),
        }
    }

    /// The selection whose best path is `best`.
    pub fn selection_of(&self, best: &BgpPath) -> Option<&Selection> {
        match self {
            Choice::Best(_, s) if &s.best == best => Some(&**s),
            Choice::Tie(t) => t.iter().map(|(_, s)| s).find(|s| &s.best == best),
            _ => None,
        }
    }
}

/// The variables of a prefix group and the data that their candidates
/// read.
pub(crate) struct Group<'n, 'a> {
    pub net: &'n Net<'a>,
    /// The process and the key of each variable, in the order of the key
    /// and the process.
    pub vars: Vec<(usize, RouteKey)>,
    pub index: BTreeMap<(usize, RouteKey), usize>,
    /// The links into the process of each variable, with the variable of
    /// the sender.
    pub inlinks: Vec<Vec<(usize, usize)>>,
    /// The links out of the process of each variable.
    pub outlinks: Vec<Vec<usize>>,
    /// The variables of the routes inside an aggregate of each variable.
    pub contributors: Vec<Vec<usize>>,
    /// The variables of the summary-only aggregates of the process that
    /// hold each variable back.
    pub suppressors: Vec<Vec<usize>>,
    pub network: Vec<Option<Offer>>,
    pub has_aggregate: Vec<bool>,
    /// The offer of each `redistribute` statement that offers a path or an
    /// unknown result, by the index of the statement.
    pub redistributed: Vec<Vec<(usize, Offer)>>,
    pub seeds: Vec<Vec<(usize, Offer)>>,
    /// The leaks into the process of each variable, with the variable of
    /// the source.
    pub inleaks: Vec<Vec<(usize, usize)>>,
}

impl<'n, 'a> Group<'n, 'a> {
    pub fn new(net: &'n Net<'a>, keys: &BTreeSet<RouteKey>) -> Group<'n, 'a> {
        let mut vars = Vec::new();
        for &k in keys {
            for i in 0..net.procs.len() {
                if net.holds(i, &k) {
                    vars.push((i, k));
                }
            }
        }
        let index: BTreeMap<(usize, RouteKey), usize> =
            vars.iter().enumerate().map(|(v, &x)| (x, v)).collect();
        let mut g = Group {
            net,
            inlinks: vec![Vec::new(); vars.len()],
            outlinks: vec![Vec::new(); vars.len()],
            contributors: vec![Vec::new(); vars.len()],
            suppressors: vec![Vec::new(); vars.len()],
            network: vec![None; vars.len()],
            has_aggregate: vec![false; vars.len()],
            redistributed: vec![Vec::new(); vars.len()],
            seeds: vec![Vec::new(); vars.len()],
            inleaks: vec![Vec::new(); vars.len()],
            vars,
            index,
        };
        // The EVPN IP prefix keys of each prefix.
        let mut evpn_keys: BTreeMap<rsim_core::Prefix, Vec<RouteKey>> = BTreeMap::new();
        for k in keys.iter().filter(|k| k.family == Family::EvpnIpPrefix) {
            evpn_keys.entry(k.prefix).or_default().push(*k);
        }
        for v in 0..g.vars.len() {
            let (i, k) = g.vars[v];
            let p = net.procs[i];
            for (l, link) in net.links.iter().enumerate() {
                if link.to == i
                    && let Some(&w) = g.index.get(&(link.from, k))
                {
                    g.inlinks[v].push((l, w));
                }
                if link.from == i {
                    g.outlinks[v].push(l);
                }
            }
            for (li, lk) in net.leaks.iter().enumerate().filter(|(_, l)| l.to == i) {
                let from = net.procs[lk.from];
                let sources: Vec<RouteKey> = match lk.kind {
                    LeakKind::EvpnExport => match (k.family, from.targets.rd) {
                        (Family::EvpnIpPrefix, Some(rd)) if k.rd == Some(rd) => {
                            vec![RouteKey::unicast(k.prefix)]
                        }
                        _ => Vec::new(),
                    },
                    LeakKind::EvpnImport if k.family != Family::EvpnIpPrefix => {
                        evpn_keys.get(&k.prefix).cloned().unwrap_or_default()
                    }
                    LeakKind::EvpnImport => Vec::new(),
                    LeakKind::Vrf if k.family != Family::EvpnIpPrefix => vec![k],
                    LeakKind::Vrf => Vec::new(),
                };
                for sk in sources {
                    if let Some(&w) = g.index.get(&(lk.from, sk)) {
                        g.inleaks[v].push((li, w));
                    }
                }
            }
            if let Some(route) = net.igp_routes.get(&(i, k.prefix))
                && k.family != Family::EvpnIpPrefix
            {
                for (ri, r) in p.redistributions.iter().enumerate() {
                    let offer = g.resolve(i, redistribute_offer(p, r, &k, route));
                    if !matches!(offer, Offer::None) {
                        g.redistributed[v].push((ri, offer));
                    }
                }
            }
            if let Some(n) = p.networks.iter().find(|n| n.key == k) {
                let present = net.igp.has_route(&p.device, &p.vrf, k.prefix);
                g.network[v] = Some(network_offer(p, n, present));
            }
            if p.aggregates.iter().any(|a| a.key == k) {
                g.has_aggregate[v] = true;
                g.contributors[v] = keys
                    .iter()
                    .filter(|&c| inside(c, &k))
                    .filter_map(|c| g.index.get(&(i, *c)).copied())
                    .collect();
            }
            g.suppressors[v] = p
                .aggregates
                .iter()
                .filter(|a| a.summary_only && inside(&k, &a.key))
                .filter_map(|a| g.index.get(&(i, a.key)).copied())
                .collect();
            for (si, s) in net.seeds.iter().enumerate() {
                if net.proc_index(&s.device, &s.vrf) == Some(i) && s.key == k {
                    let offer = g.seed_offer(i, s);
                    g.seeds[v].push((si, offer));
                }
            }
        }
        g
    }

    pub fn at(&self, v: usize) -> (&BgpProcess, RouteKey) {
        let (i, k) = self.vars[v];
        (self.net.procs[i], k)
    }

    fn seed_offer(&self, i: usize, s: &Seed) -> Offer {
        let p = self.net.procs[i];
        let n = &p.neighbors[&s.neighbor];
        let offer = if s.received {
            receive(p, n, s.path.peer.router_id, &s.key, &s.path)
        } else {
            let mut path = s.path.clone();
            path.peer.address = Some(s.neighbor);
            path.peer.kind = p.session_kind(n);
            Offer::Path(path)
        };
        self.resolve(i, offer)
    }

    /// The offer with the IGP cost of its next hop at process `i`, in the
    /// VRF of a leaked path. A next hop that does not resolve gives no
    /// path.
    fn resolve(&self, i: usize, offer: Offer) -> Offer {
        let Offer::Path(mut path) = offer else {
            return offer;
        };
        let Some(nh) = path.next_hop else {
            return Offer::Path(path);
        };
        let p = self.net.procs[i];
        let vrf = path
            .leaked
            .as_ref()
            .map_or(p.vrf.as_str(), |l| l.vrf.as_str());
        match self.net.igp.resolve(&p.device, vrf, nh) {
            Resolution::Resolved { cost } => {
                path.igp_cost = cost;
                Offer::Path(path)
            }
            Resolution::Unresolved => Offer::None,
            Resolution::Unknown(why) => Offer::Unknown(Unknown::new(
                Reason::NextHopNotResolved,
                format!("{nh} at {} {vrf}: {why}", p.device),
            )),
        }
    }

    /// The offer of leak `li` for the best path `best` of its source
    /// variable, with the IGP cost at the receiver.
    pub fn leak(&self, li: usize, best: &BestPath) -> Offer {
        let lk = self.net.leaks[li];
        let (from, to) = (self.net.procs[lk.from], self.net.procs[lk.to]);
        let offer = match best {
            BestPath::None => Offer::None,
            BestPath::Unknown(u) => Offer::Unknown(u.clone()),
            BestPath::Path(p) => match lk.kind {
                LeakKind::EvpnExport => evpn_export(from, to, p),
                LeakKind::EvpnImport => evpn_import(to, p),
                LeakKind::Vrf => vrf_leak(from, to, p),
            },
        };
        self.resolve(lk.to, offer)
    }

    /// True if each path that `w` can select comes from an iBGP neighbour
    /// that is not a route-reflector client.
    fn ibgp_only(&self, w: usize) -> bool {
        let p = self.net.procs[self.vars[w].0];
        self.network[w].is_none()
            && !self.has_aggregate[w]
            && self.redistributed[w].is_empty()
            && self.seeds[w].is_empty()
            && self.inleaks[w].is_empty()
            && self.inlinks[w].iter().all(|&(l, _)| {
                let n = &p.neighbors[&self.net.links[l].to_neighbor];
                p.session_kind(n) == SessionKind::Ibgp && !n.route_reflector_client
            })
    }

    /// The sent path over link `l` for the best path `best` of variable
    /// `w` at the sender, with no summary-only check. An unknown best path
    /// gives no path to an iBGP neighbour that is not a route-reflector
    /// client when each path of `w` comes from such a neighbour.
    pub fn sent(&self, l: usize, w: usize, best: &BestPath) -> Offer {
        let link = &self.net.links[l];
        let sender = self.net.procs[link.from];
        let key = self.vars[w].1;
        match best {
            BestPath::None => Offer::None,
            BestPath::Unknown(u) => {
                let n = &sender.neighbors[&link.from_neighbor];
                if sender.session_kind(n) == SessionKind::Ibgp
                    && !n.route_reflector_client
                    && self.ibgp_only(w)
                {
                    Offer::None
                } else {
                    Offer::Unknown(u.clone())
                }
            }
            BestPath::Path(p) => export(
                sender,
                &sender.neighbors[&link.from_neighbor],
                link.to_neighbor,
                &key,
                p,
            ),
        }
    }

    /// The accepted path over link `l` for the best path `best` of the
    /// sender variable `w`, with the IGP cost at the receiver, with no
    /// summary-only check.
    pub fn transfer(&self, l: usize, w: usize, best: &BestPath) -> Offer {
        let link = &self.net.links[l];
        let receiver = self.net.procs[link.to];
        let sender = self.net.procs[link.from];
        let key = self.vars[w].1;
        let offer = match self.sent(l, w, best) {
            Offer::Path(p) => receive(
                receiver,
                &receiver.neighbors[&link.to_neighbor],
                sender.router_id,
                &key,
                &p,
            ),
            other => other,
        };
        self.resolve(link.to, offer)
    }

    /// The effect of the summary-only aggregates of the sender of `w`:
    /// `Some(true)` holds the route back, `None` is not known.
    pub fn suppressed(
        &self,
        w: usize,
        get: &dyn Fn(usize) -> Option<BestPath>,
    ) -> Option<Option<bool>> {
        let mut unknown = false;
        for &s in &self.suppressors[w] {
            match get(s)? {
                BestPath::Path(_) => return Some(Some(true)),
                BestPath::Unknown(_) => unknown = true,
                BestPath::None => {}
            }
        }
        Some(if unknown { None } else { Some(false) })
    }

    pub fn aggregate(&self, v: usize, contributors: &[BestPath]) -> Offer {
        let (p, k) = self.at(v);
        match p.aggregates.iter().find(|a| a.key == k) {
            Some(a) => aggregate_offer(p, a, contributors),
            None => Offer::None,
        }
    }

    /// The candidates of `v` for the best paths that `get` gives. `None`
    /// when `get` gives none for a variable that they read.
    pub fn candidates(
        &self,
        v: usize,
        get: &dyn Fn(usize) -> Option<BestPath>,
    ) -> Option<Vec<Cand>> {
        let mut out = Vec::new();
        let mut push = |source: Source, offer: &Offer| match offer {
            Offer::None => {}
            Offer::Path(p) => out.push(Cand {
                source,
                offer: Ok(p.clone()),
            }),
            Offer::Unknown(u) => out.push(Cand {
                source,
                offer: Err(u.clone()),
            }),
        };
        if let Some(n) = &self.network[v] {
            push(Source::Network, n);
        }
        if self.has_aggregate[v] {
            let cs: Option<Vec<BestPath>> = self.contributors[v].iter().map(|&c| get(c)).collect();
            push(Source::Aggregate, &self.aggregate(v, &cs?));
        }
        for (ri, offer) in &self.redistributed[v] {
            push(Source::Redistribute(*ri), offer);
        }
        for (si, offer) in &self.seeds[v] {
            push(Source::Seed(*si), offer);
        }
        for &(li, w) in &self.inleaks[v] {
            let best = get(w)?;
            push(Source::Leak(li), &self.leak(li, &best));
        }
        for &(l, w) in &self.inlinks[v] {
            let best = get(w)?;
            let offer = match self.suppressed(w, get)? {
                Some(true) => Offer::None,
                Some(false) => self.transfer(l, w, &best),
                None => match best {
                    BestPath::None => Offer::None,
                    _ => Offer::Unknown(Unknown::new(
                        Reason::SelectionNotKnown,
                        "summary-only aggregate".to_string(),
                    )),
                },
            };
            push(Source::Link(l), &offer);
        }
        Some(out)
    }

    /// The selection of `v` from `cands`.
    pub fn choose(&self, v: usize, cands: &[Cand]) -> Choice {
        if cands.is_empty() {
            return Choice::None;
        }
        if let Some(u) = cands.iter().find_map(|c| c.offer.as_ref().err()) {
            return Choice::Unknown(u.clone());
        }
        let (p, _) = self.at(v);
        let paths: Vec<BgpPath> = cands
            .iter()
            .filter_map(|c| c.offer.as_ref().ok().cloned())
            .collect();
        let profile = p.profile();
        let sel = |base: usize, mp: &[usize]| Selection {
            best: paths[base].clone(),
            multipath: mp.iter().map(|&j| paths[j].clone()).collect(),
        };
        let tie = |tied: &[usize], profile: &BgpProfile| {
            let mut out = Vec::new();
            for &t in tied {
                match multipath_for(&paths, t, &p.options, profile) {
                    Ok(mp) => out.push((cands[t].source, sel(t, &mp))),
                    Err(u) => return Choice::Unknown(u),
                }
            }
            Choice::Tie(out)
        };
        let decision = decide(&paths, &p.options, profile.as_ref());
        if matches!(decision, Decision::Best { .. } | Decision::Tie { .. }) {
            match order_winners(&paths, &p.options, profile.as_ref()) {
                Err(u) => return Choice::Unknown(u),
                Ok(Some(winners)) if winners.len() > 1 => {
                    let profile = profile.expect("order winners have a profile");
                    return tie(&winners, &profile);
                }
                Ok(_) => {}
            }
        }
        match decision {
            Decision::NoCandidate => Choice::None,
            Decision::Best {
                best, multipath, ..
            } => Choice::Best(cands[best].source, Box::new(sel(best, &multipath))),
            Decision::Tie { tied, .. } => {
                let profile = profile.expect("a tie has a profile");
                tie(&tied, &profile)
            }
            Decision::Unknown(u) => Choice::Unknown(u),
        }
    }

    /// The selection of `v` for the best paths of `state`.
    pub fn choice(&self, v: usize, state: &[BestPath]) -> Choice {
        let get = |w: usize| Some(state[w].clone());
        let cands = self
            .candidates(v, &get)
            .expect("a full state gives each variable");
        self.choose(v, &cands)
    }

    /// One synchronous round: the best path of each variable from the
    /// best paths of `state`.
    pub fn round(&self, state: &[BestPath]) -> Vec<BestPath> {
        (0..self.vars.len())
            .map(|v| self.choice(v, state).pick())
            .collect()
    }
}
