//! The OSPF route calculation of one router over its link-state database.
//!
//! - RFC 2328 16.1 runs Dijkstra in each attached area over the router and
//!   network LSAs. A vertex is entered only when its own LSA links back. At
//!   equal cost a network vertex leaves the candidate list before a router
//!   vertex. The second stage adds the stub links and the network prefixes,
//!   and for OSPFv3 the prefixes of the intra-area-prefix LSAs. Over a
//!   point-to-point link the next hop is the address of the neighbour from
//!   its link back, for OSPFv3 the link-local address of its link LSA. Over
//!   a directly attached transit network it is the address of the
//!   neighbour on the segment. Each other vertex takes the next hops of its
//!   parent.
//! - RFC 2328 16.2 gives the inter-area routes from the summary and
//!   ASBR-summary LSAs. An area border router reads only the summary LSAs of
//!   the backbone. A router with no active backbone attachment reads the
//!   summary LSAs of each attached area (RFC 3509). A summary LSA that the
//!   router originates into the same area for the same prefix is an active
//!   area range, and the copy of another border router is ignored.
//! - RFC 2328 16.4 and RFC 3101 2.5 give the external routes from the
//!   AS-external LSAs and, in each attached NSSA, the NSSA LSAs. The P bit of
//!   an NSSA LSA is taken as set.
//! - A virtual link of the calculating router is not computed (16.3).

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::net::{IpAddr, Ipv4Addr};

use rsim_core::{Prefix, SourceSpan};

use super::{
    AreaId, AreaType, BACKBONE, Body, Calculation, Database, Gap, GapReach, LS_INFINITY, LinkKind,
    Lsa, LsaType, NextHop, Note, OspfProfile, PathType, Reference, Route, RouterId, RouterLink,
    Version,
};

type Hops = BTreeSet<NextHop>;

/// The key of a network vertex: the link-state ID of an OSPFv2 network LSA,
/// the designated router and its interface ID for OSPFv3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum NetKey {
    V2(Ipv4Addr),
    V3(RouterId, u32),
}

impl NetKey {
    fn lsid(self) -> Ipv4Addr {
        match self {
            NetKey::V2(a) => a,
            NetKey::V3(_, i) => Ipv4Addr::from(i),
        }
    }
}

/// A vertex of the shortest path tree. A network ranks before a router at
/// equal cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Vid {
    Network(NetKey),
    Router(RouterId),
}

/// The router LSAs of one router in one area. OSPFv3 joins the links of
/// all router LSAs of the router.
struct RouterV<'a> {
    links: Vec<&'a RouterLink>,
    expired: bool,
    span: SourceSpan,
}

struct Index<'a> {
    routers: BTreeMap<(AreaId, RouterId), RouterV<'a>>,
    networks: BTreeMap<(AreaId, NetKey), &'a Lsa>,
    links: BTreeMap<(AreaId, RouterId, u32), &'a Lsa>,
}

impl<'a> Index<'a> {
    fn new(db: &'a Database) -> Index<'a> {
        let mut ix = Index {
            routers: BTreeMap::new(),
            networks: BTreeMap::new(),
            links: BTreeMap::new(),
        };
        for lsa in db.lsas.values() {
            let Some(area) = lsa.area else { continue };
            match (&lsa.body, lsa.lsa_type) {
                (Body::Router { links }, LsaType::Router) => {
                    let e = ix
                        .routers
                        .entry((area, lsa.adv_router))
                        .or_insert_with(|| RouterV {
                            links: Vec::new(),
                            expired: true,
                            span: lsa.span.clone(),
                        });
                    if !lsa.expired() {
                        if e.expired {
                            e.span = lsa.span.clone();
                        }
                        e.expired = false;
                        e.links.extend(links.iter());
                    }
                }
                (Body::Network { .. }, LsaType::Network) => {
                    let key = match db.version {
                        Version::V2 => NetKey::V2(lsa.lsid),
                        Version::V3 => NetKey::V3(lsa.adv_router, u32::from(lsa.lsid)),
                    };
                    let newer = ix
                        .networks
                        .get(&(area, key))
                        .is_none_or(|held| lsa.fresher(held));
                    if newer {
                        ix.networks.insert((area, key), lsa);
                    }
                }
                (Body::Link { .. }, LsaType::Link) => {
                    ix.links
                        .insert((area, lsa.adv_router, u32::from(lsa.lsid)), lsa);
                }
                _ => {}
            }
        }
        ix
    }
}

/// The fixed inputs of one calculation.
struct Cx<'a> {
    db: &'a Database,
    index: Index<'a>,
    root: RouterId,
    profile: OspfProfile,
    by_address: BTreeMap<IpAddr, &'a str>,
    by_id: BTreeMap<u32, &'a str>,
}

impl Cx<'_> {
    fn version(&self) -> Version {
        self.db.version
    }

    fn net_key(&self, link: &RouterLink) -> Option<NetKey> {
        match self.version() {
            Version::V2 => Some(NetKey::V2(link.id)),
            Version::V3 => link.neighbor_interface_id.map(|i| NetKey::V3(link.id, i)),
        }
    }

    /// The interface of the calculating router at the root end of a link.
    fn own_interface(&self, link: &RouterLink) -> Option<String> {
        match self.version() {
            Version::V2 => link
                .data
                .and_then(|d| self.by_address.get(&IpAddr::V4(d)))
                .map(|s| s.to_string()),
            Version::V3 => link
                .interface_id
                .and_then(|i| self.by_id.get(&i))
                .map(|s| s.to_string()),
        }
    }

    /// The interface of the calculating router in a prefix.
    fn interface_in(&self, prefix: Prefix) -> Option<String> {
        self.db
            .interfaces
            .iter()
            .find(|i| i.address.is_some_and(|(a, _)| prefix.contains(a)))
            .map(|i| i.name.clone())
    }

    fn rfc1583(&self) -> bool {
        self.profile.rfc1583_compatible
    }
}

/// The routes that a gap reaches, while the gaps are collected.
enum Reach {
    All,
    Cost(u32),
    Prefixes(Vec<Prefix>),
}

struct GapEntry {
    detail: String,
    all: bool,
    bound: Option<u32>,
    prefixes: BTreeSet<Prefix>,
}

/// The gaps by type, link-state ID and area, each listed once, and the
/// notes of the calculation.
#[derive(Default)]
struct Out {
    gaps: BTreeMap<(LsaType, Ipv4Addr, bool, AreaId), GapEntry>,
    notes: Vec<Note>,
}

impl Out {
    fn gap(
        &mut self,
        version: Version,
        lsa_type: LsaType,
        lsid: Ipv4Addr,
        area: Option<AreaId>,
        detail: &str,
        reach: Reach,
    ) {
        let key = (lsa_type, lsid, area.is_none(), area.unwrap_or(BACKBONE));
        let e = self.gaps.entry(key).or_insert_with(|| {
            let place = area.map(|a| format!(" in area {a}")).unwrap_or_default();
            GapEntry {
                detail: format!(
                    "{} LSA {lsid}{place} is not in the database: {detail}",
                    lsa_type.name(version)
                ),
                all: false,
                bound: None,
                prefixes: BTreeSet::new(),
            }
        });
        match reach {
            Reach::All => e.all = true,
            Reach::Cost(c) => e.bound = Some(e.bound.map_or(c, |b| b.min(c))),
            Reach::Prefixes(p) => e.prefixes.extend(p),
        }
    }

    fn note(&mut self, kind: &str, subject: String, detail: String) {
        self.notes.push(Note::new(kind, subject, detail));
    }

    fn gap_list(&self) -> Vec<Gap> {
        self.gaps
            .iter()
            .map(|(&(lsa_type, lsid, no_area, area), e)| Gap {
                lsa_type,
                lsid,
                area: (!no_area).then_some(area),
                detail: e.detail.clone(),
                reach: if e.all {
                    GapReach::All
                } else if let Some(b) = e.bound {
                    GapReach::FromCost(b)
                } else {
                    GapReach::Prefixes(e.prefixes.iter().copied().collect())
                },
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
struct Vertex {
    cost: u32,
    hops: Hops,
}

/// An intra-area path to a prefix in one area.
#[derive(Clone, Debug)]
struct Entry {
    cost: u32,
    hops: Hops,
    /// True for a subnet of the calculating router. The route table holds it
    /// as a connected route, and it resolves forwarding addresses.
    direct: bool,
    spans: BTreeSet<SourceSpan>,
}

#[derive(Default)]
struct Tree {
    routers: BTreeMap<RouterId, Vertex>,
    networks: BTreeMap<NetKey, Vertex>,
    prefixes: BTreeMap<Prefix, Entry>,
}

impl Tree {
    fn placed(&self, vid: Vid) -> bool {
        match vid {
            Vid::Router(r) => self.routers.contains_key(&r),
            Vid::Network(n) => self.networks.contains_key(&n),
        }
    }
}

#[derive(Default)]
struct Frontier {
    candidates: BTreeMap<Vid, Vertex>,
    heap: BinaryHeap<Reverse<(u32, Vid)>>,
}

impl Frontier {
    fn offer(&mut self, tree: &Tree, vid: Vid, cost: u32, hops: Hops) {
        if tree.placed(vid) {
            return;
        }
        match self.candidates.get_mut(&vid) {
            Some(held) if cost == held.cost => held.hops.extend(hops),
            Some(held) if cost > held.cost => {}
            _ => {
                self.candidates.insert(vid, Vertex { cost, hops });
                self.heap.push(Reverse((cost, vid)));
            }
        }
    }
}

/// The prefix length of a mask, or `None` for a mask that is not
/// contiguous.
pub fn mask_len(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let len = bits.leading_ones();
    (bits.checked_shl(len).unwrap_or(0) == 0).then_some(len as u8)
}

pub(crate) fn v2_prefix(id: Ipv4Addr, mask: Option<Ipv4Addr>) -> Option<Prefix> {
    mask.and_then(mask_len)
        .map(|len| Prefix::new(IpAddr::V4(id), len))
}

fn attached(net: &Lsa) -> &[RouterId] {
    match &net.body {
        Body::Network { attached, .. } => attached,
        _ => &[],
    }
}

/// The next hops over a point-to-point link from the calculating router
/// (RFC 2328 16.1.1). OSPFv2 takes the interface address of the neighbour
/// from the link data of its link back, and pairs parallel links by the
/// stub subnet of the own end. OSPFv3 takes the link-local address of the
/// link LSA of the neighbour on the link back.
fn p2p_hops(
    cx: &Cx<'_>,
    out: &mut Out,
    area: AreaId,
    link: &RouterLink,
    backs: &[&RouterLink],
    bound: u32,
) -> Hops {
    let root = cx.root;
    let far = link.id;
    let version = cx.version();
    let interface = cx.own_interface(link);
    match version {
        Version::V2 => {
            let mut addrs: Vec<Ipv4Addr> = backs
                .iter()
                .filter_map(|b| b.data)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            if addrs.is_empty() {
                out.gap(
                    version,
                    LsaType::Router,
                    far,
                    Some(area),
                    &format!("the link back of router {far} to {root} has no interface address"),
                    Reach::Cost(bound),
                );
                return Hops::new();
            }
            if addrs.len() > 1
                && let Some(own) = link.data
            {
                let root_links = cx
                    .index
                    .routers
                    .get(&(area, root))
                    .map(|r| r.links.as_slice())
                    .unwrap_or_default();
                if let Some(stub) = root_links.iter().find(|s| {
                    s.kind == LinkKind::Stub
                        && v2_prefix(s.id, s.data).is_some_and(|p| p.contains(IpAddr::V4(own)))
                }) && let Some(p) = v2_prefix(stub.id, stub.data)
                {
                    let paired: Vec<Ipv4Addr> = addrs
                        .iter()
                        .copied()
                        .filter(|a| p.contains(IpAddr::V4(*a)))
                        .collect();
                    if !paired.is_empty() {
                        addrs = paired;
                    }
                }
                if addrs.len() > 1 {
                    out.note(
                        "ospf-ambiguous-next-hop",
                        format!("{area}/{far}"),
                        format!(
                            "routers {root} and {far} share {} point-to-point links in area {area}, and no stub link pairs {own} with one of them; each far-end address is a next hop",
                            addrs.len()
                        ),
                    );
                }
            }
            for a in &addrs {
                if a.octets()[..3] == [0, 0, 0] {
                    out.note(
                        "ospf-unnumbered-link",
                        format!("{area}/{far}"),
                        format!(
                            "the link from {root} to {far} in area {area} is unnumbered, and its link data {a} is an interface index"
                        ),
                    );
                }
            }
            addrs
                .into_iter()
                .map(|a| NextHop {
                    gateway: IpAddr::V4(a),
                    interface: interface.clone(),
                })
                .collect()
        }
        Version::V3 => {
            let paired: Vec<&RouterLink> = match link.neighbor_interface_id {
                Some(n) => backs
                    .iter()
                    .copied()
                    .filter(|b| b.interface_id == Some(n))
                    .collect(),
                None => Vec::new(),
            };
            let backs: Vec<&RouterLink> = if paired.is_empty() {
                backs.to_vec()
            } else {
                paired
            };
            v3_hops(cx, out, area, far, &backs, interface, bound)
        }
    }
}

/// The link-local addresses of a neighbour on its links back, from its link
/// LSAs. A link LSA that the database lacks is a gap.
fn v3_hops(
    cx: &Cx<'_>,
    out: &mut Out,
    area: AreaId,
    far: RouterId,
    backs: &[&RouterLink],
    interface: Option<String>,
    bound: u32,
) -> Hops {
    let mut hops = Hops::new();
    for b in backs {
        let Some(id) = b.interface_id else {
            out.gap(
                Version::V3,
                LsaType::Router,
                far,
                Some(area),
                &format!(
                    "the link back of router {far} to {} has no interface ID",
                    cx.root
                ),
                Reach::Cost(bound),
            );
            continue;
        };
        let link_lsa = cx.index.links.get(&(area, far, id));
        let address = link_lsa.and_then(|l| match &l.body {
            Body::Link { address, .. } => *address,
            _ => None,
        });
        let Some(address) = address else {
            out.gap(
                Version::V3,
                LsaType::Link,
                Ipv4Addr::from(id),
                Some(area),
                &format!(
                    "the link-local address of router {far} on its link to {}",
                    cx.root
                ),
                Reach::Cost(bound),
            );
            continue;
        };
        let interface = interface.clone().or_else(|| {
            link_lsa.and_then(|l| match &l.body {
                Body::Link { interface, .. } => interface.clone(),
                _ => None,
            })
        });
        hops.insert(NextHop {
            gateway: IpAddr::V6(address),
            interface,
        });
    }
    hops
}

/// The next hops to the routers on a transit network that the calculating
/// router is attached to.
fn direct_hops(
    cx: &Cx<'_>,
    out: &mut Out,
    area: AreaId,
    key: NetKey,
    far: RouterId,
    backs: &[&RouterLink],
    bound: u32,
) -> Hops {
    let own = cx
        .index
        .routers
        .get(&(area, cx.root))
        .and_then(|r| {
            r.links
                .iter()
                .find(|l| l.kind == LinkKind::Transit && cx.net_key(l) == Some(key))
        })
        .and_then(|l| cx.own_interface(l));
    match cx.version() {
        Version::V2 => {
            let hops: Hops = backs
                .iter()
                .filter_map(|b| b.data)
                .map(|a| NextHop {
                    gateway: IpAddr::V4(a),
                    interface: own.clone(),
                })
                .collect();
            if hops.is_empty() {
                out.gap(
                    Version::V2,
                    LsaType::Router,
                    far,
                    Some(area),
                    &format!(
                        "the link of router {far} to network {} has no interface address",
                        key.lsid()
                    ),
                    Reach::Cost(bound),
                );
            }
            hops
        }
        Version::V3 => v3_hops(cx, out, area, far, backs, own, bound),
    }
}

/// RFC 2328 16.1 over one area.
fn spf(cx: &Cx<'_>, out: &mut Out, area: AreaId) -> Tree {
    let root = cx.root;
    let version = cx.version();
    let mut tree = Tree::default();
    let mut front = Frontier::default();
    front.offer(&tree, Vid::Router(root), 0, Hops::new());
    while let Some(Reverse((cost, vid))) = front.heap.pop() {
        if tree.placed(vid) || front.candidates.get(&vid).is_none_or(|v| v.cost != cost) {
            continue;
        }
        let vertex = front
            .candidates
            .remove(&vid)
            .expect("the candidate is held");
        match vid {
            Vid::Router(rid) => {
                tree.routers.insert(rid, vertex.clone());
                let Some(rv) = cx.index.routers.get(&(area, rid)) else {
                    continue;
                };
                for link in rv.links.iter().copied() {
                    let next = cost.saturating_add(link.metric);
                    match link.kind {
                        LinkKind::Stub => {}
                        LinkKind::Virtual if rid == root => out.note(
                            "ospf-virtual-link-not-modeled",
                            format!("{area}/{}", link.id),
                            format!(
                                "router {root} has a virtual link to {} in area {area}; the paths of the transit area are not computed, so the link is skipped",
                                link.id
                            ),
                        ),
                        LinkKind::Transit => {
                            let Some(key) = cx.net_key(link) else {
                                out.note(
                                    "malformed-lsa",
                                    format!("{rid}"),
                                    format!(
                                        "the transit link of router {rid} to {} has no interface ID of the designated router",
                                        link.id
                                    ),
                                );
                                continue;
                            };
                            let Some(net) = cx.index.networks.get(&(area, key)) else {
                                out.gap(
                                    version,
                                    LsaType::Network,
                                    key.lsid(),
                                    Some(area),
                                    &format!("named by a transit link of router {rid}"),
                                    Reach::Cost(next),
                                );
                                continue;
                            };
                            if net.expired() || !attached(net).contains(&rid) {
                                continue;
                            }
                            let hops = if rid == root {
                                Hops::new()
                            } else {
                                vertex.hops.clone()
                            };
                            front.offer(&tree, Vid::Network(key), next, hops);
                        }
                        LinkKind::PointToPoint | LinkKind::Virtual => {
                            let Some(far) = cx.index.routers.get(&(area, link.id)) else {
                                out.gap(
                                    version,
                                    LsaType::Router,
                                    link.id,
                                    Some(area),
                                    &format!("named by a {} link of router {rid}", link.kind.name()),
                                    Reach::Cost(next),
                                );
                                continue;
                            };
                            if far.expired {
                                continue;
                            }
                            let backs: Vec<&RouterLink> = far
                                .links
                                .iter()
                                .copied()
                                .filter(|b| {
                                    matches!(b.kind, LinkKind::PointToPoint | LinkKind::Virtual)
                                        && b.id == rid
                                })
                                .collect();
                            if backs.is_empty() {
                                continue;
                            }
                            let hops = if rid == root {
                                p2p_hops(cx, out, area, link, &backs, next)
                            } else {
                                vertex.hops.clone()
                            };
                            if hops.is_empty() {
                                continue;
                            }
                            front.offer(&tree, Vid::Router(link.id), next, hops);
                        }
                    }
                }
            }
            Vid::Network(key) => {
                tree.networks.insert(key, vertex.clone());
                let Some(net) = cx.index.networks.get(&(area, key)) else {
                    continue;
                };
                let direct = vertex.hops.is_empty();
                let members: BTreeSet<RouterId> = attached(net).iter().copied().collect();
                for rid in members {
                    if rid == root {
                        continue;
                    }
                    let Some(far) = cx.index.routers.get(&(area, rid)) else {
                        out.gap(
                            version,
                            LsaType::Router,
                            rid,
                            Some(area),
                            &format!("attached to network {}", key.lsid()),
                            Reach::Cost(cost),
                        );
                        continue;
                    };
                    if far.expired {
                        continue;
                    }
                    let backs: Vec<&RouterLink> = far
                        .links
                        .iter()
                        .copied()
                        .filter(|b| b.kind == LinkKind::Transit && cx.net_key(b) == Some(key))
                        .collect();
                    if backs.is_empty() {
                        continue;
                    }
                    let hops = if direct {
                        direct_hops(cx, out, area, key, rid, &backs, cost)
                    } else {
                        vertex.hops.clone()
                    };
                    if hops.is_empty() {
                        continue;
                    }
                    front.offer(&tree, Vid::Router(rid), cost, hops);
                }
            }
        }
    }
    prefixes(cx, out, area, &mut tree);
    tree
}

/// The second stage of 16.1: the stub links and the network prefixes of
/// OSPFv2, and the prefixes of the intra-area-prefix LSAs of OSPFv3.
fn prefixes(cx: &Cx<'_>, out: &mut Out, area: AreaId, tree: &mut Tree) {
    let root = cx.root;
    match cx.version() {
        Version::V2 => {
            for (rid, v) in &tree.routers {
                let Some(rv) = cx.index.routers.get(&(area, *rid)) else {
                    continue;
                };
                for link in rv.links.iter().filter(|l| l.kind == LinkKind::Stub) {
                    let Some(p) = v2_prefix(link.id, link.data) else {
                        continue;
                    };
                    offer_prefix(
                        &mut tree.prefixes,
                        p,
                        v.cost.saturating_add(link.metric),
                        &v.hops,
                        *rid == root,
                        &rv.span,
                    );
                }
            }
            for (key, v) in &tree.networks {
                let Some(net) = cx.index.networks.get(&(area, *key)) else {
                    continue;
                };
                let mask = match &net.body {
                    Body::Network { mask, .. } => *mask,
                    _ => None,
                };
                let Some(p) = v2_prefix(key.lsid(), mask) else {
                    out.note(
                        "malformed-lsa",
                        key.lsid().to_string(),
                        format!(
                            "{} has no usable mask; its prefix is left out",
                            net.describe(Version::V2)
                        ),
                    );
                    continue;
                };
                offer_prefix(
                    &mut tree.prefixes,
                    p,
                    v.cost,
                    &v.hops,
                    v.hops.is_empty(),
                    &net.span,
                );
            }
        }
        Version::V3 => {
            for lsa in cx.db.lsas.values() {
                if lsa.area != Some(area)
                    || lsa.lsa_type != LsaType::IntraAreaPrefix
                    || lsa.expired()
                {
                    continue;
                }
                let Body::IntraAreaPrefix {
                    reference,
                    router,
                    prefixes,
                } = &lsa.body
                else {
                    continue;
                };
                let found = match reference {
                    Reference::Router => tree.routers.get(router).map(|v| (v, *router == root)),
                    Reference::Network(id) => tree
                        .networks
                        .get(&NetKey::V3(*router, *id))
                        .map(|v| (v, v.hops.is_empty())),
                };
                let Some((v, direct)) = found else { continue };
                for (p, metric) in prefixes {
                    offer_prefix(
                        &mut tree.prefixes,
                        *p,
                        v.cost.saturating_add(*metric),
                        &v.hops,
                        direct,
                        &lsa.span,
                    );
                }
            }
        }
    }
}

fn offer_prefix(
    prefixes: &mut BTreeMap<Prefix, Entry>,
    prefix: Prefix,
    cost: u32,
    hops: &Hops,
    direct: bool,
    span: &SourceSpan,
) {
    let new = || Entry {
        cost,
        hops: hops.clone(),
        direct,
        spans: BTreeSet::from([span.clone()]),
    };
    match prefixes.get_mut(&prefix) {
        None => {
            prefixes.insert(prefix, new());
        }
        Some(held) => {
            if held.direct {
                if direct && cost < held.cost {
                    *held = new();
                }
            } else if direct || cost < held.cost {
                *held = new();
            } else if cost == held.cost {
                held.hops.extend(hops.iter().cloned());
                held.spans.insert(span.clone());
            }
        }
    }
}

/// A routing table entry of destination type router (RFC 2328 section 11)
/// in one area.
#[derive(Clone, Debug)]
struct RouterPath {
    cost: u32,
    hops: Hops,
    area: AreaId,
    path_type: PathType,
}

#[derive(Clone, Debug)]
struct NetEntry {
    path_type: PathType,
    cost: u32,
    hops: Hops,
    area: Option<AreaId>,
    advertising_router: Option<RouterId>,
    lsa_type: Option<LsaType>,
    forward_cost: Option<u32>,
    direct: bool,
    /// The intra-area path in each area, for RFC 2328 16.4.1.
    by_area: BTreeMap<AreaId, Entry>,
    forwarding: Option<IpAddr>,
    /// The class of RFC 2328 16.4.1: 0 when the path to the ASBR or the
    /// forwarding address is intra-area through an area other than the
    /// backbone, 1 for each other path.
    asbr_class: u8,
    spans: BTreeSet<SourceSpan>,
}

impl NetEntry {
    fn intra(entry: &Entry, area: AreaId) -> NetEntry {
        NetEntry {
            path_type: PathType::IntraArea,
            cost: entry.cost,
            hops: entry.hops.clone(),
            area: Some(area),
            advertising_router: None,
            lsa_type: None,
            forward_cost: None,
            direct: entry.direct,
            by_area: BTreeMap::from([(area, entry.clone())]),
            forwarding: None,
            asbr_class: 1,
            spans: entry.spans.clone(),
        }
    }
}

type RouterTable = BTreeMap<RouterId, BTreeMap<AreaId, RouterPath>>;

fn install_intra(
    table: &mut BTreeMap<Prefix, NetEntry>,
    prefix: Prefix,
    entry: &Entry,
    area: AreaId,
) {
    let Some(held) = table.get_mut(&prefix) else {
        table.insert(prefix, NetEntry::intra(entry, area));
        return;
    };
    held.by_area.insert(area, entry.clone());
    if held.direct {
        return;
    }
    if entry.direct || entry.cost < held.cost {
        held.cost = entry.cost;
        held.hops = entry.hops.clone();
        held.area = Some(area);
        held.direct = entry.direct;
        held.spans = entry.spans.clone();
    } else if entry.cost == held.cost {
        held.hops.extend(entry.hops.iter().cloned());
        held.spans.extend(entry.spans.iter().cloned());
    }
}

/// The prefixes of the external LSAs of an ASBR.
fn external_prefixes(db: &Database, asbr: RouterId) -> Vec<Prefix> {
    db.lsas
        .values()
        .filter(|l| l.adv_router == asbr)
        .filter_map(|l| match &l.body {
            Body::External { prefix, .. } => Some(*prefix),
            _ => None,
        })
        .collect()
}

/// RFC 2328 16.2 over the summary and ASBR-summary LSAs of one area.
fn inter_area(
    cx: &Cx<'_>,
    out: &mut Out,
    area: AreaId,
    table: &mut BTreeMap<Prefix, NetEntry>,
    routers: &mut RouterTable,
) {
    let root = cx.root;
    let version = cx.version();
    let lsas: Vec<&Lsa> = cx
        .db
        .lsas
        .values()
        .filter(|l| {
            l.area == Some(area) && matches!(l.lsa_type, LsaType::Summary | LsaType::AsbrSummary)
        })
        .collect();
    let own: BTreeSet<Prefix> = lsas
        .iter()
        .filter(|l| l.adv_router == root)
        .filter_map(|l| match &l.body {
            Body::Summary { prefix, .. } => Some(*prefix),
            _ => None,
        })
        .collect();
    for lsa in lsas {
        let metric = match &lsa.body {
            Body::Summary { metric, .. } | Body::AsbrSummary { metric, .. } => *metric,
            _ => continue,
        };
        let adv = lsa.adv_router;
        if adv == root || lsa.expired() || metric >= LS_INFINITY {
            continue;
        }
        let border = routers
            .get(&adv)
            .and_then(|m| m.get(&area))
            .filter(|b| b.path_type == PathType::IntraArea)
            .cloned();
        let Some(border) = border else {
            if !cx.index.routers.contains_key(&(area, adv)) {
                let reach = match &lsa.body {
                    Body::Summary { prefix, .. } => vec![*prefix],
                    Body::AsbrSummary { router, .. } => external_prefixes(cx.db, *router),
                    _ => Vec::new(),
                };
                out.gap(
                    version,
                    LsaType::Router,
                    adv,
                    Some(area),
                    &format!(
                        "the area border router that advertises {}; the route that it describes has no cost",
                        lsa.describe(version)
                    ),
                    Reach::Prefixes(reach),
                );
            }
            continue;
        };
        let cost = border.cost.saturating_add(metric);
        match &lsa.body {
            Body::Summary { prefix, .. } => {
                if own.contains(prefix) {
                    continue;
                }
                match table.get_mut(prefix) {
                    Some(h) if h.path_type == PathType::IntraArea => {}
                    Some(h) if h.path_type == PathType::InterArea && cost == h.cost => {
                        h.hops.extend(border.hops.iter().cloned());
                        h.spans.insert(lsa.span.clone());
                    }
                    Some(h) if h.path_type == PathType::InterArea && cost > h.cost => {}
                    _ => {
                        table.insert(
                            *prefix,
                            NetEntry {
                                path_type: PathType::InterArea,
                                cost,
                                hops: border.hops.clone(),
                                area: Some(area),
                                advertising_router: Some(adv),
                                lsa_type: Some(LsaType::Summary),
                                forward_cost: None,
                                direct: false,
                                by_area: BTreeMap::new(),
                                forwarding: None,
                                asbr_class: 1,
                                spans: BTreeSet::from([lsa.span.clone()]),
                            },
                        );
                    }
                }
            }
            Body::AsbrSummary { router, .. } => {
                let entries = routers.entry(*router).or_default();
                match entries.get_mut(&area) {
                    Some(h) if h.path_type == PathType::IntraArea => {}
                    Some(h) if cost == h.cost => h.hops.extend(border.hops.iter().cloned()),
                    Some(h) if cost > h.cost => {}
                    _ => {
                        entries.insert(
                            area,
                            RouterPath {
                                cost,
                                hops: border.hops.clone(),
                                area,
                                path_type: PathType::InterArea,
                            },
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

/// The cost, the next hops and the ASBR class of the best path (RFC 2328
/// 16.4.1). Without RFC 1583 compatibility, only the intra-area paths
/// through areas other than the backbone are candidates when one exists.
fn pick(paths: &[RouterPath], rfc1583: bool) -> (u32, Hops, u8) {
    let preferred: Vec<&RouterPath> = paths
        .iter()
        .filter(|p| p.path_type == PathType::IntraArea && p.area != BACKBONE)
        .collect();
    let (paths, class): (Vec<&RouterPath>, u8) = if !rfc1583 && !preferred.is_empty() {
        (preferred, 0)
    } else {
        (paths.iter().collect(), 1)
    };
    let best = paths.iter().map(|p| p.cost).min().unwrap_or(0);
    let hops = paths
        .iter()
        .filter(|p| p.cost == best)
        .flat_map(|p| p.hops.iter().cloned())
        .collect();
    (best, hops, class)
}

/// The longest-prefix lookup of a forwarding address over the intra-area
/// and inter-area routes.
struct Resolver {
    entries: Vec<(Prefix, NetEntry)>,
}

impl Resolver {
    fn new(table: &BTreeMap<Prefix, NetEntry>) -> Resolver {
        Resolver {
            entries: table
                .iter()
                .filter(|(_, e)| matches!(e.path_type, PathType::IntraArea | PathType::InterArea))
                .map(|(p, e)| (*p, e.clone()))
                .collect(),
        }
    }

    fn lookup(&self, address: IpAddr) -> Option<&(Prefix, NetEntry)> {
        self.entries
            .iter()
            .filter(|(p, _)| p.contains(address))
            .max_by_key(|(p, _)| p.len())
    }
}

/// The internal distance, the next hops and the ASBR class of the path to
/// the ASBR or to the forwarding address of an external LSA (RFC 2328 16.4
/// step 3 with RFC 3101 2.5), or `None` when the LSA is not usable.
fn external_path(
    cx: &Cx<'_>,
    out: &mut Out,
    lsa: &Lsa,
    prefix: Prefix,
    forwarding: Option<IpAddr>,
    resolver: &Resolver,
    routers: &RouterTable,
) -> Option<(u32, Hops, u8)> {
    let nssa = lsa.lsa_type == LsaType::NssaExternal;
    let db = cx.db;
    let Some(fa) = forwarding else {
        let entries = routers.get(&lsa.adv_router);
        let paths: Vec<RouterPath> = entries
            .map(|m| {
                m.iter()
                    .filter(|(a, e)| {
                        if nssa {
                            Some(**a) == lsa.area && e.path_type == PathType::IntraArea
                        } else {
                            db.area_type(**a) == AreaType::Normal
                        }
                    })
                    .map(|(_, e)| e.clone())
                    .collect()
            })
            .unwrap_or_default();
        if paths.is_empty() {
            if entries.is_none_or(BTreeMap::is_empty) {
                out.gap(
                    db.version,
                    LsaType::Router,
                    lsa.adv_router,
                    lsa.area,
                    &format!(
                        "the AS boundary router that advertises {}; no router LSA and no ASBR-summary LSA places it, so the external route has no cost",
                        lsa.describe(db.version)
                    ),
                    Reach::Prefixes(vec![prefix]),
                );
            }
            return None;
        }
        return Some(pick(&paths, cx.rfc1583()));
    };
    let (net, entry) = resolver.lookup(fa)?;
    if entry.path_type == PathType::IntraArea {
        let paths: Vec<RouterPath> = entry
            .by_area
            .iter()
            .filter(|(a, _)| {
                if nssa {
                    Some(**a) == lsa.area
                } else {
                    db.area_type(**a) == AreaType::Normal
                }
            })
            .map(|(a, e)| RouterPath {
                cost: e.cost,
                hops: if e.direct {
                    Hops::from([NextHop {
                        gateway: fa,
                        interface: cx.interface_in(*net),
                    }])
                } else {
                    e.hops.clone()
                },
                area: *a,
                path_type: PathType::IntraArea,
            })
            .collect();
        if paths.is_empty() {
            return None;
        }
        return Some(pick(&paths, cx.rfc1583()));
    }
    let area = entry.area?;
    if nssa || db.area_type(area) != AreaType::Normal {
        return None;
    }
    Some(pick(
        &[RouterPath {
            cost: entry.cost,
            hops: entry.hops.clone(),
            area,
            path_type: PathType::InterArea,
        }],
        cx.rfc1583(),
    ))
}

/// Compares 2 external paths (RFC 2328 16.4 step 6): negative when `new` is
/// preferred, positive when `held` is preferred, zero at equal preference.
fn compare_external(new: &NetEntry, held: &NetEntry, rfc1583: bool) -> i8 {
    if new.path_type != held.path_type {
        return if new.path_type == PathType::External1 {
            -1
        } else {
            1
        };
    }
    if new.path_type == PathType::External2 && new.cost != held.cost {
        return if new.cost < held.cost { -1 } else { 1 };
    }
    if !rfc1583 && new.asbr_class != held.asbr_class {
        return if new.asbr_class < held.asbr_class {
            -1
        } else {
            1
        };
    }
    let distance = |e: &NetEntry| {
        if e.path_type == PathType::External1 {
            e.cost
        } else {
            e.forward_cost.unwrap_or(0)
        }
    };
    match distance(new).cmp(&distance(held)) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Greater => 1,
        std::cmp::Ordering::Equal => 0,
    }
}

/// The rank of an LSA among LSAs of the same destination, cost and
/// forwarding address (RFC 3101 2.5 step 6e): an NSSA LSA first, then the
/// higher advertising router. The lower rank is preferred.
fn lsa_rank(e: &NetEntry) -> (u8, Reverse<u32>) {
    (
        u8::from(e.lsa_type != Some(LsaType::NssaExternal)),
        Reverse(e.advertising_router.map_or(0, u32::from)),
    )
}

/// RFC 2328 16.4 and RFC 3101 2.5.
fn externals(
    cx: &Cx<'_>,
    out: &mut Out,
    attached: &[AreaId],
    table: &mut BTreeMap<Prefix, NetEntry>,
    routers: &RouterTable,
) {
    let resolver = Resolver::new(table);
    let mut candidates: Vec<&Lsa> = cx
        .db
        .lsas
        .values()
        .filter(|l| l.lsa_type == LsaType::External)
        .collect();
    for a in attached {
        candidates.extend(
            cx.db
                .lsas
                .values()
                .filter(|l| l.lsa_type == LsaType::NssaExternal && l.area == Some(*a)),
        );
    }
    for lsa in candidates {
        let Body::External {
            prefix,
            metric,
            metric_type,
            forwarding,
        } = &lsa.body
        else {
            continue;
        };
        if lsa.adv_router == cx.root || lsa.expired() || *metric >= LS_INFINITY {
            continue;
        }
        let fa = forwarding.filter(|a| !a.is_unspecified());
        let Some((distance, hops, asbr_class)) =
            external_path(cx, out, lsa, *prefix, fa, &resolver, routers)
        else {
            continue;
        };
        if !matches!(metric_type, Some(1 | 2)) {
            out.note(
                "malformed-lsa",
                lsa.lsid.to_string(),
                format!(
                    "{} has no metric type; it is costed as type 2",
                    lsa.describe(cx.version())
                ),
            );
        }
        let type1 = *metric_type == Some(1);
        let new = NetEntry {
            path_type: if type1 {
                PathType::External1
            } else {
                PathType::External2
            },
            cost: if type1 {
                distance.saturating_add(*metric)
            } else {
                *metric
            },
            hops,
            area: None,
            advertising_router: Some(lsa.adv_router),
            lsa_type: Some(lsa.lsa_type),
            forward_cost: Some(distance),
            direct: false,
            by_area: BTreeMap::new(),
            forwarding: fa,
            asbr_class,
            spans: BTreeSet::from([lsa.span.clone()]),
        };
        let Some(held) = table.get_mut(prefix) else {
            table.insert(*prefix, new);
            continue;
        };
        if matches!(held.path_type, PathType::IntraArea | PathType::InterArea) {
            continue;
        }
        match compare_external(&new, held, cx.rfc1583()) {
            v if v < 0 => *held = new,
            0 => {
                if new.forwarding.is_some() && new.forwarding == held.forwarding {
                    if lsa_rank(&new) < lsa_rank(held) {
                        *held = new;
                    }
                } else {
                    held.hops.extend(new.hops);
                    held.spans.extend(new.spans);
                }
            }
            _ => {}
        }
    }
}

/// The OSPF routes that the router `router_id` computes from its database
/// `db`, with the defaults of `profile`. A database with no router LSA of
/// the router gives no route and a gap.
pub fn compute(db: &Database, router_id: RouterId, profile: &OspfProfile) -> Calculation {
    let cx = Cx {
        db,
        index: Index::new(db),
        root: router_id,
        profile: *profile,
        by_address: db
            .interfaces
            .iter()
            .filter_map(|i| i.address.map(|(a, _)| (a, i.name.as_str())))
            .collect(),
        by_id: db
            .interfaces
            .iter()
            .filter_map(|i| i.interface_id.map(|id| (id, i.name.as_str())))
            .collect(),
    };
    let mut out = Out::default();
    let root = router_id;
    let attached: Vec<AreaId> = db
        .areas()
        .into_iter()
        .filter(|a| cx.index.routers.contains_key(&(*a, root)))
        .collect();
    let mut calc = Calculation {
        router_id,
        version: db.version,
        routes: Vec::new(),
        router_costs: BTreeMap::new(),
        gaps: Vec::new(),
        notes: Vec::new(),
        area_border_router: false,
    };
    if attached.is_empty() {
        out.gap(
            db.version,
            LsaType::Router,
            root,
            None,
            "the router LSA of the calculating router; the database gives no routes",
            Reach::All,
        );
        calc.gaps = out.gap_list();
        calc.notes = out.notes;
        return calc;
    }
    let trees: BTreeMap<AreaId, Tree> = attached
        .iter()
        .map(|a| (*a, spf(&cx, &mut out, *a)))
        .collect();
    let mut table: BTreeMap<Prefix, NetEntry> = BTreeMap::new();
    let mut routers: RouterTable = BTreeMap::new();
    for (area, tree) in &trees {
        for (rid, v) in &tree.routers {
            routers.entry(*rid).or_default().insert(
                *area,
                RouterPath {
                    cost: v.cost,
                    hops: v.hops.clone(),
                    area: *area,
                    path_type: PathType::IntraArea,
                },
            );
        }
        for (prefix, entry) in &tree.prefixes {
            install_intra(&mut table, *prefix, entry, *area);
        }
    }
    let active_backbone = trees.get(&BACKBONE).is_some_and(|t| t.routers.len() > 1);
    let abr = attached.len() > 1 && active_backbone;
    let summary_areas = if abr {
        vec![BACKBONE]
    } else {
        attached.clone()
    };
    for area in summary_areas {
        inter_area(&cx, &mut out, area, &mut table, &mut routers);
    }
    externals(&cx, &mut out, &attached, &mut table, &routers);

    let gaps = out.gap_list();
    let all = gaps.iter().find(|g| g.reach == GapReach::All);
    let bound = gaps
        .iter()
        .filter_map(|g| match g.reach {
            GapReach::FromCost(b) => Some((b, g)),
            _ => None,
        })
        .min_by_key(|(b, _)| *b);
    for (prefix, e) in table {
        if e.direct {
            continue;
        }
        let gap = all.or_else(|| match e.path_type {
            PathType::IntraArea => bound.filter(|(b, _)| e.cost >= *b).map(|(_, g)| g),
            _ => bound.map(|(_, g)| g).or_else(|| {
                gaps.iter()
                    .find(|g| matches!(&g.reach, GapReach::Prefixes(p) if p.contains(&prefix)))
            }),
        });
        calc.routes.push(Route {
            prefix,
            path_type: e.path_type,
            metric: e.cost,
            forward_metric: e.forward_cost,
            area: e.area,
            advertising_router: e.advertising_router,
            lsa_type: e.lsa_type,
            next_hops: e.hops.into_iter().collect(),
            spans: e.spans.into_iter().collect(),
            unknown: gap.map(|g| format!("database gap: {}", g.detail)),
        });
    }
    for (rid, m) in &routers {
        if *rid == root {
            continue;
        }
        for (area, p) in m {
            calc.router_costs.insert((*area, *rid), p.cost);
        }
    }
    calc.gaps = gaps;
    calc.notes = out.notes;
    calc.area_border_router = abr;
    calc
}
