//! The OSPFv2 calculation against an oracle on random single-area databases,
//! and the examples of RFC 2328 sections 2 and 3.
//!
//! The oracle reads the router LSAs and the network LSAs of one area. It
//! finds the cost between each pair of vertices with Floyd-Warshall. A first
//! hop of the calculating router serves a destination when the cost of the
//! first hop plus the cost from its far end to the destination is the cost of
//! the destination.
//!
//! The oracle has 2 rules of rsim. A prefix of a stub link of the calculating
//! router is not a route. A network prefix is not a route when a shortest
//! path to the network is the direct link of the calculating router.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

use rsim_core::{Prefix, SourceSpan};
use rsim_routing::Platform;
use rsim_routing::ospf::{
    BACKBONE, Body, Calculation, Database, Interface, LinkKind, Lsa, LsaType, OspfProfile,
    PathType, RouterLink, Version, compute,
};

const SEED: u64 = 0x0002_0328_0000_0001;
const INTRA_CASES: u64 = 400;
const EXTERNAL_CASES: u64 = 300;
const INF: u64 = u64::MAX;

const MASK_26: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 192);
const MASK_28: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 240);
const MASK_29: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 248);
const MASK_30: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 252);
const MASK_32: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);

/// SplitMix64.
struct Rng(u64);

impl Rng {
    fn step(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number in 0 to `n - 1`.
    fn below(&mut self, n: usize) -> usize {
        (self.step() % n as u64) as usize
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.step() % 100 < percent
    }

    /// A link cost in 1 to 20. Half of the costs are 1, 5 or 10, so equal
    /// costs are frequent.
    fn cost(&mut self) -> u32 {
        if self.chance(50) {
            [1, 5, 10][self.below(3)]
        } else {
            1 + self.below(20) as u32
        }
    }

    /// `k` different numbers in 0 to `n - 1`.
    fn pick(&mut self, n: usize, k: usize) -> Vec<usize> {
        let mut v: Vec<usize> = (0..n).collect();
        for i in 0..k {
            let j = i + self.below(n - i);
            v.swap(i, j);
        }
        v.truncate(k);
        v
    }
}

fn lsa(
    lsa_type: LsaType,
    area: Option<Ipv4Addr>,
    lsid: Ipv4Addr,
    adv: Ipv4Addr,
    body: Body,
) -> Lsa {
    Lsa {
        lsa_type,
        area,
        lsid,
        adv_router: adv,
        seq: Some(0x8000_0001),
        age: Some(1),
        body,
        span: SourceSpan::line("lsdb", 1),
    }
}

fn link(kind: LinkKind, id: Ipv4Addr, data: Ipv4Addr, metric: u32) -> RouterLink {
    RouterLink {
        kind,
        id,
        data: Some(data),
        metric,
        interface_id: None,
        neighbor_interface_id: None,
    }
}

fn v4(p: Prefix) -> Ipv4Addr {
    match p.addr() {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => unreachable!(),
    }
}

fn prefix(id: Ipv4Addr, mask: Ipv4Addr) -> Prefix {
    Prefix::new(IpAddr::V4(id), u32::from(mask).leading_ones() as u8)
}

fn rid(i: usize) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, i as u8 + 1)
}

/// A stub network that more than one router can advertise.
fn shared(t: usize) -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, 64 + 16 * t as u8)
}

/// An external network.
fn external_net(e: usize) -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, 192 + 8 * e as u8)
}

struct Case {
    db: Database,
    root: Ipv4Addr,
    platform: Platform,
    one_way: usize,
}

/// A random single-area database: 2 to 12 routers, a random tree and extra
/// point-to-point links, each pair of routers with at most one, 0 to 4
/// broadcast segments of 2 to 6 routers, a loopback of each router and
/// shared stub networks. A point-to-point link has no link back in 8 % of
/// the cases. A segment has a member that the network LSA does not list, or
/// a member with a stub link in place of its transit link, in 16 % of the
/// cases. With `externals`, 1 to 3 routers advertise external networks.
fn random_case(rng: &mut Rng, externals: bool) -> Case {
    let n = 2 + rng.below(11);
    let area = if rng.chance(50) {
        BACKBONE
    } else {
        Ipv4Addr::new(0, 0, 0, 1)
    };
    let mut links: Vec<Vec<RouterLink>> = vec![Vec::new(); n];
    let mut ifaces: Vec<Vec<(Ipv4Addr, u8)>> = vec![Vec::new(); n];
    let mut db = Database::new(Version::V2, "default", "1");
    let mut one_way = 0;

    let mut pairs = Vec::new();
    for i in 1..n {
        if rng.chance(70) {
            pairs.push((rng.below(i), i));
        }
    }
    for _ in 0..rng.below(n + 1) {
        let v = rng.pick(n, 2);
        pairs.push((v[0], v[1]));
    }
    let mut seen = BTreeSet::new();
    pairs.retain(|&(a, b)| seen.insert((a.min(b), a.max(b))));
    for (k, (a, b)) in pairs.into_iter().enumerate() {
        let base = 4 * k as u8;
        let subnet = Ipv4Addr::new(192, 0, 2, base);
        let a_addr = Ipv4Addr::new(192, 0, 2, base + 1);
        let b_addr = Ipv4Addr::new(192, 0, 2, base + 2);
        let ca = rng.cost();
        let cb = if rng.chance(60) { ca } else { rng.cost() };
        links[a].push(link(LinkKind::PointToPoint, rid(b), a_addr, ca));
        links[a].push(link(LinkKind::Stub, subnet, MASK_30, ca));
        if rng.chance(8) {
            one_way += 1;
        } else {
            links[b].push(link(LinkKind::PointToPoint, rid(a), b_addr, cb));
        }
        links[b].push(link(LinkKind::Stub, subnet, MASK_30, cb));
        ifaces[a].push((a_addr, 30));
        ifaces[b].push((b_addr, 30));
    }

    for s in 0..rng.below(5) {
        let size = 2 + rng.below(n.min(6) - 1);
        let members = rng.pick(n, size);
        let base = 16 * s as u8;
        let subnet = Ipv4Addr::new(198, 51, 100, base);
        let addr = |j: usize| Ipv4Addr::new(198, 51, 100, base + 1 + j as u8);
        let dr = rng.below(members.len());
        let mut attached: Vec<Ipv4Addr> = members.iter().map(|&m| rid(m)).collect();
        let mut stub_member = None;
        let fault = rng.below(100);
        if fault < 8 {
            let j = (dr + 1 + rng.below(members.len() - 1)) % members.len();
            attached.remove(j);
            one_way += 1;
        } else if fault < 16 {
            stub_member = Some(rng.below(members.len()));
            one_way += 1;
        }
        for (j, &m) in members.iter().enumerate() {
            let cost = rng.cost();
            if stub_member == Some(j) {
                links[m].push(link(LinkKind::Stub, subnet, MASK_28, cost));
            } else {
                links[m].push(link(LinkKind::Transit, addr(dr), addr(j), cost));
            }
            ifaces[m].push((addr(j), 28));
        }
        db.insert(lsa(
            LsaType::Network,
            Some(area),
            addr(dr),
            rid(members[dr]),
            Body::Network {
                mask: Some(MASK_28),
                attached,
            },
        ));
    }

    for (i, l) in links.iter_mut().enumerate() {
        let loopback = Ipv4Addr::new(203, 0, 113, i as u8 + 1);
        l.push(link(LinkKind::Stub, loopback, MASK_32, rng.below(2) as u32));
        if rng.chance(40) {
            let k = 1 + rng.below(2);
            for t in rng.pick(8, k) {
                l.push(link(LinkKind::Stub, shared(t), MASK_28, rng.cost()));
            }
        }
    }
    for (i, l) in links.into_iter().enumerate() {
        db.insert(lsa(
            LsaType::Router,
            Some(area),
            rid(i),
            rid(i),
            Body::Router { links: l },
        ));
    }

    if externals {
        let k = 1 + rng.below(n.min(3));
        for a in rng.pick(n, k) {
            let count = 1 + rng.below(4);
            let mut nets: Vec<Prefix> = rng
                .pick(8, count)
                .into_iter()
                .map(|e| prefix(external_net(e), MASK_29))
                .collect();
            if rng.chance(15) {
                nets.push(prefix(shared(rng.below(8)), MASK_28));
            }
            for p in nets {
                let metric = if rng.chance(50) {
                    [1, 10, 20][rng.below(3)]
                } else {
                    1 + rng.below(30) as u32
                };
                let metric_type = Some(1 + rng.below(2) as u8);
                let forwarding = rng.chance(50).then_some(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                db.insert(lsa(
                    LsaType::External,
                    None,
                    v4(p),
                    rid(a),
                    Body::External {
                        prefix: p,
                        metric,
                        metric_type,
                        forwarding,
                    },
                ));
            }
        }
    }

    let root = rng.below(n);
    db.router_id = Some(rid(root));
    for (k, (addr, len)) in ifaces[root].iter().enumerate() {
        db.interfaces.push(Interface {
            name: format!("eth{k}"),
            area: Some(area),
            address: Some((IpAddr::V4(*addr), Some(*len))),
            interface_id: None,
            cost: None,
            span: SourceSpan::line("interfaces", k as u32 + 1),
        });
    }
    let platform = if rng.chance(50) {
        Platform::Nxos
    } else {
        Platform::Iosxe
    };
    Case {
        db,
        root: rid(root),
        platform,
        one_way,
    }
}

/// The next hops of a route: the gateway and the interface.
type Hops = BTreeSet<(IpAddr, Option<String>)>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Answer {
    path: PathType,
    metric: u32,
    /// The internal distance of a type 2 external route.
    forward: Option<u32>,
    hops: Hops,
}

type Table = BTreeMap<Prefix, Answer>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Vx {
    Router(Ipv4Addr),
    Net(Ipv4Addr),
}

/// An edge of the graph with the link data of the router at each end. A
/// network has no link data.
struct Edge {
    from: usize,
    to: usize,
    cost: u64,
    near: Option<Ipv4Addr>,
    far: Option<Ipv4Addr>,
}

/// The graph of one area and the cost between each pair of vertices.
struct Graph<'a> {
    routers: BTreeMap<Ipv4Addr, &'a [RouterLink]>,
    networks: BTreeMap<Ipv4Addr, (Ipv4Addr, &'a [Ipv4Addr])>,
    vertices: Vec<Vx>,
    edges: Vec<Edge>,
    /// The cost from vertex `i` to vertex `j` at `i * n + j`.
    dist: Vec<u64>,
}

impl<'a> Graph<'a> {
    fn new(db: &'a Database, area: Ipv4Addr) -> Graph<'a> {
        let mut routers = BTreeMap::new();
        let mut networks = BTreeMap::new();
        for l in db.lsas.values().filter(|l| l.area == Some(area)) {
            match &l.body {
                Body::Router { links } => {
                    routers.insert(l.adv_router, links.as_slice());
                }
                Body::Network { mask, attached } => {
                    networks.insert(l.lsid, (mask.unwrap(), attached.as_slice()));
                }
                _ => {}
            }
        }
        let mut vertices: Vec<Vx> = routers.keys().map(|r| Vx::Router(*r)).collect();
        vertices.extend(networks.keys().map(|d| Vx::Net(*d)));
        let index = |v: Vx| vertices.iter().position(|x| *x == v).unwrap();
        let back = |router: Ipv4Addr, kind: LinkKind, id: Ipv4Addr| {
            routers
                .get(&router)
                .and_then(|ls| ls.iter().find(|b| b.kind == kind && b.id == id))
        };
        let mut edges = Vec::new();
        for (&r, links) in &routers {
            for l in links.iter() {
                match l.kind {
                    LinkKind::PointToPoint => {
                        if let Some(b) = back(l.id, LinkKind::PointToPoint, r) {
                            edges.push(Edge {
                                from: index(Vx::Router(r)),
                                to: index(Vx::Router(l.id)),
                                cost: u64::from(l.metric),
                                near: l.data,
                                far: b.data,
                            });
                        }
                    }
                    LinkKind::Transit => {
                        if networks.get(&l.id).is_some_and(|(_, att)| att.contains(&r)) {
                            edges.push(Edge {
                                from: index(Vx::Router(r)),
                                to: index(Vx::Net(l.id)),
                                cost: u64::from(l.metric),
                                near: l.data,
                                far: None,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
        for (&d, (_, attached)) in &networks {
            for &x in attached.iter() {
                if let Some(b) = back(x, LinkKind::Transit, d) {
                    edges.push(Edge {
                        from: index(Vx::Net(d)),
                        to: index(Vx::Router(x)),
                        cost: 0,
                        near: None,
                        far: b.data,
                    });
                }
            }
        }
        let n = vertices.len();
        let mut dist = vec![INF; n * n];
        for i in 0..n {
            dist[i * n + i] = 0;
        }
        for e in &edges {
            let d = &mut dist[e.from * n + e.to];
            *d = (*d).min(e.cost);
        }
        for k in 0..n {
            for i in 0..n {
                for j in 0..n {
                    let via = dist[i * n + k].saturating_add(dist[k * n + j]);
                    if via < dist[i * n + j] {
                        dist[i * n + j] = via;
                    }
                }
            }
        }
        Graph {
            routers,
            networks,
            vertices,
            edges,
            dist,
        }
    }

    fn d(&self, i: usize, j: usize) -> u64 {
        self.dist[i * self.vertices.len() + j]
    }

    fn index(&self, v: Vx) -> Option<usize> {
        self.vertices.iter().position(|x| *x == v)
    }

    /// The next hops from `s` to `t` and true when a shortest path is the
    /// direct link of `s` to the network `t` (RFC 2328 16.1.1). The gateway
    /// over a point-to-point link is the link data of the link back. The
    /// gateway over a network of `s` is the link data of the next router on
    /// the network.
    fn first_hops(
        &self,
        s: usize,
        t: usize,
        iface: &dyn Fn(Option<Ipv4Addr>) -> Option<String>,
    ) -> (Hops, bool) {
        let total = self.d(s, t);
        let mut hops = Hops::new();
        let mut direct = false;
        for e in self.edges.iter().filter(|e| e.from == s) {
            if e.cost.saturating_add(self.d(e.to, t)) != total {
                continue;
            }
            match self.vertices[e.to] {
                Vx::Router(_) => {
                    if let Some(far) = e.far {
                        hops.insert((IpAddr::V4(far), iface(e.near)));
                    }
                }
                Vx::Net(_) if e.to == t => direct = true,
                Vx::Net(_) => {
                    for f in self.edges.iter().filter(|f| f.from == e.to && f.to != s) {
                        if e.cost.saturating_add(self.d(f.to, t)) == total
                            && let Some(far) = f.far
                        {
                            hops.insert((IpAddr::V4(far), iface(e.near)));
                        }
                    }
                }
            }
        }
        (hops, direct)
    }
}

/// The facts of one oracle run that show that a case is not trivial.
#[derive(Default)]
struct Features {
    ecmp_routes: usize,
    root_on_segment: usize,
    direct_and_indirect: usize,
    type_2_routes: usize,
    ecmp_externals: usize,
}

/// The routes of `root` over a single-area database.
fn oracle(db: &Database, root: Ipv4Addr, features: &mut Features) -> Table {
    let area = db
        .lsas
        .values()
        .find(|l| l.lsa_type == LsaType::Router && l.adv_router == root)
        .and_then(|l| l.area)
        .unwrap();
    let g = Graph::new(db, area);
    let iface = |a: Option<Ipv4Addr>| {
        let a = IpAddr::V4(a?);
        db.interfaces
            .iter()
            .find(|i| i.address.is_some_and(|(x, _)| x == a))
            .map(|i| i.name.clone())
    };
    let s = g.index(Vx::Router(root)).unwrap();
    if g.edges
        .iter()
        .any(|e| e.from == s && matches!(g.vertices[e.to], Vx::Net(_)))
    {
        features.root_on_segment += 1;
    }

    // The candidates of each prefix: the cost, the next hops and true for a
    // subnet of the root.
    let mut candidates: BTreeMap<Prefix, Vec<(u64, Hops, bool)>> = BTreeMap::new();
    for (t, vx) in g.vertices.iter().enumerate() {
        let total = g.d(s, t);
        if total == INF {
            continue;
        }
        let (hops, direct) = if t == s {
            (Hops::new(), true)
        } else {
            g.first_hops(s, t, &iface)
        };
        match vx {
            Vx::Router(r) => {
                for l in g.routers[r].iter().filter(|l| l.kind == LinkKind::Stub) {
                    candidates
                        .entry(prefix(l.id, l.data.unwrap()))
                        .or_default()
                        .push((total + u64::from(l.metric), hops.clone(), t == s));
                }
            }
            Vx::Net(d) => {
                if direct && !hops.is_empty() {
                    features.direct_and_indirect += 1;
                }
                candidates
                    .entry(prefix(*d, g.networks[d].0))
                    .or_default()
                    .push((total, hops, direct));
            }
        }
    }
    let mut table = Table::new();
    for (p, list) in &candidates {
        if list.iter().any(|c| c.2) {
            continue;
        }
        let best = list.iter().map(|c| c.0).min().unwrap();
        let hops: Hops = list
            .iter()
            .filter(|c| c.0 == best)
            .flat_map(|c| c.1.iter().cloned())
            .collect();
        if hops.len() > 1 {
            features.ecmp_routes += 1;
        }
        table.insert(
            *p,
            Answer {
                path: PathType::IntraArea,
                metric: best as u32,
                forward: None,
                hops,
            },
        );
    }

    // RFC 2328 16.4 with no forwarding address. A type 1 path ranks by the
    // sum of the distance and the metric. A type 2 path ranks after each
    // type 1 path, by the metric and then by the distance.
    let mut externals: BTreeMap<Prefix, Vec<((u8, u64, u64), Answer)>> = BTreeMap::new();
    for l in db.lsas.values() {
        let Body::External {
            prefix: p,
            metric,
            metric_type,
            ..
        } = &l.body
        else {
            continue;
        };
        if l.adv_router == root || candidates.contains_key(p) {
            continue;
        }
        let Some(t) = g.index(Vx::Router(l.adv_router)) else {
            continue;
        };
        let distance = g.d(s, t);
        if distance == INF {
            continue;
        }
        let hops = g.first_hops(s, t, &iface).0;
        let m = u64::from(*metric);
        let (rank, answer) = if *metric_type == Some(1) {
            (
                (1, distance + m, 0),
                Answer {
                    path: PathType::External1,
                    metric: (distance + m) as u32,
                    forward: None,
                    hops,
                },
            )
        } else {
            (
                (2, m, distance),
                Answer {
                    path: PathType::External2,
                    metric: *metric,
                    forward: Some(distance as u32),
                    hops,
                },
            )
        };
        externals.entry(*p).or_default().push((rank, answer));
    }
    for (p, list) in externals {
        let best = list.iter().map(|c| c.0).min().unwrap();
        let mut chosen = list.into_iter().filter(|c| c.0 == best).map(|c| c.1);
        let mut answer = chosen.next().unwrap();
        for other in chosen {
            answer.hops.extend(other.hops);
        }
        if answer.path == PathType::External2 {
            features.type_2_routes += 1;
        }
        if answer.hops.len() > 1 {
            features.ecmp_externals += 1;
        }
        table.insert(p, answer);
    }
    table
}

/// The routes of a calculation. The internal distance is kept only for a
/// type 2 external route.
fn answers(c: &Calculation) -> Table {
    c.routes
        .iter()
        .map(|r| {
            (
                r.prefix,
                Answer {
                    path: r.path_type,
                    metric: r.metric,
                    forward: if r.path_type == PathType::External2 {
                        r.forward_metric
                    } else {
                        None
                    },
                    hops: r
                        .next_hops
                        .iter()
                        .map(|h| (h.gateway, h.interface.clone()))
                        .collect(),
                },
            )
        })
        .collect()
}

/// The database as one line for each LSA and each interface.
fn describe(case: &Case) -> String {
    let mut out = format!("root {} platform {:?}\n", case.root, case.platform);
    for l in case.db.lsas.values() {
        match &l.body {
            Body::Router { links } => {
                let _ = write!(out, "router {} area {:?}:", l.adv_router, l.area);
                for k in links {
                    let _ = write!(
                        out,
                        " [{} {} {:?} {}]",
                        k.kind.name(),
                        k.id,
                        k.data,
                        k.metric
                    );
                }
                out.push('\n');
            }
            Body::Network { mask, attached } => {
                let _ = writeln!(
                    out,
                    "network {} from {} mask {:?} attached {:?}",
                    l.lsid, l.adv_router, mask, attached
                );
            }
            Body::External {
                prefix,
                metric,
                metric_type,
                forwarding,
            } => {
                let _ = writeln!(
                    out,
                    "external {prefix} from {} metric {metric} type {metric_type:?} forwarding {forwarding:?}",
                    l.adv_router
                );
            }
            other => {
                let _ = writeln!(out, "{other:?}");
            }
        }
    }
    for i in &case.db.interfaces {
        let _ = writeln!(out, "interface {} {:?}", i.name, i.address);
    }
    out
}

fn difference(expected: &Table, got: &Table) -> String {
    let mut out = String::new();
    let keys: BTreeSet<&Prefix> = expected.keys().chain(got.keys()).collect();
    for p in keys {
        let (e, g) = (expected.get(p), got.get(p));
        if e != g {
            let _ = writeln!(out, "{p}\n  oracle:  {e:?}\n  compute: {g:?}");
        }
    }
    out
}

/// Runs the cases and fails with the smallest case that gives another
/// answer than the oracle.
fn run_cases(seed: u64, cases: u64, externals: bool) -> Features {
    let mut features = Features::default();
    let mut one_way = 0;
    let mut sizes = BTreeSet::new();
    let mut failures: Vec<(usize, u64, String)> = Vec::new();
    for i in 0..cases {
        let mut rng = Rng(seed.wrapping_add(i));
        let case = random_case(&mut rng, externals);
        one_way += case.one_way;
        let routers = case
            .db
            .lsas
            .values()
            .filter(|l| l.lsa_type == LsaType::Router)
            .count();
        sizes.insert(routers);
        let expected = oracle(&case.db, case.root, &mut features);
        let calc = compute(&case.db, case.root, &OspfProfile::of(case.platform));
        let got = answers(&calc);
        let problem = if expected != got {
            difference(&expected, &got)
        } else if !externals
            && (!calc.gaps.is_empty() || calc.routes.iter().any(|r| r.unknown.is_some()))
        {
            format!("gaps {:?}", calc.gaps)
        } else {
            String::new()
        };
        if !problem.is_empty() {
            failures.push((
                case.db.lsas.len(),
                i,
                format!("{}{problem}", describe(&case)),
            ));
        }
    }
    failures.sort();
    if let Some((_, i, text)) = failures.first() {
        panic!(
            "{} of {cases} cases give another answer than the oracle; case {i}:\n{text}",
            failures.len()
        );
    }
    assert!(one_way > 0);
    assert_eq!(sizes.first(), Some(&2));
    assert_eq!(sizes.last(), Some(&12));
    features
}

#[test]
fn random_single_area_databases_give_the_intra_area_routes_of_the_oracle() {
    let f = run_cases(SEED, INTRA_CASES, false);
    assert!(f.ecmp_routes > 0);
    assert!(f.root_on_segment > 0);
    assert!(f.direct_and_indirect > 0);
}

#[test]
fn random_external_lsas_give_the_external_routes_of_the_oracle() {
    let f = run_cases(SEED ^ 0xE87E_4AA1, EXTERNAL_CASES, true);
    assert!(f.type_2_routes > 0);
    assert!(f.ecmp_externals > 0);
}

// The examples of RFC 2328. The RFC gives names and no addresses. The tests
// use these documentation addresses:
//
// - router RTn: 192.0.2.n
// - N1 198.51.100.0/28, N2 .16/28, N3 .32/28 with RTn at .32+n, N4 .48/28
// - N6 198.51.100.64/28 with RT7 .65, RT8 .66 and RT10 .67, N7 .80/28, N8
//   .96/28 with RT10 .97 and RT11 .98
// - N9 198.51.100.192/28 with RT9 .193, RT11 .194 and RT12 .195, N10
//   .208/28, N11 .224/28, H1 .240/32; the range of area 3 is .192/26
// - the link of RT6 and RT10: Ia 203.0.113.1 on RT6 and Ib 203.0.113.2 on
//   RT10, each a /32 stub link of the router at the far end
// - the other point-to-point links: RT3 203.0.113.5 and RT6 .6, RT4 .9 and
//   RT5 .10, RT5 .13 and RT6 .14, RT5 .17 and RT7 .18. The RFC has these
//   links unnumbered. They have no stub links.
// - N12 203.0.113.128/28, N13 .144/28, N14 .160/28, N15 .176/28

fn rt(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, n)
}

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn p2p(n: u8, own: &str, metric: u32) -> RouterLink {
    link(LinkKind::PointToPoint, rt(n), ip(own), metric)
}

fn transit(dr: &str, own: &str, metric: u32) -> RouterLink {
    link(LinkKind::Transit, ip(dr), ip(own), metric)
}

fn stub(net: &str, mask: Ipv4Addr, metric: u32) -> RouterLink {
    link(LinkKind::Stub, ip(net), mask, metric)
}

fn router_lsa(n: u8, area: Ipv4Addr, links: Vec<RouterLink>) -> Lsa {
    lsa(
        LsaType::Router,
        Some(area),
        rt(n),
        rt(n),
        Body::Router { links },
    )
}

fn network_lsa(dr: &str, adv: u8, area: Ipv4Addr, attached: &[u8]) -> Lsa {
    lsa(
        LsaType::Network,
        Some(area),
        ip(dr),
        rt(adv),
        Body::Network {
            mask: Some(MASK_28),
            attached: attached.iter().map(|n| rt(*n)).collect(),
        },
    )
}

fn external_lsa(net: &str, adv: u8, metric: u32, metric_type: u8) -> Lsa {
    lsa(
        LsaType::External,
        None,
        ip(net),
        rt(adv),
        Body::External {
            prefix: prefix(ip(net), MASK_28),
            metric,
            metric_type: Some(metric_type),
            forwarding: None,
        },
    )
}

fn database(lsas: Vec<Lsa>) -> Database {
    let mut db = Database::new(Version::V2, "default", "1");
    for l in lsas {
        db.insert(l);
    }
    db
}

/// Each route as its prefix, path type, metric and gateways.
fn rows(c: &Calculation) -> Vec<(String, &'static str, u32, Vec<String>)> {
    c.routes
        .iter()
        .map(|r| {
            (
                r.prefix.to_string(),
                r.path_type.name(),
                r.metric,
                r.next_hops.iter().map(|h| h.gateway.to_string()).collect(),
            )
        })
        .collect()
}

fn row(
    prefix: &str,
    path: &'static str,
    metric: u32,
    hops: &[&str],
) -> (String, &'static str, u32, Vec<String>) {
    (
        prefix.to_string(),
        path,
        metric,
        hops.iter().map(|h| h.to_string()).collect(),
    )
}

/// Figure 2 of RFC 2328 with the AS-external LSAs of RT5 and RT7 of section
/// 2.3, with the metric type `external`.
fn figure_2(external: u8) -> Database {
    let a = BACKBONE;
    database(vec![
        router_lsa(
            1,
            a,
            vec![
                transit("198.51.100.33", "198.51.100.33", 1),
                stub("198.51.100.0", MASK_28, 3),
            ],
        ),
        router_lsa(
            2,
            a,
            vec![
                transit("198.51.100.33", "198.51.100.34", 1),
                stub("198.51.100.16", MASK_28, 3),
            ],
        ),
        router_lsa(
            3,
            a,
            vec![
                transit("198.51.100.33", "198.51.100.35", 1),
                p2p(6, "203.0.113.5", 8),
                stub("198.51.100.48", MASK_28, 2),
            ],
        ),
        router_lsa(
            4,
            a,
            vec![
                transit("198.51.100.33", "198.51.100.36", 1),
                p2p(5, "203.0.113.9", 8),
            ],
        ),
        router_lsa(
            5,
            a,
            vec![
                p2p(4, "203.0.113.10", 8),
                p2p(6, "203.0.113.13", 7),
                p2p(7, "203.0.113.17", 6),
            ],
        ),
        router_lsa(
            6,
            a,
            vec![
                p2p(3, "203.0.113.6", 6),
                p2p(5, "203.0.113.14", 6),
                p2p(10, "203.0.113.1", 7),
                stub("203.0.113.2", MASK_32, 7),
            ],
        ),
        router_lsa(
            7,
            a,
            vec![
                p2p(5, "203.0.113.18", 6),
                transit("198.51.100.67", "198.51.100.65", 1),
            ],
        ),
        router_lsa(
            8,
            a,
            vec![
                transit("198.51.100.67", "198.51.100.66", 1),
                stub("198.51.100.80", MASK_28, 4),
            ],
        ),
        router_lsa(
            9,
            a,
            vec![
                transit("198.51.100.195", "198.51.100.193", 1),
                stub("198.51.100.224", MASK_28, 3),
            ],
        ),
        router_lsa(
            10,
            a,
            vec![
                p2p(6, "203.0.113.2", 5),
                transit("198.51.100.67", "198.51.100.67", 1),
                transit("198.51.100.98", "198.51.100.97", 3),
                stub("203.0.113.1", MASK_32, 5),
            ],
        ),
        router_lsa(
            11,
            a,
            vec![
                transit("198.51.100.98", "198.51.100.98", 2),
                transit("198.51.100.195", "198.51.100.194", 1),
            ],
        ),
        router_lsa(
            12,
            a,
            vec![
                transit("198.51.100.195", "198.51.100.195", 1),
                stub("198.51.100.208", MASK_28, 2),
                stub("198.51.100.240", MASK_32, 10),
            ],
        ),
        network_lsa("198.51.100.33", 1, a, &[1, 2, 3, 4]),
        network_lsa("198.51.100.67", 10, a, &[7, 8, 10]),
        network_lsa("198.51.100.98", 11, a, &[10, 11]),
        network_lsa("198.51.100.195", 12, a, &[9, 11, 12]),
        external_lsa("203.0.113.128", 5, 8, external),
        external_lsa("203.0.113.144", 5, 8, external),
        external_lsa("203.0.113.160", 5, 8, external),
        external_lsa("203.0.113.128", 7, 2, external),
        external_lsa("203.0.113.176", 7, 9, external),
    ])
}

/// Table 2 and Table 3 of RFC 2328: the routing table of RT6. Ib is a stub
/// link of RT6 and is not a route.
#[test]
fn rfc_2328_figure_2_gives_the_routing_table_of_rt6() {
    let c = compute(&figure_2(1), rt(6), &OspfProfile::of(Platform::Nxos));
    let rt3 = "203.0.113.5";
    let rt5 = "203.0.113.13";
    let rt10 = "203.0.113.2";
    assert!(c.gaps.is_empty(), "{:?}", c.gaps);
    assert_eq!(
        rows(&c),
        [
            row("198.51.100.0/28", "intra-area", 10, &[rt3]),
            row("198.51.100.16/28", "intra-area", 10, &[rt3]),
            row("198.51.100.32/28", "intra-area", 7, &[rt3]),
            row("198.51.100.48/28", "intra-area", 8, &[rt3]),
            row("198.51.100.64/28", "intra-area", 8, &[rt10]),
            row("198.51.100.80/28", "intra-area", 12, &[rt10]),
            row("198.51.100.96/28", "intra-area", 10, &[rt10]),
            row("198.51.100.192/28", "intra-area", 11, &[rt10]),
            row("198.51.100.208/28", "intra-area", 13, &[rt10]),
            row("198.51.100.224/28", "intra-area", 14, &[rt10]),
            row("198.51.100.240/32", "intra-area", 21, &[rt10]),
            row("203.0.113.1/32", "intra-area", 12, &[rt10]),
            row("203.0.113.128/28", "external-1", 10, &[rt10]),
            row("203.0.113.144/28", "external-1", 14, &[rt5]),
            row("203.0.113.160/28", "external-1", 14, &[rt5]),
            row("203.0.113.176/28", "external-1", 17, &[rt10]),
        ]
    );
    assert_eq!(c.router_costs.get(&(BACKBONE, rt(5))), Some(&6));
    assert_eq!(c.router_costs.get(&(BACKBONE, rt(7))), Some(&8));
}

/// RFC 2328 section 2.3: with type 2 metrics, RT6 sends the traffic for
/// N12 to RT7, because 2 is less than 8.
#[test]
fn rfc_2328_figure_2_with_type_2_externals_sends_n12_to_rt7() {
    let c = compute(&figure_2(2), rt(6), &OspfProfile::of(Platform::Nxos));
    let r = c.route(prefix(ip("203.0.113.128"), MASK_28)).unwrap();
    assert_eq!(r.path_type, PathType::External2);
    assert_eq!(r.metric, 2);
    assert_eq!(r.forward_metric, Some(8));
    assert_eq!(r.advertising_router, Some(rt(7)));
    let hops: Vec<String> = r.next_hops.iter().map(|h| h.gateway.to_string()).collect();
    assert_eq!(hops, ["203.0.113.2"]);
}

/// Figure 8 of RFC 2328: the backbone, with the virtual link of RT10 and
/// RT11 through area 2. The summary LSAs are left out.
fn figure_8() -> Database {
    let a = BACKBONE;
    let virtual_link =
        |n: u8, own: &str, metric: u32| link(LinkKind::Virtual, rt(n), ip(own), metric);
    database(vec![
        router_lsa(3, a, vec![p2p(6, "203.0.113.5", 8)]),
        router_lsa(4, a, vec![p2p(5, "203.0.113.9", 8)]),
        router_lsa(
            5,
            a,
            vec![
                p2p(4, "203.0.113.10", 8),
                p2p(6, "203.0.113.13", 7),
                p2p(7, "203.0.113.17", 6),
            ],
        ),
        router_lsa(
            6,
            a,
            vec![
                p2p(3, "203.0.113.6", 6),
                p2p(5, "203.0.113.14", 6),
                p2p(10, "203.0.113.1", 7),
                stub("203.0.113.2", MASK_32, 7),
            ],
        ),
        router_lsa(7, a, vec![p2p(5, "203.0.113.18", 6)]),
        router_lsa(
            10,
            a,
            vec![
                p2p(6, "203.0.113.2", 5),
                virtual_link(11, "198.51.100.97", 3),
                stub("203.0.113.1", MASK_32, 5),
            ],
        ),
        router_lsa(11, a, vec![virtual_link(10, "198.51.100.98", 2)]),
    ])
}

/// Table 5 of RFC 2328: the backbone distances of RT3 and RT4.
#[test]
fn rfc_2328_figure_8_gives_the_backbone_distances_of_rt3_and_rt4() {
    let db = figure_8();
    let profile = OspfProfile::of(Platform::Nxos);
    for (root, gateway, costs, ia, ib) in [
        (
            3,
            "203.0.113.6",
            [(4, 22), (7, 20), (10, 15), (11, 18), (5, 14)],
            20,
            15,
        ),
        (
            4,
            "203.0.113.10",
            [(3, 21), (7, 14), (10, 22), (11, 25), (5, 8)],
            27,
            22,
        ),
    ] {
        let c = compute(&db, rt(root), &profile);
        assert!(c.gaps.is_empty(), "RT{root}: {:?}", c.gaps);
        for (to, cost) in costs {
            assert_eq!(
                c.router_costs.get(&(BACKBONE, rt(to))),
                Some(&cost),
                "RT{root} to RT{to}"
            );
        }
        assert_eq!(
            rows(&c),
            [
                row("203.0.113.1/32", "intra-area", ia, &[gateway]),
                row("203.0.113.2/32", "intra-area", ib, &[gateway]),
            ],
            "RT{root}"
        );
    }
}

/// Figure 7 of RFC 2328: area 1 with the summary LSAs and the ASBR-summary
/// LSAs of RT3 and RT4 from Table 6.
fn figure_7() -> Database {
    let a = Ipv4Addr::new(0, 0, 0, 1);
    let mut lsas = vec![
        router_lsa(
            1,
            a,
            vec![
                transit("198.51.100.33", "198.51.100.33", 1),
                stub("198.51.100.0", MASK_28, 3),
            ],
        ),
        router_lsa(
            2,
            a,
            vec![
                transit("198.51.100.33", "198.51.100.34", 1),
                stub("198.51.100.16", MASK_28, 3),
            ],
        ),
        router_lsa(
            3,
            a,
            vec![
                transit("198.51.100.33", "198.51.100.35", 1),
                stub("198.51.100.48", MASK_28, 2),
            ],
        ),
        router_lsa(4, a, vec![transit("198.51.100.33", "198.51.100.36", 1)]),
        network_lsa("198.51.100.33", 1, a, &[1, 2, 3, 4]),
    ];
    let summaries = [
        ("203.0.113.0", MASK_30, 20, 27),
        ("198.51.100.64", MASK_28, 16, 15),
        ("198.51.100.80", MASK_28, 20, 19),
        ("198.51.100.96", MASK_28, 18, 18),
        ("198.51.100.192", MASK_26, 29, 36),
    ];
    for (net, mask, by_rt3, by_rt4) in summaries {
        for (adv, metric) in [(3, by_rt3), (4, by_rt4)] {
            lsas.push(lsa(
                LsaType::Summary,
                Some(a),
                ip(net),
                rt(adv),
                Body::Summary {
                    prefix: prefix(ip(net), mask),
                    metric,
                },
            ));
        }
    }
    for (asbr, by_rt3, by_rt4) in [(5, 14, 8), (7, 20, 14)] {
        for (adv, metric) in [(3, by_rt3), (4, by_rt4)] {
            lsas.push(lsa(
                LsaType::AsbrSummary,
                Some(a),
                rt(asbr),
                rt(adv),
                Body::AsbrSummary {
                    router: rt(asbr),
                    metric,
                },
            ));
        }
    }
    database(lsas)
}

/// RFC 2328 section 3: RT1 uses RT4 for N6, RT3 for N10, and both for N8.
#[test]
fn rfc_2328_figure_7_gives_the_border_router_choices_of_rt1() {
    let a = Ipv4Addr::new(0, 0, 0, 1);
    let c = compute(&figure_7(), rt(1), &OspfProfile::of(Platform::Nxos));
    let rt3 = "198.51.100.35";
    let rt4 = "198.51.100.36";
    assert!(c.gaps.is_empty(), "{:?}", c.gaps);
    assert_eq!(
        rows(&c),
        [
            row("198.51.100.16/28", "intra-area", 4, &["198.51.100.34"]),
            row("198.51.100.48/28", "intra-area", 3, &[rt3]),
            row("198.51.100.64/28", "inter-area", 16, &[rt4]),
            row("198.51.100.80/28", "inter-area", 20, &[rt4]),
            row("198.51.100.96/28", "inter-area", 19, &[rt3, rt4]),
            row("198.51.100.192/26", "inter-area", 30, &[rt3]),
            row("203.0.113.0/30", "inter-area", 21, &[rt3]),
        ]
    );
    assert_eq!(c.router_costs.get(&(a, rt(5))), Some(&9));
    assert_eq!(c.router_costs.get(&(a, rt(7))), Some(&15));
}
