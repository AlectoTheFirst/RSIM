//! The OSPF database builder and the calculation against an oracle on
//! random single-area configs.
//!
//! The oracle reads the configs directly. 2 up, non-passive interfaces of a
//! point-to-point subnet are neighbours. A broadcast subnet with 2 or more
//! up, non-passive interfaces and one of them with a priority above 0 is a
//! transit network. Floyd-Warshall gives the cost between each pair of
//! routers and transit networks. A first hop of the calculating router
//! serves a destination when the cost of the first hop plus the cost from
//! its far end to the destination is the cost of the destination (RFC 2328
//! 16.1.1).
//!
//! The oracle has 2 rules of rsim. A prefix of a stub link of the calculating
//! router is not a route. A network prefix is not a route when the direct
//! link of the calculating router is a shortest path to the network.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use rsim_core::{Prefix, SourceSpan};
use rsim_routing::Platform;
use rsim_routing::ospf::build::{RouterInput, build};
use rsim_routing::ospf::config::{Area, NetworkType, OspfInterface, Process, RouterConfig};
use rsim_routing::ospf::{AreaType, BACKBONE, NextHop, OspfProfile, Version, compute};

const SEED: u64 = 0x0002_0328_0000_0004;
const CASES: u64 = 300;
const INF: u64 = u64::MAX / 4;

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

    fn below(&mut self, n: usize) -> usize {
        (self.step() % n as u64) as usize
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.step() % 100 < percent
    }

    /// A cost in 1 to 20. Half of the costs are 1, 5 or 10.
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

#[derive(Clone, Debug)]
struct Port {
    router: usize,
    name: String,
    address: Ipv4Addr,
    cost: u32,
    passive: bool,
    up: bool,
    priority: u8,
}

impl Port {
    fn active(&self) -> bool {
        self.up && !self.passive
    }
}

#[derive(Clone, Debug)]
struct Segment {
    broadcast: bool,
    prefix: Prefix,
    ports: Vec<Port>,
}

impl Segment {
    /// True for a broadcast segment that is a transit network.
    fn transit(&self) -> bool {
        let active: Vec<&Port> = self.ports.iter().filter(|p| p.active()).collect();
        self.broadcast && active.len() >= 2 && active.iter().any(|p| p.priority > 0)
    }

    /// True for a point-to-point segment with 2 neighbours.
    fn adjacent(&self) -> bool {
        !self.broadcast && self.ports.iter().all(Port::active)
    }
}

struct Case {
    routers: usize,
    loopbacks: Vec<Option<u32>>,
    segments: Vec<Segment>,
}

fn rid(i: usize) -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, i as u8 + 1)
}

fn port(rng: &mut Rng, router: usize, j: usize, address: Ipv4Addr, broadcast: bool) -> Port {
    Port {
        router,
        name: format!("eth{j:02}"),
        address,
        cost: rng.cost(),
        passive: rng.chance(10),
        up: !rng.chance(10),
        priority: if broadcast && rng.chance(20) {
            0
        } else {
            1 + rng.below(3) as u8
        },
    }
}

fn case(rng: &mut Rng) -> Case {
    let n = 2 + rng.below(5);
    let loopbacks = (0..n)
        .map(|_| rng.chance(70).then(|| 1 + rng.below(5) as u32))
        .collect();
    let mut segments = Vec::new();
    let mut ports = vec![0usize; n];
    let p2p = rng.below(n + 3);
    for k in 0..p2p {
        let pair = rng.pick(n, 2);
        let base = 4 * k as u8;
        let mut seg = Segment {
            broadcast: false,
            prefix: Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, base)), 30),
            ports: Vec::new(),
        };
        for (h, r) in pair.into_iter().enumerate() {
            let a = Ipv4Addr::new(192, 0, 2, base + 1 + h as u8);
            seg.ports.push(port(rng, r, ports[r], a, false));
            ports[r] += 1;
        }
        segments.push(seg);
    }
    let lans = rng.below(4);
    for k in 0..lans {
        let members = rng.pick(n, 1 + rng.below(n.min(4)));
        let base = 8 * k as u8;
        let mut seg = Segment {
            broadcast: true,
            prefix: Prefix::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, base)), 29),
            ports: Vec::new(),
        };
        for (h, r) in members.into_iter().enumerate() {
            let a = Ipv4Addr::new(198, 51, 100, base + 1 + h as u8);
            seg.ports.push(port(rng, r, ports[r], a, true));
            ports[r] += 1;
        }
        segments.push(seg);
    }
    Case {
        routers: n,
        loopbacks,
        segments,
    }
}

fn inputs(c: &Case) -> BTreeMap<String, RouterInput> {
    let mut out = BTreeMap::new();
    for r in 0..c.routers {
        let mut interfaces = Vec::new();
        for seg in &c.segments {
            for p in seg.ports.iter().filter(|p| p.router == r) {
                interfaces.push(OspfInterface {
                    name: p.name.clone(),
                    area: BACKBONE,
                    address: Some((IpAddr::V4(p.address), seg.prefix.len())),
                    cost: Some(p.cost),
                    bandwidth_kbps: None,
                    network: if seg.broadcast {
                        NetworkType::Broadcast
                    } else {
                        NetworkType::PointToPoint
                    },
                    passive: p.passive,
                    priority: p.priority,
                    up: p.up,
                    span: SourceSpan::line(&p.name, 1),
                });
            }
        }
        if let Some(cost) = c.loopbacks[r] {
            interfaces.push(OspfInterface {
                name: "lo0".to_string(),
                area: BACKBONE,
                address: Some((IpAddr::V4(rid(r)), 32)),
                cost: Some(cost),
                bandwidth_kbps: None,
                network: NetworkType::Loopback,
                passive: false,
                priority: 1,
                up: true,
                span: SourceSpan::line("lo0", 1),
            });
        }
        let process = Process {
            version: Version::V2,
            vrf: "default".to_string(),
            process: "1".to_string(),
            router_id: Some(rid(r)),
            reference_bandwidth_mbps: None,
            areas: BTreeMap::from([(
                BACKBONE,
                Area {
                    kind: AreaType::Normal,
                    no_summary: false,
                    default_cost: None,
                    span: SourceSpan::line("area", 1),
                },
            )]),
            interfaces,
            redistribute: Vec::new(),
            default_originate: None,
            passive_default: false,
            unhandled: Vec::new(),
            span: SourceSpan::line("process", 1),
        };
        out.insert(
            format!("r{r}"),
            RouterInput::new(
                RouterConfig {
                    processes: vec![process],
                },
                Platform::Iosxe,
            ),
        );
    }
    out
}

/// A first hop of the calculating router: its cost, its far end and the
/// next hop.
struct FirstHop {
    cost: u64,
    far: usize,
    hop: NextHop,
}

/// The routes of `root` by prefix: the cost and the next hops.
fn oracle(c: &Case, root: usize) -> BTreeMap<Prefix, (u32, BTreeSet<NextHop>)> {
    let n = c.routers;
    let nets: Vec<usize> = (0..c.segments.len())
        .filter(|s| c.segments[*s].transit())
        .collect();
    let v = n + nets.len();
    let mut d = vec![vec![INF; v]; v];
    for (i, row) in d.iter_mut().enumerate() {
        row[i] = 0;
    }
    for seg in c.segments.iter().filter(|s| s.adjacent()) {
        let (a, b) = (&seg.ports[0], &seg.ports[1]);
        d[a.router][b.router] = d[a.router][b.router].min(u64::from(a.cost));
        d[b.router][a.router] = d[b.router][a.router].min(u64::from(b.cost));
    }
    for (k, s) in nets.iter().enumerate() {
        for p in c.segments[*s].ports.iter().filter(|p| p.active()) {
            d[p.router][n + k] = u64::from(p.cost);
            d[n + k][p.router] = 0;
        }
    }
    for k in 0..v {
        for i in 0..v {
            for j in 0..v {
                let via = d[i][k].saturating_add(d[k][j]);
                if via < d[i][j] {
                    d[i][j] = via;
                }
            }
        }
    }
    let mut first = Vec::new();
    for seg in c.segments.iter().filter(|s| s.adjacent()) {
        for (own, far) in [(0, 1), (1, 0)] {
            let (o, f) = (&seg.ports[own], &seg.ports[far]);
            if o.router == root {
                first.push(FirstHop {
                    cost: u64::from(o.cost),
                    far: f.router,
                    hop: NextHop {
                        gateway: IpAddr::V4(f.address),
                        interface: Some(o.name.clone()),
                    },
                });
            }
        }
    }
    for s in &nets {
        let seg = &c.segments[*s];
        let Some(own) = seg.ports.iter().find(|p| p.router == root && p.active()) else {
            continue;
        };
        for f in seg.ports.iter().filter(|p| p.active() && p.router != root) {
            first.push(FirstHop {
                cost: u64::from(own.cost),
                far: f.router,
                hop: NextHop {
                    gateway: IpAddr::V4(f.address),
                    interface: Some(own.name.clone()),
                },
            });
        }
    }
    let hops = |x: usize| -> BTreeSet<NextHop> {
        first
            .iter()
            .filter(|h| d[root][x] < INF && h.cost + d[h.far][x] == d[root][x])
            .map(|h| h.hop.clone())
            .collect()
    };
    // The sources of each prefix: the vertex and the cost after it.
    let mut sources: BTreeMap<Prefix, Vec<(usize, u64)>> = BTreeMap::new();
    let mut own_stub: BTreeSet<Prefix> = BTreeSet::new();
    let mut direct: BTreeSet<Prefix> = BTreeSet::new();
    for (r, lb) in c.loopbacks.iter().enumerate() {
        if let Some(cost) = lb {
            let p = Prefix::host(IpAddr::V4(rid(r)));
            sources.entry(p).or_default().push((r, u64::from(*cost)));
            if r == root {
                own_stub.insert(p);
            }
        }
    }
    for (s, seg) in c.segments.iter().enumerate() {
        let transit = seg.transit();
        for p in seg.ports.iter().filter(|p| p.up) {
            if transit && p.active() {
                continue;
            }
            sources
                .entry(seg.prefix)
                .or_default()
                .push((p.router, u64::from(p.cost)));
            if p.router == root {
                own_stub.insert(seg.prefix);
            }
        }
        if transit {
            let k = n + nets.iter().position(|x| *x == s).unwrap();
            sources.entry(seg.prefix).or_default().push((k, 0));
            if let Some(own) = seg.ports.iter().find(|p| p.router == root && p.active())
                && u64::from(own.cost) == d[root][k]
            {
                direct.insert(seg.prefix);
            }
        }
    }
    let mut out = BTreeMap::new();
    for (prefix, list) in sources {
        if own_stub.contains(&prefix) || direct.contains(&prefix) {
            continue;
        }
        let best = list
            .iter()
            .map(|(x, add)| d[root][*x].saturating_add(*add))
            .min()
            .unwrap_or(INF);
        if best >= INF {
            continue;
        }
        let set: BTreeSet<NextHop> = list
            .iter()
            .filter(|(x, add)| d[root][*x].saturating_add(*add) == best)
            .flat_map(|(x, _)| hops(*x))
            .collect();
        out.insert(prefix, (best as u32, set));
    }
    out
}

#[test]
fn the_routes_of_the_built_database_match_the_shortest_paths_of_the_config_graph() {
    let mut rng = Rng(SEED);
    let profile = OspfProfile::of(Platform::Iosxe);
    for i in 0..CASES {
        let c = case(&mut rng);
        let built = build(&inputs(&c));
        for r in 0..c.routers {
            let key = (
                format!("r{r}"),
                "default".to_string(),
                Version::V2,
                "1".to_string(),
            );
            let db = &built.databases[&key];
            let calc = compute(db, rid(r), &profile);
            let got: BTreeMap<Prefix, (u32, BTreeSet<NextHop>)> = calc
                .routes
                .iter()
                .map(|x| {
                    assert_eq!(
                        x.unknown, None,
                        "case {i} router r{r}: {} is unknown",
                        x.prefix
                    );
                    (x.prefix, (x.metric, x.next_hops.iter().cloned().collect()))
                })
                .collect();
            let want = oracle(&c, r);
            assert_eq!(
                got, want,
                "case {i} router r{r}: the routes differ\nsegments: {:#?}\nloopbacks: {:?}",
                c.segments, c.loopbacks
            );
        }
    }
}
