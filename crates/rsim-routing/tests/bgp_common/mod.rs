//! Builders and a fixed-seed generator for the BGP tests.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};

use rsim_core::Prefix;
use rsim_routing::bgp::{AsPath, Asn, BgpPath, Peer, RouteKey, SessionKind};

pub fn pfx(s: &str) -> Prefix {
    s.parse().unwrap()
}

pub fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

pub fn v4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

pub fn key(s: &str) -> RouteKey {
    RouteKey::unicast(pfx(s))
}

/// A path from the peer `addr` of `kind`, with the router ID `addr` and
/// the next hop `addr`.
pub fn path(kind: SessionKind, addr: &str, as_path: &[u32]) -> BgpPath {
    let asn = as_path.first().copied().unwrap_or(65000);
    let peer = Peer {
        address: Some(ip(addr)),
        router_id: v4(addr),
        asn: Asn(asn),
        kind,
    };
    BgpPath::new(peer, Some(ip(addr)), AsPath::sequence(as_path))
}

pub fn ebgp(addr: &str, as_path: &[u32]) -> BgpPath {
    path(SessionKind::Ebgp, addr, as_path)
}

pub fn ibgp(addr: &str, as_path: &[u32]) -> BgpPath {
    path(SessionKind::Ibgp, addr, as_path)
}

/// A xorshift64 generator with a fixed seed.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// A number in `0..n`.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize]
    }
}

/// Each permutation of `0..n`, in lexicographic order.
pub fn permutations(n: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut cur: Vec<usize> = (0..n).collect();
    loop {
        out.push(cur.clone());
        let Some(i) = (0..n.saturating_sub(1))
            .rev()
            .find(|&i| cur[i] < cur[i + 1])
        else {
            return out;
        };
        let j = (i + 1..n).rev().find(|&j| cur[j] > cur[i]).unwrap();
        cur.swap(i, j);
        cur[i + 1..].reverse();
    }
}

/// An IGP view of fixed costs. A next hop with no cost resolves with the
/// cost 0, and a next hop in `unknown` has an unknown resolution.
#[derive(Clone, Debug, Default)]
pub struct Igp {
    pub costs: std::collections::BTreeMap<(String, IpAddr), u32>,
    pub unresolved: std::collections::BTreeSet<(String, IpAddr)>,
    pub unknown: std::collections::BTreeSet<(String, IpAddr)>,
    pub routes: std::collections::BTreeSet<(String, Prefix)>,
}

impl rsim_routing::bgp::IgpView for Igp {
    fn resolve(&self, device: &str, _vrf: &str, nh: IpAddr) -> rsim_routing::bgp::Resolution {
        use rsim_routing::bgp::Resolution;
        let k = (device.to_string(), nh);
        if self.unknown.contains(&k) {
            return Resolution::Unknown("not in the test view".to_string());
        }
        if self.unresolved.contains(&k) {
            return Resolution::Unresolved;
        }
        Resolution::Resolved {
            cost: self.costs.get(&k).copied().unwrap_or(0),
        }
    }

    fn has_route(&self, device: &str, _vrf: &str, prefix: Prefix) -> Option<bool> {
        Some(self.routes.contains(&(device.to_string(), prefix)))
    }
}

/// A neighbour with IPv4 and IPv6 unicast activated, the local address
/// `local` and each community sent.
pub fn neighbor(addr: &str, remote_as: u32, local: &str) -> rsim_routing::bgp::Neighbor {
    use rsim_routing::bgp::{Family, Neighbor};
    let mut n = Neighbor::new(ip(addr), Asn(remote_as));
    n.local_address = Some(ip(local));
    n.activated = [Family::Ipv4Unicast, Family::Ipv6Unicast].into();
    n.send_community = true;
    n.send_community_extended = true;
    n
}

/// A test twin: processes in the VRF `default`, sessions, seeds and an IGP
/// view.
#[derive(Clone, Debug, Default)]
pub struct Lab {
    pub input: rsim_routing::bgp::BgpInput,
    pub igp: Igp,
}

impl Lab {
    pub fn router(
        &mut self,
        device: &str,
        platform: rsim_routing::Platform,
        asn: u32,
        router_id: &str,
    ) -> &mut rsim_routing::bgp::BgpProcess {
        self.input
            .processes
            .push(rsim_routing::bgp::BgpProcess::new(
                device,
                "default",
                Some(platform),
                Asn(asn),
                v4(router_id),
            ));
        self.input.processes.last_mut().unwrap()
    }

    pub fn proc(&mut self, device: &str) -> &mut rsim_routing::bgp::BgpProcess {
        self.input
            .processes
            .iter_mut()
            .find(|p| p.device == device)
            .unwrap()
    }

    pub fn get(&self, device: &str) -> &rsim_routing::bgp::BgpProcess {
        self.input
            .processes
            .iter()
            .find(|p| p.device == device)
            .unwrap()
    }

    /// A session between `a` with the address `a_addr` and `b` with the
    /// address `b_addr`. Each neighbour has the AS of the other process.
    pub fn peer(&mut self, a: &str, a_addr: &str, b: &str, b_addr: &str) {
        use rsim_routing::bgp::{Session, SessionEnd};
        let (asn_a, asn_b) = (self.get(a).asn.0, self.get(b).asn.0);
        self.proc(a)
            .neighbors
            .insert(ip(b_addr), neighbor(b_addr, asn_b, a_addr));
        self.proc(b)
            .neighbors
            .insert(ip(a_addr), neighbor(a_addr, asn_a, b_addr));
        self.input.sessions.push(Session {
            a: SessionEnd {
                device: a.to_string(),
                vrf: "default".to_string(),
                neighbor: ip(b_addr),
            },
            b: SessionEnd {
                device: b.to_string(),
                vrf: "default".to_string(),
                neighbor: ip(a_addr),
            },
        });
    }

    pub fn neighbor_mut(&mut self, device: &str, addr: &str) -> &mut rsim_routing::bgp::Neighbor {
        self.proc(device).neighbors.get_mut(&ip(addr)).unwrap()
    }

    /// A `network` statement of `prefix` at `device` with the route in the
    /// IGP view.
    pub fn originate(&mut self, device: &str, prefix: &str) {
        use rsim_routing::bgp::Network;
        self.proc(device).networks.push(Network {
            key: key(prefix),
            policy: None,
            spans: Vec::new(),
        });
        self.igp.routes.insert((device.to_string(), pfx(prefix)));
    }

    /// A received path of `prefix` from the peer `addr` of the AS
    /// `peer_as` outside the twin, with the next hop `addr`.
    pub fn seed(
        &mut self,
        device: &str,
        addr: &str,
        peer_as: u32,
        prefix: &str,
        as_path: &[u32],
        med: Option<u32>,
    ) {
        use rsim_routing::bgp::Seed;
        let local = self.get(device).router_id.to_string();
        self.proc(device)
            .neighbors
            .entry(ip(addr))
            .or_insert_with(|| neighbor(addr, peer_as, &local));
        let mut p = ebgp(addr, as_path);
        p.med = med;
        self.input.seeds.push(Seed {
            device: device.to_string(),
            vrf: "default".to_string(),
            neighbor: ip(addr),
            key: key(prefix),
            path: p,
            received: true,
        });
    }

    pub fn cost(&mut self, device: &str, nh: &str, cost: u32) {
        self.igp.costs.insert((device.to_string(), ip(nh)), cost);
    }

    pub fn run(&self) -> rsim_routing::bgp::BgpResult {
        rsim_routing::bgp::compute(&self.input, &self.igp).unwrap()
    }
}

/// The best path of `prefix` at `device`, `None` for no route.
pub fn best<'a>(
    r: &'a rsim_routing::bgp::BgpResult,
    device: &str,
    prefix: &str,
) -> Option<&'a rsim_routing::bgp::Selection> {
    use rsim_routing::bgp::{RouteAt, RouteState};
    match r.routes.get(&RouteAt {
        device: device.to_string(),
        vrf: "default".to_string(),
        key: key(prefix),
    })? {
        RouteState::Selected(s) => Some(s),
        RouteState::Unknown(_) => None,
    }
}

/// The state of `prefix` at `device`.
pub fn state<'a>(
    r: &'a rsim_routing::bgp::BgpResult,
    device: &str,
    prefix: &str,
) -> Option<&'a rsim_routing::bgp::RouteState> {
    r.routes.get(&rsim_routing::bgp::RouteAt {
        device: device.to_string(),
        vrf: "default".to_string(),
        key: key(prefix),
    })
}

/// The AS path of the best path of `prefix` at `device` as numbers.
pub fn as_path_of(
    r: &rsim_routing::bgp::BgpResult,
    device: &str,
    prefix: &str,
) -> Option<Vec<u32>> {
    best(r, device, prefix).map(|s| s.best.as_path.flat().iter().map(|a| a.0).collect())
}

/// The prefix that node 0 of a stable-paths instance originates.
pub const SPP_PREFIX: &str = "203.0.113.0/24";

/// A stable-paths instance. Node 0 originates [`SPP_PREFIX`]. `perm[u]`
/// holds the permitted paths of node `u`, the most preferred first, each as
/// the nodes from `u` to 0. `perm[0]` is empty.
#[derive(Clone, Debug)]
pub struct Spp {
    pub perm: Vec<Vec<Vec<usize>>>,
}

pub fn spp_asn(u: usize) -> u32 {
    64600 + u as u32
}

fn spp_addr(u: usize, v: usize) -> String {
    let (i, j) = (u.min(v), u.max(v));
    format!("10.{i}.{j}.{}", if u < v { 1 } else { 2 })
}

pub fn spp_device(u: usize) -> String {
    format!("n{u}")
}

/// The instance as eBGP between one AS for each node, with a session
/// between each 2 nodes. The import policy of node `u` from node `v` permits
/// the permitted paths of `u` through `v` with a local preference by rank
/// and denies each other path.
pub fn spp_lab(spp: &Spp) -> Lab {
    use rsim_routing::bgp::{
        AsPathLine, AsPathList, Clause, MatchTerm, PolicyBody, RoutePolicy, SetAction,
    };
    let n = spp.perm.len();
    let mut lab = Lab::default();
    for u in 0..n {
        lab.router(
            &spp_device(u),
            rsim_routing::Platform::Iosxe,
            spp_asn(u),
            &format!("10.255.0.{}", u + 1),
        );
    }
    for i in 0..n {
        for j in i + 1..n {
            lab.peer(
                &spp_device(i),
                &spp_addr(i, j),
                &spp_device(j),
                &spp_addr(j, i),
            );
        }
    }
    lab.originate(&spp_device(0), SPP_PREFIX);
    for u in 1..n {
        for v in 0..n {
            if v == u {
                continue;
            }
            let name = format!("from-{v}");
            let mut clauses = Vec::new();
            for (r, path) in spp.perm[u].iter().enumerate() {
                if path[1] != v {
                    continue;
                }
                let list = format!("p{r}");
                let text = path[1..]
                    .iter()
                    .map(|&x| spp_asn(x).to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                let p = lab.proc(&spp_device(u));
                p.policy.as_path_lists.insert(
                    list.clone(),
                    AsPathList::new(vec![AsPathLine::regex(1, true, &format!("^{text}$"))]),
                );
                let mut c = Clause::new(10 * (r as u32 + 1), true);
                c.matches.push(MatchTerm::AsPathList(vec![list]));
                c.sets.push(SetAction::LocalPref(1000 - r as u32));
                clauses.push(c);
            }
            let p = lab.proc(&spp_device(u));
            p.policy.policies.insert(
                name.clone(),
                RoutePolicy {
                    name: name.clone(),
                    body: PolicyBody::RouteMap(clauses),
                    spans: Vec::new(),
                },
            );
            lab.neighbor_mut(&spp_device(u), &spp_addr(v, u))
                .import_policy = Some(name);
        }
    }
    lab
}

/// Each stable assignment of the instance from the definition: each node
/// holds its most preferred permitted path whose rest is the path of the
/// next node, or no path.
pub fn spp_stable(spp: &Spp) -> Vec<Vec<Option<Vec<usize>>>> {
    let n = spp.perm.len();
    let mut out = Vec::new();
    let mut cur: Vec<usize> = vec![0; n];
    loop {
        let mut pi: Vec<Option<Vec<usize>>> = (0..n)
            .map(|u| {
                if u == 0 {
                    Some(vec![0])
                } else if cur[u] == 0 {
                    None
                } else {
                    Some(spp.perm[u][cur[u] - 1].clone())
                }
            })
            .collect();
        let ok = (1..n).all(|u| {
            let avail = spp.perm[u]
                .iter()
                .find(|p| pi[p[1]].as_deref() == Some(&p[1..]))
                .cloned();
            avail == pi[u]
        });
        if ok {
            pi[0] = Some(vec![0]);
            out.push(pi);
        }
        let mut u = 1;
        loop {
            if u == n {
                return out;
            }
            cur[u] += 1;
            if cur[u] <= spp.perm[u].len() {
                break;
            }
            cur[u] = 0;
            u += 1;
        }
    }
}

/// The path of each node in a map of routes, as nodes.
pub fn spp_paths(
    spp: &Spp,
    routes: &std::collections::BTreeMap<rsim_routing::bgp::RouteAt, rsim_routing::bgp::RouteState>,
) -> Vec<Option<Vec<usize>>> {
    use rsim_routing::bgp::{RouteAt, RouteState};
    (0..spp.perm.len())
        .map(|u| {
            if u == 0 {
                return Some(vec![0]);
            }
            let at = RouteAt {
                device: spp_device(u),
                vrf: "default".to_string(),
                key: key(SPP_PREFIX),
            };
            match routes.get(&at)? {
                RouteState::Selected(s) => {
                    let mut p = vec![u];
                    p.extend(s.best.as_path.flat().iter().map(|a| (a.0 - 64600) as usize));
                    Some(p)
                }
                RouteState::Unknown(u) => panic!("unknown route: {u}"),
            }
        })
        .collect()
}
