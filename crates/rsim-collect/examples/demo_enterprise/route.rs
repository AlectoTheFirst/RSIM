//! The state of the demo estate that the devices learn: the route tables
//! from the shortest paths over the routing adjacencies and the tunnels of
//! the fabrics, the ARP tables, the MAC tables and the spanning tree.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::Ipv4Addr;

use super::model::*;

/// The kind of a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Connected,
    Local,
    Static,
    Ospf,
    Ebgp,
    Ibgp,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Path {
    pub next_hop: Option<Ipv4Addr>,
    pub iface: Option<String>,
    /// The VNI of a path through a VXLAN tunnel.
    pub vxlan: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct Route {
    pub vrf: String,
    pub prefix: (Ipv4Addr, u8),
    pub kind: Kind,
    pub metric: u32,
    pub paths: Vec<Path>,
}

#[derive(Clone, Debug)]
pub struct Arp {
    pub iface: String,
    pub ip: Ipv4Addr,
    pub mac: Mac,
    /// An address of the device itself.
    pub own: bool,
}

#[derive(Clone, Debug)]
pub struct MacEntry {
    pub vlan: u16,
    pub mac: Mac,
    pub port: String,
}

#[derive(Clone, Debug)]
pub struct StpPort {
    pub port: String,
    pub root: bool,
    pub blocked: bool,
    pub edge: bool,
}

/// The learned state of each device, by device index.
pub struct Tables {
    pub ribs: Vec<Vec<Route>>,
    pub arp: Vec<Vec<Arp>>,
    pub macs: Vec<Vec<MacEntry>>,
    pub stp: Vec<BTreeMap<u16, Vec<StpPort>>>,
}

type Node = (usize, String);

struct Edge {
    to: Node,
    cost: u32,
    kind: Kind,
    path: Path,
}

fn kind(p: Proto) -> Kind {
    match p {
        Proto::Ospf => Kind::Ospf,
        Proto::Ebgp => Kind::Ebgp,
    }
}

/// The routing adjacencies: the interfaces with a routing cost in one
/// subnet, and the tunnels between the leaf pairs of a fabric in the
/// tenant VRF.
fn edges(e: &Estate) -> BTreeMap<Node, Vec<Edge>> {
    let mut out: BTreeMap<Node, Vec<Edge>> = BTreeMap::new();
    let mut segments: BTreeMap<(Ipv4Addr, u8), Vec<(usize, &Iface)>> = BTreeMap::new();
    for (d, dev) in e.devs.iter().enumerate() {
        for i in &dev.ifaces {
            if let (Some((a, l)), Some(_)) = (i.addr, i.routing) {
                segments.entry((network(a, l), l)).or_default().push((d, i));
            }
        }
    }
    for members in segments.values() {
        for (a, ia) in members {
            for (b, ib) in members {
                if a == b {
                    continue;
                }
                let (cost, proto) = ia.routing.expect("a routing interface");
                out.entry((*a, ia.vrf.clone())).or_default().push(Edge {
                    to: (*b, ib.vrf.clone()),
                    cost,
                    kind: kind(proto),
                    path: Path {
                        next_hop: ib.addr.map(|x| x.0),
                        iface: Some(ia.name.clone()),
                        vxlan: None,
                    },
                });
            }
        }
    }
    for (a, da) in e.devs.iter().enumerate() {
        let Some((vrf, vni, _)) = &da.l3vni else {
            continue;
        };
        for (b, db) in e.devs.iter().enumerate() {
            if db.site != da.site || db.l3vni.is_none() || db.vtep == da.vtep {
                continue;
            }
            out.entry((a, vrf.clone())).or_default().push(Edge {
                to: (b, vrf.clone()),
                cost: 10,
                kind: Kind::Ibgp,
                path: Path {
                    next_hop: db.vtep,
                    iface: None,
                    vxlan: Some(*vni),
                },
            });
        }
    }
    out
}

/// The prefixes that each node gives to the others: its connected subnets
/// and, on the internet edge, the default route.
fn owned(e: &Estate) -> BTreeMap<(Ipv4Addr, u8), BTreeSet<Node>> {
    let mut out: BTreeMap<(Ipv4Addr, u8), BTreeSet<Node>> = BTreeMap::new();
    for (d, dev) in e.devs.iter().enumerate() {
        for i in &dev.ifaces {
            if i.mode == Mode::Mgmt {
                continue;
            }
            for (a, l) in i.addr.iter().chain(i.secondary.iter()) {
                out.entry((network(*a, *l), *l))
                    .or_default()
                    .insert((d, i.vrf.clone()));
            }
        }
        if dev.role == Role::Inet {
            out.entry((ip(0, 0, 0, 0), 0))
                .or_default()
                .insert((d, "default".to_string()));
        }
    }
    out
}

/// The connected and local routes of a device, and its static routes.
fn own_routes(e: &Estate, d: usize) -> Vec<Route> {
    let dev = &e.devs[d];
    let mut out = Vec::new();
    for i in &dev.ifaces {
        for (a, l) in i.addr.iter().chain(i.secondary.iter()) {
            if *l < 32 {
                out.push(Route {
                    vrf: i.vrf.clone(),
                    prefix: (network(*a, *l), *l),
                    kind: Kind::Connected,
                    metric: 0,
                    paths: vec![Path {
                        next_hop: None,
                        iface: Some(i.name.clone()),
                        vxlan: None,
                    }],
                });
            }
            out.push(Route {
                vrf: i.vrf.clone(),
                prefix: (*a, 32),
                kind: if *l == 32 && dev.os == Os::Iosxe {
                    Kind::Connected
                } else {
                    Kind::Local
                },
                metric: 0,
                paths: vec![Path {
                    next_hop: None,
                    iface: Some(i.name.clone()),
                    vxlan: None,
                }],
            });
        }
    }
    for s in &dev.statics {
        let iface = dev
            .ifaces
            .iter()
            .find(|i| {
                i.vrf == s.vrf
                    && i.addr
                        .is_some_and(|(a, l)| network(a, l) == network(s.next_hop, l))
            })
            .map(|i| i.name.clone());
        out.push(Route {
            vrf: s.vrf.clone(),
            prefix: s.prefix,
            kind: Kind::Static,
            metric: 0,
            paths: vec![Path {
                next_hop: Some(s.next_hop),
                iface,
                vxlan: None,
            }],
        });
    }
    out
}

/// The administrative distance of a kind of route.
fn distance(k: Kind) -> u8 {
    match k {
        Kind::Connected | Kind::Local => 0,
        Kind::Static => 1,
        Kind::Ebgp => 20,
        Kind::Ospf => 110,
        Kind::Ibgp => 200,
    }
}

/// The route tables of all devices.
fn ribs(e: &Estate) -> Vec<Vec<Route>> {
    let edges = edges(e);
    let owned = owned(e);
    let mut reverse: BTreeMap<Node, Vec<(Node, u32)>> = BTreeMap::new();
    for (from, list) in &edges {
        for x in list {
            reverse
                .entry(x.to.clone())
                .or_default()
                .push((from.clone(), x.cost));
        }
    }
    let mut out: Vec<Vec<Route>> = (0..e.devs.len()).map(|d| own_routes(e, d)).collect();
    for (prefix, owners) in &owned {
        // The distance of each node to the nearest owner.
        let mut dist: BTreeMap<Node, u32> = owners.iter().map(|o| (o.clone(), 0)).collect();
        let mut queue: BTreeSet<(u32, Node)> = owners.iter().map(|o| (0, o.clone())).collect();
        while let Some((c, n)) = queue.pop_first() {
            if dist.get(&n).is_some_and(|x| *x < c) {
                continue;
            }
            for (m, w) in reverse.get(&n).into_iter().flatten() {
                let nc = c + w;
                if dist.get(m).is_none_or(|x| nc < *x) {
                    dist.insert(m.clone(), nc);
                    queue.insert((nc, m.clone()));
                }
            }
        }
        for (n, c) in &dist {
            if *c == 0 {
                continue;
            }
            let mut paths: Vec<(Kind, Path)> = edges
                .get(n)
                .into_iter()
                .flatten()
                .filter(|x| dist.get(&x.to).is_some_and(|m| m + x.cost == *c))
                .map(|x| (x.kind, x.path.clone()))
                .collect();
            paths.sort();
            paths.dedup();
            let Some(k) = paths.first().map(|p| p.0) else {
                continue;
            };
            out[n.0].push(Route {
                vrf: n.1.clone(),
                prefix: *prefix,
                kind: k,
                metric: *c,
                paths: paths
                    .into_iter()
                    .filter(|p| p.0 == k)
                    .map(|p| p.1)
                    .collect(),
            });
        }
    }
    // The OSPF routes of each OSPF router come from the calculation over its
    // database. A route of another kind with a lower distance stays.
    for (d, rib) in out.iter_mut().enumerate() {
        let Some(computed) = super::ospf::routes(e, d, e.devs[d].os) else {
            continue;
        };
        rib.retain(|r| !(r.vrf == "default" && r.kind == Kind::Ospf));
        for c in computed {
            let held = rib
                .iter()
                .filter(|r| r.vrf == "default" && r.prefix == c.prefix)
                .map(|r| distance(r.kind))
                .min();
            if held.is_some_and(|h| h < distance(Kind::Ospf)) {
                continue;
            }
            rib.retain(|r| !(r.vrf == "default" && r.prefix == c.prefix));
            rib.push(c);
        }
    }
    for r in &mut out {
        r.sort_by(|a, b| {
            (&a.vrf, a.prefix.0, a.prefix.1, a.kind).cmp(&(&b.vrf, b.prefix.0, b.prefix.1, b.kind))
        });
    }
    out
}

/// The layer 2 port of a port: the port channel of a member.
fn l2_port(dev: &Dev, port: &str) -> Option<String> {
    let i = dev.iface(port);
    match &i.mode {
        Mode::Member(n, _) => Some(
            dev.ifaces
                .iter()
                .find(|x| {
                    matches!(x.mode, Mode::PortChannel(_)) && x.name.ends_with(&format!("{n}"))
                })
                .map(|x| x.name.clone())
                .unwrap_or_else(|| panic!("{}: no port channel {n}", dev.name)),
        ),
        Mode::Trunk(_) | Mode::PortChannel(_) | Mode::Access(_) => Some(port.to_string()),
        _ => None,
    }
}

fn carries(i: &Iface, v: u16) -> bool {
    match &i.mode {
        Mode::Trunk(l) | Mode::PortChannel(l) | Mode::Member(_, l) => l.contains(&v),
        Mode::Access(a) => *a == v,
        _ => false,
    }
}

/// The forwarding links of the switches in a VLAN: for each switch, its
/// layer 2 ports that lead to another switch with the far switch.
fn l2_links(e: &Estate, v: u16) -> BTreeMap<usize, BTreeMap<String, usize>> {
    let mut out: BTreeMap<usize, BTreeMap<String, usize>> = BTreeMap::new();
    for l in &e.links {
        let (da, db) = (&e.devs[l.a.0], &e.devs[l.b.0]);
        let (ia, ib) = (da.iface(&l.a.1), db.iface(&l.b.1));
        if !carries(ia, v) || !carries(ib, v) || ia.blocked || ib.blocked {
            continue;
        }
        if matches!(ia.mode, Mode::Access(_)) || matches!(ib.mode, Mode::Access(_)) {
            continue;
        }
        let (Some(pa), Some(pb)) = (l2_port(da, &l.a.1), l2_port(db, &l.b.1)) else {
            continue;
        };
        out.entry(l.a.0).or_default().insert(pa, l.b.0);
        out.entry(l.b.0).or_default().insert(pb, l.a.0);
    }
    out
}

/// The port of switch `from` that leads to switch `to` in a VLAN, if any.
fn toward(
    links: &BTreeMap<usize, BTreeMap<String, usize>>,
    from: usize,
    to: usize,
) -> Option<String> {
    let mut seen = BTreeSet::from([from]);
    let mut queue: VecDeque<(usize, String)> = VecDeque::new();
    for (p, n) in links.get(&from).into_iter().flatten() {
        if seen.insert(*n) {
            queue.push_back((*n, p.clone()));
        }
    }
    while let Some((n, first)) = queue.pop_front() {
        if n == to {
            return Some(first);
        }
        for m in links.get(&n).into_iter().flat_map(|x| x.values()) {
            if seen.insert(*m) {
                queue.push_back((*m, first.clone()));
            }
        }
    }
    None
}

/// The MACs in a VLAN with the switch that has them: on a port for a host,
/// or on the switch itself for an SVI and the virtual MAC of an active
/// HSRP group.
fn owners(e: &Estate, v: u16) -> Vec<(Mac, usize, Option<String>)> {
    let mut out = Vec::new();
    for h in &e.hosts {
        if h.vlan == v {
            out.push((h.mac, h.dev, Some(h.port.clone())));
        }
    }
    for (d, dev) in e.devs.iter().enumerate() {
        for i in &dev.ifaces {
            if i.svi_vlan() != Some(v) || i.anycast || i.ip_forward {
                continue;
            }
            if let Some(m) = i.mac {
                out.push((m, d, None));
            }
            if let Some(h) = &i.hsrp
                && h.active
            {
                out.push((hsrp_mac(h.group), d, None));
            }
        }
    }
    out
}

fn macs(e: &Estate) -> Vec<Vec<MacEntry>> {
    let mut out: Vec<Vec<MacEntry>> = vec![Vec::new(); e.devs.len()];
    let vlans: BTreeSet<u16> = e
        .devs
        .iter()
        .flat_map(|d| d.vlans.iter().map(|v| v.id))
        .collect();
    for v in vlans {
        let links = l2_links(e, v);
        let owners = owners(e, v);
        for (s, dev) in e.devs.iter().enumerate() {
            if !dev.has_vlan(v) || dev.l3vni.as_ref().is_some_and(|x| x.2 == v) {
                continue;
            }
            for (m, at, port) in &owners {
                let port = if *at == s {
                    port.clone()
                } else {
                    toward(&links, s, *at)
                };
                if let Some(port) = port {
                    out[s].push(MacEntry {
                        vlan: v,
                        mac: *m,
                        port,
                    });
                }
            }
        }
    }
    for x in &mut out {
        x.sort_by_key(|m| (m.vlan, m.mac));
    }
    out
}

/// The spanning tree state of the ports of each IOS-XE switch, with the
/// switch of the lowest priority as the root.
fn stp(e: &Estate) -> Vec<BTreeMap<u16, Vec<StpPort>>> {
    let mut out = vec![BTreeMap::new(); e.devs.len()];
    for (s, dev) in e.devs.iter().enumerate() {
        if dev.os != Os::Iosxe {
            continue;
        }
        for v in dev.vlans.iter().map(|x| x.id) {
            let links = l2_links(e, v);
            // The root of the tree of the switch.
            let mut tree = BTreeSet::from([s]);
            let mut queue = VecDeque::from([s]);
            while let Some(n) = queue.pop_front() {
                for m in links.get(&n).into_iter().flat_map(|x| x.values()) {
                    if tree.insert(*m) {
                        queue.push_back(*m);
                    }
                }
            }
            let root = *tree
                .iter()
                .min_by_key(|d| (e.devs[**d].stp_priority, e.devs[**d].base_mac))
                .expect("the switch itself");
            let root_port = (root != s).then(|| toward(&links, s, root)).flatten();
            let mut ports = Vec::new();
            for i in &dev.ifaces {
                if !carries(i, v) || matches!(i.mode, Mode::Member(..)) {
                    continue;
                }
                let edge = matches!(i.mode, Mode::Access(_));
                ports.push(StpPort {
                    port: i.name.clone(),
                    root: root_port.as_deref() == Some(i.name.as_str()),
                    blocked: i.blocked,
                    edge,
                });
            }
            if !ports.is_empty() {
                out[s].insert(v, ports);
            }
        }
    }
    out
}

/// The address and the MAC of each SVI, HSRP group and host in a VLAN of
/// the layer 2 domain of a switch.
fn segment(e: &Estate, s: usize, v: u16) -> Vec<(Ipv4Addr, Mac, usize)> {
    let links = l2_links(e, v);
    let reach = |d: usize| d == s || toward(&links, s, d).is_some();
    let mut out = Vec::new();
    for (d, dev) in e.devs.iter().enumerate() {
        if !reach(d) {
            continue;
        }
        for i in &dev.ifaces {
            if i.svi_vlan() != Some(v) || i.anycast {
                continue;
            }
            if let (Some((a, _)), Some(m)) = (i.addr, i.mac) {
                out.push((a, m, d));
            }
            if let Some(h) = &i.hsrp
                && h.active
            {
                out.push((h.vip, hsrp_mac(h.group), d));
            }
        }
    }
    for h in &e.hosts {
        if h.vlan == v && reach(h.dev) && e.devs[s].site == e.devs[h.dev].site {
            out.push((h.ip, h.mac, usize::MAX));
        }
    }
    out
}

fn arp(e: &Estate) -> Vec<Vec<Arp>> {
    let mut out = vec![Vec::new(); e.devs.len()];
    for (d, dev) in e.devs.iter().enumerate() {
        let mut rows = Vec::new();
        for i in &dev.ifaces {
            let Some((a, _)) = i.addr else { continue };
            if matches!(i.mode, Mode::Loopback | Mode::Nve) {
                continue;
            }
            let own_mac = i.mac.unwrap_or(0);
            match &i.mode {
                Mode::Routed => {
                    rows.push(Arp {
                        iface: i.name.clone(),
                        ip: a,
                        mac: own_mac,
                        own: true,
                    });
                    if let Some((f, port)) = e.far(d, &i.name) {
                        let fi = e.devs[f].iface(&port);
                        if let (Some((fa, _)), Some(fm)) = (fi.addr, fi.mac) {
                            rows.push(Arp {
                                iface: i.name.clone(),
                                ip: fa,
                                mac: fm,
                                own: false,
                            });
                        }
                    }
                    for x in e
                        .externals
                        .iter()
                        .filter(|x| x.dev == d && x.port == i.name)
                    {
                        rows.push(Arp {
                            iface: i.name.clone(),
                            ip: x.ip,
                            mac: x.mac,
                            own: false,
                        });
                    }
                }
                Mode::Mgmt => {
                    rows.push(Arp {
                        iface: i.name.clone(),
                        ip: a,
                        mac: own_mac,
                        own: true,
                    });
                    rows.push(Arp {
                        iface: i.name.clone(),
                        ip: ip(10, 255, u8::try_from(dev.site + 1).expect("2"), 1),
                        mac: 0x025e_fe00_0000 + u64::try_from(dev.site).expect("2"),
                        own: false,
                    });
                }
                Mode::Svi(v) => {
                    if !i.anycast {
                        rows.push(Arp {
                            iface: i.name.clone(),
                            ip: a,
                            mac: own_mac,
                            own: true,
                        });
                    }
                    if let Some(h) = &i.hsrp
                        && h.active
                    {
                        rows.push(Arp {
                            iface: i.name.clone(),
                            ip: h.vip,
                            mac: hsrp_mac(h.group),
                            own: true,
                        });
                    }
                    for (ip, mac, at) in segment(e, d, *v) {
                        if at == d {
                            continue;
                        }
                        rows.push(Arp {
                            iface: i.name.clone(),
                            ip,
                            mac,
                            own: false,
                        });
                    }
                }
                _ => {}
            }
        }
        rows.sort_by_key(|r| (r.iface.clone(), r.ip));
        rows.dedup_by_key(|r| (r.iface.clone(), r.ip));
        out[d] = rows;
    }
    out
}

pub fn tables(e: &Estate) -> Tables {
    Tables {
        ribs: ribs(e),
        arp: arp(e),
        macs: macs(e),
        stp: stp(e),
    }
}
