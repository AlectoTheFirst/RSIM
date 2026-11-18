//! A generated estate for the scale benchmark.
//!
//! Each site has an edge router, a firewall, 2 core routers and 7 access
//! routers. Each access router has 4 user networks with the users, and the
//! firewall has a DMZ network with the servers. The access routers have a
//! link to each core router, the core routers have a link to the inside of
//! the firewall, and the outside of the firewall has a link to the edge
//! router. The edge routers of the first sites are the hub routers of a
//! routed backbone: the hubs are a full mesh, and the edge router of each
//! other site has a link to 2 hubs. 1,000 sites give 10,000 routers, 1,000
//! firewalls with 60,000 rules and 60,000 endpoints.
//!
//! A route table has the routes of the estate and more routes up to a size
//! for its role, so the size of a table does not depend on the number of
//! sites. Some hubs also have a full-size table.
//!
//! The addresses are private or documentation addresses: the sites are in
//! 10.0.0.0/9, the extra routes and the full tables in 10.128.0.0/9 and
//! 2001:db8::/32, the backbone links in 172.16.0.0/12 and the upstream
//! links in 198.51.100.0/24. A fixed pseudo-random sequence gives the
//! variation, so each build gives the same estate.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use rsim_core::{
    AddrCond, EndpointId, FunctionId, InterfaceId, Match, NeighbourTarget, ObjectId, PROTO_TCP,
    PROTO_UDP, PortCond, Prefix, PrefixTable, RulePredicate, SourceSpan, TriePrefixTable,
    ValueCond, VrfId, ZoneId,
};
use rsim_engine::{AttachmentKind, AttachmentRecord, EdgeInterface, Endpoint, TwinBuilder};
use rsim_functions::{
    Egress, EgressMode, Fib, FirewallPolicy, Ingress, Link, Meta, Neighbour, NextHopResolution,
    Route, RouteKind, RouteLookup, RouteNextHop, RouteProtocol, Rule, RuleAction, SessionCommit,
    SessionLookup, StateActions, VendorProfile, VrfSelection, ZoneLookup, ZoneRole, ZoneScope,
};

use crate::profiles::{fortios, nxos};

/// The number of sites of the full estate.
pub const FULL_SITES: usize = 1000;
/// The access routers of a site.
pub const ACCESS: usize = 7;
/// The user networks of an access router.
pub const VLANS: usize = 4;
/// The users of a site.
pub const USERS: usize = 54;
/// The servers of a site, in the DMZ.
pub const SERVERS: usize = 6;
/// The rules of a firewall.
pub const RULES: usize = 60;
/// The sites of a hub of the full estate.
const SITES_PER_HUB: usize = 25;

/// The size of a route table of each role, before a variation of up to
/// 25 % in each direction.
const ACCESS_ROUTES: usize = 500;
const CORE_ROUTES: usize = 3000;
const FIREWALL_ROUTES: usize = 400;
const EDGE_ROUTES: usize = 3000;
const HUB_ROUTES: usize = 8000;

/// The options of the generated estate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScaleOpts {
    /// The number of sites, at least 2 and at most 1,024.
    pub sites: usize,
    /// Fill each route table up to the size of its role. With `false`,
    /// a table has only the routes of the estate, and no hub has a full
    /// table.
    pub fill_tables: bool,
    /// The IPv4 and IPv6 routes of a full table.
    pub full_table: (usize, usize),
    /// The hubs with a full table.
    pub full_table_routers: usize,
}

impl ScaleOpts {
    /// The estate at `percent` % of the full size: 1,000 sites at 100 %,
    /// and 4 hubs with a full table of 1,000,000 IPv4 and 200,000 IPv6
    /// routes at 100 %, at least 1.
    pub fn percent(percent: f64) -> ScaleOpts {
        let sites = ((FULL_SITES as f64 * percent / 100.0).round() as usize).clamp(2, 1024);
        ScaleOpts {
            sites,
            fill_tables: true,
            full_table: (1_000_000, 200_000),
            full_table_routers: (4 * sites).div_ceil(FULL_SITES),
        }
    }
}

/// The counts of a generated estate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScaleCounts {
    pub sites: usize,
    pub hubs: usize,
    /// All routers: the access, core, edge and hub routers.
    pub routers: usize,
    pub firewalls: usize,
    pub rules: usize,
    pub endpoints: usize,
    /// The routes of all route tables, after duplicate prefixes.
    pub routes: usize,
    /// The routes of the full tables.
    pub full_table_routes: usize,
    pub full_table_routers: usize,
}

/// A generated estate: the builder of the twin and its counts.
pub struct ScaleEstate {
    pub builder: TwinBuilder,
    pub counts: ScaleCounts,
}

/// A fixed pseudo-random sequence.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// `base` with a variation of up to 25 % in each direction.
    fn around(&mut self, base: usize) -> usize {
        base - base / 4 + self.below(base / 2 + 1)
    }
}

fn v4(a: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(a))
}

/// The first address of the /19 network of a site.
fn site_base(site: usize) -> u32 {
    0x0A00_0000 + ((site as u32) << 13)
}

/// The /19 network of a site.
pub fn site_network(site: usize) -> Prefix {
    Prefix::new(v4(site_base(site)), 19)
}

/// The user network `vlan` of the access router `access` of a site.
pub fn user_network(site: usize, access: usize, vlan: usize) -> Prefix {
    Prefix::new(
        v4(site_base(site) + (((access * VLANS + vlan) as u32) << 8)),
        24,
    )
}

/// The DMZ network of a site.
pub fn dmz_network(site: usize) -> Prefix {
    Prefix::new(v4(site_base(site) + (28 << 8)), 24)
}

/// The access router, the user network and the address of user `k` of a
/// site.
pub fn user(site: usize, k: usize) -> (usize, usize, IpAddr) {
    let n = ACCESS * VLANS;
    let (access, vlan) = ((k % n) / VLANS, (k % n) % VLANS);
    let IpAddr::V4(net) = user_network(site, access, vlan).addr() else {
        unreachable!("the sites are IPv4")
    };
    (access, vlan, v4(u32::from(net) + 10 + (k / n) as u32))
}

/// The address of server `k` of a site.
pub fn server(site: usize, k: usize) -> IpAddr {
    let IpAddr::V4(net) = dmz_network(site).addr() else {
        unreachable!("the sites are IPv4")
    };
    v4(u32::from(net) + 10 + k as u32)
}

/// The 2 addresses of the link `k` of a site, in the network
/// 10.x.x.0/24 after the DMZ.
fn site_link(site: usize, k: usize) -> (IpAddr, IpAddr) {
    let a = site_base(site) + (31 << 8) + 2 * k as u32;
    (v4(a), v4(a + 1))
}

/// The /31 network of a link.
fn link_net(a: IpAddr) -> Prefix {
    Prefix::new(a, 31)
}

/// A next hop of a route: the interface index and the gateway.
type Hop = (usize, Option<IpAddr>);

/// A device under construction: its interfaces, route table and
/// neighbours.
struct Node {
    name: String,
    profile: VendorProfile,
    vrf: VrfId,
    file: Arc<str>,
    line: u32,
    ifaces: Vec<InterfaceId>,
    /// The ingress function at the far end of each interface's link.
    peers: Vec<Option<FunctionId>>,
    fib: Fib,
    /// The function that the route lookup gives a packet to.
    after_route: FunctionId,
    neighbours: TriePrefixTable<Vec<Neighbour>>,
}

impl Node {
    fn new(name: String, profile: VendorProfile, after_route: &str) -> Node {
        let vrf = profile.default_vrf.clone().expect("the profile has a VRF");
        let after_route = FunctionId::new(format!("{name}/{after_route}"));
        Node {
            file: Arc::from(format!("{name}.conf")),
            name,
            profile,
            vrf,
            line: 1,
            ifaces: Vec::new(),
            peers: Vec::new(),
            fib: Fib::new(),
            after_route,
            neighbours: TriePrefixTable::new(),
        }
    }

    fn id(&self, f: &str) -> FunctionId {
        FunctionId::new(format!("{}/{f}", self.name))
    }

    fn span(&mut self) -> SourceSpan {
        self.line += 1;
        SourceSpan {
            file: self.file.clone(),
            first_line: self.line,
            last_line: self.line,
        }
    }

    fn meta(&mut self, f: &str) -> Meta {
        let span = self.span();
        Meta::new(self.id(f), self.name.as_str(), &self.profile).with_span(span)
    }

    /// Adds an interface with a link to the ingress `peer` of another
    /// device, and gives its index.
    fn iface(&mut self, name: &str, peer: Option<String>) -> usize {
        self.ifaces.push(InterfaceId::new(name));
        self.peers.push(peer.map(FunctionId::new));
        self.ifaces.len() - 1
    }

    fn route(&mut self, p: Prefix, kind: RouteKind, hops: &[Hop]) {
        let next_hops = hops
            .iter()
            .map(|(i, gw)| RouteNextHop {
                interface: self.ifaces[*i].clone(),
                gateway: *gw,
                next: self.after_route.clone(),
            })
            .collect();
        let span = self.span();
        self.fib.insert(p, Route::new(kind, next_hops, vec![span]));
    }

    fn connected(&mut self, p: Prefix, iface: usize) {
        self.route(p, RouteKind::Connected, &[(iface, None)]);
    }

    fn neighbour(&mut self, addr: IpAddr, iface: usize, target: NeighbourTarget, owner: &str) {
        let span = self.span();
        let p = Prefix::host(addr);
        let mut v = self.neighbours.get(&p).cloned().unwrap_or_default();
        v.push(Neighbour {
            interface: self.ifaces[iface].clone(),
            target,
            owner: owner.to_string(),
            mac: None,
            spans: vec![span],
        });
        self.neighbours.insert(p, v);
    }

    /// The far end of a link at the gateway `addr`.
    fn link_peer(&mut self, addr: IpAddr, iface: usize, owner: &str) {
        self.neighbour(addr, iface, NeighbourTarget::Link, owner);
    }

    /// Adds the functions of the device: the ingress of each interface,
    /// the functions from `first` to the route lookup, the route lookup,
    /// the functions after it, the next-hop resolution and the egress of
    /// each interface.
    fn finish(
        mut self,
        b: &mut TwinBuilder,
        first: &str,
        before_route: Vec<Arc<dyn rsim_core::NetFunction>>,
        after_route: Vec<Arc<dyn rsim_core::NetFunction>>,
    ) -> usize {
        for i in 0..self.ifaces.len() {
            let name = format!("in/{}", self.ifaces[i]);
            let meta = self.meta(&name);
            b.add(Ingress {
                meta,
                interface: self.ifaces[i].clone(),
                next: self.id("vrf"),
            });
        }
        let meta = self.meta("vrf");
        b.add(VrfSelection {
            meta,
            by_interface: BTreeMap::new(),
            default_vrf: Some(self.vrf.clone()),
            next: self.id(first),
        });
        for f in before_route {
            b.add_arc(f);
        }
        let routes = self.fib.len();
        let meta = self.meta("route");
        let fib = std::mem::take(&mut self.fib);
        b.add(RouteLookup {
            meta,
            tables: BTreeMap::from([(self.vrf.clone(), fib)]),
            fallback: None,
            local: None,
        });
        for f in after_route {
            b.add_arc(f);
        }
        let meta = self.meta("nexthop");
        let egress = self
            .ifaces
            .iter()
            .map(|i| (i.clone(), self.id(&format!("out/{i}"))))
            .collect();
        b.add(NextHopResolution {
            meta,
            neighbours: std::mem::take(&mut self.neighbours),
            complete: true,
            egress,
            point_to_point: Default::default(),
        });
        for i in 0..self.ifaces.len() {
            let name = format!("out/{}", self.ifaces[i]);
            let meta = self.meta(&name);
            let span = self.span();
            b.add(Egress {
                meta,
                interface: self.ifaces[i].clone(),
                mode: EgressMode::Routed,
                link: self.peers[i].clone().map(|peer| Link {
                    peer: Some(peer),
                    delay_ns: None,
                    provenance: vec![span],
                    facts: None,
                }),
                rewrite: Default::default(),
                tag: Default::default(),
                exit: None,
            });
        }
        routes
    }
}

/// The names of the devices of a site.
fn access_name(site: usize, a: usize) -> String {
    format!("s{site:04}-acc{a}")
}
fn core_name(site: usize, c: usize) -> String {
    format!("s{site:04}-core{c}")
}
fn fw_name(site: usize) -> String {
    format!("s{site:04}-fw")
}
fn edge_name(site: usize) -> String {
    format!("s{site:04}-edge")
}
fn ingress(device: &str, iface: &str) -> Option<String> {
    Some(format!("{device}/in/{iface}"))
}

/// The links of a site: core `c` to access `a`, the firewall to core `c`,
/// and the edge to the firewall.
fn core_access_link(c: usize, a: usize) -> usize {
    c * ACCESS + a
}
fn fw_core_link(c: usize) -> usize {
    2 * ACCESS + c
}
const EDGE_FW_LINK: usize = 2 * ACCESS + 2;

/// Fills a route table with routes from 10.128.0.0/9 up to `target`
/// routes; `hop` gives the next hops of the route `k`.
fn fill(n: &mut Node, g: &mut Lcg, target: usize, hop: &dyn Fn(usize) -> Vec<Hop>) {
    let pool = 1u32 << 15;
    let start = g.below(pool as usize) as u32;
    let step = (g.below(pool as usize / 2) as u32) * 2 + 1;
    let mut k = 0usize;
    while n.fib.len() < target {
        let j = (start + step.wrapping_mul(k as u32)) % pool;
        let base = 0x0A80_0000 + (j << 8);
        let r = g.below(100);
        let (addr, len) = match r {
            0..60 => (base, 24),
            60..75 => (base + ((g.below(4) as u32) << 6), 26),
            75..85 => (base + ((g.below(8) as u32) << 5), 27),
            85..92 => (base + ((g.below(16) as u32) << 4), 28),
            92..97 => (base, 23),
            _ => (base, 22),
        };
        let hops = hop(k);
        n.route(
            Prefix::new(v4(addr), len),
            RouteKind::Learned(RouteProtocol::Bgp),
            &hops,
        );
        k += 1;
    }
}

/// Prefix lengths in about the proportions of an internet table.
fn v4_len(r: u64) -> u8 {
    match r % 100 {
        0..60 => 24,
        60..70 => 23,
        70..80 => 22,
        80..85 => 21,
        85..90 => 20,
        90..93 => 19,
        93..95 => 18,
        95..98 => 16,
        _ => 8 + (r % 8) as u8,
    }
}

fn v6_len(r: u64) -> u8 {
    match r % 100 {
        0..50 => 48,
        50..65 => 32,
        65..75 => 40,
        75..85 => 44,
        85..92 => 36,
        _ => 29,
    }
}

/// Adds a full table: IPv4 routes in 10.128.0.0/9, with the lengths of an
/// internet table moved 8 bits down, and IPv6 routes in 2001:db8::/32,
/// with the lengths of an internet table moved 16 bits down.
fn full_table(n: &mut Node, g: &mut Lcg, (v4n, v6n): (usize, usize), iface: usize, gw: IpAddr) {
    let kind = RouteKind::Learned(RouteProtocol::Bgp);
    for _ in 0..v4n {
        let a = 0x0A80_0000 | (g.next() as u32 & 0x007F_FFFF);
        let len = (v4_len(g.next()) + 8).min(32);
        n.route(Prefix::new(v4(a), len), kind, &[(iface, Some(gw))]);
    }
    for _ in 0..v6n {
        let hi = (0x2001_0db8u128 << 96) | (u128::from(g.next() as u32) << 64);
        let len = v6_len(g.next()) + 16;
        n.route(
            Prefix::new(IpAddr::V6(Ipv6Addr::from(hi)), len),
            kind,
            &[(iface, Some(gw))],
        );
    }
}

/// The well-known ports of the generated rules. 443 is left out: only the
/// 2 rules of the benchmark path match it.
const PORTS: [u16; 16] = [
    22, 25, 53, 80, 123, 135, 389, 445, 636, 1433, 1521, 3306, 3389, 5432, 8080, 8443,
];

/// A random address condition: a site, a user network, the own site or
/// any address.
fn rand_addr(g: &mut Lcg, own: usize) -> AddrCond {
    match g.below(10) {
        0..4 => AddrCond::In(vec![site_network(g.below(FULL_SITES))]),
        4..7 => AddrCond::In(vec![user_network(
            g.below(FULL_SITES),
            g.below(ACCESS),
            g.below(VLANS),
        )]),
        7..9 => AddrCond::In(vec![site_network(own), dmz_network(own)]),
        _ => AddrCond::Any,
    }
}

/// The rules of the firewall of a site. The rules at positions 48 and 54
/// permit TCP port 443 from the site to the other sites and from the other
/// sites to the DMZ; the last rule denies all.
fn rules(site: usize, g: &mut Lcg, fw: &mut Node) -> Vec<(ZoneScope, Rule<RuleAction>)> {
    const PAIRS: [(&str, &str); 6] = [
        ("inside", "outside"),
        ("outside", "dmz"),
        ("inside", "dmz"),
        ("outside", "inside"),
        ("dmz", "outside"),
        ("dmz", "inside"),
    ];
    let sites: Prefix = Prefix::new(v4(0x0A00_0000), 9);
    let mut out = Vec::with_capacity(RULES);
    for k in 0..RULES {
        let span = fw.span();
        let (scope, name, m, action) = match k {
            48 => (
                ZoneScope::between("inside", "outside"),
                "site-to-sites-https".to_string(),
                Match {
                    src_ip: AddrCond::In(vec![site_network(site)]),
                    dst_ip: AddrCond::In(vec![sites]),
                    protocol: ValueCond::one(PROTO_TCP),
                    dst_port: PortCond::one(443),
                    ..Match::any()
                },
                RuleAction::Permit,
            ),
            54 => (
                ZoneScope::between("outside", "dmz"),
                "sites-to-dmz-https".to_string(),
                Match {
                    src_ip: AddrCond::In(vec![sites]),
                    dst_ip: AddrCond::In(vec![dmz_network(site)]),
                    protocol: ValueCond::one(PROTO_TCP),
                    dst_port: PortCond::one(443),
                    ..Match::any()
                },
                RuleAction::Permit,
            ),
            k if k == RULES - 1 => (
                ZoneScope::default(),
                "deny-all".to_string(),
                Match::any(),
                RuleAction::Deny,
            ),
            k => {
                let (from, to) = PAIRS[g.below(PAIRS.len())];
                let protocol = if g.below(10) < 7 {
                    PROTO_TCP
                } else {
                    PROTO_UDP
                };
                let dst_port = if g.below(10) < 8 {
                    PortCond::one(PORTS[g.below(PORTS.len())])
                } else {
                    let lo = 9000 + g.below(900) as u16;
                    PortCond::In(vec![(lo, lo + 99)])
                };
                let action = if g.below(4) == 0 {
                    RuleAction::Deny
                } else {
                    RuleAction::Permit
                };
                (
                    ZoneScope::between(from, to),
                    format!("rule-{k}"),
                    Match {
                        src_ip: rand_addr(g, site),
                        dst_ip: rand_addr(g, site),
                        protocol: ValueCond::one(protocol),
                        dst_port,
                        ..Match::any()
                    },
                    action,
                )
            }
        };
        out.push((
            scope,
            Rule::new(&name, RulePredicate::exact(m), action).with_span(span),
        ));
    }
    out
}

/// The generated estate of `opts.sites` sites.
///
/// # Panics
///
/// Panics if `opts.sites` is not between 2 and 1,024.
pub fn scale_estate(opts: ScaleOpts) -> ScaleEstate {
    let sites = opts.sites;
    assert!((2..=1024).contains(&sites), "2 to 1,024 sites");
    let hubs = sites.div_ceil(SITES_PER_HUB).max(2);
    let full = if opts.fill_tables {
        opts.full_table_routers.min(hubs)
    } else {
        0
    };
    let mut g = Lcg(0x5CA1_E000 + sites as u64);
    let mut b = TwinBuilder::new();
    let mut counts = ScaleCounts {
        sites,
        hubs,
        full_table_routers: full,
        ..ScaleCounts::default()
    };
    let target = |g: &mut Lcg, base: usize| if opts.fill_tables { g.around(base) } else { 0 };
    let all_sites: Vec<Prefix> = (0..sites).map(site_network).collect();

    // The hubs of a site that is not a hub, and the backbone links.
    let site_hubs = |s: usize| [s % hubs, (s + 1) % hubs];
    let mut next_link = 0u32;
    let mut backbone = |_: ()| {
        let a = 0xAC10_0000 + 2 * next_link;
        next_link += 1;
        (v4(a), v4(a + 1))
    };
    // The link between hub `h` and the edge of site `s`, and between 2 hubs.
    let mut edge_links: BTreeMap<(usize, usize), (IpAddr, IpAddr)> = BTreeMap::new();
    for s in hubs..sites {
        for h in site_hubs(s) {
            edge_links.entry((h, s)).or_insert_with(|| backbone(()));
        }
    }
    let mut hub_links: BTreeMap<(usize, usize), (IpAddr, IpAddr)> = BTreeMap::new();
    for h in 0..hubs {
        for k in h + 1..hubs {
            hub_links.insert((h, k), backbone(()));
        }
    }

    for site in 0..sites {
        let fw = fw_name(site);
        let edge = edge_name(site);
        let cores = [core_name(site, 0), core_name(site, 1)];

        // The access routers.
        for a in 0..ACCESS {
            let mut n = Node::new(access_name(site, a), nxos(), "nexthop");
            let up: Vec<usize> = (0..2)
                .map(|c| n.iface(&format!("up{c}"), ingress(&cores[c], &format!("acc{a}"))))
                .collect();
            let vl: Vec<usize> = (0..VLANS)
                .map(|v| n.iface(&format!("vlan{v}"), None))
                .collect();
            let mut gws = Vec::new();
            for c in 0..2 {
                let (core_addr, _) = site_link(site, core_access_link(c, a));
                n.connected(link_net(core_addr), up[c]);
                n.link_peer(core_addr, up[c], &cores[c]);
                gws.push((up[c], Some(core_addr)));
            }
            for (v, &i) in vl.iter().enumerate() {
                n.connected(user_network(site, a, v), i);
            }
            for oa in (0..ACCESS).filter(|x| *x != a) {
                for v in 0..VLANS {
                    n.route(
                        user_network(site, oa, v),
                        RouteKind::Learned(RouteProtocol::Ospf),
                        &gws,
                    );
                }
            }
            n.route(
                dmz_network(site),
                RouteKind::Learned(RouteProtocol::Ospf),
                &gws,
            );
            n.route(
                Prefix::new(v4(0), 0),
                RouteKind::Learned(RouteProtocol::Ospf),
                &gws,
            );
            let t = target(&mut g, ACCESS_ROUTES);
            fill(&mut n, &mut g, t, &|_| gws.clone());
            for k in (0..USERS).filter(|k| user(site, *k).0 == a) {
                let (_, v, addr) = user(site, k);
                let id = format!("s{site:04}-u{k:02}");
                let iface = vl[v];
                n.neighbour(
                    addr,
                    iface,
                    NeighbourTarget::Endpoint(EndpointId::new(&id)),
                    &id,
                );
                let device = n.name.clone();
                add_endpoint(&mut b, &id, addr, &device, &format!("vlan{v}"));
            }
            for v in 0..VLANS {
                b.edge_interface(EdgeInterface {
                    device: n.name.as_str().into(),
                    interface: InterfaceId::new(format!("vlan{v}")),
                    networks: vec![user_network(site, a, v)],
                    provenance: vec![SourceSpan::line(format!("{}.conf", n.name), 1)],
                });
            }
            counts.routes += n.finish(&mut b, "route", Vec::new(), Vec::new());
            counts.routers += 1;
        }

        // The core routers.
        for (c, core) in cores.iter().enumerate() {
            let mut n = Node::new(core.clone(), nxos(), "nexthop");
            let acc: Vec<usize> = (0..ACCESS)
                .map(|a| {
                    n.iface(
                        &format!("acc{a}"),
                        ingress(&access_name(site, a), &format!("up{c}")),
                    )
                })
                .collect();
            let fwi = n.iface("fw", ingress(&fw, &format!("in{c}")));
            for (a, &i) in acc.iter().enumerate() {
                let (_, acc_addr) = site_link(site, core_access_link(c, a));
                n.connected(link_net(acc_addr), i);
                n.link_peer(acc_addr, i, &access_name(site, a));
                for v in 0..VLANS {
                    n.route(
                        user_network(site, a, v),
                        RouteKind::Learned(RouteProtocol::Ospf),
                        &[(i, Some(acc_addr))],
                    );
                }
            }
            let (fw_addr, _) = site_link(site, fw_core_link(c));
            n.connected(link_net(fw_addr), fwi);
            n.link_peer(fw_addr, fwi, &fw);
            let via_fw = [(fwi, Some(fw_addr))];
            n.route(dmz_network(site), RouteKind::Static, &via_fw);
            for (_, p) in all_sites.iter().enumerate().filter(|(s, _)| *s != site) {
                n.route(*p, RouteKind::Learned(RouteProtocol::Bgp), &via_fw);
            }
            n.route(Prefix::new(v4(0), 0), RouteKind::Static, &via_fw);
            let t = target(&mut g, CORE_ROUTES);
            fill(&mut n, &mut g, t, &|_| via_fw.to_vec());
            counts.routes += n.finish(&mut b, "route", Vec::new(), Vec::new());
            counts.routers += 1;
        }

        // The firewall.
        {
            let mut n = Node::new(fw.clone(), fortios(), "zone-dst");
            let ins: Vec<usize> = (0..2)
                .map(|c| n.iface(&format!("in{c}"), ingress(&cores[c], "fw")))
                .collect();
            let out = n.iface("out", ingress(&edge, "fw"));
            let dmz = n.iface("dmz", None);
            let mut gws = Vec::new();
            for c in 0..2 {
                let (_, core_addr) = site_link(site, fw_core_link(c));
                n.connected(link_net(core_addr), ins[c]);
                n.link_peer(core_addr, ins[c], &cores[c]);
                gws.push((ins[c], Some(core_addr)));
            }
            let (edge_addr, _) = site_link(site, EDGE_FW_LINK);
            n.connected(link_net(edge_addr), out);
            n.link_peer(edge_addr, out, &edge);
            n.connected(dmz_network(site), dmz);
            for a in 0..ACCESS {
                for v in 0..VLANS {
                    n.route(user_network(site, a, v), RouteKind::Static, &gws);
                }
            }
            n.route(
                Prefix::new(v4(0), 0),
                RouteKind::Static,
                &[(out, Some(edge_addr))],
            );
            let t = target(&mut g, FIREWALL_ROUTES);
            fill(&mut n, &mut g, t, &|_| vec![(out, Some(edge_addr))]);
            for k in 0..SERVERS {
                let id = format!("s{site:04}-srv{k}");
                let addr = server(site, k);
                n.neighbour(
                    addr,
                    dmz,
                    NeighbourTarget::Endpoint(EndpointId::new(&id)),
                    &id,
                );
                add_endpoint(&mut b, &id, addr, &fw, "dmz");
            }
            b.edge_interface(EdgeInterface {
                device: fw.as_str().into(),
                interface: InterfaceId::new("dmz"),
                networks: vec![dmz_network(site)],
                provenance: vec![SourceSpan::line(format!("{fw}.conf"), 1)],
            });
            let zones: BTreeMap<InterfaceId, ZoneId> = [
                ("in0", "inside"),
                ("in1", "inside"),
                ("out", "outside"),
                ("dmz", "dmz"),
            ]
            .into_iter()
            .map(|(i, z)| (InterfaceId::new(i), ZoneId::new(z)))
            .collect();
            let unzoned = n.profile.unzoned_interface;
            let before: Vec<Arc<dyn rsim_core::NetFunction>> = vec![
                Arc::new(ZoneLookup {
                    meta: n.meta("zone-src"),
                    role: ZoneRole::Source,
                    by_interface: zones.clone(),
                    unzoned,
                    next: n.id("session-lookup"),
                }),
                Arc::new(SessionLookup {
                    meta: n.meta("session-lookup"),
                    next: n.id("route"),
                    states: StateActions::default(),
                }),
            ];
            let rules = rules(site, &mut g, &mut n);
            counts.rules += rules.len();
            let after: Vec<Arc<dyn rsim_core::NetFunction>> = vec![
                Arc::new(ZoneLookup {
                    meta: n.meta("zone-dst"),
                    role: ZoneRole::Destination,
                    by_interface: zones,
                    unzoned,
                    next: n.id("policy"),
                }),
                Arc::new(FirewallPolicy::new(
                    n.meta("policy"),
                    ObjectId::new(format!("{fw}:policy")),
                    rules,
                    n.profile.firewall_default,
                    n.id("session-commit"),
                )),
                Arc::new(SessionCommit {
                    meta: n.meta("session-commit"),
                    next: n.id("nexthop"),
                    keep_untranslated: true,
                }),
            ];
            counts.routes += n.finish(&mut b, "zone-src", before, after);
            counts.firewalls += 1;
        }

        // The edge router, or the hub router of a hub site.
        {
            let mut n = Node::new(edge.clone(), nxos(), "nexthop");
            let fwi = n.iface("fw", ingress(&fw, "out"));
            let (_, fw_addr) = site_link(site, EDGE_FW_LINK);
            n.connected(link_net(fw_addr), fwi);
            n.link_peer(fw_addr, fwi, &fw);
            n.route(
                site_network(site),
                RouteKind::Static,
                &[(fwi, Some(fw_addr))],
            );
            if site >= hubs {
                let mut gws = Vec::new();
                for (w, h) in site_hubs(site).into_iter().enumerate() {
                    let (hub_addr, _) = edge_links[&(h, site)];
                    let i = n.iface(
                        &format!("wan{w}"),
                        ingress(&edge_name(h), &format!("e{site:04}")),
                    );
                    n.connected(link_net(hub_addr), i);
                    n.link_peer(hub_addr, i, &edge_name(h));
                    gws.push((i, Some(hub_addr)));
                }
                for p in all_sites
                    .iter()
                    .enumerate()
                    .filter(|(s, _)| *s != site)
                    .map(|(_, p)| p)
                {
                    n.route(*p, RouteKind::Learned(RouteProtocol::Bgp), &gws);
                }
                n.route(
                    Prefix::new(v4(0), 0),
                    RouteKind::Learned(RouteProtocol::Bgp),
                    &gws,
                );
                let t = target(&mut g, EDGE_ROUTES);
                fill(&mut n, &mut g, t, &|_| gws.clone());
            } else {
                let h = site;
                // The links to the edges of the region and to the other hubs.
                let mut to_edge: BTreeMap<usize, Hop> = BTreeMap::new();
                for (&(_, s), &(_, edge_addr)) in edge_links.range((h, 0)..(h + 1, 0)) {
                    let i = n.iface(
                        &format!("e{s:04}"),
                        ingress(&edge_name(s), &wan_of(s, h, hubs)),
                    );
                    n.connected(link_net(edge_addr), i);
                    n.link_peer(edge_addr, i, &edge_name(s));
                    to_edge.insert(s, (i, Some(edge_addr)));
                }
                let mut to_hub: BTreeMap<usize, Hop> = BTreeMap::new();
                for k in (0..hubs).filter(|k| *k != h) {
                    let (lo, hi) = hub_links[&(h.min(k), h.max(k))];
                    let (_, far) = if h < k { (lo, hi) } else { (hi, lo) };
                    let i = n.iface(
                        &format!("h{k:04}"),
                        ingress(&edge_name(k), &format!("h{h:04}")),
                    );
                    n.connected(link_net(far), i);
                    n.link_peer(far, i, &edge_name(k));
                    to_hub.insert(k, (i, Some(far)));
                }
                let up = n.iface("internet", None);
                let up_gw = v4(0xC633_6400 + 2 * h as u32 + 1);
                n.connected(Prefix::new(up_gw, 31), up);
                n.link_peer(up_gw, up, "upstream");
                for (s, p) in all_sites.iter().enumerate().filter(|(s, _)| *s != site) {
                    let hops: Vec<Hop> = if let Some(hop) = to_edge.get(&s) {
                        vec![*hop]
                    } else if let Some(hop) = to_hub.get(&s) {
                        vec![*hop]
                    } else {
                        let mut v: Vec<Hop> = site_hubs(s)
                            .iter()
                            .filter_map(|k| to_hub.get(k).copied())
                            .collect();
                        v.dedup();
                        v
                    };
                    n.route(*p, RouteKind::Learned(RouteProtocol::Bgp), &hops);
                }
                n.route(
                    Prefix::new(v4(0), 0),
                    RouteKind::Learned(RouteProtocol::Bgp),
                    &[(up, Some(up_gw))],
                );
                let ways: Vec<Hop> = to_hub
                    .values()
                    .copied()
                    .chain([(up, Some(up_gw))])
                    .collect();
                let t = target(&mut g, HUB_ROUTES);
                fill(&mut n, &mut g, t, &|k| vec![ways[k % ways.len()]]);
                if h < full {
                    let before = n.fib.len();
                    full_table(&mut n, &mut g, opts.full_table, up, up_gw);
                    counts.full_table_routes += n.fib.len() - before;
                }
            }
            counts.routes += n.finish(&mut b, "route", Vec::new(), Vec::new());
            counts.routers += 1;
        }
        counts.endpoints += USERS + SERVERS;
    }
    ScaleEstate { builder: b, counts }
}

/// The interface of the edge of site `s` toward hub `h`.
fn wan_of(s: usize, h: usize, hubs: usize) -> String {
    let w = if s % hubs == h { 0 } else { 1 };
    format!("wan{w}")
}

fn add_endpoint(b: &mut TwinBuilder, id: &str, addr: IpAddr, device: &str, iface: &str) {
    let span = SourceSpan::line(format!("{device}.clients"), 1);
    b.endpoint(Endpoint {
        id: EndpointId::new(id),
        addresses: vec![addr],
    });
    b.attachment(AttachmentRecord {
        address: addr,
        device: device.into(),
        interface: InterfaceId::new(iface),
        kind: AttachmentKind::Client,
        host: id.to_string(),
        provenance: vec![span],
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsim_core::{Header, PROTO_TCP, VerdictKind};
    use rsim_engine::{Answer, Executor, Query};

    fn kinds(a: &Answer) -> Vec<Option<VerdictKind>> {
        a.summary.iter().map(|p| p.summary.kind()).collect()
    }

    fn small() -> ScaleOpts {
        ScaleOpts {
            sites: 4,
            fill_tables: true,
            full_table: (2000, 400),
            full_table_routers: 1,
        }
    }

    #[test]
    fn the_estate_has_the_counts_of_its_size() {
        let e = scale_estate(small());
        let c = e.counts;
        assert_eq!(c.routers, 4 * 10);
        assert_eq!(c.firewalls, 4);
        assert_eq!(c.rules, 4 * RULES);
        assert_eq!(c.endpoints, 4 * (USERS + SERVERS));
        assert_eq!(c.hubs, 2);
        let twin = e.builder.build().unwrap();
        assert_eq!(twin.device_count(), c.routers + c.firewalls);
        assert_eq!(twin.endpoints().count(), c.endpoints);
    }

    #[test]
    fn two_builds_give_the_same_estate() {
        let a = scale_estate(small());
        let b = scale_estate(small());
        assert_eq!(a.counts, b.counts);
        let ids = |e: ScaleEstate| {
            e.builder
                .build()
                .unwrap()
                .functions()
                .map(|f| f.id().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(a), ids(b));
    }

    #[test]
    fn a_user_reaches_a_server_of_another_site_and_the_reply_comes_back() {
        let twin = scale_estate(small()).builder.build().unwrap();
        let (_, _, src) = user(3, 5);
        let h = Header::request(src, server(2, 1), PROTO_TCP)
            .with_src_port(40000)
            .with_dst_port(443);
        let mut q = Query::path(&twin, &h);
        q.reply = true;
        let a = Executor::new(&twin).run(&q).unwrap();
        assert_eq!(
            kinds(&a),
            vec![Some(VerdictKind::Deliver)],
            "{:?}",
            a.summary
        );
        assert!(!a.replies.is_empty());
    }

    #[test]
    fn the_firewall_denies_a_port_that_no_rule_permits() {
        let twin = scale_estate(small()).builder.build().unwrap();
        let (_, _, src) = user(3, 5);
        let h = Header::request(src, server(2, 1), PROTO_TCP)
            .with_src_port(40000)
            .with_dst_port(444);
        let a = Executor::new(&twin).run(&Query::path(&twin, &h)).unwrap();
        assert_eq!(kinds(&a), vec![Some(VerdictKind::Drop)], "{:?}", a.summary);
    }
}
