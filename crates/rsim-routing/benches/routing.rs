//! The routing benchmark: a generated estate of `RSIM_ROUTING_SITES` EVPN
//! sites (default 50) and 2 WAN hubs. A site has 20 NX-OS devices: 2 spines
//! that reflect the EVPN routes, 16 leaves and 2 border leaves. Each leaf
//! has `RSIM_ROUTING_TENANTS` tenant networks of length 26 (default 4) in
//! the VRF `PROD`, redistributed from its connected routes and advertised as
//! EVPN IP prefix routes. The first border leaf of each site has an eBGP
//! session in `PROD` to the first hub, and the second border leaf to the
//! second hub, both of AS 64000. Each site runs OSPF in area 0 over the
//! point-to-point links of its spines. A counting allocator measures the
//! live heap and the peak above the start of each measure.
//!
//! The benchmark prints the count of devices, processes, sessions and
//! tenant networks, and the time and the peak heap of the build of the OSPF
//! databases, of the shortest-path calculation of each router and of the
//! BGP calculation, with the count of prefix groups, of routes, of the
//! rounds of the forward passes and of the groups of each convergence
//! result. When the live heap passes `RSIM_ROUTING_CAP_GIB` GiB (default
//! 12), the process stops.

// The global allocator needs `unsafe`. It is only in this benchmark binary.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Instant;

use rsim_core::{Prefix, SourceSpan};
use rsim_routing::Platform;
use rsim_routing::bgp::{
    AdminValue, Asn, BgpInput, BgpProcess, ConvergenceKind, Event, Family, IgpRoute, IgpSource,
    IgpView, Neighbor, RedistSource, Redistribution, Resolution, RouteDistinguisher, Session,
    SessionEnd, compute,
};
use rsim_routing::ospf::build::{RouterInput, build};
use rsim_routing::ospf::config::{Area, NetworkType, OspfInterface, Process, RouterConfig};
use rsim_routing::ospf::{AreaType, BACKBONE, OspfProfile, Version};

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);
static CAP: AtomicIsize = AtomicIsize::new(isize::MAX);

fn grew(by: isize) {
    let now = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(now, Ordering::Relaxed);
    if now > CAP.load(Ordering::Relaxed) {
        let _ = std::io::stderr().write_all(b"the live heap passed the cap; stop\n");
        std::process::abort();
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        grew(l.size() as isize);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        grew(n as isize - l.size() as isize);
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static A: Counting = Counting;

/// Sets the peak to the live heap, and gives the live heap.
fn reset_peak() -> isize {
    let now = LIVE.load(Ordering::Relaxed);
    PEAK.store(now, Ordering::Relaxed);
    now
}

/// The peak above `start` in MiB.
fn peak_above(start: isize) -> f64 {
    (PEAK.load(Ordering::Relaxed) - start) as f64 / (1024.0 * 1024.0)
}

fn out(line: String) {
    let mut o = std::io::stdout().lock();
    let _ = writeln!(o, "{line}");
    let _ = o.flush();
}

fn env_num(k: &str, default: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

const LEAVES: u8 = 16;
/// The device indexes of a site: 1 and 2 are the spines, 3 to 18 the
/// leaves, 19 and 20 the border leaves.
const DEVICES: u8 = 20;
const VRF: &str = "PROD";
const HUB_AS: u32 = 64000;

fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

fn span() -> SourceSpan {
    SourceSpan::new("bench", 1, 1)
}

fn name(site: u8, i: u8) -> String {
    match i {
        1 | 2 => format!("s{site}-spine{i}"),
        19 | 20 => format!("s{site}-bl{}", i - 18),
        _ => format!("s{site}-leaf{}", i - 2),
    }
}

/// The router ID and the address of loopback 0.
fn lo0(site: u8, i: u8) -> Ipv4Addr {
    v4(10, 255, site, i)
}

/// The tunnel end address of loopback 1.
fn lo1(site: u8, i: u8) -> Ipv4Addr {
    v4(10, 254, site, i)
}

/// The addresses of the link of spine `k` to the device `j`: the spine end
/// and the device end of a /31.
fn link(site: u8, k: u8, j: u8) -> (Ipv4Addr, Ipv4Addr) {
    (
        v4(10, 100 + k, site, 2 * j),
        v4(10, 100 + k, site, 2 * j + 1),
    )
}

/// The addresses of the link of border leaf `k` of a site to hub `k`: the
/// hub end and the border leaf end of a /31.
fn hub_link(site: u8, k: u8) -> (Ipv4Addr, Ipv4Addr) {
    (v4(100, 63 + k, site, 0), v4(100, 63 + k, site, 1))
}

fn tenant(site: u8, leaf: u8, t: u8) -> Prefix {
    Prefix::new(
        IpAddr::V4(v4(172, 16 + site / 16, (site % 16) * 16 + leaf, 64 * t)),
        26,
    )
}

fn ospf_if(n: &str, addr: Ipv4Addr, len: u8, network: NetworkType, cost: u32) -> OspfInterface {
    OspfInterface {
        name: n.to_string(),
        area: BACKBONE,
        address: Some((IpAddr::V4(addr), len)),
        secondaries: Vec::new(),
        cost: Some(cost),
        bandwidth_kbps: None,
        network,
        passive: false,
        priority: 1,
        up: true,
        span: span(),
    }
}

/// The OSPF input of device `i` of a site.
fn ospf_router(site: u8, i: u8) -> RouterInput {
    let mut interfaces = vec![
        ospf_if("loopback0", lo0(site, i), 32, NetworkType::Loopback, 1),
        ospf_if("loopback1", lo1(site, i), 32, NetworkType::Loopback, 1),
    ];
    if i <= 2 {
        for j in 3..=DEVICES {
            let (a, _) = link(site, i, j);
            let n = format!("Ethernet1/{j}");
            interfaces.push(ospf_if(&n, a, 31, NetworkType::PointToPoint, 10));
        }
    } else {
        for k in 1..=2 {
            let (_, b) = link(site, k, i);
            let n = format!("Ethernet1/{}", 48 + k);
            interfaces.push(ospf_if(&n, b, 31, NetworkType::PointToPoint, 10));
        }
    }
    let process = Process {
        version: Version::V2,
        vrf: "default".to_string(),
        process: "UNDERLAY".to_string(),
        router_id: Some(lo0(site, i)),
        reference_bandwidth_mbps: None,
        areas: BTreeMap::from([(
            BACKBONE,
            Area {
                kind: AreaType::Normal,
                no_summary: false,
                default_cost: None,
                span: span(),
            },
        )]),
        interfaces,
        redistribute: Vec::new(),
        default_originate: None,
        passive_default: false,
        unhandled: Vec::new(),
        span: span(),
    };
    RouterInput::new(
        RouterConfig {
            processes: vec![process],
        },
        Platform::Nxos,
    )
}

fn site_as(site: u8) -> u32 {
    64512 + u32::from(site)
}

fn neighbor(addr: Ipv4Addr, remote_as: u32, local: Ipv4Addr, family: Family) -> Neighbor {
    let mut n = Neighbor::new(IpAddr::V4(addr), Asn(remote_as));
    n.local_address = Some(IpAddr::V4(local));
    n.activated = BTreeSet::from([family]);
    n.send_community = true;
    n.send_community_extended = true;
    n
}

fn end(device: &str, vrf: &str, neighbor: Ipv4Addr) -> SessionEnd {
    SessionEnd {
        device: device.to_string(),
        vrf: vrf.to_string(),
        neighbor: IpAddr::V4(neighbor),
    }
}

/// The IGP view: the cost of each OSPF route of each device, and the
/// connected and local prefixes of each device and VRF.
#[derive(Default)]
struct View {
    ospf: BTreeMap<String, BTreeMap<Prefix, u32>>,
    connected: BTreeMap<(String, String), Vec<Prefix>>,
}

impl IgpView for View {
    fn resolve(&self, device: &str, vrf: &str, nh: IpAddr) -> Resolution {
        if let Some(c) = self.connected.get(&(device.to_string(), vrf.to_string()))
            && c.iter().any(|p| p.contains(nh))
        {
            return Resolution::Resolved { cost: 0 };
        }
        if vrf == "default"
            && let Some(m) = self.ospf.get(device).and_then(|r| r.get(&Prefix::host(nh)))
        {
            return Resolution::Resolved { cost: *m };
        }
        Resolution::Unresolved
    }

    fn has_route(&self, _device: &str, _vrf: &str, _prefix: Prefix) -> Option<bool> {
        Some(false)
    }
}

fn main() {
    let sites = env_num("RSIM_ROUTING_SITES", 50).min(255) as u8;
    let tenants = env_num("RSIM_ROUTING_TENANTS", 4).min(4) as u8;
    let cap = env_num("RSIM_ROUTING_CAP_GIB", 12);
    CAP.store((cap as isize) << 30, Ordering::Relaxed);

    let start = reset_peak();
    let t = Instant::now();
    let mut ospf_in: BTreeMap<String, RouterInput> = BTreeMap::new();
    let mut input = BgpInput::default();
    let mut view = View::default();
    let hubs = ["hub1", "hub2"];
    for (k, h) in hubs.iter().enumerate() {
        let k = k as u8 + 1;
        let mut p = BgpProcess::new(
            *h,
            "default",
            Some(Platform::Iosxe),
            Asn(HUB_AS),
            v4(10, 253, 0, k),
        );
        let mut connected = Vec::new();
        for s in 0..sites {
            let (hub, bl) = hub_link(s, k);
            p.neighbors.insert(
                IpAddr::V4(bl),
                neighbor(bl, site_as(s), hub, Family::Ipv4Unicast),
            );
            connected.push(Prefix::new(IpAddr::V4(hub), 31));
            input.sessions.push(Session {
                a: end(h, "default", bl),
                b: end(&name(s, 18 + k), VRF, hub),
            });
        }
        view.connected
            .insert((h.to_string(), "default".to_string()), connected);
        input.processes.push(p);
    }
    for s in 0..sites {
        let asn = site_as(s);
        let rt = AdminValue::As2 {
            asn: asn as u16,
            value: 50001,
        };
        for i in 1..=DEVICES {
            let d = name(s, i);
            ospf_in.insert(d.clone(), ospf_router(s, i));
            let mut p = BgpProcess::new(
                d.clone(),
                "default",
                Some(Platform::Nxos),
                Asn(asn),
                lo0(s, i),
            );
            let mut connected = vec![
                Prefix::host(IpAddr::V4(lo0(s, i))),
                Prefix::host(IpAddr::V4(lo1(s, i))),
            ];
            if i <= 2 {
                for j in 3..=DEVICES {
                    let mut n = neighbor(lo0(s, j), asn, lo0(s, i), Family::EvpnIpPrefix);
                    n.route_reflector_client = true;
                    p.neighbors.insert(IpAddr::V4(lo0(s, j)), n);
                    input.sessions.push(Session {
                        a: end(&d, "default", lo0(s, j)),
                        b: end(&name(s, j), "default", lo0(s, i)),
                    });
                    connected.push(Prefix::new(IpAddr::V4(link(s, i, j).0), 31));
                }
            } else {
                for k in 1..=2 {
                    p.neighbors.insert(
                        IpAddr::V4(lo0(s, k)),
                        neighbor(lo0(s, k), asn, lo0(s, i), Family::EvpnIpPrefix),
                    );
                    connected.push(Prefix::new(IpAddr::V4(link(s, k, i).1), 31));
                }
                let mut vrf =
                    BgpProcess::new(d.clone(), VRF, Some(Platform::Nxos), Asn(asn), lo0(s, i));
                vrf.targets.rd = Some(RouteDistinguisher(AdminValue::Ipv4 {
                    addr: lo0(s, i),
                    value: 3,
                }));
                vrf.targets.evpn_import = BTreeSet::from([rt]);
                vrf.targets.evpn_export = BTreeSet::from([rt]);
                vrf.targets.advertise_evpn = true;
                vrf.targets.evpn_next_hop = Some(IpAddr::V4(lo1(s, i)));
                let mut vrf_connected = Vec::new();
                if i <= 2 + LEAVES {
                    vrf.redistributions.push(Redistribution {
                        family: Family::Ipv4Unicast,
                        source: RedistSource::Connected,
                        ospf_match: None,
                        policy: None,
                        metric: None,
                        spans: Vec::new(),
                    });
                    for t in 0..tenants {
                        let prefix = tenant(s, i - 3, t);
                        vrf_connected.push(prefix);
                        input.igp_routes.push(IgpRoute {
                            device: d.clone(),
                            vrf: VRF.to_string(),
                            prefix,
                            source: IgpSource::Connected,
                            metric: 0,
                            tag: None,
                            next_hop: None,
                            unknown: None,
                            spans: Vec::new(),
                        });
                    }
                } else {
                    let k = i - 18;
                    let (hub, bl) = hub_link(s, k);
                    vrf.neighbors.insert(
                        IpAddr::V4(hub),
                        neighbor(hub, HUB_AS, bl, Family::Ipv4Unicast),
                    );
                    vrf_connected.push(Prefix::new(IpAddr::V4(bl), 31));
                }
                view.connected
                    .insert((d.clone(), VRF.to_string()), vrf_connected);
                input.processes.push(vrf);
            }
            view.connected.insert((d, "default".to_string()), connected);
            input.processes.push(p);
        }
    }
    let devices = usize::from(sites) * usize::from(DEVICES) + hubs.len();
    out(format!(
        "estate: {sites} sites, {devices} devices, {} processes, {} sessions, {} tenant networks, generated in {:.2} s, {:.1} MiB",
        input.processes.len(),
        input.sessions.len(),
        input.igp_routes.len(),
        t.elapsed().as_secs_f64(),
        peak_above(start)
    ));

    let start = reset_peak();
    let t = Instant::now();
    let built = build(&ospf_in);
    out(format!(
        "ospf build: {} databases in {:.2} s, peak {:.1} MiB",
        built.databases.len(),
        t.elapsed().as_secs_f64(),
        peak_above(start)
    ));

    let start = reset_peak();
    let t = Instant::now();
    let profile = OspfProfile::of(Platform::Nxos);
    let mut routes = 0;
    for ((device, ..), db) in &built.databases {
        let Some(rid) = db.router_id else {
            continue;
        };
        let calc = rsim_routing::ospf::compute(db, rid, &profile);
        routes += calc.routes.len();
        let m = view.ospf.entry(device.clone()).or_default();
        for r in calc.routes {
            m.insert(r.prefix, r.metric);
        }
    }
    out(format!(
        "ospf shortest paths: {} routers, {routes} routes in {:.2} s, peak {:.1} MiB",
        built.databases.len(),
        t.elapsed().as_secs_f64(),
        peak_above(start)
    ));

    let start = reset_peak();
    let t = Instant::now();
    let r = compute(&input, &view).expect("the input is valid");
    let secs = t.elapsed().as_secs_f64();
    let rounds = r
        .events
        .iter()
        .filter(|e| matches!(e, Event::Round { .. }))
        .count();
    let searches = r
        .events
        .iter()
        .filter(|e| matches!(e, Event::Search { .. }))
        .count();
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for g in &r.groups {
        *kinds
            .entry(
                match g.convergence.kind() {
                    ConvergenceKind::Converged => "converged",
                    ConvergenceKind::MultipleStableOutcomes => "multiple stable outcomes",
                    ConvergenceKind::NoConvergence => "no convergence",
                    ConvergenceKind::Unknown => "unknown",
                }
                .to_string(),
            )
            .or_default() += 1;
    }
    let largest = r.groups.iter().map(|g| g.keys.len()).max().unwrap_or(0);
    out(format!(
        "bgp: {} prefix groups, largest {largest} keys, {} routes, {rounds} rounds with a change, {searches} searches, {kinds:?} in {secs:.2} s, peak {:.1} MiB",
        r.groups.len(),
        r.routes.len(),
        peak_above(start)
    ));
}
