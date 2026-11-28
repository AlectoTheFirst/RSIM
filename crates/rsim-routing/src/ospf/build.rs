//! The link-state databases of the twin from the OSPF configs of its routers
//! (RFC 2328 sections 9.4 and 12.4, RFC 5340 for OSPFv3, RFC 3101 for the
//! NSSA).
//!
//! - 2 up, non-passive OSPF interfaces of 2 processes are neighbours when
//!   they are in one subnet, one VRF, one version, one area with one area
//!   type, and have one network type. A broadcast segment elects its
//!   designated router by the priority, then by the router ID. Priority 0 is
//!   never elected.
//! - The flooding scope of an area is a connected component of the
//!   adjacencies in that area. The AS of a process is the connected
//!   component of the adjacencies in all areas.
//! - An area border router originates the summary LSAs of the intra-area
//!   routes of each attached area into its other areas, and the summary LSAs
//!   of its inter-area routes of the backbone into its other areas. It
//!   computes these routes with [`compute`] on the LSAs of one area.
//! - An ASBR in an NSSA that originates no AS-external LSA sets the P bit
//!   of its NSSA LSAs and gives them a forwarding address (RFC 3101 2.3 and
//!   2.4). The translator of an NSSA is the NSSA border router with the
//!   highest router ID that the NSSA calculation of each other router of the
//!   NSSA reaches (RFC 3101 3.1). It translates the NSSA LSAs of its routes
//!   with the P bit into AS-external LSAs with the same forwarding address,
//!   except the default route (RFC 3101 3.2). A left-out border router, a
//!   border router that a gap hides, or an NSSA with no reached border
//!   router gives a gap of the AS-external LSAs of the AS.
//! - `redistribute bgp` gives the external LSAs of the installed BGP routes
//!   of the VRF of the round before, other than a default route. An iBGP
//!   route is redistributed only when the BGP profile of the platform
//!   offers the iBGP routes. An unknown BGP route gives a gap of its prefix.
//!   With no BGP routes of the VRF, the redistribution is not evaluated.
//! - The process with an unhandled line, or with an active interface with no
//!   address of its version, originates no LSA, so the calculation of each
//!   neighbour sees a gap. Each area of the process has a gap of its
//!   interface prefixes and its redistributed prefixes. The AS has a gap of
//!   AS-external LSAs when the process redistributes from a source that is
//!   not evaluated or has `default-information originate`.
//! - A gap of a process in an area where the process has no neighbour is a
//!   gap of each area instance with that area ID in the VRF and the version.
//! - An area border router carries the gaps of the prefixes of a left-out
//!   router in an area into its summary LSAs of the other areas.
//! - LSAs that the builder leaves out are gaps of each database of their
//!   flooding scope (`Database::gaps`): the AS for an AS-external LSA, the
//!   area for a summary or an NSSA LSA. In the database of the router that
//!   leaves them out, they are in `Database::own_gaps`.
//! - The LSAs have no sequence number and no age.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rsim_core::{Prefix, SourceSpan};

use super::config::{Area, NetworkType, OspfInterface, Process, RouterConfig, Source};
use super::{
    AreaId, AreaType, BACKBONE, Body, Database, Gap, GapReach, Interface, LinkKind, Lsa, LsaKey,
    LsaType, Neighbor, Note, OspfProfile, PathType, Reference, RouterId, RouterLink, Version,
    compute,
};
use crate::platform::Platform;

/// The key of a database: the device, the VRF, the version and the process.
pub type ProcessKey = (String, String, Version, String);

/// An IPv4 address of a router for the router ID rule of its platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub interface: String,
    pub address: Ipv4Addr,
    pub loopback: bool,
    /// True if the interface is up.
    pub up: bool,
}

/// The OSPF config of one router and the facts of the router that the
/// builder needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterInput {
    pub config: RouterConfig,
    pub platform: Platform,
    /// By VRF: the prefixes of the connected routes for redistribution.
    pub connected: BTreeMap<String, Vec<Prefix>>,
    /// By VRF: the prefixes of the static routes for redistribution.
    pub statics: BTreeMap<String, Vec<Prefix>>,
    /// By VRF: the installed BGP routes for redistribution. A VRF with no
    /// entry has BGP routes that are not known.
    pub bgp: BTreeMap<String, BgpRoutes>,
    /// The VRFs whose route table has a default route that is not from
    /// OSPF.
    pub default_route: BTreeSet<String>,
    /// By VRF: the IPv4 addresses of the interfaces for the router ID rule.
    /// The rule also reads the addresses of the OSPF interfaces.
    pub addresses: BTreeMap<String, Vec<Address>>,
    /// By interface name: the IPv6 link-local address for OSPFv3.
    pub link_local: BTreeMap<String, Ipv6Addr>,
}

impl RouterInput {
    pub fn new(config: RouterConfig, platform: Platform) -> RouterInput {
        RouterInput {
            config,
            platform,
            connected: BTreeMap::new(),
            statics: BTreeMap::new(),
            bgp: BTreeMap::new(),
            default_route: BTreeSet::new(),
            addresses: BTreeMap::new(),
            link_local: BTreeMap::new(),
        }
    }
}

/// The installed BGP routes of a VRF for a redistribution of BGP.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct BgpRoutes {
    /// The prefix of each installed BGP route, with true for a route from
    /// an iBGP or a confederation session.
    pub routes: BTreeMap<Prefix, bool>,
    /// The prefixes of the unknown BGP routes.
    pub unknown: BTreeSet<Prefix>,
}

/// The databases of the twin and the notes of the build.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Built {
    /// By device, VRF, version and process.
    pub databases: BTreeMap<ProcessKey, Database>,
    /// The notes by device.
    pub notes: Vec<(String, Note)>,
}

/// The router ID of a process with no configured router ID. The Cisco
/// platforms take the highest address of an up loopback, else the highest
/// address of an up interface. FRR takes the highest address of an up
/// interface. Not confirmed by a vendor document.
pub fn default_router_id(platform: Platform, addresses: &[Address]) -> Option<RouterId> {
    let usable: Vec<&Address> = addresses
        .iter()
        .filter(|a| a.up && !a.address.is_unspecified() && !a.address.is_loopback())
        .collect();
    let highest = usable.iter().map(|a| a.address).max();
    match platform {
        Platform::Iosxe | Platform::Iosxr | Platform::Nxos => usable
            .iter()
            .filter(|a| a.loopback)
            .map(|a| a.address)
            .max()
            .or(highest),
        Platform::FrrTraditional | Platform::FrrDatacenter => highest,
    }
}

/// The metric of the host prefix of a loopback. OSPFv2 on Cisco: the
/// configured cost, else 1. OSPFv2 on FRR and OSPFv3: 0. Not confirmed by a
/// vendor document.
pub fn loopback_cost(platform: Platform, version: Version, configured: Option<u32>) -> u32 {
    match (platform, version) {
        (_, Version::V3) => 0,
        (Platform::FrrTraditional | Platform::FrrDatacenter, Version::V2) => 0,
        (_, Version::V2) => configured.unwrap_or(1),
    }
}

/// The cost of an interface with no configured cost and no known bandwidth.
/// FRR: 10. The Cisco platforms: the cost of a 1 Gb/s interface. Not
/// confirmed by a vendor document.
pub fn unknown_bandwidth_cost(profile: &OspfProfile) -> u32 {
    match profile.platform {
        Platform::FrrTraditional | Platform::FrrDatacenter => 10,
        _ => profile.interface_cost(1_000_000),
    }
}

/// The metric of a redistributed route with no metric in the statement, from
/// HST `simul/platforms.py` `ospf_redistribute_metric`. Not confirmed by a
/// vendor document.
pub fn redistribute_metric(platform: Platform, source: &Source) -> u32 {
    match (platform, source) {
        (Platform::Iosxe, Source::Bgp) => 1,
        _ => 20,
    }
}

/// The metric of the default route of `default-information originate` with
/// no metric in the statement. The Cisco platforms: 1. FRR: 1 with
/// `always`, else 10. Not confirmed by a vendor document.
pub fn default_originate_metric(platform: Platform, always: bool) -> u32 {
    match platform {
        Platform::FrrTraditional | Platform::FrrDatacenter if !always => 10,
        _ => 1,
    }
}

/// An interface of a process and the interface index in its process.
type Ref = (usize, usize);

#[derive(Clone, Debug)]
enum Link {
    Stub,
    PointToPoint(Ref),
    Transit { dr: Ref, members: Vec<Ref> },
}

struct If<'a> {
    cfg: &'a OspfInterface,
    /// The OSPFv3 interface ID: 1 plus the position of the interface in the
    /// name order of the interfaces of the process.
    id: u32,
    cost: u32,
    /// The address of the family of the version. OSPFv3 takes the global
    /// address.
    addr: Option<IpAddr>,
    /// The subnet, the host prefix for a loopback.
    prefix: Option<Prefix>,
    link: Link,
}

struct Proc<'a> {
    key: ProcessKey,
    input: &'a RouterInput,
    cfg: &'a Process,
    profile: OspfProfile,
    rid: Option<RouterId>,
    /// True if the process has an unhandled line.
    left_out: bool,
    /// The up interfaces.
    ifs: Vec<If<'a>>,
}

impl Proc<'_> {
    fn version(&self) -> Version {
        self.key.2
    }

    fn subject(&self) -> String {
        format!(
            "{}/{}/{}",
            self.cfg.vrf,
            self.version().name(),
            self.cfg.process
        )
    }

    fn originates(&self) -> bool {
        self.rid.is_some() && !self.left_out
    }

    fn areas(&self) -> BTreeSet<AreaId> {
        if self.rid.is_none() {
            return BTreeSet::new();
        }
        self.ifs.iter().map(|f| f.cfg.area).collect()
    }

    fn area(&self, area: AreaId) -> Option<&Area> {
        self.cfg.areas.get(&area)
    }

    fn area_type(&self, area: AreaId) -> AreaType {
        self.area(area).map_or(AreaType::Normal, |a| a.kind)
    }

    fn no_summary(&self, area: AreaId) -> bool {
        self.area(area).is_some_and(|a| a.no_summary)
    }

    fn abr(&self) -> bool {
        let areas = self.areas();
        self.originates() && areas.contains(&BACKBONE) && areas.len() > 1
    }
}

struct UnionFind(Vec<usize>);

impl UnionFind {
    fn add(&mut self) -> usize {
        self.0.push(self.0.len());
        self.0.len() - 1
    }

    fn find(&self, mut x: usize) -> usize {
        while self.0[x] != x {
            x = self.0[x];
        }
        x
    }

    fn union(&mut self, a: usize, b: usize) {
        let (a, b) = (self.find(a), self.find(b));
        if a != b {
            let (lo, hi) = (a.min(b), a.max(b));
            self.0[hi] = lo;
        }
    }
}

/// One external route of an ASBR.
#[derive(Clone, Debug)]
struct Ext {
    metric: u32,
    metric_type: u8,
    /// True for a connected route. The next hop of a static route or of the
    /// default route is not known, and the forwarding address of its NSSA
    /// LSA is not known.
    connected: bool,
    span: SourceSpan,
}

/// The routes of an area border router in each attached area.
#[derive(Default)]
struct AbrView {
    intra: BTreeMap<AreaId, BTreeMap<Prefix, u32>>,
    asbrs: BTreeMap<AreaId, BTreeMap<RouterId, u32>>,
    /// The areas whose intra-area routes depend on a gap of the database.
    incomplete: BTreeSet<AreaId>,
    /// By area: the prefixes of the router gaps with a list of prefixes.
    left: BTreeMap<AreaId, BTreeSet<Prefix>>,
}

type Store = BTreeMap<LsaKey, Lsa>;

struct Builder<'a> {
    procs: Vec<Proc<'a>>,
    notes: Vec<Vec<Note>>,
    global: Vec<(String, Note)>,
    uf: UnionFind,
    /// The node of each process and area.
    nodes: BTreeMap<(usize, AreaId), usize>,
    /// The node of the AS of each process.
    as_nodes: BTreeMap<usize, usize>,
    area_store: BTreeMap<usize, Store>,
    as_store: BTreeMap<usize, Store>,
    link_store: BTreeMap<Ref, Lsa>,
    asbrs: BTreeSet<usize>,
    /// The gaps of each area instance and of each AS.
    area_gaps: BTreeMap<usize, Vec<Gap>>,
    as_gaps: BTreeMap<usize, Vec<Gap>>,
    /// The NSSA LSAs with the P bit, by area instance, advertising router and
    /// prefix.
    p_bit: BTreeSet<(usize, RouterId, Prefix)>,
}

fn family_ok(version: Version, a: IpAddr) -> bool {
    match (version, a) {
        (Version::V2, IpAddr::V4(_)) => true,
        (Version::V3, IpAddr::V6(v6)) => !link_local(v6),
        _ => false,
    }
}

fn link_local(a: Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

fn mask(len: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0))
}

fn v4(a: IpAddr) -> Option<Ipv4Addr> {
    match a {
        IpAddr::V4(a) => Some(a),
        IpAddr::V6(_) => None,
    }
}

fn default_prefix(version: Version) -> Prefix {
    match version {
        Version::V2 => Prefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        Version::V3 => Prefix::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn prefix_of(body: &Body) -> Option<Prefix> {
    match body {
        Body::Summary { prefix, .. } | Body::External { prefix, .. } => Some(*prefix),
        _ => None,
    }
}

fn new_lsa(
    lsa_type: LsaType,
    area: Option<AreaId>,
    lsid: Ipv4Addr,
    adv_router: RouterId,
    body: Body,
    span: SourceSpan,
) -> Lsa {
    Lsa {
        lsa_type,
        area,
        lsid,
        adv_router,
        seq: None,
        age: None,
        body,
        span,
    }
}

/// Adds a summary, an ASBR-summary or an external LSA. The OSPFv2
/// link-state ID of a prefix is its network address, with the host bits
/// set when another prefix of the router has that address (RFC 2328
/// appendix E). The OSPFv3 link-state ID of a prefix is the count of the
/// LSAs of that type of the router in the scope. Returns false when the
/// link-state ID is taken.
fn add_prefix_lsa(store: &mut Store, version: Version, mut lsa: Lsa) -> bool {
    let same = |s: &Store, lsid: Ipv4Addr, l: &Lsa| {
        s.get(&LsaKey {
            no_area: l.area.is_none(),
            area: l.area.unwrap_or(BACKBONE),
            lsa_type: l.lsa_type,
            lsid,
            adv_router: l.adv_router,
        })
        .is_some()
    };
    if let Some(prefix) = prefix_of(&lsa.body) {
        match version {
            Version::V2 => {
                let net = v4(prefix.addr()).unwrap_or(Ipv4Addr::UNSPECIFIED);
                let host = Ipv4Addr::from(u32::from(net) | !u32::from(mask(prefix.len())));
                let Some(lsid) = [net, host].into_iter().find(|id| !same(store, *id, &lsa)) else {
                    return false;
                };
                lsa.lsid = lsid;
            }
            Version::V3 => {
                let count = store
                    .values()
                    .filter(|l| {
                        l.lsa_type == lsa.lsa_type
                            && l.adv_router == lsa.adv_router
                            && l.area == lsa.area
                    })
                    .count();
                lsa.lsid = Ipv4Addr::from(count as u32);
            }
        }
    }
    if same(store, lsa.lsid, &lsa) {
        return false;
    }
    store.insert(lsa.key(), lsa);
    true
}

impl<'a> Builder<'a> {
    fn new(routers: &'a BTreeMap<String, RouterInput>) -> Builder<'a> {
        let mut b = Builder {
            procs: Vec::new(),
            notes: Vec::new(),
            global: Vec::new(),
            uf: UnionFind(Vec::new()),
            nodes: BTreeMap::new(),
            as_nodes: BTreeMap::new(),
            area_store: BTreeMap::new(),
            as_store: BTreeMap::new(),
            link_store: BTreeMap::new(),
            asbrs: BTreeSet::new(),
            area_gaps: BTreeMap::new(),
            as_gaps: BTreeMap::new(),
            p_bit: BTreeSet::new(),
        };
        for (device, input) in routers {
            for cfg in &input.config.processes {
                b.add_process(device, input, cfg);
            }
        }
        b
    }

    fn note(&mut self, pi: usize, kind: &str, detail: String) {
        let subject = self.procs[pi].subject();
        self.notes[pi].push(Note::new(kind, subject, detail));
    }

    fn stated(
        &self,
        pi: usize,
        lsa_type: LsaType,
        area: Option<AreaId>,
        reach: GapReach,
        detail: String,
    ) -> Gap {
        Gap {
            lsa_type,
            lsid: self.procs[pi].rid.unwrap_or(Ipv4Addr::UNSPECIFIED),
            area,
            detail,
            reach,
        }
    }

    /// Adds a gap to the area instance of a process in `area`.
    fn area_gap(
        &mut self,
        pi: usize,
        area: AreaId,
        lsa_type: LsaType,
        reach: GapReach,
        detail: String,
    ) {
        let Some(inst) = self.inst(pi, area) else {
            return;
        };
        let gap = self.stated(pi, lsa_type, Some(area), reach, detail);
        self.area_gaps.entry(inst).or_default().push(gap);
    }

    /// The processes whose area instance of `area` gets a gap of the process
    /// `pi`: the process `pi` and, when no interface of `pi` in `area` has a
    /// neighbour, each process of the same VRF and version in an area with
    /// that ID.
    fn gap_procs(&self, pi: usize, area: AreaId) -> BTreeSet<usize> {
        let p = &self.procs[pi];
        let linked = p
            .ifs
            .iter()
            .any(|f| f.cfg.area == area && !matches!(f.link, Link::Stub));
        let mut out = BTreeSet::from([pi]);
        if !linked {
            out.extend(
                self.nodes
                    .keys()
                    .filter(|&&(q, a)| {
                        a == area
                            && self.procs[q].cfg.vrf == p.cfg.vrf
                            && self.procs[q].version() == p.version()
                    })
                    .map(|&(q, _)| q),
            );
        }
        out
    }

    /// Adds a gap of the process `pi` to each area instance of `gap_procs`.
    fn spread_gap(
        &mut self,
        pi: usize,
        area: AreaId,
        lsa_type: LsaType,
        reach: GapReach,
        detail: String,
    ) {
        let gap = self.stated(pi, lsa_type, Some(area), reach, detail);
        let insts: BTreeSet<usize> = self
            .gap_procs(pi, area)
            .into_iter()
            .filter_map(|q| self.inst(q, area))
            .collect();
        for inst in insts {
            self.area_gaps.entry(inst).or_default().push(gap.clone());
        }
    }

    /// Adds a gap of AS-external LSAs to the AS of a process.
    fn as_gap(&mut self, pi: usize, reach: GapReach, detail: String) {
        let gap = self.stated(pi, LsaType::External, None, reach, detail);
        let as_id = self.as_of(pi);
        self.as_gaps.entry(as_id).or_default().push(gap);
    }

    fn add_process(&mut self, device: &str, input: &'a RouterInput, cfg: &'a Process) {
        let key = (
            device.to_string(),
            cfg.vrf.clone(),
            cfg.version,
            cfg.process.clone(),
        );
        if self.procs.iter().any(|p| p.key == key) {
            self.global.push((
                device.to_string(),
                Note::new(
                    "ospf-duplicate-process",
                    format!("{}/{}/{}", cfg.vrf, cfg.version.name(), cfg.process),
                    "the config has 2 processes with this VRF, version and name, and the second is left out",
                ),
            ));
            return;
        }
        let mut profile = OspfProfile::of(input.platform);
        if let Some(r) = cfg.reference_bandwidth_mbps {
            profile.reference_bandwidth_mbps = r;
        }
        let version = cfg.version;
        let mut notes = Vec::new();
        let subject = format!("{}/{}/{}", cfg.vrf, version.name(), cfg.process);
        let mut order: Vec<&OspfInterface> = cfg.interfaces.iter().collect();
        order.sort_by(|a, b| a.name.cmp(&b.name));
        let mut ifs = Vec::new();
        let mut no_address = Vec::new();
        for (i, f) in order.iter().copied().enumerate() {
            if !f.up {
                continue;
            }
            let loopback = f.network == NetworkType::Loopback;
            let (addr, prefix) = match f.address {
                Some((a, len)) if family_ok(version, a) && len <= max_len(a) => {
                    let p = if loopback {
                        Prefix::host(a)
                    } else {
                        Prefix::new(a, len)
                    };
                    (Some(a), Some(p))
                }
                _ => (None, None),
            };
            if addr.is_none() && !loopback && !f.passive {
                no_address.push(f.name.clone());
            }
            let cost = if loopback {
                loopback_cost(input.platform, version, f.cost)
            } else if let Some(c) = f.cost {
                c
            } else if let Some(bw) = f.bandwidth_kbps {
                profile.interface_cost(bw)
            } else {
                let c = unknown_bandwidth_cost(&profile);
                notes.push(Note::new(
                    "ospf-cost-default",
                    subject.clone(),
                    format!(
                        "interface {} has no configured cost and no known bandwidth, and its cost is {c}",
                        f.name
                    ),
                ));
                c
            };
            ifs.push(If {
                cfg: f,
                id: i as u32 + 1,
                cost,
                addr,
                prefix,
                link: Link::Stub,
            });
        }
        let rid = cfg.router_id.or_else(|| {
            let mut addresses = input.addresses.get(&cfg.vrf).cloned().unwrap_or_default();
            addresses.extend(cfg.interfaces.iter().filter_map(|f| {
                let (a, _) = f.address?;
                Some(Address {
                    interface: f.name.clone(),
                    address: v4(a)?,
                    loopback: f.network == NetworkType::Loopback,
                    up: f.up,
                })
            }));
            default_router_id(input.platform, &addresses)
        });
        if rid.is_none() {
            notes.push(Note::new(
                "ospf-no-router-id",
                subject.clone(),
                "the process has no router ID, and it originates no LSA",
            ));
        }
        for (line, span) in &cfg.unhandled {
            notes.push(Note::new(
                "ospf-unhandled-line",
                subject.clone(),
                format!(
                    "the line `{line}` at {} line {} is not handled, and each LSA of the process is left out",
                    span.file, span.first_line
                ),
            ));
        }
        let family = match version {
            Version::V2 => "IPv4 address",
            Version::V3 => "global IPv6 address",
        };
        for name in &no_address {
            notes.push(Note::new(
                "ospf-no-address",
                subject.clone(),
                format!(
                    "the active interface {name} has no {family}, its neighbours are not known, and each LSA of the process is left out"
                ),
            ));
        }
        self.procs.push(Proc {
            key,
            input,
            cfg,
            profile,
            rid,
            left_out: !cfg.unhandled.is_empty() || !no_address.is_empty(),
            ifs,
        });
        self.notes.push(notes);
    }

    fn rid(&self, r: Ref) -> RouterId {
        self.procs[r.0].rid.unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    fn iface(&self, r: Ref) -> &If<'a> {
        &self.procs[r.0].ifs[r.1]
    }

    /// The neighbours of each interface and the designated routers.
    fn adjacencies(&mut self) {
        let mut segments: BTreeMap<(String, Version, Prefix), Vec<Ref>> = BTreeMap::new();
        for (pi, p) in self.procs.iter().enumerate() {
            if p.rid.is_none() {
                continue;
            }
            for (ii, f) in p.ifs.iter().enumerate() {
                if f.cfg.passive || f.cfg.network == NetworkType::Loopback {
                    continue;
                }
                let Some(prefix) = f.prefix else { continue };
                segments
                    .entry((p.cfg.vrf.clone(), p.version(), prefix))
                    .or_default()
                    .push((pi, ii));
            }
        }
        for ((_, _, prefix), members) in segments {
            let mut parts: BTreeMap<(AreaId, NetworkType, AreaType), Vec<Ref>> = BTreeMap::new();
            for r in members {
                let f = self.iface(r);
                let key = (
                    f.cfg.area,
                    f.cfg.network,
                    self.procs[r.0].area_type(f.cfg.area),
                );
                let part = parts.entry(key).or_default();
                if part.iter().any(|m| m.0 == r.0) {
                    let name = f.cfg.name.clone();
                    self.note(
                        r.0,
                        "ospf-same-subnet",
                        format!(
                            "interface {name} is in {prefix} with another interface of the process, and it has no neighbour"
                        ),
                    );
                    continue;
                }
                part.push(r);
            }
            if parts.len() > 1 {
                let all: Vec<Ref> = parts.values().flatten().copied().collect();
                for r in all {
                    let name = self.iface(r).cfg.name.clone();
                    self.note(
                        r.0,
                        "ospf-adjacency-mismatch",
                        format!(
                            "the OSPF interfaces in {prefix} differ in the area, the area type or the network type, and interface {name} has neighbours only with the same values"
                        ),
                    );
                }
            }
            for ((_, network, _), refs) in parts {
                if refs.len() < 2 {
                    continue;
                }
                match network {
                    NetworkType::PointToPoint if refs.len() == 2 => {
                        self.procs[refs[0].0].ifs[refs[0].1].link = Link::PointToPoint(refs[1]);
                        self.procs[refs[1].0].ifs[refs[1].1].link = Link::PointToPoint(refs[0]);
                    }
                    NetworkType::PointToPoint => {
                        for r in refs {
                            let name = self.iface(r).cfg.name.clone();
                            self.note(
                                r.0,
                                "ospf-point-to-point-ambiguous",
                                format!(
                                    "the point-to-point interface {name} has more than one router in {prefix}, and it has no neighbour"
                                ),
                            );
                        }
                    }
                    NetworkType::Broadcast => {
                        let dr = refs
                            .iter()
                            .copied()
                            .filter(|r| self.iface(*r).cfg.priority > 0)
                            .max_by_key(|r| (self.iface(*r).cfg.priority, self.rid(*r)));
                        match dr {
                            Some(dr) => {
                                for r in &refs {
                                    self.procs[r.0].ifs[r.1].link = Link::Transit {
                                        dr,
                                        members: refs.clone(),
                                    };
                                }
                            }
                            None => {
                                for r in refs {
                                    let name = self.iface(r).cfg.name.clone();
                                    self.note(
                                        r.0,
                                        "ospf-no-designated-router",
                                        format!(
                                            "each router in {prefix} has priority 0, and interface {name} has no neighbour"
                                        ),
                                    );
                                }
                            }
                        }
                    }
                    NetworkType::Loopback => {}
                }
            }
        }
    }

    /// The area instances and the AS of each process.
    fn scopes(&mut self) {
        for pi in 0..self.procs.len() {
            let n = self.uf.add();
            self.as_nodes.insert(pi, n);
            for a in self.procs[pi].areas() {
                let n = self.uf.add();
                self.nodes.insert((pi, a), n);
            }
        }
        let mut pairs = Vec::new();
        for (pi, p) in self.procs.iter().enumerate() {
            for f in &p.ifs {
                let other = match &f.link {
                    Link::Stub => continue,
                    Link::PointToPoint(r) => *r,
                    Link::Transit { dr, .. } => *dr,
                };
                pairs.push((pi, other.0, f.cfg.area));
            }
        }
        for (a, b, area) in pairs {
            self.uf.union(self.as_nodes[&a], self.as_nodes[&b]);
            if let (Some(x), Some(y)) = (self.nodes.get(&(a, area)), self.nodes.get(&(b, area))) {
                self.uf.union(*x, *y);
            }
        }
    }

    fn inst(&self, pi: usize, area: AreaId) -> Option<usize> {
        self.nodes.get(&(pi, area)).map(|n| self.uf.find(*n))
    }

    fn as_of(&self, pi: usize) -> usize {
        self.uf.find(self.as_nodes[&pi])
    }

    fn put(&mut self, pi: usize, area: AreaId, lsa: Lsa) {
        let Some(inst) = self.inst(pi, area) else {
            return;
        };
        let store = self.area_store.entry(inst).or_default();
        let key = lsa.key();
        if store.contains_key(&key) {
            let detail = format!(
                "{} is also originated by another process, and the second is left out",
                lsa.describe(self.procs[pi].version())
            );
            self.note(pi, "ospf-duplicate-lsa", detail);
            return;
        }
        store.insert(key, lsa);
    }

    /// The router, network, link and intra-area-prefix LSAs.
    fn originate_intra(&mut self) {
        for pi in 0..self.procs.len() {
            if !self.procs[pi].originates() {
                continue;
            }
            for area in self.procs[pi].areas() {
                self.originate_area(pi, area);
            }
        }
    }

    fn originate_area(&mut self, pi: usize, area: AreaId) {
        let p = &self.procs[pi];
        let rid = p.rid.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let version = p.version();
        let mut links = Vec::new();
        let mut prefixes: Vec<(Prefix, u32)> = Vec::new();
        let mut lsas = Vec::new();
        let mut missing_link_local = Vec::new();
        for (ii, f) in p.ifs.iter().enumerate() {
            if f.cfg.area != area {
                continue;
            }
            let own = f.addr.and_then(v4);
            let loopback = f.cfg.network == NetworkType::Loopback;
            let stub = |prefix: Prefix, metric: u32| RouterLink {
                kind: LinkKind::Stub,
                id: v4(prefix.addr()).unwrap_or(Ipv4Addr::UNSPECIFIED),
                data: Some(mask(prefix.len())),
                metric,
                interface_id: None,
                neighbor_interface_id: None,
            };
            match (version, &f.link) {
                (Version::V2, Link::Stub) => {
                    if let Some(prefix) = f.prefix {
                        links.push(stub(prefix, f.cost));
                    }
                }
                (Version::V2, Link::PointToPoint(r)) => {
                    links.push(RouterLink {
                        kind: LinkKind::PointToPoint,
                        id: self.rid(*r),
                        data: own,
                        metric: f.cost,
                        interface_id: None,
                        neighbor_interface_id: None,
                    });
                    if let Some(prefix) = f.prefix {
                        links.push(stub(prefix, f.cost));
                    }
                }
                (Version::V2, Link::Transit { dr, .. }) => {
                    links.push(RouterLink {
                        kind: LinkKind::Transit,
                        id: self
                            .iface(*dr)
                            .addr
                            .and_then(v4)
                            .unwrap_or(Ipv4Addr::UNSPECIFIED),
                        data: own,
                        metric: f.cost,
                        interface_id: None,
                        neighbor_interface_id: None,
                    });
                }
                (Version::V3, Link::Stub) => {
                    if let Some(prefix) = f.prefix {
                        prefixes.push((prefix, f.cost));
                    }
                }
                (Version::V3, Link::PointToPoint(r)) => {
                    links.push(RouterLink {
                        kind: LinkKind::PointToPoint,
                        id: self.rid(*r),
                        data: None,
                        metric: f.cost,
                        interface_id: Some(f.id),
                        neighbor_interface_id: Some(self.iface(*r).id),
                    });
                    if let Some(prefix) = f.prefix {
                        prefixes.push((prefix, f.cost));
                    }
                }
                (Version::V3, Link::Transit { dr, .. }) => {
                    links.push(RouterLink {
                        kind: LinkKind::Transit,
                        id: self.rid(*dr),
                        data: None,
                        metric: f.cost,
                        interface_id: Some(f.id),
                        neighbor_interface_id: Some(self.iface(*dr).id),
                    });
                }
            }
            for (a, l) in &f.cfg.secondaries {
                if a.is_ipv4() != (version == Version::V2) {
                    continue;
                }
                let p = Prefix::new(*a, *l);
                match version {
                    Version::V2 => links.push(stub(p, f.cost)),
                    Version::V3 => prefixes.push((p, f.cost)),
                }
            }
            if let Link::Transit { dr, members } = &f.link
                && *dr == (pi, ii)
            {
                let mut attached: Vec<RouterId> = members.iter().map(|m| self.rid(*m)).collect();
                attached.sort();
                attached.dedup();
                match version {
                    Version::V2 => {
                        lsas.push(new_lsa(
                            LsaType::Network,
                            Some(area),
                            own.unwrap_or(Ipv4Addr::UNSPECIFIED),
                            rid,
                            Body::Network {
                                mask: f.prefix.map(|p| mask(p.len())),
                                attached,
                            },
                            f.cfg.span.clone(),
                        ));
                    }
                    Version::V3 => {
                        let lsid = Ipv4Addr::from(f.id);
                        lsas.push(new_lsa(
                            LsaType::Network,
                            Some(area),
                            lsid,
                            rid,
                            Body::Network {
                                mask: None,
                                attached,
                            },
                            f.cfg.span.clone(),
                        ));
                        let mut on_link: Vec<(Prefix, u32)> = members
                            .iter()
                            .filter_map(|m| self.iface(*m).prefix)
                            .map(|p| (p, 0))
                            .collect();
                        on_link.sort();
                        on_link.dedup();
                        lsas.push(new_lsa(
                            LsaType::IntraAreaPrefix,
                            Some(area),
                            lsid,
                            rid,
                            Body::IntraAreaPrefix {
                                reference: Reference::Network(f.id),
                                router: rid,
                                prefixes: on_link,
                            },
                            f.cfg.span.clone(),
                        ));
                    }
                }
            }
            if version == Version::V3 && !loopback {
                let address = p.input.link_local.get(&f.cfg.name).copied();
                if address.is_none() {
                    missing_link_local.push(f.cfg.name.clone());
                }
                self.link_store.insert(
                    (pi, ii),
                    new_lsa(
                        LsaType::Link,
                        Some(area),
                        Ipv4Addr::from(f.id),
                        rid,
                        Body::Link {
                            address,
                            prefixes: f.prefix.into_iter().collect(),
                            interface: None,
                        },
                        f.cfg.span.clone(),
                    ),
                );
            }
        }
        let span = p.cfg.span.clone();
        let router_lsid = match version {
            Version::V2 => rid,
            Version::V3 => Ipv4Addr::UNSPECIFIED,
        };
        lsas.insert(
            0,
            new_lsa(
                LsaType::Router,
                Some(area),
                router_lsid,
                rid,
                Body::Router { links },
                span.clone(),
            ),
        );
        if version == Version::V3 && !prefixes.is_empty() {
            prefixes.sort();
            prefixes.dedup_by(|b, a| a.0 == b.0);
            lsas.push(new_lsa(
                LsaType::IntraAreaPrefix,
                Some(area),
                Ipv4Addr::UNSPECIFIED,
                rid,
                Body::IntraAreaPrefix {
                    reference: Reference::Router,
                    router: rid,
                    prefixes,
                },
                span,
            ));
        }
        for name in missing_link_local {
            self.note(
                pi,
                "ospf-no-link-local",
                format!(
                    "interface {name} has no link-local address, and its link LSA has no address"
                ),
            );
        }
        for lsa in lsas {
            self.put(pi, area, lsa);
        }
    }

    /// The external routes of a process by prefix, and the reach and the
    /// text of each gap of the external LSAs that the process leaves out.
    fn externals(&mut self, pi: usize) -> (BTreeMap<Prefix, Ext>, Vec<(GapReach, String)>) {
        let p = &self.procs[pi];
        let version = p.version();
        let vrf = &p.cfg.vrf;
        let platform = p.input.platform;
        let rid = p.rid.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let own: BTreeSet<Prefix> = p
            .cfg
            .interfaces
            .iter()
            .filter_map(|f| f.address)
            .filter(|(a, len)| family_ok(version, *a) && *len <= max_len(*a))
            .flat_map(|(a, len)| [Prefix::new(a, len), Prefix::host(a)])
            .collect();
        let usable = |prefix: &Prefix| {
            family_ok(version, prefix.addr()) && prefix.len() > 0 && !own.contains(prefix)
        };
        let mut out: BTreeMap<Prefix, Ext> = BTreeMap::new();
        let mut notes = Vec::new();
        let mut left = Vec::new();
        let ibgp = crate::bgp::BgpProfile::of(platform)
            .redistribute
            .ibgp_into_igp;
        for r in &p.cfg.redistribute {
            let bgp = match &r.source {
                Source::Bgp => p.input.bgp.get(vrf),
                _ => None,
            };
            let bgp_list: Option<Vec<Prefix>> = bgp.map(|b| {
                b.routes
                    .iter()
                    .filter(|(_, internal)| ibgp || !**internal)
                    .map(|(x, _)| *x)
                    .collect()
            });
            let list = match &r.source {
                Source::Connected => p.input.connected.get(vrf),
                Source::Static => p.input.statics.get(vrf),
                Source::Bgp if bgp_list.is_some() => bgp_list.as_ref(),
                Source::Bgp | Source::Other(_) => {
                    let word = match &r.source {
                        Source::Other(w) => w.as_str(),
                        _ => "bgp",
                    };
                    notes.push((
                        "ospf-redistribute-unknown",
                        format!(
                            "the redistribution of {word} is not evaluated, and its external LSAs are left out"
                        ),
                    ));
                    left.push((
                        GapReach::External,
                        format!("the external LSAs of the redistribution of {word} by {rid} are left out"),
                    ));
                    continue;
                }
            };
            let prefixes: Vec<Prefix> = list
                .map(|l| l.iter().copied().filter(usable).collect())
                .unwrap_or_default();
            if let Some(b) = bgp {
                let unknown: Vec<Prefix> = b.unknown.iter().copied().filter(usable).collect();
                if !unknown.is_empty() {
                    left.push((
                        GapReach::Prefixes(unknown),
                        format!(
                            "the external LSAs of the unknown bgp routes of {rid} are left out"
                        ),
                    ));
                }
            }
            if let Some(map) = &r.route_map {
                let word = match r.source {
                    Source::Connected => "connected",
                    Source::Bgp => "bgp",
                    _ => "static",
                };
                let text: Vec<String> = prefixes.iter().map(|x| x.to_string()).collect();
                notes.push((
                    "ospf-redistribute-unknown",
                    format!(
                        "the redistribution of {word} with the route-map {map} is not evaluated, and the external LSAs of the prefixes {} are left out",
                        text.join(", ")
                    ),
                ));
                if !prefixes.is_empty() {
                    left.push((
                        GapReach::Prefixes(prefixes),
                        format!(
                            "the external LSAs of the redistribution of {word} with the route-map {map} by {rid} are left out"
                        ),
                    ));
                }
                continue;
            }
            for prefix in prefixes {
                out.entry(prefix).or_insert(Ext {
                    metric: r.metric.unwrap_or(redistribute_metric(platform, &r.source)),
                    metric_type: r.metric_type.unwrap_or(2),
                    connected: r.source == Source::Connected,
                    span: r.span.clone(),
                });
            }
        }
        if let Some(d) = &p.cfg.default_originate {
            if let Some(map) = &d.route_map {
                notes.push((
                    "ospf-default-unknown",
                    format!(
                        "the default route with the route-map {map} is not evaluated, and its external LSA is left out"
                    ),
                ));
                left.push((
                    GapReach::Prefixes(vec![default_prefix(version)]),
                    format!(
                        "the external LSA of the default route with the route-map {map} by {rid} is left out"
                    ),
                ));
            } else if d.always || p.input.default_route.contains(vrf) {
                out.insert(
                    default_prefix(version),
                    Ext {
                        metric: d
                            .metric
                            .unwrap_or(default_originate_metric(platform, d.always)),
                        metric_type: d.metric_type.unwrap_or(2),
                        connected: false,
                        span: d.span.clone(),
                    },
                );
            }
        }
        for (kind, detail) in notes {
            self.note(pi, kind, detail);
        }
        (out, left)
    }

    /// The forwarding address of the NSSA LSAs with the P bit of a process
    /// in an NSSA (RFC 3101 2.3): the highest address of a loopback of the
    /// process in the area, else the highest address of an up OSPF
    /// interface of the process in the area. Not confirmed by a vendor
    /// document.
    fn nssa_forwarding_address(&self, pi: usize, area: AreaId) -> Option<IpAddr> {
        self.procs[pi]
            .ifs
            .iter()
            .filter(|f| f.cfg.area == area)
            .filter_map(|f| f.addr.map(|a| (f.cfg.network == NetworkType::Loopback, a)))
            .max()
            .map(|(_, a)| a)
    }

    /// The gaps of each left-out process with a router ID: a gap of its
    /// interface prefixes and its redistributed prefixes in each of its
    /// areas, and a gap of AS-external LSAs when it redistributes from a
    /// source that is not evaluated or has `default-information originate`.
    fn left_out_gaps(&mut self) {
        for pi in 0..self.procs.len() {
            let p = &self.procs[pi];
            let Some(rid) = p.rid else { continue };
            if !p.left_out {
                continue;
            }
            let version = p.version();
            let vrf = &p.cfg.vrf;
            let mut prefixes: BTreeSet<Prefix> = p.ifs.iter().filter_map(|f| f.prefix).collect();
            let mut external = p.cfg.default_originate.is_some();
            for r in &p.cfg.redistribute {
                let list = match &r.source {
                    Source::Connected => p.input.connected.get(vrf),
                    Source::Static => p.input.statics.get(vrf),
                    Source::Bgp | Source::Other(_) => {
                        external = true;
                        continue;
                    }
                };
                prefixes.extend(
                    list.into_iter()
                        .flatten()
                        .copied()
                        .filter(|x| family_ok(version, x.addr()) && x.len() > 0),
                );
            }
            let areas = p.areas();
            // The NSSAs of the process. Its type 7 LSAs of the sources that
            // are not known are gaps of each NSSA, because the routers of an
            // NSSA do not read the gaps of the AS.
            let nssas: BTreeSet<AreaId> = areas
                .iter()
                .copied()
                .filter(|a| p.cfg.areas.get(a).is_some_and(|x| x.kind == AreaType::Nssa))
                .collect();
            let mut procs = BTreeSet::from([pi]);
            for a in areas {
                procs.extend(self.gap_procs(pi, a));
                if external && nssas.contains(&a) {
                    self.spread_gap(
                        pi,
                        a,
                        LsaType::NssaExternal,
                        GapReach::External,
                        format!(
                            "the process of {rid} is left out, and its NSSA LSAs are not known"
                        ),
                    );
                }
                if !prefixes.is_empty() {
                    self.spread_gap(
                        pi,
                        a,
                        LsaType::Router,
                        GapReach::Prefixes(prefixes.iter().copied().collect()),
                        format!(
                            "the process of {rid} is left out, and the routes of its interface prefixes and its redistributed prefixes are not known"
                        ),
                    );
                }
            }
            if external {
                let gap = self.stated(
                    pi,
                    LsaType::External,
                    None,
                    GapReach::External,
                    format!(
                        "the process of {rid} is left out, and its AS-external LSAs are not known"
                    ),
                );
                let ases: BTreeSet<usize> = procs.iter().map(|q| self.as_of(*q)).collect();
                for as_id in ases {
                    self.as_gaps.entry(as_id).or_default().push(gap.clone());
                }
            }
        }
    }

    /// The AS-external LSAs and the NSSA LSAs, and the gaps of the external
    /// LSAs that the processes leave out.
    fn originate_externals(&mut self) {
        for pi in 0..self.procs.len() {
            if !self.procs[pi].originates() {
                continue;
            }
            let (exts, left) = self.externals(pi);
            if exts.is_empty() && left.is_empty() {
                continue;
            }
            let p = &self.procs[pi];
            let rid = p.rid.unwrap_or(Ipv4Addr::UNSPECIFIED);
            let version = p.version();
            let areas = p.areas();
            let normal = areas.iter().any(|a| p.area_type(*a) == AreaType::Normal);
            let nssas: Vec<AreaId> = areas
                .iter()
                .copied()
                .filter(|a| p.area_type(*a) == AreaType::Nssa)
                .collect();
            if !normal && nssas.is_empty() {
                self.note(
                    pi,
                    "ospf-external-not-flooded",
                    "the process redistributes routes and attaches to no normal area and no NSSA, and it originates no external LSA".to_string(),
                );
                continue;
            }
            let lsa = |lsa_type, area, prefix: Prefix, e: &Ext, forwarding: Option<IpAddr>| {
                new_lsa(
                    lsa_type,
                    area,
                    Ipv4Addr::UNSPECIFIED,
                    rid,
                    Body::External {
                        prefix,
                        metric: e.metric,
                        metric_type: Some(e.metric_type),
                        forwarding,
                    },
                    e.span.clone(),
                )
            };
            let mut lost = Vec::new();
            if normal {
                self.asbrs.insert(pi);
                let as_id = self.as_of(pi);
                let store = self.as_store.entry(as_id).or_default();
                let mut as_lost = Vec::new();
                for (prefix, e) in &exts {
                    if !add_prefix_lsa(
                        store,
                        version,
                        lsa(LsaType::External, None, *prefix, e, None),
                    ) {
                        as_lost.push(*prefix);
                    }
                }
                if !as_lost.is_empty() {
                    self.as_gap(
                        pi,
                        GapReach::Prefixes(as_lost.clone()),
                        format!(
                            "the external LSAs of {rid} with a taken link-state ID are left out"
                        ),
                    );
                }
                lost.extend(as_lost);
                for (reach, detail) in &left {
                    self.as_gap(pi, reach.clone(), detail.clone());
                }
            }
            for a in nssas {
                let Some(inst) = self.inst(pi, a) else {
                    continue;
                };
                let p_bit = !normal;
                let forwarding = if p_bit {
                    self.nssa_forwarding_address(pi, a)
                } else {
                    None
                };
                if p_bit && forwarding.is_none() {
                    self.note(
                        pi,
                        "ospf-nssa-no-forwarding-address",
                        format!("the process has no address in the NSSA {a}, and it originates no NSSA LSA into it"),
                    );
                    if !exts.is_empty() {
                        self.spread_gap(
                            pi,
                            a,
                            LsaType::NssaExternal,
                            GapReach::Prefixes(exts.keys().copied().collect()),
                            format!(
                                "the process of {rid} has no address in the NSSA {a}, and its NSSA LSAs are left out"
                            ),
                        );
                    }
                    for (reach, detail) in &left {
                        self.spread_gap(
                            pi,
                            a,
                            LsaType::NssaExternal,
                            reach.clone(),
                            detail.clone(),
                        );
                    }
                    continue;
                }
                let store = self.area_store.entry(inst).or_default();
                let mut area_lost = Vec::new();
                let mut fa_unknown = Vec::new();
                for (prefix, e) in &exts {
                    if !add_prefix_lsa(
                        store,
                        version,
                        lsa(LsaType::NssaExternal, Some(a), *prefix, e, forwarding),
                    ) {
                        area_lost.push(*prefix);
                        continue;
                    }
                    if p_bit {
                        self.p_bit.insert((inst, rid, *prefix));
                        if !e.connected && prefix.len() > 0 {
                            fa_unknown.push(*prefix);
                        }
                    }
                }
                if !area_lost.is_empty() {
                    self.area_gap(
                        pi,
                        a,
                        LsaType::NssaExternal,
                        GapReach::Prefixes(area_lost.clone()),
                        format!("the NSSA LSAs of {rid} with a taken link-state ID are left out"),
                    );
                }
                lost.extend(area_lost);
                if !fa_unknown.is_empty() {
                    self.area_gap(
                        pi,
                        a,
                        LsaType::NssaExternal,
                        GapReach::Prefixes(fa_unknown),
                        format!(
                            "the next hops of the static and default routes of {rid} are not known, and the forwarding addresses of their NSSA LSAs are not known"
                        ),
                    );
                }
                for (reach, detail) in &left {
                    self.area_gap(pi, a, LsaType::NssaExternal, reach.clone(), detail.clone());
                }
            }
            self.lsid_notes(pi, lost);
        }
    }

    /// RFC 3101 3.1 and 3.2: the translator of each NSSA is the NSSA border
    /// router with the highest router ID that the NSSA calculation of each
    /// other originating router of the NSSA reaches. It translates the NSSA
    /// LSAs of its routes with the P bit, except the default route, into
    /// AS-external LSAs. It does not translate a prefix that an ASBR also
    /// originates in an AS-external LSA, and that prefix is a gap. The gaps
    /// of the NSSA in the calculation of the translator are gaps of the AS.
    /// The AS has a gap of AS-external LSAs, and no LSA is translated, when a
    /// border router with a higher router ID than the translator is left out
    /// or is not reached by a calculation with a gap, or when no border
    /// router is reached.
    fn translate_nssa(&mut self) {
        let mut borders: BTreeMap<usize, Vec<(RouterId, usize, AreaId)>> = BTreeMap::new();
        for (pi, p) in self.procs.iter().enumerate() {
            let Some(rid) = p.rid else { continue };
            let areas = p.areas();
            if !areas.contains(&BACKBONE) || areas.len() < 2 {
                continue;
            }
            for a in areas {
                if p.area_type(a) != AreaType::Nssa {
                    continue;
                }
                if let Some(inst) = self.inst(pi, a) {
                    borders.entry(inst).or_default().push((rid, pi, a));
                }
            }
        }
        let originated: BTreeSet<(usize, Prefix)> = self
            .as_store
            .iter()
            .flat_map(|(as_id, store)| {
                let as_id = *as_id;
                store
                    .values()
                    .filter_map(|l| prefix_of(&l.body))
                    .map(move |x| (as_id, x))
            })
            .collect();
        for (inst, mut list) in borders {
            list.sort_by(|x, y| y.cmp(x));
            let Some(&(_, first, a)) = list.first() else {
                continue;
            };
            let members: Vec<usize> = self
                .nodes
                .keys()
                .filter(|&&(q, x)| {
                    x == a && self.procs[q].originates() && self.inst(q, a) == Some(inst)
                })
                .map(|&(q, _)| q)
                .collect();
            let views: Vec<(usize, BTreeSet<RouterId>, bool)> = members
                .iter()
                .map(|&q| {
                    let db = self.assemble(q, &BTreeSet::from([a]), false);
                    let own = self.procs[q].rid.unwrap_or(Ipv4Addr::UNSPECIFIED);
                    let calc = compute(&db, own, &self.procs[q].profile);
                    let reached = calc
                        .router_costs
                        .keys()
                        .filter(|(x, _)| *x == a)
                        .map(|(_, r)| *r)
                        .collect();
                    let hidden = calc
                        .gaps
                        .iter()
                        .any(|g| matches!(g.reach, GapReach::All | GapReach::FromCost(_)));
                    (q, reached, hidden)
                })
                .collect();
            let mut elected = None;
            let mut unknown = None;
            for &(rid, pi, _) in &list {
                if self.procs[pi].left_out {
                    unknown = Some((
                        pi,
                        format!(
                            "the NSSA border router {rid} of area {a} is left out, and the NSSA translator of area {a} and its AS-external LSAs are not known"
                        ),
                    ));
                    break;
                }
                let missed: Vec<bool> = views
                    .iter()
                    .filter(|(q, reached, _)| *q != pi && !reached.contains(&rid))
                    .map(|(_, _, hidden)| *hidden)
                    .collect();
                if missed.is_empty() {
                    elected = Some((rid, pi));
                    break;
                }
                if missed.contains(&true) {
                    unknown = Some((
                        pi,
                        format!(
                            "the NSSA border router {rid} of area {a} is not reached past a gap of the database, and the NSSA translator of area {a} and its AS-external LSAs are not known"
                        ),
                    ));
                    break;
                }
            }
            let Some((rid, pi)) = elected else {
                let (gp, detail) = unknown.unwrap_or_else(|| {
                    (
                        first,
                        format!(
                            "no NSSA border router of area {a} is reached in the NSSA, and the NSSA translator of area {a} and its AS-external LSAs are not known"
                        ),
                    )
                });
                self.as_gap(gp, GapReach::External, detail);
                continue;
            };
            let version = self.procs[pi].version();
            let db = self.assemble(pi, &BTreeSet::from([a]), false);
            let calc = compute(&db, rid, &self.procs[pi].profile);
            let as_id = self.as_of(pi);
            let mut wide = false;
            let mut prefixes: BTreeSet<Prefix> = BTreeSet::new();
            for g in &calc.gaps {
                match &g.reach {
                    GapReach::Prefixes(p) => prefixes.extend(p.iter().copied()),
                    _ => wide = true,
                }
            }
            let mut lsas = Vec::new();
            for r in &calc.routes {
                if r.lsa_type != Some(LsaType::NssaExternal)
                    || r.unknown.is_some()
                    || r.prefix.len() == 0
                {
                    continue;
                }
                let Some(adv) = r.advertising_router else {
                    continue;
                };
                if !self.p_bit.contains(&(inst, adv, r.prefix)) {
                    continue;
                }
                if originated.contains(&(as_id, r.prefix)) {
                    prefixes.insert(r.prefix);
                    continue;
                }
                let Some(source) = self.area_store.get(&inst).and_then(|s| {
                    s.values().find(|l| {
                        l.lsa_type == LsaType::NssaExternal
                            && l.adv_router == adv
                            && prefix_of(&l.body) == Some(r.prefix)
                    })
                }) else {
                    continue;
                };
                let mut body = source.body.clone();
                if let Body::External { prefix, .. } = &mut body {
                    *prefix = r.prefix;
                }
                lsas.push(new_lsa(
                    LsaType::External,
                    None,
                    Ipv4Addr::UNSPECIFIED,
                    rid,
                    body,
                    source.span.clone(),
                ));
            }
            let mut lost = Vec::new();
            if !lsas.is_empty() {
                self.asbrs.insert(pi);
                let store = self.as_store.entry(as_id).or_default();
                for l in lsas {
                    let prefix = prefix_of(&l.body);
                    if !add_prefix_lsa(store, version, l)
                        && let Some(prefix) = prefix
                    {
                        lost.push(prefix);
                    }
                }
            }
            prefixes.extend(lost.iter().copied());
            prefixes.retain(|x| x.len() > 0);
            self.lsid_notes(pi, lost);
            if wide {
                self.as_gap(
                    pi,
                    GapReach::External,
                    format!(
                        "the routes of the NSSA LSAs of area {a} at the translator {rid} depend on a gap of the database, and its AS-external LSAs are not known"
                    ),
                );
            }
            if !prefixes.is_empty() {
                self.as_gap(
                    pi,
                    GapReach::Prefixes(prefixes.into_iter().collect()),
                    format!(
                        "the translation of the NSSA LSAs of area {a} by {rid} is not known for these prefixes"
                    ),
                );
            }
        }
    }

    fn lsid_notes(&mut self, pi: usize, lost: Vec<Prefix>) {
        for prefix in lost {
            self.note(
                pi,
                "ospf-lsid-collision",
                format!("the link-state ID of {prefix} is taken, and its LSA is left out"),
            );
        }
    }

    /// The database of a process over the LSAs of `areas`, with the
    /// AS-external LSAs when `externals` is true.
    fn assemble(&self, pi: usize, areas: &BTreeSet<AreaId>, externals: bool) -> Database {
        let p = &self.procs[pi];
        let version = p.version();
        let mut db = Database::new(version, &p.cfg.vrf, &p.cfg.process);
        db.router_id = p.rid;
        db.area_types = p.cfg.areas.iter().map(|(a, x)| (*a, x.kind)).collect();
        let link_local = |r: Ref| -> Option<Ipv6Addr> {
            let q = &self.procs[r.0];
            q.input.link_local.get(&q.ifs[r.1].cfg.name).copied()
        };
        for (ii, f) in p.ifs.iter().enumerate() {
            let address = match version {
                Version::V2 => f
                    .cfg
                    .address
                    .filter(|(a, _)| a.is_ipv4())
                    .map(|(a, l)| (a, Some(l))),
                Version::V3 => link_local((pi, ii)).map(|a| (IpAddr::V6(a), None)),
            };
            db.interfaces.push(Interface {
                name: f.cfg.name.clone(),
                area: Some(f.cfg.area),
                address,
                interface_id: (version == Version::V3).then_some(f.id),
                cost: Some(f.cost),
                span: f.cfg.span.clone(),
            });
            if p.rid.is_none() {
                continue;
            }
            let (others, dr): (Vec<Ref>, Option<Ref>) = match &f.link {
                Link::Stub => (Vec::new(), None),
                Link::PointToPoint(r) => (vec![*r], None),
                Link::Transit { dr, members } => (members.clone(), Some(*dr)),
            };
            let bdr = dr.and_then(|dr| {
                others
                    .iter()
                    .copied()
                    .filter(|r| *r != dr && self.iface(*r).cfg.priority > 0)
                    .max_by_key(|r| (self.iface(*r).cfg.priority, self.rid(*r)))
            });
            let elected = |r: Ref| Some(r) == dr || Some(r) == bdr;
            for r in others.iter().copied().filter(|r| *r != (pi, ii)) {
                let full = dr.is_none() || elected(r) || elected((pi, ii));
                let address = match version {
                    Version::V2 => self.iface(r).addr,
                    Version::V3 => link_local(r).map(IpAddr::V6),
                };
                db.neighbors.push(Neighbor {
                    router_id: self.rid(r),
                    address,
                    interface: Some(f.cfg.name.clone()),
                    state: Some(if full { "FULL" } else { "2WAY" }.to_string()),
                    span: f.cfg.span.clone(),
                });
            }
            if version == Version::V3 && areas.contains(&f.cfg.area) {
                let mut on_link = others;
                on_link.push((pi, ii));
                on_link.sort();
                on_link.dedup();
                for r in on_link {
                    if let Some(l) = self.link_store.get(&r) {
                        let mut l = l.clone();
                        if let Body::Link { interface, .. } = &mut l.body {
                            *interface = Some(f.cfg.name.clone());
                        }
                        db.insert(l);
                    }
                }
            }
        }
        if p.rid.is_none() {
            return db;
        }
        for a in areas {
            if let Some(store) = self.inst(pi, *a).and_then(|i| self.area_store.get(&i)) {
                for l in store.values() {
                    db.insert(l.clone());
                }
            }
        }
        let normal = areas.iter().any(|a| p.area_type(*a) == AreaType::Normal);
        if externals
            && normal
            && let Some(store) = self.as_store.get(&self.as_of(pi))
        {
            for l in store.values() {
                db.insert(l.clone());
            }
        }
        for a in areas {
            if let Some(gaps) = self.inst(pi, *a).and_then(|i| self.area_gaps.get(&i)) {
                db.gaps.extend(gaps.iter().cloned());
            }
        }
        if externals
            && normal
            && let Some(gaps) = self.as_gaps.get(&self.as_of(pi))
        {
            db.gaps.extend(gaps.iter().cloned());
        }
        let (own, others): (Vec<Gap>, Vec<Gap>) =
            db.gaps.drain(..).partition(|g| Some(g.lsid) == p.rid);
        db.gaps = others;
        db.own_gaps = own;
        for list in [&mut db.gaps, &mut db.own_gaps] {
            list.sort();
            list.dedup();
        }
        db
    }

    /// The routes of an area border router in each attached area, from the
    /// router and network LSAs.
    fn abr_view(&mut self, pi: usize) -> AbrView {
        let mut view = AbrView::default();
        let p = &self.procs[pi];
        let rid = p.rid.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let profile = p.profile;
        let as_id = self.as_of(pi);
        let asbr_ids: BTreeSet<RouterId> = self
            .asbrs
            .iter()
            .filter(|q| self.as_of(**q) == as_id)
            .filter_map(|q| self.procs[*q].rid)
            .collect();
        let mut notes = Vec::new();
        for area in p.areas() {
            let db = self.assemble(pi, &BTreeSet::from([area]), false);
            let calc = compute(&db, rid, &profile);
            if calc
                .gaps
                .iter()
                .any(|g| matches!(g.reach, GapReach::All | GapReach::FromCost(_)))
            {
                view.incomplete.insert(area);
                notes.push((
                    "ospf-summary-incomplete",
                    format!(
                        "the intra-area routes of area {area} depend on a gap of the database, and the summary LSAs of the routes behind the gap are missing"
                    ),
                ));
            }
            for g in &calc.gaps {
                if g.lsa_type == LsaType::Router
                    && let GapReach::Prefixes(x) = &g.reach
                {
                    view.left.entry(area).or_default().extend(x.iter().copied());
                }
            }
            let intra = view.intra.entry(area).or_default();
            for r in &calc.routes {
                if r.path_type != PathType::IntraArea {
                    continue;
                }
                if r.unknown.is_some() {
                    notes.push((
                        "ospf-summary-unknown",
                        format!(
                            "the intra-area route of {} in area {area} is unknown, and its summary LSA is left out",
                            r.prefix
                        ),
                    ));
                    continue;
                }
                intra.insert(r.prefix, r.metric);
            }
            for f in p.ifs.iter().filter(|f| f.cfg.area == area) {
                if let Some(prefix) = f.prefix {
                    let c = intra.entry(prefix).or_insert(f.cost);
                    *c = (*c).min(f.cost);
                }
            }
            let asbrs = view.asbrs.entry(area).or_default();
            for ((a, r), c) in &calc.router_costs {
                if *a == area && asbr_ids.contains(r) {
                    asbrs.insert(*r, *c);
                }
            }
        }
        for (kind, detail) in notes {
            self.note(pi, kind, detail);
        }
        view
    }

    fn summary(
        &self,
        pi: usize,
        area: AreaId,
        prefix: Prefix,
        metric: u32,
        span: SourceSpan,
    ) -> Lsa {
        new_lsa(
            LsaType::Summary,
            Some(area),
            Ipv4Addr::UNSPECIFIED,
            self.procs[pi].rid.unwrap_or(Ipv4Addr::UNSPECIFIED),
            Body::Summary { prefix, metric },
            span,
        )
    }

    fn asbr_summary(&self, pi: usize, area: AreaId, router: RouterId, metric: u32) -> Lsa {
        new_lsa(
            LsaType::AsbrSummary,
            Some(area),
            router,
            self.procs[pi].rid.unwrap_or(Ipv4Addr::UNSPECIFIED),
            Body::AsbrSummary { router, metric },
            self.procs[pi].cfg.span.clone(),
        )
    }

    fn add_summaries(&mut self, pi: usize, area: AreaId, lsas: Vec<Lsa>) {
        let Some(inst) = self.inst(pi, area) else {
            return;
        };
        let version = self.procs[pi].version();
        let store = self.area_store.entry(inst).or_default();
        let mut lost = Vec::new();
        for l in lsas {
            let prefix = prefix_of(&l.body);
            if !add_prefix_lsa(store, version, l)
                && let Some(prefix) = prefix
            {
                lost.push(prefix);
            }
        }
        if !lost.is_empty() {
            let rid = self.procs[pi].rid.unwrap_or(Ipv4Addr::UNSPECIFIED);
            self.area_gap(
                pi,
                area,
                LsaType::Summary,
                GapReach::Prefixes(lost.clone()),
                format!("the summary LSAs of {rid} with a taken link-state ID are left out"),
            );
        }
        self.lsid_notes(pi, lost);
    }

    /// RFC 2328 12.4.3: the summary and ASBR-summary LSAs of each area
    /// border router.
    fn originate_summaries(&mut self) {
        let abrs: Vec<usize> = (0..self.procs.len())
            .filter(|pi| self.procs[*pi].abr())
            .collect();
        let views: BTreeMap<usize, AbrView> =
            abrs.iter().map(|pi| (*pi, self.abr_view(*pi))).collect();
        for (pi, view) in &views {
            let pi = *pi;
            let p = &self.procs[pi];
            let span = p.cfg.span.clone();
            let mut out: Vec<(AreaId, Vec<Lsa>)> = Vec::new();
            let mut incomplete = Vec::new();
            let mut carried = Vec::new();
            for b in p.areas() {
                let kind = p.area_type(b);
                let mut prefixes: BTreeMap<Prefix, (u32, SourceSpan)> = BTreeMap::new();
                if (kind == AreaType::Normal || !p.no_summary(b))
                    && view.incomplete.iter().any(|a| *a != b)
                {
                    incomplete.push(b);
                }
                if kind == AreaType::Normal || !p.no_summary(b) {
                    let left: BTreeSet<Prefix> = view
                        .left
                        .iter()
                        .filter(|(a, _)| **a != b)
                        .flat_map(|(_, x)| x.iter().copied())
                        .collect();
                    if !left.is_empty() {
                        carried.push((b, left));
                    }
                }
                if kind == AreaType::Normal || !p.no_summary(b) {
                    for (a, routes) in &view.intra {
                        if *a == b {
                            continue;
                        }
                        for (prefix, c) in routes {
                            let e = prefixes.entry(*prefix).or_insert((*c, span.clone()));
                            e.0 = e.0.min(*c);
                        }
                    }
                }
                if kind == AreaType::Stub || (kind == AreaType::Nssa && p.no_summary(b)) {
                    let area = p.area(b);
                    prefixes.insert(
                        default_prefix(p.version()),
                        (
                            area.and_then(|x| x.default_cost).unwrap_or(1),
                            area.map_or(span.clone(), |x| x.span.clone()),
                        ),
                    );
                }
                let mut lsas: Vec<Lsa> = prefixes
                    .into_iter()
                    .map(|(prefix, (c, s))| self.summary(pi, b, prefix, c, s))
                    .collect();
                if kind == AreaType::Normal {
                    let mut routers: BTreeMap<RouterId, u32> = BTreeMap::new();
                    let in_b = view.asbrs.get(&b);
                    for (a, m) in &view.asbrs {
                        if *a == b {
                            continue;
                        }
                        for (r, c) in m {
                            if in_b.is_some_and(|x| x.contains_key(r)) {
                                continue;
                            }
                            let e = routers.entry(*r).or_insert(*c);
                            *e = (*e).min(*c);
                        }
                    }
                    lsas.extend(
                        routers
                            .into_iter()
                            .map(|(r, c)| self.asbr_summary(pi, b, r, c)),
                    );
                }
                out.push((b, lsas));
            }
            for (b, lsas) in out {
                self.add_summaries(pi, b, lsas);
            }
            let rid = self.procs[pi].rid.unwrap_or(Ipv4Addr::UNSPECIFIED);
            for b in incomplete {
                self.area_gap(
                    pi,
                    b,
                    LsaType::Summary,
                    GapReach::InterArea,
                    format!(
                        "the summary LSAs of {rid} into area {b} of the routes behind a gap of the database are left out"
                    ),
                );
            }
            for (b, left) in carried {
                self.area_gap(
                    pi,
                    b,
                    LsaType::Summary,
                    GapReach::Prefixes(left.into_iter().collect()),
                    format!(
                        "the summary LSAs of {rid} into area {b} of the prefixes of a left-out router are not known"
                    ),
                );
            }
        }
        for (pi, view) in &views {
            self.inter_area_summaries(*pi, view);
        }
    }

    /// The summary LSAs of the inter-area routes of the backbone into the
    /// other attached areas.
    fn inter_area_summaries(&mut self, pi: usize, view: &AbrView) {
        let p = &self.procs[pi];
        let rid = p.rid.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let db = self.assemble(pi, &BTreeSet::from([BACKBONE]), false);
        let calc = compute(&db, rid, &p.profile);
        let intra: BTreeSet<Prefix> = view
            .intra
            .values()
            .flat_map(|m| m.keys().copied())
            .collect();
        let reached: BTreeSet<RouterId> = view
            .asbrs
            .values()
            .flat_map(|m| m.keys().copied())
            .collect();
        let as_id = self.as_of(pi);
        let asbr_ids: BTreeSet<RouterId> = self
            .asbrs
            .iter()
            .filter(|q| self.as_of(**q) == as_id)
            .filter_map(|q| self.procs[*q].rid)
            .collect();
        let mut wide = false;
        let mut gap_prefixes: BTreeSet<Prefix> = BTreeSet::new();
        for g in &calc.gaps {
            match &g.reach {
                GapReach::Prefixes(x) => gap_prefixes.extend(x.iter().copied()),
                GapReach::External => {}
                GapReach::All | GapReach::FromCost(_) | GapReach::InterArea => wide = true,
            }
        }
        let mut notes = Vec::new();
        let mut routes: Vec<(Prefix, u32)> = Vec::new();
        for r in &calc.routes {
            if r.path_type != PathType::InterArea || intra.contains(&r.prefix) {
                continue;
            }
            if r.unknown.is_some() {
                notes.push(format!(
                    "the inter-area route of {} is unknown, and its summary LSA is left out",
                    r.prefix
                ));
                continue;
            }
            routes.push((r.prefix, r.metric));
        }
        let routers: Vec<(RouterId, u32)> = calc
            .router_costs
            .iter()
            .filter(|((a, r), _)| {
                *a == BACKBONE && asbr_ids.contains(r) && !reached.contains(r) && *r != rid
            })
            .map(|((_, r), c)| (*r, *c))
            .collect();
        let span = p.cfg.span.clone();
        let mut out = Vec::new();
        let mut gap_areas = Vec::new();
        for b in p.areas() {
            if b == BACKBONE {
                continue;
            }
            let kind = p.area_type(b);
            if kind != AreaType::Normal && p.no_summary(b) {
                continue;
            }
            gap_areas.push(b);
            let mut lsas: Vec<Lsa> = routes
                .iter()
                .map(|(prefix, c)| self.summary(pi, b, *prefix, *c, span.clone()))
                .collect();
            if kind == AreaType::Normal {
                lsas.extend(
                    routers
                        .iter()
                        .map(|(r, c)| self.asbr_summary(pi, b, *r, *c)),
                );
            }
            out.push((b, lsas));
        }
        for (b, lsas) in out {
            self.add_summaries(pi, b, lsas);
        }
        for b in gap_areas {
            if wide {
                self.area_gap(
                    pi,
                    b,
                    LsaType::Summary,
                    GapReach::InterArea,
                    format!(
                        "the inter-area routes of the backbone at {rid} depend on a gap of the database, and its summary LSAs into area {b} are not known"
                    ),
                );
            }
            if !gap_prefixes.is_empty() {
                self.area_gap(
                    pi,
                    b,
                    LsaType::Summary,
                    GapReach::Prefixes(gap_prefixes.iter().copied().collect()),
                    format!(
                        "the summary LSAs of {rid} into area {b} of these prefixes are not known"
                    ),
                );
            }
        }
        for detail in notes {
            self.note(pi, "ospf-summary-unknown", detail);
        }
    }

    fn finish(self) -> Built {
        let mut built = Built {
            databases: BTreeMap::new(),
            notes: self.global.clone(),
        };
        for (pi, p) in self.procs.iter().enumerate() {
            let mut db = self.assemble(pi, &p.areas(), true);
            db.notes = self.notes[pi].clone();
            for n in &self.notes[pi] {
                built.notes.push((p.key.0.clone(), n.clone()));
            }
            built.databases.insert(p.key.clone(), db);
        }
        built
    }
}

fn max_len(a: IpAddr) -> u8 {
    if a.is_ipv4() { 32 } else { 128 }
}

/// The link-state database of each OSPF process of the routers, by device,
/// VRF, version and process, and the notes of the build.
pub fn build(routers: &BTreeMap<String, RouterInput>) -> Built {
    let mut b = Builder::new(routers);
    b.adjacencies();
    b.scopes();
    b.originate_intra();
    b.originate_externals();
    b.left_out_gaps();
    b.translate_nssa();
    b.originate_summaries();
    b.finish()
}
