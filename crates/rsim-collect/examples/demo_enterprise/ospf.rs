//! The OSPF link-state database of each OSPF router of the demo estate, in
//! area 0 of the default VRF, and its OSPF sections in the formats that the
//! NX-OS, IOS-XE and IOS-XR readers of `rsim-ingest` read.
//!
//! An OSPF interface is an interface with `ospf` in the default VRF: on
//! NX-OS a routed port or a loopback. Its cost is `ospf_cost`. A routed
//! port of NX-OS and IOS-XE and each port of IOS-XR other than a loopback
//! is point-to-point. An IOS-XE SVI is a broadcast segment whose designated
//! router has the highest address. A loopback is a stub link of its /32. A
//! passive interface is a stub link of its network. The secondary address
//! of a loopback is a stub link of its /32 with the cost 1. A router of the
//! internet edge originates the default route as an external LSA of type 2
//! with the metric 1. A router with `ospf_redistribute_bgp` originates an
//! external LSA of type 2 with the metric 20 for each prefix of its eBGP
//! routes in the default VRF. The database of a router holds the LSAs of
//! the routers that its adjacencies reach.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write;
use std::net::Ipv4Addr;

use serde_json::{Value, json};

use super::model::*;

const AGE: u32 = 100;
const SEQ: u32 = 0x8000_0001;
const BACKBONE: &str = "0.0.0.0";
/// The metric of a route that IOS-XR redistributes from BGP with no metric
/// in the statement.
const BGP_METRIC: u32 = 20;

/// The prefixes that each router with `ospf_redistribute_bgp` redistributes
/// from BGP, by device index.
pub type Redistributed = BTreeMap<usize, Vec<(Ipv4Addr, u8)>>;

/// The prefixes of the eBGP routes of the default VRF of `ribs` of each
/// router with `ospf_redistribute_bgp`, other than the default route.
/// IOS-XR redistributes an iBGP route only with `bgp
/// redistribute-internal`.
pub fn redistributed(e: &Estate, ribs: &[Vec<super::route::Route>]) -> Redistributed {
    let mut out = Redistributed::new();
    for (d, dev) in e.devs.iter().enumerate() {
        if !dev.ospf_redistribute_bgp {
            continue;
        }
        let mut list: Vec<(Ipv4Addr, u8)> = ribs[d]
            .iter()
            .filter(|r| r.vrf == "default" && r.kind == super::route::Kind::Ebgp && r.prefix.1 > 0)
            .map(|r| r.prefix)
            .collect();
        list.sort();
        list.dedup();
        out.insert(d, list);
    }
    out
}

/// An AS-external LSA of type 2.
#[derive(Clone, Debug)]
struct AsExternal {
    adv: Ipv4Addr,
    net: Ipv4Addr,
    len: u8,
    metric: u32,
    tag: u32,
}

/// A link of a router LSA.
#[derive(Clone, Debug)]
enum Link {
    P2p {
        nbr: Ipv4Addr,
        own: Ipv4Addr,
        metric: u32,
    },
    Transit {
        dr: Ipv4Addr,
        own: Ipv4Addr,
        metric: u32,
    },
    Stub {
        net: Ipv4Addr,
        len: u8,
        metric: u32,
    },
}

/// A network LSA of a broadcast segment.
#[derive(Clone, Debug)]
struct Network {
    dr: Ipv4Addr,
    adv: Ipv4Addr,
    len: u8,
    attached: Vec<Ipv4Addr>,
}

/// An OSPF interface of a router.
#[derive(Clone, Debug)]
struct OIface {
    name: String,
    addr: Ipv4Addr,
    len: u8,
    cost: u32,
    p2p: bool,
    loopback: bool,
    passive: bool,
}

/// The OSPF state of one router.
pub struct Ospf {
    rid: Ipv4Addr,
    ifaces: Vec<OIface>,
    /// The router ID, the address, the interface and the state word of each
    /// neighbour.
    neighbors: Vec<(Ipv4Addr, Ipv4Addr, String, &'static str)>,
    routers: BTreeMap<Ipv4Addr, Vec<Link>>,
    networks: Vec<Network>,
    /// The AS-external LSAs in the order of the prefix and the advertising
    /// router.
    externals: Vec<AsExternal>,
}

fn router_id(dev: &Dev) -> Option<Ipv4Addr> {
    match dev.os {
        Os::Iosxe => dev
            .ifaces
            .iter()
            .find(|i| i.name == "Loopback0")
            .and_then(|i| i.addr)
            .map(|a| a.0),
        _ => dev.bgp.as_ref().map(|b| b.router_id),
    }
}

fn ospf_ifaces(dev: &Dev) -> Vec<OIface> {
    dev.ifaces
        .iter()
        .filter(|i| i.ospf && i.vrf == "default")
        .filter(|i| dev.os != Os::Nxos || matches!(i.mode, Mode::Routed | Mode::Loopback))
        .filter_map(|i| {
            let (addr, len) = i.addr?;
            let loopback = i.mode == Mode::Loopback;
            let p2p = !loopback
                && match dev.os {
                    Os::Nxos | Os::Iosxe => i.mode == Mode::Routed,
                    Os::Iosxr => true,
                };
            Some(OIface {
                name: i.name.clone(),
                addr,
                len,
                cost: i.ospf_cost,
                p2p,
                loopback,
                passive: i.ospf_passive,
            })
        })
        .collect()
}

/// The OSPF state of the router `d`, or `None` for a device with no OSPF.
pub fn of(e: &Estate, d: usize, redistributed: &Redistributed) -> Option<Ospf> {
    let mut rids: BTreeMap<usize, Ipv4Addr> = BTreeMap::new();
    let mut ifaces: BTreeMap<usize, Vec<OIface>> = BTreeMap::new();
    for (x, dev) in e.devs.iter().enumerate() {
        let list = ospf_ifaces(dev);
        if let (false, Some(rid)) = (list.is_empty(), router_id(dev)) {
            rids.insert(x, rid);
            ifaces.insert(x, list);
        }
    }
    rids.get(&d)?;
    let mut segments: BTreeMap<(Ipv4Addr, u8), Vec<(usize, OIface)>> = BTreeMap::new();
    for (x, list) in &ifaces {
        for i in list.iter().filter(|i| !i.loopback && !i.passive) {
            segments
                .entry((network(i.addr, i.len), i.len))
                .or_default()
                .push((*x, i.clone()));
        }
    }
    let mut routers: BTreeMap<usize, Vec<Link>> = BTreeMap::new();
    let mut networks = Vec::new();
    let mut adjacent: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for ((net, len), members) in &segments {
        let dr = members.iter().map(|(_, i)| i.addr).max().expect("a member");
        let p2p = members.len() == 2 && members.iter().all(|(_, i)| i.p2p);
        for (x, i) in members {
            let others: Vec<&(usize, OIface)> = members.iter().filter(|(y, _)| y != x).collect();
            let links = routers.entry(*x).or_default();
            if others.is_empty() {
                links.push(Link::Stub {
                    net: *net,
                    len: *len,
                    metric: i.cost,
                });
                continue;
            }
            adjacent
                .entry(*x)
                .or_default()
                .extend(others.iter().map(|(y, _)| *y));
            if p2p {
                links.push(Link::P2p {
                    nbr: rids[&others[0].0],
                    own: i.addr,
                    metric: i.cost,
                });
                links.push(Link::Stub {
                    net: *net,
                    len: *len,
                    metric: i.cost,
                });
            } else {
                links.push(Link::Transit {
                    dr,
                    own: i.addr,
                    metric: i.cost,
                });
            }
        }
        if members.len() > 1 && !p2p {
            let at = members.iter().find(|(_, i)| i.addr == dr).expect("the DR");
            let mut attached: Vec<Ipv4Addr> = members.iter().map(|(x, _)| rids[x]).collect();
            attached.sort();
            attached.dedup();
            networks.push(Network {
                dr,
                adv: rids[&at.0],
                len: *len,
                attached,
            });
        }
    }
    for (x, list) in &ifaces {
        for i in list.iter().filter(|i| i.loopback) {
            routers.entry(*x).or_default().push(Link::Stub {
                net: i.addr,
                len: 32,
                metric: i.cost,
            });
        }
        for i in e.devs[*x]
            .ifaces
            .iter()
            .filter(|i| i.vrf == "default" && i.mode != Mode::Mgmt)
        {
            let links = routers.entry(*x).or_default();
            if let Some(o) = list.iter().find(|o| o.passive && o.name == i.name) {
                links.push(Link::Stub {
                    net: network(o.addr, o.len),
                    len: o.len,
                    metric: o.cost,
                });
            }
            if let (Some((a, l)), true) = (i.secondary, list.iter().any(|o| o.name == i.name)) {
                links.push(Link::Stub {
                    net: network(a, l),
                    len: l,
                    metric: 1,
                });
            }
        }
    }
    let mut reach = BTreeSet::from([d]);
    let mut queue = VecDeque::from([d]);
    while let Some(x) = queue.pop_front() {
        for y in adjacent.get(&x).into_iter().flatten() {
            if reach.insert(*y) {
                queue.push_back(*y);
            }
        }
    }
    let in_area: BTreeSet<Ipv4Addr> = reach.iter().map(|x| rids[x]).collect();
    let mut externals = Vec::new();
    for x in &reach {
        if e.devs[*x].role == Role::Inet {
            externals.push(AsExternal {
                adv: rids[x],
                net: Ipv4Addr::UNSPECIFIED,
                len: 0,
                metric: 1,
                tag: 1,
            });
        }
        for (net, len) in redistributed.get(x).into_iter().flatten() {
            externals.push(AsExternal {
                adv: rids[x],
                net: *net,
                len: *len,
                metric: BGP_METRIC,
                tag: 0,
            });
        }
    }
    externals.sort_by_key(|x| (x.net, x.len, x.adv));
    let own = &ifaces[&d];
    let mut neighbors = Vec::new();
    for i in own.iter().filter(|i| !i.loopback && !i.passive) {
        let seg = &segments[&(network(i.addr, i.len), i.len)];
        let dr = seg.iter().map(|(_, j)| j.addr).max().expect("a member");
        for (y, j) in seg.iter().filter(|(y, _)| *y != d) {
            let state = if seg.len() == 2 && seg.iter().all(|(_, k)| k.p2p) {
                "FULL/  -"
            } else if j.addr == dr {
                "FULL/DR"
            } else {
                "FULL/DROTHER"
            };
            neighbors.push((rids[y], j.addr, i.name.clone(), state));
        }
    }
    Some(Ospf {
        rid: rids[&d],
        ifaces: own.clone(),
        neighbors,
        routers: reach
            .iter()
            .map(|x| (rids[x], routers.get(x).cloned().unwrap_or_default()))
            .collect(),
        networks: networks
            .into_iter()
            .filter(|n| in_area.contains(&n.adv))
            .collect(),
        externals,
    })
}

fn mask(len: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0))
}

// NX-OS: `| json` for all VRFs, the process `UNDERLAY`.

fn nx_ctx(extra: Value) -> String {
    let mut ctx = json!({"ptag": "UNDERLAY", "cname": "default"});
    if let (Value::Object(c), Value::Object(x)) = (&mut ctx, extra) {
        c.extend(x);
    }
    super::nxos::pretty(&json!({"TABLE_ctx": {"ROW_ctx": [ctx]}}))
}

fn nx_head(lsid: Ipv4Addr, adv: Ipv4Addr) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("lsid".into(), json!(lsid.to_string()));
    m.insert("advrouter".into(), json!(adv.to_string()));
    m.insert("seqno".into(), json!(format!("{SEQ:#010x}")));
    m.insert("age".into(), json!(AGE.to_string()));
    m
}

fn nx_area(lsas: Vec<Value>) -> Value {
    json!({"TABLE_area": {"ROW_area": [{"aid": BACKBONE, "TABLE_lsdb": {"ROW_lsdb": lsas}}]}})
}

/// The OSPF sections of an NX-OS switch. A switch with no OSPF, and each
/// OSPFv3 section, has the answer of a feature that is not on.
pub fn nxos(
    e: &Estate,
    d: usize,
    redistributed: &Redistributed,
    out: &mut BTreeMap<&'static str, String>,
) {
    let no = super::nxos::NO_FEATURE;
    for n in rsim_collect::ospf::V3 {
        out.insert(n, no.to_string());
    }
    let Some(o) = of(e, d, redistributed) else {
        for n in rsim_collect::ospf::V2 {
            out.insert(n, no.to_string());
        }
        return;
    };
    out.insert(
        "ospf",
        nx_ctx(json!({"rid": o.rid.to_string(), "TABLE_area": {"ROW_area": [{"aid": BACKBONE}]}})),
    );
    let intf: Vec<Value> = o
        .ifaces
        .iter()
        .map(|i| {
            json!({"ifname": i.name, "addr": i.addr.to_string(), "masklen": i.len.to_string(),
                   "area": BACKBONE, "cost": i.cost.to_string()})
        })
        .collect();
    out.insert(
        "ospf_interfaces",
        nx_ctx(json!({"TABLE_intf": {"ROW_intf": intf}})),
    );
    let nbr: Vec<Value> = o
        .neighbors
        .iter()
        .map(|(r, a, i, _)| {
            json!({"rid": r.to_string(), "addr": a.to_string(), "intf": i, "state": "FULL"})
        })
        .collect();
    out.insert(
        "ospf_neighbors",
        nx_ctx(json!({"TABLE_nbr": {"ROW_nbr": nbr}})),
    );
    let routers: Vec<Value> = o
        .routers
        .iter()
        .map(|(rid, links)| {
            let mut m = nx_head(*rid, *rid);
            let rows: Vec<Value> = links
                .iter()
                .map(|l| match l {
                    Link::P2p { nbr, own, metric } => json!({"type": "p2p", "id": nbr.to_string(),
                        "data": own.to_string(), "metric": metric.to_string()}),
                    Link::Transit { dr, own, metric } => {
                        json!({"type": "transit", "id": dr.to_string(),
                        "data": own.to_string(), "metric": metric.to_string()})
                    }
                    Link::Stub { net, len, metric } => {
                        json!({"type": "stub", "id": net.to_string(),
                        "data": mask(*len).to_string(), "metric": metric.to_string()})
                    }
                })
                .collect();
            m.insert("TABLE_link".into(), json!({"ROW_link": rows}));
            Value::Object(m)
        })
        .collect();
    out.insert("ospf_lsdb_router", nx_ctx(nx_area(routers)));
    let nets: Vec<Value> = o
        .networks
        .iter()
        .map(|n| {
            let mut m = nx_head(n.dr, n.adv);
            m.insert("netmask".into(), json!(mask(n.len).to_string()));
            let rtr: Vec<Value> = n
                .attached
                .iter()
                .map(|r| json!({"rtr": r.to_string()}))
                .collect();
            m.insert("TABLE_rtr".into(), json!({"ROW_rtr": rtr}));
            Value::Object(m)
        })
        .collect();
    out.insert("ospf_lsdb_network", nx_ctx(nx_area(nets)));
    for n in [
        "ospf_lsdb_summary",
        "ospf_lsdb_asbr_summary",
        "ospf_lsdb_nssa_external",
    ] {
        out.insert(n, nx_ctx(nx_area(Vec::new())));
    }
    let ext: Vec<Value> = o
        .externals
        .iter()
        .map(|x| {
            let mut m = nx_head(x.net, x.adv);
            m.insert("netmask".into(), json!(mask(x.len).to_string()));
            m.insert("metric".into(), json!(x.metric.to_string()));
            m.insert("metrictype".into(), json!("2"));
            m.insert("fwdaddr".into(), json!("0.0.0.0"));
            Value::Object(m)
        })
        .collect();
    out.insert(
        "ospf_lsdb_external",
        nx_ctx(json!({"TABLE_lsdb": {"ROW_lsdb": ext}})),
    );
}

// IOS-XE and IOS-XR: the text of `show ip ospf ...` and `show ospf ...`.

fn lsa_head(s: &mut String, kind: &str, lsid: Ipv4Addr, adv: Ipv4Addr, suffix: &str) {
    let _ = writeln!(
        s,
        "  LS age: {AGE}\n  Options: (No TOS-capability, DC)\n  LS Type: {kind}\n  Link State ID: {lsid}{suffix}\n  \
         Advertising Router: {adv}\n  LS Seq Number: {SEQ:X}\n  Checksum: 0x1A2B\n  Length: 48"
    );
}

fn header(stamp: &str, o: &Ospf, process: &str, title: &str) -> String {
    let mut s = String::from(stamp);
    let _ = writeln!(
        s,
        "\n            OSPF Router with ID ({}) (Process ID {process})\n\n                {title} (Area 0)\n",
        o.rid
    );
    s
}

/// The OSPF sections of an IOS-XE or IOS-XR router. `stamp` is the time
/// line before each IOS-XR answer. A router with no OSPF answers each
/// command with the stamp alone, as does each OSPFv3 command.
pub fn cisco(
    e: &Estate,
    d: usize,
    stamp: &str,
    process: &str,
    redistributed: &Redistributed,
    out: &mut BTreeMap<&'static str, String>,
) {
    for n in rsim_collect::ospf::V3 {
        out.insert(n, stamp.to_string());
    }
    let Some(o) = of(e, d, redistributed) else {
        for n in rsim_collect::ospf::V2 {
            out.insert(n, stamp.to_string());
        }
        return;
    };
    let mut p = String::from(stamp);
    let _ = writeln!(
        p,
        " Routing Process \"ospf {process}\" with ID {}\n Supports only single TOS(TOS0) routes\n \
         Area BACKBONE(0)\n    Number of interfaces in this area is {}\n",
        o.rid,
        o.ifaces.len()
    );
    out.insert("ospf", p);
    let mut s = String::from(stamp);
    for i in &o.ifaces {
        let kind = if i.loopback {
            "LOOPBACK"
        } else if i.p2p {
            "POINT_TO_POINT"
        } else {
            "BROADCAST"
        };
        let _ = writeln!(
            s,
            "{} is up, line protocol is up\n  Internet Address {}/{}, Area 0, Attached via Interface Enable\n  \
             Process ID {process}, Router ID {}, Network Type {kind}, Cost: {}",
            i.name, i.addr, i.len, o.rid, i.cost
        );
    }
    out.insert("ospf_interfaces", s);
    let mut s = String::from(stamp);
    s.push_str("Neighbor ID     Pri   State           Dead Time   Address         Interface\n");
    for (r, a, i, state) in &o.neighbors {
        let _ = writeln!(s, "{r:<15}   1   {state:<15} 00:00:35    {a:<15} {i}");
    }
    out.insert("ospf_neighbors", s);
    let mut s = header(stamp, &o, process, "Router Link States");
    for (rid, links) in &o.routers {
        lsa_head(&mut s, "Router Links", *rid, *rid, "");
        let _ = writeln!(s, "  Number of Links: {}", links.len());
        for l in links {
            s.push('\n');
            let (desc, id, data, metric) = match l {
                Link::P2p { nbr, own, metric } => (
                    "another Router (point-to-point)\n     (Link ID) Neighboring Router ID:",
                    *nbr,
                    format!("(Link Data) Router Interface address: {own}"),
                    metric,
                ),
                Link::Transit { dr, own, metric } => (
                    "a Transit Network\n     (Link ID) Designated Router address:",
                    *dr,
                    format!("(Link Data) Router Interface address: {own}"),
                    metric,
                ),
                Link::Stub { net, len, metric } => (
                    "a Stub Network\n     (Link ID) Network/subnet number:",
                    *net,
                    format!("(Link Data) Network Mask: {}", mask(*len)),
                    metric,
                ),
            };
            let _ = writeln!(
                s,
                "    Link connected to: {desc} {id}\n     {data}\n      Number of MTID metrics: 0\n       TOS 0 Metrics: {metric}"
            );
        }
        s.push('\n');
    }
    out.insert("ospf_lsdb_router", s);
    let mut s = header(stamp, &o, process, "Net Link States");
    for n in &o.networks {
        lsa_head(
            &mut s,
            "Network Links",
            n.dr,
            n.adv,
            " (address of Designated Router)",
        );
        let _ = writeln!(s, "  Network Mask: /{}", n.len);
        for r in &n.attached {
            let _ = writeln!(s, "        Attached Router: {r}");
        }
        s.push('\n');
    }
    out.insert("ospf_lsdb_network", s);
    out.insert(
        "ospf_lsdb_summary",
        header(stamp, &o, process, "Summary Net Link States"),
    );
    out.insert(
        "ospf_lsdb_asbr_summary",
        header(stamp, &o, process, "Summary ASB Link States"),
    );
    out.insert(
        "ospf_lsdb_nssa_external",
        header(stamp, &o, process, "Type-7 AS External Link States"),
    );
    let mut s = String::from(stamp);
    let _ = writeln!(
        s,
        "\n            OSPF Router with ID ({}) (Process ID {process})\n\n                Type-5 AS External Link States\n",
        o.rid
    );
    for x in &o.externals {
        lsa_head(
            &mut s,
            "AS External Link",
            x.net,
            x.adv,
            " (External Network Number )",
        );
        let _ = write!(
            s,
            "  Network Mask: /{}\n        Metric Type: 2 (Larger than any link state path)\n        MTID: 0\n        \
             Metric: {}\n        Forward Address: 0.0.0.0\n        External Route Tag: {}\n\n",
            x.len, x.metric, x.tag
        );
    }
    out.insert("ospf_lsdb_external", s);
}

/// The link-state database of a router for the OSPF calculation of
/// `rsim-routing`, in area 0 of the default VRF.
fn database(o: &Ospf) -> rsim_routing::ospf::Database {
    use rsim_routing::ospf::{
        BACKBONE, Body, Database, Interface, LinkKind, Lsa, LsaType, RouterLink, Version,
    };
    let span = rsim_core::SourceSpan::line("demo", 1);
    let mut db = Database::new(Version::V2, "default", "1");
    db.router_id = Some(o.rid);
    for i in &o.ifaces {
        db.interfaces.push(Interface {
            name: i.name.clone(),
            area: Some(BACKBONE),
            address: Some((std::net::IpAddr::V4(i.addr), Some(i.len))),
            interface_id: None,
            cost: Some(i.cost),
            span: span.clone(),
        });
    }
    let lsa = |lsa_type, lsid, adv_router, body| Lsa {
        lsa_type,
        area: Some(BACKBONE),
        lsid,
        adv_router,
        seq: Some(SEQ),
        age: Some(AGE),
        body,
        span: span.clone(),
    };
    for (rid, links) in &o.routers {
        let links = links
            .iter()
            .map(|l| {
                let (kind, id, data, metric) = match l {
                    Link::P2p { nbr, own, metric } => {
                        (LinkKind::PointToPoint, *nbr, Some(*own), *metric)
                    }
                    Link::Transit { dr, own, metric } => {
                        (LinkKind::Transit, *dr, Some(*own), *metric)
                    }
                    Link::Stub { net, len, metric } => {
                        (LinkKind::Stub, *net, Some(mask(*len)), *metric)
                    }
                };
                RouterLink {
                    kind,
                    id,
                    data,
                    metric,
                    interface_id: None,
                    neighbor_interface_id: None,
                }
            })
            .collect();
        db.insert(lsa(LsaType::Router, *rid, *rid, Body::Router { links }));
    }
    for n in &o.networks {
        db.insert(lsa(
            LsaType::Network,
            n.dr,
            n.adv,
            Body::Network {
                mask: Some(mask(n.len)),
                attached: n.attached.clone(),
            },
        ));
    }
    for x in &o.externals {
        db.insert(lsa(
            LsaType::External,
            x.net,
            x.adv,
            Body::External {
                prefix: rsim_core::Prefix::new(std::net::IpAddr::V4(x.net), x.len),
                metric: x.metric,
                metric_type: Some(2),
                forwarding: None,
            },
        ));
    }
    db
}

/// The OSPF routes of the router `d` from the calculation of `rsim-routing`
/// on its database, or `None` for a device with no OSPF. A route with no
/// next hop or that depends on a gap is left out.
pub fn routes(
    e: &Estate,
    d: usize,
    os: Os,
    redistributed: &Redistributed,
) -> Option<Vec<super::route::Route>> {
    use rsim_routing::Platform;
    use rsim_routing::ospf::{OspfProfile, PathType, compute};
    let o = of(e, d, redistributed)?;
    let platform = match os {
        Os::Nxos => Platform::Nxos,
        Os::Iosxe => Platform::Iosxe,
        Os::Iosxr => Platform::Iosxr,
    };
    let calc = compute(&database(&o), o.rid, &OspfProfile::of(platform));
    let mut out = Vec::new();
    for r in calc.routes.iter().filter(|r| r.unknown.is_none()) {
        let std::net::IpAddr::V4(net) = r.prefix.addr() else {
            continue;
        };
        let paths: Vec<super::route::Path> = r
            .next_hops
            .iter()
            .map(|h| super::route::Path {
                next_hop: match h.gateway {
                    std::net::IpAddr::V4(g) => Some(g),
                    std::net::IpAddr::V6(_) => None,
                },
                iface: h.interface.clone(),
                vxlan: None,
            })
            .collect();
        if paths.is_empty() {
            continue;
        }
        out.push(super::route::Route {
            vrf: "default".to_string(),
            prefix: (net, r.prefix.len()),
            kind: super::route::Kind::Ospf,
            external: matches!(r.path_type, PathType::External1 | PathType::External2),
            metric: r.metric,
            paths,
        });
    }
    Some(out)
}
