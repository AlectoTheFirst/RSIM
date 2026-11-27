//! The OSPF link-state database of each OSPF router of the demo estate, in
//! area 0 of the default VRF, and its OSPF sections in the formats that the
//! NX-OS, IOS-XE and IOS-XR readers of `rsim-ingest` read.
//!
//! An OSPF interface is an interface with `ospf` in the default VRF: on
//! NX-OS a routed port or a loopback. A routed port of NX-OS and IOS-XE and
//! each port of IOS-XR other than a loopback is point-to-point; an IOS-XE
//! SVI is a broadcast segment whose designated router has the highest
//! address. A loopback is a stub link of its /32 with the cost 1. A router
//! of the internet edge originates the default route as an external LSA of
//! type 2 with the metric 1. The database of a router holds the LSAs of the
//! routers that its adjacencies reach.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write;
use std::net::Ipv4Addr;

use serde_json::{Value, json};

use super::model::*;

const AGE: u32 = 100;
const SEQ: u32 = 0x8000_0001;
const BACKBONE: &str = "0.0.0.0";

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
    /// The routers that originate the default route.
    externals: Vec<Ipv4Addr>,
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
                cost: if loopback {
                    1
                } else {
                    i.routing.map_or(1, |r| r.0)
                },
                p2p,
                loopback,
            })
        })
        .collect()
}

/// The OSPF state of the router `d`, or `None` for a device with no OSPF.
pub fn of(e: &Estate, d: usize) -> Option<Ospf> {
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
        for i in list.iter().filter(|i| !i.loopback) {
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
                metric: 1,
            });
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
    let own = &ifaces[&d];
    let mut neighbors = Vec::new();
    for i in own.iter().filter(|i| !i.loopback) {
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
        externals: reach
            .iter()
            .filter(|x| e.devs[**x].role == Role::Inet)
            .map(|x| rids[x])
            .collect(),
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
pub fn nxos(e: &Estate, d: usize, out: &mut BTreeMap<&'static str, String>) {
    let no = super::nxos::NO_FEATURE;
    for n in rsim_collect::ospf::V3 {
        out.insert(n, no.to_string());
    }
    let Some(o) = of(e, d) else {
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
        .map(|adv| {
            let mut m = nx_head(Ipv4Addr::UNSPECIFIED, *adv);
            m.insert("netmask".into(), json!("0.0.0.0"));
            m.insert("metric".into(), json!("1"));
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
    out: &mut BTreeMap<&'static str, String>,
) {
    for n in rsim_collect::ospf::V3 {
        out.insert(n, stamp.to_string());
    }
    let Some(o) = of(e, d) else {
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
    for adv in &o.externals {
        lsa_head(
            &mut s,
            "AS External Link",
            Ipv4Addr::UNSPECIFIED,
            *adv,
            " (External Network Number )",
        );
        s.push_str(
            "  Network Mask: /0\n        Metric Type: 2 (Larger than any link state path)\n        MTID: 0\n        \
             Metric: 1\n        Forward Address: 0.0.0.0\n        External Route Tag: 1\n\n",
        );
    }
    out.insert("ospf_lsdb_external", s);
}
