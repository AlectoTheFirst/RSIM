//! The links between NX-OS switches and to VyOS routers from LLDP and CDP,
//! and the place of each NX-OS endpoint across these links. Both need all
//! devices of the estate, so the estate runs them between a first lowering
//! of each switch, which gives its summary, and the final lowering.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{FunctionId, Mac, Prefix, PrefixTable, SourceSpan, TriePrefixTable};
use rsim_functions::{HostMac, LinkEnd};

use super::names::Names;
use super::state::Neighbour;

/// The VLANs of a switch port.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortVlans {
    pub native: Option<u16>,
    pub tagged: BTreeSet<u16>,
    /// An access port with no LLDP or CDP neighbour.
    pub edge: bool,
}

/// The facts of a VLAN with an SVI on a switch, for the hosts of the VLAN.
#[derive(Clone, Debug, Default)]
pub struct VlanInfo {
    /// The SVI addresses and the active virtual addresses.
    pub hosts: TriePrefixTable<HostMac>,
    pub local: Vec<Prefix>,
    pub gateway: Option<HostMac>,
}

/// The summary of a switch from its first lowering.
#[derive(Clone, Debug, Default)]
pub struct Summary {
    pub host_name: Option<String>,
    pub names: Names,
    /// The port channel of each member port.
    pub channel: BTreeMap<String, String>,
    /// The switch ports with their VLANs, or `None` for a port that gives
    /// `Unknown`.
    pub ports: BTreeMap<String, Option<PortVlans>>,
    /// The routed ports and port channels that can end a link.
    pub routed: BTreeSet<String>,
    /// The port of each MAC in each VLAN, with the span of its row.
    pub macs: BTreeMap<(u16, Mac), (String, SourceSpan)>,
    pub vlans: BTreeMap<u16, VlanInfo>,
    /// The ARP rows of the SVIs: the VLAN, the address, the MAC, the span.
    pub arp: Vec<(u16, IpAddr, Mac, SourceSpan)>,
    pub neighbours: Vec<Neighbour>,
    pub neighbour_section: bool,
    /// The next hops of the routes of the switch.
    pub next_hops: BTreeSet<IpAddr>,
    /// The physical facts of each port.
    pub facts: BTreeMap<String, LinkEnd>,
    pub vpc: Option<VpcSummary>,
}

/// The vPC facts of a switch.
#[derive(Clone, Debug, Default)]
pub struct VpcSummary {
    pub domain: u32,
    /// True if the domain is lowered: its config is read and its peer status
    /// is `peer-ok`.
    pub ok: bool,
    /// The vPC id of each member port channel.
    pub members: BTreeMap<String, u32>,
    /// The vPC ids whose member port channel is down.
    pub down: BTreeSet<u32>,
    /// The vPC ids whose member port channel is up.
    pub up: BTreeSet<u32>,
    /// The MAC of each SVI.
    pub svi_macs: BTreeMap<String, Mac>,
    /// The peer-link port channel.
    pub peer_link: Option<String>,
}

/// The vPC facts of the peer switch of a vPC pair.
#[derive(Clone, Debug, Default)]
pub struct VpcPeer {
    /// The vPC ids whose member port channel is down on the peer.
    pub down: BTreeSet<u32>,
    /// The vPC ids whose member port channel is up on the peer.
    pub up: BTreeSet<u32>,
    /// The MAC of each SVI of the peer.
    pub svi_macs: BTreeMap<String, Mac>,
}

impl Summary {
    /// The config name of a port that a section prints, with a member port
    /// as its port channel.
    pub fn port(&self, name: &str) -> String {
        let n = self.names.resolve(name);
        self.channel.get(&n).cloned().unwrap_or(n)
    }
}

/// An interface of a VyOS router that can end a link: the physical
/// interface, its MAC, the span of its row and its physical facts.
#[derive(Clone, Debug)]
pub struct RouterPort {
    pub interface: String,
    pub mac: Mac,
    pub span: SourceSpan,
    pub facts: Option<LinkEnd>,
}

/// The far end of a link from a port.
#[derive(Clone, Debug)]
pub struct Peer {
    /// The ingress or the hand-off function of the far end.
    pub target: FunctionId,
    pub provenance: Vec<SourceSpan>,
    pub remote: Option<LinkEnd>,
}

/// An endpoint on a port of a switch, with the facts of its VLAN from the
/// switch with the SVI.
#[derive(Clone, Debug)]
pub struct Placed {
    pub id: String,
    pub port: String,
    pub mac: Mac,
    pub addrs: Vec<(IpAddr, SourceSpan)>,
    /// The spans of the MAC table rows on the way to the port.
    pub spans: Vec<SourceSpan>,
    pub hosts: TriePrefixTable<HostMac>,
    pub local: Vec<Prefix>,
    pub gateway: Option<HostMac>,
}

/// The facts from outside a switch for its final lowering.
#[derive(Clone, Debug, Default)]
pub struct External {
    /// The peers of each port with a link: one, or 2 for a link to the 2
    /// switches of a vPC pair.
    pub peers: BTreeMap<String, Vec<Peer>>,
    pub endpoints: Vec<Placed>,
    /// The peer switch of the vPC pair, if it is in the estate.
    pub vpc_peer: Option<VpcPeer>,
}

/// One end of a link.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum End {
    Switch(String, String),
    Router(String, String),
}

/// The ends and the facts that the estate gives the lowerings.
#[derive(Default)]
pub struct Joined {
    pub switches: BTreeMap<String, External>,
    /// The peer of each physical interface of each VyOS router, in the form
    /// of `vyos::Layer2Links`.
    pub routers: BTreeMap<String, crate::vyos::Layer2Links>,
    pub notes: BTreeMap<String, Vec<String>>,
}

fn target(switches: &BTreeMap<String, Summary>, end: &End) -> Option<FunctionId> {
    match end {
        End::Switch(d, p) => {
            let s = switches.get(d)?;
            if s.ports.contains_key(p) {
                Some(FunctionId::new(format!("{d}/port/{p}/in")))
            } else if s.routed.contains(p) {
                Some(FunctionId::new(format!("{d}/handoff/{p}")))
            } else {
                None
            }
        }
        End::Router(r, i) => Some(FunctionId::new(format!("{r}/handoff/{i}"))),
    }
}

/// The links of the estate. A link needs one far end for all LLDP and CDP
/// rows of a port. When the far end is a switch with a neighbour section,
/// that switch must report the link too. An end that 2 links claim gets no
/// link.
pub fn join(
    switches: &BTreeMap<String, Summary>,
    routers: &BTreeMap<String, Vec<RouterPort>>,
    next_hops: &BTreeSet<IpAddr>,
    device_macs: &BTreeSet<Mac>,
) -> Joined {
    let mut out = Joined::default();
    let by_name: BTreeMap<&str, &str> = switches
        .iter()
        .filter_map(|(d, s)| Some((s.host_name.as_deref()?, d.as_str())))
        .collect();
    let router_of = |m: Mac| -> Option<(String, &RouterPort)> {
        routers
            .iter()
            .find_map(|(r, ports)| ports.iter().find(|p| p.mac == m).map(|p| (r.clone(), p)))
    };

    // The far end that each switch port names.
    let mut named: BTreeMap<End, (Option<End>, Vec<SourceSpan>)> = BTreeMap::new();
    let mut vpc_named: BTreeMap<End, (Vec<End>, Vec<SourceSpan>)> = BTreeMap::new();
    for (d, s) in switches {
        let mut rows: BTreeMap<String, Vec<&Neighbour>> = BTreeMap::new();
        for n in &s.neighbours {
            rows.entry(s.port(&n.port)).or_default().push(n);
        }
        for (port, list) in rows {
            let mut router_notes: Vec<String> = Vec::new();
            let mut far: BTreeSet<Option<End>> = BTreeSet::new();
            for n in &list {
                let sw = n
                    .name
                    .as_deref()
                    .and_then(|x| by_name.get(x))
                    .filter(|x| **x != d.as_str());
                let end = match sw {
                    Some(other) => {
                        let o = &switches[*other];
                        n.remote_port
                            .as_deref()
                            .map(|rp| End::Switch((*other).to_string(), o.port(rp)))
                    }
                    None => {
                        // The router of the port MAC, else of the chassis
                        // MAC. The interface of the port MAC, else of the
                        // port name on that router. A chassis MAC names the
                        // router, not the interface.
                        let router = n
                            .port_mac
                            .and_then(router_of)
                            .or_else(|| n.chassis.and_then(router_of))
                            .map(|(r, _)| r);
                        match router {
                            Some(r) => {
                                let ports = &routers[&r];
                                let iface = n
                                    .port_mac
                                    .and_then(|m| ports.iter().find(|p| p.mac == m))
                                    .or_else(|| {
                                        let rp = n.remote_port.as_deref()?;
                                        ports.iter().find(|p| p.interface == rp)
                                    });
                                match iface {
                                    Some(p) => Some(End::Router(r, p.interface.clone())),
                                    None => {
                                        router_notes.push(format!(
                                            "{port}: the neighbour {r} names no interface of its own, so the port has no link"
                                        ));
                                        None
                                    }
                                }
                            }
                            None => None,
                        }
                    }
                };
                far.insert(end);
            }
            out.notes.entry(d.clone()).or_default().extend(router_notes);
            let spans = list.iter().map(|n| n.span.clone()).collect();
            let here = End::Switch(d.clone(), port.clone());
            // The member ports of one vPC on the 2 switches of a vPC pair.
            let vpc_ends: Option<Vec<End>> = (far.len() == 2)
                .then(|| far.iter().cloned().collect::<Option<Vec<End>>>())
                .flatten()
                .filter(|ends| {
                    let ids: BTreeSet<(u32, u32)> = ends
                        .iter()
                        .filter_map(|e| match e {
                            End::Switch(o, p) => {
                                let v = switches[o].vpc.as_ref().filter(|v| v.ok)?;
                                Some((v.domain, *v.members.get(p)?))
                            }
                            End::Router(..) => None,
                        })
                        .collect();
                    let devs: BTreeSet<&str> = ends
                        .iter()
                        .filter_map(|e| match e {
                            End::Switch(o, _) => Some(o.as_str()),
                            End::Router(..) => None,
                        })
                        .collect();
                    ids.len() == 1 && devs.len() == 2
                });
            if far.len() == 1 {
                named.insert(here, (far.into_iter().next().flatten(), spans));
            } else if let Some(ends) = vpc_ends {
                vpc_named.insert(here, (ends, spans));
            } else {
                out.notes.entry(d.clone()).or_default().push(format!(
                    "{port}: the LLDP and CDP rows name more than one neighbour, so the port has no link"
                ));
            }
        }
    }

    // The links: a port that names a far end, confirmed by the far end if it
    // has a neighbour section.
    let mut links: Vec<(End, End, Vec<SourceSpan>)> = Vec::new();
    for (here, (far, spans)) in &named {
        let Some(far) = far else {
            continue;
        };
        // A member port of a vPC that links to a port with 2 peers: the vPC
        // link below covers it.
        if vpc_named.get(far).is_some_and(|(e, _)| e.contains(here)) {
            continue;
        }
        let confirmed = match far {
            End::Switch(o, _) => {
                if !switches[o].neighbour_section {
                    true
                } else {
                    match named.get(far) {
                        Some((Some(back), _)) => back == here,
                        _ => false,
                    }
                }
            }
            End::Router(..) => true,
        };
        if !confirmed {
            let End::Switch(d, p) = here else { continue };
            out.notes.entry(d.clone()).or_default().push(format!(
                "{p}: the neighbour does not report the link back, so the port has no link"
            ));
            continue;
        }
        // Each link once: from the smaller end of 2 switches.
        if let End::Switch(..) = far
            && named.get(far).and_then(|x| x.0.as_ref()) == Some(here)
            && far < here
        {
            continue;
        }
        let mut spans = spans.clone();
        if let Some((_, back)) = named.get(far) {
            spans.extend(back.iter().cloned());
        }
        links.push((here.clone(), far.clone(), spans));
    }

    // The vPC pairs: 2 switches of one lowered domain whose peer-link port
    // channels a link joins.
    let peer_link = |e: &End| -> Option<(String, u32)> {
        let End::Switch(d, p) = e else { return None };
        let v = switches[d].vpc.as_ref().filter(|v| v.ok)?;
        (v.peer_link.as_deref() == Some(p.as_str())).then(|| (d.clone(), v.domain))
    };
    let mut pairs: BTreeSet<(String, String)> = BTreeSet::new();
    for (a, b, _) in &links {
        if let (Some((da, x)), Some((db, y))) = (peer_link(a), peer_link(b))
            && x == y
            && da != db
        {
            pairs.insert((da.clone(), db.clone()));
            pairs.insert((db, da));
        }
    }

    // A link to a vPC pair: the 2 member ports are on a pair, and each must
    // report the link back if its switch has a neighbour section.
    let mut vpc_links: Vec<(End, Vec<End>, Vec<SourceSpan>)> = Vec::new();
    for (here, (ends, spans)) in &vpc_named {
        let devs: Vec<&str> = ends
            .iter()
            .filter_map(|e| match e {
                End::Switch(d, _) => Some(d.as_str()),
                End::Router(..) => None,
            })
            .collect();
        let paired = matches!(devs.as_slice(), [a, b] if pairs.contains(&((*a).to_string(), (*b).to_string())));
        let confirmed = paired
            && ends.iter().all(|f| match f {
                End::Switch(o, _) => {
                    !switches[o].neighbour_section
                        || matches!(named.get(f), Some((Some(back), _)) if back == here)
                }
                End::Router(..) => false,
            });
        if !confirmed {
            let End::Switch(d, p) = here else { continue };
            out.notes.entry(d.clone()).or_default().push(format!(
                "{p}: the vPC pair does not report the link back, so the port has no link"
            ));
            continue;
        }
        let mut spans = spans.clone();
        for f in ends {
            if let Some((_, back)) = named.get(f) {
                spans.extend(back.iter().cloned());
            }
        }
        vpc_links.push((here.clone(), ends.clone(), spans));
    }
    // The member ports of a vPC link do not link on their own.
    let vpc_members: BTreeSet<&End> = vpc_links.iter().flat_map(|(_, e, _)| e.iter()).collect();
    links.retain(|(a, b, _)| !vpc_members.contains(a) && !vpc_members.contains(b));

    // An end that 2 links claim gets no link.
    let mut claims: BTreeMap<&End, u32> = BTreeMap::new();
    for (a, b, _) in &links {
        *claims.entry(a).or_default() += 1;
        *claims.entry(b).or_default() += 1;
    }
    for (a, ends, _) in &vpc_links {
        *claims.entry(a).or_default() += 1;
        for b in ends {
            *claims.entry(b).or_default() += 1;
        }
    }
    let doubled: BTreeSet<End> = claims
        .iter()
        .filter(|(_, n)| **n > 1)
        .map(|(e, _)| (*e).clone())
        .collect();
    for e in &doubled {
        let (dev, what) = match e {
            End::Switch(d, p) | End::Router(d, p) => (d.clone(), p.clone()),
        };
        out.notes
            .entry(dev)
            .or_default()
            .push(format!("{what}: 2 links claim the port, so it has no link"));
    }

    let facts = |e: &End| -> Option<LinkEnd> {
        match e {
            End::Switch(d, p) => switches.get(d)?.facts.get(p).cloned(),
            End::Router(r, i) => routers
                .get(r)?
                .iter()
                .find(|p| p.interface == *i)?
                .facts
                .clone(),
        }
    };
    for (a, b, spans) in links {
        if doubled.contains(&a) || doubled.contains(&b) {
            continue;
        }
        let (Some(ta), Some(tb)) = (target(switches, &a), target(switches, &b)) else {
            let End::Switch(d, p) = &a else { continue };
            out.notes.entry(d.clone()).or_default().push(format!(
                "{p}: an end of the link is not a lowered port, so the port has no link"
            ));
            continue;
        };
        for (from, to, t) in [(&a, &b, tb), (&b, &a, ta)] {
            match from {
                End::Switch(d, p) => {
                    out.switches
                        .entry(d.clone())
                        .or_default()
                        .peers
                        .entry(p.clone())
                        .or_default()
                        .push(Peer {
                            target: t,
                            provenance: spans.clone(),
                            remote: facts(to),
                        });
                }
                End::Router(r, i) => {
                    out.routers
                        .entry(r.clone())
                        .or_default()
                        .insert(i.clone(), (t, spans.clone(), facts(to)));
                }
            }
        }
    }
    for (a, ends, spans) in vpc_links {
        if doubled.contains(&a) || ends.iter().any(|e| doubled.contains(e)) {
            continue;
        }
        let ta = target(switches, &a);
        let tb: Option<Vec<FunctionId>> = ends.iter().map(|e| target(switches, e)).collect();
        let (Some(ta), Some(tb), End::Switch(d, p)) = (ta, tb, &a) else {
            continue;
        };
        for (e, t) in ends.iter().zip(tb) {
            out.switches
                .entry(d.clone())
                .or_default()
                .peers
                .entry(p.clone())
                .or_default()
                .push(Peer {
                    target: t,
                    provenance: spans.clone(),
                    remote: facts(e),
                });
            if let End::Switch(d2, p2) = e {
                out.switches
                    .entry(d2.clone())
                    .or_default()
                    .peers
                    .entry(p2.clone())
                    .or_default()
                    .push(Peer {
                        target: ta.clone(),
                        provenance: spans.clone(),
                        remote: facts(&a),
                    });
            }
        }
    }

    // The vPC peer of each switch of a pair.
    for (a, b) in &pairs {
        let v = switches[b].vpc.as_ref().expect("a domain");
        out.switches.entry(a.clone()).or_default().vpc_peer = Some(VpcPeer {
            down: v.down.clone(),
            up: v.up.clone(),
            svi_macs: v.svi_macs.clone(),
        });
    }
    place(switches, &mut out, next_hops, device_macs);
    out
}

/// The places of the endpoints. From an ARP row of an SVI, the MAC table
/// rows lead across the links of switch ports to an edge access port. One
/// endpoint is one MAC on one port, with the addresses of all ARP rows that
/// lead there. A MAC with an address that is a next hop, or a MAC of a
/// collected device, is not an endpoint.
fn place(
    switches: &BTreeMap<String, Summary>,
    out: &mut Joined,
    next_hops: &BTreeSet<IpAddr>,
    device_macs: &BTreeSet<Mac>,
) {
    // The far end of each linked switch port.
    let mut far: BTreeMap<(String, String), (String, String)> = BTreeMap::new();
    for (d, ext) in &out.switches {
        for (p, list) in &ext.peers {
            let [peer] = list.as_slice() else {
                continue;
            };
            let t = peer.target.as_str();
            if let Some((dev, rest)) = t.split_once("/port/")
                && let Some(port) = rest.strip_suffix("/in")
            {
                far.insert((d.clone(), p.clone()), (dev.to_string(), port.to_string()));
            }
        }
    }
    // Each ARP row leads to a place, or to none.
    struct At {
        vlan: u16,
        addrs: Vec<(IpAddr, SourceSpan)>,
        spans: Vec<SourceSpan>,
        /// The switches with an SVI that lead here, with their VLAN.
        svis: BTreeSet<(String, u16)>,
    }
    let mut at: BTreeMap<(String, String, Mac), At> = BTreeMap::new();
    for (s, sum) in switches {
        for (v, ip, m, span) in &sum.arp {
            let (mut dev, mut vlan) = (s.clone(), *v);
            let mut seen = BTreeSet::new();
            let mut spans = Vec::new();
            let mut place = None;
            while seen.insert(dev.clone()) {
                let here = &switches[&dev];
                let Some((port, row)) = here.macs.get(&(vlan, *m)) else {
                    break;
                };
                spans.push(row.clone());
                let Some(Some(pv)) = here.ports.get(port) else {
                    break;
                };
                // A port with a link leads on; it is never an edge port.
                let Some((d2, q)) = far.get(&(dev.clone(), port.clone())) else {
                    if pv.edge && pv.native == Some(vlan) {
                        place = Some((dev.clone(), port.clone()));
                    }
                    break;
                };
                let Some(Some(qv)) = switches[d2].ports.get(q) else {
                    break;
                };
                // The tag of the frame on the link gives the VLAN on the far
                // switch.
                vlan = if pv.tagged.contains(&vlan) && qv.tagged.contains(&vlan) {
                    vlan
                } else if pv.native == Some(vlan) && qv.native.is_some() {
                    qv.native.unwrap_or(vlan)
                } else {
                    break;
                };
                dev = d2.clone();
            }
            let Some((dev, port)) = place else {
                continue;
            };
            let e = at.entry((dev, port, *m)).or_insert_with(|| At {
                vlan,
                addrs: Vec::new(),
                spans: spans.clone(),
                svis: BTreeSet::new(),
            });
            if !e.addrs.iter().any(|(x, _)| x == ip) {
                e.addrs.push((*ip, span.clone()));
            }
            e.svis.insert((s.clone(), *v));
        }
    }
    // The host table of each VLAN of a switch with an SVI: its own entries
    // and the addresses of the endpoints that its VLAN leads to.
    let mut hosts: BTreeMap<(String, u16), TriePrefixTable<HostMac>> = BTreeMap::new();
    let mut keep = Vec::new();
    for ((dev, port, m), a) in at {
        let id = format!("{dev}/vlan{}/{m:?}", a.vlan);
        let why = if device_macs.contains(&m) {
            Some("a MAC of a collected device")
        } else if a.addrs.iter().any(|(ip, _)| next_hops.contains(ip)) {
            Some("a next hop of a route")
        } else {
            None
        };
        if let Some(why) = why {
            out.notes
                .entry(dev.clone())
                .or_default()
                .push(format!("{id}: {why}, so it is not an endpoint"));
            continue;
        }
        for (s, v) in &a.svis {
            let t = hosts.entry((s.clone(), *v)).or_insert_with(|| {
                switches[s]
                    .vlans
                    .get(v)
                    .map(|x| x.hosts.clone())
                    .unwrap_or_default()
            });
            for (ip, span) in &a.addrs {
                let mut sp = vec![span.clone()];
                sp.extend(a.spans.iter().cloned());
                t.insert(Prefix::host(*ip), HostMac { mac: m, spans: sp });
            }
        }
        keep.push((id, dev, port, m, a));
    }
    for (id, dev, port, m, a) in keep {
        // The host table, the networks and the gateway of the first switch
        // with an SVI, with the endpoints of all of them.
        let Some((s, v)) = a.svis.iter().next().cloned() else {
            continue;
        };
        let info = switches[&s].vlans.get(&v).cloned().unwrap_or_default();
        let mut table = hosts.get(&(s, v)).cloned().unwrap_or_default();
        for (s2, v2) in a.svis.iter().skip(1) {
            if let Some(t) = hosts.get(&(s2.clone(), *v2)) {
                for (p, h) in t.entries() {
                    if table.get(&p).is_none() {
                        table.insert(p, h.clone());
                    }
                }
            }
        }
        out.switches.entry(dev).or_default().endpoints.push(Placed {
            id,
            port,
            mac: m,
            addrs: a.addrs,
            spans: a.spans,
            hosts: table,
            local: info.local,
            gateway: info.gateway,
        });
    }
}
