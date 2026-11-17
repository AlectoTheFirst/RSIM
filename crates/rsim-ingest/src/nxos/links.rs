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
    /// The peer of each port with a link.
    pub peers: BTreeMap<String, Peer>,
    pub endpoints: Vec<Placed>,
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
    for (d, s) in switches {
        let mut rows: BTreeMap<String, Vec<&Neighbour>> = BTreeMap::new();
        for n in &s.neighbours {
            rows.entry(s.port(&n.port)).or_default().push(n);
        }
        for (port, list) in rows {
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
                        let by_port = n.remote_port.as_deref().and_then(|rp| {
                            routers.iter().find_map(|(r, ports)| {
                                ports
                                    .iter()
                                    .find(|p| p.interface == rp)
                                    .map(|p| (r.clone(), p))
                            })
                        });
                        let found = n
                            .port_mac
                            .and_then(router_of)
                            .or_else(|| n.chassis.and_then(router_of));
                        match (found, by_port) {
                            (Some((r, _)), Some((r2, p))) if r == r2 => {
                                Some(End::Router(r, p.interface.clone()))
                            }
                            (Some((r, p)), _) => Some(End::Router(r, p.interface.clone())),
                            (None, _) => None,
                        }
                    }
                };
                far.insert(end);
            }
            let spans = list.iter().map(|n| n.span.clone()).collect();
            let here = End::Switch(d.clone(), port.clone());
            if far.len() == 1 {
                named.insert(here, (far.into_iter().next().flatten(), spans));
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

    // An end that 2 links claim gets no link.
    let mut claims: BTreeMap<&End, u32> = BTreeMap::new();
    for (a, b, _) in &links {
        *claims.entry(a).or_default() += 1;
        *claims.entry(b).or_default() += 1;
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
                    out.switches.entry(d.clone()).or_default().peers.insert(
                        p.clone(),
                        Peer {
                            target: t,
                            provenance: spans.clone(),
                            remote: facts(to),
                        },
                    );
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
    place(switches, &mut out, next_hops);
    out
}

/// The places of the endpoints. From an ARP row of an SVI, the MAC table
/// rows lead across the links of switch ports to an edge access port.
fn place(switches: &BTreeMap<String, Summary>, out: &mut Joined, next_hops: &BTreeSet<IpAddr>) {
    // The far end of each linked switch port.
    let mut far: BTreeMap<(String, String), (String, String)> = BTreeMap::new();
    for (d, ext) in &out.switches {
        for (p, peer) in &ext.peers {
            let t = peer.target.as_str();
            if let Some((dev, rest)) = t.split_once("/port/")
                && let Some(port) = rest.strip_suffix("/in")
            {
                far.insert((d.clone(), p.clone()), (dev.to_string(), port.to_string()));
            }
        }
    }
    // The endpoints of each switch with an SVI, by MAC and VLAN.
    #[allow(clippy::type_complexity)]
    let mut found: BTreeMap<
        (String, u16, Mac),
        (
            Vec<(IpAddr, SourceSpan)>,
            Option<(String, String, Vec<SourceSpan>)>,
        ),
    > = BTreeMap::new();
    for (s, sum) in switches {
        for (v, ip, m, span) in &sum.arp {
            let e = found.entry((s.clone(), *v, *m)).or_default();
            e.0.push((*ip, span.clone()));
            if e.1.is_some() {
                continue;
            }
            // The walk across the links, at most once through each switch.
            let (mut dev, mut vlan) = (s.clone(), *v);
            let mut seen = BTreeSet::new();
            let mut spans = Vec::new();
            while seen.insert(dev.clone()) {
                let here = &switches[&dev];
                let Some((port, row)) = here.macs.get(&(vlan, *m)) else {
                    break;
                };
                spans.push(row.clone());
                let Some(Some(pv)) = here.ports.get(port) else {
                    break;
                };
                if pv.edge && pv.native == Some(vlan) {
                    e.1 = Some((dev.clone(), port.clone(), spans.clone()));
                    break;
                }
                let Some((d2, q)) = far.get(&(dev.clone(), port.clone())) else {
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
        }
    }
    // A MAC with an address that is a next hop is a router.
    let mut hosts: BTreeMap<(String, u16), TriePrefixTable<HostMac>> = BTreeMap::new();
    let mut keep = Vec::new();
    for ((s, v, m), (addrs, at)) in found {
        let id = format!("{s}/vlan{v}/{m:?}");
        if addrs.iter().any(|(ip, _)| next_hops.contains(ip)) {
            out.notes.entry(s.clone()).or_default().push(format!(
                "{id}: a next hop of a route, so it is not an endpoint"
            ));
            continue;
        }
        let Some((dev, port, spans)) = at else {
            continue;
        };
        let t = hosts.entry((s.clone(), v)).or_insert_with(|| {
            switches[&s]
                .vlans
                .get(&v)
                .map(|x| x.hosts.clone())
                .unwrap_or_default()
        });
        for (ip, span) in &addrs {
            let mut sp = vec![span.clone()];
            sp.extend(spans.iter().cloned());
            t.insert(Prefix::host(*ip), HostMac { mac: m, spans: sp });
        }
        keep.push((s, v, m, id, addrs, dev, port, spans));
    }
    for (s, v, m, id, addrs, dev, port, spans) in keep {
        let info = switches[&s].vlans.get(&v).cloned().unwrap_or_default();
        out.switches.entry(dev).or_default().endpoints.push(Placed {
            id,
            port,
            mac: m,
            addrs,
            spans,
            hosts: hosts.get(&(s.clone(), v)).cloned().unwrap_or_default(),
            local: info.local,
            gateway: info.gateway,
        });
    }
}
