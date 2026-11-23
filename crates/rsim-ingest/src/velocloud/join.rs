//! The summary of each edge for the link join of the estate: its ports with
//! their entry functions and their layer 3 addresses, the addresses that
//! its ports name as their BGP neighbours and their gateways, and its next
//! hops. An edge gives no MAC, no ARP row and no neighbour record, so the
//! join links its ports by address.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{FunctionId, Prefix, SourceSpan};

use crate::links::{AddressPeer, PortAddress, Summary};

use super::lower::{usable_links, wan_iface};
use super::reader::{Edge, EdgeSegment, Enterprise, Interface, InterfaceKind, SessionSegment};

/// The state of an observed BGP session that is up.
const ESTABLISHED: &str = "ESTABLISHED";

/// The VRF of a segment for the address rules: its name, and none for the
/// Global Segment.
fn vrf(s: &EdgeSegment) -> Option<String> {
    (!s.global).then(|| s.name.clone())
}

/// The prefix length of a host address.
fn host_len(a: IpAddr) -> u8 {
    if a.is_ipv4() { 32 } else { 128 }
}

/// The summary of each edge of an enterprise, by twin device.
pub fn summaries(ent: &Enterprise) -> BTreeMap<String, Summary> {
    ent.edges
        .iter()
        .map(|e| (e.device.clone(), summary(ent, e)))
        .collect()
}

fn summary(ent: &Enterprise, e: &Edge) -> Summary {
    let mut s = Summary {
        by_address: true,
        ..Summary::default()
    };
    let entry = |port: &str| FunctionId::new(format!("{}/in/{port}", e.device));
    let global = e.segments.iter().find(|x| x.global);

    // The LAN interfaces with their segments.
    let mut lan: Vec<(&Interface, &EdgeSegment)> = Vec::new();
    for i in &e.interfaces {
        if i.wan || i.kind == InterfaceKind::Loopback {
            continue;
        }
        let seg = match i.segment {
            Some(id) => e.segments.iter().find(|x| x.id == id),
            None => global,
        };
        let Some(seg) = seg else {
            continue;
        };
        lan.push((i, seg));
        s.entries.insert(i.name.clone(), entry(i.name.as_str()));
        s.port_spans.insert(i.name.clone(), i.span.clone());
        if let Some((a, len)) = i.address {
            s.l3.insert(i.name.clone(), BTreeMap::from([(None, vec![(a, len)])]));
            s.port_addresses.push(PortAddress {
                port: i.name.clone(),
                address: a,
                vlan: None,
                vrf: vrf(seg),
                spans: vec![i.span.clone()],
            });
        }
    }

    // The WAN links: the interface address is evidence, the address after
    // a NAT is not, and the gateway names the far end.
    let global_name = global.map(|x| x.name.clone());
    let (used, _) = usable_links(e);
    for l in used {
        let port = wan_iface(l);
        s.entries.insert(port.clone(), entry(port.as_str()));
        let span = l.spans.first().cloned().unwrap_or_else(|| e.span.clone());
        s.port_spans.insert(port.clone(), span);
        if let Some(a) = l.local {
            let len = e
                .interfaces
                .iter()
                .find(|i| i.wan && i.name == port)
                .and_then(|i| i.address)
                .filter(|(x, _)| *x == a)
                .map_or_else(|| host_len(a), |(_, n)| n);
            s.l3.insert(port.clone(), BTreeMap::from([(None, vec![(a, len)])]));
            s.port_addresses.push(PortAddress {
                port: port.clone(),
                address: a,
                vlan: None,
                vrf: None,
                spans: l.spans.clone(),
            });
        }
        if let Some(a) = l.address.filter(|a| l.local != Some(*a)) {
            s.shared_addresses.insert(a);
        }
        if let Some(g) = l.gateway {
            s.next_hops.insert(g);
            if let Some(n) = &global_name {
                s.next_hop_vrfs.entry(g).or_default().insert(n.clone());
            }
            s.address_peers.push(AddressPeer {
                port,
                address: g,
                vrf: None,
                spans: l.spans.clone(),
            });
        }
    }

    // The static gateways and the BGP neighbours of the segments.
    for seg in &e.segments {
        for st in &seg.statics {
            if let Some(g) = st.gateway {
                s.next_hops.insert(g);
                s.next_hop_vrfs
                    .entry(g)
                    .or_default()
                    .insert(seg.name.clone());
            }
        }
        let Some(bgp) = &seg.bgp else {
            continue;
        };
        for n in &bgp.neighbours {
            s.next_hops.insert(n.address);
            s.next_hop_vrfs
                .entry(n.address)
                .or_default()
                .insert(seg.name.clone());
            // The LAN interface of the neighbour: the interface with its
            // local address, else the interface whose network holds its
            // address.
            let ifs: Vec<&Interface> = lan
                .iter()
                .filter(|(_, x)| x.id == seg.id)
                .map(|(i, _)| *i)
                .collect();
            let by_local = ifs
                .iter()
                .copied()
                .find(|i| n.local.is_some() && i.address.map(|(a, _)| a) == n.local);
            let by_network = || {
                ifs.iter().copied().find(|i| {
                    i.address
                        .is_some_and(|(a, len)| Prefix::new(a, len).contains(n.address))
                })
            };
            let Some(i) = by_local.or_else(by_network) else {
                continue;
            };
            let mut spans = vec![n.span.clone()];
            spans.extend(session_spans(ent, e, seg, n.address));
            s.address_peers.push(AddressPeer {
                port: i.name.clone(),
                address: n.address,
                vrf: vrf(seg),
                spans,
            });
        }
    }
    s
}

/// The rows of the observed sessions of an edge that are up with the
/// neighbour `address` of the segment `seg`.
fn session_spans(
    ent: &Enterprise,
    e: &Edge,
    seg: &EdgeSegment,
    address: IpAddr,
) -> Vec<SourceSpan> {
    let want = if seg.global {
        SessionSegment::Global
    } else {
        SessionSegment::Segment(seg.id)
    };
    ent.sessions
        .iter()
        .flatten()
        .filter(|x| {
            x.edge == e.logical_id
                && x.neighbour == address
                && x.segment == want
                && x.state.as_deref() == Some(ESTABLISHED)
        })
        .flat_map(|x| x.spans.iter().cloned())
        .collect()
}
