//! The links between the devices of the estate from their neighbour
//! records, and the place of each endpoint across these links. The join
//! knows no vendor: each device gives a summary of its ports, its
//! neighbours, its MAC table, its ARP rows and its next hops. Both need all
//! devices of the estate, so the estate runs them between a first lowering
//! of each device, which gives its summary, and the final lowering.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{FunctionId, Mac, Prefix, PrefixTable, SourceSpan, TriePrefixTable};
use rsim_functions::{HostMac, LinkEnd};

use crate::nxos::names::Names;

/// A neighbour record of a port, from LLDP, CDP or an uplink record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbour {
    /// The local port, with the name of the device.
    pub port: String,
    /// The name of the neighbour, without the domain and the serial.
    pub name: Option<String>,
    /// The port of the neighbour as it sends it.
    pub remote_port: Option<String>,
    /// The chassis MAC, and the remote port as a MAC if it is one.
    pub chassis: Option<Mac>,
    pub port_mac: Option<Mac>,
    pub span: SourceSpan,
}

/// The layer 3 addresses of a port by VLAN, with their prefix lengths.
pub type VlanAddrs = BTreeMap<Option<u16>, Vec<(IpAddr, u8)>>;

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
    /// The function that a frame enters on each port that can end a link.
    pub entries: BTreeMap<String, FunctionId>,
    /// The MAC of each port, for a neighbour that names a port by its MAC.
    pub port_macs: BTreeMap<String, Mac>,
    /// The source row of a port, for the provenance of its links.
    pub port_spans: BTreeMap<String, SourceSpan>,
    /// The layer 3 addresses of a port by VLAN, `None` for the untagged
    /// interface.
    pub l3: BTreeMap<String, VlanAddrs>,
    /// The tunnel end of the switch, if it forwards.
    pub tunnel: Option<TunnelSummary>,
    /// The BGP peers of the device: one fact for each configured neighbour,
    /// each listen range and each observed peer with no neighbour.
    pub bgp_peers: Vec<BgpPeerFact>,
    /// All local addresses of the device for each VRF, loopbacks included.
    pub local_addresses: BTreeMap<String, BTreeSet<IpAddr>>,
    /// True if no BGP stanza that can hold a neighbour or a listen range is
    /// unhandled or not read, also where the collected route rows make the
    /// routing lines known-irrelevant, so a neighbour or a listen range that
    /// the peer facts do not hold is not in the config.
    pub bgp_read: bool,
    /// The collected routes of each VRF, for the egress interface of the
    /// route lookup on the address of a BGP peer. The estate takes them out
    /// after that lookup, so they are empty in the join.
    pub routes: crate::resolve::Resolver,
}

/// The peer of a BGP neighbour.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BgpPeer {
    Address(IpAddr),
    /// A listen range: the peers whose address is in the prefix.
    Range(Prefix),
    /// A neighbour named by its interface, with no address in the config.
    Interface(String),
}

impl std::fmt::Display for BgpPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BgpPeer::Address(a) => write!(f, "{a}"),
            BgpPeer::Range(p) => write!(f, "{p}"),
            BgpPeer::Interface(i) => write!(f, "{i}"),
        }
    }
}

/// Where a BGP peer fact comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerSource {
    /// A neighbour of the config.
    Configured,
    /// A listen range of the config.
    ListenRange,
    /// An observed peer in exactly one listen range whose inheritance
    /// resolves, with the settings of the range.
    Dynamic(Prefix),
    /// An observed peer with no neighbour and no single listen range.
    Observed,
}

impl PeerSource {
    pub fn name(&self) -> &'static str {
        match self {
            PeerSource::Configured => "configured",
            PeerSource::ListenRange => "listen-range",
            PeerSource::Dynamic(_) => "dynamic",
            PeerSource::Observed => "observed",
        }
    }
}

/// The AS numbers of one side of a BGP session, or the reason why they are
/// not known. A side has 2 numbers with `dual-as`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsnValue {
    Known(Vec<u32>),
    Unknown(String),
}

/// An AS value with the spans of the lines that give it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asn {
    pub value: AsnValue,
    pub spans: Vec<SourceSpan>,
}

/// One BGP peer of a device: the config side after the inheritance, joined
/// with the session rows of the device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BgpPeerFact {
    pub device: String,
    pub vrf: String,
    pub peer: BgpPeer,
    pub source: PeerSource,
    /// The interface or the address of the update-source or local address
    /// line.
    pub update_source: Option<String>,
    /// The local address of the session from the update-source or local
    /// address line, `None` when no such line gives one.
    pub local_address: Option<IpAddr>,
    /// The source address of the session: the local address, else the
    /// address of the egress interface of the route lookup on the peer
    /// address.
    pub source_address: AddressValue,
    /// The spans of the routes of that lookup.
    pub source_spans: Vec<SourceSpan>,
    /// The AS that the device presents to the peer.
    pub local_asn: Asn,
    /// The AS of the peer from the config, or from the session row of an
    /// observed peer.
    pub peer_asn: Asn,
    /// The AS of the peer as the session row states it.
    pub observed_asn: Option<u32>,
    /// `None` when an inheritance gap can hide a `shutdown` line.
    pub shutdown: Option<bool>,
    /// The activated address families after the inheritance and the
    /// defaults of the vendor, for example `ipv4-unicast`.
    pub families: BTreeSet<String>,
    /// The reason why `families` can miss an activated family: an
    /// inheritance gap, or an address family that the reader does not name.
    /// `None` when the set is known in full.
    pub families_open: Option<String>,
    pub policy_in: Option<String>,
    pub policy_out: Option<String>,
    /// The peer groups, templates and session groups of the inheritance.
    pub inherits: Vec<String>,
    /// The reasons of an inheritance that does not resolve.
    pub gaps: Vec<String>,
    /// The session rows of the peer, one for each address family that the
    /// section states.
    pub sessions: Vec<crate::bgp::SessionRow>,
    /// The router ID of the peer as the device states it.
    pub router_id: Option<IpAddr>,
    /// The outcome of the session section of the device and its scope.
    pub section: crate::bgp::SectionOutcome,
    /// The config lines of the neighbour and of the lines that it inherits.
    pub spans: Vec<SourceSpan>,
    /// The far end of a configured neighbour with a peer address, from the
    /// join; `None` for another fact.
    pub far: Option<BgpFar>,
}

/// An address of one side of a BGP session, or the reason why it is not
/// known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressValue {
    Known(IpAddr),
    Unknown(String),
}

/// The far end of a configured BGP neighbour in the twin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BgpFar {
    /// No other device of the twin has the peer address.
    Outside,
    /// The peer address is a local address of the device itself, or of
    /// more than one device or VRF: each device and VRF.
    Ambiguous(Vec<(String, String)>),
    /// The device and the VRF that hold the peer address, with the side of
    /// that device.
    Device {
        device: String,
        vrf: String,
        side: FarSide,
    },
}

/// The side of the far device of a BGP neighbour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FarSide {
    /// The fact of the far device for the source address of the near side:
    /// a neighbour of that address whose own source address is the peer
    /// address of the near side, a dynamic peer of a listen range for that
    /// address, or the listen range that holds it. The index is the place of
    /// the fact in the BGP peers of the far device.
    Paired(usize),
    /// The neighbour of the far device for the source address of the near
    /// side, whose own source address is known and is not the peer address
    /// of the near side.
    SourceMismatch(usize),
    /// A neighbour of the far device that names another local address of
    /// the near device than the source address, while the BGP config of the
    /// far device is read in full and no other neighbour of the near device
    /// can be the far side of that neighbour.
    OtherAddress(usize),
    /// The far device has no neighbour and no listen range for the source
    /// address. `read` is true if the BGP config of the far device is read
    /// in full and no neighbour named by its interface can be the peer.
    Absent { read: bool },
    /// The pairing is not known, with the reason.
    Unresolved(String),
}

/// The start of the reason of a source address that is not known.
pub const SOURCE_NOT_RESOLVED: &str = "source address not resolved";

impl BgpPeerFact {
    /// The reason why the activated address families can be more than
    /// `families`: `families_open`, else the first inheritance gap.
    pub fn open_families(&self) -> Option<&str> {
        self.families_open
            .as_deref()
            .or_else(|| self.gaps.first().map(String::as_str))
    }

    /// True if the scope of the session section covers each activated
    /// address family of the peer in its VRF. A configured peer with no
    /// activated family is not covered. An observed peer is covered.
    pub fn in_scope(&self) -> bool {
        match self.source {
            PeerSource::Observed => true,
            _ => {
                !self.families.is_empty()
                    && self
                        .families
                        .iter()
                        .all(|f| self.section.scope.covers(&self.vrf, f))
            }
        }
    }
}

/// The layer 2 tunnel end of a switch, for example a VXLAN tunnel end.
#[derive(Clone, Debug, Default)]
pub struct TunnelSummary {
    /// The address of the tunnel end.
    pub address: Option<IpAddr>,
    /// The peer tunnel ends that the switch knows.
    pub peers: BTreeSet<IpAddr>,
    /// The segment identifier of each VLAN in the tunnel.
    pub segments: BTreeMap<u16, u32>,
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

/// The far end of a link from a port.
#[derive(Clone, Debug)]
pub struct Peer {
    /// The ingress or the hand-off function of the far end.
    pub target: FunctionId,
    /// The device and the port of the far end.
    pub far: (String, String),
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
    /// The MAC of the far end of the link of each port with one peer, when
    /// the far end is a routed port: a port that is not a switch port and
    /// has layer 3 addresses.
    pub far_macs: BTreeMap<String, Mac>,
}

/// One end of a link: a device and a port.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct End(String, String);

/// The facts that the estate gives the lowering of each device.
#[derive(Default)]
pub struct Joined {
    pub devices: BTreeMap<String, External>,
    pub notes: BTreeMap<String, Vec<String>>,
    /// The BGP peer facts of each device with one, each configured
    /// neighbour with a peer address with its far end.
    pub bgp: BTreeMap<String, Vec<BgpPeerFact>>,
    /// The peer addresses of the configured BGP neighbours whose peer is
    /// outside the twin.
    pub bgp_outside: BTreeSet<IpAddr>,
}

fn target(devices: &BTreeMap<String, Summary>, end: &End) -> Option<FunctionId> {
    devices.get(&end.0)?.entries.get(&end.1).cloned()
}

/// The links of the estate. A link needs one far end for all neighbour
/// records of a port. A record names the far device by its name, else by
/// the MAC of the far port, else by its chassis MAC; the far port is the
/// port of the name or of the MAC. When the far device has a neighbour
/// section, it must report the link too. An end that 2 links claim gets no
/// link.
pub fn join(
    devices: &BTreeMap<String, Summary>,
    next_hops: &BTreeSet<IpAddr>,
    device_macs: &BTreeSet<Mac>,
) -> Joined {
    let switches = devices;
    let mut out = Joined {
        bgp: bgp_pairs(devices),
        ..Joined::default()
    };
    for f in out.bgp.values().flatten() {
        if let (Some(BgpFar::Outside), BgpPeer::Address(a)) = (&f.far, &f.peer) {
            out.bgp_outside.insert(*a);
        }
    }
    let mut hops = next_hops.clone();
    hops.extend(out.bgp_outside.iter().copied());
    let next_hops = &hops;
    // The device of each host name. A host name that more than one device
    // has names no device.
    let mut name_owners: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (d, s) in switches {
        if let Some(n) = s.host_name.as_deref() {
            name_owners.entry(n).or_default().push(d.as_str());
        }
    }
    let mut by_name: BTreeMap<&str, &str> = BTreeMap::new();
    for (n, list) in &name_owners {
        match list.as_slice() {
            [one] => {
                by_name.insert(n, one);
            }
            _ => {
                for d in list {
                    out.notes.entry((*d).to_string()).or_default().push(format!(
                        "the host name {n} is on more than one device, so it names no neighbour"
                    ));
                }
            }
        }
    }
    // The device and the port of a port MAC. A MAC that more than one port
    // has, for example an anycast gateway MAC, proves no port.
    let mut owners: BTreeMap<Mac, Vec<(String, String)>> = BTreeMap::new();
    for (d, s) in switches {
        for (p, m) in &s.port_macs {
            owners.entry(*m).or_default().push((d.clone(), p.clone()));
        }
    }
    for (m, list) in &owners {
        if list.len() > 1 {
            for (d, p) in list {
                out.notes.entry(d.clone()).or_default().push(format!(
                    "{p}: its MAC {m:?} is on more than one port, so it proves no link"
                ));
            }
        }
    }
    let port_of_mac = |m: Mac| -> Option<(String, String)> {
        match owners.get(&m).map(Vec::as_slice) {
            Some([one]) => Some(one.clone()),
            _ => None,
        }
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
                            .map(|rp| End((*other).to_string(), o.port(rp)))
                    }
                    None => {
                        // The port of the port MAC, else the device of the
                        // chassis MAC and its port of the port name. A
                        // chassis MAC names the device, not the port.
                        let by_port = n.port_mac.and_then(port_of_mac).filter(|(o, _)| o != d);
                        let mut by_chassis = || {
                            let (o, _) = n.chassis.and_then(port_of_mac)?;
                            if o == *d {
                                return None;
                            }
                            let os = &switches[&o];
                            match n.remote_port.as_deref() {
                                Some(rp) if os.entries.contains_key(&os.port(rp)) => {
                                    Some(Some(End(o.clone(), os.port(rp))))
                                }
                                _ => {
                                    router_notes.push(format!(
                                        "{port}: the neighbour {o} names no port of its own, so the port has no link"
                                    ));
                                    Some(None)
                                }
                            }
                        };
                        match by_port {
                            Some((o, p)) => Some(End(o, p)),
                            None => by_chassis().flatten(),
                        }
                    }
                };
                far.insert(end);
            }
            out.notes.entry(d.clone()).or_default().extend(router_notes);
            let spans = list.iter().map(|n| n.span.clone()).collect();
            let here = End(d.clone(), port.clone());
            // The member ports of one vPC on the 2 switches of a vPC pair.
            let vpc_ends: Option<Vec<End>> = (far.len() == 2)
                .then(|| far.iter().cloned().collect::<Option<Vec<End>>>())
                .flatten()
                .filter(|ends| {
                    let ids: BTreeSet<(u32, u32)> = ends
                        .iter()
                        .filter_map(|End(o, p)| {
                            let v = switches[o].vpc.as_ref().filter(|v| v.ok)?;
                            Some((v.domain, *v.members.get(p)?))
                        })
                        .collect();
                    let devs: BTreeSet<&str> = ends.iter().map(|End(o, _)| o.as_str()).collect();
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
        let confirmed = if !switches[&far.0].neighbour_section {
            true
        } else {
            match named.get(far) {
                Some((Some(back), _)) => back == here,
                _ => false,
            }
        };
        if !confirmed {
            let End(d, p) = here;
            out.notes.entry(d.clone()).or_default().push(format!(
                "{p}: the neighbour does not report the link back, so the port has no link"
            ));
            continue;
        }
        // Each link once: from the smaller end of 2 switches.
        if named.get(far).and_then(|x| x.0.as_ref()) == Some(here) && far < here {
            continue;
        }
        let mut spans = spans.clone();
        if let Some((_, back)) = named.get(far) {
            spans.extend(back.iter().cloned());
        }
        for e in [here, far] {
            if let Some(sp) = switches[&e.0].port_spans.get(&e.1) {
                spans.push(sp.clone());
            }
        }
        links.push((here.clone(), far.clone(), spans));
    }

    // The vPC pairs: 2 switches of one lowered domain whose peer-link port
    // channels a link joins.
    let peer_link = |e: &End| -> Option<(String, u32)> {
        let End(d, p) = e;
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
        let devs: Vec<&str> = ends.iter().map(|End(d, _)| d.as_str()).collect();
        let paired = matches!(devs.as_slice(), [a, b] if pairs.contains(&((*a).to_string(), (*b).to_string())));
        let confirmed = paired
            && ends.iter().all(|f| {
                !switches[&f.0].neighbour_section
                    || matches!(named.get(f), Some((Some(back), _)) if back == here)
            });
        if !confirmed {
            let End(d, p) = here;
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
        let End(dev, what) = e.clone();
        out.notes
            .entry(dev)
            .or_default()
            .push(format!("{what}: 2 links claim the port, so it has no link"));
    }

    let mut l2_far: BTreeMap<(String, String), (String, String)> = BTreeMap::new();
    let facts = |e: &End| -> Option<LinkEnd> { switches.get(&e.0)?.facts.get(&e.1).cloned() };
    for (a, b, spans) in links {
        if doubled.contains(&a) || doubled.contains(&b) {
            continue;
        }
        let (Some(ta), Some(tb)) = (target(switches, &a), target(switches, &b)) else {
            let End(d, p) = &a;
            out.notes.entry(d.clone()).or_default().push(format!(
                "{p}: an end of the link is not a lowered port, so the port has no link"
            ));
            continue;
        };
        // The far end of each switch port with a link, for the placement of
        // the endpoints.
        if switches[&a.0].ports.contains_key(&a.1) && switches[&b.0].ports.contains_key(&b.1) {
            l2_far.insert((a.0.clone(), a.1.clone()), (b.0.clone(), b.1.clone()));
            l2_far.insert((b.0.clone(), b.1.clone()), (a.0.clone(), a.1.clone()));
        }
        for (End(d, p), to, t) in [(&a, &b, tb), (&b, &a, ta)] {
            // The MAC of a routed far end, if no other port of the estate
            // has it.
            let far = &switches[&to.0];
            if !far.ports.contains_key(&to.1)
                && far.l3.contains_key(&to.1)
                && let Some(m) = far.port_macs.get(&to.1)
                && port_of_mac(*m).as_ref() == Some(&(to.0.clone(), to.1.clone()))
            {
                out.devices
                    .entry(d.clone())
                    .or_default()
                    .far_macs
                    .insert(p.clone(), *m);
            }
            out.devices
                .entry(d.clone())
                .or_default()
                .peers
                .entry(p.clone())
                .or_default()
                .push(Peer {
                    target: t,
                    far: (to.0.clone(), to.1.clone()),
                    provenance: spans.clone(),
                    remote: facts(to),
                });
        }
    }
    for (a, ends, spans) in vpc_links {
        if doubled.contains(&a) || ends.iter().any(|e| doubled.contains(e)) {
            continue;
        }
        let ta = target(switches, &a);
        let tb: Option<Vec<FunctionId>> = ends.iter().map(|e| target(switches, e)).collect();
        let (Some(ta), Some(tb), End(d, p)) = (ta, tb, &a) else {
            continue;
        };
        for (e, t) in ends.iter().zip(tb) {
            out.devices
                .entry(d.clone())
                .or_default()
                .peers
                .entry(p.clone())
                .or_default()
                .push(Peer {
                    target: t,
                    far: (e.0.clone(), e.1.clone()),
                    provenance: spans.clone(),
                    remote: facts(e),
                });
            {
                let End(d2, p2) = e;
                if switches[&a.0].ports.contains_key(&a.1) && switches[d2].ports.contains_key(p2) {
                    l2_far.insert((d2.clone(), p2.clone()), (a.0.clone(), a.1.clone()));
                }
                out.devices
                    .entry(d2.clone())
                    .or_default()
                    .peers
                    .entry(p2.clone())
                    .or_default()
                    .push(Peer {
                        target: ta.clone(),
                        far: (a.0.clone(), a.1.clone()),
                        provenance: spans.clone(),
                        remote: facts(&a),
                    });
            }
        }
    }

    // The vPC peer of each switch of a pair.
    for (a, b) in &pairs {
        let v = switches[b].vpc.as_ref().expect("a domain");
        out.devices.entry(a.clone()).or_default().vpc_peer = Some(VpcPeer {
            down: v.down.clone(),
            up: v.up.clone(),
            svi_macs: v.svi_macs.clone(),
        });
    }
    place(switches, &mut out, &l2_far, next_hops, device_macs);
    out
}

/// The BGP peer facts of each device with one, each configured neighbour
/// with a peer address with its far end. Two neighbours pair on the exact
/// transport addresses: the far device holds the peer address of the near
/// neighbour in a VRF, and in that VRF it has a neighbour whose peer
/// address is the source address of the near neighbour and whose source
/// address is the peer address of the near neighbour, or one listen range
/// that holds the source address. The VRF names of the 2 devices are not compared,
/// and the AS numbers are not part of the pairing.
pub fn bgp_pairs(devices: &BTreeMap<String, Summary>) -> BTreeMap<String, Vec<BgpPeerFact>> {
    let mut owners: BTreeMap<IpAddr, Vec<(&str, &str)>> = BTreeMap::new();
    for (d, s) in devices {
        for (vrf, addrs) in &s.local_addresses {
            for a in addrs {
                owners.entry(*a).or_default().push((d, vrf));
            }
        }
    }
    let mut out = BTreeMap::new();
    for (d, s) in devices {
        if s.bgp_peers.is_empty() {
            continue;
        }
        let facts = s
            .bgp_peers
            .iter()
            .map(|f| {
                let mut f = f.clone();
                f.far = match (&f.source, &f.peer) {
                    (PeerSource::Configured, BgpPeer::Address(a)) => {
                        Some(far_end(devices, &owners, d, &f, *a))
                    }
                    _ => None,
                };
                f
            })
            .collect();
        out.insert(d.clone(), facts);
    }
    out
}

/// The far end of the configured neighbour `f` of the device `near` with
/// the peer address `peer`.
fn far_end(
    devices: &BTreeMap<String, Summary>,
    owners: &BTreeMap<IpAddr, Vec<(&str, &str)>>,
    near: &str,
    f: &BgpPeerFact,
    peer: IpAddr,
) -> BgpFar {
    let at: &[(&str, &str)] = owners.get(&peer).map_or(&[], Vec::as_slice);
    let (b, vrf) = match at {
        [] => return BgpFar::Outside,
        [(b, v)] if *b != near => (*b, *v),
        more => {
            return BgpFar::Ambiguous(
                more.iter()
                    .map(|(d, v)| ((*d).to_string(), (*v).to_string()))
                    .collect(),
            );
        }
    };
    let side = |side| BgpFar::Device {
        device: b.to_string(),
        vrf: vrf.to_string(),
        side,
    };
    let src = match &f.source_address {
        AddressValue::Known(a) => *a,
        AddressValue::Unknown(r) => return side(FarSide::Unresolved(r.clone())),
    };
    let far = &devices[b];
    let in_vrf = || {
        far.bgp_peers
            .iter()
            .enumerate()
            .filter(|(_, g)| g.vrf == vrf)
    };
    let at_src = BgpPeer::Address(src);
    for kind in ["configured", "dynamic"] {
        if let Some((i, g)) = in_vrf().find(|(_, g)| g.source.name() == kind && g.peer == at_src) {
            return side(match (&g.source, &g.source_address) {
                (PeerSource::Configured, AddressValue::Known(x)) if *x != peer => {
                    FarSide::SourceMismatch(i)
                }
                (PeerSource::Configured, AddressValue::Unknown(r)) => FarSide::Unresolved(format!(
                    "the source address of the neighbour {src} of {b} is not known: {r}"
                )),
                _ => FarSide::Paired(i),
            });
        }
    }
    let ranges: Vec<usize> = in_vrf()
        .filter(|(_, g)| {
            g.source == PeerSource::ListenRange
                && matches!(&g.peer, BgpPeer::Range(p) if p.contains(src))
        })
        .map(|(i, _)| i)
        .collect();
    match ranges.as_slice() {
        [] => {}
        [i] => return side(FarSide::Paired(*i)),
        _ => {
            return side(FarSide::Unresolved(format!(
                "the source address {src} is in more than one listen range of {b}"
            )));
        }
    }
    if in_vrf().any(|(_, g)| g.source == PeerSource::Observed && g.peer == at_src) {
        return side(FarSide::Unresolved(format!(
            "{b} has a session with {src} and no neighbour or listen range for it"
        )));
    }
    let read = far.bgp_read && !in_vrf().any(|(_, g)| matches!(g.peer, BgpPeer::Interface(_)));
    if !read {
        return side(FarSide::Absent { read });
    }
    // The other configured neighbours of the near device in the VRF whose
    // peer is an address of the far device in its VRF.
    let near_sum = &devices[near];
    let mine = near_sum.local_addresses.get(&f.vrf);
    let theirs = far.local_addresses.get(vrf);
    let others: Vec<&BgpPeerFact> = near_sum
        .bgp_peers
        .iter()
        .filter(|h| {
            h.source == PeerSource::Configured
                && h.vrf == f.vrf
                && h.peer != f.peer
                && matches!(&h.peer, BgpPeer::Address(p) if theirs.is_some_and(|t| t.contains(p)))
        })
        .collect();
    let mut unsure = None;
    for (i, g) in in_vrf() {
        let BgpPeer::Address(x) = g.peer else {
            continue;
        };
        if g.source != PeerSource::Configured || x == src || !mine.is_some_and(|m| m.contains(&x)) {
            continue;
        }
        // A neighbour of the far device for the source address of another
        // session of the near device belongs to that session.
        if others
            .iter()
            .any(|h| h.source_address == AddressValue::Known(x))
        {
            continue;
        }
        if let Some(h) = others
            .iter()
            .find(|h| matches!(h.source_address, AddressValue::Unknown(_)))
        {
            unsure.get_or_insert_with(|| {
                format!(
                    "the neighbour {x} of {b} can belong to the neighbour {} of {near}, whose source address is not known",
                    h.peer
                )
            });
            continue;
        }
        return side(FarSide::OtherAddress(i));
    }
    match unsure {
        Some(r) => side(FarSide::Unresolved(r)),
        None => side(FarSide::Absent { read: true }),
    }
}

/// The places of the endpoints. From an ARP row of an SVI, the MAC table
/// rows lead across the links of switch ports to an edge access port. One
/// endpoint is one MAC on one port, with the addresses of all ARP rows that
/// lead there. A MAC with an address that is a next hop, or a MAC of a
/// collected device, is not an endpoint.
fn place(
    switches: &BTreeMap<String, Summary>,
    out: &mut Joined,
    far: &BTreeMap<(String, String), (String, String)>,
    next_hops: &BTreeSet<IpAddr>,
    device_macs: &BTreeSet<Mac>,
) {
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
    // The VLANs of the switches that a tunnel joins into one segment: the
    // same segment identifier on 2 tunnel ends that know each other.
    let mut tunnelled: BTreeMap<(String, u16), BTreeSet<(String, u16)>> = BTreeMap::new();
    for (s, a) in switches {
        let Some(ta) = &a.tunnel else { continue };
        for (s2, b) in switches {
            let Some(tb) = &b.tunnel else { continue };
            if s == s2 {
                continue;
            }
            let know = tb.address.is_some_and(|x| ta.peers.contains(&x))
                || ta.address.is_some_and(|x| tb.peers.contains(&x));
            if !know {
                continue;
            }
            for (v, id) in &ta.segments {
                for (v2, id2) in &tb.segments {
                    if id == id2 {
                        tunnelled
                            .entry((s.clone(), *v))
                            .or_default()
                            .insert((s2.clone(), *v2));
                    }
                }
            }
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
        let mut table = hosts.get(&(s.clone(), v)).cloned().unwrap_or_default();
        let joined = tunnelled.get(&(s, v)).cloned().unwrap_or_default();
        for (s2, v2) in a.svis.iter().skip(1).chain(joined.iter()) {
            if let Some(t) = hosts.get(&(s2.clone(), *v2)) {
                for (p, h) in t.entries() {
                    if table.get(&p).is_none() {
                        table.insert(p, h.clone());
                    }
                }
            }
        }
        out.devices.entry(dev).or_default().endpoints.push(Placed {
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
