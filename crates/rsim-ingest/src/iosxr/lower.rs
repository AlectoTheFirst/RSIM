//! Lowering of an IOS-XR running config and its collected sections into the
//! layer 3 function instances of a router: the interfaces with their VRFs,
//! the input and output ACLs, the QoS policies, the route table of each VRF,
//! the next-hop resolution through ARP, the HSRP groups, and the hand-off
//! and the egress of each port with a link. Gives the summary of the router
//! for the link join too.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{
    FieldValue, InterfaceId, Mac, MacCond, Match, NeighbourTarget, ObjectId, Prefix, PrefixTable,
    Rewrite, RulePredicate, SourceSpan, TriePrefixTable, VrfId,
};
use rsim_engine::EdgeInterface;
use rsim_functions::{
    AclMatch, DeviceDelivery, Egress, EgressMode, Fib, Ingress, Layer3HandOff, Link, LinkEnd,
    LinkFacts, LocalInput, Neighbour, NextHopResolution, Route, RouteKind, RouteLookup,
    RouteNextHop, Rule as FRule, RuleAction, Tag, VendorProfile, VrfSelection,
};

use super::config::{Config, HsrpGroup, Interface};
use super::profile::{
    ALL_IPV4, CONNECTED_CODE, DEFAULT_VRF, HSRP_ACTIVE, HSRP_DEFAULT_VERSION, HSRP_NOT_ACTIVE,
    LOCAL_CODE, UP_WITHOUT_SHUTDOWN, hsrp_vmac,
};
use super::state::{self, Rib, RoutePath, Section, UnreadRoute};
use crate::links::{External, Summary, VlanAddrs};
use crate::nxos;
use crate::nxos::config::{Ace, AclAction, AddrSpec, PortSpec};
use crate::nxos::lower::{L, iface_addr};
use crate::vyos::Lowered;

/// The protocol word of the shared ACL functions for all IPv4 protocols.
const SHARED_ALL_IP: &str = "ip";

/// A layer 3 interface that is lowered, in the form of the shared ACL
/// functions.
struct Port {
    i: nxos::config::Interface,
    /// The span of its record in `show interfaces`.
    state: Option<SourceSpan>,
    /// The VLAN of `encapsulation dot1q` of a sub-interface.
    dot1q: Option<u16>,
    /// The IPv6 addresses of the config.
    ipv6: Vec<String>,
    /// The MAC of `show interfaces`.
    mac: Option<Mac>,
}

impl Port {
    fn vrf(&self) -> &str {
        self.i.vrf.as_deref().unwrap_or(DEFAULT_VRF)
    }
}

/// The port of an interface: the name without the sub-interface number.
fn parent(name: &str) -> &str {
    name.split_once('.').map_or(name, |x| x.0)
}

/// The interface types that cannot end a link, in lower case.
const NO_LINK: &[&str] = &["loopback", "null", "tunnel", "bvi"];

/// The state of an HSRP group from the config and `show hsrp`.
enum GroupState {
    Active,
    NotActive,
    Unknown(String),
}

/// An IPv4 HSRP group of a lowered interface.
struct Group<'a> {
    g: &'a HsrpGroup,
    /// The config name of the interface.
    interface: String,
    state: GroupState,
    vmac: Option<Mac>,
    spans: Vec<SourceSpan>,
}

/// A virtual address in the route table: a local route of an active group,
/// or a route with no next hop of a group whose state is not known.
struct Vip {
    vrf: String,
    ip: IpAddr,
    local: bool,
    spans: Vec<SourceSpan>,
}

fn port(i: &Interface) -> nxos::config::Interface {
    nxos::config::Interface {
        name: i.name.clone(),
        admin_up: Some(!i.shutdown),
        vrf: i.vrf.as_ref().map(|v| v.0.clone()),
        addresses: i
            .addresses
            .iter()
            .map(|a| nxos::config::Address {
                prefix: a.prefix.clone(),
                secondary: a.secondary,
                lines: a.lines,
            })
            .collect(),
        acl_in: i.acl_in.clone(),
        acl_out: i.acl_out.clone(),
        qos_in: i.qos_in.clone(),
        qos_out: i.qos_out.clone(),
        unhandled: i.unhandled.clone(),
        lines: i.lines,
        ..nxos::config::Interface::default()
    }
}

/// The IPv4 ACLs in the form of the shared ACL functions. An entry that the
/// config reader cannot read and that starts with a sequence number and an
/// action stays at its place as an entry whose match set is not known, so
/// the match bounds decide the packets that reach it.
fn acls(cfg: &Config) -> BTreeMap<String, nxos::config::Acl> {
    let seq = |s: &str| s.parse::<u64>().ok();
    cfg.acls
        .iter()
        .map(|(name, acl)| {
            let mut acl = acl.clone();
            for e in &mut acl.entries {
                if e.protocol == ALL_IPV4 {
                    e.protocol = SHARED_ALL_IP.to_string();
                }
            }
            let mut rest = Vec::new();
            for text in std::mem::take(&mut acl.unreadable) {
                let w: Vec<&str> = text.split_whitespace().collect();
                let (n, action) = match w.as_slice() {
                    [s, a @ ("permit" | "deny"), ..] if seq(s).is_some() => (
                        seq(s).unwrap_or_default(),
                        if *a == "permit" {
                            AclAction::Permit
                        } else {
                            AclAction::Deny
                        },
                    ),
                    _ => {
                        rest.push(text);
                        continue;
                    }
                };
                let at = acl
                    .entries
                    .iter()
                    .position(|e| seq(&e.seq).is_some_and(|s| s > n))
                    .unwrap_or(acl.entries.len());
                acl.entries.insert(
                    at,
                    Ace {
                        seq: n.to_string(),
                        action,
                        protocol: SHARED_ALL_IP.to_string(),
                        source: AddrSpec::Any,
                        source_port: PortSpec::Any,
                        destination: AddrSpec::Any,
                        destination_port: PortSpec::Any,
                        icmp: None,
                        established: false,
                        unhandled: vec![format!("the entry is not read: {text}")],
                        lines: acl.lines,
                    },
                );
            }
            acl.unreadable = rest;
            (name.clone(), acl)
        })
        .collect()
}

fn error<T>(s: &Section<T>) -> Option<&str> {
    match s {
        Some(Err(e)) => Some(e),
        _ => None,
    }
}

/// The MACs of the interfaces of a router in `show interfaces`.
pub fn device_macs(cfg: &Config, sections: &BTreeMap<String, (Vec<u8>, String)>) -> BTreeSet<Mac> {
    let only: BTreeMap<String, (Vec<u8>, String)> = sections
        .iter()
        .filter(|(k, _)| k.as_str() == "interfaces")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    state::read(&only, &super::names(cfg))
        .interfaces
        .and_then(Result::ok)
        .map(|m| m.values().filter_map(|s| s.mac).collect())
        .unwrap_or_default()
}

/// Lowers one IOS-XR router. `sections` holds the text sections of
/// [`super::SECTIONS`], each with its file name. `ext` gives the links from
/// the estate. Gives the summary of the router for the estate too.
pub fn lower(
    device: &str,
    file: &str,
    profile: &VendorProfile,
    cfg: &Config,
    sections: &BTreeMap<String, (Vec<u8>, String)>,
    ext: &External,
) -> (Lowered, Summary) {
    let names = super::names(cfg);
    let st = state::read(sections, &names);
    let shared = nxos::Config {
        acls: acls(cfg),
        ..nxos::Config::default()
    };
    let mut l = L::new(device, file, profile, &shared);
    for (name, e) in [
        ("interfaces", error(&st.interfaces)),
        ("vrfs", error(&st.vrfs)),
        ("rib", error(&st.rib)),
        ("arp", error(&st.arp)),
        ("lldp", error(&st.lldp)),
        ("cdp", error(&st.cdp)),
        ("hsrp", error(&st.hsrp)),
    ] {
        if let Some(e) = e {
            l.note(format!("the section {name} is not read: {e}"));
        }
    }
    let states = st.interfaces.as_ref().and_then(|x| x.as_ref().ok());
    let mut active: Vec<Port> = Vec::new();
    for i in &cfg.interfaces {
        let s = states.and_then(|m| m.get(&i.name));
        let admin = if i.shutdown {
            Some(false)
        } else if UP_WITHOUT_SHUTDOWN {
            Some(true)
        } else {
            None
        };
        if admin == Some(false) {
            continue;
        }
        if s.is_some_and(|s| s.admin_down) {
            l.note(format!(
                "{}: show interfaces gives administratively down, and the config has no shutdown line",
                i.name
            ));
        }
        if s.and_then(|s| s.oper_up) == Some(false) || i.addresses.is_empty() {
            continue;
        }
        let mut p = port(i);
        if admin.is_none() {
            p.unhandled.push("the admin state is not known".into());
        }
        active.push(Port {
            i: p,
            state: s.map(|s| s.span.clone()),
            dot1q: i.dot1q.map(|d| d.0),
            ipv6: i.ipv6.iter().map(|a| a.0.clone()).collect(),
            mac: s.and_then(|s| s.mac),
        });
    }
    cross_check(&mut l, cfg, &st);
    let groups = hsrp(&mut l, cfg, &st, &active, &names);
    let sum = summary(&l, cfg, &st, &active, &names);
    if active.is_empty() {
        return (l.out, sum);
    }

    // Ingress, the input QoS and the input ACLs.
    for p in &active {
        let i = &p.i;
        let filtered = i.acl_in.is_some() || !i.unhandled.is_empty();
        let after_qos = if filtered {
            format!("acl-in/{}", i.name)
        } else {
            "vrf".to_string()
        };
        let mut spans = vec![l.span(i.lines)];
        spans.extend(p.state.clone());
        let meta = l.meta(&format!("in/{}", i.name), spans);
        l.add(Ingress {
            meta,
            interface: InterfaceId::new(&i.name),
            next: l.id(&match &i.qos_in {
                Some(_) => format!("qos-in/{}", i.name),
                None => after_qos.clone(),
            }),
        });
        if let Some((policy, lines)) = &i.qos_in {
            let f = l.qos(&format!("qos-in/{}", i.name), policy, *lines, &after_qos);
            l.add(f);
        }
        if filtered {
            let f = l.interface_acl(i, i.acl_in.as_ref(), "in", "vrf");
            l.add(f);
        }
    }
    let meta = l.meta("vrf", Vec::new());
    l.add(VrfSelection {
        meta,
        by_interface: active
            .iter()
            .map(|p| (InterfaceId::new(&p.i.name), VrfId::new(p.vrf())))
            .collect(),
        default_vrf: profile.default_vrf.clone(),
        next: l.id("route"),
    });

    // The route lookup in the table of each VRF.
    let rib = st.rib.as_ref().and_then(|x| x.as_ref().ok());
    if st.rib.is_none() {
        l.note("no route table section, so each route lookup is unknown".into());
    }
    let mut vrfs: BTreeSet<String> = cfg.vrfs.keys().cloned().collect();
    vrfs.insert(DEFAULT_VRF.to_string());
    vrfs.extend(active.iter().map(|p| p.vrf().to_string()));
    if let Some(r) = rib {
        vrfs.extend(r.paths.iter().map(|p| p.vrf.clone()));
        vrfs.extend(r.unread.iter().filter_map(|u| u.vrf.clone()));
    }
    let vips: Vec<Vip> = groups
        .iter()
        .flat_map(|g| {
            let local = match g.state {
                GroupState::Active => true,
                GroupState::Unknown(_) => false,
                GroupState::NotActive => return Vec::new(),
            };
            let vrf = active
                .iter()
                .find(|p| p.i.name == g.interface)
                .map_or(DEFAULT_VRF, Port::vrf);
            g.g.addresses
                .iter()
                .map(|(a, _)| Vip {
                    vrf: vrf.to_string(),
                    ip: IpAddr::V4(*a),
                    local,
                    spans: g.spans.clone(),
                })
                .collect()
        })
        .collect();
    let mut tables = BTreeMap::new();
    for v in &vrfs {
        let t = fib(&mut l, v, &active, rib, &vips);
        tables.insert(VrfId::new(v), t);
    }
    l.note("IPv6 is not lowered: each IPv6 packet is unknown at the route lookup".into());
    // The next-hop resolution and the egress exist when a route has a next
    // hop.
    let forwards = tables
        .values()
        .any(|t: &Fib| t.groups().iter().any(|g| !g.next_hops.is_empty()));
    let meta = l.meta("route", Vec::new());
    l.add(RouteLookup {
        meta,
        tables,
        fallback: None,
        local: Some(l.id("local")),
    });
    let meta = l.meta("local", Vec::new());
    l.add(LocalInput {
        meta,
        zone: None,
        next: l.id("deliver"),
    });
    let meta = l.meta("deliver", Vec::new());
    l.add(DeviceDelivery { meta });

    if forwards {
        next_hops(&mut l, &active, &st, ext);
    }
    handoffs(&mut l, &active, &groups, &sum, ext);
    edges(&mut l, device, &active);
    (l.out, sum)
}

/// The summary of the router for the link join. A port that can end a
/// link is a physical port or a bundle that is not a bundle member and not
/// shut, with a MAC in `show interfaces`, and with a lowered interface: the
/// port or a sub-interface. A frame enters it at its hand-off. Its layer 3
/// addresses are the addresses of the port and of its sub-interfaces by
/// their dot1q VLAN. The ARP rows of the sub-interfaces with a VLAN are the
/// ARP rows of the summary.
fn summary(
    l: &L,
    cfg: &Config,
    st: &state::State,
    active: &[Port],
    names: &nxos::names::Names,
) -> Summary {
    let mut sum = Summary {
        host_name: cfg
            .hostname
            .as_deref()
            .and_then(nxos::state::neighbour_name),
        names: names.clone(),
        ..Summary::default()
    };
    let states = st.interfaces.as_ref().and_then(|x| x.as_ref().ok());
    for i in &cfg.interfaces {
        if let Some((n, _)) = i.bundle {
            sum.channel
                .insert(i.name.clone(), format!("Bundle-Ether{n}"));
        }
    }
    for i in &cfg.interfaces {
        let lower_name = i.name.to_ascii_lowercase();
        let s = states.and_then(|m| m.get(&i.name));
        if i.name.contains('.')
            || i.bundle.is_some()
            || i.shutdown
            || NO_LINK.iter().any(|t| lower_name.starts_with(t))
            || s.and_then(|s| s.oper_up) == Some(false)
            || !active.iter().any(|p| parent(&p.i.name) == i.name)
        {
            continue;
        }
        let Some((s, m)) = s.and_then(|s| Some((s, s.mac?))) else {
            continue;
        };
        sum.entries
            .insert(i.name.clone(), l.id(&format!("handoff/{}", i.name)));
        sum.port_macs.insert(i.name.clone(), m);
        sum.port_spans.insert(i.name.clone(), s.span.clone());
        if s.speed_mbps.is_some() || s.full_duplex.is_some() {
            sum.facts.insert(
                i.name.clone(),
                LinkEnd {
                    speed_mbps: s.speed_mbps,
                    full_duplex: s.full_duplex,
                    media: None,
                    spans: vec![s.span.clone()],
                },
            );
        }
        let mut vlans = VlanAddrs::new();
        for p in active.iter().filter(|p| parent(&p.i.name) == i.name) {
            let vlan = if p.i.name == i.name {
                None
            } else if let Some(v) = p.dot1q {
                Some(v)
            } else {
                continue;
            };
            let list = vlans.entry(vlan).or_default();
            list.extend(p.i.addresses.iter().filter_map(|a| iface_addr(&a.prefix)));
            list.extend(p.ipv6.iter().filter_map(|a| iface_addr(a)));
        }
        sum.l3.insert(i.name.clone(), vlans);
    }
    for n in [&st.lldp, &st.cdp] {
        if n.is_some() {
            sum.neighbour_section = true;
        }
        if let Some(Ok(rows)) = n {
            sum.neighbours.extend(rows.iter().cloned());
        }
    }
    if let Some(Ok(rib)) = &st.rib {
        sum.next_hops = rib.paths.iter().filter_map(|p| p.gateway).collect();
    }
    let vlan_of: BTreeMap<&str, u16> = active
        .iter()
        .filter_map(|p| Some((p.i.name.as_str(), p.dot1q?)))
        .collect();
    for a in st.arp.iter().flatten().flatten() {
        if let Some(v) = vlan_of.get(a.interface.as_str()) {
            sum.arp.push((*v, a.ip, a.mac, a.span.clone()));
        }
    }
    sum
}

/// The state of an HSRP group from `show hsrp`: the state word of the IPv4
/// row of the interface and the group, with the group address of the
/// config. `spans` takes the span of the row.
fn group_state(
    g: &HsrpGroup,
    iface: &str,
    vmac: Option<Mac>,
    st: &state::State,
    spans: &mut Vec<SourceSpan>,
) -> GroupState {
    if !g.unhandled.is_empty() {
        return GroupState::Unknown(format!("the lines {} are not read", g.unhandled.join(", ")));
    }
    let Some(primary) = g.addresses.first() else {
        return GroupState::Unknown("the config gives no virtual address".into());
    };
    let rows = match &st.hsrp {
        None => return GroupState::Unknown("no show hsrp section".into()),
        Some(Err(e)) => return GroupState::Unknown(format!("show hsrp is not read: {e}")),
        Some(Ok(rows)) => rows,
    };
    let mine: Vec<&state::HsrpRow> = rows
        .iter()
        .filter(|r| r.interface == iface && r.group == g.group)
        .filter(|r| !r.address.is_some_and(|a| a.is_ipv6()))
        .collect();
    let [r] = mine.as_slice() else {
        return GroupState::Unknown(format!(
            "show hsrp has {} IPv4 rows of the group",
            mine.len()
        ));
    };
    spans.push(r.span.clone());
    if let Some(a) = r.address
        && a != IpAddr::V4(primary.0)
    {
        return GroupState::Unknown(format!(
            "show hsrp gives the address {a}, and the config gives {}",
            primary.0
        ));
    }
    let word = r.state.to_ascii_lowercase();
    if word == HSRP_ACTIVE {
        if vmac.is_none() {
            return GroupState::Unknown("the virtual MAC is not known".into());
        }
        GroupState::Active
    } else if HSRP_NOT_ACTIVE.contains(&word.as_str()) {
        GroupState::NotActive
    } else {
        GroupState::Unknown(format!("the state {:?} is not known", r.state))
    }
}

/// The IPv4 HSRP groups of the lowered interfaces with their state. A
/// group whose state cannot be read, or with a line that is not read, has a
/// state that is not known.
fn hsrp<'a>(
    l: &mut L,
    cfg: &'a Config,
    st: &state::State,
    active: &[Port],
    names: &nxos::names::Names,
) -> Vec<Group<'a>> {
    let mut out = Vec::new();
    for g in &cfg.hsrp {
        let iface = names.resolve(&g.interface);
        if !active.iter().any(|p| p.i.name == iface) {
            if !cfg.interfaces.iter().any(|i| i.name == iface) {
                l.note(format!(
                    "HSRP group {} of {}: the config has no such interface",
                    g.group, g.interface
                ));
            }
            continue;
        }
        let mut spans = vec![l.span(g.lines)];
        spans.extend(g.addresses.iter().map(|(_, x)| l.span(*x)));
        let version = g.version.map_or(HSRP_DEFAULT_VERSION, |v| v.0);
        let vmac = match g.mac {
            Some((m, x)) => {
                spans.push(l.span(x));
                Some(m)
            }
            None => hsrp_vmac(version, g.group),
        };
        let state = group_state(g, &iface, vmac, st, &mut spans);
        if let GroupState::Unknown(why) = &state {
            l.note(format!(
                "{iface}: HSRP group {}: {why}, so the packets to its virtual address and MAC are unknown",
                g.group
            ));
        }
        out.push(Group {
            g,
            interface: iface,
            state,
            vmac,
            spans,
        });
    }
    out
}

/// The hand-off of each port with a link: the MACs of the port, of its
/// sub-interfaces and of its active HSRP groups go to the ingress of the
/// port or of the sub-interface of the dot1q VLAN. A frame to the virtual
/// MAC of a group whose state is not known gives `Unknown`; if that MAC is
/// not known, each frame of the port gives `Unknown`.
fn handoffs(l: &mut L, active: &[Port], groups: &[Group], sum: &Summary, ext: &External) {
    for (port, peers) in &ext.peers {
        if !sum.entries.contains_key(port) || peers.is_empty() {
            continue;
        }
        let f = format!("handoff/{port}");
        let mine: Vec<&Port> = active
            .iter()
            .filter(|p| parent(&p.i.name) == port)
            .collect();
        let mut spans: Vec<SourceSpan> = peers.iter().flat_map(|p| p.provenance.clone()).collect();
        spans.extend(mine.iter().map(|p| l.span(p.i.lines)));
        let on_port: Vec<&Group> = groups
            .iter()
            .filter(|g| mine.iter().any(|p| p.i.name == g.interface))
            .collect();
        let mut macs: BTreeSet<Mac> = sum.port_macs.get(port).copied().into_iter().collect();
        macs.extend(mine.iter().filter_map(|p| p.mac));
        let mut unknown: BTreeSet<Mac> = BTreeSet::new();
        let mut blind: Vec<String> = Vec::new();
        for g in &on_port {
            match (&g.state, g.vmac) {
                (GroupState::Active, Some(m)) => {
                    macs.insert(m);
                    spans.extend(g.spans.iter().cloned());
                }
                (GroupState::Unknown(_), Some(m)) => {
                    unknown.insert(m);
                }
                (GroupState::Unknown(why), None) => {
                    blind.push(format!(
                        "HSRP group {} of {}: {why}",
                        g.g.group, g.interface
                    ));
                }
                (GroupState::Active | GroupState::NotActive, _) => {}
            }
        }
        if !blind.is_empty() {
            let span = l.span(mine.first().map_or_else(Default::default, |p| p.i.lines));
            let s = l.sink(
                &f,
                format!("{port}: a virtual MAC is not known: {}", blind.join("; ")),
                span,
            );
            l.add(s);
            continue;
        }
        let entry = if unknown.is_empty() {
            f.clone()
        } else {
            let next = format!("{f}/mac");
            let gate_spans: Vec<SourceSpan> = on_port
                .iter()
                .filter(|g| matches!(g.state, GroupState::Unknown(_)))
                .flat_map(|g| g.spans.clone())
                .collect();
            let mut rule = FRule::new(
                format!("{port}: the virtual MAC of an HSRP group whose state is not known"),
                RulePredicate::bounded(
                    Match {
                        dst_mac: MacCond::In(BTreeSet::new()),
                        ..Match::any()
                    },
                    Match {
                        dst_mac: MacCond::In(unknown),
                        ..Match::any()
                    },
                ),
                RuleAction::Deny,
            );
            rule.spans = gate_spans.clone();
            let meta = l.meta(&f, gate_spans);
            l.add(AclMatch {
                meta,
                acl: ObjectId::new(format!("{}:{f}", l.dev)),
                rules: vec![rule],
                default: RuleAction::Permit,
                next: l.id(&next),
            });
            next
        };
        let meta = l.meta(&entry, spans);
        l.add(Layer3HandOff {
            meta,
            macs,
            untagged: mine
                .iter()
                .find(|p| p.i.name == *port)
                .map(|p| l.id(&format!("in/{}", p.i.name))),
            tagged: mine
                .iter()
                .filter_map(|p| Some((p.dot1q?, l.id(&format!("in/{}", p.i.name)))))
                .collect(),
        });
    }
}

/// The next hops through ARP, the output ACLs, the output QoS and egress.
/// An egress whose port has one peer goes over the link, with the MAC of
/// the interface as the source MAC and the dot1q VLAN of a sub-interface as
/// the tag.
fn next_hops(l: &mut L, active: &[Port], st: &state::State, ext: &External) {
    let mut neighbours: TriePrefixTable<Vec<Neighbour>> = TriePrefixTable::new();
    for a in st.arp.iter().flatten().flatten() {
        let p = Prefix::host(a.ip);
        let mut v = neighbours.get(&p).cloned().unwrap_or_default();
        v.push(Neighbour {
            interface: InterfaceId::new(&a.interface),
            target: NeighbourTarget::Link,
            owner: format!("{:?}", a.mac),
            mac: Some(a.mac),
            spans: vec![a.span.clone()],
        });
        neighbours.insert(p, v);
    }
    let filtered_out = |i: &nxos::config::Interface| i.acl_out.is_some() || !i.unhandled.is_empty();
    let meta = l.meta("nexthop", Vec::new());
    l.add(NextHopResolution {
        meta,
        neighbours,
        complete: false,
        egress: active
            .iter()
            .map(|p| {
                let i = &p.i;
                let f = if filtered_out(i) {
                    format!("acl-out/{}", i.name)
                } else if i.qos_out.is_some() {
                    format!("qos-out/{}", i.name)
                } else {
                    format!("out/{}", i.name)
                };
                (InterfaceId::new(&i.name), l.id(&f))
            })
            .collect(),
        point_to_point: BTreeMap::new(),
    });
    for p in active {
        let i = &p.i;
        let out = format!("out/{}", i.name);
        let after_acl = match &i.qos_out {
            Some(_) => format!("qos-out/{}", i.name),
            None => out.clone(),
        };
        if filtered_out(i) {
            let f = l.interface_acl(i, i.acl_out.as_ref(), "out", &after_acl);
            l.add(f);
        }
        if let Some((policy, lines)) = &i.qos_out {
            let f = l.qos(&after_acl, policy, *lines, &out);
            l.add(f);
        }
        let meta = l.meta(&out, vec![l.span(i.lines)]);
        let (link, rewrite, tag) = egress_link(l, p, st, ext);
        l.add(Egress {
            meta,
            interface: InterfaceId::new(&i.name),
            mode: EgressMode::Routed,
            link,
            rewrite,
            tag,
        });
    }
}

/// The link, the rewrite and the tag of the egress of an interface. An
/// interface whose port has no peer keeps the tag and has no link.
fn egress_link(
    l: &mut L,
    p: &Port,
    st: &state::State,
    ext: &External,
) -> (Option<Link>, Rewrite, Tag) {
    let name = &p.i.name;
    let port = parent(name);
    let none = (None, Rewrite::default(), Tag::Keep);
    let peer = match ext.peers.get(port).map(Vec::as_slice) {
        Some([one]) => one,
        Some([]) | None => return none,
        Some(_) => {
            l.note(format!(
                "{name}: the port {port} has more than one peer, so the egress has no link"
            ));
            return none;
        }
    };
    let tag = if name == port {
        Some(Tag::Untagged)
    } else {
        p.dot1q.map(Tag::Vlan)
    };
    let src = p.mac.or_else(|| {
        st.interfaces
            .as_ref()
            .and_then(|x| x.as_ref().ok())
            .and_then(|m| m.get(port)?.mac)
    });
    let (Some(tag), Some(m)) = (tag, src) else {
        let why = if tag.is_none() {
            "the sub-interface has no dot1q VLAN"
        } else {
            "show interfaces gives no MAC"
        };
        l.note(format!("{name}: {why}, so the egress has no link"));
        return none;
    };
    (
        Some(Link {
            peer: Some(peer.target.clone()),
            delay_ns: None,
            provenance: peer.provenance.clone(),
            facts: Some(LinkFacts {
                local: link_end(st, port).unwrap_or_default(),
                remote: peer.remote.clone(),
            }),
        }),
        Rewrite {
            src_mac: Some(FieldValue::Known(m)),
            ..Rewrite::default()
        },
        tag,
    )
}

/// The physical facts of a port from `show interfaces`.
fn link_end(st: &state::State, port: &str) -> Option<LinkEnd> {
    let s = st.interfaces.as_ref()?.as_ref().ok()?.get(port)?;
    Some(LinkEnd {
        speed_mbps: s.speed_mbps,
        full_duplex: s.full_duplex,
        media: None,
        spans: vec![s.span.clone()],
    })
}

/// The edge interfaces: each interface with a connected network.
fn edges(l: &mut L, device: &str, active: &[Port]) {
    for p in active {
        let nets: Vec<Prefix> =
            p.i.addresses
                .iter()
                .filter_map(|a| iface_addr(&a.prefix))
                .filter(|(_, len)| *len < 32)
                .map(|(a, len)| Prefix::new(a, len))
                .collect();
        if !nets.is_empty() {
            l.out.edges.push(EdgeInterface {
                device: device.into(),
                interface: InterfaceId::new(&p.i.name),
                networks: nets,
                provenance: vec![l.span(p.i.lines)],
            });
        }
    }
}

/// Compares the VRF members of `show vrf all detail` with the `vrf` lines
/// of the config. Each difference gives a note; the config decides.
fn cross_check(l: &mut L, cfg: &Config, st: &state::State) {
    let Some(Ok(rows)) = &st.vrfs else {
        return;
    };
    let mut listed: BTreeMap<&str, &str> = BTreeMap::new();
    for r in rows {
        for i in &r.interfaces {
            listed.insert(i.as_str(), r.vrf.as_str());
        }
    }
    let configured: BTreeSet<&str> = cfg.interfaces.iter().map(|i| i.name.as_str()).collect();
    for i in &cfg.interfaces {
        let c = i.vrf.as_ref().map(|v| v.0.as_str());
        let s = listed.get(i.name.as_str()).copied();
        match (c, s) {
            (Some(c), None) => l.note(format!(
                "{}: VRF {c} in the config, and show vrf all detail does not list the interface; the config decides",
                i.name
            )),
            (c, Some(s)) if c != Some(s) => l.note(format!(
                "{}: VRF {s} in show vrf all detail, and {} in the config; the config decides",
                i.name,
                c.map_or("the default VRF".to_string(), |c| format!("VRF {c}"))
            )),
            _ => {}
        }
    }
    for (i, v) in &listed {
        if !configured.contains(i) {
            l.note(format!(
                "{i}: VRF {v} in show vrf all detail, and the config has no such interface"
            ));
        }
    }
}

/// The route code of a path, without the `*` of a candidate default.
fn code(protocol: &str) -> &str {
    protocol
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_end_matches('*')
}

/// The paths that are not backup paths.
fn primary<'a>(paths: &[&'a RoutePath]) -> Vec<&'a RoutePath> {
    paths.iter().copied().filter(|p| !p.backup).collect()
}

fn line_of(s: &SourceSpan) -> String {
    format!("{} line {}", s.file, s.first_line)
}

/// The FIB of a VRF from the route table section. A route table line that
/// is not read makes the lookup of its prefix unknown; such a line with no
/// prefix makes each lookup of the VRF unknown, as does a VRF that the
/// section does not have. The addresses of the interfaces of the VRF are
/// local routes, as are the virtual addresses of the active HSRP groups; the
/// virtual address of a group whose state is not known has no next hop.
/// Each IPv6 packet is unknown.
fn fib(l: &mut L, vrf: &str, active: &[Port], rib: Option<&Rib>, vips: &[Vip]) -> Fib {
    let mut t = Fib::new();
    let all: Prefix = "0.0.0.0/0".parse().expect("a valid prefix");
    let unknown_all = |spans: Vec<SourceSpan>| Route::new(RouteKind::Static, Vec::new(), spans);
    match rib {
        None => t.insert(all, unknown_all(Vec::new())),
        Some(rib) => {
            let mine = |v: &Option<String>| v.as_deref().is_none_or(|v| v == vrf);
            let whole: Vec<&UnreadRoute> = rib
                .unread
                .iter()
                .filter(|u| u.prefix.is_none() && mine(&u.vrf))
                .collect();
            let present = rib.paths.iter().any(|p| p.vrf == vrf)
                || rib.unread.iter().any(|u| u.vrf.as_deref() == Some(vrf));
            if !whole.is_empty() {
                for u in &whole {
                    l.note(format!(
                        "VRF {vrf}: each route lookup is unknown: {} is not read: {}",
                        line_of(&u.span),
                        u.text
                    ));
                }
                t.insert(
                    all,
                    unknown_all(whole.iter().map(|u| u.span.clone()).collect()),
                );
            } else if !present {
                l.note(format!(
                    "VRF {vrf}: the route table section has no route of the VRF, so each route lookup is unknown"
                ));
                t.insert(all, unknown_all(Vec::new()));
            } else {
                routes(l, &mut t, vrf, rib, &mine);
            }
        }
    }
    for p in active.iter().filter(|p| p.vrf() == vrf) {
        for a in &p.i.addresses {
            if let Some((ip, _)) = iface_addr(&a.prefix) {
                t.insert(
                    Prefix::host(ip),
                    Route::new(RouteKind::Local, Vec::new(), vec![l.span(a.lines)]),
                );
            }
        }
    }
    for v in vips.iter().filter(|v| v.vrf == vrf) {
        let kind = if v.local {
            RouteKind::Local
        } else {
            RouteKind::Static
        };
        t.insert(
            Prefix::host(v.ip),
            Route::new(kind, Vec::new(), v.spans.clone()),
        );
    }
    let v6: Prefix = "::/0".parse().expect("a valid prefix");
    t.insert(v6, Route::new(RouteKind::Static, Vec::new(), Vec::new()));
    t
}

/// The routes of the paths of a VRF, and the routes of the lines that are
/// not read.
fn routes(l: &mut L, t: &mut Fib, vrf: &str, rib: &Rib, mine: &dyn Fn(&Option<String>) -> bool) {
    let mut unread: BTreeMap<Prefix, Vec<&UnreadRoute>> = BTreeMap::new();
    for u in rib.unread.iter().filter(|u| mine(&u.vrf)) {
        if let Some(p) = u.prefix {
            unread.entry(p).or_default().push(u);
        }
    }
    let mut by_prefix: BTreeMap<Prefix, Vec<&RoutePath>> = BTreeMap::new();
    for p in rib.paths.iter().filter(|p| p.vrf == vrf) {
        by_prefix.entry(p.prefix).or_default().push(p);
    }
    // The next hop of a path with no interface: the interface of the
    // connected route that is the longest match of the next hop.
    let resolve = |g: IpAddr| -> Result<String, String> {
        let best = by_prefix
            .iter()
            .filter(|(_, paths)| !primary(paths).is_empty())
            .map(|(p, _)| p)
            .chain(unread.keys())
            .filter(|p| p.contains(g))
            .max_by_key(|p| p.len())
            .ok_or_else(|| format!("the next hop {g} has no route"))?;
        if unread.contains_key(best) {
            return Err(format!(
                "the next hop {g} resolves through {best}, a route that is not read"
            ));
        }
        let paths = primary(&by_prefix[best]);
        let ifaces: BTreeSet<&str> = paths
            .iter()
            .filter(|p| code(&p.protocol) == CONNECTED_CODE && p.gateway.is_none())
            .filter_map(|p| p.interface.as_deref())
            .collect();
        match ifaces.into_iter().collect::<Vec<_>>().as_slice() {
            [one] if paths.len() == 1 => Ok((*one).to_string()),
            _ => Err(format!(
                "the next hop {g} does not resolve through one connected route"
            )),
        }
    };
    let hop = |l: &L, iface: &str, gw: Option<IpAddr>| RouteNextHop {
        interface: InterfaceId::new(iface),
        gateway: gw,
        next: l.id("nexthop"),
    };
    let mut out: Vec<(Prefix, Route)> = Vec::new();
    let mut notes = Vec::new();
    for (prefix, paths) in &by_prefix {
        if unread.contains_key(prefix) {
            continue;
        }
        let spans: Vec<SourceSpan> = paths.iter().map(|p| p.span.clone()).collect();
        let first = primary(paths);
        let Some(head) = first.first() else {
            notes.push(format!(
                "route {prefix} in VRF {vrf}: each path is a backup path"
            ));
            out.push((*prefix, Route::new(RouteKind::Static, Vec::new(), spans)));
            continue;
        };
        let c = code(&head.protocol);
        if c == LOCAL_CODE {
            out.push((*prefix, Route::new(RouteKind::Local, Vec::new(), spans)));
            continue;
        }
        if first.iter().any(|p| {
            p.interface
                .as_deref()
                .is_some_and(|i| i.eq_ignore_ascii_case("null0"))
        }) {
            out.push((*prefix, Route::new(RouteKind::Null, Vec::new(), spans)));
            continue;
        }
        let kind = if c == CONNECTED_CODE {
            RouteKind::Connected
        } else {
            RouteKind::Static
        };
        let mut hops = Vec::new();
        let mut problem = None;
        for p in &first {
            if let Some(v) = &p.other_vrf {
                problem = Some(format!(
                    "a next hop in VRF {v} is reached through a label switched path, which is not lowered"
                ));
                break;
            }
            match (&p.interface, p.gateway) {
                (Some(i), gw) => hops.push(hop(l, i, gw)),
                (None, Some(g)) => match resolve(g) {
                    Ok(i) => hops.push(hop(l, &i, Some(g))),
                    Err(why) => {
                        problem = Some(why);
                        break;
                    }
                },
                (None, None) => {
                    problem = Some("a path with no next hop and no interface".to_string());
                    break;
                }
            }
        }
        if let Some(why) = problem {
            notes.push(format!("route {prefix} in VRF {vrf}: {why}"));
            hops.clear();
        }
        out.push((*prefix, Route::new(kind, hops, spans)));
    }
    for (prefix, lines) in &unread {
        for u in lines {
            notes.push(format!(
                "route {prefix} in VRF {vrf}: {} is not read: {}",
                line_of(&u.span),
                u.text
            ));
        }
        out.push((
            *prefix,
            Route::new(
                RouteKind::Static,
                Vec::new(),
                lines.iter().map(|u| u.span.clone()).collect(),
            ),
        ));
    }
    for n in notes {
        l.note(n);
    }
    for (p, r) in out {
        t.insert(p, r);
    }
}
