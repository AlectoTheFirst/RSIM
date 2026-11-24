//! Lowering of an IOS-XR running config and its collected sections into the
//! layer 3 function instances of a router: the interfaces with their VRFs,
//! the input and output ACLs, the QoS policies, the route table of each VRF,
//! the next-hop resolution through ARP, the HSRP groups, and the hand-off
//! and the egress of each port with a link. Gives the summary of the router
//! for the link join too.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use rsim_core::{
    FieldValue, FunctionId, InterfaceId, Mac, MacCond, Match, NeighbourTarget, ObjectId, PortCond,
    Prefix, PrefixTable, Rewrite, RulePredicate, SourceSpan, TriePrefixTable, VrfId,
};
use rsim_engine::EdgeInterface;
use rsim_functions::{
    AclMatch, DeviceDelivery, Egress, EgressMode, Fib, Ingress, Layer3HandOff, Link, LinkEnd,
    LinkFacts, LocalInput, Neighbour, NextHopResolution, Route, RouteKind, RouteLookup,
    RouteNextHop, RouteProtocol, Rule as FRule, RuleAction, Tag, VendorProfile, VrfSelection,
};

use super::config::{Config, Interface};
use super::profile::{
    ALL_IPV4, CONNECTED_CODE, DEFAULT_VRF, HSRP_ACTIVE, HSRP_NOT_ACTIVE, LOCAL_CODE,
    UP_WITHOUT_SHUTDOWN,
};
use super::state::{self, HsrpRow, Rib, RoutePath, Section, UnreadRoute};
use crate::links::{External, Summary, VlanAddrs};
use crate::nxos;
use crate::nxos::config::{Ace, AclAction, AddrSpec, Lines, PortSpec};
use crate::nxos::lower::{L, iface_addr};
use crate::resolve::{Origin, Path, Resolver, Target, through_default};
use crate::route_tables::{TABLE_NOT_COLLECTED, route_kind};
use crate::vyos::Lowered;

/// The protocol word of the shared ACL functions for all IPv4 protocols.
const SHARED_ALL_IP: &str = "ip";

/// A layer 3 interface that is lowered, in the form of the shared ACL
/// functions.
pub(crate) struct Port {
    pub(crate) i: nxos::config::Interface,
    /// The span of its record in `show interfaces`.
    pub(crate) state: Option<SourceSpan>,
    /// The VLAN of `encapsulation dot1q` of a sub-interface.
    pub(crate) dot1q: Option<u16>,
    /// The IPv6 addresses of the config.
    pub(crate) ipv6: Vec<String>,
    /// The MAC of `show interfaces`.
    pub(crate) mac: Option<Mac>,
}

impl Port {
    pub(crate) fn vrf(&self) -> &str {
        self.i.vrf.as_deref().unwrap_or(DEFAULT_VRF)
    }
}

/// The port of an interface: the name without the sub-interface number.
pub(crate) fn parent(name: &str) -> &str {
    name.split_once('.').map_or(name, |x| x.0)
}

/// The interface types that cannot end a link, in lower case.
const NO_LINK: &[&str] = &["loopback", "null", "tunnel", "bvi"];

/// The state of an HSRP or a VRRP group from the config and its section.
pub(crate) enum GroupState {
    Active,
    NotActive,
    Unknown(String),
}

/// An IPv4 HSRP or VRRP group of a lowered interface.
pub(crate) struct Group {
    /// `HSRP` or `VRRP`.
    pub(crate) what: &'static str,
    pub(crate) group: u32,
    /// The virtual addresses, the primary first.
    pub(crate) addresses: Vec<Ipv4Addr>,
    /// The config name of the interface.
    pub(crate) interface: String,
    pub(crate) state: GroupState,
    pub(crate) vmac: Option<Mac>,
    pub(crate) spans: Vec<SourceSpan>,
}

/// The words of the state section of a group protocol.
pub(crate) struct GroupRules<'a> {
    /// `HSRP` or `VRRP`.
    pub(crate) what: &'static str,
    /// The command of the section, for the notes.
    pub(crate) command: &'a str,
    /// The state word of the router that owns the virtual address, in
    /// lower case.
    pub(crate) active: &'a str,
    /// The state words of a router that does not own it, in lower case.
    pub(crate) not_active: &'a [&'a str],
    /// Why a group with no MAC of the config has no known virtual MAC.
    pub(crate) no_vmac: &'a str,
}

/// A virtual address in the route table: a local route of an active group,
/// or a route with no next hop of a group whose state is not known.
pub(crate) struct Vip {
    pub(crate) vrf: String,
    pub(crate) ip: IpAddr,
    pub(crate) local: bool,
    pub(crate) spans: Vec<SourceSpan>,
}

/// Where the routes of a VRF go: the function of each next hop, and the
/// reason of a path whose next hop is in another VRF.
pub(crate) struct Hops<'a> {
    pub(crate) next: &'a str,
    pub(crate) other_vrf: &'a dyn Fn(&str) -> String,
    /// The route codes of the learned routes and of the static routes of
    /// the vendor profile.
    pub(crate) learned: &'a [(&'a str, RouteProtocol)],
    pub(crate) statics: &'a [&'a str],
    /// The VRFs with a dynamic routing protocol in the config.
    pub(crate) dynamic: &'a BTreeMap<String, Vec<(u32, u32)>>,
    /// The routes of the route table section of each VRF, for the
    /// resolution of a next hop with no interface.
    pub(crate) resolver: &'a Resolver,
    /// The flag of the vendor profile: true if the next hop of a computed
    /// route resolves through a default route.
    pub(crate) computed_through_default: bool,
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

/// The IPv4 ACLs in the form of the shared ACL functions, with the entries
/// that the config reader cannot read placed by [`place_unreadable`].
fn acls(cfg: &Config) -> BTreeMap<String, nxos::config::Acl> {
    cfg.acls
        .iter()
        .map(|(name, acl)| {
            let mut acl = acl.clone();
            for e in &mut acl.entries {
                if e.protocol == ALL_IPV4 {
                    e.protocol = SHARED_ALL_IP.to_string();
                }
            }
            place_unreadable(&mut acl);
            (name.clone(), acl)
        })
        .collect()
}

/// Places each entry of an ACL that the config reader cannot read and that
/// starts with a sequence number and an action at its place, as an entry
/// whose match set is not known, so the match bounds decide the packets
/// that reach it. The other unreadable lines stay unreadable.
pub(crate) fn place_unreadable(acl: &mut nxos::config::Acl) {
    let seq = |s: &str| s.parse::<u64>().ok();
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
                unhandled: vec![format!("entry not read: {text}")],
                lines: acl.lines,
            },
        );
    }
    acl.unreadable = rest;
}

pub(crate) fn error<T>(s: &Section<T>) -> Option<&str> {
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
            l.note(format!("section {name} not read: {e}"));
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
                "{}: administratively down in show interfaces, no shutdown line in the config",
                i.name
            ));
        }
        if s.and_then(|s| s.oper_up) == Some(false) || i.addresses.is_empty() {
            continue;
        }
        let mut p = port(i);
        if admin.is_none() {
            p.unhandled.push("admin state not known".into());
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
    let mut sum = summary(&l, cfg, &st, &active, &names);
    for i in &cfg.interfaces {
        if let Some((text, lines)) = &i.description
            && sum.entries.contains_key(&i.name)
        {
            sum.descriptions
                .insert(i.name.clone(), (text.clone(), l.span(*lines)));
        }
    }
    if active.is_empty() {
        return (l.out, sum);
    }

    inputs(&mut l, &active, profile.default_vrf.clone(), "route");

    // The route lookup in the table of each VRF.
    let rib = st.rib.as_ref().and_then(|x| x.as_ref().ok());
    if st.rib.is_none() {
        l.note("no route table section, each route lookup unknown".into());
    }
    let mut vrfs: BTreeSet<String> = cfg.vrfs.keys().cloned().collect();
    vrfs.insert(DEFAULT_VRF.to_string());
    vrfs.extend(active.iter().map(|p| p.vrf().to_string()));
    if let Some(r) = rib {
        vrfs.extend(r.paths.iter().map(|p| p.vrf.clone()));
        vrfs.extend(r.unread.iter().filter_map(|u| u.vrf.clone()));
    }
    let vips = vips(&groups, &active);
    let other_vrf =
        |v: &str| format!("next hop in VRF {v} through a label switched path, not lowered");
    let resolver = resolver(rib, &vrfs);
    sum.routes = resolver.clone();
    let hops = Hops {
        next: "nexthop",
        other_vrf: &other_vrf,
        learned: super::profile::LEARNED_CODES,
        statics: super::profile::STATIC_CODES,
        dynamic: &cfg.dynamic_vrfs,
        resolver: &resolver,
        computed_through_default: super::profile::COMPUTED_THROUGH_DEFAULT,
    };
    let mut tables = BTreeMap::new();
    for v in &vrfs {
        let t = fib(&mut l, v, &active, rib, &vips, &hops);
        tables.insert(VrfId::new(v), t);
    }
    l.note("IPv6 not lowered".into());
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
        next_hops(&mut l, &active, &st, ext, &BTreeMap::new());
    }
    handoffs(
        &mut l,
        &active,
        &groups,
        &sum,
        ext,
        &unlowered(cfg, &st, &active),
    );
    edges(&mut l, device, &active);
    (l.out, sum)
}

/// The interfaces whose frames the hand-off of their port does not lower:
/// the `l2transport` sub-interfaces, the lowered sub-interfaces with no
/// dot1q VLAN that the handlers read, and the interfaces that are not shut,
/// not down in `show interfaces` and not lowered, with an IPv6 address or
/// an unhandled line.
fn unlowered(cfg: &Config, st: &state::State, active: &[Port]) -> Vec<Unlowered> {
    let mut out: Vec<Unlowered> = cfg
        .l2transport
        .iter()
        .map(|t| Unlowered {
            name: t.name.clone(),
            vlan: t.dot1q,
            routed: false,
            tagged: true,
            untagged: false,
            reason: format!("{} not lowered", t.key),
            lines: t.lines,
        })
        .collect();
    out.extend(
        active
            .iter()
            .filter(|p| p.i.name.contains('.') && p.dot1q.is_none())
            .map(|p| Unlowered {
                name: p.i.name.clone(),
                vlan: None,
                routed: true,
                tagged: true,
                untagged: false,
                reason: format!("dot1q VLAN of {} not read", p.i.name),
                lines: p.i.lines,
            }),
    );
    let states = st.interfaces.as_ref().and_then(|x| x.as_ref().ok());
    for i in &cfg.interfaces {
        let s = states.and_then(|m| m.get(&i.name));
        if i.shutdown || i.bundle.is_some() || s.and_then(|s| s.oper_up) == Some(false) {
            continue;
        }
        let lowered = active.iter().any(|p| p.i.name == i.name);
        if lowered || (i.ipv6.is_empty() && i.unhandled.is_empty()) {
            continue;
        }
        let sub = i.name.contains('.');
        out.push(Unlowered {
            name: i.name.clone(),
            vlan: i.dot1q.map(|d| d.0),
            routed: true,
            tagged: sub,
            untagged: !sub,
            reason: format!("{} not lowered", i.name),
            lines: i.lines,
        });
    }
    out
}

/// An interface whose frames the hand-off of its port does not lower.
pub(crate) struct Unlowered {
    pub(crate) name: String,
    /// Its VLAN; with none, each VLAN of no lowered sub-interface.
    pub(crate) vlan: Option<u16>,
    /// True when only its frames to a MAC of the router are affected.
    pub(crate) routed: bool,
    /// True when it can take a tagged frame.
    pub(crate) tagged: bool,
    /// True when it can take an untagged frame too.
    pub(crate) untagged: bool,
    pub(crate) reason: String,
    pub(crate) lines: nxos::config::Lines,
}

/// The VLANs from 0 to 4095 that are not in `taken`, as ranges.
fn other_vlans(taken: &BTreeSet<u16>) -> Vec<(u16, u16)> {
    let mut out = Vec::new();
    let mut lo: u16 = 0;
    for &v in taken {
        if v > lo {
            out.push((lo, v - 1));
        }
        lo = v + 1;
    }
    if lo <= 4095 {
        out.push((lo, 4095));
    }
    out
}

/// The ingress of each lowered interface, its input QoS and its input ACL,
/// and the VRF selection, which goes to `next`.
pub(crate) fn inputs(l: &mut L, active: &[Port], default_vrf: Option<VrfId>, next: &str) {
    for p in active {
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
        default_vrf,
        next: l.id(next),
    });
}

/// The summary of the router for the link join.
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
    let ports: Vec<RouterPort> = cfg
        .interfaces
        .iter()
        .map(|i| RouterPort {
            name: &i.name,
            channel: i.bundle.map(|(n, _)| format!("Bundle-Ether{n}")),
            shut: i.shutdown,
        })
        .collect();
    routed_summary(l, &mut sum, &ports, NO_LINK, st, active);
    sum
}

/// An interface of a router for the summary: its config name, the bundle
/// or port channel of a member port, and true for a shut interface.
pub(crate) struct RouterPort<'a> {
    pub(crate) name: &'a str,
    pub(crate) channel: Option<String>,
    pub(crate) shut: bool,
}

/// Adds the routed ports of a router to its summary. A port that can end a
/// link is a physical port or a bundle that is not a bundle member and not
/// shut, whose type is not in `no_link`, with a MAC in `show interfaces`,
/// and with a lowered interface: the port or a sub-interface. A frame
/// enters it at its hand-off. Its layer 3 addresses are the addresses of
/// the port and of its sub-interfaces by their dot1q VLAN. The ARP rows of
/// the sub-interfaces with a VLAN are ARP rows of the summary. The LLDP and
/// CDP rows and the next hops of the route table complete it.
pub(crate) fn routed_summary(
    l: &L,
    sum: &mut Summary,
    ports: &[RouterPort],
    no_link: &[&str],
    st: &state::State,
    active: &[Port],
) {
    let states = st.interfaces.as_ref().and_then(|x| x.as_ref().ok());
    for i in ports {
        if let Some(c) = &i.channel {
            sum.channel.insert(i.name.to_string(), c.clone());
        }
    }
    for i in ports {
        let lower_name = i.name.to_ascii_lowercase();
        let s = states.and_then(|m| m.get(i.name));
        if i.name.contains('.')
            || i.channel.is_some()
            || i.shut
            || no_link.iter().any(|t| lower_name.starts_with(t))
            || s.and_then(|s| s.oper_up) == Some(false)
            || !active.iter().any(|p| parent(&p.i.name) == i.name)
        {
            continue;
        }
        let Some((s, m)) = s.and_then(|s| Some((s, s.mac?))) else {
            continue;
        };
        sum.entries
            .insert(i.name.to_string(), l.id(&format!("handoff/{}", i.name)));
        sum.port_macs.insert(i.name.to_string(), m);
        sum.port_spans.insert(i.name.to_string(), s.span.clone());
        if s.speed_mbps.is_some() || s.full_duplex.is_some() {
            sum.facts.insert(
                i.name.to_string(),
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
        sum.l3.insert(i.name.to_string(), vlans);
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
        for p in &rib.paths {
            if let Some(g) = p.gateway {
                let vrf = p.other_vrf.as_ref().unwrap_or(&p.vrf);
                sum.next_hop_vrfs.entry(g).or_default().insert(vrf.clone());
            }
        }
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
}

/// The state of a group from the rows of its section: the state word of the
/// IPv4 row of the interface and the group, with the primary virtual
/// address of the config. `spans` takes the span of the row. A group with a
/// line that is not read has a state that is not known.
pub(crate) fn group_state(
    group: u32,
    primary: Option<Ipv4Addr>,
    unhandled: &[String],
    iface: &str,
    rows: &Section<Vec<HsrpRow>>,
    rules: &GroupRules,
    spans: &mut Vec<SourceSpan>,
) -> GroupState {
    if !unhandled.is_empty() {
        return GroupState::Unknown(format!("lines {} not read", unhandled.join(", ")));
    }
    let Some(primary) = primary else {
        return GroupState::Unknown("no virtual address in the config".into());
    };
    let cmd = rules.command;
    let rows = match rows {
        None => return GroupState::Unknown(format!("no {cmd} section")),
        Some(Err(e)) => return GroupState::Unknown(format!("{cmd} not read: {e}")),
        Some(Ok(rows)) => rows,
    };
    let mine: Vec<&HsrpRow> = rows
        .iter()
        .filter(|r| r.interface == iface && r.group == group)
        .filter(|r| !r.address.is_some_and(|a| a.is_ipv6()))
        .collect();
    let [r] = mine.as_slice() else {
        return GroupState::Unknown(format!("{} IPv4 rows of the group in {cmd}", mine.len()));
    };
    spans.push(r.span.clone());
    if let Some(a) = r.address
        && a != IpAddr::V4(primary)
    {
        return GroupState::Unknown(format!("address {a} in {cmd}, {primary} in the config"));
    }
    let word = r.state.to_ascii_lowercase();
    if word == rules.active {
        GroupState::Active
    } else if rules.not_active.contains(&word.as_str()) {
        GroupState::NotActive
    } else {
        GroupState::Unknown(format!("state {:?} not known", r.state))
    }
}

/// The note of a group whose state or virtual MAC is not known.
pub(crate) fn group_note(l: &mut L, g: &Group, rules: &GroupRules) {
    match (&g.state, g.vmac) {
        (GroupState::Unknown(why), _) => l.note(format!(
            "{}: {} group {}: {why}, virtual address and MAC unknown",
            g.interface, g.what, g.group
        )),
        (GroupState::Active, None) => l.note(format!(
            "{}: {} group {}: {}, virtual MAC not known",
            g.interface, g.what, g.group, rules.no_vmac
        )),
        _ => {}
    }
}

/// The virtual addresses of the groups in the route table: a local route
/// for an active group, and a route with no next hop for a group whose
/// state is not known.
pub(crate) fn vips(groups: &[Group], active: &[Port]) -> Vec<Vip> {
    groups
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
            g.addresses
                .iter()
                .map(|a| Vip {
                    vrf: vrf.to_string(),
                    ip: IpAddr::V4(*a),
                    local,
                    spans: g.spans.clone(),
                })
                .collect()
        })
        .collect()
}

/// The words of `show hsrp`.
const HSRP_RULES: GroupRules = GroupRules {
    what: "HSRP",
    command: "show hsrp",
    active: HSRP_ACTIVE,
    not_active: HSRP_NOT_ACTIVE,
    no_vmac: "no mac-address line",
};

/// The IPv4 HSRP groups of the lowered interfaces with their state and
/// their virtual MAC. A group whose state cannot be read, or with a line
/// that is not read, has a state that is not known. The virtual MAC is the
/// MAC of the `mac-address` line; a group with no such line has a virtual
/// MAC that is not known.
fn hsrp(
    l: &mut L,
    cfg: &Config,
    st: &state::State,
    active: &[Port],
    names: &nxos::names::Names,
) -> Vec<Group> {
    let mut out = Vec::new();
    for g in &cfg.hsrp {
        let iface = names.resolve(&g.interface);
        if !active.iter().any(|p| p.i.name == iface) {
            if !cfg.interfaces.iter().any(|i| i.name == iface) {
                l.note(format!(
                    "HSRP group {} of {}: no such interface in the config",
                    g.group, g.interface
                ));
            }
            continue;
        }
        let mut spans = vec![l.span(g.lines)];
        spans.extend(g.addresses.iter().map(|(_, x)| l.span(*x)));
        let vmac = g.mac.map(|(m, x)| {
            spans.push(l.span(x));
            m
        });
        let state = group_state(
            g.group,
            g.addresses.first().map(|a| a.0),
            &g.unhandled,
            &iface,
            &st.hsrp,
            &HSRP_RULES,
            &mut spans,
        );
        let group = Group {
            what: HSRP_RULES.what,
            group: g.group,
            addresses: g.addresses.iter().map(|a| a.0).collect(),
            interface: iface,
            state,
            vmac,
            spans,
        };
        group_note(l, &group, &HSRP_RULES);
        out.push(group);
    }
    out
}

/// The hand-off of each port with a link: the MACs of the port, of its
/// sub-interfaces and of its active groups go to the ingress of the port or
/// of the sub-interface of the dot1q VLAN. A frame to the virtual MAC of a
/// group whose state is not known gives `Unknown`, as does a frame of an
/// interface in `unlowered`: each frame of its VLAN, or of a routed
/// interface each frame of its VLAN to a MAC of the router, if it can take
/// a tagged frame, and the untagged frames of an interface that can take
/// them. If an active group or a group whose state is not known has no
/// known virtual MAC, each frame of the port gives `Unknown`.
pub(crate) fn handoffs(
    l: &mut L,
    active: &[Port],
    groups: &[Group],
    sum: &Summary,
    ext: &External,
    unlowered: &[Unlowered],
) {
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
                (GroupState::Unknown(_) | GroupState::Active, None) => {
                    blind.push(format!("{} group {} of {}", g.what, g.group, g.interface));
                }
                (GroupState::NotActive, _) => {}
            }
        }
        if !blind.is_empty() {
            let span = l.span(mine.first().map_or_else(Default::default, |p| p.i.lines));
            let s = l.sink(
                &f,
                format!("{port}: virtual MAC not known: {}", blind.join(", ")),
                span,
            );
            l.add(s);
            continue;
        }
        let tagged: BTreeSet<u16> = mine.iter().filter_map(|p| p.dot1q).collect();
        let mut rules: Vec<FRule<RuleAction>> = Vec::new();
        for u in unlowered
            .iter()
            .filter(|u| parent(&u.name) == port && u.tagged)
        {
            let vlans = u
                .vlan
                .map_or_else(|| other_vlans(&tagged), |v| vec![(v, v)]);
            let dst_mac = if u.routed {
                MacCond::In(macs.union(&unknown).copied().collect())
            } else {
                MacCond::Any
            };
            let mut rule = FRule::new(
                format!("{port}: {}", u.reason),
                RulePredicate::bounded(
                    Match {
                        vlan: PortCond::In(Vec::new()),
                        ..Match::any()
                    },
                    Match {
                        dst_mac,
                        vlan: PortCond::In(vlans),
                        ..Match::any()
                    },
                ),
                RuleAction::Deny,
            );
            rule.spans = vec![l.span(u.lines)];
            rules.push(rule);
        }
        // The untagged frames come after each tagged frame.
        let open: Vec<&Unlowered> = unlowered
            .iter()
            .filter(|u| parent(&u.name) == port && u.untagged)
            .collect();
        if !open.is_empty() {
            rules.push(FRule::new(
                format!("{port}: a tagged frame"),
                RulePredicate::exact(Match {
                    vlan: PortCond::In(vec![(0, 4095)]),
                    ..Match::any()
                }),
                RuleAction::Permit,
            ));
        }
        for u in open {
            let dst_mac = if u.routed {
                MacCond::In(macs.union(&unknown).copied().collect())
            } else {
                MacCond::Any
            };
            let mut rule = FRule::new(
                format!("{port}: {}", u.reason),
                RulePredicate::bounded(
                    Match {
                        dst_mac: MacCond::In(BTreeSet::new()),
                        ..Match::any()
                    },
                    Match {
                        dst_mac,
                        ..Match::any()
                    },
                ),
                RuleAction::Deny,
            );
            rule.spans = vec![l.span(u.lines)];
            rules.push(rule);
        }
        let entry = if unknown.is_empty() && rules.is_empty() {
            f.clone()
        } else {
            let next = format!("{f}/mac");
            let mut gate_spans: Vec<SourceSpan> = on_port
                .iter()
                .filter(|g| matches!(g.state, GroupState::Unknown(_)))
                .flat_map(|g| g.spans.clone())
                .collect();
            let mut gate: Vec<FRule<RuleAction>> = Vec::new();
            if !unknown.is_empty() {
                let what: BTreeSet<&str> = on_port
                    .iter()
                    .filter(|g| matches!(g.state, GroupState::Unknown(_)))
                    .map(|g| g.what)
                    .collect();
                let what: Vec<&str> = what.into_iter().collect();
                let mut rule = FRule::new(
                    format!(
                        "{port}: virtual MAC of an {} group of unknown state",
                        what.join(" or ")
                    ),
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
                gate.push(rule);
            }
            gate_spans.extend(rules.iter().flat_map(|r| r.spans.clone()));
            gate.extend(rules);
            let meta = l.meta(&f, gate_spans);
            l.add(AclMatch {
                meta,
                acl: ObjectId::new(format!("{}:{f}", l.dev)),
                rules: gate,
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
/// the tag. The egress of an interface in `svis` goes untagged to the
/// function of its SVI port, with the MAC of the SVI as the source MAC.
pub(crate) fn next_hops(
    l: &mut L,
    active: &[Port],
    st: &state::State,
    ext: &External,
    svis: &BTreeMap<String, (FunctionId, Mac)>,
) {
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
        let (link, rewrite, tag) = match svis.get(&i.name) {
            Some((port, m)) => (
                Some(Link {
                    peer: Some(port.clone()),
                    delay_ns: None,
                    provenance: Vec::new(),
                    facts: None,
                }),
                Rewrite {
                    src_mac: Some(FieldValue::Known(*m)),
                    ..Rewrite::default()
                },
                Tag::Untagged,
            ),
            None => egress_link(l, p, st, ext),
        };
        l.add(Egress {
            meta,
            interface: InterfaceId::new(&i.name),
            mode: EgressMode::Routed,
            link,
            rewrite,
            tag,
            exit: None,
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
                "{name}: port {port} has more than one peer, no link"
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
            "sub-interface with no dot1q VLAN"
        } else {
            "no MAC in show interfaces"
        };
        l.note(format!("{name}: {why}, no link"));
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
pub(crate) fn edges(l: &mut L, device: &str, active: &[Port]) {
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
                "{}: VRF {c} in the config, not in show vrf all detail, config used",
                i.name
            )),
            (c, Some(s)) if c != Some(s) => l.note(format!(
                "{}: VRF {s} in show vrf all detail, {} in the config, config used",
                i.name,
                c.map_or("the default VRF".to_string(), |c| format!("VRF {c}"))
            )),
            _ => {}
        }
    }
    for (i, v) in &listed {
        if !configured.contains(i) {
            l.note(format!(
                "{i}: VRF {v} in show vrf all detail, no such interface in the config"
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
/// section does not have, with the reason that its route table is not
/// collected if its config has a dynamic routing protocol. The addresses of the interfaces of the VRF are
/// local routes, as are the virtual addresses of the active HSRP groups; the
/// virtual address of a group whose state is not known has no next hop.
/// Each IPv6 packet is unknown. The next hops go to the function of `hops`.
pub(crate) fn fib(
    l: &mut L,
    vrf: &str,
    active: &[Port],
    rib: Option<&Rib>,
    vips: &[Vip],
    hops: &Hops,
) -> Fib {
    let mut t = Fib::new();
    let all: Prefix = "0.0.0.0/0".parse().expect("a valid prefix");
    let unknown_all = |spans: Vec<SourceSpan>| Route::new(RouteKind::Static, Vec::new(), spans);
    // A VRF with a dynamic routing protocol and no route of the section.
    let not_collected = |l: &L| {
        hops.dynamic.get(vrf).map(|found| {
            let spans = found
                .iter()
                .map(|(first, last)| {
                    l.span(Lines {
                        first: *first,
                        last: *last,
                    })
                })
                .collect();
            Route::unknown_with(
                RouteKind::Static,
                rsim_core::ReasonCode::NotCollected,
                TABLE_NOT_COLLECTED,
                spans,
            )
        })
    };
    match rib {
        None => t.insert(
            all,
            not_collected(l).unwrap_or_else(|| unknown_all(Vec::new())),
        ),
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
                        "VRF {vrf}: {} not read: {}, each route lookup unknown",
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
                    "VRF {vrf}: no route of the VRF in the route table section, each route lookup unknown"
                ));
                t.insert(
                    all,
                    not_collected(l).unwrap_or_else(|| unknown_all(Vec::new())),
                );
            } else {
                routes(l, &mut t, vrf, rib, &mine, hops);
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

/// The routes of the route table section for the resolution of a next hop:
/// a route with a line that is not read is unknown, as is a route with only
/// backup paths or with a next hop in another VRF; a line with no prefix
/// makes each resolution in its VRF unknown, or in each VRF for a line
/// before the first VRF.
pub(crate) fn resolver(rib: Option<&Rib>, vrfs: &BTreeSet<String>) -> Resolver {
    let mut r = Resolver::new();
    let Some(rib) = rib else {
        return r;
    };
    let mut by_prefix: BTreeMap<(&str, Prefix), Vec<&RoutePath>> = BTreeMap::new();
    for p in &rib.paths {
        by_prefix.entry((&p.vrf, p.prefix)).or_default().push(p);
    }
    for ((vrf, prefix), paths) in &by_prefix {
        let spans: Vec<SourceSpan> = paths.iter().map(|p| p.span.clone()).collect();
        let first = primary(paths);
        let target = match first.first() {
            None => Target::Unknown,
            Some(head) if code(&head.protocol) == LOCAL_CODE => Target::Local,
            Some(_)
                if first.iter().any(|p| {
                    p.interface
                        .as_deref()
                        .is_some_and(|i| i.eq_ignore_ascii_case("null0"))
                }) =>
            {
                Target::Null
            }
            Some(_) if first.iter().any(|p| p.other_vrf.is_some()) => Target::Unknown,
            Some(_) => Target::Paths(
                first
                    .iter()
                    .map(|p| Path {
                        interface: p.interface.clone(),
                        gateway: p.gateway,
                        vrf: None,
                    })
                    .collect(),
            ),
        };
        r.add(vrf, *prefix, target, spans);
    }
    for u in &rib.unread {
        let of: Vec<&str> = match &u.vrf {
            Some(v) => vec![v.as_str()],
            None => vrfs.iter().map(String::as_str).collect(),
        };
        for v in of {
            match u.prefix {
                Some(p) => r.add(v, p, Target::Unknown, vec![u.span.clone()]),
                None => r.unknown_vrf(v, vec![u.span.clone()]),
            }
        }
    }
    r
}

/// The routes of the paths of a VRF, and the routes of the lines that are
/// not read.
fn routes(
    l: &mut L,
    t: &mut Fib,
    vrf: &str,
    rib: &Rib,
    mine: &dyn Fn(&Option<String>) -> bool,
    to: &Hops,
) {
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
    let hop = |l: &L, iface: &str, gw: Option<IpAddr>| RouteNextHop {
        interface: InterfaceId::new(iface),
        gateway: gw,
        next: l.id(to.next),
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
            notes.push(format!("route {prefix} in VRF {vrf}, only backup paths"));
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
            route_kind(c, to.learned, to.statics)
        };
        if let Some(v) = first.iter().find_map(|p| p.other_vrf.as_ref()) {
            notes.push(format!(
                "route {prefix} in VRF {vrf}, {}",
                (to.other_vrf)(v)
            ));
            out.push((*prefix, Route::new(kind, Vec::new(), spans)));
            continue;
        }
        let paths: Vec<Path> = first
            .iter()
            .map(|p| Path {
                interface: p.interface.clone(),
                gateway: p.gateway,
                vrf: None,
            })
            .collect();
        let through = through_default(Origin::Collected, to.computed_through_default);
        match to.resolver.resolve(vrf, &paths, through) {
            Ok((found, more)) => {
                let hops = found
                    .iter()
                    .map(|h| hop(l, &h.interface, h.gateway))
                    .collect();
                let mut all = spans;
                all.extend(more);
                out.push((*prefix, Route::new(kind, hops, all)));
            }
            Err(u) => {
                notes.push(format!("route {prefix} in VRF {vrf}, {}", u.why));
                let mut all = spans;
                all.extend(u.spans);
                out.push((*prefix, Route::unknown(kind, u.reason, all)));
            }
        }
    }
    for (prefix, lines) in &unread {
        for u in lines {
            notes.push(format!(
                "route {prefix} in VRF {vrf}, {} not read: {}",
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
