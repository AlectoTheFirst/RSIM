//! Lowering of an IOS-XR running config and its collected sections into the
//! layer 3 function instances of a router: the interfaces with their VRFs,
//! the input and output ACLs, the QoS policies, the route table of each VRF
//! and the next-hop resolution through ARP.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{
    InterfaceId, NeighbourTarget, Prefix, PrefixTable, Rewrite, SourceSpan, TriePrefixTable, VrfId,
};
use rsim_engine::EdgeInterface;
use rsim_functions::{
    DeviceDelivery, Egress, EgressMode, Fib, Ingress, LocalInput, Neighbour, NextHopResolution,
    Route, RouteKind, RouteLookup, RouteNextHop, Tag, VendorProfile, VrfSelection,
};

use super::config::{Config, Interface};
use super::profile::{ALL_IPV4, CONNECTED_CODE, DEFAULT_VRF, LOCAL_CODE, UP_WITHOUT_SHUTDOWN};
use super::state::{self, Rib, RoutePath, Section, UnreadRoute};
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
}

impl Port {
    fn vrf(&self) -> &str {
        self.i.vrf.as_deref().unwrap_or(DEFAULT_VRF)
    }
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

/// Lowers the layer 3 part of one IOS-XR router. `sections` holds the text
/// sections of [`super::SECTIONS`], each with its file name.
pub fn lower(
    device: &str,
    file: &str,
    profile: &VendorProfile,
    cfg: &Config,
    sections: &BTreeMap<String, (Vec<u8>, String)>,
) -> Lowered {
    let st = state::read(sections, &super::names(cfg));
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
        });
    }
    cross_check(&mut l, cfg, &st);
    if active.is_empty() {
        return l.out;
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
    let mut tables = BTreeMap::new();
    for v in &vrfs {
        let t = fib(&mut l, v, &active, rib);
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
        next_hops(&mut l, &active, &st);
    }
    edges(&mut l, device, &active);
    l.out
}

/// The next hops through ARP, the output ACLs, the output QoS and egress.
fn next_hops(l: &mut L, active: &[Port], st: &state::State) {
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
        l.add(Egress {
            meta,
            interface: InterfaceId::new(&i.name),
            mode: EgressMode::Routed,
            link: None,
            rewrite: Rewrite::default(),
            tag: Tag::Keep,
        });
    }
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
/// local routes. Each IPv6 packet is unknown.
fn fib(l: &mut L, vrf: &str, active: &[Port], rib: Option<&Rib>) -> Fib {
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
