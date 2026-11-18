//! Lowering of an IOS-XE running config and its collected sections into the
//! layer 3 function instances of a router: the interfaces with their VRFs,
//! the input and output ACLs, the QoS policies, the NAT, the route table of
//! each VRF and the next-hop resolution through ARP. The chain of an
//! interface is the chain of NX-OS: ingress, input QoS, input ACL, VRF
//! selection, session lookup, outside NAT, route lookup, inside NAT, session
//! commit, next-hop resolution, output ACL, output QoS and egress.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{InterfaceId, ObjectId, SourceSpan, VrfId};
use rsim_functions::{
    DestinationNat, DeviceDelivery, LocalInput, RouteLookup, SessionCommit, SessionLookup,
    SourceNat, VendorProfile,
};

use super::config::{Config, Interface};
use super::profile::{DEFAULT_VRF, KEEPS_UNTRANSLATED_FLOWS, UP_WITHOUT_SHUTDOWN};
use super::state::{self, State};
use crate::iosxr::lower::{
    Hops, Port, Vip, edges, error, fib, inputs, next_hops, place_unreadable,
};
use crate::links::External;
use crate::nxos;
use crate::nxos::config::{FhrpKind, Lines, NatRole};
use crate::nxos::lower::L;
use crate::vyos::Lowered;

/// Lowers one IOS-XE router. `sections` holds the text sections of
/// [`super::SECTIONS`], each with its file name. `ext` gives the links from
/// the estate.
pub fn lower(
    device: &str,
    file: &str,
    profile: &VendorProfile,
    cfg: &Config,
    sections: &BTreeMap<String, (Vec<u8>, String)>,
    ext: &External,
) -> Lowered {
    let names = super::names(cfg);
    let st = state::read(sections, &names);
    let mut acls = cfg.acls.clone();
    for acl in acls.values_mut() {
        place_unreadable(acl);
    }
    let shared = nxos::Config {
        acls,
        nat_rules: cfg.nat_rules.clone(),
        nat_pools: cfg.nat_pools.clone(),
        ..nxos::Config::default()
    };
    let mut l = L::new(device, file, profile, &shared);
    for (name, e) in [
        ("interfaces", error(&st.l3.interfaces)),
        ("rib", error(&st.l3.rib)),
        ("arp", error(&st.l3.arp)),
        ("acls", error(&st.acls)),
    ] {
        if let Some(e) = e {
            l.note(format!("the section {name} is not read: {e}"));
        }
    }
    let (active, vips) = ports(&mut l, cfg, &st);
    cross_check_acls(&mut l, &shared, &st);
    cross_check_routes(&mut l, cfg, &st);
    if active.is_empty() {
        return l.out;
    }
    let nat_ifs = |role: NatRole| -> BTreeSet<InterfaceId> {
        active
            .iter()
            .filter(|p| p.vrf() == DEFAULT_VRF && p.i.nat.map(|n| n.0) == Some(role))
            .map(|p| InterfaceId::new(&p.i.name))
            .collect()
    };
    let inside = nat_ifs(NatRole::Inside);
    let outside = nat_ifs(NatRole::Outside);

    inputs(
        &mut l,
        &active,
        profile.default_vrf.clone(),
        "session-lookup",
    );
    let meta = l.meta("session-lookup", Vec::new());
    l.add(SessionLookup {
        meta,
        next: l.id("dnat"),
    });
    // The NAT of the outside to inside direction, before the route lookup.
    let (dnat, scopes) = l.destination_nat(&outside);
    let meta = l.meta("dnat", Vec::new());
    l.add(DestinationNat {
        meta,
        table: ObjectId::new(format!("{device}:nat:outside")),
        rules: dnat,
        ingress: scopes,
        next: l.id("route"),
    });

    // The route lookup in the table of each VRF. The next hops of the
    // default VRF go to the NAT of the inside to outside direction; the
    // next hops of another VRF need its ARP table, which is not collected.
    let rib = st.l3.rib.as_ref().and_then(|x| x.as_ref().ok());
    if st.l3.rib.is_none() {
        l.note(
            "no route table section, so each route lookup is unknown and the static routes of the config are not lowered"
                .into(),
        );
    }
    let mut vrfs: BTreeSet<String> = cfg.vrfs.keys().cloned().collect();
    vrfs.insert(DEFAULT_VRF.to_string());
    vrfs.extend(active.iter().map(|p| p.vrf().to_string()));
    if let Some(r) = rib {
        vrfs.extend(r.paths.iter().map(|p| p.vrf.clone()));
        vrfs.extend(r.unread.iter().filter_map(|u| u.vrf.clone()));
    }
    let other_vrf = |v: &str| format!("a next hop in VRF {v} is not lowered");
    let mut tables = BTreeMap::new();
    let mut forwards = false;
    for v in &vrfs {
        let next = if v == DEFAULT_VRF {
            "snat".to_string()
        } else {
            format!("arp/{v}")
        };
        let hops = Hops {
            next: &next,
            other_vrf: &other_vrf,
        };
        let t = fib(&mut l, v, &active, rib, &vips, &hops);
        let has_hops = t.groups().iter().any(|g| !g.next_hops.is_empty());
        if has_hops && v == DEFAULT_VRF {
            forwards = true;
        } else if has_hops {
            let span = vrf_span(&l, cfg, rib, v);
            let s = l.sink(
                &next,
                format!(
                    "the ARP table of VRF {v} is not collected, so its next hops are not known"
                ),
                span,
            );
            l.add(s);
        }
        tables.insert(VrfId::new(v), t);
    }
    l.note("IPv6 is not lowered: each IPv6 packet is unknown at the route lookup".into());
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
        // The NAT of the inside to outside direction, after the route
        // lookup, and the session of the reply.
        let shared_active: Vec<nxos::config::Interface> =
            active.iter().map(|p| p.i.clone()).collect();
        let snat = l.source_nat(&shared_active, &inside, &outside);
        let meta = l.meta("snat", Vec::new());
        l.add(SourceNat::with_scopes(
            meta,
            ObjectId::new(format!("{device}:nat:inside")),
            snat,
            l.id("session-commit"),
        ));
        let meta = l.meta("session-commit", Vec::new());
        l.add(SessionCommit {
            meta,
            next: l.id("nexthop"),
            keep_untranslated: KEEPS_UNTRANSLATED_FLOWS,
        });
        next_hops(&mut l, &active, &st.l3, ext);
    }
    edges(&mut l, device, &active);
    l.out
}

/// The span of a VRF: its stanza in the config, else its first route in the
/// route table section, else the first line of the config.
fn vrf_span(l: &L, cfg: &Config, rib: Option<&crate::iosxr::state::Rib>, vrf: &str) -> SourceSpan {
    if let Some(v) = cfg.vrfs.get(vrf) {
        return l.span(v.lines);
    }
    rib.and_then(|r| r.paths.iter().find(|p| p.vrf == vrf))
        .map_or_else(|| l.span(Lines { first: 1, last: 1 }), |p| p.span.clone())
}

/// The layer 3 interfaces that are lowered, and the virtual addresses of
/// their HSRP and VRRP groups. A layer 3 interface has an IPv4 address of
/// the config, is not a switch port, is not shut and is not down in
/// `show interfaces`. A line of an interface that the lowering does not
/// model makes each packet in or out of it `Unknown`.
fn ports(l: &mut L, cfg: &Config, st: &State) -> (Vec<Port>, Vec<Vip>) {
    let states = st.l3.interfaces.as_ref().and_then(|x| x.as_ref().ok());
    let mut active = Vec::new();
    let mut vips = Vec::new();
    for i in &cfg.interfaces {
        if i.switchport == Some(true) {
            continue;
        }
        let s = states.and_then(|m| m.get(&i.name));
        let admin = match i.admin_up {
            Some(up) => Some(up),
            None if UP_WITHOUT_SHUTDOWN => Some(true),
            None => None,
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
        if s.and_then(|s| s.oper_up) == Some(false) {
            continue;
        }
        if i.dynamic_address.is_some() {
            l.note(format!(
                "{}: an address that the config does not state is not lowered",
                i.name
            ));
        }
        if i.addresses.is_empty() {
            continue;
        }
        let p = port(i, admin, cfg);
        let vrf = p.vrf.clone().unwrap_or_else(|| DEFAULT_VRF.to_string());
        for g in &i.fhrp {
            let kind = match g.kind {
                FhrpKind::Hsrp => "HSRP",
                FhrpKind::Vrrp => "VRRP",
            };
            l.note(format!(
                "{}: {kind} group {}: the group state is not read, so the packets to its virtual addresses are unknown",
                i.name, g.group
            ));
            for (a, lines) in &g.addresses {
                vips.push(Vip {
                    vrf: vrf.clone(),
                    ip: IpAddr::V4(*a),
                    local: false,
                    spans: vec![l.span(g.lines), l.span(*lines)],
                });
            }
        }
        active.push(Port {
            i: p,
            state: s.map(|s| s.span.clone()),
            dot1q: i.dot1q.filter(|d| !d.1).map(|d| d.0),
            ipv6: i.ipv6.iter().map(|a| a.0.clone()).collect(),
            mac: s.and_then(|s| s.mac),
        });
    }
    (active, vips)
}

/// An interface in the form of the shared ACL and NAT functions. The lines
/// that the lowering does not model go to the unhandled lines: a NAT role
/// in a VRF, a VRF with no IPv4 or not in the config, a native VLAN of a
/// sub-interface, an admin state that is not known and `no ip routing`.
fn port(i: &Interface, admin: Option<bool>, cfg: &Config) -> nxos::config::Interface {
    let vrf = i.vrf.as_ref().map(|v| v.0.clone());
    let mut unhandled = i.unhandled.clone();
    if admin.is_none() {
        unhandled.push("the admin state is not known".into());
    }
    if let (Some((role, _)), Some(v)) = (i.nat, &vrf) {
        let r = match role {
            NatRole::Inside => "inside",
            NatRole::Outside => "outside",
        };
        unhandled.push(format!("ip nat {r} in VRF {v}"));
    }
    if let Some(v) = &vrf {
        match cfg.vrfs.get(v) {
            None => unhandled.push(format!("VRF {v} is not in the config")),
            Some(x) if x.ipv4.is_none() => {
                unhandled.push(format!("VRF {v} has no IPv4 address family"));
            }
            Some(_) => {}
        }
    }
    if i.dot1q.is_some_and(|d| d.1) {
        unhandled.push("encapsulation dot1Q native".into());
    }
    if cfg.ip_routing.as_ref().is_some_and(|r| !r.0) {
        unhandled.push("no ip routing".into());
    }
    nxos::config::Interface {
        name: i.name.clone(),
        admin_up: admin,
        vrf,
        addresses: i.addresses.clone(),
        acl_in: i.acl_in.clone(),
        acl_out: i.acl_out.clone(),
        nat: i.nat,
        qos_in: i.qos_in.clone(),
        qos_out: i.qos_out.clone(),
        unhandled,
        lines: i.lines,
        ..nxos::config::Interface::default()
    }
}

/// Compares the entries of `show ip access-lists` with the ACLs of the
/// config by their numbers and actions. Each difference gives a note; the
/// config decides.
fn cross_check_acls(l: &mut L, shared: &nxos::Config, st: &State) {
    let Some(Ok(lists)) = &st.acls else {
        return;
    };
    let entries = |acl: &nxos::config::Acl| -> BTreeSet<(u64, String)> {
        acl.entries
            .iter()
            .filter_map(|e| {
                let action = match e.action {
                    nxos::config::AclAction::Permit => "permit",
                    nxos::config::AclAction::Deny => "deny",
                };
                Some((e.seq.parse().ok()?, action.to_string()))
            })
            .collect()
    };
    let show = |set: &BTreeSet<(u64, String)>| {
        set.iter()
            .map(|(n, a)| format!("{n} {a}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    for (name, acl) in &shared.acls {
        match lists.get(name) {
            None => l.note(format!(
                "ACL {name}: show ip access-lists does not list it; the config decides"
            )),
            Some(list) => {
                let mine = entries(acl);
                if mine != list.entries {
                    l.note(format!(
                        "ACL {name}: show ip access-lists gives the entries {}, and the config gives {}; the config decides",
                        show(&list.entries),
                        show(&mine)
                    ));
                }
            }
        }
    }
    for name in lists.keys() {
        if !shared.acls.contains_key(name) {
            l.note(format!(
                "ACL {name}: show ip access-lists lists it, and the config has no such ACL"
            ));
        }
    }
}

/// Compares the VRFs and the static routes of the config with the route
/// table section. A VRF of the route table that the config does not have,
/// and a static route of the config with no static path of its prefix and
/// its next hop in the route table, give a note.
fn cross_check_routes(l: &mut L, cfg: &Config, st: &State) {
    let Some(Ok(rib)) = &st.l3.rib else {
        return;
    };
    let listed: BTreeSet<&str> = rib.paths.iter().map(|p| p.vrf.as_str()).collect();
    for v in listed {
        if v != DEFAULT_VRF && !cfg.vrfs.contains_key(v) {
            l.note(format!(
                "VRF {v} is in the route table section, and the config has no such VRF"
            ));
        }
    }
    for r in &cfg.static_routes {
        let Ok(prefix) = r.prefix.parse::<rsim_core::Prefix>() else {
            continue;
        };
        let gateway = r.next_hop.as_deref().and_then(|g| g.parse::<IpAddr>().ok());
        let installed = rib.paths.iter().any(|p| {
            p.vrf == r.vrf
                && p.prefix == prefix
                && p.protocol.starts_with('S')
                && (gateway.is_none() || p.gateway == gateway)
        });
        if !installed {
            let via = r
                .next_hop
                .as_deref()
                .or(r.interface.as_deref())
                .unwrap_or_default();
            l.note(format!(
                "static route {} via {via} in VRF {}: the route table has no such static path",
                r.prefix, r.vrf
            ));
        }
    }
}
