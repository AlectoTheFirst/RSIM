//! Lowering of an IOS-XE running config and its collected sections into the
//! function instances of a router or a Catalyst switch: the interfaces with
//! their VRFs, the input and output ACLs, the QoS policies, the NAT, the
//! route table of each VRF, the next-hop resolution through the ARP table of
//! the global table and of each VRF, the HSRP and VRRP groups, the hand-off
//! and the egress of each port with a link, and the switch ports, the VLANs,
//! the SVIs, the MAC table, the spanning tree state and the endpoints. The chain of an interface
//! is the chain of NX-OS: ingress, input QoS, input ACL, VRF selection,
//! session lookup, outside NAT, route lookup, inside NAT, session commit,
//! next-hop resolution, output ACL, output QoS and egress. Gives the summary
//! of the device for the link join too.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{InterfaceId, Mac, ObjectId, SourceSpan, VrfId};
use rsim_functions::{
    DestinationNat, DeviceDelivery, LinkEnd, LocalInput, RouteLookup, SessionCommit, SessionLookup,
    SourceNat, VendorProfile,
};

use super::config::{Config, Interface};
use super::profile::{
    DEFAULT_VRF, HSRP_ACTIVE, HSRP_NOT_ACTIVE, KEEPS_UNTRANSLATED_FLOWS, NO_LINK,
    UP_WITHOUT_SHUTDOWN, VRRP_MASTER, VRRP_NOT_MASTER,
};
use super::state::{self, State};
use crate::iosxr::lower::{
    Group, GroupRules, GroupState, Hops, Port, RouterPort, edges, error, fib, group_note,
    group_state, handoffs, inputs, next_hops, place_unreadable, routed_summary, vips,
};
use crate::iosxr::state::HsrpRow;
use crate::links::{External, Summary};
use crate::nxos;
use crate::nxos::config::{FhrpKind, Lines, NatRole};
use crate::nxos::lower::L;
use crate::vyos::Lowered;

/// The words of `show standby brief`.
const HSRP_RULES: GroupRules = GroupRules {
    what: "HSRP",
    command: "show standby brief",
    active: HSRP_ACTIVE,
    not_active: HSRP_NOT_ACTIVE,
    no_vmac: "no mac-address line, and show standby brief gives no virtual MAC",
};

/// The words of `show vrrp brief`.
const VRRP_RULES: GroupRules = GroupRules {
    what: "VRRP",
    command: "show vrrp brief",
    active: VRRP_MASTER,
    not_active: VRRP_NOT_MASTER,
    no_vmac: "show vrrp brief gives no virtual MAC",
};

/// The words of `show standby`.
const HSRP_DETAIL_RULES: GroupRules = GroupRules {
    what: "HSRP",
    command: "show standby",
    active: HSRP_ACTIVE,
    not_active: HSRP_NOT_ACTIVE,
    no_vmac: "no mac-address line, and show standby gives no virtual MAC",
};

/// The words of `show vrrp`.
const VRRP_DETAIL_RULES: GroupRules = GroupRules {
    what: "VRRP",
    command: "show vrrp",
    active: VRRP_MASTER,
    not_active: VRRP_NOT_MASTER,
    no_vmac: "show vrrp gives no virtual MAC",
};

/// The MACs of the interfaces of a router or a switch in `show interfaces`.
pub fn device_macs(cfg: &Config, sections: &BTreeMap<String, (Vec<u8>, String)>) -> BTreeSet<Mac> {
    let only: BTreeMap<String, (Vec<u8>, String)> = sections
        .iter()
        .filter(|(k, _)| k.as_str() == "interfaces")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    state::read(&only, &super::names(cfg))
        .l3
        .interfaces
        .and_then(Result::ok)
        .map(|m| m.values().filter_map(|s| s.mac).collect())
        .unwrap_or_default()
}

/// Lowers one IOS-XE router or switch. `sections` holds the text sections
/// of [`super::SECTIONS`], each with its file name. `ext` gives the links
/// from the estate. Gives the summary of the device for the estate too.
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
    let mut acls = cfg.acls.clone();
    for acl in acls.values_mut() {
        place_unreadable(acl);
    }
    let (vlans, unknown_vlans) = super::layer2::vlans(cfg, &st);
    let shared = nxos::Config {
        acls,
        nat_rules: cfg.nat_rules.clone(),
        nat_pools: cfg.nat_pools.clone(),
        interfaces: super::layer2::interfaces(cfg, &st),
        vlans,
        unknown_vlans,
        unreadable_vlans: cfg.unreadable_vlans.clone(),
        hostname: cfg.hostname.clone(),
        ..nxos::Config::default()
    };
    let mut l = L::new(device, file, profile, &shared);
    for (name, e) in [
        ("interfaces", error(&st.l3.interfaces)),
        ("rib", error(&st.l3.rib)),
        ("arp", error(&st.l3.arp)),
        ("acls", error(&st.acls)),
        ("lldp", error(&st.l3.lldp)),
        ("cdp", error(&st.l3.cdp)),
        ("hsrp", error(&st.l3.hsrp)),
        ("vrrp", error(&st.vrrp)),
        ("hsrp_detail", error(&st.hsrp_detail)),
        ("vrrp_detail", error(&st.vrrp_detail)),
        ("mac_table", error(&st.mac_table)),
        ("spanning_tree", error(&st.stp)),
        ("vlans", error(&st.vlans)),
        ("arp_vrfs", error(&st.arp_vrfs)),
    ] {
        if let Some(e) = e {
            l.note(format!("the section {name} is not read: {e}"));
        }
    }
    for (v, status) in super::layer2::inactive_vlans(cfg, &st) {
        l.note(format!(
            "VLAN {v}: show vlan brief gives the status {status}, so each port that carries it is unknown"
        ));
    }
    let active = ports(&mut l, cfg, &st);
    let groups = groups(&mut l, cfg, &st, &active, &names);
    let vips = vips(&groups, &active);
    cross_check_acls(&mut l, &shared, &st);
    cross_check_routes(&mut l, cfg, &st);

    // The summary: the switch ports from the layer 2 part, then the routed
    // ports.
    let mut sum = Summary::default();
    let states = st.l3.interfaces.as_ref().and_then(|x| x.as_ref().ok());
    for (name, s) in states.into_iter().flatten() {
        if s.speed_mbps.is_some() || s.full_duplex.is_some() {
            sum.facts.insert(
                name.clone(),
                LinkEnd {
                    speed_mbps: s.speed_mbps,
                    full_duplex: s.full_duplex,
                    media: None,
                    spans: vec![s.span.clone()],
                },
            );
        }
    }
    let mut svi_links = BTreeMap::new();
    if super::layer2::has_layer2(cfg) {
        let nst = super::layer2::switch_state(&st);
        let gws = super::layer2::gateways(&active, &groups, &st);
        let shared_active: Vec<nxos::config::Interface> =
            active.iter().map(|p| p.i.clone()).collect();
        svi_links = l.switch_layer2(
            &shared_active,
            &gws,
            &nst,
            &super::layer2::collected(&st),
            &names,
            ext,
            &mut sum,
        );
        for p in sum.ports.keys() {
            sum.entries.insert(p.clone(), l.id(&format!("port/{p}/in")));
            if let Some(s) = states.and_then(|m| m.get(p)) {
                if let Some(m) = s.mac {
                    sum.port_macs.insert(p.clone(), m);
                }
                sum.port_spans.insert(p.clone(), s.span.clone());
            }
        }
    }
    sum.names = names.clone();
    sum.host_name = cfg
        .hostname
        .as_deref()
        .and_then(nxos::state::neighbour_name);
    let channel = |n: u32| {
        let want = format!("port-channel{n}");
        cfg.interfaces
            .iter()
            .find(|i| i.name.eq_ignore_ascii_case(&want))
            .map_or_else(|| format!("Port-channel{n}"), |i| i.name.clone())
    };
    let router_ports: Vec<RouterPort> = cfg
        .interfaces
        .iter()
        .map(|i| RouterPort {
            name: &i.name,
            channel: i.channel_group.map(|(n, _)| channel(n)),
            shut: i.admin_up == Some(false),
        })
        .collect();
    routed_summary(&l, &mut sum, &router_ports, NO_LINK, &st.l3, &active);
    sum.next_hops.extend(
        cfg.static_routes
            .iter()
            .filter_map(|r| r.next_hop.as_deref()?.parse::<IpAddr>().ok()),
    );
    // The ARP rows of the global table and of each VRF whose table is read.
    let vrf_arp: Vec<&crate::iosxr::state::ArpRow> = st
        .arp_vrfs
        .iter()
        .flatten()
        .flat_map(|m| m.values())
        .flatten()
        .flatten()
        .collect();
    for a in st
        .l3
        .arp
        .iter()
        .flatten()
        .flatten()
        .chain(vrf_arp.iter().copied())
    {
        if let Some(v) = nxos::layer2::svi_vlan(&a.interface)
            && svi_links.contains_key(&a.interface)
        {
            sum.arp.push((v, a.ip, a.mac, a.span.clone()));
        }
    }
    if active.is_empty() {
        return (l.out, sum);
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
    // next hops of another VRF go to the next-hop resolution if the section
    // `arp_vrfs` gives its ARP table, else to `arp/<vrf>`, which gives
    // `Unknown`.
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
    let mut vrf_forwards = false;
    for v in &vrfs {
        let arp_of_vrf = vrf_arp_state(&st, v);
        let next = if v == DEFAULT_VRF {
            "snat".to_string()
        } else if arp_of_vrf.is_ok() {
            "nexthop".to_string()
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
            match arp_of_vrf {
                Ok(()) => vrf_forwards = true,
                Err(why) => {
                    let span = vrf_span(&l, cfg, rib, v);
                    let s = l.sink(
                        &next,
                        format!("{why}, so its next hops are not known"),
                        span,
                    );
                    l.add(s);
                }
            }
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
    }
    if forwards || vrf_forwards {
        // One next-hop resolution for the global table and the VRFs: an
        // ARP row names its interface, which is in one VRF.
        let mut l3 = st.l3.clone();
        let mut rows: Vec<crate::iosxr::state::ArpRow> =
            st.l3.arp.iter().flatten().flatten().cloned().collect();
        rows.extend(vrf_arp.iter().map(|a| (*a).clone()));
        l3.arp = Some(Ok(rows));
        next_hops(&mut l, &active, &l3, ext, &svi_links);
    }
    handoffs(&mut l, &active, &groups, &sum, ext);
    edges(&mut l, device, &active);
    (l.out, sum)
}

/// Whether the section `arp_vrfs` gives the ARP table of a VRF other than
/// the default VRF, or why it does not.
fn vrf_arp_state(st: &State, vrf: &str) -> Result<(), String> {
    match &st.arp_vrfs {
        None => Err(format!("the ARP table of VRF {vrf} is not collected")),
        Some(Err(e)) => Err(format!(
            "the section arp_vrfs is not read ({e}), so the ARP table of VRF {vrf} is not known"
        )),
        Some(Ok(m)) => match m.get(vrf) {
            None => Err(format!(
                "the section arp_vrfs has no ARP table of VRF {vrf}"
            )),
            Some(Err(e)) => Err(e.clone()),
            Some(Ok(_)) => Ok(()),
        },
    }
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

/// The layer 3 interfaces that are lowered. A layer 3 interface has an IPv4
/// address of the config, is not a switch port, is not shut and is not down
/// in `show interfaces`. A line of an interface that the lowering does not
/// model makes each packet in or out of it `Unknown`.
fn ports(l: &mut L, cfg: &Config, st: &State) -> Vec<Port> {
    let states = st.l3.interfaces.as_ref().and_then(|x| x.as_ref().ok());
    let mut active = Vec::new();
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
        active.push(Port {
            i: port(i, admin, cfg),
            state: s.map(|s| s.span.clone()),
            dot1q: i.dot1q.filter(|d| !d.1).map(|d| d.0),
            ipv6: i.ipv6.iter().map(|a| a.0.clone()).collect(),
            mac: s.and_then(|s| s.mac),
        });
    }
    active
}

/// The IPv4 HSRP and VRRP groups of the lowered interfaces with their state
/// from `show standby` and `show vrrp` when the template reads them, else
/// from `show standby brief` and `show vrrp brief`. The virtual MAC is the
/// MAC of
/// `standby <group> mac-address`, else the virtual MAC of `show standby` or
/// `show vrrp`; the brief forms give none. A virtual MAC of the section that
/// differs from the MAC of the config, and an HSRP state that contradicts
/// the active router of `show standby`, make the state `Unknown`.
fn groups(
    l: &mut L,
    cfg: &Config,
    st: &State,
    active: &[Port],
    names: &nxos::names::Names,
) -> Vec<Group> {
    let mut out = Vec::new();
    for i in &cfg.interfaces {
        let iface = names.resolve(&i.name);
        if !active.iter().any(|p| p.i.name == iface) {
            continue;
        }
        for g in &i.fhrp {
            let (brief_rules, detail_rules, brief, detail) = match g.kind {
                FhrpKind::Hsrp => (
                    &HSRP_RULES,
                    &HSRP_DETAIL_RULES,
                    &st.l3.hsrp,
                    &st.hsrp_detail,
                ),
                FhrpKind::Vrrp => (&VRRP_RULES, &VRRP_DETAIL_RULES, &st.vrrp, &st.vrrp_detail),
            };
            let detail_rows: Option<Result<Vec<HsrpRow>, String>> = detail.as_ref().map(|d| {
                d.as_ref()
                    .map(|v| v.iter().map(|x| x.row.clone()).collect())
                    .map_err(Clone::clone)
            });
            // The detail form decides when its template reads it; else the
            // brief form, if it is in the snapshot.
            let (rules, rows) = match (&detail_rows, brief) {
                (Some(Ok(_)), _) | (Some(Err(_)), None) => (detail_rules, &detail_rows),
                _ => (brief_rules, brief),
            };
            let mut spans = vec![l.span(g.lines)];
            spans.extend(g.addresses.iter().map(|(_, x)| l.span(*x)));
            let mut vmac = g.mac.map(|(m, x)| {
                spans.push(l.span(x));
                m
            });
            let mut state = group_state(
                g.group,
                g.addresses.first().map(|a| a.0),
                &g.unhandled,
                &iface,
                rows,
                rules,
                &mut spans,
            );
            let row = detail.iter().flatten().flatten().find(|x| {
                x.row.interface == iface
                    && x.row.group == g.group
                    && !x.row.address.is_some_and(|a| a.is_ipv6())
            });
            if let (Some(x), false) = (row, matches!(state, GroupState::Unknown(_))) {
                let cmd = rules.command;
                match (vmac, x.vmac) {
                    (None, Some(m)) => vmac = Some(m),
                    (Some(c), Some(m)) if c != m => {
                        state = GroupState::Unknown(format!(
                            "{cmd} gives the virtual MAC {m:?}, and the config gives {c:?}"
                        ));
                    }
                    _ => {}
                }
                match (&state, x.active_local) {
                    (GroupState::Active, Some(false)) => {
                        state = GroupState::Unknown(format!(
                            "{cmd} gives the state {} and another active router",
                            x.row.state
                        ));
                    }
                    (GroupState::NotActive, Some(true)) => {
                        state = GroupState::Unknown(format!(
                            "{cmd} gives the state {} and the router itself as the active router",
                            x.row.state
                        ));
                    }
                    _ => {}
                }
            }
            let group = Group {
                what: rules.what,
                group: g.group,
                addresses: g.addresses.iter().map(|a| a.0).collect(),
                interface: iface.clone(),
                state,
                vmac,
                spans,
            };
            group_note(l, &group, rules);
            out.push(group);
        }
    }
    out
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
