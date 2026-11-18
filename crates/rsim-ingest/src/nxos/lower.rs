//! Lowering of an NX-OS running config and its collected state into the
//! function instances of a switch.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use rsim_core::{
    AddrCond, FieldValue, FunctionId, InterfaceId, Match, NeighbourTarget, NetFunction, ObjectId,
    PortCond, Prefix, PrefixTable, Rewrite, RulePredicate, SourceSpan, TriePrefixTable, ValueCond,
    VrfId,
};
use rsim_engine::EdgeInterface;
use rsim_functions::{
    AclMatch, DestinationNat, DeviceDelivery, Egress, EgressMode, Fib, Ingress, Link, LocalInput,
    Meta, NatAction, NatScope, Neighbour, NextHopResolution, PortTranslation, QosNotEvaluated,
    Route, RouteKind, RouteLookup, RouteNextHop, Rule as FRule, RuleAction, SessionCommit,
    SessionLookup, SourceNat, StateActions, Tag, VendorProfile, VrfSelection,
};

use super::config::{
    AclAction, AddrSpec, Config, Interface, Lines, NatKind, NatRole, NatTarget, PortSpec,
};
use super::names::Names;
use crate::collected::Collected;
use crate::links::{External, Summary};
use crate::resolve::{Origin, Path, Resolver, Target, through_default};
use crate::route_tables::{TABLE_NOT_COLLECTED, route_kind};
use crate::vyos::Lowered;

/// The VRF of an interface with no `vrf member`.
pub(super) const DEFAULT_VRF: &str = "default";

/// The VXLAN facts that the FIB build reads: the VXLAN paths of the route
/// table, the tunnel end and its layer 3 encapsulation.
pub(super) struct Vx<'a> {
    pub st: &'a super::state::State,
    pub tunnel: &'a super::vxlan::Plan,
    pub encap: Option<&'a FunctionId>,
    /// The collected routes of each VRF, for the resolution of a next hop
    /// with no interface.
    pub resolver: &'a Resolver,
}

/// The lowering of one device: its name, the file of its config, its
/// profile, the typed config that the ACL functions read, and the functions
/// and notes so far.
pub(crate) struct L<'a> {
    pub(crate) dev: &'a str,
    file: &'a str,
    profile: &'a VendorProfile,
    pub(super) cfg: &'a Config,
    pub(crate) out: Lowered,
}

impl<'a> L<'a> {
    pub(crate) fn new(
        dev: &'a str,
        file: &'a str,
        profile: &'a VendorProfile,
        cfg: &'a Config,
    ) -> L<'a> {
        L {
            dev,
            file,
            profile,
            cfg,
            out: Lowered::default(),
        }
    }
    pub(crate) fn id(&self, f: &str) -> FunctionId {
        FunctionId::new(format!("{}/{f}", self.dev))
    }
    pub(super) fn file_name(&self) -> &str {
        self.file
    }
    pub(crate) fn span(&self, l: Lines) -> SourceSpan {
        SourceSpan::new(self.file, l.first.max(1), l.last.max(l.first).max(1))
    }
    pub(crate) fn meta(&self, f: &str, spans: Vec<SourceSpan>) -> Meta {
        let mut m = Meta::new(self.id(f), self.dev, self.profile);
        m.provenance = spans;
        m
    }
    pub(crate) fn add(&mut self, f: impl NetFunction + 'static) {
        self.out.functions.push(Arc::new(f));
    }
    pub(crate) fn note(&mut self, s: String) {
        self.out.notes.push(s);
    }
}

fn vrf_of(i: &Interface) -> &str {
    i.vrf.as_deref().unwrap_or(DEFAULT_VRF)
}

/// An interface address: the address and the prefix length.
pub(crate) fn iface_addr(s: &str) -> Option<(IpAddr, u8)> {
    let (a, l) = s.split_once('/')?;
    Some((a.parse().ok()?, l.parse().ok()?))
}

/// Lowers one NX-OS switch. `sections` holds the JSON sections of
/// [`super::SECTIONS`], each with its file name. `ext` gives the links and
/// the endpoints from the estate. Gives the summary of the switch for the
/// estate too.
pub fn lower(
    device: &str,
    file: &str,
    profile: &VendorProfile,
    cfg: &Config,
    col: &Collected,
    sections: &BTreeMap<String, (Vec<u8>, String)>,
    ext: &External,
) -> (Lowered, Summary) {
    let mut sum = Summary::default();
    let mut l = L {
        dev: device,
        file,
        profile,
        cfg,
        out: Lowered::default(),
    };
    let names = Names::new(cfg.interfaces.iter().map(|i| i.name.as_str()));
    let mut st = super::state::read(sections, &names);
    st.no_mac_table = !super::state::mac_table_collected(sections, !col.macs.is_empty());
    let mut active: Vec<Interface> = Vec::new();
    for i in &cfg.interfaces {
        let collected = st.interfaces.get(&i.name);
        let admin = i.admin_up.or(collected.and_then(|s| s.admin_up));
        let oper = collected.and_then(|s| s.oper_up);
        if admin == Some(false)
            || oper == Some(false)
            || (i.addresses.is_empty() && !i.dynamic_address && !i.ip_forward)
        {
            continue;
        }
        let mut i = i.clone();
        let lower_name = i.name.to_ascii_lowercase();
        if admin.is_none() && !lower_name.starts_with("loopback") && !lower_name.starts_with("mgmt")
        {
            i.unhandled.push(
                "no shutdown line and no collected state, so the admin state is not known".into(),
            );
        }
        if i.dynamic_address {
            l.note(format!(
                "{}: an address that the config does not state is not lowered",
                i.name
            ));
        }
        if let Some((role, _)) = i.nat
            && vrf_of(&i) != DEFAULT_VRF
        {
            let r = match role {
                NatRole::Inside => "inside",
                NatRole::Outside => "outside",
            };
            i.unhandled
                .push(format!("ip nat {r} in VRF {}", vrf_of(&i)));
        }
        if i.acl_out.is_some() && i.nat.is_some() {
            i.unhandled
                .push("ip access-group out on an interface with a NAT role".into());
        }
        active.push(i);
    }
    let nat_ifs = |role: NatRole| -> BTreeSet<InterfaceId> {
        active
            .iter()
            .filter(|i| vrf_of(i) == DEFAULT_VRF && i.nat.map(|n| n.0) == Some(role))
            .map(|i| InterfaceId::new(&i.name))
            .collect()
    };
    let gws = l.gateways(&active, &st, col, &names, super::layer2::vpc_ok(cfg, &st));
    let tunnel = super::vxlan::plan(cfg, &st, &active, &mut l);
    let svi_links = l.layer2(&active, &gws, &st, col, &names, ext, &tunnel, &mut sum);
    // The routed ports that can end a link: a physical port or a port
    // channel with a collected MAC.
    sum.routed = active
        .iter()
        .filter(|i| {
            let n = i.name.to_ascii_lowercase();
            (n.starts_with("ethernet") || n.starts_with("port-channel"))
                && gws.get(&i.name).is_some_and(|g| g.svi_mac.is_some())
        })
        .map(|i| i.name.clone())
        .collect();
    // The entry function and the MAC of each port that can end a link.
    for p in sum.ports.keys() {
        sum.entries.insert(p.clone(), l.id(&format!("port/{p}/in")));
    }
    for p in &sum.routed {
        sum.entries.insert(p.clone(), l.id(&format!("handoff/{p}")));
    }
    for r in &col.links {
        let p = names.resolve(&r.interface);
        if sum.entries.contains_key(&p)
            && let Some(m) = r.mac.as_deref().and_then(super::state::mac)
        {
            sum.port_macs.insert(p, m);
        }
    }
    // A switch with no layer 3 interface has no layer 3 chain.
    if active.is_empty() {
        return (l.out, sum);
    }
    let inside = nat_ifs(NatRole::Inside);
    let outside = nat_ifs(NatRole::Outside);

    // Ingress and the input ACLs.
    for i in &active {
        let filtered = i.acl_in.is_some() || !i.unhandled.is_empty();
        let after_qos = if filtered {
            format!("acl-in/{}", i.name)
        } else {
            "vrf".to_string()
        };
        let span = l.span(i.lines);
        let meta = l.meta(&format!("in/{}", i.name), vec![span]);
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
    let vrf_meta = l.meta("vrf", Vec::new());
    l.add(VrfSelection {
        meta: vrf_meta,
        by_interface: active
            .iter()
            .map(|i| (InterfaceId::new(&i.name), VrfId::new(vrf_of(i))))
            .collect(),
        default_vrf: profile.default_vrf.clone(),
        next: l.id("session-lookup"),
    });
    let meta = l.meta("session-lookup", Vec::new());
    l.add(SessionLookup {
        meta,
        next: l.id("dnat"),
        states: StateActions::default(),
    });

    // The multicast routes, before the unicast route lookup.
    let vpc = super::layer2::vpc_ok(cfg, &st);
    let mcast = l.mcast(&st, &tunnel, &active, vpc);
    if let Some(m) = &mcast {
        let meta = l.meta("mroute", Vec::new());
        l.add(rsim_functions::MulticastLookup {
            meta,
            routes: m.received.clone(),
            unicast: Some(l.id("route")),
            rpf_interface: None,
            unknown: m.unknown.clone(),
        });
    }

    // NAT in the outside to inside direction, before the route lookup.
    let (dnat, dnat_scopes) = l.destination_nat(&outside);
    let meta = l.meta("dnat", Vec::new());
    l.add(DestinationNat {
        meta,
        table: ObjectId::new(format!("{device}:nat:outside")),
        rules: dnat,
        ingress: dnat_scopes,
        next: l.id(if mcast.is_some() { "mroute" } else { "route" }),
    });

    // The route lookup in the FIB of each VRF.
    let mut vrfs: BTreeSet<String> = cfg.vrfs.keys().cloned().collect();
    vrfs.insert(DEFAULT_VRF.to_string());
    vrfs.extend(active.iter().map(|i| vrf_of(i).to_string()));
    let encap_l3 = l.vxlan_encap_l3(&tunnel);
    let resolver = resolver(col, &names, &st);
    let vx = Vx {
        st: &st,
        tunnel: &tunnel,
        encap: encap_l3.as_ref(),
        resolver: &resolver,
    };
    let mut tables = BTreeMap::new();
    for v in &vrfs {
        let vips: Vec<(IpAddr, Vec<SourceSpan>)> = active
            .iter()
            .filter(|i| vrf_of(i) == v.as_str())
            .filter_map(|i| gws.get(&i.name))
            .flat_map(|g| g.active.iter().map(|(_, a, s)| (*a, s.clone())))
            .collect();
        let fib = l.fib(v, &active, col, &names, &vips, "snat", &vx);
        tables.insert(VrfId::new(v), fib);
    }
    l.note("IPv6 is not lowered: each IPv6 packet is unknown at the route lookup".into());
    let dev = l.dev;
    let bd = move |v: u16| super::layer2::bd_of(dev, v);
    let local = l
        .vxlan_decap(&tunnel, "local", &bd)
        .unwrap_or_else(|| l.id("local"));
    let meta = l.meta("route", Vec::new());
    l.add(RouteLookup {
        meta,
        tables,
        fallback: None,
        local: Some(local.clone()),
    });
    // The underlay lookup exists when a function sends packets to it.
    let entry = l.id(super::profile::VXLAN_ENTRY);
    let encapsulates = l
        .out
        .functions
        .iter()
        .any(|f| f.successors().contains(&entry));
    if encapsulates {
        let fib = l.fib(DEFAULT_VRF, &active, col, &names, &[], "vxlan/nexthop", &vx);
        let meta = l.meta(super::profile::VXLAN_ENTRY, Vec::new());
        l.add(RouteLookup {
            meta,
            tables: [(VrfId::new(DEFAULT_VRF), fib)].into_iter().collect(),
            fallback: None,
            local: Some(local),
        });
    }
    // The multicast lookup of a flood copy that the tunnel end sends to a
    // group: the reverse path check takes the source interface.
    let mroute_id = l.id("vxlan/mroute");
    let sends_to_group = l
        .out
        .functions
        .iter()
        .any(|f| f.successors().contains(&mroute_id));
    if let (true, super::vxlan::Plan::Exact(t)) = (sends_to_group, &tunnel) {
        let meta = l.meta("vxlan/mroute", t.spans.clone());
        let (routes, unknown) = match &mcast {
            Some(m) => (m.sent.clone(), m.unknown.clone()),
            None => (
                BTreeMap::new(),
                Some("no multicast route section".to_string()),
            ),
        };
        l.add(rsim_functions::MulticastLookup {
            meta,
            routes,
            unicast: None,
            rpf_interface: Some(InterfaceId::new(&t.source_if)),
            unknown,
        });
    }
    let meta = l.meta("local", Vec::new());
    l.add(LocalInput {
        meta,
        zone: None,
        next: l.id("deliver"),
    });
    let meta = l.meta("deliver", Vec::new());
    l.add(DeviceDelivery { meta });

    // NAT in the inside to outside direction, after the route lookup.
    let snat = l.source_nat(&active, &inside, &outside);
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
        keep_untranslated: super::profile::KEEPS_UNTRANSLATED_FLOWS,
    });

    // Next hops, the output ACLs and egress.
    let mut neighbours: TriePrefixTable<Vec<Neighbour>> = TriePrefixTable::new();
    for n in &col.neighbours {
        let Ok(ip) = n.ip.parse::<IpAddr>() else {
            continue;
        };
        let Some(mac) = n.mac.as_deref().and_then(|m| m.parse().ok()) else {
            continue;
        };
        let p = Prefix::host(ip);
        let mut v = neighbours.get(&p).cloned().unwrap_or_default();
        v.push(Neighbour {
            interface: InterfaceId::new(names.resolve(&n.interface)),
            target: NeighbourTarget::Link,
            owner: n.mac.clone().unwrap_or_default(),
            mac: Some(mac),
            spans: vec![n.span.clone()],
        });
        neighbours.insert(p, v);
    }
    let filtered_out = |i: &Interface| i.acl_out.is_some() || !i.unhandled.is_empty();
    // The next hops of the outer header of a VXLAN packet: no source states
    // whether an output ACL of the egress applies to it, so such an egress
    // gives Unknown.
    if encapsulates {
        let mut egress = BTreeMap::new();
        for i in &active {
            let f = if filtered_out(i) {
                let f = format!("vxlan/acl-out/{}", i.name);
                let s = l.sink(
                    &f,
                    format!(
                        "{}: an output ACL or a line that is not lowered on the egress of a VXLAN packet",
                        i.name
                    ),
                    l.span(i.lines),
                );
                l.add(s);
                f
            } else if i.qos_out.is_some() {
                format!("qos-out/{}", i.name)
            } else {
                format!("out/{}", i.name)
            };
            egress.insert(InterfaceId::new(&i.name), l.id(&f));
        }
        let meta = l.meta("vxlan/nexthop", Vec::new());
        l.add(NextHopResolution {
            meta,
            neighbours: neighbours.clone(),
            complete: false,
            egress,
            point_to_point: BTreeMap::new(),
        });
    }
    let meta = l.meta("nexthop", Vec::new());
    l.add(NextHopResolution {
        meta,
        neighbours,
        complete: false,
        egress: active
            .iter()
            .map(|i| {
                let f = if filtered_out(i) {
                    format!("acl-out/{}", i.name)
                } else if i.qos_out.is_some() {
                    format!("qos-out/{}", i.name)
                } else {
                    format!("out/{}", i.name)
                };
                (InterfaceId::new(&i.name), l.id(&f))
            })
            .chain(match (&tunnel, &encap_l3) {
                (super::vxlan::Plan::Exact(t), Some(e)) => {
                    Some((InterfaceId::new(&t.nve), e.clone()))
                }
                _ => None,
            })
            .collect(),
        point_to_point: match (&tunnel, &encap_l3) {
            (super::vxlan::Plan::Exact(t), Some(_)) => {
                BTreeMap::from([(InterfaceId::new(&t.nve), "the peer tunnel end".to_string())])
            }
            _ => BTreeMap::new(),
        },
    });
    for i in &active {
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
        let span = l.span(i.lines);
        let meta = l.meta(&format!("out/{}", i.name), vec![span]);
        // The routed egress of an SVI goes into its VLAN through the SVI
        // port, with the MAC of the SVI as the source MAC. A routed port with
        // a link goes to the far end.
        let routed_peers = ext
            .peers
            .get(&i.name)
            .filter(|_| sum.routed.contains(&i.name));
        let routed_peer = routed_peers
            .and_then(|list| match list.as_slice() {
                [p] => Some(p),
                _ => None,
            })
            .and_then(|p| {
                let m = gws.get(&i.name)?.svi_mac.as_ref()?.0;
                Some((p, m))
            });
        let target = svi_links
            .get(&i.name)
            .map(|(peer, m)| (peer.clone(), *m, Vec::new(), None))
            .or_else(|| {
                routed_peer.map(|(p, m)| {
                    (
                        p.target.clone(),
                        m,
                        p.provenance.clone(),
                        Some(rsim_functions::LinkFacts {
                            local: sum.facts.get(&i.name).cloned().unwrap_or_default(),
                            remote: p.remote.clone(),
                        }),
                    )
                })
            });
        let (link, rewrite, tag) = match target {
            Some((peer, m, provenance, facts)) => (
                Some(Link {
                    peer: Some(peer),
                    delay_ns: None,
                    provenance,
                    facts,
                }),
                Rewrite {
                    src_mac: Some(FieldValue::Known(m)),
                    ..Rewrite::default()
                },
                Tag::Untagged,
            ),
            None => (None, Rewrite::default(), Tag::Keep),
        };
        // The hand-off of a routed port with one or more links: its MAC and
        // the active virtual MACs go to its ingress.
        if routed_peers.is_some_and(|list| !list.is_empty()) {
            let g = gws.get(&i.name).cloned().unwrap_or_default();
            let f = format!("handoff/{}", i.name);
            let span = l.span(i.lines);
            match (&g.unknown, &g.svi_mac) {
                (None, Some((m, mspan))) => {
                    let mut spans = vec![span, mspan.clone()];
                    spans.extend(g.active.iter().flat_map(|a| a.2.clone()));
                    let meta = l.meta(&f, spans);
                    l.add(rsim_functions::Layer3HandOff {
                        meta,
                        macs: std::iter::once(*m)
                            .chain(g.active.iter().map(|a| a.0))
                            .chain(mcast.iter().flat_map(|x| x.macs.iter().copied()))
                            .collect(),
                        untagged: Some(l.id(&format!("in/{}", i.name))),
                        tagged: BTreeMap::new(),
                    });
                }
                (why, _) => {
                    let why = why.clone().unwrap_or_else(|| "no collected MAC".into());
                    let s = l.sink(&f, format!("{}: {why}", i.name), span);
                    l.add(s);
                }
            }
        }
        if mcast.as_ref().is_some_and(|m| m.oifs.contains(&i.name)) {
            let meta = l.meta(&format!("mcast/out/{}", i.name), vec![l.span(i.lines)]);
            l.add(Egress {
                meta,
                interface: InterfaceId::new(&i.name),
                mode: EgressMode::Transparent,
                link: link.clone(),
                rewrite: rewrite.clone(),
                tag,
            });
        }
        l.add(Egress {
            meta,
            interface: InterfaceId::new(&i.name),
            mode: EgressMode::Routed,
            link: link.clone(),
            rewrite: rewrite.clone(),
            tag,
        });
    }

    // Edge interfaces: each interface with a connected network.
    for i in &active {
        let nets: Vec<Prefix> = i
            .addresses
            .iter()
            .filter_map(|a| iface_addr(&a.prefix))
            .filter(|(_, len)| *len < 32)
            .map(|(a, len)| Prefix::new(a, len))
            .collect();
        if !nets.is_empty() {
            l.out.edges.push(EdgeInterface {
                device: device.into(),
                interface: InterfaceId::new(&i.name),
                networks: nets,
                provenance: vec![l.span(i.lines)],
            });
        }
    }
    (l.out, sum)
}

/// The protocol number of a protocol of an ACL entry, or `None` for all
/// IPv4 protocols.
fn protocol_number(p: &str) -> Result<Option<u8>, String> {
    let n = match p {
        "ip" => return Ok(None),
        "icmp" => 1,
        "igmp" => 2,
        "tcp" => 6,
        "udp" => 17,
        "gre" => 47,
        "esp" => 50,
        "ahp" => 51,
        "eigrp" => 88,
        "ospf" => 89,
        "nos" => 94,
        "pim" => 103,
        "pcp" => 108,
        "sctp" => 132,
        other => {
            return other
                .parse()
                .map(Some)
                .map_err(|_| format!("protocol {other}"));
        }
    };
    Ok(Some(n))
}

/// The number of a port name of an NX-OS ACL entry.
pub fn port_number(name: &str) -> Option<u16> {
    let n = match name {
        "bgp" => 179,
        "biff" => 512,
        "bootpc" => 68,
        "bootps" => 67,
        "chargen" => 19,
        "cmd" => 514,
        "daytime" => 13,
        "discard" => 9,
        "dnsix" => 195,
        "domain" => 53,
        "drip" => 3949,
        "echo" => 7,
        "exec" => 512,
        "finger" => 79,
        "ftp" => 21,
        "ftp-data" => 20,
        "gopher" => 70,
        "hostname" => 101,
        "ident" => 113,
        "irc" => 194,
        "isakmp" => 500,
        "klogin" => 543,
        "kshell" => 544,
        "login" => 513,
        "lpd" => 515,
        "mobile-ip" => 434,
        "nameserver" => 42,
        "netbios-dgm" => 138,
        "netbios-ns" => 137,
        "netbios-ss" => 139,
        "nntp" => 119,
        "non500-isakmp" => 4500,
        "ntp" => 123,
        "pim-auto-rp" => 496,
        "pop2" => 109,
        "pop3" => 110,
        "rip" => 520,
        "smtp" => 25,
        "snmp" => 161,
        "snmptrap" => 162,
        "sunrpc" => 111,
        "syslog" => 514,
        "tacacs" => 49,
        "talk" => 517,
        "telnet" => 23,
        "tftp" => 69,
        "time" => 37,
        "uucp" => 540,
        "who" => 513,
        "whois" => 43,
        "www" => 80,
        "xdmcp" => 177,
        _ => return None,
    };
    Some(n)
}

/// The ICMP type and the code of an ICMP name of an NX-OS ACL entry, or of
/// a type number.
pub fn icmp_type(name: &str) -> Option<(u8, Option<u8>)> {
    if let Ok(n) = name.parse::<u8>() {
        return Some((n, None));
    }
    let t = match name {
        "echo-reply" => (0, None),
        "unreachable" => (3, None),
        "net-unreachable" => (3, Some(0)),
        "host-unreachable" => (3, Some(1)),
        "protocol-unreachable" => (3, Some(2)),
        "port-unreachable" => (3, Some(3)),
        "packet-too-big" => (3, Some(4)),
        "source-quench" => (4, None),
        "redirect" => (5, None),
        "alternate-address" => (6, None),
        "echo" => (8, None),
        "router-advertisement" => (9, None),
        "router-solicitation" => (10, None),
        "time-exceeded" => (11, None),
        "ttl-exceeded" => (11, Some(0)),
        "parameter-problem" => (12, None),
        "timestamp-request" => (13, None),
        "timestamp-reply" => (14, None),
        "information-request" => (15, None),
        "information-reply" => (16, None),
        "mask-request" => (17, None),
        "mask-reply" => (18, None),
        "traceroute" => (30, None),
        "conversion-error" => (31, None),
        "mobile-redirect" => (32, None),
        _ => return None,
    };
    Some(t)
}

/// A port as a number.
fn port(p: &str) -> Result<u16, String> {
    p.parse::<u16>()
        .ok()
        .or_else(|| port_number(p))
        .ok_or_else(|| format!("port {p}"))
}

/// A match of all IPv4 packets.
fn ipv4() -> Match {
    Match {
        src_ip: AddrCond::In(vec!["0.0.0.0/0".parse().expect("a valid prefix")]),
        ..Match::any()
    }
}

/// A match of all IPv6 packets.
fn ipv6() -> Match {
    Match {
        src_ip: AddrCond::In(vec!["::/0".parse().expect("a valid prefix")]),
        ..Match::any()
    }
}

/// The prefix of an address with a wildcard mask, if the mask is
/// contiguous.
fn wildcard_prefix(addr: &str, wildcard: &str) -> Option<Prefix> {
    let w: std::net::Ipv4Addr = wildcard.parse().ok()?;
    let inv = !u32::from(w);
    let len = super::config::mask_len(&std::net::Ipv4Addr::from(inv).to_string())?;
    format!("{addr}/{len}").parse().ok()
}

impl L<'_> {
    /// The prefixes of an address of an ACL entry, or `None` for any
    /// address.
    fn addr(&self, a: &AddrSpec, depth: u8) -> Result<Option<Vec<Prefix>>, String> {
        match a {
            AddrSpec::Any => Ok(None),
            AddrSpec::Prefix(p) => p
                .parse::<Prefix>()
                .map(|p| Some(vec![p]))
                .map_err(|_| format!("address {p}")),
            AddrSpec::Wildcard(a, w) => wildcard_prefix(a, w)
                .map(|p| Some(vec![p]))
                .ok_or_else(|| format!("wildcard {a} {w}")),
            AddrSpec::Group(g) => {
                let members = self
                    .cfg
                    .address_groups
                    .get(g)
                    .filter(|_| depth == 0)
                    .ok_or_else(|| format!("address group {g}"))?;
                let mut out = Vec::new();
                for m in members {
                    match self.addr(m, depth + 1)? {
                        Some(v) => out.extend(v),
                        None => return Ok(None),
                    }
                }
                Ok(Some(out))
            }
        }
    }

    /// The port ranges of a port condition of an ACL entry, or `None` for
    /// any port.
    fn ports(&self, p: &PortSpec, depth: u8) -> Result<Option<Vec<(u16, u16)>>, String> {
        let v = match p {
            PortSpec::Any => return Ok(None),
            PortSpec::Eq(list) => {
                let mut v = Vec::new();
                for x in list {
                    let n = port(x)?;
                    v.push((n, n));
                }
                v
            }
            PortSpec::Neq(x) => {
                let n = port(x)?;
                let mut v = Vec::new();
                if n > 0 {
                    v.push((0, n - 1));
                }
                if n < u16::MAX {
                    v.push((n + 1, u16::MAX));
                }
                v
            }
            PortSpec::Lt(x) => {
                let n = port(x)?;
                if n == 0 { Vec::new() } else { vec![(0, n - 1)] }
            }
            PortSpec::Gt(x) => {
                let n = port(x)?;
                if n == u16::MAX {
                    Vec::new()
                } else {
                    vec![(n + 1, u16::MAX)]
                }
            }
            PortSpec::Range(a, b) => {
                let (a, b) = (port(a)?, port(b)?);
                vec![(a.min(b), a.max(b))]
            }
            PortSpec::Group(g) => {
                let members = self
                    .cfg
                    .port_groups
                    .get(g)
                    .filter(|_| depth == 0)
                    .ok_or_else(|| format!("port group {g}"))?;
                let mut v = Vec::new();
                for m in members {
                    match self.ports(m, depth + 1)? {
                        Some(x) => v.extend(x),
                        None => return Ok(None),
                    }
                }
                v
            }
        };
        Ok(Some(v))
    }

    /// The predicate of an ACL entry. A part that cannot be lowered gives
    /// match bounds: the entry matches nothing for certain, and at most the
    /// packets of its other parts.
    fn ace_predicate(&mut self, e: &super::config::Ace, name: &str) -> RulePredicate {
        let mut problems: Vec<String> = e.unhandled.clone();
        let mut upper = ipv4();
        match protocol_number(&e.protocol) {
            Ok(Some(n)) => upper.protocol = ValueCond::one(n),
            Ok(None) => {}
            Err(x) => problems.push(x),
        }
        for (side, target) in [(&e.source, 0), (&e.destination, 1)] {
            match self.addr(side, 0) {
                Ok(Some(v)) if target == 0 => upper.src_ip = AddrCond::In(v),
                Ok(Some(v)) => upper.dst_ip = AddrCond::In(v),
                Ok(None) => {}
                Err(x) => problems.push(x),
            }
        }
        for (side, target) in [(&e.source_port, 0), (&e.destination_port, 1)] {
            match self.ports(side, 0) {
                Ok(Some(v)) if target == 0 => upper.src_port = PortCond::In(v),
                Ok(Some(v)) => upper.dst_port = PortCond::In(v),
                Ok(None) => {}
                Err(x) => problems.push(x),
            }
        }
        if let Some((t, code)) = &e.icmp {
            match icmp_type(t) {
                Some((ty, c)) => {
                    upper.icmp_type = ValueCond::one(ty);
                    let c = code.as_deref().and_then(|x| x.parse::<u8>().ok()).or(c);
                    if let Some(c) = c {
                        upper.icmp_code = ValueCond::one(c);
                    }
                }
                None => problems.push(format!("icmp {t}")),
            }
        }
        if e.established {
            problems.push("established".into());
        }
        if problems.is_empty() {
            RulePredicate::exact(upper)
        } else {
            self.note(format!("{name}: match bounds for {}", problems.join(", ")));
            let nothing = Match {
                src_ip: AddrCond::In(Vec::new()),
                ..Match::any()
            };
            RulePredicate::bounded(nothing, upper)
        }
    }

    /// The rules of an IP ACL, without its implicit rules. An ACL that the
    /// config does not have or that has no entry, or a line that the handler
    /// cannot read, gives an unhandled rule. With no `deny` action, each deny
    /// entry is an unhandled rule.
    fn acl_rules<A: Clone>(
        &mut self,
        name: &str,
        bind: Lines,
        permit: A,
        deny: Option<A>,
    ) -> Vec<FRule<A>> {
        let Some(acl) = self.cfg.acls.get(name).cloned() else {
            let msg = format!("ACL {name} does not exist");
            self.note(msg.clone());
            return vec![FRule::unhandled(msg, self.span(bind))];
        };
        let mut out = Vec::new();
        if acl.entries.is_empty() && acl.unreadable.is_empty() {
            let msg = format!("ACL {name} has no entry");
            self.note(msg.clone());
            return vec![FRule::unhandled(msg, self.span(acl.lines))];
        }
        if !acl.unreadable.is_empty() {
            let msg = format!("ACL {name}: lines not read: {}", acl.unreadable.join(", "));
            self.note(msg.clone());
            out.push(FRule::unhandled(msg, self.span(acl.lines)));
        }
        for e in &acl.entries {
            let rname = format!("{name}/{}", e.seq);
            let p = self.ace_predicate(e, &rname);
            let span = self.span(e.lines);
            let action = match (e.action, &deny) {
                (AclAction::Permit, _) => permit.clone(),
                (AclAction::Deny, Some(d)) => d.clone(),
                (AclAction::Deny, None) => {
                    let msg = format!("{rname}: a deny of a NAT ACL before another NAT rule");
                    self.note(msg.clone());
                    out.push(FRule::unhandled(msg, span));
                    continue;
                }
            };
            out.push(FRule::new(rname, p, action).with_span(span));
        }
        out
    }

    /// The function of a QoS policy of an interface. It forwards the
    /// packets, and the marking and the class become unknown.
    pub(crate) fn qos(&self, f: &str, policy: &str, lines: Lines, next: &str) -> QosNotEvaluated {
        QosNotEvaluated {
            meta: self.meta(f, vec![self.span(lines)]),
            stanza: ObjectId::new(format!("{}:qos:{policy}", self.dev)),
            next: self.id(next),
        }
    }

    /// The ACL function of an interface in one direction. The unhandled
    /// options of the interface come first, so the function gives `Unknown`
    /// for each packet. With no bound ACL, the function permits the other
    /// packets. An IPv4 ACL does not filter IPv6 packets.
    pub(crate) fn interface_acl(
        &mut self,
        i: &Interface,
        bound: Option<&(String, Lines)>,
        dir: &str,
        next: &str,
    ) -> AclMatch {
        let mut rules = Vec::new();
        if !i.unhandled.is_empty() {
            let msg = format!(
                "{}: options not lowered: {}",
                i.name,
                i.unhandled.join(", ")
            );
            if dir == "in" {
                self.note(msg.clone());
            }
            rules.push(FRule::unhandled(msg, self.span(i.lines)));
        }
        let default = match bound {
            Some((name, lines)) => {
                rules.extend(self.acl_rules(
                    name,
                    *lines,
                    RuleAction::Permit,
                    Some(RuleAction::Deny),
                ));
                let mut v6 = FRule::new(
                    format!("{name}/IPv6 not filtered"),
                    RulePredicate::exact(ipv6()),
                    RuleAction::Permit,
                );
                if let Some(s) = self.profile.source.first() {
                    v6 = v6.with_span(s.clone());
                }
                rules.push(v6);
                self.profile.acl_default
            }
            None => RuleAction::Permit,
        };
        let spans = bound.map(|(_, l)| vec![self.span(*l)]).unwrap_or_default();
        let fname = format!("acl-{dir}/{}", i.name);
        let meta = self.meta(&fname, spans);
        let acl = bound.map_or_else(
            || format!("{}:{fname}", self.dev),
            |(n, _)| format!("{}:acl:{n}", self.dev),
        );
        AclMatch {
            meta,
            acl: ObjectId::new(acl),
            rules,
            default,
            next: self.id(next),
        }
    }

    /// The rules of the NAT in the outside to inside direction: the
    /// unhandled forms first, then the static rules, which translate the
    /// global destination to the local address. Each rule applies only on
    /// the outside interfaces.
    #[allow(clippy::type_complexity)]
    pub(crate) fn destination_nat(
        &mut self,
        outside: &BTreeSet<InterfaceId>,
    ) -> (Vec<FRule<NatAction>>, Vec<Option<BTreeSet<InterfaceId>>>) {
        let mut rules = Vec::new();
        let mut scopes = Vec::new();
        let mut nat_rules = self.cfg.nat_rules.clone();
        nat_rules.sort_by_key(|r| !matches!(r.kind, NatKind::Other(_)));
        for r in nat_rules {
            let span = self.span(r.lines);
            let rule = match &r.kind {
                NatKind::Static {
                    protocol,
                    local,
                    local_port,
                    global,
                    global_port,
                    uncertain,
                } => {
                    let name = format!("static {global} to {local}");
                    match self.static_parts(protocol, global, global_port, local, local_port) {
                        Ok((m, addr, port)) => FRule::new(
                            name.clone(),
                            self.static_predicate(
                                &name,
                                uncertain,
                                Match {
                                    dst_ip: m.0,
                                    dst_port: m.1,
                                    ..m.2
                                },
                            ),
                            NatAction::Translate { addr, port },
                        )
                        .with_span(span),
                        Err(x) => {
                            self.note(format!("{name}: {x}"));
                            FRule::unhandled(name, span)
                        }
                    }
                }
                NatKind::List { .. } => continue,
                NatKind::Other(text) => {
                    self.note(format!("NAT rule not lowered: {text}"));
                    FRule::unhandled(text.clone(), span)
                }
            };
            rules.push(rule);
            scopes.push(Some(outside.clone()));
        }
        (rules, scopes)
    }

    /// The parts of a static rule from the side `from` to the side `to`: the
    /// address and port conditions of `from` with the protocol, and the
    /// translation to `to`.
    #[allow(clippy::type_complexity)]
    fn static_parts(
        &self,
        protocol: &Option<String>,
        from: &str,
        from_port: &Option<String>,
        to: &str,
        to_port: &Option<String>,
    ) -> Result<((AddrCond, PortCond, Match), IpAddr, PortTranslation), String> {
        let from_ip: IpAddr = from.parse().map_err(|_| format!("address {from}"))?;
        let to_ip: IpAddr = to.parse().map_err(|_| format!("address {to}"))?;
        let mut base = ipv4();
        let mut pc = PortCond::Any;
        let mut pt = PortTranslation::Preserve;
        if let Some(p) = protocol {
            let n = protocol_number(p)?.ok_or_else(|| format!("protocol {p}"))?;
            base.protocol = ValueCond::one(n);
            let fp = port(from_port.as_deref().unwrap_or_default())?;
            let tp = port(to_port.as_deref().unwrap_or_default())?;
            pc = PortCond::one(fp);
            pt = PortTranslation::To(tp);
        }
        Ok((
            (AddrCond::In(vec![Prefix::host(from_ip)]), pc, base),
            to_ip,
            pt,
        ))
    }

    /// The predicate of a static rule: exact, or with no definite match
    /// and the rule's match as the upper bound if the line has a word that
    /// the lowering does not model.
    fn static_predicate(
        &mut self,
        name: &str,
        uncertain: &Option<String>,
        m: Match,
    ) -> RulePredicate {
        match uncertain {
            None => RulePredicate::exact(m),
            Some(word) => {
                self.note(format!(
                    "{name}: {word} is not lowered, so the packets that the rule can translate are unknown"
                ));
                let nothing = Match {
                    src_ip: AddrCond::In(Vec::new()),
                    ..Match::any()
                };
                RulePredicate::bounded(nothing, m)
            }
        }
    }

    /// The rules of the NAT in the inside to outside direction. Each rule
    /// applies only from an inside interface to an outside interface.
    pub(crate) fn source_nat(
        &mut self,
        active: &[Interface],
        inside: &BTreeSet<InterfaceId>,
        outside: &BTreeSet<InterfaceId>,
    ) -> Vec<(NatScope, FRule<NatAction>)> {
        let scope = NatScope {
            ingress: Some(inside.clone()),
            egress: Some(outside.clone()),
        };
        // The unhandled forms come first, then the static rules, then the
        // list rules in the order of the config. A deny of a list ACL exempts
        // the packet only from its own rule, so it is exact only in the last
        // list rule.
        let mut rules = self.cfg.nat_rules.clone();
        rules.sort_by_key(|r| match r.kind {
            NatKind::Other(_) => 0,
            NatKind::Static { .. } => 1,
            NatKind::List { .. } => 2,
        });
        let last_list = rules
            .iter()
            .rposition(|r| matches!(r.kind, NatKind::List { .. }));
        let mut out = Vec::new();
        for (index, r) in rules.into_iter().enumerate() {
            let span = self.span(r.lines);
            match &r.kind {
                NatKind::Static {
                    protocol,
                    local,
                    local_port,
                    global,
                    global_port,
                    uncertain,
                } => {
                    let name = format!("static {local} to {global}");
                    let rule =
                        match self.static_parts(protocol, local, local_port, global, global_port) {
                            Ok((m, addr, port)) => FRule::new(
                                name.clone(),
                                self.static_predicate(
                                    &name,
                                    uncertain,
                                    Match {
                                        src_ip: m.0,
                                        src_port: m.1,
                                        ..m.2
                                    },
                                ),
                                NatAction::Translate { addr, port },
                            )
                            .with_span(span),
                            Err(x) => {
                                self.note(format!("{name}: {x}"));
                                FRule::unhandled(name, span)
                            }
                        };
                    out.push((scope.clone(), rule));
                }
                NatKind::List {
                    acl,
                    target,
                    overload,
                } => {
                    let name = format!("list {acl}");
                    let addr = match target {
                        NatTarget::Pool(p) => match self.cfg.nat_pools.get(p) {
                            Some(pool) if pool.start == pool.end => {
                                pool.start.parse::<IpAddr>().ok()
                            }
                            Some(_) => {
                                self.note(format!(
                                    "{name}: pool {p} has more than 1 address, so the address is not known"
                                ));
                                None
                            }
                            None => {
                                self.note(format!("{name}: pool {p} does not exist"));
                                None
                            }
                        },
                        NatTarget::Interface(i) => {
                            let a = active
                                .iter()
                                .find(|x| x.name == *i)
                                .and_then(|x| x.addresses.iter().find(|a| !a.secondary))
                                .and_then(|a| iface_addr(&a.prefix))
                                .map(|x| x.0);
                            if a.is_none() {
                                self.note(format!("{name}: interface {i} has no address"));
                            }
                            a
                        }
                    };
                    let Some(addr) = addr else {
                        out.push((scope.clone(), FRule::unhandled(name, span)));
                        continue;
                    };
                    let port = if *overload {
                        PortTranslation::Allocate
                    } else {
                        self.profile.snat_port
                    };
                    let translate = NatAction::Translate { addr, port };
                    let deny = (Some(index) == last_list).then_some(NatAction::NoTranslate);
                    for mut rule in self.acl_rules(acl, r.lines, translate, deny) {
                        rule = rule.with_span(span.clone());
                        out.push((scope.clone(), rule));
                    }
                }
                NatKind::Other(text) => {
                    out.push((scope.clone(), FRule::unhandled(text.clone(), span)));
                }
            }
        }
        out
    }

    /// The FIB of a VRF: the collected route rows of the VRF, or else the
    /// connected and static routes of the config. With no rows and a
    /// dynamic routing protocol in the VRF, only the connected routes give
    /// an answer: the static routes and each other destination are unknown.
    /// The addresses of the interfaces of the VRF are local routes.
    /// Each IPv6 packet is unknown. Each next hop goes to the function
    /// `next`, and each VXLAN path to the encapsulation of `vx`.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn fib(
        &mut self,
        vrf: &str,
        active: &[Interface],
        col: &Collected,
        names: &Names,
        vips: &[(IpAddr, Vec<SourceSpan>)],
        next: &str,
        vx: &Vx<'_>,
    ) -> Fib {
        let mut t = Fib::new();
        let hop = |l: &L, iface: &str, gw: Option<IpAddr>| RouteNextHop {
            interface: InterfaceId::new(iface),
            gateway: gw,
            next: l.id(next),
        };
        if !col.routes.iter().any(|r| r.vrf == vrf) {
            for i in active.iter().filter(|i| vrf_of(i) == vrf) {
                for a in &i.addresses {
                    if let Some((ip, len)) = iface_addr(&a.prefix)
                        && len < 32
                    {
                        t.insert(
                            Prefix::new(ip, len),
                            Route::new(
                                RouteKind::Connected,
                                vec![hop(self, &i.name, None)],
                                vec![self.span(a.lines)],
                            ),
                        );
                    }
                }
            }
            for r in self.cfg.static_routes.clone() {
                if r.vrf != vrf {
                    continue;
                }
                let span = vec![self.span(r.lines)];
                let Ok(p) = r.prefix.parse::<Prefix>() else {
                    self.note(format!(
                        "static route {}: the prefix is not valid",
                        r.prefix
                    ));
                    continue;
                };
                if r.interface
                    .as_deref()
                    .is_some_and(|i| i.eq_ignore_ascii_case("null0"))
                {
                    t.insert(p, Route::new(RouteKind::Null, Vec::new(), span));
                    continue;
                }
                let gw = r.next_hop.as_deref().and_then(|g| g.parse::<IpAddr>().ok());
                let iface = r.interface.clone().map(|i| names.resolve(&i)).or_else(|| {
                    let gw = gw?;
                    active
                        .iter()
                        .filter(|i| vrf_of(i) == vrf)
                        .find(|i| {
                            i.addresses.iter().any(|a| {
                                iface_addr(&a.prefix).is_some_and(|(ip, len)| {
                                    len < 32 && Prefix::new(ip, len).contains(gw)
                                })
                            })
                        })
                        .map(|i| i.name.clone())
                });
                let hops = match iface {
                    Some(i) if r.unhandled.is_empty() => vec![hop(self, &i, gw)],
                    _ => {
                        self.note(format!(
                            "static route {} in VRF {vrf}: the next hop is not known",
                            r.prefix
                        ));
                        Vec::new()
                    }
                };
                t.insert(p, Route::new(RouteKind::Static, hops, span));
            }
            if let Some(found) = self.cfg.dynamic_vrfs.get(vrf).cloned() {
                self.note(format!(
                    "VRF {vrf}: a dynamic routing protocol and no collected route rows, so each destination outside the connected and local routes is unknown"
                ));
                let spans: Vec<SourceSpan> = found
                    .iter()
                    .map(|(first, last)| {
                        self.span(Lines {
                            first: *first,
                            last: *last,
                        })
                    })
                    .collect();
                // A learned route can be more specific than a static route,
                // so only the connected routes stay definite.
                let not_collected = |mut s: Vec<SourceSpan>| {
                    s.extend(spans.iter().cloned());
                    Route::unknown_with(
                        RouteKind::Static,
                        rsim_core::ReasonCode::NotCollected,
                        TABLE_NOT_COLLECTED,
                        s,
                    )
                };
                for (p, r) in t.entries() {
                    if r.kind != RouteKind::Connected {
                        t.insert(p, not_collected(r.spans));
                    }
                }
                let all: Prefix = "0.0.0.0/0".parse().expect("a valid prefix");
                if t.get(&all).is_none() {
                    t.insert(all, not_collected(Vec::new()));
                }
            }
        } else {
            let mut by_prefix: BTreeMap<String, Vec<&crate::collected::RouteRow>> = BTreeMap::new();
            for r in col.routes.iter().filter(|r| r.selected && r.vrf == vrf) {
                by_prefix.entry(r.prefix.clone()).or_default().push(r);
            }
            for (prefix, rows) in by_prefix {
                let Ok(p) = prefix.parse::<Prefix>() else {
                    self.note(format!(
                        "route {prefix} in VRF {vrf}: the prefix is not valid"
                    ));
                    continue;
                };
                let spans: Vec<SourceSpan> = rows.iter().map(|r| r.span.clone()).collect();
                let protocol = rows[0].protocol.as_str();
                let kind = match protocol {
                    "direct" => RouteKind::Connected,
                    "local" => RouteKind::Local,
                    _ => route_kind(
                        super::profile::protocol_word(protocol),
                        super::profile::LEARNED_WORDS,
                        super::profile::STATIC_WORDS,
                    ),
                };
                if kind == RouteKind::Local {
                    t.insert(p, Route::new(kind, Vec::new(), spans));
                    continue;
                }
                if rows.iter().any(|r| {
                    r.interface
                        .as_deref()
                        .is_some_and(|i| i.eq_ignore_ascii_case("null0"))
                }) {
                    t.insert(p, Route::new(RouteKind::Null, Vec::new(), spans));
                    continue;
                }
                // An active virtual address is a local route below.
                if vips.iter().any(|(a, _)| Prefix::host(*a) == p) {
                    continue;
                }
                // The VNI of each path with a VXLAN encapsulation.
                let tunnelled: Vec<Option<u32>> = rows
                    .iter()
                    .map(|r| {
                        vx.st
                            .vxlan_paths
                            .get(&(vrf.to_string(), prefix.clone(), r.next_hop.clone()?))
                            .map(|x| x.0)
                    })
                    .collect();
                let vxlan_problem =
                    tunnelled
                        .iter()
                        .flatten()
                        .find_map(|segid| match (vx.tunnel, vx.encap) {
                            (super::vxlan::Plan::Exact(t), Some(_)) => match t.l3.get(vrf) {
                                Some(x) if x.vni == *segid => None,
                                Some(x) => Some(format!(
                                    "a VXLAN path with VNI {segid}, and the VNI of the VRF is {}",
                                    x.vni
                                )),
                                None => Some(format!(
                                    "a VXLAN path with VNI {segid} in a VRF with no layer 3 VNI"
                                )),
                            },
                            _ => {
                                Some("a VXLAN path, and the tunnel end is not lowered".to_string())
                            }
                        });
                // A route stays in the table with no next hop when one of its
                // paths cannot be lowered, so its packets are unknown and do
                // not fall to a shorter prefix.
                let problem = if let Some(why) = &vxlan_problem {
                    Some(why.as_str())
                } else if rows
                    .iter()
                    .any(|r| matches!(r.protocol.as_str(), "hsrp" | "vrrp"))
                {
                    Some("a route of a gateway group that is not active on this switch")
                } else {
                    None
                };
                if let Some(why) = problem {
                    self.note(format!("route {prefix} in VRF {vrf}: {why}"));
                    t.insert(p, Route::new(kind, Vec::new(), spans));
                    continue;
                }
                let mut hops = Vec::new();
                let mut paths = Vec::new();
                for (r, tun) in rows.iter().zip(&tunnelled) {
                    let gw = r
                        .next_hop
                        .as_deref()
                        .and_then(|g| g.split('%').next()?.parse().ok());
                    if tun.is_some()
                        && let super::vxlan::Plan::Exact(tunnel) = vx.tunnel
                    {
                        hops.push(hop(self, &tunnel.nve, gw));
                    } else {
                        paths.push(path_of(r, vrf, names));
                    }
                }
                let through =
                    through_default(Origin::Collected, super::profile::COMPUTED_THROUGH_DEFAULT);
                match vx.resolver.resolve(vrf, &paths, through) {
                    Ok((found, more)) => {
                        hops.extend(found.iter().map(|h| hop(self, &h.interface, h.gateway)));
                        let mut all = spans;
                        all.extend(more);
                        t.insert(p, Route::new(kind, hops, all));
                    }
                    Err(u) => {
                        self.note(format!("route {prefix} in VRF {vrf}: {}", u.why));
                        let mut all = spans;
                        all.extend(u.spans);
                        t.insert(p, Route::unknown(kind, u.reason, all));
                    }
                }
            }
        }
        for i in active.iter().filter(|i| vrf_of(i) == vrf) {
            for a in &i.addresses {
                if let Some((ip, _)) = iface_addr(&a.prefix) {
                    t.insert(
                        Prefix::host(ip),
                        Route::new(RouteKind::Local, Vec::new(), vec![self.span(a.lines)]),
                    );
                }
            }
        }
        for (a, spans) in vips {
            t.insert(
                Prefix::host(*a),
                Route::new(RouteKind::Local, Vec::new(), spans.clone()),
            );
        }
        let v6: Prefix = "::/0".parse().expect("a valid prefix");
        t.insert(v6, Route::new(RouteKind::Static, Vec::new(), Vec::new()));
        t
    }
}

/// The path of a collected route row: its interface, and its next hop with
/// the VRF of a `%vrf` suffix that names another VRF. A connected row has
/// no next hop.
fn path_of(r: &crate::collected::RouteRow, vrf: &str, names: &Names) -> Path {
    let (gateway, other) = match r.next_hop.as_deref() {
        Some(g) if r.protocol != "direct" => {
            let (addr, suffix) = match g.split_once('%') {
                Some((a, v)) => (a, Some(v)),
                None => (g, None),
            };
            (
                addr.parse().ok(),
                suffix.filter(|v| *v != vrf).map(str::to_string),
            )
        }
        _ => (None, None),
    };
    Path {
        interface: r.interface.as_deref().map(|i| names.resolve(i)),
        gateway,
        vrf: other,
    }
}

/// The collected routes of each VRF for the resolution of a next hop: a
/// local route, a discard route, the route of a gateway group and a route
/// with a VXLAN path give no next hop.
fn resolver(col: &Collected, names: &Names, st: &super::state::State) -> Resolver {
    let mut by: BTreeMap<(&str, &str), Vec<&crate::collected::RouteRow>> = BTreeMap::new();
    for r in col.routes.iter().filter(|r| r.selected) {
        by.entry((&r.vrf, &r.prefix)).or_default().push(r);
    }
    let mut out = Resolver::new();
    for ((vrf, prefix), rows) in by {
        let Ok(p) = prefix.parse::<Prefix>() else {
            continue;
        };
        let spans: Vec<SourceSpan> = rows.iter().map(|r| r.span.clone()).collect();
        let tunnelled = rows.iter().any(|r| {
            r.next_hop.as_ref().is_some_and(|g| {
                st.vxlan_paths
                    .contains_key(&(vrf.to_string(), prefix.to_string(), g.clone()))
            })
        });
        let target = if rows[0].protocol == "local" {
            Target::Local
        } else if rows.iter().any(|r| {
            r.interface
                .as_deref()
                .is_some_and(|i| i.eq_ignore_ascii_case("null0"))
        }) {
            Target::Null
        } else if tunnelled
            || rows
                .iter()
                .any(|r| matches!(r.protocol.as_str(), "hsrp" | "vrrp"))
        {
            Target::Unknown
        } else {
            Target::Paths(rows.iter().map(|r| path_of(r, vrf, names)).collect())
        };
        out.add(vrf, p, target, spans);
    }
    out
}
