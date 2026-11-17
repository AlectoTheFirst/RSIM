//! Lowering of an NX-OS running config and its collected state into the
//! layer 3 function instances of a switch.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use rsim_core::{
    AddrCond, FunctionId, InterfaceId, Match, NeighbourTarget, NetFunction, ObjectId, PortCond,
    Prefix, PrefixTable, RulePredicate, SourceSpan, TriePrefixTable, ValueCond, VrfId,
};
use rsim_engine::EdgeInterface;
use rsim_functions::{
    AclMatch, DestinationNat, DeviceDelivery, Egress, EgressMode, Fib, Ingress, LocalInput, Meta,
    NatAction, NatScope, Neighbour, NextHopResolution, PortTranslation, Route, RouteKind,
    RouteLookup, RouteNextHop, Rule as FRule, RuleAction, SessionCommit, SessionLookup, SourceNat,
    Tag, VendorProfile, VrfSelection,
};

use super::config::{
    AclAction, AddrSpec, Config, Interface, Lines, NatKind, NatRole, NatTarget, PortSpec,
};
use super::names::Names;
use crate::collected::Collected;
use crate::vyos::Lowered;

/// The VRF of an interface with no `vrf member`.
const DEFAULT_VRF: &str = "default";

struct L<'a> {
    dev: &'a str,
    file: &'a str,
    profile: &'a VendorProfile,
    cfg: &'a Config,
    out: Lowered,
}

impl L<'_> {
    fn id(&self, f: &str) -> FunctionId {
        FunctionId::new(format!("{}/{f}", self.dev))
    }
    fn span(&self, l: Lines) -> SourceSpan {
        SourceSpan::new(self.file, l.first.max(1), l.last.max(l.first).max(1))
    }
    fn meta(&self, f: &str, spans: Vec<SourceSpan>) -> Meta {
        let mut m = Meta::new(self.id(f), self.dev, self.profile);
        m.provenance = spans;
        m
    }
    fn add(&mut self, f: impl NetFunction + 'static) {
        self.out.functions.push(Arc::new(f));
    }
    fn note(&mut self, s: String) {
        self.out.notes.push(s);
    }
}

fn vrf_of(i: &Interface) -> &str {
    i.vrf.as_deref().unwrap_or(DEFAULT_VRF)
}

/// An interface address: the address and the prefix length.
fn iface_addr(s: &str) -> Option<(IpAddr, u8)> {
    let (a, l) = s.split_once('/')?;
    Some((a.parse().ok()?, l.parse().ok()?))
}

/// Lowers the layer 3 part of one NX-OS switch.
pub fn lower(
    device: &str,
    file: &str,
    profile: &VendorProfile,
    cfg: &Config,
    col: &Collected,
) -> Lowered {
    let mut l = L {
        dev: device,
        file,
        profile,
        cfg,
        out: Lowered::default(),
    };
    let names = Names::new(cfg.interfaces.iter().map(|i| i.name.as_str()));
    let mut active: Vec<Interface> = Vec::new();
    for i in &cfg.interfaces {
        if i.shutdown || (i.addresses.is_empty() && !i.dynamic_address) {
            continue;
        }
        let mut i = i.clone();
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
    let inside = nat_ifs(NatRole::Inside);
    let outside = nat_ifs(NatRole::Outside);

    // Ingress and the input ACLs.
    for i in &active {
        let filtered = i.acl_in.is_some() || !i.unhandled.is_empty();
        let span = l.span(i.lines);
        let meta = l.meta(&format!("in/{}", i.name), vec![span]);
        l.add(Ingress {
            meta,
            interface: InterfaceId::new(&i.name),
            next: l.id(&if filtered {
                format!("acl-in/{}", i.name)
            } else {
                "vrf".to_string()
            }),
        });
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
    });

    // NAT in the outside to inside direction, before the route lookup.
    let (dnat, dnat_scopes) = l.destination_nat(&outside);
    let meta = l.meta("dnat", Vec::new());
    l.add(DestinationNat {
        meta,
        table: ObjectId::new(format!("{device}:nat:outside")),
        rules: dnat,
        ingress: dnat_scopes,
        next: l.id("route"),
    });

    // The route lookup in the FIB of each VRF.
    let mut vrfs: BTreeSet<String> = cfg.vrfs.keys().cloned().collect();
    vrfs.insert(DEFAULT_VRF.to_string());
    vrfs.extend(active.iter().map(|i| vrf_of(i).to_string()));
    let mut tables = BTreeMap::new();
    for v in &vrfs {
        let fib = l.fib(v, &active, col, &names);
        tables.insert(VrfId::new(v), fib);
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
                } else {
                    format!("out/{}", i.name)
                };
                (InterfaceId::new(&i.name), l.id(&f))
            })
            .collect(),
        point_to_point: BTreeMap::new(),
    });
    for i in &active {
        if filtered_out(i) {
            let next = format!("out/{}", i.name);
            let f = l.interface_acl(i, i.acl_out.as_ref(), "out", &next);
            l.add(f);
        }
        let span = l.span(i.lines);
        let meta = l.meta(&format!("out/{}", i.name), vec![span]);
        l.add(Egress {
            meta,
            interface: InterfaceId::new(&i.name),
            mode: EgressMode::Routed,
            link: None,
            rewrite: Default::default(),
            tag: Tag::Keep,
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
    l.out
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
    /// config does not have, or a line that the handler cannot read, gives
    /// an unhandled rule.
    fn acl_rules<A: Clone>(
        &mut self,
        name: &str,
        bind: Lines,
        permit: A,
        deny: A,
    ) -> Vec<FRule<A>> {
        let Some(acl) = self.cfg.acls.get(name).cloned() else {
            let msg = format!("ACL {name} does not exist");
            self.note(msg.clone());
            return vec![FRule::unhandled(msg, self.span(bind))];
        };
        let mut out = Vec::new();
        if !acl.unreadable.is_empty() {
            let msg = format!("ACL {name}: lines not read: {}", acl.unreadable.join(", "));
            self.note(msg.clone());
            out.push(FRule::unhandled(msg, self.span(acl.lines)));
        }
        for e in &acl.entries {
            let rname = format!("{name}/{}", e.seq);
            let p = self.ace_predicate(e, &rname);
            let action = match e.action {
                AclAction::Permit => permit.clone(),
                AclAction::Deny => deny.clone(),
            };
            out.push(FRule::new(rname, p, action).with_span(self.span(e.lines)));
        }
        out
    }

    /// The ACL function of an interface in one direction. The unhandled
    /// options of the interface come first, so the function gives `Unknown`
    /// for each packet. With no bound ACL, the function permits the other
    /// packets. An IPv4 ACL does not filter IPv6 packets.
    fn interface_acl(
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
                rules.extend(self.acl_rules(name, *lines, RuleAction::Permit, RuleAction::Deny));
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

    /// The rules of the NAT in the outside to inside direction: the static
    /// rules, which translate the global destination to the local address.
    /// Each rule applies only on the outside interfaces.
    #[allow(clippy::type_complexity)]
    fn destination_nat(
        &mut self,
        outside: &BTreeSet<InterfaceId>,
    ) -> (Vec<FRule<NatAction>>, Vec<Option<BTreeSet<InterfaceId>>>) {
        let mut rules = Vec::new();
        let mut scopes = Vec::new();
        for r in self.cfg.nat_rules.clone() {
            let span = self.span(r.lines);
            let rule = match &r.kind {
                NatKind::Static {
                    protocol,
                    local,
                    local_port,
                    global,
                    global_port,
                } => {
                    let name = format!("static {global} to {local}");
                    match self.static_parts(protocol, global, global_port, local, local_port) {
                        Ok((m, addr, port)) => FRule::new(
                            name,
                            RulePredicate::exact(Match {
                                dst_ip: m.0,
                                dst_port: m.1,
                                ..m.2
                            }),
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

    /// The rules of the NAT in the inside to outside direction. Each rule
    /// applies only from an inside interface to an outside interface.
    fn source_nat(
        &mut self,
        active: &[Interface],
        inside: &BTreeSet<InterfaceId>,
        outside: &BTreeSet<InterfaceId>,
    ) -> Vec<(NatScope, FRule<NatAction>)> {
        let scope = NatScope {
            ingress: Some(inside.clone()),
            egress: Some(outside.clone()),
        };
        let mut out = Vec::new();
        for r in self.cfg.nat_rules.clone() {
            let span = self.span(r.lines);
            match &r.kind {
                NatKind::Static {
                    protocol,
                    local,
                    local_port,
                    global,
                    global_port,
                } => {
                    let name = format!("static {local} to {global}");
                    let rule =
                        match self.static_parts(protocol, local, local_port, global, global_port) {
                            Ok((m, addr, port)) => FRule::new(
                                name,
                                RulePredicate::exact(Match {
                                    src_ip: m.0,
                                    src_port: m.1,
                                    ..m.2
                                }),
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
                    for mut rule in self.acl_rules(acl, r.lines, translate, NatAction::NoTranslate)
                    {
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

    /// The FIB of a VRF: the collected route table, or else the connected
    /// and static routes of the config. The addresses of the interfaces of
    /// the VRF are local routes. Each IPv6 packet is unknown.
    fn fib(&mut self, vrf: &str, active: &[Interface], col: &Collected, names: &Names) -> Fib {
        let mut t = Fib::new();
        let hop = |l: &L, iface: &str, gw: Option<IpAddr>| RouteNextHop {
            interface: InterfaceId::new(iface),
            gateway: gw,
            next: l.id("snat"),
        };
        if col.routes.is_empty() {
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
                    _ => RouteKind::Static,
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
                // A route stays in the table with no next hop when one of its
                // paths cannot be lowered, so its packets are unknown and do
                // not fall to a shorter prefix.
                let problem = if rows
                    .iter()
                    .any(|r| matches!(r.protocol.as_str(), "hsrp" | "vrrp"))
                {
                    Some("a route of a gateway protocol is not lowered")
                } else if rows
                    .iter()
                    .any(|r| r.next_hop.as_deref().is_some_and(|g| g.contains('%')))
                {
                    Some("a next hop in another VRF is not lowered")
                } else if rows.iter().any(|r| r.interface.is_none()) {
                    Some("a next hop with no interface")
                } else {
                    None
                };
                let hops = match problem {
                    Some(why) => {
                        self.note(format!("route {prefix} in VRF {vrf}: {why}"));
                        Vec::new()
                    }
                    None => rows
                        .iter()
                        .filter_map(|r| {
                            let gw = r.next_hop.as_deref().and_then(|g| g.parse().ok());
                            let i = names.resolve(r.interface.as_deref()?);
                            Some(hop(self, &i, gw))
                        })
                        .collect(),
                };
                t.insert(p, Route::new(kind, hops, spans));
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
        let v6: Prefix = "::/0".parse().expect("a valid prefix");
        t.insert(v6, Route::new(RouteKind::Static, Vec::new(), Vec::new()));
        t
    }
}
