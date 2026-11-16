//! A builder for the functions of one device.

use rsim_core::{
    AddrCond, EndpointId, FunctionId, InterfaceId, Match, NeighbourTarget, ObjectId, PortCond,
    Prefix, PrefixTable, RulePredicate, SourceSpan, TriePrefixTable, ValueCond, VrfId, ZoneId,
};
use rsim_engine::{AttachmentKind, AttachmentRecord, EdgeInterface, Endpoint, TwinBuilder};
use rsim_functions::{
    AclMatch, Egress, EgressMode, Ingress, Link, Meta, Neighbour, NextHopResolution, Route,
    RouteKind, RouteLookup, RouteNextHop, Rule, RuleAction, SessionCommit, SessionLookup,
    VendorProfile, VrfSelection, ZoneLookup, ZoneRole,
};

use crate::helpers::*;

/// A device under construction.
pub struct Dev {
    pub name: String,
    pub profile: VendorProfile,
}

impl Dev {
    pub fn new(name: &str, profile: VendorProfile) -> Self {
        Dev {
            name: name.to_string(),
            profile,
        }
    }

    pub fn id(&self, f: &str) -> FunctionId {
        FunctionId::new(format!("{}/{f}", self.name))
    }

    pub fn span(&self, first: u32, last: u32) -> SourceSpan {
        SourceSpan::new(format!("{}.conf", self.name), first, last)
    }

    pub fn meta(&self, f: &str, first: u32, last: u32) -> Meta {
        Meta::new(self.id(f), self.name.as_str(), &self.profile).with_span(self.span(first, last))
    }

    pub fn ingress(&self, iface: &str, next: &str, line: u32) -> Ingress {
        Ingress {
            meta: self.meta(&format!("in/{iface}"), line, line),
            interface: InterfaceId::new(iface),
            next: self.id(next),
        }
    }

    pub fn vrf(&self, map: &[(&str, &str)], next: &str, line: u32) -> VrfSelection {
        VrfSelection {
            meta: self.meta("vrf", line, line + map.len() as u32),
            by_interface: map
                .iter()
                .map(|(i, v)| (InterfaceId::new(*i), VrfId::new(*v)))
                .collect(),
            default_vrf: self.profile.default_vrf.clone(),
            next: self.id(next),
        }
    }

    pub fn zone(
        &self,
        name: &str,
        role: ZoneRole,
        map: &[(&str, &str)],
        next: &str,
        line: u32,
    ) -> ZoneLookup {
        ZoneLookup {
            meta: self.meta(name, line, line + map.len() as u32),
            role,
            by_interface: map
                .iter()
                .map(|(i, z)| (InterfaceId::new(*i), ZoneId::new(*z)))
                .collect(),
            unzoned: self.profile.unzoned_interface,
            next: self.id(next),
        }
    }

    pub fn acl(
        &self,
        name: &str,
        acl: &str,
        rules: Vec<Rule<RuleAction>>,
        next: &str,
        line: u32,
    ) -> AclMatch {
        AclMatch {
            meta: self.meta(name, line, line + rules.len() as u32 + 1),
            acl: ObjectId::new(acl),
            rules,
            default: self.profile.acl_default,
            next: self.id(next),
        }
    }

    pub fn session_lookup(&self, next: &str) -> SessionLookup {
        SessionLookup {
            meta: self.meta("session-lookup", 1, 1),
            next: self.id(next),
        }
    }

    pub fn session_commit(&self, next: &str) -> SessionCommit {
        SessionCommit {
            meta: self.meta("session-commit", 1, 1),
            next: self.id(next),
        }
    }

    pub fn egress(
        &self,
        iface: &str,
        mode: EgressMode,
        link: Option<(&str, Option<u64>)>,
        line: u32,
    ) -> Egress {
        Egress {
            meta: self.meta(&format!("out/{iface}"), line, line),
            interface: InterfaceId::new(iface),
            mode,
            link: link.map(|(peer, delay)| Link {
                peer: (!peer.is_empty()).then(|| fid(peer)),
                delay_ns: delay,
                provenance: vec![SourceSpan::line("topology/links.yaml", line)],
                facts: None,
            }),
            rewrite: Default::default(),
            tag: Default::default(),
        }
    }

    pub fn nexthop(
        &self,
        entries: &[(&str, &str, Target)],
        egress: &[&str],
        line: u32,
    ) -> NextHopResolution {
        let mut table: TriePrefixTable<Vec<Neighbour>> = TriePrefixTable::new();
        for (i, (addr, iface, target)) in entries.iter().enumerate() {
            let p = Prefix::host(ip(addr));
            let n = Neighbour {
                interface: InterfaceId::new(*iface),
                target: match target {
                    Target::Link(_) => NeighbourTarget::Link,
                    Target::Endpoint(e) => NeighbourTarget::Endpoint(EndpointId::new(*e)),
                },
                owner: match target {
                    Target::Link(o) | Target::Endpoint(o) => o.to_string(),
                },
                mac: None,
                spans: vec![SourceSpan::line(format!("{}.arp", self.name), i as u32 + 1)],
            };
            let mut v = table.get(&p).cloned().unwrap_or_default();
            v.push(n);
            table.insert(p, v);
        }
        NextHopResolution {
            meta: self.meta("nexthop", line, line),
            neighbours: table,
            complete: true,
            egress: egress
                .iter()
                .map(|i| (InterfaceId::new(*i), self.id(&format!("out/{i}"))))
                .collect(),
            point_to_point: Default::default(),
        }
    }

    /// A route lookup with one VRF. Each route: prefix, kind, next hops of
    /// (interface, gateway, next function).
    pub fn routes(
        &self,
        vrf: &str,
        routes: &[(&str, RouteKind, &[(&str, Option<&str>, &str)])],
        line: u32,
    ) -> RouteLookup {
        let mut t = TriePrefixTable::new();
        for (i, (p, kind, nhs)) in routes.iter().enumerate() {
            let nh = nhs
                .iter()
                .map(|(iface, gw, next)| RouteNextHop {
                    interface: InterfaceId::new(*iface),
                    gateway: gw.map(ip),
                    next: self.id(next),
                })
                .collect();
            t.insert(
                pfx(p),
                Route::new(*kind, nh, vec![self.span(line + i as u32, line + i as u32)]),
            );
        }
        RouteLookup {
            meta: self.meta("route", line, line + routes.len() as u32),
            tables: [(VrfId::new(vrf), t)].into_iter().collect(),
            fallback: None,
            local: None,
        }
    }
}

#[derive(Clone, Copy)]
pub enum Target {
    /// The neighbour is behind the link; the text names the owner.
    Link(&'static str),
    Endpoint(&'static str),
}

pub fn rule(name: &str, m: Match, action: RuleAction, span: SourceSpan) -> Rule<RuleAction> {
    Rule::new(name, RulePredicate::exact(m), action).with_span(span)
}

pub fn m_src_dst(src: &[&str], dst: &[&str]) -> Match {
    Match {
        src_ip: if src.is_empty() {
            AddrCond::Any
        } else {
            AddrCond::prefixes(src)
        },
        dst_ip: if dst.is_empty() {
            AddrCond::Any
        } else {
            AddrCond::prefixes(dst)
        },
        ..Match::any()
    }
}

pub fn with_proto_dport(m: Match, proto: u8, dport: u16) -> Match {
    Match {
        protocol: ValueCond::one(proto),
        dst_port: PortCond::one(dport),
        ..m
    }
}

/// An endpoint with its client attachment record, and its interface as an
/// edge interface with the connected network of the address.
#[derive(Clone, Debug)]
pub struct Host {
    pub endpoint: Endpoint,
    pub record: AttachmentRecord,
    pub edge: EdgeInterface,
}

/// A host at the ingress function `attachment`, named `<device>/in/<interface>`.
/// The connected network is the /24 network of the address.
///
/// # Panics
///
/// Panics if `attachment` is not of the form `<device>/in/<interface>`.
pub fn endpoint(id: &str, addr: &str, attachment: FunctionId) -> Host {
    let name = attachment.to_string();
    let (device, interface) = name
        .split_once("/in/")
        .expect("an ingress function is named <device>/in/<interface>");
    let a = ip(addr);
    let span = SourceSpan::line(format!("{device}.clients"), 1);
    Host {
        endpoint: Endpoint {
            id: EndpointId::new(id),
            addresses: vec![a],
        },
        record: AttachmentRecord {
            address: a,
            device: device.into(),
            interface: InterfaceId::new(interface),
            kind: AttachmentKind::Client,
            host: id.to_string(),
            provenance: vec![span.clone()],
        },
        edge: EdgeInterface {
            device: device.into(),
            interface: InterfaceId::new(interface),
            networks: vec![Prefix::new(a, 24)],
            provenance: vec![span],
        },
    }
}

/// Adds a host: the endpoint, the record and the edge interface.
pub fn add_host(b: &mut TwinBuilder, h: Host) {
    b.endpoint(h.endpoint);
    b.attachment(h.record);
    b.edge_interface(h.edge);
}
