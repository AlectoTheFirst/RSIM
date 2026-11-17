//! Lowering of the layer 2 part of an NX-OS switch: the switch ports, the
//! MAC table, the flood, the SVI hand-off, HSRP and VRRP, and the endpoints.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use rsim_core::{
    BridgeDomainId, EndpointId, FunctionId, InterfaceId, Mac, ObjectId, PortId, Prefix,
    PrefixTable, SourceSpan, TriePrefixTable,
};
use rsim_engine::{AttachmentKind, AttachmentRecord, Endpoint};
use rsim_functions::{
    AclMatch, Flood, HostMac, HostResolution, Layer3HandOff, MacEntry, MacLookup, PortEgress,
    PortIngress, Rule as FRule, RuleAction,
};

use super::config::{FhrpKind, Interface, PortMode};
use super::lower::{L, iface_addr};
use super::names::Names;
use super::profile::{ACCESS_VLAN, DEFAULT_MODE_IS_ACCESS, NATIVE_VLAN};
use super::state::{self, State};
use crate::collected::Collected;

/// The gateway facts of a layer 3 interface.
#[derive(Clone, Debug, Default)]
pub(super) struct Gateway {
    /// The collected MAC of the interface.
    pub svi_mac: Option<(Mac, SourceSpan)>,
    /// The virtual MAC and the virtual address of each active group.
    pub active: Vec<(Mac, IpAddr, Vec<SourceSpan>)>,
    /// A virtual MAC of a group of the interface, active or not.
    pub vmac: Option<(Mac, Vec<SourceSpan>)>,
    /// Why the hand-off of the interface is not known.
    pub unknown: Option<String>,
}

/// The VLAN of an SVI name such as `Vlan10`.
pub(super) fn svi_vlan(name: &str) -> Option<u16> {
    let lower = name.to_ascii_lowercase();
    lower.strip_prefix("vlan")?.parse().ok()
}

/// True for the name of a physical port or a port channel.
fn is_switch_port(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.starts_with("ethernet") || l.starts_with("port-channel")
}

/// An endpoint: its addresses with the span of each ARP row, its MAC, its
/// port, its VLAN and the span of its MAC table row.
#[derive(Clone, Debug)]
struct Ep {
    addrs: Vec<(IpAddr, SourceSpan)>,
    mac: Mac,
    port: String,
    vlan: u16,
    mac_span: SourceSpan,
}

/// The plan of a switch port.
#[derive(Clone, Debug)]
enum Plan {
    Exact {
        native: Option<u16>,
        qos_in: Option<(String, super::config::Lines)>,
        qos_out: Option<(String, super::config::Lines)>,
        tagged: BTreeSet<u16>,
        /// True for an access port with no LLDP or CDP neighbour.
        edge: bool,
        lines: super::config::Lines,
    },
    Unknown(String, super::config::Lines),
}

/// The state words of a group that are neither active nor unknown.
const HSRP_OTHER: &[&str] = &["standby", "listen", "speak", "init", "initial", "learn"];
const VRRP_OTHER: &[&str] = &["backup", "init", "initialize"];

impl L<'_> {
    /// The gateway facts of each layer 3 interface.
    pub(super) fn gateways(
        &mut self,
        active: &[Interface],
        st: &State,
        col: &Collected,
        names: &Names,
    ) -> BTreeMap<String, Gateway> {
        let mut out = BTreeMap::new();
        for i in active {
            let mut g = Gateway {
                svi_mac: col
                    .links
                    .iter()
                    .find(|r| names.resolve(&r.interface) == i.name)
                    .and_then(|r| Some((state::mac(r.mac.as_deref()?)?, r.span.clone()))),
                ..Gateway::default()
            };
            for f in &i.fhrp {
                let (collected, word, others, what) = match f.kind {
                    FhrpKind::Hsrp => (st.hsrp_collected, "active", HSRP_OTHER, "HSRP"),
                    FhrpKind::Vrrp => (st.vrrp_collected, "master", VRRP_OTHER, "VRRP"),
                };
                let row = st
                    .groups
                    .iter()
                    .find(|r| r.kind == f.kind && r.interface == i.name && r.group == f.group);
                let Some(r) = row.filter(|_| collected) else {
                    g.unknown = Some(format!("{what} group {}: no collected state", f.group));
                    continue;
                };
                let spans = vec![self.span(f.lines), r.span.clone()];
                if let Some(m) = r.vmac {
                    g.vmac.get_or_insert((m, spans.clone()));
                }
                let state = r.state.as_deref().unwrap_or_default().to_ascii_lowercase();
                let vip = r.vip.as_deref().and_then(|v| v.parse::<IpAddr>().ok());
                match (state.as_str(), vip, r.vmac) {
                    (s, Some(vip), Some(m)) if s == word => g.active.push((m, vip, spans)),
                    (s, _, _) if others.contains(&s) => {}
                    (s, _, _) => {
                        g.unknown = Some(format!(
                            "{what} group {}: the state {s:?}, the virtual address or the virtual MAC is not known",
                            f.group
                        ));
                    }
                }
            }
            if let Some(why) = &g.unknown {
                self.note(format!("{}: {why}", i.name));
            }
            out.insert(i.name.clone(), g);
        }
        out
    }

    /// A function that gives `Unknown` for each packet, in place of a port
    /// function that the lowering cannot make exact.
    fn sink(&self, f: &str, why: String, span: SourceSpan) -> AclMatch {
        AclMatch {
            meta: self.meta(f, vec![span.clone()]),
            acl: ObjectId::new(format!("{}:{f}", self.dev)),
            rules: vec![FRule::unhandled(why, span)],
            default: RuleAction::Deny,
            next: self.id(f),
        }
    }

    fn bd(&self, vlan: u16) -> BridgeDomainId {
        BridgeDomainId::new(format!("{}/vlan{vlan}", self.dev))
    }

    /// Lowers the layer 2 part. Gives the ingress function of the SVI port
    /// and the MAC of each SVI that has one, for the routed egress of the
    /// SVI.
    pub(super) fn layer2(
        &mut self,
        active: &[Interface],
        gws: &BTreeMap<String, Gateway>,
        st: &State,
        col: &Collected,
        names: &Names,
    ) -> BTreeMap<String, (FunctionId, Mac)> {
        let cfg = self.cfg;
        let vlans: BTreeSet<u16> = cfg.vlans.iter().flat_map(|(a, b)| *a..=*b).collect();
        let unknown_vlans: BTreeSet<u16> = cfg
            .unknown_vlans
            .iter()
            .flat_map(|(a, b)| *a..=*b)
            .collect();
        let l3: BTreeSet<&str> = active.iter().map(|i| i.name.as_str()).collect();

        // The port channel of each member port.
        let mut channel: BTreeMap<String, String> = BTreeMap::new();
        for i in &cfg.interfaces {
            if let Some(n) = i.channel_group {
                channel.insert(i.name.clone(), format!("port-channel{n}"));
            }
        }
        let port_of = |name: &str| -> String {
            let n = names.resolve(name);
            channel.get(&n).cloned().unwrap_or(n)
        };
        let neighbour: BTreeSet<String> = st.neighbour_ports.iter().map(|p| port_of(p)).collect();
        let mac_ports: BTreeSet<String> = col
            .macs
            .iter()
            .filter_map(|r| r.port.as_deref())
            .map(port_of)
            .collect();

        if !st.neighbours_collected {
            self.note("no LLDP or CDP section, so each access port counts as an edge port".into());
        }
        for line in &cfg.unreadable_vlans {
            self.note(format!("{line}: the VLAN list is not read"));
        }

        // The plan of each switch port.
        let mut plans: BTreeMap<String, Plan> = BTreeMap::new();
        for i in &cfg.interfaces {
            if !is_switch_port(&i.name)
                || l3.contains(i.name.as_str())
                || i.channel_group.is_some()
                || i.switchport == Some(false)
            {
                continue;
            }
            let collected = st.interfaces.get(&i.name);
            let admin = i.admin_up.or(collected.and_then(|s| s.admin_up));
            let oper = collected.and_then(|s| s.oper_up);
            if admin == Some(false) || oper == Some(false) {
                continue;
            }
            let relevant = mac_ports.contains(&i.name) || neighbour.contains(&i.name);
            // The mode: the config, else the collected `eth_mode`.
            let collected_mode = collected.and_then(|s| s.mode.as_deref());
            let l2 = i
                .switchport
                .or(cfg.default_switchport)
                .or(match collected_mode {
                    Some("access" | "trunk") => Some(true),
                    Some("routed") => Some(false),
                    _ => None,
                });
            let plan = match l2 {
                None if !relevant => continue,
                Some(false) => continue,
                None => Plan::Unknown("the mode of the port is not known".into(), i.lines),
                Some(true) if admin.is_none() => {
                    Plan::Unknown("the admin state of the port is not known".into(), i.lines)
                }
                Some(true) if !i.unhandled.is_empty() => Plan::Unknown(
                    format!("options not lowered: {}", i.unhandled.join(", ")),
                    i.lines,
                ),
                Some(true)
                    if i.acl_in.is_some()
                        || i.acl_out.is_some()
                        || i.nat.is_some()
                        || i.vrf.is_some() =>
                {
                    Plan::Unknown(
                        "a layer 3 option on a switch port is not lowered".into(),
                        i.lines,
                    )
                }
                Some(true) => {
                    let from_state = match collected_mode {
                        Some("access") => Some(PortMode::Access),
                        Some("trunk") => Some(PortMode::Trunk),
                        _ => None,
                    };
                    let mode = i.mode.or(from_state).unwrap_or(if DEFAULT_MODE_IS_ACCESS {
                        PortMode::Access
                    } else {
                        PortMode::Trunk
                    });
                    let (native, tagged) = match mode {
                        PortMode::Access => {
                            (Some(i.access_vlan.unwrap_or(ACCESS_VLAN)), BTreeSet::new())
                        }
                        PortMode::Trunk => {
                            let native = i.native_vlan.unwrap_or(NATIVE_VLAN);
                            let allowed: BTreeSet<u16> = match &i.allowed {
                                Some(r) => r.iter().flat_map(|(a, b)| *a..=*b).collect(),
                                None => vlans.clone(),
                            };
                            let native = allowed.contains(&native).then_some(native);
                            let tagged = allowed
                                .iter()
                                .copied()
                                .filter(|v| vlans.contains(v) && Some(*v) != native)
                                .collect();
                            (native, tagged)
                        }
                    };
                    let used: Vec<u16> = native.into_iter().chain(tagged.iter().copied()).collect();
                    match (
                        native.filter(|v| !vlans.contains(v)),
                        used.iter().find(|v| unknown_vlans.contains(v)),
                    ) {
                        (Some(v), _) => {
                            Plan::Unknown(format!("VLAN {v} is not in the config"), i.lines)
                        }
                        (None, Some(v)) => Plan::Unknown(
                            format!("VLAN {v} has a line that is not lowered"),
                            i.lines,
                        ),
                        (None, None) => Plan::Exact {
                            native,
                            qos_in: i.qos_in.clone(),
                            qos_out: i.qos_out.clone(),
                            tagged,
                            edge: mode == PortMode::Access && !neighbour.contains(&i.name),
                            lines: i.lines,
                        },
                    }
                }
            };
            if let Plan::Unknown(why, _) = &plan {
                self.note(format!("{}: {why}", i.name));
            }
            plans.insert(i.name.clone(), plan);
        }

        // The SVIs and their MACs.
        let mut svis: BTreeMap<String, (u16, Mac, SourceSpan)> = BTreeMap::new();
        for i in active {
            let Some(v) = svi_vlan(&i.name) else {
                continue;
            };
            if !vlans.contains(&v) {
                self.note(format!("{}: VLAN {v} is not in the config", i.name));
                continue;
            }
            match gws.get(&i.name).and_then(|g| g.svi_mac.clone()) {
                Some((m, span)) => {
                    svis.insert(i.name.clone(), (v, m, span));
                }
                None => self.note(format!(
                    "{}: no collected MAC, so the SVI is not joined to the VLAN",
                    i.name
                )),
            }
        }
        // The MACs of the switch itself in each VLAN: the MAC of each SVI and
        // each active virtual MAC. The lowering adds them, so their MAC table
        // rows are not used.
        let mut own: BTreeSet<(u16, Mac)> = BTreeSet::new();
        for (name, (v, m, _)) in &svis {
            own.insert((*v, *m));
            if let Some(g) = gws.get(name) {
                own.extend(g.active.iter().map(|a| (*v, a.0)));
            }
        }

        // The addresses that are next hops of a route: a router, not an
        // endpoint, so a packet to its MAC can go on beyond the estate.
        let mut next_hops: BTreeSet<IpAddr> = col
            .routes
            .iter()
            .filter_map(|r| r.next_hop.as_deref())
            .filter_map(|g| g.split('%').next()?.parse().ok())
            .collect();
        next_hops.extend(
            cfg.static_routes
                .iter()
                .filter_map(|r| r.next_hop.as_deref()?.parse::<IpAddr>().ok()),
        );

        // The endpoints: the ARP rows of an SVI whose MAC is on an edge
        // port, one endpoint for each MAC with all its addresses.
        let mut endpoints: BTreeMap<String, Ep> = BTreeMap::new();
        let mut routers: BTreeSet<String> = BTreeSet::new();
        for n in &col.neighbours {
            let iface = names.resolve(&n.interface);
            let (Some(v), Ok(ip), Some(m)) = (
                svi_vlan(&iface),
                n.ip.parse::<IpAddr>(),
                n.mac.as_deref().and_then(state::mac),
            ) else {
                continue;
            };
            let Some(row) = col
                .macs
                .iter()
                .find(|r| r.vlan == u64::from(v) && state::mac(&r.mac) == Some(m))
            else {
                continue;
            };
            let Some(port) = row.port.as_deref().map(port_of) else {
                continue;
            };
            if !matches!(plans.get(&port), Some(Plan::Exact { edge: true, .. })) {
                continue;
            }
            let id = format!("{}/vlan{v}/{m:?}", self.dev);
            if next_hops.contains(&ip) {
                routers.insert(id);
                continue;
            }
            let e = endpoints.entry(id).or_insert_with(|| Ep {
                addrs: Vec::new(),
                mac: m,
                port,
                vlan: v,
                mac_span: row.span.clone(),
            });
            e.addrs.push((ip, n.span.clone()));
        }
        for id in &routers {
            endpoints.remove(id);
            self.note(format!(
                "{id}: a next hop of a route, so it is not an endpoint"
            ));
        }

        // The host table of each VLAN: the endpoints, the SVI addresses and
        // the active virtual addresses.
        let mut hosts: BTreeMap<u16, TriePrefixTable<HostMac>> = BTreeMap::new();
        for e in endpoints.values() {
            for (ip, span) in &e.addrs {
                hosts.entry(e.vlan).or_default().insert(
                    Prefix::host(*ip),
                    HostMac {
                        mac: e.mac,
                        spans: vec![span.clone(), e.mac_span.clone()],
                    },
                );
            }
        }
        for i in active {
            let Some((v, m, span)) = svis.get(&i.name) else {
                continue;
            };
            let t = hosts.entry(*v).or_default();
            for a in &i.addresses {
                if let Some((ip, _)) = iface_addr(&a.prefix) {
                    t.insert(
                        Prefix::host(ip),
                        HostMac {
                            mac: *m,
                            spans: vec![span.clone()],
                        },
                    );
                }
            }
            if let Some(g) = gws.get(&i.name) {
                for (m, vip, spans) in &g.active {
                    t.insert(
                        Prefix::host(*vip),
                        HostMac {
                            mac: *m,
                            spans: spans.clone(),
                        },
                    );
                }
            }
        }

        let mut tables: BTreeMap<BridgeDomainId, BTreeMap<Mac, MacEntry>> = BTreeMap::new();
        let mut flood: BTreeMap<BridgeDomainId, Vec<(PortId, FunctionId)>> = BTreeMap::new();
        let mut egress: BTreeMap<PortId, FunctionId> = BTreeMap::new();
        let mac_id = self.id("mac");

        // The switch ports.
        for (name, plan) in &plans {
            let pid = PortId::new(name);
            let in_f = format!("port/{name}/in");
            let out_f = format!("port/{name}/out");
            match plan {
                Plan::Unknown(why, lines) => {
                    let span = self.span(*lines);
                    let f = self.sink(&in_f, format!("{name}: {why}"), span.clone());
                    self.add(f);
                    let f = self.sink(&out_f, format!("{name}: {why}"), span);
                    self.add(f);
                    let out_id = self.id(&out_f);
                    egress.insert(pid.clone(), out_id.clone());
                    for v in &vlans {
                        flood
                            .entry(self.bd(*v))
                            .or_default()
                            .push((pid.clone(), out_id.clone()));
                    }
                }
                Plan::Exact {
                    native,
                    qos_in,
                    qos_out,
                    tagged,
                    edge,
                    lines,
                } => {
                    let span = self.span(*lines);
                    let meta = self.meta(&in_f, vec![span.clone()]);
                    let qin_f = format!("port/{name}/qos-in");
                    self.add(PortIngress {
                        meta,
                        port: pid.clone(),
                        native: native.map(|v| self.bd(v)),
                        tagged: tagged.iter().map(|v| (*v, self.bd(*v))).collect(),
                        next: if qos_in.is_some() {
                            self.id(&qin_f)
                        } else {
                            mac_id.clone()
                        },
                    });
                    if let Some((policy, l)) = qos_in {
                        let f = self.qos(&qin_f, policy, *l, "mac");
                        self.add(f);
                    }
                    let port_hosts: BTreeMap<Mac, EndpointId> = endpoints
                        .iter()
                        .filter(|(_, e)| e.port == *name)
                        .map(|(id, e)| (e.mac, EndpointId::new(id)))
                        .collect();
                    let meta = self.meta(&out_f, vec![span.clone()]);
                    self.add(PortEgress {
                        meta,
                        port: pid.clone(),
                        native: native.map(|v| self.bd(v)),
                        tagged: tagged.iter().map(|v| (self.bd(*v), *v)).collect(),
                        peer: None,
                        hosts: port_hosts,
                        link: None,
                    });
                    let out_id = match qos_out {
                        Some((policy, l)) => {
                            let f = format!("port/{name}/qos-out");
                            let q = self.qos(&f, policy, *l, &out_f);
                            self.add(q);
                            self.id(&f)
                        }
                        None => self.id(&out_f),
                    };
                    egress.insert(pid.clone(), out_id.clone());
                    let flood_id = if *edge {
                        out_id
                    } else {
                        let f = format!("port/{name}/stp");
                        let s = self.sink(
                            &f,
                            format!("{name}: the spanning tree state of the port is not collected"),
                            span,
                        );
                        self.add(s);
                        self.id(&f)
                    };
                    for v in native.iter().chain(tagged.iter()) {
                        flood
                            .entry(self.bd(*v))
                            .or_default()
                            .push((pid.clone(), flood_id.clone()));
                    }
                }
            }
        }

        // The SVI ports and the hand-off to layer 3.
        let mut links = BTreeMap::new();
        for (name, (v, m, span)) in &svis {
            let pid = PortId::new(format!("svi/{name}"));
            let in_f = format!("svi/{name}/in");
            let out_f = format!("svi/{name}/out");
            let meta = self.meta(&in_f, vec![span.clone()]);
            self.add(PortIngress {
                meta,
                port: pid.clone(),
                native: Some(self.bd(*v)),
                tagged: BTreeMap::new(),
                next: mac_id.clone(),
            });
            let g = gws.get(name).cloned().unwrap_or_default();
            match &g.unknown {
                Some(why) => {
                    let f = self.sink(&out_f, format!("{name}: {why}"), span.clone());
                    self.add(f);
                }
                None => {
                    let handoff = format!("handoff/{name}");
                    let meta = self.meta(&out_f, vec![span.clone()]);
                    self.add(PortEgress {
                        meta,
                        port: pid.clone(),
                        native: Some(self.bd(*v)),
                        tagged: BTreeMap::new(),
                        peer: Some(self.id(&handoff)),
                        hosts: BTreeMap::new(),
                        link: None,
                    });
                    let mut spans = vec![span.clone()];
                    spans.extend(g.active.iter().flat_map(|a| a.2.clone()));
                    let meta = self.meta(&handoff, spans);
                    self.add(Layer3HandOff {
                        meta,
                        macs: std::iter::once(*m)
                            .chain(g.active.iter().map(|a| a.0))
                            .collect(),
                        untagged: Some(self.id(&format!("in/{name}"))),
                        tagged: BTreeMap::new(),
                    });
                }
            }
            let out_id = self.id(&out_f);
            egress.insert(pid.clone(), out_id.clone());
            flood
                .entry(self.bd(*v))
                .or_default()
                .push((pid.clone(), out_id));
            let table = tables.entry(self.bd(*v)).or_default();
            for mac in std::iter::once(*m).chain(g.active.iter().map(|a| a.0)) {
                table.insert(
                    mac,
                    MacEntry {
                        port: pid.clone(),
                        spans: vec![span.clone()],
                    },
                );
            }
            links.insert(name.clone(), (self.id(&in_f), *m));
        }

        // The collected MAC table.
        let mut missing: BTreeSet<u16> = BTreeSet::new();
        for r in &col.macs {
            let (Ok(v), Some(m)) = (u16::try_from(r.vlan), state::mac(&r.mac)) else {
                continue;
            };
            if !vlans.contains(&v) {
                missing.insert(v);
                continue;
            }
            if own.contains(&(v, m)) {
                continue;
            }
            let Some(port) = r.port.as_deref().map(port_of) else {
                continue;
            };
            tables.entry(self.bd(v)).or_default().insert(
                m,
                MacEntry {
                    port: PortId::new(port),
                    spans: vec![r.span.clone()],
                },
            );
        }

        for v in missing {
            self.note(format!(
                "the MAC table has VLAN {v}, which is not in the config"
            ));
        }
        if !plans.is_empty() || !svis.is_empty() {
            let meta = self.meta("mac", Vec::new());
            self.out.functions.push(Arc::new(MacLookup {
                meta,
                tables,
                egress,
                flood: self.id("flood"),
                hairpin: BTreeSet::new(),
                blocked: BTreeMap::new(),
            }));
            let meta = self.meta("flood", Vec::new());
            self.out
                .functions
                .push(Arc::new(Flood { meta, ports: flood }));
        }

        // The endpoints, their attachment records and the host resolution
        // of their ports.
        let mut points: BTreeSet<String> = BTreeSet::new();
        for (id, e) in &endpoints {
            self.out.endpoints.push(Endpoint {
                id: EndpointId::new(id),
                addresses: e.addrs.iter().map(|a| a.0).collect(),
            });
            for (ip, span) in &e.addrs {
                self.out.attachments.push(AttachmentRecord {
                    address: *ip,
                    device: self.dev.into(),
                    interface: InterfaceId::new(&e.port),
                    kind: AttachmentKind::Client,
                    host: id.clone(),
                    provenance: vec![span.clone(), e.mac_span.clone()],
                });
            }
            if !points.insert(e.port.clone()) {
                continue;
            }
            let svi = active.iter().find(|i| svi_vlan(&i.name) == Some(e.vlan));
            let local: Vec<Prefix> = svi
                .into_iter()
                .flat_map(|i| i.addresses.iter())
                .filter_map(|a| iface_addr(&a.prefix))
                .filter(|(_, len)| *len < 32)
                .map(|(a, len)| Prefix::new(a, len))
                .collect();
            let gateway = svi
                .and_then(|i| gws.get(&i.name))
                .and_then(|g| {
                    g.vmac
                        .clone()
                        .or_else(|| g.svi_mac.clone().map(|(m, s)| (m, vec![s])))
                })
                .map(|(mac, spans)| HostMac { mac, spans });
            if gateway.is_none() {
                self.note(format!("{}: no gateway MAC for VLAN {}", e.port, e.vlan));
            }
            let meta = self.meta(&format!("host/{}", e.port), vec![e.mac_span.clone()]);
            let next = self.id(&format!("port/{}/in", e.port));
            self.add(HostResolution {
                meta,
                interface: InterfaceId::new(&e.port),
                hosts: hosts.get(&e.vlan).cloned().unwrap_or_default(),
                local,
                gateway,
                next,
            });
        }
        links
    }
}
