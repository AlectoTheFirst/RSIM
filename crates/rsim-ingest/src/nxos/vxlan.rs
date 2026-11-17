//! The VXLAN tunnel end of an NX-OS switch: the NVE interface, the
//! `vn-segment` lines and the collected NVE sections.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{
    BridgeDomainId, FieldValue, FunctionId, Match, ObjectId, PortId, RulePredicate, SourceSpan,
    VrfId,
};
use rsim_functions::{
    AclMatch, OuterFields, Rule as FRule, RuleAction, Segment, TunnelPeer, VxlanDecap, VxlanEncap,
};

use super::config::{Config, Interface, Lines, Replication};
use super::lower::{L, iface_addr};
use super::profile::{VXLAN_ENTRY, VXLAN_GUIDE, VXLAN_UDP_PORT};
use super::state::State;
use crate::collected::Collected;

/// A layer 2 VNI of the tunnel end.
#[derive(Clone, Debug)]
pub(super) struct L2Vni {
    pub vni: u32,
    pub replication: Replication,
    pub spans: Vec<SourceSpan>,
}

/// The tunnel end of a switch that the lowering makes exact.
#[derive(Clone, Debug)]
pub(super) struct Tunnel {
    /// The name of the NVE interface, for example `nve1`.
    pub nve: String,
    pub source: IpAddr,
    pub spans: Vec<SourceSpan>,
    /// The layer 2 VNI of each VLAN.
    pub l2: BTreeMap<u16, L2Vni>,
    /// The peer tunnel ends that are up, or why they are not known.
    pub peers: Result<Vec<(IpAddr, SourceSpan)>, String>,
}

/// The plan of the tunnel end of a switch.
#[derive(Clone, Debug)]
pub(super) enum Plan {
    /// The switch has no tunnel end that forwards.
    None,
    Exact(Tunnel),
    /// The tunnel end exists, and the lowering cannot make it exact.
    Unknown {
        nve: String,
        why: String,
        lines: Lines,
    },
}

/// The plan of the tunnel end from the config, the collected state and the
/// active layer 3 interfaces.
pub(super) fn plan(cfg: &Config, st: &State, active: &[Interface], l: &mut L<'_>) -> Plan {
    let Some(n) = &cfg.nve else {
        return Plan::None;
    };
    let unknown = |why: String| Plan::Unknown {
        nve: n.name.clone(),
        why,
        lines: n.lines,
    };
    let admin = n
        .admin_up
        .or_else(|| st.interfaces.get(&n.name).and_then(|s| s.admin_up));
    match admin {
        Some(false) => return Plan::None,
        None => return unknown("the admin state of the NVE interface is not known".into()),
        Some(true) => {}
    }
    if !n.unhandled.is_empty() {
        return unknown(format!("options not lowered: {}", n.unhandled.join(", ")));
    }
    if !n.bgp {
        return unknown("a tunnel end with no BGP host reachability is not lowered".into());
    }
    let Some((src, src_lines)) = &n.source else {
        return unknown("the NVE interface has no source interface".into());
    };
    let source = active
        .iter()
        .find(|i| i.name.eq_ignore_ascii_case(src))
        .and_then(|i| {
            i.addresses
                .iter()
                .find(|a| !a.secondary)
                .and_then(|a| iface_addr(&a.prefix))
        });
    let Some((source, _)) = source else {
        return unknown(format!("the source interface {src} has no active address"));
    };
    let mut spans = vec![l.span(n.lines), l.span(*src_lines)];
    if let Some(i) = active.iter().find(|i| i.name.eq_ignore_ascii_case(src)) {
        spans.push(l.span(i.lines));
    }
    let by_vni: BTreeMap<u32, (u16, Lines)> = cfg
        .segments
        .iter()
        .map(|(v, (vni, lines))| (*vni, (*v, *lines)))
        .collect();
    let mut l2 = BTreeMap::new();
    for m in n.members.iter().filter(|m| !m.l3) {
        let Some((vlan, seg_lines)) = by_vni.get(&m.vni) else {
            l.note(format!("VNI {}: no VLAN has it as its vn-segment", m.vni));
            continue;
        };
        let mut vspans = vec![l.span(m.lines), l.span(*seg_lines)];
        if let Some(vnis) = &st.nve_vnis {
            let vnis = match vnis {
                Ok(v) => v,
                Err(why) => return unknown(why.clone()),
            };
            match vnis.iter().find(|r| r.vni == m.vni) {
                Some(r) if r.up == Some(true) => vspans.push(r.span.clone()),
                Some(r) if r.up.is_none() => {
                    return unknown(format!("the state of VNI {} is not known", m.vni));
                }
                Some(_) => {
                    l.note(format!("VNI {}: the collected state is not up", m.vni));
                    continue;
                }
                None => {
                    l.note(format!("VNI {}: not in the collected VNIs", m.vni));
                    continue;
                }
            }
        }
        let replication = match (&m.replication, &n.global) {
            (Replication::Unstated, Some(g)) => g.clone(),
            (r, _) => r.clone(),
        };
        l2.insert(
            *vlan,
            L2Vni {
                vni: m.vni,
                replication,
                spans: vspans,
            },
        );
    }
    if st.nve_vnis.is_none() {
        l.note("no NVE VNI section, so each member VNI counts as up".into());
    }
    let peers = match &st.nve_peers {
        None => Err("no NVE peer section, so the peers of the flood are not known".to_string()),
        Some(Err(why)) => Err(why.clone()),
        Some(Ok(ps)) => match ps.iter().find(|p| p.up.is_none()) {
            Some(p) => Err(format!(
                "the state of the NVE peer {} is not known",
                p.address
            )),
            None => Ok(ps
                .iter()
                .filter(|p| p.up == Some(true))
                .map(|p| (p.address, p.span.clone()))
                .collect()),
        },
    };
    Plan::Exact(Tunnel {
        nve: n.name.clone(),
        source,
        spans,
        l2,
        peers,
    })
}

/// The tunnel facts of the switch for the link join: the address of the
/// source interface, the peers of the NVE section and of the MAC table, and
/// the layer 2 VNI of each VLAN. `None` with no NVE interface or with one
/// that is shut down.
pub(super) fn summary(
    cfg: &Config,
    st: &State,
    active: &[Interface],
    col: &Collected,
) -> Option<crate::links::TunnelSummary> {
    let n = cfg.nve.as_ref()?;
    if n.admin_up == Some(false) {
        return None;
    }
    let address = n.source.as_ref().and_then(|(src, _)| {
        let i = active.iter().find(|i| i.name.eq_ignore_ascii_case(src))?;
        let a = i.addresses.iter().find(|a| !a.secondary)?;
        iface_addr(&a.prefix).map(|x| x.0)
    });
    let mut peers: BTreeSet<IpAddr> = st
        .nve_peers
        .iter()
        .flatten()
        .flatten()
        .filter(|p| p.up != Some(false))
        .map(|p| p.address)
        .collect();
    peers.extend(
        col.macs
            .iter()
            .filter_map(|r| tunnel_port(&n.name, r.port.as_deref()?)),
    );
    let by_vni: BTreeMap<u32, u16> = cfg
        .segments
        .iter()
        .map(|(v, (vni, _))| (*vni, *v))
        .collect();
    let segments = n
        .members
        .iter()
        .filter(|m| !m.l3)
        .filter_map(|m| Some((*by_vni.get(&m.vni)?, m.vni)))
        .collect();
    Some(crate::links::TunnelSummary {
        address,
        peers,
        segments,
    })
}

/// The peer tunnel end of a MAC table port such as `nve1(192.0.2.2)`.
pub(super) fn tunnel_port(nve: &str, port: &str) -> Option<IpAddr> {
    let rest = port.strip_prefix(nve)?;
    rest.strip_prefix('(')?
        .strip_suffix(')')?
        .trim()
        .parse()
        .ok()
}

/// True for the name of a tunnel port of the NVE interface `nve`: the
/// interface itself or a port with a peer.
fn is_tunnel(nve: &str, port: &str) -> bool {
    port == nve || tunnel_port(nve, port).is_some()
}

/// The functions of the tunnel end in the layer 2 part, with the ports of
/// the tunnel in the flood of each VLAN.
pub(super) struct Layer2 {
    /// The egress function of each tunnel port.
    pub egress: BTreeMap<PortId, FunctionId>,
    /// The tunnel ports of the flood of each bridge domain.
    pub flood: BTreeMap<BridgeDomainId, Vec<(PortId, FunctionId)>>,
}

impl L<'_> {
    fn deny(&mut self, f: &str, why: &str, span: SourceSpan) {
        let rule = FRule::new(why, RulePredicate::exact(Match::any()), RuleAction::Deny)
            .with_span(span.clone());
        let acl = ObjectId::new(format!("{}:{f}", self.dev));
        self.add(AclMatch {
            meta: self.meta(f, vec![span]),
            acl,
            rules: vec![rule],
            default: RuleAction::Deny,
            next: self.id(f),
        });
    }

    /// The encapsulation and the flood copies of the tunnel end. `bd` gives
    /// the bridge domain of a VLAN.
    pub(super) fn vxlan_layer2(
        &mut self,
        plan: &Plan,
        col: &Collected,
        bd: &dyn Fn(u16) -> BridgeDomainId,
    ) -> Layer2 {
        let mut out = Layer2 {
            egress: BTreeMap::new(),
            flood: BTreeMap::new(),
        };
        match plan {
            Plan::None => {}
            Plan::Unknown { nve, why, lines } => {
                let f = "vxlan/unknown";
                let s = self.sink(f, format!("{nve}: {why}"), self.span(*lines));
                self.add(s);
                let id = self.id(f);
                for r in &col.macs {
                    if let Some(p) = r.port.as_deref().filter(|p| is_tunnel(nve, p)) {
                        out.egress.insert(PortId::new(p), id.clone());
                    }
                }
                for v in self.cfg.segments.keys() {
                    out.flood
                        .entry(bd(*v))
                        .or_default()
                        .push((PortId::new(nve), id.clone()));
                }
            }
            Plan::Exact(t) => {
                let vnis: BTreeMap<Segment, u32> =
                    t.l2.iter()
                        .map(|(v, x)| (Segment::BridgeDomain(bd(*v)), x.vni))
                        .collect();
                let mut peers: BTreeSet<IpAddr> = col
                    .macs
                    .iter()
                    .filter_map(|r| tunnel_port(&t.nve, r.port.as_deref()?))
                    .collect();
                peers.extend(t.peers.iter().flatten().map(|p| p.0));
                for peer in &peers {
                    let f = format!("vxlan/encap/{peer}");
                    let mut spans = t.spans.clone();
                    if let Some((_, s)) = t.peers.iter().flatten().find(|p| p.0 == *peer) {
                        spans.push(s.clone());
                    }
                    let meta = self.meta(&f, spans);
                    let next = self.id(VXLAN_ENTRY);
                    self.add(VxlanEncap {
                        meta,
                        source: t.source,
                        peer: TunnelPeer::Fixed(*peer),
                        vnis: vnis.clone(),
                        outer: outer(),
                        underlay: VrfId::new(super::lower::DEFAULT_VRF),
                        next,
                    });
                    out.egress
                        .insert(PortId::new(format!("{}({peer})", t.nve)), self.id(&f));
                }
                for (v, x) in &t.l2 {
                    let copies: Vec<(PortId, FunctionId)> = match (&x.replication, &t.peers) {
                        (Replication::Ingress, Ok(ps)) => ps
                            .iter()
                            .map(|(p, _)| {
                                (
                                    PortId::new(format!("{}({p})", t.nve)),
                                    self.id(&format!("vxlan/encap/{p}")),
                                )
                            })
                            .collect(),
                        (rep, peers) => {
                            let why = match rep {
                                Replication::Ingress => peers.clone().err().unwrap_or_default(),
                                Replication::Multicast(g) => {
                                    format!("the flood to the multicast group {g} is not lowered")
                                }
                                Replication::Unstated => {
                                    format!("VNI {}: the replication is not stated", x.vni)
                                }
                            };
                            let f = format!("vxlan/flood/vlan{v}");
                            let span = x
                                .spans
                                .first()
                                .cloned()
                                .unwrap_or_else(|| self.span(Lines::default()));
                            let s = self.sink(&f, why, span);
                            self.add(s);
                            vec![(PortId::new(&t.nve), self.id(&f))]
                        }
                    };
                    out.flood.entry(bd(*v)).or_default().extend(copies);
                }
            }
        }
        out
    }

    /// The MAC lookup and the flood of a frame out of the tunnel: a frame
    /// does not go back into the tunnel. Gives the decapsulation of the
    /// tunnel end, or `None` if the switch has no tunnel end.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn vxlan_split_horizon(
        &mut self,
        plan: &Plan,
        tables: &BTreeMap<BridgeDomainId, BTreeMap<rsim_core::Mac, rsim_functions::MacEntry>>,
        egress: &BTreeMap<PortId, FunctionId>,
        flood: &BTreeMap<BridgeDomainId, Vec<(PortId, FunctionId)>>,
        bd: &dyn Fn(u16) -> BridgeDomainId,
    ) {
        let Plan::Exact(t) = plan else {
            return;
        };
        if t.l2.is_empty() {
            return;
        }
        let f = "vxlan/split-horizon";
        self.deny(
            f,
            "a frame out of the tunnel does not go back into it",
            t.spans[0].clone(),
        );
        let deny = self.id(f);
        let egress_t: BTreeMap<PortId, FunctionId> = egress
            .iter()
            .map(|(p, id)| {
                if is_tunnel(&t.nve, p.as_str()) {
                    (p.clone(), deny.clone())
                } else {
                    (p.clone(), id.clone())
                }
            })
            .collect();
        let flood_t: BTreeMap<BridgeDomainId, Vec<(PortId, FunctionId)>> =
            t.l2.keys()
                .map(|v| {
                    let ports = flood
                        .get(&bd(*v))
                        .map(|ps| {
                            ps.iter()
                                .filter(|(p, _)| !is_tunnel(&t.nve, p.as_str()))
                                .cloned()
                                .collect()
                        })
                        .unwrap_or_default();
                    (bd(*v), ports)
                })
                .collect();
        let meta = self.meta("mac-tunnel", t.spans.clone());
        self.add(rsim_functions::MacLookup {
            meta,
            tables: tables.clone(),
            egress: egress_t,
            flood: self.id("flood-tunnel"),
            hairpin: BTreeSet::new(),
            blocked: BTreeMap::new(),
        });
        let meta = self.meta("flood-tunnel", t.spans.clone());
        self.add(rsim_functions::Flood {
            meta,
            ports: flood_t,
        });
    }

    /// The decapsulation at the local delivery of the switch, or `None` if
    /// the switch has no tunnel end. `local` is the function of the other
    /// packets to the switch.
    pub(super) fn vxlan_decap(
        &mut self,
        plan: &Plan,
        local: &str,
        bd: &dyn Fn(u16) -> BridgeDomainId,
    ) -> Option<FunctionId> {
        let (vnis, unmatched, spans, port) = match plan {
            Plan::None => return None,
            Plan::Unknown { nve, why, lines } => (
                BTreeMap::new(),
                Some(format!("{nve}: {why}")),
                vec![self.span(*lines)],
                None,
            ),
            Plan::Exact(t) => (
                t.l2.iter()
                    .map(|(v, x)| {
                        (
                            x.vni,
                            (Segment::BridgeDomain(bd(*v)), self.id("mac-tunnel")),
                        )
                    })
                    .collect(),
                None,
                t.spans.clone(),
                Some(PortId::new(&t.nve)),
            ),
        };
        let mut spans = spans;
        spans.push(SourceSpan::line(VXLAN_GUIDE, 1));
        let meta = self.meta("vxlan-decap", spans);
        let plain = Some(self.id(local));
        self.add(VxlanDecap {
            meta,
            vnis,
            plain,
            port,
            unmatched,
        });
        Some(self.id("vxlan-decap"))
    }
}

/// The outer fields of a VXLAN packet of NX-OS.
fn outer() -> OuterFields {
    OuterFields {
        udp_port: VXLAN_UDP_PORT,
        src_port: FieldValue::Unknown,
        dscp: FieldValue::Unknown,
        ecn: FieldValue::Unknown,
    }
}
