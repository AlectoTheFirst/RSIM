//! Layer 2: host resolution, port ingress, wireless attachment, MAC lookup,
//! flood, port egress and the hand-off to a router.

use std::collections::{BTreeMap, BTreeSet};

use rsim_core::{
    AddrField, Alternative, Attr, Branch, BridgeDomainId, Context, ContextAttr, Dependency,
    Destination, EndpointId, FieldValue, FloodCopy, FlowState, FunctionId, FunctionKind,
    InterfaceId, Mac, MacCond, Match, NetFunction, Outcome, PacketSet, PortCond, PortId, Prefix,
    PrefixTable, Reason, ReasonCode, Rewrite, RulePredicate, SourceSpan, TriePrefixTable,
};

use crate::common::{Meta, push_nonempty};
use crate::forwarding::meta_methods;

/// The physical facts of one end of a link: the speed, the duplex and the
/// media of the port, from collected state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkEnd {
    pub speed_mbps: Option<u64>,
    pub full_duplex: Option<bool>,
    /// The media, for example `GE` or `SFP+`.
    pub media: Option<String>,
    pub spans: Vec<SourceSpan>,
}

impl LinkEnd {
    fn text(&self) -> String {
        let mut v = Vec::new();
        v.push(match self.speed_mbps {
            Some(s) => format!("{s} Mbit/s"),
            None => "speed not known".to_string(),
        });
        match self.full_duplex {
            Some(true) => v.push("full duplex".into()),
            Some(false) => v.push("half duplex".into()),
            None => {}
        }
        if let Some(m) = &self.media {
            v.push(m.clone());
        }
        v.join(" ")
    }
}

/// The physical facts of a link: the local end and, if it is known, the
/// remote end.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkFacts {
    pub local: LinkEnd,
    pub remote: Option<LinkEnd>,
}

impl LinkFacts {
    /// The facts as text for a trace step, with a mismatch of the 2 ends.
    pub fn text(&self) -> String {
        let mut t = format!("link {}", self.local.text());
        if let Some(r) = &self.remote {
            t.push_str(&format!(" to {}", r.text()));
            if let (Some(a), Some(b)) = (self.local.speed_mbps, r.speed_mbps)
                && a != b
            {
                t.push_str(", speed mismatch");
            }
            if let (Some(a), Some(b)) = (self.local.full_duplex, r.full_duplex)
                && a != b
            {
                t.push_str(", duplex mismatch");
            }
        }
        if self.local.full_duplex == Some(false) {
            t.push_str(", half duplex");
        }
        t
    }

    /// The provenance of both ends.
    pub fn spans(&self) -> Vec<SourceSpan> {
        let mut v = self.local.spans.clone();
        if let Some(r) = &self.remote {
            v.extend(r.spans.iter().cloned());
        }
        v
    }
}

/// The broadcast MAC address.
pub const BROADCAST: Mac = Mac([0xff; 6]);

fn exact(m: Match) -> RulePredicate {
    RulePredicate::exact(m)
}

fn vlan_is(v: u16) -> RulePredicate {
    exact(Match {
        vlan: PortCond::In(vec![(v, v)]),
        ..Match::any()
    })
}

fn any_tag() -> RulePredicate {
    exact(Match {
        vlan: PortCond::In(vec![(0, 4095)]),
        ..Match::any()
    })
}

fn dst_mac_is(m: Mac) -> RulePredicate {
    exact(Match {
        dst_mac: MacCond::In(BTreeSet::from([m])),
        ..Match::any()
    })
}

/// The branches of a layer 2 function: the function runs on the frames
/// with no inner VLAN tag, and a frame with an inner tag is unknown.
fn with_inner_tag(
    meta: &Meta,
    input: &PacketSet,
    ctx: &Context,
    state: &FlowState,
    f: impl FnOnce(&PacketSet) -> Vec<Branch>,
) -> Vec<Branch> {
    let (inner, rest) = input.split_inner_vlan();
    if inner.is_empty() {
        return f(input);
    }
    let mut out = if rest.is_empty() {
        Vec::new()
    } else {
        f(&rest)
    };
    out.push(meta.unknown(
        inner,
        ReasonCode::UnknownAttribute,
        "2 VLAN tags, device behaviour not known",
        ctx,
        state,
    ));
    out
}

/// A MAC with its provenance and the packets that it applies to.
type Resolved = (Mac, Vec<SourceSpan>, PacketSet);

/// A host with its MAC address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostMac {
    pub mac: Mac,
    pub spans: Vec<SourceSpan>,
}

/// The attachment point of hosts on a port or an SSID. It sets the source
/// MAC from the source address and the destination MAC from the destination
/// address: the MAC of a host on a local network, or else the MAC of the
/// gateway. The frame leaves the host without a tag.
#[derive(Clone, Debug)]
pub struct HostResolution {
    pub meta: Meta,
    /// The attachment point, for example `port/15` or `wlan/office`.
    pub interface: InterfaceId,
    /// The MAC of each known host address.
    pub hosts: TriePrefixTable<HostMac>,
    /// The networks of the attachment point.
    pub local: Vec<Prefix>,
    /// The MAC of the gateway of the attachment point.
    pub gateway: Option<HostMac>,
    pub next: FunctionId,
}

impl HostResolution {
    fn by_address(
        &self,
        field: AddrField,
        input: &PacketSet,
    ) -> (Vec<Resolved>, PacketSet, PacketSet) {
        let part = input.partition_by_prefix(field, &self.hosts);
        let found = part
            .matched
            .into_iter()
            .map(|(_, h, s)| (h.mac, h.spans.clone(), s))
            .collect();
        (found, part.unmatched, part.uncertain)
    }
}

impl NetFunction for HostResolution {
    meta_methods!(FunctionKind::Ingress);

    fn each_span(&self, f: &mut dyn FnMut(&rsim_core::SourceSpan)) {
        for s in &self.meta.provenance {
            f(s);
        }
        for (_, h) in self.hosts.entries() {
            for s in &h.spans {
                f(s);
            }
        }
        for s in self.gateway.iter().flat_map(|g| &g.spans) {
            f(s);
        }
    }

    fn ingress_interface(&self) -> Option<&InterfaceId> {
        Some(&self.interface)
    }
    fn requires(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::Device, ContextAttr::IngressInterface]
    }
    fn reads(&self) -> Vec<Dependency> {
        Vec::new()
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        with_inner_tag(&self.meta, input, ctx, state, |input| {
            let mut c = ctx.clone();
            c.device = Attr::Known(self.meta.device.clone());
            c.ingress_interface = Attr::Known(self.interface.clone());
            let mut out = Vec::new();
            let unknown = |set: PacketSet, detail: String, out: &mut Vec<Branch>| {
                push_nonempty(
                    out,
                    self.meta
                        .unknown(set, ReasonCode::UnknownAttribute, detail, &c, state),
                );
            };
            let (sources, src_none, src_unc) = self.by_address(AddrField::Src, input);
            unknown(src_none, "no MAC of the source address".into(), &mut out);
            unknown(src_unc, "source address not known".into(), &mut out);
            for (src_mac, src_spans, set) in sources {
                let local: TriePrefixTable<()> = {
                    let mut t = TriePrefixTable::new();
                    for p in &self.local {
                        t.insert(*p, ());
                    }
                    t
                };
                let part = set.partition_by_prefix(AddrField::Dst, &local);
                unknown(
                    part.uncertain,
                    "destination address not known".into(),
                    &mut out,
                );
                let mut targets: Vec<(Mac, Vec<SourceSpan>, PacketSet, String)> = Vec::new();
                for (_, _, on_link) in part.matched {
                    let (dst, none, unc) = self.by_address(AddrField::Dst, &on_link);
                    unknown(none, "no MAC of the local destination".into(), &mut out);
                    unknown(unc, "destination address not known".into(), &mut out);
                    targets.extend(
                        dst.into_iter()
                            .map(|(m, s, p)| (m, s, p, "the host".to_string())),
                    );
                }
                match &self.gateway {
                    Some(g) => targets.push((
                        g.mac,
                        g.spans.clone(),
                        part.unmatched,
                        "the gateway".to_string(),
                    )),
                    None => unknown(part.unmatched, "no gateway".into(), &mut out),
                }
                for (dst_mac, dst_spans, set, what) in targets {
                    let rw = Rewrite {
                        src_mac: Some(FieldValue::Known(src_mac)),
                        dst_mac: Some(FieldValue::Known(dst_mac)),
                        ..Rewrite::default()
                    };
                    let mut b = self.meta.forward(
                        set.rewrite(&rw).set_vlan(None),
                        &self.next,
                        ReasonCode::Resolved,
                        format!("from {src_mac:?} to {what} {dst_mac:?}"),
                        c.clone(),
                        state,
                    );
                    b.spans = src_spans.iter().chain(&dst_spans).cloned().collect();
                    push_nonempty(&mut out, b);
                }
            }
            out
        })
    }
}

/// The attachment point of a host whose place is not known, for example a
/// client of the controller whose network is not the network of its port.
/// Each packet from the host is unknown.
#[derive(Clone, Debug)]
pub struct Unplaced {
    pub meta: Meta,
    /// The attachment point, for example `unplaced/h1-005351`.
    pub interface: InterfaceId,
    /// Why the host is not placed.
    pub detail: String,
}

impl NetFunction for Unplaced {
    meta_methods!(FunctionKind::Ingress);

    fn ingress_interface(&self) -> Option<&InterfaceId> {
        Some(&self.interface)
    }
    fn requires(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::Device, ContextAttr::IngressInterface]
    }
    fn reads(&self) -> Vec<Dependency> {
        Vec::new()
    }
    fn successors(&self) -> Vec<FunctionId> {
        Vec::new()
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let mut c = ctx.clone();
        c.device = Attr::Known(self.meta.device.clone());
        c.ingress_interface = Attr::Known(self.interface.clone());
        let mut out = Vec::new();
        push_nonempty(
            &mut out,
            self.meta.unknown(
                input.clone(),
                ReasonCode::UnknownAttribute,
                self.detail.clone(),
                &c,
                state,
            ),
        );
        out
    }
}

/// A frame enters a switch port. It sets the ingress port and the bridge
/// domain from the tag of the frame.
#[derive(Clone, Debug)]
pub struct PortIngress {
    pub meta: Meta,
    pub port: PortId,
    /// The bridge domain of an untagged frame.
    pub native: Option<BridgeDomainId>,
    /// The bridge domain of each tag.
    pub tagged: BTreeMap<u16, BridgeDomainId>,
    pub next: FunctionId,
}

impl NetFunction for PortIngress {
    meta_methods!(FunctionKind::PortIngress);

    fn requires(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::IngressPort, ContextAttr::BridgeDomain]
    }
    fn reads(&self) -> Vec<Dependency> {
        Vec::new()
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        with_inner_tag(&self.meta, input, ctx, state, |input| {
            let mut out = Vec::new();
            let mut c = ctx.clone();
            c.device = Attr::Known(self.meta.device.clone());
            c.ingress_port = Attr::Known(self.port.clone());
            let to = |set: PacketSet, bd: &BridgeDomainId, tag: String, out: &mut Vec<Branch>| {
                let mut c = c.clone();
                c.bridge_domain = Attr::Known(bd.clone());
                push_nonempty(
                    out,
                    self.meta.forward(
                        set,
                        &self.next,
                        ReasonCode::Classified,
                        format!("port {} {tag}, bridge domain {bd}", self.port),
                        c,
                        state,
                    ),
                );
            };
            let mut rest = input.clone();
            for (v, bd) in &self.tagged {
                let s = rest.split(&vlan_is(*v));
                to(s.matched, bd, format!("VLAN {v}"), &mut out);
                rest = s.unmatched.union(&s.uncertain);
            }
            let s = rest.split(&any_tag());
            push_nonempty(
                &mut out,
                self.meta.drop(
                    s.matched,
                    ReasonCode::Denied,
                    format!("VLAN not on port {}", self.port),
                    &c,
                    state,
                ),
            );
            push_nonempty(
                &mut out,
                self.meta.unknown(
                    s.uncertain,
                    ReasonCode::UnknownAttribute,
                    "frame tag not known",
                    &c,
                    state,
                ),
            );
            match &self.native {
                Some(bd) => to(s.unmatched, bd, "untagged".into(), &mut out),
                None => push_nonempty(
                    &mut out,
                    self.meta.drop(
                        s.unmatched,
                        ReasonCode::Denied,
                        format!("no native VLAN on port {}", self.port),
                        &c,
                        state,
                    ),
                ),
            }
            out
        })
    }
}

/// A wireless client joins the bridge domain of its SSID.
#[derive(Clone, Debug)]
pub struct WirelessAttachment {
    pub meta: Meta,
    /// The SSID as a port, for example `wlan/office`.
    pub port: PortId,
    pub bridge_domain: BridgeDomainId,
    pub next: FunctionId,
}

impl NetFunction for WirelessAttachment {
    meta_methods!(FunctionKind::WirelessAttachment);

    fn requires(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::IngressPort, ContextAttr::BridgeDomain]
    }
    fn reads(&self) -> Vec<Dependency> {
        Vec::new()
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        with_inner_tag(&self.meta, input, ctx, state, |input| {
            let mut c = ctx.clone();
            c.device = Attr::Known(self.meta.device.clone());
            c.ingress_port = Attr::Known(self.port.clone());
            c.bridge_domain = Attr::Known(self.bridge_domain.clone());
            vec![self.meta.forward(
                input.clone(),
                &self.next,
                ReasonCode::Classified,
                format!("{}, bridge domain {}", self.port, self.bridge_domain),
                c,
                state,
            )]
        })
    }
}

/// An entry of a MAC table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacEntry {
    pub port: PortId,
    pub spans: Vec<SourceSpan>,
}

/// Looks up the destination MAC in the bridge domain. A broadcast or an
/// unknown MAC goes to the flood. A frame to its own ingress port is
/// dropped, except on a hairpin port such as an SSID, where the clients
/// share one port.
#[derive(Clone, Debug)]
pub struct MacLookup {
    pub meta: Meta,
    pub tables: BTreeMap<BridgeDomainId, BTreeMap<Mac, MacEntry>>,
    /// The egress function of each port.
    pub egress: BTreeMap<PortId, FunctionId>,
    pub flood: FunctionId,
    /// The ports that can send a frame back out of the port it came in on.
    pub hairpin: BTreeSet<PortId>,
    /// The MACs that the frames of an ingress port cannot reach, for
    /// example the clients of an SSID with client isolation.
    pub blocked: BTreeMap<PortId, BTreeSet<Mac>>,
}

impl NetFunction for MacLookup {
    meta_methods!(FunctionKind::MacLookup);

    fn each_span(&self, f: &mut dyn FnMut(&rsim_core::SourceSpan)) {
        for s in &self.meta.provenance {
            f(s);
        }
        for s in self
            .tables
            .values()
            .flat_map(|t| t.values())
            .flat_map(|e| &e.spans)
        {
            f(s);
        }
    }

    fn requires(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::BridgeDomain]
    }
    fn provides(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn reads(&self) -> Vec<Dependency> {
        Vec::new()
    }
    fn successors(&self) -> Vec<FunctionId> {
        let mut v: Vec<FunctionId> = self.egress.values().cloned().collect();
        v.push(self.flood.clone());
        v.sort();
        v.dedup();
        v
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        with_inner_tag(&self.meta, input, ctx, state, |input| {
            let Some(bd) = ctx.bridge_domain.known() else {
                return vec![self.meta.unknown(
                    input.clone(),
                    ReasonCode::UnknownAttribute,
                    "bridge domain not known",
                    ctx,
                    state,
                )];
            };
            let mut out = Vec::new();
            let mut rest = input.clone();
            let mut unclear = input.empty();
            if let Some(table) = self.tables.get(bd) {
                for (mac, e) in table {
                    if rest.is_empty() {
                        break;
                    }
                    let s = rest.split(&dst_mac_is(*mac));
                    rest = s.unmatched;
                    unclear = unclear.union(&s.uncertain);
                    if s.matched.is_empty() {
                        continue;
                    }
                    let inport = ctx.ingress_port.known();
                    let isolated = inport
                        .and_then(|p| self.blocked.get(p))
                        .is_some_and(|m| m.contains(mac));
                    let b = if isolated {
                        self.meta.drop(
                            s.matched,
                            ReasonCode::Denied,
                            format!(
                                "{mac:?} isolated from port {}",
                                inport.expect("an isolated port is known")
                            ),
                            ctx,
                            state,
                        )
                    } else if inport == Some(&e.port) && !self.hairpin.contains(&e.port) {
                        self.meta.drop(
                            s.matched,
                            ReasonCode::Denied,
                            format!("{mac:?} on ingress port {}", e.port),
                            ctx,
                            state,
                        )
                    } else if let Some(next) = self.egress.get(&e.port) {
                        self.meta.forward(
                            s.matched,
                            next,
                            ReasonCode::Resolved,
                            format!("{mac:?} on port {}, bridge domain {bd}", e.port),
                            ctx.clone(),
                            state,
                        )
                    } else {
                        self.meta.unknown(
                            s.matched,
                            ReasonCode::IncompleteTable,
                            format!("no egress function of port {}", e.port),
                            ctx,
                            state,
                        )
                    };
                    push_nonempty(&mut out, b.with_spans(e.spans.clone()));
                }
            }
            push_nonempty(
                &mut out,
                self.meta.forward(
                    rest,
                    &self.flood,
                    ReasonCode::Classified,
                    format!("broadcast or unknown MAC, bridge domain {bd}"),
                    ctx.clone(),
                    state,
                ),
            );
            push_nonempty(
                &mut out,
                self.meta.unknown(
                    unclear,
                    ReasonCode::UnknownAttribute,
                    "destination MAC not known",
                    ctx,
                    state,
                ),
            );
            out
        })
    }
}

/// Sends one copy of the frames to each forwarding port of the bridge
/// domain, except the ingress port.
#[derive(Clone, Debug)]
pub struct Flood {
    pub meta: Meta,
    /// The forwarding ports of each bridge domain with their egress
    /// function, in port order.
    pub ports: BTreeMap<BridgeDomainId, Vec<(PortId, FunctionId)>>,
}

impl NetFunction for Flood {
    meta_methods!(FunctionKind::Flood);

    fn requires(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::BridgeDomain]
    }
    fn provides(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn reads(&self) -> Vec<Dependency> {
        Vec::new()
    }
    fn successors(&self) -> Vec<FunctionId> {
        let mut v: Vec<FunctionId> = self
            .ports
            .values()
            .flat_map(|p| p.iter().map(|x| x.1.clone()))
            .collect();
        v.sort();
        v.dedup();
        v
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        with_inner_tag(&self.meta, input, ctx, state, |input| {
            let Some(bd) = ctx.bridge_domain.known() else {
                return vec![self.meta.unknown(
                    input.clone(),
                    ReasonCode::UnknownAttribute,
                    "bridge domain not known",
                    ctx,
                    state,
                )];
            };
            let ports: Vec<&(PortId, FunctionId)> = self
                .ports
                .get(bd)
                .map(|v| {
                    v.iter()
                        .filter(|(p, _)| ctx.ingress_port.known() != Some(p))
                        .collect()
                })
                .unwrap_or_default();
            if ports.is_empty() {
                return vec![self.meta.drop(
                    input.clone(),
                    ReasonCode::Denied,
                    format!("no other forwarding port, bridge domain {bd}"),
                    ctx,
                    state,
                )];
            }
            let count = u32::try_from(ports.len()).expect("too many ports");
            ports
                .iter()
                .enumerate()
                .map(|(i, (port, next))| {
                    let mut b = self.meta.forward(
                        input.clone(),
                        next,
                        ReasonCode::Classified,
                        format!("flood copy to port {port}, bridge domain {bd}"),
                        ctx.clone(),
                        state,
                    );
                    b.flood_copy = Some(FloodCopy {
                        flood: self.meta.id.clone(),
                        key: String::new(),
                        port: port.clone(),
                        index: u32::try_from(i).expect("too many ports"),
                        count,
                    });
                    b
                })
                .collect()
        })
    }
}

/// The far end of the link of a switch port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortPeer {
    /// The ingress function of the far end.
    pub target: FunctionId,
    /// The physical facts of the link.
    pub link: Option<LinkFacts>,
}

/// A frame leaves a switch port. It sets the tag of the bridge domain, then
/// goes to the peer of the link, or to the host with its destination MAC.
/// A port with more than one peer, for example a port channel to 2 switches,
/// is a forwarding choice: one alternative for each peer, in the order of
/// the target.
#[derive(Clone, Debug)]
pub struct PortEgress {
    pub meta: Meta,
    pub port: PortId,
    pub native: Option<BridgeDomainId>,
    /// The tag of each tagged bridge domain.
    pub tagged: BTreeMap<BridgeDomainId, u16>,
    /// The peers of the link of the port.
    pub peers: Vec<PortPeer>,
    /// The hosts on the port.
    pub hosts: BTreeMap<Mac, EndpointId>,
}

impl NetFunction for PortEgress {
    meta_methods!(FunctionKind::PortEgress);

    fn each_span(&self, f: &mut dyn FnMut(&rsim_core::SourceSpan)) {
        for s in &self.meta.provenance {
            f(s);
        }
        for l in self.peers.iter().filter_map(|p| p.link.as_ref()) {
            for s in l
                .local
                .spans
                .iter()
                .chain(l.remote.iter().flat_map(|r| &r.spans))
            {
                f(s);
            }
        }
    }

    fn requires(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::BridgeDomain]
    }
    fn provides(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn reads(&self) -> Vec<Dependency> {
        Vec::new()
    }
    fn successors(&self) -> Vec<FunctionId> {
        self.peers.iter().map(|p| p.target.clone()).collect()
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        with_inner_tag(&self.meta, input, ctx, state, |input| {
            let Some(bd) = ctx.bridge_domain.known() else {
                return vec![self.meta.unknown(
                    input.clone(),
                    ReasonCode::UnknownAttribute,
                    "bridge domain not known",
                    ctx,
                    state,
                )];
            };
            let tag = if self.native.as_ref() == Some(bd) {
                None
            } else if let Some(v) = self.tagged.get(bd) {
                Some(*v)
            } else {
                return vec![self.meta.drop(
                    input.clone(),
                    ReasonCode::Denied,
                    format!("bridge domain {bd} not on port {}", self.port),
                    ctx,
                    state,
                )];
            };
            let set = input.set_vlan(tag);
            let shown = match tag {
                Some(v) => format!("VLAN {v}"),
                None => "untagged".to_string(),
            };
            if !self.peers.is_empty() {
                let mut peers: Vec<&PortPeer> = self.peers.iter().collect();
                peers.sort_by(|a, b| a.target.cmp(&b.target));
                let count = u32::try_from(peers.len()).expect("too many peers");
                let mut out = Vec::new();
                for (i, p) in peers.into_iter().enumerate() {
                    let facts = p
                        .link
                        .as_ref()
                        .map_or(String::new(), |l| format!(", {}", l.text()));
                    let mut b = self.meta.forward(
                        set.clone(),
                        &p.target,
                        ReasonCode::LinkHandOff,
                        format!("leave port {} {shown} to {}{facts}", self.port, p.target),
                        ctx.clone(),
                        state,
                    );
                    let spans = p.link.as_ref().map(LinkFacts::spans).unwrap_or_default();
                    b = b.with_spans(spans);
                    if count > 1 {
                        b = b.with_alternative(Alternative {
                            choice: self.meta.id.clone(),
                            key: self.port.to_string(),
                            index: u32::try_from(i).expect("too many peers"),
                            count,
                            label: p.target.to_string(),
                        });
                    }
                    out.push(b);
                }
                return out;
            }
            // The reply of a host starts on the port, which is also the
            // interface of the attachment point of the host.
            let mut delivered = ctx.clone();
            delivered.device = Attr::Known(self.meta.device.clone());
            delivered.egress_interface = Attr::Known(InterfaceId::new(self.port.to_string()));
            let mut out = Vec::new();
            let mut rest = set;
            for (mac, e) in &self.hosts {
                let s = rest.split(&dst_mac_is(*mac));
                rest = s.unmatched.union(&s.uncertain);
                push_nonempty(
                    &mut out,
                    self.meta.branch(
                        s.matched,
                        Outcome::Deliver(Destination::Endpoint(e.clone())),
                        Reason::new(
                            ReasonCode::Delivered,
                            format!("deliver to {e} on port {} {shown}", self.port),
                        ),
                        delivered.clone(),
                        state,
                    ),
                );
            }
            push_nonempty(
                &mut out,
                self.meta.unknown(
                    rest,
                    ReasonCode::NoLink,
                    format!("no known host or link on port {}", self.port),
                    ctx,
                    state,
                ),
            );
            out
        })
    }
}

/// The router side of a link to a switch. A frame to a MAC of the router
/// goes to the ingress of the router interface of its tag.
#[derive(Clone, Debug)]
pub struct Layer3HandOff {
    pub meta: Meta,
    /// The MACs of the router on the link.
    pub macs: BTreeSet<Mac>,
    /// The ingress function of the interface of an untagged frame.
    pub untagged: Option<FunctionId>,
    /// The ingress function of the interface of each tag.
    pub tagged: BTreeMap<u16, FunctionId>,
}

impl NetFunction for Layer3HandOff {
    meta_methods!(FunctionKind::Layer3HandOff);

    fn requires(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn provides(&self) -> Vec<ContextAttr> {
        Vec::new()
    }
    fn reads(&self) -> Vec<Dependency> {
        Vec::new()
    }
    fn successors(&self) -> Vec<FunctionId> {
        let mut v: Vec<FunctionId> = self.tagged.values().cloned().collect();
        v.extend(self.untagged.clone());
        v.sort();
        v.dedup();
        v
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        with_inner_tag(&self.meta, input, ctx, state, |input| {
            let mine = exact(Match {
                dst_mac: MacCond::In(self.macs.clone()),
                ..Match::any()
            });
            let s = input.split(&mine);
            let mut out = Vec::new();
            push_nonempty(
                &mut out,
                self.meta.drop(
                    s.unmatched,
                    ReasonCode::Denied,
                    "destination MAC not a MAC of the router",
                    ctx,
                    state,
                ),
            );
            push_nonempty(
                &mut out,
                self.meta.unknown(
                    s.uncertain,
                    ReasonCode::UnknownAttribute,
                    "destination MAC not known",
                    ctx,
                    state,
                ),
            );
            let mut rest = s.matched;
            let fresh = ctx.cross_device();
            for (v, next) in &self.tagged {
                let t = rest.split(&vlan_is(*v));
                rest = t.unmatched.union(&t.uncertain);
                push_nonempty(
                    &mut out,
                    self.meta.forward(
                        t.matched.set_vlan(None),
                        next,
                        ReasonCode::LinkHandOff,
                        format!("VLAN {v} to {next}"),
                        fresh.clone(),
                        state,
                    ),
                );
            }
            let t = rest.split(&any_tag());
            push_nonempty(
                &mut out,
                self.meta.drop(
                    t.matched,
                    ReasonCode::Denied,
                    "no router interface for the VLAN",
                    ctx,
                    state,
                ),
            );
            push_nonempty(
                &mut out,
                self.meta.unknown(
                    t.uncertain,
                    ReasonCode::UnknownAttribute,
                    "frame tag not known",
                    ctx,
                    state,
                ),
            );
            match &self.untagged {
                Some(next) => push_nonempty(
                    &mut out,
                    self.meta.forward(
                        t.unmatched,
                        next,
                        ReasonCode::LinkHandOff,
                        format!("untagged to {next}"),
                        fresh,
                        state,
                    ),
                ),
                None => push_nonempty(
                    &mut out,
                    self.meta.drop(
                        t.unmatched,
                        ReasonCode::Denied,
                        "no router interface for untagged frames",
                        ctx,
                        state,
                    ),
                ),
            }
            out
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsim_core::{Attr, DeviceId, SetArena, SetSpec};

    #[test]
    fn the_hand_off_keeps_the_qos_class_and_clears_the_rest() {
        let mac = Mac([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]);
        let f = Layer3HandOff {
            meta: Meta {
                id: FunctionId::new("r1/handoff"),
                device: "r1".into(),
                provenance: Vec::new(),
                processing_delay_ns: None,
                profile: "test".into(),
            },
            macs: BTreeSet::from([mac]),
            untagged: None,
            tagged: BTreeMap::from([(20, FunctionId::new("r1/in/eth0.20"))]),
        };
        let spec = SetSpec {
            dst_mac: Some(vec![mac]),
            vlan: Some(vec![(20, 20)]),
            ..SetSpec::default()
        };
        let input = PacketSet::from_spec(&SetArena::standalone(), &spec);
        let ctx = Context {
            device: Attr::Known(DeviceId::new("sw1")),
            traffic_class: Attr::Known(3),
            drop_precedence: Attr::Unknown,
            queue: Attr::Known(2),
            ..Context::default()
        };
        let out = f.apply(&input, &ctx, &FlowState::default());
        assert_eq!(out.len(), 1);
        let c = &out[0].ctx;
        assert_eq!(c.traffic_class, Attr::Known(3));
        assert_eq!(c.drop_precedence, Attr::Unknown);
        assert_eq!(c.queue, Attr::Known(2));
        assert_eq!(c.device, Attr::Unset);
    }
}
