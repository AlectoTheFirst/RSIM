//! The reader of an enterprise: each edge with its links, HA state,
//! segments, interfaces, static routes, BGP neighbours, WAN links, gateways
//! and hub references, and its effective firewall and business policy; the
//! segments, the hub clusters, the object groups, the BGP sessions and the
//! overlay rows of the route table.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use super::device_name;
use super::effective::{Effective, Merged, effective};
use super::json::{
    J, Parsed, address, asn_of, body, interface_address, mask_len, max_len, module, numeric_id,
    ref_id, segment_id, trimmed,
};
use super::routes::{OverlayTable, RouteClass, overlay};
use super::rules::{Business, Firewall, ObjectGroups, Policy, business, firewall};
use rsim_core::{Prefix, SourceSpan};

/// The name of the Global Segment when no block names it.
pub const GLOBAL_SEGMENT: &str = "Global Segment";

/// The role of a gateway that ends an overlay tunnel.
const VPN_TUNNEL: &str = "VPN_TUNNEL";

/// The prefix of a gateway logicalId in the `controlPlane` module.
const GATEWAY_PREFIX: &str = "gateway";

/// The access types of a public WAN link that is wireless.
const WIRELESS: &[&str] = &["WIRELESS", "CELLULAR", "LTE", "5G"];

/// A segment of the enterprise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub id: u32,
    pub name: String,
    /// The Global Segment: id 0, or the name `Global Segment`.
    pub global: bool,
}

/// A hub cluster, by its logicalId.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cluster {
    pub id: String,
    /// The name with the spaces at its ends removed.
    pub name: Option<String>,
    /// The member edges, sorted.
    pub members: Vec<String>,
}

/// The kind of a hub reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HubRole {
    /// `vpn.edgeToEdgeDetail.vpnHubs`
    Vpn,
    /// `vpn.backHaulEdges` or `routeCfg.backhaulEdges`
    Backhaul,
}

/// A reference to a hub edge or a hub cluster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HubRef {
    pub id: Option<String>,
    pub name: Option<String>,
    pub kind: Option<String>,
    pub role: HubRole,
    /// The cluster that the reference names.
    pub cluster: Option<String>,
    /// The edges that the reference names: the edge, else the members of
    /// the cluster, sorted. Empty for a reference that names neither.
    pub edges: Vec<String>,
    /// The number of clusters, else of edges, with the name of a reference
    /// that resolves by its name, when it is more than 1. The reference
    /// then names no edge.
    pub shared_name: Option<usize>,
    pub span: SourceSpan,
}

/// The edges and the clusters of an enterprise, to resolve hub references.
#[derive(Clone, Debug, Default)]
pub struct Hubs {
    /// The name of each edge, by logicalId.
    names: BTreeMap<String, Option<String>>,
    pub clusters: Vec<Cluster>,
}

impl Hubs {
    fn keys(j: J<'_>) -> Vec<String> {
        [
            ref_id(j),
            j.obj("data").and_then(ref_id),
            j.text("edgeLogicalId"),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// The clusters with a name.
    fn named(&self, name: &str) -> Vec<&Cluster> {
        self.clusters
            .iter()
            .filter(|c| c.name.as_deref() == Some(name))
            .collect()
    }

    /// The cluster of a reference: by its logicalId, else the one cluster
    /// with its name with the spaces at its ends removed. The second value
    /// is the number of clusters with the name when it is more than 1.
    fn cluster(&self, j: J<'_>) -> (Option<&Cluster>, Option<usize>) {
        for k in Hubs::keys(j) {
            if let Some(c) = self.clusters.iter().find(|c| c.id == k) {
                return (Some(c), None);
            }
        }
        match trimmed(j.str("name")) {
            Some(name) => one(self.named(&name)),
            None => (None, None),
        }
    }

    /// A hub reference with the edges that it names: the edge of a key,
    /// else the members of the cluster, else the one edge with its name.
    pub fn hub_ref(&self, j: J<'_>, role: HubRole) -> HubRef {
        let keys = Hubs::keys(j);
        let (cluster, shared_clusters) = self.cluster(j);
        let name = trimmed(j.str("name"));
        let (edges, shared_name) =
            if let Some(k) = keys.iter().find(|k| self.names.contains_key(*k)) {
                (vec![k.clone()], None)
            } else if let Some(c) = cluster {
                (c.members.clone(), None)
            } else if shared_clusters.is_some() {
                (Vec::new(), shared_clusters)
            } else if let Some(n) = name.as_deref() {
                let ids: Vec<&String> = self
                    .names
                    .iter()
                    .filter(|(_, e)| e.as_deref().map(str::trim) == Some(n))
                    .map(|(id, _)| id)
                    .collect();
                let (id, shared) = one(ids);
                (id.into_iter().cloned().collect(), shared)
            } else {
                (Vec::new(), None)
            };
        HubRef {
            id: ref_id(j),
            name,
            kind: j.text("type"),
            role,
            cluster: cluster.map(|c| c.id.clone()),
            edges,
            shared_name,
            span: j.span(),
        }
    }
}

/// The one item of a list, and the length of a list of more than 1.
fn one<T>(items: Vec<T>) -> (Option<T>, Option<usize>) {
    match items.len() {
        0 | 1 => (items.into_iter().next(), None),
        n => (None, Some(n)),
    }
}

/// The HA facts of an edge.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ha {
    /// `ha.type`: `ACTIVE_STANDBY` for a standby pair, `ACTIVE_ACTIVE` for a
    /// cluster member, or `NONE`.
    pub kind: Option<String>,
    /// The HA state of `edge_state`: `ha.data.haState`, else `haState` of a
    /// standby pair.
    pub state: Option<String>,
    /// The serial of the standby edge of a pair.
    pub standby_serial: Option<String>,
    /// `ha.data.clusterName` with the spaces at its ends removed.
    pub cluster_name: Option<String>,
}

/// The kind of an interface of an edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InterfaceKind {
    Routed,
    /// A subinterface of a routed interface, named `<parent>:<id>`.
    Sub {
        parent: String,
        id: i64,
    },
    Loopback,
    /// A VLAN interface of a LAN network.
    Vlan,
}

/// An interface of an edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub kind: InterfaceKind,
    /// A routed interface with a WAN overlay: it is in the Global Segment.
    pub wan: bool,
    /// The segment of an interface that is not a WAN interface. `None` is
    /// the Global Segment.
    pub segment: Option<u32>,
    pub address: Option<(IpAddr, u8)>,
    /// `addressing.type`, for example `STATIC` or `DHCP`.
    pub addressing: Option<String>,
    /// The next hop of a WAN interface.
    pub gateway: Option<IpAddr>,
    /// `natDirect` of a routed interface: the source NAT of the traffic
    /// that leaves on it direct.
    pub nat_direct: Option<bool>,
    pub vlan: Option<u16>,
    pub span: SourceSpan,
}

/// The kind of a WAN link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkKind {
    /// A private link, with the private network that the WAN module names.
    Private {
        network: Option<String>,
    },
    Public {
        wireless: bool,
    },
    NotKnown,
}

/// What gives the kind of a WAN link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KindSource {
    /// `mode` of the WAN module row of the link.
    WanModule,
    /// A private carrier name of the settings, for a link that the WAN
    /// module does not describe.
    CarrierName,
    NotKnown,
}

/// A WAN link of an edge: the listing row of the link, its WAN module row
/// and its state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WanLink {
    pub logical_id: String,
    pub internal_id: Option<String>,
    pub interface: Option<String>,
    pub name: Option<String>,
    pub isp: Option<String>,
    /// The listing address: the address after any NAT in front of the edge.
    pub address: Option<IpAddr>,
    /// The address of the WAN interface of the edge.
    pub local: Option<IpAddr>,
    /// The next hop: `nextHopIpAddress` of the WAN module, else the gateway
    /// of the WAN interface.
    pub gateway: Option<IpAddr>,
    pub kind: LinkKind,
    pub kind_from: KindSource,
    pub state: Option<String>,
    pub link_mode: Option<String>,
    pub vpn_state: Option<String>,
    pub backup_state: Option<String>,
    /// The number of listing rows of the link when no row is the configured
    /// link: the rows share the logicalId and none has the `internalId` of
    /// the WAN module. The link is then not known.
    pub ambiguous: Option<usize>,
    /// The `MTU` of the WAN module row, with the span of the value.
    pub mtu: Option<(u64, SourceSpan)>,
    pub spans: Vec<SourceSpan>,
}

/// A gateway of the `controlPlane` module with the role `VPN_TUNNEL`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gateway {
    /// The logicalId without the `gateway` prefix.
    pub id: String,
    pub name: Option<String>,
    pub address: Option<IpAddr>,
    /// The segments that the gateway serves, sorted.
    pub segments: Vec<u32>,
    pub span: SourceSpan,
}

/// A BGP neighbour of a segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbour {
    pub address: IpAddr,
    pub asn: Option<u32>,
    pub local: Option<IpAddr>,
    pub span: SourceSpan,
}

/// The BGP of a segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bgp {
    pub asn: Option<u32>,
    pub router_id: Option<IpAddr>,
    pub neighbours: Vec<Neighbour>,
    pub span: SourceSpan,
}

/// A static route of a segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticRoute {
    pub prefix: Prefix,
    pub gateway: Option<IpAddr>,
    /// `wanInterface`, as `<parent>:<id>` with a `subinterfaceId`.
    pub interface: Option<String>,
    pub cost: Option<i64>,
    pub preferred: Option<bool>,
    pub advertise: Option<bool>,
    pub span: SourceSpan,
}

impl StaticRoute {
    /// The class of the route in the route order: a route with Preferred on
    /// is a preferred local static route, a route with Preferred off is the
    /// last resort, and a route with no `preferred` is `NotKnown`.
    pub fn class(&self) -> RouteClass {
        match self.preferred {
            Some(true) => RouteClass::LocalStaticPreferred,
            Some(false) => RouteClass::LocalStatic,
            None => RouteClass::NotKnown,
        }
    }
}

/// A row of `vpn.dataCenterEdges` of the `controlPlane` module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataCenterEdge {
    pub edge: Option<String>,
    pub cluster: Option<String>,
    pub kind: Option<String>,
    pub span: SourceSpan,
}

/// A segment of an edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeSegment {
    pub id: u32,
    pub name: String,
    pub global: bool,
    /// `vpn.enabled`.
    pub vpn: Option<bool>,
    /// The BGP of the segment, when it is not disabled.
    pub bgp: Option<Bgp>,
    pub statics: Vec<StaticRoute>,
    /// The VPN hubs and the backhaul hubs of the settings.
    pub hubs: Vec<HubRef>,
    /// The hub edges that the `controlPlane` module names for the segment.
    pub data_center: Vec<DataCenterEdge>,
}

/// The path counts of an SD-WAN peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PathCount {
    pub stable: Option<i64>,
    pub unstable: Option<i64>,
    pub standby: Option<i64>,
    pub dead: Option<i64>,
    pub unknown: Option<i64>,
    pub total: Option<i64>,
}

/// A peer of `edge/getEdgeSDWANPeers`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// `edgeLogicalId`, else `deviceLogicalId`.
    pub logical_id: Option<String>,
    pub name: Option<String>,
    /// `peerType`: `BRANCH`, `HUB` or `GATEWAY`.
    pub kind: Option<String>,
    pub ha: Option<String>,
    pub cluster: Option<i64>,
    pub paths: PathCount,
    pub span: SourceSpan,
}

/// The SD-WAN peers of an edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Peers {
    NotCollected,
    /// The read of the edge gave a gap, with its reason.
    Gap(String),
    Read(Vec<Peer>),
}

/// The state of the module read of an edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Modules {
    NotCollected,
    /// The read of the edge gave a gap, with its reason.
    Gap(String),
    /// The modules, with the stale flag of their freshness.
    Read {
        stale: bool,
    },
}

/// An edge of the enterprise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edge {
    pub logical_id: String,
    /// The twin device of the edge.
    pub device: String,
    pub numeric_id: Option<u64>,
    pub name: Option<String>,
    pub serial: Option<String>,
    pub model: Option<String>,
    pub software_version: Option<String>,
    /// `edgeState` of `edge_state`.
    pub state: Option<String>,
    /// `isHub`, a member of a hub cluster, or an edge that a hub reference
    /// names.
    pub hub: bool,
    pub ha: Ha,
    /// The cluster of which the edge is a member.
    pub cluster: Option<String>,
    pub segments: Vec<EdgeSegment>,
    pub interfaces: Vec<Interface>,
    pub links: Vec<WanLink>,
    pub gateways: Vec<Gateway>,
    pub peers: Peers,
    pub modules: Modules,
    pub firewall: Policy<Firewall>,
    pub business: Policy<Business>,
    /// Why the profile part of the `deviceSettings` module is not known.
    pub settings_unknown: Option<String>,
    pub span: SourceSpan,
    pub notes: Vec<String>,
}

/// The segment of an observed BGP session.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SessionSegment {
    Global,
    Segment(u32),
    /// More than one segment of the edge has a configured neighbour with
    /// the address: the segments, sorted.
    NotKnown(Vec<u32>),
}

/// An observed BGP session of `bgp_sessions`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BgpSession {
    pub edge: String,
    pub neighbour: IpAddr,
    /// The segment of the configured neighbour with the same address on the
    /// edge, else the Global Segment.
    pub segment: SessionSegment,
    pub asn: Option<u32>,
    /// The state. Rows of one session with different states give `None`.
    pub state: Option<String>,
    pub spans: Vec<SourceSpan>,
}

/// An enterprise of an orchestrator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enterprise {
    pub logical_id: String,
    pub store_device: String,
    pub numeric_id: Option<u64>,
    pub name: Option<String>,
    /// The Global Segment first, then by name.
    pub segments: Vec<Segment>,
    /// The edges, sorted by logicalId, with one edge for each logicalId.
    pub edges: Vec<Edge>,
    pub clusters: Vec<Cluster>,
    pub object_groups: ObjectGroups,
    /// The observed sessions, or `None` when the section is not collected.
    pub sessions: Option<Vec<BgpSession>>,
    /// The overlay rows, or `None` when the route table is not collected.
    pub overlay: Option<OverlayTable>,
    pub notes: Vec<String>,
}

impl Enterprise {
    pub fn edge(&self, logical_id: &str) -> Option<&Edge> {
        self.edges
            .binary_search_by(|e| e.logical_id.as_str().cmp(logical_id))
            .ok()
            .map(|i| &self.edges[i])
    }
}

/// The parts of an edge that the enterprise-wide reads need.
struct Pre<'a> {
    id: String,
    row: J<'a>,
    state: Option<J<'a>>,
    settings: Effective<'a>,
    qos: Effective<'a>,
    firewall: Effective<'a>,
    wan: Option<J<'a>>,
    control: Option<J<'a>>,
    modules: Modules,
}

/// Reads an enterprise from its sections. `store_device` names the twin
/// devices, `enterprise` is the enterprise logicalId, and
/// `private_carriers` holds the carrier names that make a link that the WAN
/// module does not describe a private link.
pub fn read(
    store_device: &str,
    enterprise: &str,
    p: &Parsed,
    private_carriers: &[String],
) -> Enterprise {
    let mut notes = p.notes.clone();
    let carriers: BTreeSet<String> = private_carriers
        .iter()
        .map(|c| c.trim().to_lowercase())
        .filter(|c| !c.is_empty())
        .collect();
    let agg = p.root("aggregates").and_then(|r| {
        let rows = match r.get("enterprises") {
            Some(e) => e.rows(),
            None => r.rows(),
        };
        rows.into_iter()
            .find(|row| row.text("logicalId").as_deref() == Some(enterprise))
    });
    let listing: Vec<J<'_>> = p
        .root("edges")
        .map(J::rows)
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.text("logicalId").is_some())
        .collect();
    let rows = if listing.is_empty() {
        let v2: Vec<J<'_>> = p
            .root("edges_v2")
            .map(J::rows)
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.text("logicalId").is_some())
            .collect();
        if !v2.is_empty() {
            notes.push("edges read from edges_v2".to_string());
        }
        v2
    } else {
        listing
    };
    let mut by_id: BTreeMap<String, J<'_>> = BTreeMap::new();
    for r in rows {
        let id = r.text("logicalId").unwrap_or_default();
        match by_id.entry(id) {
            Entry::Occupied(o) => notes.push(format!("edge {}: more than one row", o.key())),
            Entry::Vacant(v) => {
                v.insert(r);
            }
        }
    }
    let states: BTreeMap<String, J<'_>> = p
        .root("edge_state")
        .map(J::rows)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| Some((r.text("logicalId")?, r)))
        .collect();
    let profiles: Option<BTreeMap<u64, J<'_>>> = p.root("profiles").map(|r| {
        r.rows()
            .into_iter()
            .filter_map(|row| Some((numeric_id(row.v.get("id")?)?, row)))
            .collect()
    });
    let module_rows: Option<BTreeMap<&str, J<'_>>> = p
        .root("edge_modules")
        .map(|r| r.members().into_iter().collect());
    let peer_rows: Option<BTreeMap<&str, J<'_>>> = p
        .root("sdwan_peers")
        .map(|r| r.members().into_iter().collect());
    let groups = ObjectGroups::read(p.root("object_groups"));

    let pres: Vec<Pre<'_>> = by_id
        .into_iter()
        .map(|(id, row)| {
            let (modules, wan, control) = match module_rows.as_ref() {
                None => (Modules::NotCollected, None, None),
                Some(m) => match m.get(id.as_str()) {
                    None => (Modules::NotCollected, None, None),
                    Some(m) => match gap(*m) {
                        Some(reason) => (Modules::Gap(reason), None, None),
                        None => (
                            Modules::Read { stale: stale(*m) },
                            module(*m, "WAN").map(body),
                            module(*m, "controlPlane").map(body),
                        ),
                    },
                },
            };
            Pre {
                state: states.get(&id).copied(),
                settings: effective(row, profiles.as_ref(), "deviceSettings"),
                qos: effective(row, profiles.as_ref(), "QOS"),
                firewall: effective(row, profiles.as_ref(), "firewall"),
                id,
                row,
                wan,
                control,
                modules,
            }
        })
        .collect();

    let segments = segments(&pres, &mut notes);
    let hubs = hubs(&pres);
    let mut hub_ids: BTreeSet<String> = pres
        .iter()
        .filter(|e| e.row.bool("isHub") == Some(true))
        .map(|e| e.id.clone())
        .collect();
    for c in &hubs.clusters {
        hub_ids.extend(c.members.iter().cloned());
    }
    for e in &pres {
        for block in e.control.map(|c| c.list("segments")).unwrap_or_default() {
            let vpn = block.obj("vpn");
            let rows = vpn
                .map(|v| v.list("dataCenterEdges"))
                .unwrap_or_default()
                .into_iter()
                .chain(block.list("dataCenterEdgeList"));
            for row in rows {
                if let Some(r) = ref_id(row)
                    && hubs.names.contains_key(&r)
                {
                    hub_ids.insert(r);
                }
            }
        }
        for block in e.settings.body.segments() {
            for r in hub_refs(block, &hubs) {
                hub_ids.extend(r.edges);
            }
        }
    }

    let mut edges: Vec<Edge> = pres
        .iter()
        .map(|e| {
            let peers = match peer_rows.as_ref() {
                None => Peers::NotCollected,
                Some(m) => match m.get(e.id.as_str()) {
                    None => Peers::NotCollected,
                    Some(j) => peers(*j),
                },
            };
            edge(
                e,
                &Ctx {
                    store_device,
                    segments: &segments,
                    hubs: &hubs,
                    hub_ids: &hub_ids,
                    groups: &groups,
                    carriers: &carriers,
                },
                peers,
            )
        })
        .collect();
    edges.sort_by(|a, b| a.logical_id.cmp(&b.logical_id));

    let sessions = p.root("bgp_sessions").map(|r| sessions(r, &edges));
    let by_numeric: BTreeMap<u64, String> = edges
        .iter()
        .filter_map(|e| Some((e.numeric_id?, e.logical_id.clone())))
        .collect();
    let overlay = p
        .root("route_table")
        .map(|r| overlay(r, &by_numeric, &segments));
    Enterprise {
        logical_id: enterprise.to_string(),
        store_device: store_device.to_string(),
        numeric_id: agg.and_then(|a| a.v.get("id")).and_then(numeric_id),
        name: agg.and_then(|a| a.text("name")),
        segments,
        edges,
        clusters: hubs.clusters,
        object_groups: groups,
        sessions,
        overlay,
        notes,
    }
}

/// The reason of a gap of a per-edge read: an object with a `_capability`
/// member.
fn gap(j: J<'_>) -> Option<String> {
    let c = j.get("_capability")?;
    Some(
        c.text("reason")
            .or_else(|| c.text("detail"))
            .unwrap_or_else(|| "gap".to_string()),
    )
}

/// The stale flag of `_freshness`, also below its `modules` member.
fn stale(j: J<'_>) -> bool {
    let Some(f) = j.obj("_freshness") else {
        return false;
    };
    f.bool("stale")
        .or_else(|| f.obj("modules").and_then(|m| m.bool("stale")))
        .unwrap_or(false)
}

/// The segments of the enterprise: the union of the segment blocks of the
/// `deviceSettings` of each edge. With no block and with edges, the Global
/// Segment.
fn segments(pres: &[Pre<'_>], notes: &mut Vec<String>) -> Vec<Segment> {
    let mut found: BTreeMap<u32, Option<String>> = BTreeMap::new();
    let mut nameless = 0;
    for e in pres {
        for block in e.settings.body.segments() {
            match block.segment_id() {
                Some(id) => {
                    let name = trimmed(block.segment_name().as_deref());
                    let entry = found.entry(id).or_default();
                    if entry.is_none() {
                        *entry = name;
                    }
                }
                None => nameless += 1,
            }
        }
    }
    if nameless > 0 {
        notes.push(format!("{nameless} segment blocks with no segmentId"));
    }
    if found.is_empty() && !pres.is_empty() {
        found.insert(0, Some(GLOBAL_SEGMENT.to_string()));
    }
    let mut out: Vec<Segment> = found
        .into_iter()
        .map(|(id, name)| {
            let name = name.unwrap_or_else(|| format!("segment-{id}"));
            let global = id == 0 || name.to_lowercase().replace(' ', "") == "globalsegment";
            Segment { id, name, global }
        })
        .collect();
    out.sort_by(|a, b| (!a.global, &a.name, a.id).cmp(&(!b.global, &b.name, b.id)));
    out
}

/// The hub clusters: the `memberCluster` and the `dataCenterEdges` rows with
/// a `clusterLogicalId` of the `controlPlane` modules, and the edges whose
/// `ha.data.clusterName` is the name of exactly 1 cluster.
fn hubs(pres: &[Pre<'_>]) -> Hubs {
    let names: BTreeMap<String, Option<String>> = pres
        .iter()
        .map(|e| (e.id.clone(), e.row.text("name")))
        .collect();
    let mut found: BTreeMap<String, (Option<String>, BTreeSet<String>)> = BTreeMap::new();
    for e in pres {
        let Some(c) = e.control else {
            continue;
        };
        if let Some(mc) = c.obj("memberCluster")
            && let Some(cid) = mc.text("clusterLogicalId")
        {
            let entry = found.entry(cid).or_default();
            if entry.0.is_none() {
                entry.0 = trimmed(mc.str("clusterName"));
            }
            for m in mc.list("members") {
                if let Some(r) = m.text("edgeLogicalId")
                    && names.contains_key(&r)
                {
                    entry.1.insert(r);
                }
            }
        }
        for block in c.list("segments") {
            let rows = block
                .obj("vpn")
                .map(|v| v.list("dataCenterEdges"))
                .unwrap_or_default();
            for row in rows {
                let Some(cid) = row.text("clusterLogicalId") else {
                    continue;
                };
                let entry = found.entry(cid).or_default();
                if entry.0.is_none() {
                    entry.0 = trimmed(row.str("clusterName"));
                }
                if let Some(r) = ref_id(row)
                    && names.contains_key(&r)
                {
                    entry.1.insert(r);
                }
            }
        }
    }
    for e in pres {
        let name = e
            .row
            .obj("ha")
            .and_then(|h| h.obj("data"))
            .and_then(|d| trimmed(d.str("clusterName")));
        let Some(name) = name else {
            continue;
        };
        let mut named = found
            .values_mut()
            .filter(|(n, _)| n.as_deref() == Some(name.as_str()));
        if let (Some((_, members)), None) = (named.next(), named.next()) {
            members.insert(e.id.clone());
        }
    }
    Hubs {
        names,
        clusters: found
            .into_iter()
            .map(|(id, (name, members))| Cluster {
                id,
                name,
                members: members.into_iter().collect(),
            })
            .collect(),
    }
}

/// The VPN hubs and the backhaul hubs of a segment block of the settings.
fn hub_refs(block: &Merged<'_>, hubs: &Hubs) -> Vec<HubRef> {
    let Some(vpn) = block.get("vpn") else {
        return Vec::new();
    };
    let vpn_hubs = vpn
        .obj("edgeToEdgeDetail")
        .map(|d| d.list("vpnHubs"))
        .unwrap_or_default()
        .into_iter()
        .map(|h| hubs.hub_ref(h, HubRole::Vpn));
    let backhaul = vpn
        .list("backHaulEdges")
        .into_iter()
        .map(|h| hubs.hub_ref(h, HubRole::Backhaul));
    vpn_hubs.chain(backhaul).collect()
}

/// The shared parts of the reads of each edge.
struct Ctx<'c> {
    store_device: &'c str,
    segments: &'c [Segment],
    hubs: &'c Hubs,
    hub_ids: &'c BTreeSet<String>,
    groups: &'c ObjectGroups,
    carriers: &'c BTreeSet<String>,
}

fn edge(e: &Pre<'_>, ctx: &Ctx<'_>, peers: Peers) -> Edge {
    let row = e.row;
    let mut notes = Vec::new();
    let body = &e.settings.body;
    let own: BTreeSet<u32> = body
        .segments()
        .iter()
        .filter_map(Merged::segment_id)
        .collect();
    let segments: Vec<EdgeSegment> = ctx
        .segments
        .iter()
        .filter(|s| own.is_empty() || own.contains(&s.id))
        .map(|s| {
            let block = body
                .segments()
                .iter()
                .find(|b| b.segment_id() == Some(s.id));
            let data_center = e
                .control
                .map(|c| c.list("segments"))
                .unwrap_or_default()
                .into_iter()
                .filter(|b| segment_id(*b) == Some(s.id))
                .flat_map(|b| {
                    b.obj("vpn")
                        .map(|v| v.list("dataCenterEdges"))
                        .unwrap_or_default()
                })
                .map(|r| DataCenterEdge {
                    edge: ref_id(r),
                    cluster: r.text("clusterLogicalId"),
                    kind: r.text("type"),
                    span: r.span(),
                })
                .collect();
            EdgeSegment {
                id: s.id,
                name: s.name.clone(),
                global: s.global,
                vpn: block
                    .and_then(|b| b.get("vpn"))
                    .and_then(|v| v.bool("enabled")),
                bgp: block
                    .and_then(|b| b.get("bgp"))
                    .and_then(|j| bgp(j, &s.name, &mut notes)),
                statics: block
                    .and_then(|b| b.get("routes"))
                    .map(statics)
                    .unwrap_or_default(),
                hubs: block.map(|b| hub_refs(b, ctx.hubs)).unwrap_or_default(),
                data_center,
            }
        })
        .collect();
    let interfaces = interfaces(body);
    let links = links(row, e.state, e.wan, &interfaces, ctx.carriers, &mut notes);
    let all: Vec<u32> = segments.iter().map(|s| s.id).collect();
    let state = e.state;
    let ha = ha(row, state);
    if let Some(name) = ha.cluster_name.as_deref() {
        let n = ctx.hubs.named(name).len();
        if n > 1 {
            notes.push(format!("cluster name {name}: {n} clusters"));
        }
    }
    let business = business(&e.qos, ctx.groups, ctx.hubs);
    let mut refs: Vec<&HubRef> = segments.iter().flat_map(|s| &s.hubs).collect();
    if let Policy::Read(b) = &business {
        refs.extend(
            b.segments
                .iter()
                .flat_map(|s| &s.rules)
                .flat_map(|r| &r.action.routes)
                .flat_map(|r| &r.backhaul),
        );
    }
    for r in refs {
        if let Some(n) = r.shared_name {
            let note = format!(
                "hub reference {}: {n} hubs with the name",
                r.name.as_deref().unwrap_or_default()
            );
            if !notes.contains(&note) {
                notes.push(note);
            }
        }
    }
    Edge {
        logical_id: e.id.clone(),
        device: device_name(ctx.store_device, &e.id),
        numeric_id: row.v.get("id").and_then(numeric_id),
        name: row.text("name"),
        serial: row.text("serialNumber"),
        model: row.text("modelNumber"),
        software_version: row.text("softwareVersion"),
        state: state.and_then(|s| s.text("edgeState")),
        hub: ctx.hub_ids.contains(&e.id),
        ha,
        cluster: ctx
            .hubs
            .clusters
            .iter()
            .find(|c| c.members.contains(&e.id))
            .map(|c| c.id.clone()),
        segments,
        interfaces,
        links,
        gateways: gateways(e.control, &all),
        peers,
        modules: e.modules.clone(),
        firewall: firewall(&e.firewall, ctx.groups),
        business,
        settings_unknown: e.settings.profile_unknown.clone(),
        span: row.span(),
        notes,
    }
}

fn ha(row: J<'_>, state: Option<J<'_>>) -> Ha {
    let h = row.obj("ha");
    let data = h.and_then(|h| h.obj("data"));
    let kind = h.and_then(|h| h.text("type"));
    let pair = kind
        .as_deref()
        .is_some_and(|k| k.eq_ignore_ascii_case("ACTIVE_STANDBY"));
    let pair_state = state
        .and_then(|s| s.obj("ha"))
        .and_then(|h| h.obj("data"))
        .and_then(|d| d.text("haState"));
    let row_state = if pair {
        state.and_then(|s| s.text("haState"))
    } else {
        None
    };
    Ha {
        kind,
        state: pair_state.or(row_state),
        standby_serial: data.and_then(|d| d.text("haSerialNumber")),
        cluster_name: data.and_then(|d| trimmed(d.str("clusterName"))),
    }
}

fn bgp(j: J<'_>, segment: &str, notes: &mut Vec<String>) -> Option<Bgp> {
    if j.bool("enabled") == Some(false) {
        return None;
    }
    let neighbours: Vec<Neighbour> = j
        .list("neighbors")
        .into_iter()
        .filter_map(|n| {
            Some(Neighbour {
                address: n.str("neighborIp").and_then(address)?,
                asn: n.v.get("neighborAS").and_then(asn_of),
                local: n.str("localIp").and_then(address),
                span: n.span(),
            })
        })
        .collect();
    for n in neighbours.iter().filter(|n| n.asn.is_none()) {
        notes.push(format!(
            "segment {segment}: BGP neighbour {} has no AS",
            n.address
        ));
    }
    Some(Bgp {
        asn: j.v.get("ASN").or_else(|| j.v.get("asn")).and_then(asn_of),
        router_id: j.str("routerId").and_then(address),
        neighbours,
        span: j.span(),
    })
}

fn statics(routes: J<'_>) -> Vec<StaticRoute> {
    ["static", "staticV6"]
        .iter()
        .flat_map(|k| routes.list(k))
        .filter_map(|r| {
            let dest = address(r.str("destination")?)?;
            let len = match r.int("cidrPrefix") {
                Some(n) => u8::try_from(n).ok()?,
                None => mask_len(r.str("netmask")?)?,
            };
            if len > max_len(dest) {
                return None;
            }
            let interface = r
                .text("wanInterface")
                .map(|p| match r.int("subinterfaceId") {
                    Some(s) if s >= 0 => format!("{p}:{s}"),
                    _ => p,
                });
            Some(StaticRoute {
                prefix: Prefix::new(dest, len),
                gateway: r.str("gateway").and_then(address),
                interface,
                cost: r.int("cost"),
                preferred: r.bool("preferred"),
                advertise: r.bool("advertise"),
                span: r.span(),
            })
        })
        .collect()
}

fn interfaces(b: &Merged<'_>) -> Vec<Interface> {
    let mut out = Vec::new();
    let routed = b.get("routedInterfaces").map(J::elems).unwrap_or_default();
    for i in routed {
        if !i.v.is_object() || i.bool("disabled") == Some(true) {
            continue;
        }
        let Some(name) = i.text("name") else {
            continue;
        };
        let a = i.obj("addressing");
        let overlay = i.str("wanOverlay").unwrap_or("").to_ascii_uppercase();
        let wan = !overlay.is_empty() && overlay != "DISABLED";
        out.push(Interface {
            name: name.clone(),
            kind: InterfaceKind::Routed,
            wan,
            segment: if wan { None } else { segment_id(i) },
            address: a.and_then(interface_address),
            addressing: a.and_then(|a| a.text("type")),
            gateway: if wan {
                a.and_then(|a| a.str("gateway")).and_then(address)
            } else {
                None
            },
            nat_direct: i.bool("natDirect"),
            vlan: None,
            span: i.span(),
        });
        for s in i.list("subinterfaces") {
            if s.bool("disabled") == Some(true) {
                continue;
            }
            let Some(id) = s.int("subinterfaceId").filter(|n| *n >= 0) else {
                continue;
            };
            let sa = s.obj("addressing");
            out.push(Interface {
                name: format!("{name}:{id}"),
                kind: InterfaceKind::Sub {
                    parent: name.clone(),
                    id,
                },
                wan: false,
                segment: segment_id(s),
                address: sa.and_then(interface_address),
                addressing: sa.and_then(|a| a.text("type")),
                gateway: None,
                nat_direct: None,
                vlan: s.int("vlanId").and_then(|v| u16::try_from(v).ok()),
                span: s.span(),
            });
        }
    }
    if let Some(map) = b.get("loopbackInterfaces") {
        for (name, lo) in map.members() {
            if !lo.v.is_object() {
                continue;
            }
            out.push(Interface {
                name: name.to_string(),
                kind: InterfaceKind::Loopback,
                wan: false,
                segment: segment_id(lo),
                address: if lo.bool("disableV4") == Some(true) {
                    None
                } else {
                    interface_address(lo)
                },
                addressing: None,
                gateway: None,
                nat_direct: None,
                vlan: None,
                span: lo.span(),
            });
        }
    }
    let networks = b.get("lan").map(|l| l.list("networks")).unwrap_or_default();
    for n in networks {
        if n.bool("disabled") == Some(true) {
            continue;
        }
        let vlan = n.int("vlanId").and_then(|v| u16::try_from(v).ok());
        let Some(name) = n.text("name").or_else(|| vlan.map(|v| format!("vlan{v}"))) else {
            continue;
        };
        out.push(Interface {
            name,
            kind: InterfaceKind::Vlan,
            wan: false,
            segment: segment_id(n),
            address: interface_address(n),
            addressing: None,
            gateway: None,
            nat_direct: None,
            vlan,
            span: n.span(),
        });
    }
    out
}

/// The private network of a WAN module row: `privateNetwork`, a name or an
/// object with one, else `mplsNetwork`.
fn private_network(wan: Option<J<'_>>) -> Option<String> {
    let w = wan?;
    ["privateNetwork", "mplsNetwork"].iter().find_map(|k| {
        let v = w.get(k)?;
        let t = if v.v.is_object() {
            v.str("name").or_else(|| v.str("logicalId"))
        } else {
            v.v.as_str()
        };
        trimmed(t)
    })
}

/// The WAN links of an edge. The listing rows of one logicalId are one
/// link: the row whose `internalId` is the `internalId` of a WAN module row
/// is the link, else the one row; with more than one row and no such row,
/// the link is not known. When the WAN module has rows, a link that it does
/// not describe is not a link of the edge. The kind of a link comes from
/// `mode` of its WAN module row; a private carrier name gives a private
/// link only for a link with no WAN module row.
fn links(
    row: J<'_>,
    state: Option<J<'_>>,
    wan: Option<J<'_>>,
    interfaces: &[Interface],
    carriers: &BTreeSet<String>,
    notes: &mut Vec<String>,
) -> Vec<WanLink> {
    let wan_rows = wan.map(|w| w.list("links")).unwrap_or_default();
    let by_internal: BTreeMap<String, J<'_>> = wan_rows
        .iter()
        .filter_map(|w| Some((w.text("internalId")?, *w)))
        .collect();
    let by_lid: BTreeMap<String, J<'_>> = wan_rows
        .iter()
        .filter_map(|w| Some((ref_id(*w)?, *w)))
        .collect();
    let mut groups: BTreeMap<String, Vec<J<'_>>> = BTreeMap::new();
    for l in row.list("links") {
        if l.str("networkSide")
            .is_some_and(|s| s.eq_ignore_ascii_case("LAN"))
        {
            continue;
        }
        if let Some(lid) = ref_id(l) {
            groups.entry(lid).or_default().push(l);
        }
    }
    let state_links = state.map(|s| s.list("links")).unwrap_or_default();
    let mut out = Vec::new();
    let mut unconfigured = 0;
    for (lid, group) in groups {
        let configured = group.iter().copied().find(|l| {
            l.text("internalId")
                .is_some_and(|i| by_internal.contains_key(&i))
        });
        let chosen = match configured {
            Some(l) => Some(l),
            None if group.len() == 1 => group.first().copied(),
            None => None,
        };
        let internal = chosen.and_then(|l| l.text("internalId"));
        let wan_row = internal
            .as_ref()
            .and_then(|i| by_internal.get(i).copied())
            .or_else(|| by_lid.get(&lid).copied());
        if wan_row.is_none() && !wan_rows.is_empty() {
            unconfigured += 1;
            continue;
        }
        let ambiguous = chosen.is_none().then_some(group.len());
        if let Some(n) = ambiguous {
            notes.push(format!(
                "link {lid}: {n} listing rows and none with the internalId of the WAN module"
            ));
        }
        let mode = wan_row
            .and_then(|w| w.str("mode"))
            .map(str::to_ascii_uppercase);
        let named = |l: J<'_>| {
            ["isp", "org", "displayName"]
                .iter()
                .filter_map(|k| l.str(k))
                .any(|n| carriers.contains(&n.trim().to_lowercase()))
        };
        let (kind, kind_from) = match mode.as_deref() {
            Some("PRIVATE") => (
                LinkKind::Private {
                    network: private_network(wan_row),
                },
                KindSource::WanModule,
            ),
            Some("PUBLIC") => {
                let access = wan_row
                    .and_then(|w| w.str("type"))
                    .unwrap_or("")
                    .to_ascii_uppercase();
                (
                    LinkKind::Public {
                        wireless: WIRELESS.iter().any(|x| access.contains(x)),
                    },
                    KindSource::WanModule,
                )
            }
            _ if wan_row.is_none() && chosen.is_some_and(named) => {
                (LinkKind::Private { network: None }, KindSource::CarrierName)
            }
            _ => (LinkKind::NotKnown, KindSource::NotKnown),
        };
        let interface = chosen.and_then(|l| l.text("interface"));
        let own = interface
            .as_deref()
            .and_then(|n| interfaces.iter().find(|i| i.wan && i.name == n));
        let st = chosen.and_then(|l| {
            state_links.iter().copied().find(|s| {
                ref_id(*s).as_deref() == Some(lid.as_str())
                    && s.text("internalId") == l.text("internalId")
            })
        });
        let mut spans: Vec<SourceSpan> = match chosen {
            Some(l) => vec![l.span()],
            None => group.iter().map(|l| l.span()).collect(),
        };
        spans.extend(wan_row.map(J::span));
        spans.extend(st.map(J::span));
        out.push(WanLink {
            internal_id: internal,
            name: wan_row
                .and_then(|w| w.text("name"))
                .or_else(|| chosen.and_then(|l| l.text("displayName")))
                .or_else(|| interface.clone()),
            isp: chosen
                .and_then(|l| l.text("isp"))
                .or_else(|| wan_row.and_then(|w| w.text("isp"))),
            address: chosen.and_then(|l| l.str("ipAddress")).and_then(address),
            local: own.and_then(|i| i.address).map(|(a, _)| a),
            gateway: wan_row
                .and_then(|w| w.str("nextHopIpAddress"))
                .and_then(address)
                .or_else(|| own.and_then(|i| i.gateway)),
            interface,
            kind,
            kind_from,
            state: st.and_then(|s| s.text("state")),
            link_mode: st.and_then(|s| s.text("linkMode")),
            vpn_state: st.and_then(|s| s.text("vpnState")),
            backup_state: st.and_then(|s| s.text("backupState")),
            ambiguous,
            mtu: wan_row
                .and_then(|w| w.get("MTU"))
                .and_then(|m| Some((m.v.as_u64().filter(|v| *v > 0)?, m.span()))),
            spans,
            logical_id: lid,
        });
    }
    if unconfigured > 0 {
        notes.push(format!(
            "{unconfigured} listing links not in the WAN module"
        ));
    }
    out
}

/// The gateways of the `controlPlane` module with the role `VPN_TUNNEL`:
/// the gateways of each segment of `gatewaySegmentDetailList`, and the
/// gateways of `gatewayDetailList` for each segment of the edge.
fn gateways(control: Option<J<'_>>, all: &[u32]) -> Vec<Gateway> {
    let Some(c) = control else {
        return Vec::new();
    };
    let mut found: BTreeMap<String, Gateway> = BTreeMap::new();
    for block in c.list("gatewaySegmentDetailList") {
        let segs: Vec<u32> = segment_id(block).map_or_else(|| all.to_vec(), |s| vec![s]);
        for row in block.list("gatewayDetailList") {
            add_gateway(&mut found, row, &segs);
        }
    }
    for row in c.list("gatewayDetailList") {
        add_gateway(&mut found, row, all);
    }
    found.into_values().collect()
}

fn add_gateway(found: &mut BTreeMap<String, Gateway>, row: J<'_>, segs: &[u32]) {
    let tunnel = row
        .list("roles")
        .iter()
        .any(|r| r.str("role") == Some(VPN_TUNNEL));
    if !tunnel {
        return;
    }
    let Some(id) = ref_id(row) else {
        return;
    };
    let id = id
        .strip_prefix(GATEWAY_PREFIX)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or(id);
    let g = found.entry(id.clone()).or_insert_with(|| Gateway {
        id,
        name: row.text("name"),
        address: row.str("ipAddress").and_then(address),
        segments: Vec::new(),
        span: row.span(),
    });
    for s in segs {
        if !g.segments.contains(s) {
            g.segments.push(*s);
        }
    }
    g.segments.sort_unstable();
}

/// The SD-WAN peers of an edge: an array of peer rows, or a gap.
fn peers(j: J<'_>) -> Peers {
    if let Some(reason) = gap(j) {
        return Peers::Gap(reason);
    }
    Peers::Read(
        j.rows()
            .into_iter()
            .map(|r| {
                let c = r.obj("pathStatusCount");
                let n = |k: &str| c.and_then(|c| c.int(k));
                Peer {
                    logical_id: r
                        .text("edgeLogicalId")
                        .or_else(|| r.text("deviceLogicalId")),
                    name: r.text("peerName"),
                    kind: r.text("peerType"),
                    ha: r.text("peerHAType"),
                    cluster: r.int("clusterId"),
                    paths: PathCount {
                        stable: n("stable"),
                        unstable: n("unstable"),
                        standby: n("standby"),
                        dead: n("dead"),
                        unknown: n("unknown"),
                        total: n("total"),
                    },
                    span: r.span(),
                }
            })
            .collect(),
    )
}

/// The observed sessions: one for each edge, neighbour address and
/// segment. The segment is the one segment of the edge with a configured
/// neighbour of the address; with none, the Global Segment; with more than
/// one, not known.
fn sessions(root: J<'_>, edges: &[Edge]) -> Vec<BgpSession> {
    let mut found: BTreeMap<(String, IpAddr, SessionSegment), BgpSession> = BTreeMap::new();
    for r in root.rows() {
        let Some(edge) = r.obj("edge").and_then(ref_id) else {
            continue;
        };
        let Some(neighbour) = r.str("neighborIp").and_then(address) else {
            continue;
        };
        let matching: Vec<&EdgeSegment> = edges
            .iter()
            .find(|e| e.logical_id == edge)
            .map(|e| {
                e.segments
                    .iter()
                    .filter(|s| {
                        s.bgp
                            .as_ref()
                            .is_some_and(|b| b.neighbours.iter().any(|n| n.address == neighbour))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let segment = match matching.as_slice() {
            [] => SessionSegment::Global,
            [s] if s.global => SessionSegment::Global,
            [s] => SessionSegment::Segment(s.id),
            more => {
                let mut ids: Vec<u32> = more.iter().map(|s| s.id).collect();
                ids.sort_unstable();
                SessionSegment::NotKnown(ids)
            }
        };
        let asn = r.v.get("neighborAS").and_then(asn_of);
        let state = r.text("state");
        match found.entry((edge.clone(), neighbour, segment.clone())) {
            Entry::Vacant(v) => {
                v.insert(BgpSession {
                    edge,
                    neighbour,
                    segment,
                    asn,
                    state,
                    spans: vec![r.span()],
                });
            }
            Entry::Occupied(mut o) => {
                let s = o.get_mut();
                if s.state != state {
                    s.state = None;
                }
                if s.asn != asn {
                    s.asn = None;
                }
                s.spans.push(r.span());
            }
        }
    }
    found.into_values().collect()
}
