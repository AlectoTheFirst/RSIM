//! The overlay rows of the route table of the orchestrator, and the order
//! of the routes of one prefix on an edge.
//!
//! The route table holds the routes that each edge advertises into the
//! overlay: one row for each subnet and each preferred exit of an edge. An
//! exit of a router, a filtered or unreachable exit and an eligible exit
//! give no row and are counted. A row whose edge is not known and a row of
//! a segment that the enterprise does not list are kept and counted.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{Prefix, SourceSpan};

use super::json::{J, address, int, interface_address, max_len, numeric_id, text};
use super::reader::Segment;

/// The kind of an exit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitKind {
    Connected,
    Static,
    Learned,
    Other(String),
}

/// A route that an edge advertises into the overlay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayRow {
    pub prefix: Prefix,
    /// The segment of the exit, of the learned route or of the `subnet`
    /// key. It is the Global Segment when the row names no segment.
    pub segment: u32,
    /// The logicalId of the edge, or `None` when the exit has no
    /// `edgeLogicalId` and its `edgeId` is not an edge of the listing.
    pub edge: Option<String>,
    /// `edgeId`.
    pub edge_id: Option<u64>,
    pub kind: ExitKind,
    /// `entity`, for example `EDGE` or `HUB`.
    pub entity: Option<String>,
    pub protocol: Option<String>,
    pub route_type: Option<String>,
    pub interface: Option<String>,
    /// `neighborIp`, else `nextHopIp`.
    pub next_hop: Option<IpAddr>,
    /// `cost`, else `metric`.
    pub cost: Option<i64>,
    pub span: SourceSpan,
}

/// The counts of the exits and subnets that give no row, and of the rows
/// with an edge or a segment that the enterprise does not list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Exits whose `exitType` is not `EDGE`.
    pub router: u32,
    /// Edge exits that are `filtered` or `UNREACHABLE`.
    pub withheld: u32,
    /// Edge exits of `eligableExits`.
    pub eligible: u32,
    /// Rows whose edge is not known.
    pub no_edge: u32,
    /// Subnets with no prefix that reads.
    pub no_prefix: u32,
    /// Rows whose segment is not a segment of the enterprise.
    pub other_segment: u32,
}

/// The overlay rows of a route table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OverlayTable {
    pub rows: Vec<OverlayRow>,
    pub counts: Counts,
}

/// A prefix `address/length`; the host bits are cleared.
fn prefix(text: &str) -> Option<Prefix> {
    let (a, l) = text.trim().split_once('/')?;
    let addr = address(a)?;
    let len: u8 = l.trim().parse().ok()?;
    (len <= max_len(addr)).then(|| Prefix::new(addr, len))
}

/// True for an exit that the orchestrator keeps out of use.
fn withheld(e: J<'_>) -> bool {
    let filtered = e.v.get("filtered").is_some_and(|v| {
        v.as_bool() == Some(true)
            || text(v).is_some_and(|t| t == "1" || t.eq_ignore_ascii_case("true"))
    });
    filtered
        || e.str("state")
            .is_some_and(|s| s.eq_ignore_ascii_case("UNREACHABLE"))
}

/// The overlay rows of the `route_table` section. The `subnet` key is
/// `<prefix>:<segment>`, split at its last colon, so an IPv6 prefix stays
/// whole; a key that does not read gives the prefix of `learnedRoute`. An
/// exit names its edge by `edgeLogicalId`, else by the numeric `edgeId`
/// through `edges`.
pub fn overlay(root: J<'_>, edges: &BTreeMap<u64, String>, segments: &[Segment]) -> OverlayTable {
    let global = segments.iter().find(|s| s.global).map_or(0, |s| s.id);
    let mut t = OverlayTable::default();
    for record in root.list("subnets") {
        let route = record.obj("learnedRoute");
        let split = record.str("subnet").and_then(|s| s.rsplit_once(':'));
        let from_key = split.and_then(|(h, _)| prefix(h));
        let Some(p) = from_key.or_else(|| {
            route
                .and_then(interface_address)
                .map(|(a, l)| Prefix::new(a, l))
        }) else {
            t.counts.no_prefix += 1;
            continue;
        };
        let tail = if from_key.is_some() {
            split.map(|(_, t)| t)
        } else {
            None
        };
        for (bucket, preferred) in [("preferredExits", true), ("eligableExits", false)] {
            for e in record.list(bucket) {
                if !e
                    .str("exitType")
                    .is_some_and(|x| x.eq_ignore_ascii_case("EDGE"))
                {
                    t.counts.router += 1;
                    continue;
                }
                if withheld(e) {
                    t.counts.withheld += 1;
                    continue;
                }
                if !preferred {
                    t.counts.eligible += 1;
                    continue;
                }
                let edge_id = e.v.get("edgeId").and_then(numeric_id);
                let edge = e
                    .text("edgeLogicalId")
                    .or_else(|| edge_id.and_then(|n| edges.get(&n).cloned()));
                if edge.is_none() {
                    t.counts.no_edge += 1;
                }
                let seg = |v: Option<i64>| v.and_then(|n| u32::try_from(n).ok());
                let named = seg(e.int("segmentId"))
                    .or_else(|| seg(route.and_then(|r| r.int("segmentId"))))
                    .or_else(|| tail.and_then(|x| x.trim().parse().ok()));
                let segment = match named {
                    Some(n) => {
                        if !segments.iter().any(|s| s.id == n) {
                            t.counts.other_segment += 1;
                        }
                        n
                    }
                    None => global,
                };
                let kind = match e.str("type").map(str::to_ascii_uppercase).as_deref() {
                    Some("CONNECTED") => ExitKind::Connected,
                    Some("STATIC") => ExitKind::Static,
                    Some("LEARNED") => ExitKind::Learned,
                    Some(o) => ExitKind::Other(o.to_string()),
                    None => ExitKind::Other(String::new()),
                };
                t.rows.push(OverlayRow {
                    prefix: p,
                    segment,
                    edge,
                    edge_id,
                    kind,
                    entity: e.text("entity"),
                    protocol: e.text("protocol"),
                    route_type: e.text("routeType"),
                    interface: e.text("interface"),
                    next_hop: e
                        .str("neighborIp")
                        .or_else(|| e.str("nextHopIp"))
                        .and_then(address),
                    cost: e.v.get("cost").or_else(|| e.v.get("metric")).and_then(int),
                    span: e.span(),
                });
            }
        }
    }
    t
}

/// The kind of a dynamic route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DynamicKind {
    /// A route of the site: OSPF intra area or inter area, or BGP that is
    /// not an uplink route.
    Site,
    /// A route of the site: OSPF external type 1 or type 2, or uplink BGP.
    SiteExternal,
    /// A route of another edge through the overlay, with whether its cost
    /// is a preferred cost.
    Overlay { preferred_cost: Option<bool> },
}

/// The class of a route of one prefix length on an edge, in order: the
/// first class wins. A static route with Preferred off is the last resort.
/// `NotKnown` is a route whose place in the order is not known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteClass {
    LocalConnected,
    LocalStaticPreferred,
    LocalNsdStatic,
    RemoteNsdStatic,
    RemoteConnected,
    RemoteStatic,
    GatewaySecureStatic,
    GatewayStatic,
    Dynamic {
        kind: DynamicKind,
        preference: Option<i64>,
    },
    LocalStatic,
    NotKnown,
}

impl RouteClass {
    fn rank(self) -> Option<u8> {
        Some(match self {
            RouteClass::LocalConnected => 0,
            RouteClass::LocalStaticPreferred => 1,
            RouteClass::LocalNsdStatic => 2,
            RouteClass::RemoteNsdStatic => 3,
            RouteClass::RemoteConnected => 4,
            RouteClass::RemoteStatic => 5,
            RouteClass::GatewaySecureStatic => 6,
            RouteClass::GatewayStatic => 7,
            RouteClass::Dynamic { .. } => 8,
            RouteClass::LocalStatic => 9,
            RouteClass::NotKnown => return None,
        })
    }

    /// The order of 2 classes: `Less` when `self` wins. A site route wins
    /// over an overlay route, an overlay route with a preferred cost wins
    /// over a site external route, and else the lower preference wins.
    /// `None` when the order is not known.
    pub fn order(self, other: RouteClass) -> Option<Ordering> {
        use DynamicKind::{Overlay, Site, SiteExternal};
        match (self, other) {
            (
                RouteClass::Dynamic {
                    kind: a,
                    preference: pa,
                },
                RouteClass::Dynamic {
                    kind: b,
                    preference: pb,
                },
            ) => match (a, b) {
                (Site, Overlay { .. }) => Some(Ordering::Less),
                (Overlay { .. }, Site) => Some(Ordering::Greater),
                (
                    Overlay {
                        preferred_cost: Some(true),
                    },
                    SiteExternal,
                ) => Some(Ordering::Less),
                (
                    SiteExternal,
                    Overlay {
                        preferred_cost: Some(true),
                    },
                ) => Some(Ordering::Greater),
                (
                    Overlay {
                        preferred_cost: None,
                    },
                    SiteExternal,
                )
                | (
                    SiteExternal,
                    Overlay {
                        preferred_cost: None,
                    },
                ) => None,
                _ => Some(pa?.cmp(&pb?)),
            },
            _ => Some(self.rank()?.cmp(&other.rank()?)),
        }
    }
}

/// The order of 2 routes of an edge: the longest prefix first, then the
/// class. `None` when the order is not known.
pub fn order(a: (Prefix, RouteClass), b: (Prefix, RouteClass)) -> Option<Ordering> {
    match b.0.len().cmp(&a.0.len()) {
        Ordering::Equal => a.1.order(b.1),
        o => Some(o),
    }
}

impl OverlayRow {
    /// The class of the row on the edge `local`: a row of another edge is a
    /// remote route. A learned row of another edge is an overlay dynamic
    /// route with no known preference. A row whose edge is not known, a
    /// static row of the edge, whose Preferred the row does not give, a
    /// learned row of the edge and a row of another kind are `NotKnown`.
    pub fn class(&self, local: &str) -> RouteClass {
        let Some(edge) = &self.edge else {
            return RouteClass::NotKnown;
        };
        let remote = edge.as_str() != local;
        match (&self.kind, remote) {
            (ExitKind::Connected, false) => RouteClass::LocalConnected,
            (ExitKind::Connected, true) => RouteClass::RemoteConnected,
            (ExitKind::Static, true) => RouteClass::RemoteStatic,
            (ExitKind::Learned, true) => RouteClass::Dynamic {
                kind: DynamicKind::Overlay {
                    preferred_cost: None,
                },
                preference: None,
            },
            (ExitKind::Static | ExitKind::Learned, false) | (ExitKind::Other(_), _) => {
                RouteClass::NotKnown
            }
        }
    }
}
