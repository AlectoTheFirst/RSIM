//! The OSPF database guard: the comparison of the link-state database that
//! the twin builds for a router with the collected database of the same
//! router, LSA by LSA.
//!
//! The comparison uses the meaning of each LSA. The age, the sequence
//! number and the checksum are not compared. An LSA at the maximum age is
//! left out. The LSAs of one key are merged, and their values are joined.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use rsim_core::{Prefix, SourceSpan};
use rsim_routing::ospf::{
    AreaId, Body, Database, LinkKind, Lsa, LsaType, Reference, RouterId, RouterLink, Version,
    mask_len,
};

/// The category of one LSA row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    Match,
    Differ,
    OnlyBuilt,
    OnlyCollected,
}

impl Category {
    /// The name in the tables, for example `only_built`.
    pub fn name(self) -> &'static str {
        match self {
            Category::Match => "match",
            Category::Differ => "differ",
            Category::OnlyBuilt => "only_built",
            Category::OnlyCollected => "only_collected",
        }
    }
}

/// One LSA of the database guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LsaRow {
    pub version: Version,
    pub vrf: String,
    /// `None` for an AS-external LSA.
    pub area: Option<AreaId>,
    pub lsa_type: LsaType,
    /// The key text of the LSA in its type, for example `192.0.2.0/24 from
    /// 192.0.2.1` for a summary LSA.
    pub key: String,
    pub category: Category,
    /// The fields that differ, for example `links` or `metric`.
    pub fields: Vec<&'static str>,
    /// The values of the built LSA: one `name value` text for each field,
    /// joined with `; `. The items of a set field are joined with `, `.
    pub built: Option<String>,
    pub collected: Option<String>,
    pub built_spans: Vec<SourceSpan>,
    pub collected_spans: Vec<SourceSpan>,
}

/// The fields of an LSA, each with its set of values, in a fixed order.
type Fields = Vec<(&'static str, BTreeSet<String>)>;

/// The fields of the LSAs of one key: each field with its set of values,
/// in a fixed order, and the spans of the LSAs.
#[derive(Default)]
struct Entry {
    fields: Fields,
    spans: Vec<SourceSpan>,
}

impl Entry {
    fn add(&mut self, fields: Fields, span: SourceSpan) {
        if self.fields.is_empty() {
            self.fields = fields;
        } else {
            for ((_, held), (_, new)) in self.fields.iter_mut().zip(fields) {
                held.extend(new);
            }
        }
        self.spans.push(span);
    }

    fn text(&self) -> String {
        self.fields
            .iter()
            .map(|(name, values)| {
                let v = if values.is_empty() {
                    "none".to_string()
                } else {
                    values.iter().cloned().collect::<Vec<_>>().join(", ")
                };
                format!("{name} {v}")
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// The key of an entry: the area-free LSAs last, then the area, the type
/// and the key text.
type EntryKey = (bool, AreaId, LsaType, String);

/// The lookups of one database that map a value that depends on the
/// designated router to a value that does not.
struct Index<'a> {
    db: &'a Database,
}

impl Index<'_> {
    fn lsas(&self) -> impl Iterator<Item = &Lsa> {
        self.db.lsas.values().filter(|l| !l.expired())
    }

    /// The subnet of an OSPFv2 network LSA, else `None` for a mask that is
    /// not contiguous or absent.
    fn v2_subnet(lsa: &Lsa) -> Option<Prefix> {
        match &lsa.body {
            Body::Network { mask: Some(m), .. } => {
                mask_len(*m).map(|len| Prefix::new(IpAddr::V4(lsa.lsid), len))
            }
            _ => None,
        }
    }

    /// The subnet of an OSPFv2 transit link: the network LSA of the area
    /// with the link ID as its link-state ID, else the network LSA of the
    /// area whose subnet holds the link data.
    fn v2_transit(&self, area: Option<AreaId>, id: Ipv4Addr, data: Option<Ipv4Addr>) -> String {
        let nets = || {
            self.lsas()
                .filter(move |l| l.lsa_type == LsaType::Network && l.area == area)
        };
        let by_id = nets().filter(|l| l.lsid == id).find_map(Index::v2_subnet);
        let by_data = || {
            data.and_then(|d| {
                nets()
                    .filter_map(Index::v2_subnet)
                    .find(|p| p.contains(IpAddr::V4(d)))
            })
        };
        match by_id.or_else(by_data) {
            Some(p) => p.to_string(),
            None => format!("dr {id}"),
        }
    }

    /// The attached routers of an OSPFv3 network LSA in order.
    fn v3_attached(&self, area: Option<AreaId>, dr: RouterId, id: u32) -> Option<Vec<RouterId>> {
        self.lsas()
            .find(|l| {
                l.lsa_type == LsaType::Network
                    && l.area == area
                    && l.adv_router == dr
                    && u32::from(l.lsid) == id
            })
            .and_then(|l| match &l.body {
                Body::Network { attached, .. } => {
                    let mut a = attached.clone();
                    a.sort();
                    a.dedup();
                    Some(a)
                }
                _ => None,
            })
    }

    /// The text of an OSPFv3 transit network: its attached routers, else the
    /// designated router and its interface ID.
    fn v3_network(&self, area: Option<AreaId>, dr: RouterId, id: u32) -> String {
        match self.v3_attached(area, dr, id) {
            Some(a) => format!("network of {}", join_ids(&a)),
            None => format!("network dr {dr} interface {id}"),
        }
    }

    /// The prefixes of the intra-area-prefix LSAs that refer to an OSPFv3
    /// network LSA, in order.
    fn v3_network_prefixes(&self, area: Option<AreaId>, dr: RouterId, id: u32) -> Vec<Prefix> {
        let mut out: Vec<Prefix> = self
            .lsas()
            .filter(|l| l.lsa_type == LsaType::IntraAreaPrefix && l.area == area)
            .filter_map(|l| match &l.body {
                Body::IntraAreaPrefix {
                    reference: Reference::Network(n),
                    router,
                    prefixes,
                } if *n == id && *router == dr => Some(prefixes.iter().map(|(p, _)| *p)),
                _ => None,
            })
            .flatten()
            .collect();
        out.sort();
        out.dedup();
        out
    }

    fn link_text(&self, area: Option<AreaId>, l: &RouterLink) -> String {
        match self.db.version {
            Version::V2 => {
                let id = match l.kind {
                    LinkKind::Transit => self.v2_transit(area, l.id, l.data),
                    _ => l.id.to_string(),
                };
                let data = l.data.map_or("none".to_string(), |d| d.to_string());
                format!("{} {id} data {data} metric {}", l.kind.name(), l.metric)
            }
            Version::V3 => {
                let to = match (l.kind, l.neighbor_interface_id) {
                    (LinkKind::Transit, Some(n)) => self.v3_network(area, l.id, n),
                    _ => l.id.to_string(),
                };
                format!("{} {to} metric {}", l.kind.name(), l.metric)
            }
        }
    }

    /// The key text and the fields of an LSA.
    fn entry(&self, lsa: &Lsa) -> (String, Fields) {
        let one = |v: String| BTreeSet::from([v]);
        let adv = lsa.adv_router;
        match &lsa.body {
            Body::Router { links } => (
                adv.to_string(),
                vec![(
                    "links",
                    links.iter().map(|l| self.link_text(lsa.area, l)).collect(),
                )],
            ),
            Body::Network { attached, .. } => {
                let key = match self.db.version {
                    Version::V2 => match Index::v2_subnet(lsa) {
                        Some(p) => p.to_string(),
                        None => format!("{} from {adv} with no usable mask", lsa.lsid),
                    },
                    Version::V3 => {
                        let id = u32::from(lsa.lsid);
                        let prefixes = self.v3_network_prefixes(lsa.area, adv, id);
                        if prefixes.is_empty() {
                            format!("dr {adv} interface {id}")
                        } else {
                            join_prefixes(&prefixes)
                        }
                    }
                };
                (
                    key,
                    vec![("attached", attached.iter().map(|r| r.to_string()).collect())],
                )
            }
            Body::Summary { prefix, metric } => (
                format!("{prefix} from {adv}"),
                vec![("metric", one(metric.to_string()))],
            ),
            Body::AsbrSummary { router, metric } => (
                format!("{router} from {adv}"),
                vec![("metric", one(metric.to_string()))],
            ),
            Body::External {
                prefix,
                metric,
                metric_type,
                forwarding,
            } => {
                let forwarding = forwarding.filter(|f| !f.is_unspecified());
                (
                    format!("{prefix} from {adv}"),
                    vec![
                        ("metric", one(metric.to_string())),
                        (
                            "metric_type",
                            one(metric_type.map_or("none".to_string(), |t| t.to_string())),
                        ),
                        (
                            "forwarding",
                            one(forwarding.map_or("none".to_string(), |f| f.to_string())),
                        ),
                    ],
                )
            }
            Body::Link {
                prefixes,
                interface,
                ..
            } => {
                let key = match interface {
                    Some(i) => format!("{adv} on {i}"),
                    None => format!("{adv} interface {}", u32::from(lsa.lsid)),
                };
                (
                    key,
                    vec![("prefixes", prefixes.iter().map(|p| p.to_string()).collect())],
                )
            }
            Body::IntraAreaPrefix {
                reference,
                router,
                prefixes,
            } => {
                let key = match reference {
                    Reference::Router => router.to_string(),
                    Reference::Network(id) => self.v3_network(lsa.area, *router, *id),
                };
                (
                    key,
                    vec![(
                        "prefixes",
                        prefixes
                            .iter()
                            .map(|(p, m)| format!("{p} metric {m}"))
                            .collect(),
                    )],
                )
            }
        }
    }

    fn entries(&self) -> BTreeMap<EntryKey, Entry> {
        let mut out: BTreeMap<EntryKey, Entry> = BTreeMap::new();
        for lsa in self.lsas() {
            let (key, fields) = self.entry(lsa);
            let k = (
                lsa.area.is_none(),
                lsa.area.unwrap_or(Ipv4Addr::UNSPECIFIED),
                lsa.lsa_type,
                key,
            );
            out.entry(k).or_default().add(fields, lsa.span.clone());
        }
        out
    }
}

fn join_ids(ids: &[RouterId]) -> String {
    ids.iter()
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn join_prefixes(prefixes: &[Prefix]) -> String {
    prefixes
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The rows of the comparison of the database that the twin builds for a
/// router with the collected database of the same router, version and VRF,
/// in the order of area, LSA type and key text. The version and the VRF of
/// the rows come from `built`.
///
/// The key of a router LSA is its advertising router, and its links compare
/// as a set of kind, link ID, link data and metric. The link ID of an
/// OSPFv2 transit link is the subnet of the network LSA of the designated
/// router. The neighbour of an OSPFv3 transit link is the set of the
/// attached routers of the network LSA. The key of an OSPFv2 network LSA is
/// its subnet, and the key of an OSPFv3 network LSA is the set of prefixes
/// of the intra-area-prefix LSAs that refer to it. A network LSA compares
/// its attached routers as a set. The key of a summary, an NSSA or an
/// external LSA is the prefix and the advertising router, and the LSA
/// compares the metric, the metric type and the forwarding address. An
/// intra-area-prefix LSA compares its prefixes with their metrics, and a
/// link LSA compares its prefixes.
pub fn compare_databases(built: &Database, collected: &Database) -> Vec<LsaRow> {
    let mine = Index { db: built }.entries();
    let theirs = Index { db: collected }.entries();
    let keys: BTreeSet<&EntryKey> = mine.keys().chain(theirs.keys()).collect();
    keys.into_iter()
        .map(|k| {
            let (no_area, area, lsa_type, key) = k;
            let b = mine.get(k);
            let c = theirs.get(k);
            let (category, fields) = match (b, c) {
                (Some(b), Some(c)) => {
                    let fields: Vec<&'static str> = b
                        .fields
                        .iter()
                        .zip(&c.fields)
                        .filter(|((_, x), (_, y))| x != y)
                        .map(|((name, _), _)| *name)
                        .collect();
                    if fields.is_empty() {
                        (Category::Match, fields)
                    } else {
                        (Category::Differ, fields)
                    }
                }
                (Some(_), None) => (Category::OnlyBuilt, Vec::new()),
                _ => (Category::OnlyCollected, Vec::new()),
            };
            LsaRow {
                version: built.version,
                vrf: built.vrf.clone(),
                area: (!no_area).then_some(*area),
                lsa_type: *lsa_type,
                key: key.clone(),
                category,
                fields,
                built: b.map(Entry::text),
                collected: c.map(Entry::text),
                built_spans: b.map(|e| e.spans.clone()).unwrap_or_default(),
                collected_spans: c.map(|e| e.spans.clone()).unwrap_or_default(),
            }
        })
        .collect()
}

/// The number of LSA rows of each category.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub matched: usize,
    pub differ: usize,
    pub only_built: usize,
    pub only_collected: usize,
}

impl Counts {
    pub fn of<'a>(rows: impl IntoIterator<Item = &'a LsaRow>) -> Counts {
        let mut c = Counts::default();
        for r in rows {
            match r.category {
                Category::Match => c.matched += 1,
                Category::Differ => c.differ += 1,
                Category::OnlyBuilt => c.only_built += 1,
                Category::OnlyCollected => c.only_collected += 1,
            }
        }
        c
    }

    /// The number of rows of the match rate: all rows.
    pub fn compared(&self) -> usize {
        self.matched + self.differ + self.only_built + self.only_collected
    }

    /// The match rate in percent with 1 decimal, or `None` with no row.
    pub fn rate(&self) -> Option<f64> {
        let n = self.compared();
        (n > 0).then(|| (self.matched as f64 * 1000.0 / n as f64).round() / 10.0)
    }
}

#[cfg(test)]
mod tests;
