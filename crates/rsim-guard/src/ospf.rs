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

/// The identity of an OSPFv3 network: the area, and the router ID and the
/// interface ID of the designated router.
type NetKey = (Option<AreaId>, RouterId, u32);

/// The lookups of one database that map a value that depends on the
/// designated router to a value that does not.
struct Index<'a> {
    db: &'a Database,
    /// The key texts of the OSPFv3 networks that map to a network of the
    /// other database with another designated router.
    names: BTreeMap<NetKey, String>,
    /// The area and the router of each OSPFv3 router LSA whose links have
    /// an interface ID in both databases.
    with_ids: BTreeSet<(Option<AreaId>, RouterId)>,
}

impl<'a> Index<'a> {
    fn new(db: &'a Database) -> Index<'a> {
        Index {
            db,
            names: BTreeMap::new(),
            with_ids: BTreeSet::new(),
        }
    }

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

    /// The key text of an OSPFv3 network: the prefixes of a network that
    /// maps to the other database, else the designated router and its
    /// interface ID.
    fn v3_network(&self, area: Option<AreaId>, dr: RouterId, id: u32) -> String {
        match self.names.get(&(area, dr, id)) {
            Some(name) => name.clone(),
            None => format!("dr {dr} interface {id}"),
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

    /// The OSPFv3 networks of the network LSAs, each with its prefixes.
    fn v3_networks(&self) -> BTreeMap<NetKey, Vec<Prefix>> {
        if self.db.version != Version::V3 {
            return BTreeMap::new();
        }
        self.lsas()
            .filter(|l| l.lsa_type == LsaType::Network)
            .map(|l| {
                let id = u32::from(l.lsid);
                (
                    (l.area, l.adv_router, id),
                    self.v3_network_prefixes(l.area, l.adv_router, id),
                )
            })
            .collect()
    }

    /// The area and the router of each OSPFv3 router LSA with a link that
    /// has no interface ID.
    fn v3_without_ids(&self) -> BTreeSet<(Option<AreaId>, RouterId)> {
        self.lsas()
            .filter(|l| match &l.body {
                Body::Router { links } => links.iter().any(|k| k.interface_id.is_none()),
                _ => false,
            })
            .map(|l| (l.area, l.adv_router))
            .collect()
    }

    /// The area and the router of each OSPFv3 router LSA.
    fn v3_routers(&self) -> BTreeSet<(Option<AreaId>, RouterId)> {
        self.lsas()
            .filter(|l| l.lsa_type == LsaType::Router)
            .map(|l| (l.area, l.adv_router))
            .collect()
    }

    fn link_text(&self, area: Option<AreaId>, adv: RouterId, l: &RouterLink) -> String {
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
                let text = format!("{} {to} metric {}", l.kind.name(), l.metric);
                match l.interface_id {
                    Some(i) if self.with_ids.contains(&(area, adv)) => {
                        format!("{text} on interface {i}")
                    }
                    _ => text,
                }
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
                    links
                        .iter()
                        .map(|l| self.link_text(lsa.area, adv, l))
                        .collect(),
                )],
            ),
            Body::Network { attached, .. } => {
                let attached = ("attached", attached.iter().map(|r| r.to_string()).collect());
                match self.db.version {
                    Version::V2 => {
                        let key = match Index::v2_subnet(lsa) {
                            Some(p) => p.to_string(),
                            None => format!("{} from {adv} with no usable mask", lsa.lsid),
                        };
                        (key, vec![attached])
                    }
                    Version::V3 => {
                        let id = u32::from(lsa.lsid);
                        let prefixes = self
                            .v3_network_prefixes(lsa.area, adv, id)
                            .iter()
                            .map(|p| p.to_string())
                            .collect();
                        (
                            self.v3_network(lsa.area, adv, id),
                            vec![attached, ("prefixes", prefixes)],
                        )
                    }
                }
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

fn join_prefixes(prefixes: &[Prefix]) -> String {
    prefixes
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The OSPFv3 networks of `nets` with prefixes and with no network of the
/// same identity in `other`, grouped by the area and the prefixes.
fn lone_networks(
    nets: &BTreeMap<NetKey, Vec<Prefix>>,
    other: &BTreeMap<NetKey, Vec<Prefix>>,
) -> BTreeMap<(Option<AreaId>, Vec<Prefix>), Vec<NetKey>> {
    let mut out: BTreeMap<(Option<AreaId>, Vec<Prefix>), Vec<NetKey>> = BTreeMap::new();
    for (k, prefixes) in nets {
        if !prefixes.is_empty() && !other.contains_key(k) {
            out.entry((k.0, prefixes.clone())).or_default().push(*k);
        }
    }
    out
}

/// The rows of the comparison of the database that the twin builds for a
/// router with the collected database of the same router, version and VRF,
/// in the order of area, LSA type and key text. The version and the VRF of
/// the rows come from `built`.
///
/// The key of a router LSA is its advertising router, and its links compare
/// as a set of kind, link ID, link data and metric. The link ID of an
/// OSPFv2 transit link is the subnet of the network LSA of the designated
/// router. An OSPFv3 link also compares its interface ID if each link of
/// the router LSAs of the router has one in both databases.
///
/// The key of an OSPFv2 network LSA is its subnet. The key of an OSPFv3
/// network is the router ID and the interface ID of the designated router.
/// The network LSA, the transit links to it and the intra-area-prefix LSA
/// that refers to it use this key. An OSPFv3 network with another
/// designated router in the other database has the key of its prefixes if
/// each database has exactly 1 such network with these prefixes in the
/// area. Else the network shows in only 1 database. A network LSA compares
/// its attached routers as a set, and an OSPFv3 network LSA also compares
/// the prefixes of the intra-area-prefix LSAs that refer to it.
///
/// The key of a summary LSA is the prefix and the advertising router, and
/// the key of an ASBR-summary LSA is the router and the advertising router.
/// These LSAs compare the metric. The key of an NSSA or an external LSA is
/// the prefix and the advertising router, and the LSA compares the metric,
/// the metric type and the forwarding address. An intra-area-prefix LSA
/// compares its prefixes with their metrics, and a link LSA compares its
/// prefixes.
pub fn compare_databases(built: &Database, collected: &Database) -> Vec<LsaRow> {
    let mut b = Index::new(built);
    let mut c = Index::new(collected);
    let without_ids: BTreeSet<_> = b
        .v3_without_ids()
        .union(&c.v3_without_ids())
        .copied()
        .collect();
    let with_ids: BTreeSet<_> = b
        .v3_routers()
        .union(&c.v3_routers())
        .filter(|k| !without_ids.contains(k))
        .copied()
        .collect();
    b.with_ids = with_ids.clone();
    c.with_ids = with_ids;
    let b_nets = b.v3_networks();
    let c_nets = c.v3_networks();
    let b_lone = lone_networks(&b_nets, &c_nets);
    let c_lone = lone_networks(&c_nets, &b_nets);
    for (k, bs) in &b_lone {
        if let (Some(cs), [bk]) = (c_lone.get(k), bs.as_slice())
            && let [ck] = cs.as_slice()
        {
            let name = join_prefixes(&k.1);
            b.names.insert(*bk, name.clone());
            c.names.insert(*ck, name);
        }
    }
    let mine = b.entries();
    let theirs = c.entries();
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
