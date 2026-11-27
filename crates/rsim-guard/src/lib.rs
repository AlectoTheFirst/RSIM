//! The guards of the twin. The RIB guard compares the computed route table
//! of a device and VRF with its collected route table. The OSPF database
//! guard in [`ospf`] compares the link-state database that the twin builds
//! for a router with its collected database.

pub mod ospf;

use std::collections::{BTreeMap, BTreeSet};

use rsim_core::{Prefix, RibGuardFlag, SourceSpan};
use rsim_functions::{Fib, Route, RouteKind};

/// The class of a collected route in the guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Class {
    Compared,
    NotComputed(String),
    /// A route that the calculation takes from the collected table.
    Seeded,
}

/// A collected route of one prefix with the protocol word of the device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectedRoute {
    pub protocol: String,
    pub class: Class,
}

/// The category of one route of the guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    Match,
    Differ,
    OnlyComputed,
    OnlyCollected,
    NotComputed,
    Seeded,
}

impl Category {
    /// The name in the tables, for example `only_computed`.
    pub fn name(self) -> &'static str {
        match self {
            Category::Match => "match",
            Category::Differ => "differ",
            Category::OnlyComputed => "only_computed",
            Category::OnlyCollected => "only_collected",
            Category::NotComputed => "not_computed",
            Category::Seeded => "seeded",
        }
    }
}

/// One side of a route of the guard. A next hop is `gateway@interface`, or
/// `interface` with no gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View {
    pub kind: String,
    pub next_hops: Vec<String>,
    pub unknown: Option<String>,
}

impl View {
    /// The view of a route. A route with no next hop that is not a local or
    /// a discard route is unknown, with its reason.
    pub fn of(r: &Route) -> View {
        let unknown = (r.next_hops().is_empty()
            && !matches!(r.kind, RouteKind::Local | RouteKind::Null))
        .then(|| {
            r.unknown_reason()
                .unwrap_or("a route with no next hop")
                .to_string()
        });
        View {
            kind: r.kind.name().to_string(),
            next_hops: r
                .next_hops()
                .iter()
                .map(|h| match h.gateway {
                    Some(g) => format!("{g}@{}", h.interface),
                    None => h.interface.to_string(),
                })
                .collect(),
            unknown,
        }
    }
}

/// One route of the guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub vrf: String,
    pub prefix: Prefix,
    pub category: Category,
    /// The protocol word of the collected route, else the kind of the
    /// computed route.
    pub protocol: String,
    pub computed: Option<View>,
    pub collected: Option<View>,
    /// The fields that differ, `kind` or `next_hops`.
    pub fields: Vec<&'static str>,
    pub reason: String,
    pub spans: Vec<SourceSpan>,
}

/// True for a prefix in the loopback range or the link-local range, whose
/// routes do not forward to another device.
fn host_scope(p: &Prefix) -> bool {
    let inside = |range: &str| {
        let r: Prefix = range.parse().expect("a valid prefix");
        p.len() >= r.len() && r.contains(p.addr())
    };
    ["127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10"]
        .into_iter()
        .any(inside)
}

/// The rows of one device and VRF in prefix order. `collected` is the
/// route table of the collected rows, and `routes` holds the collected
/// route of each prefix of the rows. A prefix of `collected` that `routes`
/// does not hold, for example a local route of the config, is left out, and
/// so is a loopback or link-local prefix. If no prefix of `routes` has a
/// local route in `collected`, the computed local routes are left out. A
/// computed route with no next hop that is not a local or a discard route
/// is not computed, with its reason.
pub fn compare(
    vrf: &str,
    computed: &Fib,
    collected: &Fib,
    routes: &BTreeMap<Prefix, CollectedRoute>,
) -> Vec<Row> {
    let computed_routes: BTreeMap<Prefix, Route> = computed.entries().into_iter().collect();
    // The address families whose collected table lists local routes.
    let lists_local = |v4: bool| {
        routes.keys().any(|p| {
            p.addr().is_ipv4() == v4 && collected.get(p).is_some_and(|r| r.kind == RouteKind::Local)
        })
    };
    let (local_v4, local_v6) = (lists_local(true), lists_local(false));
    let prefixes: BTreeSet<Prefix> = computed_routes
        .iter()
        .filter(|(p, r)| {
            let listed = if p.addr().is_ipv4() {
                local_v4
            } else {
                local_v6
            };
            listed || r.kind != RouteKind::Local || routes.contains_key(*p)
        })
        .map(|(p, _)| p)
        .chain(routes.keys())
        .copied()
        .filter(|p| !host_scope(p))
        .collect();
    let mut rows = Vec::new();
    for prefix in prefixes {
        let mine = computed_routes.get(&prefix);
        let theirs = routes
            .get(&prefix)
            .and_then(|c| collected.get(&prefix).map(|r| (c, r)));
        let row = |category, protocol: String, fields, reason: String| Row {
            vrf: vrf.to_string(),
            prefix,
            category,
            protocol,
            computed: mine.map(View::of),
            collected: theirs.as_ref().map(|(_, r)| View::of(r)),
            fields,
            reason,
            spans: theirs
                .iter()
                .flat_map(|(_, r)| r.spans.iter().cloned())
                .chain(mine.iter().flat_map(|r| r.spans.iter().cloned()))
                .collect(),
        };
        let mine_unknown = mine.and_then(|m| View::of(m).unknown);
        let out = match (mine, theirs.as_ref()) {
            (None, None) => continue,
            (Some(m), None) => match mine_unknown {
                Some(why) => row(
                    Category::NotComputed,
                    m.kind.name().to_string(),
                    Vec::new(),
                    format!("computed route unknown: {why}"),
                ),
                None => row(
                    Category::OnlyComputed,
                    m.kind.name().to_string(),
                    Vec::new(),
                    String::new(),
                ),
            },
            (_, Some((c, r))) => match &c.class {
                Class::NotComputed(why) => row(
                    Category::NotComputed,
                    c.protocol.clone(),
                    Vec::new(),
                    why.clone(),
                ),
                Class::Seeded => row(
                    Category::Seeded,
                    c.protocol.clone(),
                    Vec::new(),
                    String::new(),
                ),
                Class::Compared => {
                    let theirs_view = View::of(r);
                    if let Some(why) = &theirs_view.unknown {
                        row(
                            Category::NotComputed,
                            c.protocol.clone(),
                            Vec::new(),
                            format!("collected route unknown: {why}"),
                        )
                    } else if let Some(why) = mine_unknown {
                        row(
                            Category::NotComputed,
                            c.protocol.clone(),
                            Vec::new(),
                            format!("computed route unknown: {why}"),
                        )
                    } else if let Some(m) = mine {
                        let mine_view = View::of(m);
                        let mut fields = Vec::new();
                        if mine_view.kind != theirs_view.kind {
                            fields.push("kind");
                        }
                        if mine_view.next_hops != theirs_view.next_hops {
                            fields.push("next_hops");
                        }
                        let category = if fields.is_empty() {
                            Category::Match
                        } else {
                            Category::Differ
                        };
                        row(category, c.protocol.clone(), fields, String::new())
                    } else {
                        row(
                            Category::OnlyCollected,
                            c.protocol.clone(),
                            Vec::new(),
                            String::new(),
                        )
                    }
                }
            },
        };
        rows.push(out);
    }
    rows
}

/// Sets the guard result of each collected route of `rows` in the route
/// table that forwards: `MatchesCollected` for a match, and
/// `DiffersFromCollected` for a difference or a route that only the
/// collected table holds.
pub fn mark(fib: &mut Fib, rows: &[Row]) {
    for r in rows {
        let flag = match r.category {
            Category::Match => RibGuardFlag::MatchesCollected,
            Category::Differ | Category::OnlyCollected => RibGuardFlag::DiffersFromCollected,
            _ => continue,
        };
        fib.set_guard(&r.prefix, flag);
    }
}

/// The number of rows of each category.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub matched: usize,
    pub differ: usize,
    pub only_computed: usize,
    pub only_collected: usize,
    pub not_computed: usize,
    pub seeded: usize,
}

impl Counts {
    pub fn of<'a>(rows: impl IntoIterator<Item = &'a Row>) -> Counts {
        let mut c = Counts::default();
        for r in rows {
            match r.category {
                Category::Match => c.matched += 1,
                Category::Differ => c.differ += 1,
                Category::OnlyComputed => c.only_computed += 1,
                Category::OnlyCollected => c.only_collected += 1,
                Category::NotComputed => c.not_computed += 1,
                Category::Seeded => c.seeded += 1,
            }
        }
        c
    }

    /// The number of rows of the match rate. These are the matches, the
    /// differences and the routes of only one table. The rows that are not
    /// computed and the seeded rows are outside the rate.
    pub fn compared(&self) -> usize {
        self.matched + self.differ + self.only_computed + self.only_collected
    }

    /// The match rate in percent with 1 decimal, or `None` with no compared
    /// row.
    pub fn rate(&self) -> Option<f64> {
        let n = self.compared();
        (n > 0).then(|| (self.matched as f64 * 1000.0 / n as f64).round() / 10.0)
    }
}

#[cfg(test)]
mod tests;
