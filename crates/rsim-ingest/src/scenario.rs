//! The what-if layers of a scenario, and the forwarding table of each
//! device and VRF of a scenario: the collected table plus the difference
//! between the computed table of the scenario and the computed table of the
//! base.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use rsim_core::{NetFunction, Prefix, RibGuardFlag, SourceSpan};
use rsim_functions::{Fib, Route, RouteKind, RouteLookup};
use rsim_guard::{Category, Class, CollectedRoute, Row, View};
use rsim_routing::ospf::config::RouterConfig;

/// The reason of a collected route of a protocol that the engine does not
/// compute, in a scenario.
pub const NOT_RECOMPUTED: &str = "routing not recomputed";

/// The reason of a route that a scenario changes or keeps through a down
/// interface, where the computed table of the base does not agree with the
/// collected table.
pub const GUARD_MISMATCH: &str = "route table guard mismatch";

/// The vendors whose routers and switches a layer can change.
pub const VENDORS: &[&str] = &["vyos", "nxos", "iosxr", "iosxe"];

/// A what-if layer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Layer {
    /// Both ends of the link of the interface are administratively down. An
    /// interface with no link goes down alone. A far port with 2 or more
    /// peers stays up.
    LinkDown { device: String, interface: String },
}

impl Layer {
    /// The link-down layer of `<device>:<interface>`.
    pub fn link_down(target: &str) -> Result<Layer, String> {
        let bad = |s: &str| s.is_empty() || s.contains(char::is_whitespace);
        match target.split_once(':') {
            Some((device, interface)) if !bad(device) && !bad(interface) => Ok(Layer::LinkDown {
                device: device.to_string(),
                interface: interface.to_string(),
            }),
            _ => Err(format!("{target:?} is not <device>:<interface>")),
        }
    }

    /// The layer of a text, for example `link-down r1:eth1`.
    pub fn parse(text: &str) -> Result<Layer, String> {
        match text.split_once(' ') {
            Some(("link-down", target)) => Layer::link_down(target),
            _ => Err(format!(
                "{text:?} is not a layer: link-down <device>:<interface>"
            )),
        }
    }

    /// The text of the layer, for example `link-down r1:eth1`.
    pub fn text(&self) -> String {
        match self {
            Layer::LinkDown { device, interface } => format!("link-down {device}:{interface}"),
        }
    }

    /// The span of the layer at the position `n` of the scenario, from 1:
    /// the file `layer <n>: <text>` and the line 1.
    pub fn span(&self, n: usize) -> SourceSpan {
        SourceSpan::line(format!("layer {n}: {}", self.text()), 1)
    }
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text())
    }
}

/// The pass of the lowering of a router or a switch.
#[derive(Clone, Debug, Default)]
pub enum Pass {
    /// A snapshot twin. Each VRF forwards on its collected table.
    #[default]
    Snapshot,
    /// The base of a scenario. It forwards as a snapshot twin, and the
    /// lowering keeps the tables of each VRF with a guard.
    Base,
    /// A scenario. Each VRF with a guard forwards on the table of
    /// [`forward`].
    Scenario(DeviceScenario),
}

/// The inputs of the forwarding tables of one device in a scenario.
#[derive(Clone, Debug, Default)]
pub struct DeviceScenario {
    /// The tables of the base of each VRF with a guard.
    pub base: BTreeMap<String, BaseVrf>,
    /// The interfaces of the device that a layer takes down.
    pub down: BTreeSet<String>,
    /// The spans of the layers of the scenario.
    pub spans: Vec<SourceSpan>,
}

/// The tables of one VRF of the base with a guard.
#[derive(Clone, Debug)]
pub struct BaseVrf {
    pub computed: Fib,
    /// The collected table with the guard results.
    pub collected: Fib,
    pub rows: Vec<Row>,
}

/// True if the interface `name` is down: a layer names it or the interface
/// of which it is a sub-interface.
pub fn is_down(down: &BTreeSet<String>, name: &str) -> bool {
    down.contains(name)
        || down.iter().any(|d| {
            name.strip_prefix(d.as_str())
                .is_some_and(|rest| rest.starts_with('.'))
        })
}

/// Sets each OSPF interface of the config that is down to not up.
pub fn down_ospf(cfg: &mut RouterConfig, down: &BTreeSet<String>) {
    for p in &mut cfg.processes {
        for i in &mut p.interfaces {
            if is_down(down, &i.name) {
                i.up = false;
            }
        }
    }
}

/// The end of the RIB guard of a VRF, with the computed table `computed`
/// and the collected route of each prefix in `routes`. A snapshot pass
/// marks the collected table `t` with the guard rows and adds the rows to
/// `rows`. A base pass also adds the tables of the VRF to `tables`. A
/// scenario pass marks `t` with the rows of the base and replaces it with
/// the table of [`forward`], or of [`fallback`] for a VRF with no tables in
/// the base.
pub(crate) fn finish(
    pass: &Pass,
    vrf: &str,
    t: &mut Fib,
    routes: &BTreeMap<Prefix, CollectedRoute>,
    computed: Fib,
    rows: &mut Vec<Row>,
    tables: &mut Vec<(String, BaseVrf)>,
) {
    match pass {
        Pass::Snapshot | Pass::Base => {
            let r = rsim_guard::compare(vrf, &computed, t, routes);
            rsim_guard::mark(t, &r);
            if matches!(pass, Pass::Base) {
                tables.push((
                    vrf.to_string(),
                    BaseVrf {
                        computed,
                        collected: t.clone(),
                        rows: r.clone(),
                    },
                ));
            }
            rows.extend(r);
        }
        Pass::Scenario(s) => match s.base.get(vrf) {
            Some(b) => {
                rsim_guard::mark(t, &b.rows);
                *t = forward(t, routes, b, &computed, &s.down, &s.spans);
            }
            None => *t = fallback(t, &s.down, &s.spans),
        },
    }
}

/// A route with the spans of the layers added.
fn with_layers(r: &Route, spans: &[SourceSpan]) -> Route {
    let mut r = r.clone();
    r.spans.extend(spans.iter().cloned());
    r
}

/// An unknown route of the kind of `from`, with its spans and the spans of
/// the layers.
fn unknown(from: &Route, why: &str, spans: &[SourceSpan]) -> Route {
    let mut all = from.spans.clone();
    all.extend(spans.iter().cloned());
    Route::unknown(from.kind, why, all)
}

/// True if a next hop of the route leaves on a down interface.
fn through_down(r: &Route, down: &BTreeSet<String>) -> bool {
    r.next_hops()
        .iter()
        .any(|h| is_down(down, h.interface.as_str()))
}

/// A collected route that the scenario keeps: unknown with the reason
/// [`GUARD_MISMATCH`] if a next hop leaves on a down interface.
fn kept(
    r: &Route,
    flag: RibGuardFlag,
    down: &BTreeSet<String>,
    spans: &[SourceSpan],
) -> (Route, RibGuardFlag) {
    if through_down(r, down) {
        (
            unknown(r, GUARD_MISMATCH, spans),
            RibGuardFlag::DiffersFromCollected,
        )
    } else {
        (r.clone(), flag)
    }
}

/// The forwarding table of a VRF in a scenario. `t` is the collected table
/// with the guard results of the base, `routes` the collected route of each
/// prefix, `base` the tables of the base, and `computed` the computed table
/// of the scenario. For each prefix in order:
///
/// - A collected route that is not computed is unknown with the reason
///   [`NOT_RECOMPUTED`]. A seeded route stays.
/// - A prefix whose computed route is the same and known in the base and in
///   the scenario keeps its collected route.
/// - A prefix with no route in the base that the scenario computes gets the
///   computed route of the scenario.
/// - A prefix whose computed route changes takes the computed route of the
///   scenario, or is removed if the scenario has none, when the guard of
///   the base matches for the prefix. Else its route is unknown with the
///   reason [`GUARD_MISMATCH`].
/// - A kept route with a next hop on a down interface is unknown with the
///   reason [`GUARD_MISMATCH`].
///
/// The guard of the base matches for a prefix when its guard row is a
/// match, or, for a prefix with no guard row, when the collected route of
/// the base and the computed route of the base are the same and known, or
/// both absent. Each route that the scenario changes gets the spans of the
/// layers.
pub fn forward(
    t: &Fib,
    routes: &BTreeMap<Prefix, CollectedRoute>,
    base: &BaseVrf,
    computed: &Fib,
    down: &BTreeSet<String>,
    spans: &[SourceSpan],
) -> Fib {
    let rows: BTreeMap<Prefix, Category> =
        base.rows.iter().map(|r| (r.prefix, r.category)).collect();
    let mine: BTreeMap<Prefix, Route> = t.entries().into_iter().collect();
    let was: BTreeMap<Prefix, Route> = base.computed.entries().into_iter().collect();
    let now: BTreeMap<Prefix, Route> = computed.entries().into_iter().collect();
    let prefixes: BTreeSet<Prefix> = mine
        .keys()
        .chain(was.keys())
        .chain(now.keys())
        .copied()
        .collect();
    let view = |r: Option<&Route>| r.map(View::of);
    let known = |r: Option<&Route>| r.is_none_or(|r| View::of(r).unknown.is_none());
    let mut out = Fib::new();
    for p in prefixes {
        let col = mine.get(&p);
        let (b, s) = (was.get(&p), now.get(&p));
        let flag = t.guard(&p).unwrap_or(RibGuardFlag::NotChecked);
        let class = routes.get(&p).map(|c| &c.class);
        let result: Option<(Route, RibGuardFlag)> = match (class, col) {
            (Some(Class::NotComputed(_)), Some(c)) => {
                Some((unknown(c, NOT_RECOMPUTED, spans), flag))
            }
            (Some(Class::Seeded), Some(c)) => Some(kept(c, flag, down, spans)),
            _ if view(b) == view(s) && known(b) => col.map(|c| kept(c, flag, down, spans)),
            _ if b.is_none() && base.collected.get(&p).is_none() && col.is_none() => {
                s.map(|r| (with_layers(r, spans), RibGuardFlag::NotChecked))
            }
            _ => {
                let collected_base = base.collected.get(&p);
                let matches = match rows.get(&p) {
                    Some(c) => *c == Category::Match,
                    None => view(collected_base.as_ref()) == view(b) && known(b),
                };
                if matches {
                    s.map(|r| (with_layers(r, spans), RibGuardFlag::NotChecked))
                } else {
                    let from = col.or(b).or(s).or(collected_base.as_ref());
                    from.map(|r| {
                        (
                            unknown(r, GUARD_MISMATCH, spans),
                            RibGuardFlag::DiffersFromCollected,
                        )
                    })
                }
            }
        };
        if let Some((r, f)) = result {
            out.insert(p, r);
            out.set_guard(&p, f);
        }
    }
    out
}

/// The forwarding table of a collected table in a scenario with no computed
/// table: each learned route is unknown with the reason [`NOT_RECOMPUTED`],
/// and each other route with a next hop on a down interface is unknown with
/// the reason [`GUARD_MISMATCH`].
pub fn fallback(t: &Fib, down: &BTreeSet<String>, spans: &[SourceSpan]) -> Fib {
    let mut out = Fib::new();
    for (p, r) in t.entries() {
        let flag = t.guard(&p).unwrap_or(RibGuardFlag::NotChecked);
        let (r, f) = if matches!(r.kind, RouteKind::Learned(_)) {
            (unknown(&r, NOT_RECOMPUTED, spans), flag)
        } else {
            kept(&r, flag, down, spans)
        };
        out.insert(p, r);
        out.set_guard(&p, f);
    }
    out
}

/// A function of a device whose vendor has no route calculation, in a
/// scenario: a route lookup gets the tables of [`fallback`] with no down
/// interface. Each other function stays.
pub(crate) fn not_recomputed(
    f: Arc<dyn NetFunction>,
    spans: &[SourceSpan],
) -> Arc<dyn NetFunction> {
    let lookup = {
        let any: &dyn std::any::Any = f.as_ref();
        any.downcast_ref::<RouteLookup>().cloned()
    };
    match lookup {
        Some(mut r) => {
            for t in r.tables.values_mut() {
                *t = fallback(t, &BTreeSet::new(), spans);
            }
            Arc::new(r)
        }
        None => f,
    }
}

#[cfg(test)]
mod tests;
