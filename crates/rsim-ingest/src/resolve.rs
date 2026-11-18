//! The recursive resolution of the next hop of a collected route path that
//! names a gateway and no interface, for all vendors.
//!
//! A gateway resolves to the longest matching route of its VRF. A path of
//! that route with an interface gives the interface, with the gateway of the
//! path, or with the resolved gateway for a connected path; a path with a
//! gateway and no interface resolves in its turn. A route of the collected
//! table resolves the way the table shows, so through a default route too.
//! A gateway with no route, a resolution that comes back to a route that it
//! already went through, and a route that was not read, is unknown, a local
//! address or a discard route leave the next hop unresolved.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{Prefix, PrefixTable, SourceSpan, TriePrefixTable};

/// The start of the reason of a route whose next hop does not resolve.
pub const NOT_RESOLVED: &str = "next hop not resolved";

/// One path of a collected route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path {
    pub interface: Option<String>,
    pub gateway: Option<IpAddr>,
    /// The VRF of the gateway, if it is not the VRF of the route.
    pub vrf: Option<String>,
}

/// What a route of the table gives to a resolution through it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// The paths of a route that forwards.
    Paths(Vec<Path>),
    /// An address of the device itself.
    Local,
    /// A discard route.
    Null,
    /// A route that was not read or whose forwarding is not known.
    Unknown,
}

/// One resolved next hop: the egress interface and the gateway on it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hop {
    pub interface: String,
    pub gateway: Option<IpAddr>,
}

/// Where a route comes from. A collected route resolves the way the device
/// shows it; a computed route resolves through a default route only if the
/// vendor profile allows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Collected,
    Computed,
}

/// True if a route of `origin` resolves its next hop through a default
/// route, with `computed_through_default` the flag of the vendor profile.
pub fn through_default(origin: Origin, computed_through_default: bool) -> bool {
    match origin {
        Origin::Collected => true,
        Origin::Computed => computed_through_default,
    }
}

/// The spans in their first order, each once.
fn unique(spans: Vec<SourceSpan>) -> Vec<SourceSpan> {
    let mut out: Vec<SourceSpan> = Vec::with_capacity(spans.len());
    for s in spans {
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

#[derive(Clone, Debug, Default)]
struct Table {
    trie: TriePrefixTable<usize>,
    routes: Vec<(Target, Vec<SourceSpan>)>,
    /// True if each lookup of the VRF is unknown.
    unknown: Option<Vec<SourceSpan>>,
}

/// The routes of each VRF of a device, for the resolution.
#[derive(Clone, Debug, Default)]
pub struct Resolver {
    tables: BTreeMap<String, Table>,
}

/// A resolution that did not give a next hop: the reason and the spans of
/// the routes that it went through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unresolved {
    pub reason: String,
    pub why: String,
    pub spans: Vec<SourceSpan>,
}

impl Resolver {
    pub fn new() -> Self {
        Resolver::default()
    }

    /// Adds a route. A route of the same VRF and prefix is replaced.
    pub fn add(&mut self, vrf: &str, prefix: Prefix, target: Target, spans: Vec<SourceSpan>) {
        let t = self.tables.entry(vrf.to_string()).or_default();
        match t.trie.get(&prefix) {
            Some(i) => t.routes[*i] = (target, spans),
            None => {
                t.routes.push((target, spans));
                t.trie.insert(prefix, t.routes.len() - 1);
            }
        }
    }

    /// Makes each resolution in a VRF unknown, for example when a line of
    /// its table with no prefix was not read.
    pub fn unknown_vrf(&mut self, vrf: &str, spans: Vec<SourceSpan>) {
        self.tables.entry(vrf.to_string()).or_default().unknown = Some(spans);
    }

    /// The hops of the paths of a route of `vrf`: a path with an interface
    /// stays as it is, and a path with a gateway and no interface resolves.
    /// The spans are those of the routes of each resolution.
    pub fn resolve(
        &self,
        vrf: &str,
        paths: &[Path],
        through_default: bool,
    ) -> Result<(Vec<Hop>, Vec<SourceSpan>), Unresolved> {
        let mut hops = Vec::new();
        let mut spans = Vec::new();
        for p in paths {
            match (&p.interface, p.gateway) {
                (Some(i), gw) => hops.push(Hop {
                    interface: i.clone(),
                    gateway: gw,
                }),
                (None, Some(g)) => {
                    let in_vrf = p.vrf.as_deref().unwrap_or(vrf);
                    let mut visited = Vec::new();
                    let r = self.gateway(in_vrf, g, through_default, &mut visited, &mut spans);
                    match r {
                        Ok(h) => hops.extend(h),
                        Err(why) => {
                            return Err(Unresolved {
                                reason: format!("{NOT_RESOLVED}: {g}"),
                                why,
                                spans: unique(spans),
                            });
                        }
                    }
                }
                (None, None) => {
                    return Err(Unresolved {
                        reason: NOT_RESOLVED.to_string(),
                        why: "a path with no next hop and no interface".to_string(),
                        spans,
                    });
                }
            }
        }
        hops.sort();
        hops.dedup();
        Ok((hops, unique(spans)))
    }

    fn gateway(
        &self,
        vrf: &str,
        g: IpAddr,
        through_default: bool,
        visited: &mut Vec<(String, Prefix)>,
        spans: &mut Vec<SourceSpan>,
    ) -> Result<Vec<Hop>, String> {
        let Some(t) = self.tables.get(vrf) else {
            return Err(format!("the next hop {g} has no route in VRF {vrf}"));
        };
        if let Some(s) = &t.unknown {
            spans.extend(s.iter().cloned());
            return Err(format!("the route table of VRF {vrf} is not known"));
        }
        let Some((prefix, i)) = t.trie.longest_match(g) else {
            return Err(format!("the next hop {g} has no route in VRF {vrf}"));
        };
        if prefix.len() == 0 && !through_default {
            return Err(format!(
                "the next hop {g} matches only the default route of VRF {vrf}"
            ));
        }
        let key = (vrf.to_string(), prefix);
        if visited.contains(&key) {
            return Err(format!(
                "the resolution of {g} comes back to {prefix} in VRF {vrf}"
            ));
        }
        let (target, s) = &t.routes[*i];
        spans.extend(s.iter().cloned());
        let paths = match target {
            Target::Paths(p) => p,
            Target::Local => {
                return Err(format!(
                    "the next hop {g} is an address of the device in VRF {vrf}"
                ));
            }
            Target::Null => {
                return Err(format!(
                    "the next hop {g} resolves through the discard route {prefix} in VRF {vrf}"
                ));
            }
            Target::Unknown => {
                return Err(format!(
                    "the next hop {g} resolves through {prefix} in VRF {vrf}, a route that is not read or not known"
                ));
            }
        };
        visited.push(key);
        let mut out = Vec::new();
        for p in paths {
            match (&p.interface, p.gateway) {
                (Some(i), Some(h)) => out.push(Hop {
                    interface: i.clone(),
                    gateway: Some(h),
                }),
                (Some(i), None) => out.push(Hop {
                    interface: i.clone(),
                    gateway: Some(g),
                }),
                (None, Some(h)) => {
                    let in_vrf = p.vrf.as_deref().unwrap_or(vrf);
                    let r = self.gateway(in_vrf, h, through_default, visited, spans);
                    match r {
                        Ok(h) => out.extend(h),
                        Err(why) => {
                            visited.pop();
                            return Err(why);
                        }
                    }
                }
                (None, None) => {
                    visited.pop();
                    return Err(format!(
                        "the next hop {g} resolves through {prefix} in VRF {vrf}, which has a path with no next hop"
                    ));
                }
            }
        }
        visited.pop();
        if out.is_empty() {
            return Err(format!(
                "the next hop {g} resolves through {prefix} in VRF {vrf}, which has no path"
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn via(iface: Option<&str>, gw: Option<&str>) -> Path {
        Path {
            interface: iface.map(str::to_string),
            gateway: gw.map(|g| g.parse().unwrap()),
            vrf: None,
        }
    }

    fn span(n: u32) -> Vec<SourceSpan> {
        vec![SourceSpan::line("r1/routes", n)]
    }

    fn hop(iface: &str, gw: &str) -> Hop {
        Hop {
            interface: iface.into(),
            gateway: Some(gw.parse().unwrap()),
        }
    }

    /// An IGP with 2 equal paths to the loopback 203.0.113.9, a connected
    /// network and a default route.
    fn resolver() -> Resolver {
        let mut r = Resolver::new();
        r.add(
            "default",
            p("203.0.113.9/32"),
            Target::Paths(vec![
                via(Some("eth1"), Some("198.51.100.2")),
                via(Some("eth2"), Some("198.51.100.6")),
            ]),
            span(1),
        );
        r.add(
            "default",
            p("192.0.2.0/24"),
            Target::Paths(vec![via(Some("eth3"), None)]),
            span(2),
        );
        r.add(
            "default",
            p("0.0.0.0/0"),
            Target::Paths(vec![via(None, Some("192.0.2.254"))]),
            span(3),
        );
        r
    }

    #[test]
    fn a_next_hop_through_an_igp_with_two_paths_gives_two_hops() {
        let (hops, spans) = resolver()
            .resolve("default", &[via(None, Some("203.0.113.9"))], true)
            .unwrap();
        assert_eq!(
            hops,
            [hop("eth1", "198.51.100.2"), hop("eth2", "198.51.100.6")]
        );
        assert_eq!(spans, span(1));
    }

    #[test]
    fn a_next_hop_through_the_default_route_recurses_to_the_connected_network() {
        let r = resolver();
        let (hops, spans) = r
            .resolve("default", &[via(None, Some("198.18.0.1"))], true)
            .unwrap();
        assert_eq!(hops, [hop("eth3", "192.0.2.254")]);
        assert_eq!(spans, [span(3), span(2)].concat());
        let e = r
            .resolve("default", &[via(None, Some("198.18.0.1"))], false)
            .unwrap_err();
        assert_eq!(e.reason, "next hop not resolved: 198.18.0.1");
    }

    #[test]
    fn a_path_with_an_interface_stays_as_it_is() {
        let (hops, _) = Resolver::new()
            .resolve("default", &[via(Some("eth9"), Some("192.0.2.1"))], true)
            .unwrap();
        assert_eq!(hops, [hop("eth9", "192.0.2.1")]);
    }

    #[test]
    fn a_loop_an_unknown_route_and_a_missing_route_give_no_hop() {
        let mut r = Resolver::new();
        r.add(
            "default",
            p("198.51.100.240/28"),
            Target::Paths(vec![via(None, Some("198.51.100.250"))]),
            span(1),
        );
        r.add(
            "default",
            p("198.51.100.248/29"),
            Target::Paths(vec![via(None, Some("198.51.100.241"))]),
            span(2),
        );
        r.add("default", p("192.0.2.0/24"), Target::Unknown, span(3));
        r.add("default", p("192.0.2.128/25"), Target::Local, span(4));
        let e = r
            .resolve("default", &[via(None, Some("198.51.100.250"))], true)
            .unwrap_err();
        assert_eq!(e.reason, "next hop not resolved: 198.51.100.250");
        assert!(e.why.contains("comes back"), "{e:?}");
        assert_eq!(e.spans, [span(2), span(1)].concat());
        let e = r
            .resolve("default", &[via(None, Some("192.0.2.1"))], true)
            .unwrap_err();
        assert!(e.why.contains("not read"), "{e:?}");
        assert_eq!(e.spans, span(3));
        assert!(
            r.resolve("default", &[via(None, Some("192.0.2.129"))], true)
                .is_err()
        );
        assert!(
            r.resolve("default", &[via(None, Some("203.0.113.1"))], true)
                .is_err()
        );
        assert!(
            r.resolve("BLUE", &[via(None, Some("198.51.100.250"))], true)
                .is_err()
        );
    }

    #[test]
    fn two_paths_to_one_next_hop_are_not_a_loop() {
        let mut r = resolver();
        r.add(
            "default",
            p("198.51.100.64/26"),
            Target::Paths(vec![
                via(None, Some("203.0.113.9")),
                via(None, Some("203.0.113.9")),
            ]),
            span(5),
        );
        let (hops, spans) = r
            .resolve("default", &[via(None, Some("198.51.100.65"))], true)
            .unwrap();
        assert_eq!(hops.len(), 2);
        assert_eq!(spans, [span(5), span(1)].concat());
    }

    #[test]
    fn a_next_hop_in_another_vrf_resolves_there() {
        let mut path = via(None, Some("203.0.113.9"));
        path.vrf = Some("default".into());
        let (hops, _) = resolver().resolve("RED", &[path], true).unwrap();
        assert_eq!(hops.len(), 2);
    }

    #[test]
    fn an_unknown_vrf_gives_no_hop() {
        let mut r = resolver();
        r.unknown_vrf("default", span(9));
        let e = r
            .resolve("default", &[via(None, Some("203.0.113.9"))], true)
            .unwrap_err();
        assert_eq!(e.spans, span(9));
    }

    #[test]
    fn only_a_computed_route_reads_the_flag_of_the_profile() {
        assert!(through_default(Origin::Collected, false));
        assert!(through_default(Origin::Collected, true));
        assert!(!through_default(Origin::Computed, false));
        assert!(through_default(Origin::Computed, true));
    }
}
