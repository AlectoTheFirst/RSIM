//! The choice of the route table of each VRF of a device: the collected
//! rows of the VRF, or else the routes of the config.
//!
//! A VRF with collected rows forwards on them, and the routing lines of its
//! config are known-irrelevant. A VRF with no collected rows forwards on the
//! connected and static routes of its config. If its config has a dynamic
//! routing protocol, its routing lines are unhandled, and only its
//! connected and local routes give an answer: a learned route that is not
//! known can be more specific than a static route, so the static routes and
//! each other destination are unknown with the code `NotCollected`.

use std::collections::{BTreeMap, BTreeSet};

use rsim_functions::{RouteKind, RouteProtocol};

use crate::coverage::{Reach, State, Table};
use crate::stanza::Stanza;

/// The place of the VRF name in the levels of [`RouteTables::push_vrfs`].
pub const VRF: &str = "<vrf>";

/// The first and the last line of a stanza.
pub fn lines(s: &Stanza) -> (u32, u32) {
    (s.first_line, s.last_line)
}

/// The words of the key of a stanza.
pub fn words(s: &Stanza) -> Vec<&str> {
    s.key.split_whitespace().collect()
}

/// The reason of a route lookup in a VRF with a dynamic routing protocol
/// and no collected route rows, with the code `NotCollected`.
pub const TABLE_NOT_COLLECTED: &str = "vrf route table not collected";

/// The VRFs of one device with collected route rows, and the VRFs whose
/// config has a dynamic routing protocol.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteTables {
    /// The VRFs with at least one collected route row.
    pub rows: BTreeSet<String>,
    /// The VRFs with a dynamic routing protocol in the config, each with
    /// the first and the last line of each stanza that shows it.
    pub dynamic: BTreeMap<String, Vec<(u32, u32)>>,
    /// True if each VRF has collected rows, for the coverage of a config
    /// with no collected state.
    every: bool,
}

impl RouteTables {
    pub fn new(
        rows: impl IntoIterator<Item = String>,
        dynamic: BTreeMap<String, Vec<(u32, u32)>>,
    ) -> Self {
        RouteTables {
            rows: rows.into_iter().collect(),
            dynamic,
            every: false,
        }
    }

    /// The tables of a device with collected route rows in each VRF.
    pub fn every_vrf(dynamic: BTreeMap<String, Vec<(u32, u32)>>) -> Self {
        RouteTables {
            rows: BTreeSet::new(),
            dynamic,
            every: true,
        }
    }

    /// The tables of a device with collected route rows in each VRF if
    /// `collected` is true, and in no VRF if it is false.
    pub fn uniform(collected: bool, dynamic: BTreeMap<String, Vec<(u32, u32)>>) -> Self {
        if collected {
            RouteTables::every_vrf(dynamic)
        } else {
            RouteTables::new([], dynamic)
        }
    }

    /// True if the VRF has collected route rows.
    pub fn collected(&self, vrf: &str) -> bool {
        self.every || self.rows.contains(vrf)
    }

    /// The lines of the dynamic protocols of a VRF with no collected rows,
    /// or `None` if the VRF has rows or no dynamic protocol.
    pub fn not_collected(&self, vrf: &str) -> Option<&[(u32, u32)]> {
        if self.collected(vrf) {
            return None;
        }
        self.dynamic.get(vrf).map(Vec::as_slice)
    }

    /// The state of the routing lines of one VRF.
    pub fn routing(&self, vrf: &str) -> State {
        if self.collected(vrf) {
            State::Irrelevant
        } else {
            State::Unhandled
        }
    }

    /// Adds the entries of a routing stanza of each VRF. One segment of
    /// `levels` holds [`VRF`] in place of the VRF name: the entry with `*`
    /// there is unhandled, and the entry with the name of each VRF with
    /// collected rows is known-irrelevant.
    pub fn push_vrfs(&self, t: &mut Table, levels: &[&str]) {
        let with =
            |name: &str| -> Vec<String> { levels.iter().map(|l| l.replace(VRF, name)).collect() };
        let any = with("*");
        let state = if self.every {
            State::Irrelevant
        } else {
            State::Unhandled
        };
        t.push_levels(
            &any.iter().map(String::as_str).collect::<Vec<_>>(),
            state,
            Reach::Subtree,
        );
        for v in &self.rows {
            let named = with(v);
            t.push_levels(
                &named.iter().map(String::as_str).collect::<Vec<_>>(),
                State::Irrelevant,
                Reach::Subtree,
            );
        }
    }

    /// The state of the routing lines that belong to no one VRF, for
    /// example a route map, a prefix list or a routing line of an
    /// interface: known-irrelevant only if the device has collected rows
    /// and each VRF with a dynamic protocol has them.
    pub fn shared(&self) -> State {
        if self.every
            || (!self.rows.is_empty() && self.dynamic.keys().all(|v| self.rows.contains(v)))
        {
            State::Irrelevant
        } else {
            State::Unhandled
        }
    }
}

/// The kind of a collected route that is not connected, local or a discard
/// route, from the protocol word of the vendor: a learned route for a word
/// of `learned`, a static route for a word of `statics`, and a learned
/// route of another protocol for each other word.
pub fn route_kind(word: &str, learned: &[(&str, RouteProtocol)], statics: &[&str]) -> RouteKind {
    if let Some((_, p)) = learned.iter().find(|(w, _)| *w == word) {
        return RouteKind::Learned(*p);
    }
    if statics.contains(&word) {
        return RouteKind::Static;
    }
    RouteKind::Learned(RouteProtocol::Other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_of_the_routing_lines_follows_the_rows_of_each_vrf() {
        let t = RouteTables::new(
            ["default".to_string()],
            BTreeMap::from([
                ("default".to_string(), vec![(1, 2)]),
                ("BLUE".to_string(), vec![(3, 4)]),
            ]),
        );
        assert_eq!(t.routing("default"), State::Irrelevant);
        assert_eq!(t.routing("BLUE"), State::Unhandled);
        assert_eq!(t.shared(), State::Unhandled);
        assert_eq!(t.not_collected("default"), None);
        assert_eq!(t.not_collected("BLUE"), Some(&[(3, 4)][..]));
        assert_eq!(t.not_collected("GREEN"), None);
        let all = RouteTables::new(
            ["default".to_string(), "BLUE".to_string()],
            t.dynamic.clone(),
        );
        assert_eq!(all.shared(), State::Irrelevant);
        assert_eq!(RouteTables::default().shared(), State::Unhandled);
    }

    #[test]
    fn a_word_that_is_not_listed_is_a_learned_route_of_another_protocol() {
        let learned = [("bgp", RouteProtocol::Bgp)];
        assert_eq!(
            route_kind("bgp", &learned, &["static"]),
            RouteKind::Learned(RouteProtocol::Bgp)
        );
        assert_eq!(
            route_kind("static", &learned, &["static"]),
            RouteKind::Static
        );
        assert_eq!(
            route_kind("babel", &learned, &["static"]),
            RouteKind::Learned(RouteProtocol::Other)
        );
    }
}
