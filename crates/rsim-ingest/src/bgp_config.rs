//! The BGP processes of the config of a device for the BGP calculation, in
//! the form of `rsim_routing::bgp`, and the gaps of the config: the lines
//! and the neighbours that the calculation does not evaluate.
//!
//! A neighbour is lowered with the settings of its unicast and EVPN address
//! families. A neighbour whose families have different settings, an
//! unknown AS, an inheritance gap, a listen range and a neighbour named by
//! its interface are gaps.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::SourceSpan;
use rsim_routing::bgp::{Asn, BgpProcess, Family, LocalAs, Neighbor, NextHopSelf};

use crate::bgp_peers::{Neighbour, RemoteAs};
use crate::links::BgpPeer;

/// The unicast families.
pub const UNICAST: [Family; 2] = [Family::Ipv4Unicast, Family::Ipv6Unicast];

/// The families of the calculation: the unicast families and the EVPN IP
/// prefix routes of the `l2vpn evpn` family.
pub const FAMILIES: [Family; 3] = [
    Family::Ipv4Unicast,
    Family::Ipv6Unicast,
    Family::EvpnIpPrefix,
];

/// The start of the reason of a gap.
pub const GAP: &str = "bgp gap";

/// A line or a neighbour of the BGP config that the calculation does not
/// evaluate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Gap {
    pub vrf: String,
    /// The unicast families that the gap can reach.
    pub families: BTreeSet<Family>,
    /// The line through the mask of the vendor, or the neighbour with the
    /// reason.
    pub text: String,
    pub spans: Vec<SourceSpan>,
}

/// The BGP config of one device for the calculation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceBgp {
    /// The process of each VRF with a known AS.
    pub processes: Vec<BgpProcess>,
    pub gaps: Vec<Gap>,
}

impl DeviceBgp {
    /// Adds a gap of `vrf` for `families`.
    pub fn gap(
        &mut self,
        vrf: &str,
        families: &[Family],
        text: impl Into<String>,
        spans: Vec<SourceSpan>,
    ) {
        self.gaps.push(Gap {
            vrf: vrf.to_string(),
            families: families.iter().copied().collect(),
            text: text.into(),
            spans,
        });
    }
}

/// The family of the name of a family of the session sections, for
/// example `ipv4-unicast`. `None` for a family other than IPv4 and IPv6
/// unicast.
pub fn unicast_of(name: &str) -> Option<Family> {
    match name {
        "ipv4-unicast" => Some(Family::Ipv4Unicast),
        "ipv6-unicast" => Some(Family::Ipv6Unicast),
        _ => None,
    }
}

/// The unicast family of the words after `address-family`, for example
/// `ipv4 unicast`.
pub fn unicast_words(words: &[&str]) -> Option<Family> {
    crate::bgp_peers::family(words).and_then(|f| unicast_of(&f))
}

/// The family of the name of a family of the session sections: a unicast
/// family, or the EVPN IP prefix routes for `l2vpn-evpn`.
pub fn family_of(name: &str) -> Option<Family> {
    match name {
        "l2vpn-evpn" => Some(Family::EvpnIpPrefix),
        _ => unicast_of(name),
    }
}

/// The family of the calculation of the words after `address-family`, for
/// example `l2vpn evpn`.
pub fn family_words(words: &[&str]) -> Option<Family> {
    crate::bgp_peers::family(words).and_then(|f| family_of(&f))
}

/// The settings of a neighbour in one address family. Each is `None` when
/// no line of the neighbour or of its sources states it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AfSettings {
    pub import: Option<String>,
    pub export: Option<String>,
    pub rr_client: Option<bool>,
    pub next_hop_self: Option<NextHopSelf>,
    pub send_community: Option<bool>,
    pub send_community_extended: Option<bool>,
    pub remove_private_as: Option<bool>,
}

impl AfSettings {
    /// Takes each setting of `other` that this one does not state.
    pub fn fill(&mut self, other: &AfSettings) {
        fn f<T: Clone>(own: &mut Option<T>, o: &Option<T>) {
            if own.is_none() {
                own.clone_from(o);
            }
        }
        f(&mut self.import, &other.import);
        f(&mut self.export, &other.export);
        f(&mut self.rr_client, &other.rr_client);
        f(&mut self.next_hop_self, &other.next_hop_self);
        f(&mut self.send_community, &other.send_community);
        f(
            &mut self.send_community_extended,
            &other.send_community_extended,
        );
        f(&mut self.remove_private_as, &other.remove_private_as);
    }
}

/// The span of the lines `lines` of `file`.
pub fn span(file: &str, lines: (u32, u32)) -> SourceSpan {
    SourceSpan::new(file, lines.0, lines.1.max(lines.0))
}

/// The neighbour of a process from the config after the inheritance and the
/// settings of each family of [`FAMILIES`] that it activates. `asn` is the AS of
/// the process. The communities are sent only when a line states it. Gives
/// the reason when the neighbour is not lowered.
pub fn neighbor(
    n: &Neighbour,
    asn: u32,
    af: &BTreeMap<Family, AfSettings>,
    file: &str,
) -> Result<Neighbor, String> {
    let address: IpAddr = match &n.peer {
        BgpPeer::Address(a) => *a,
        BgpPeer::Range(p) => return Err(format!("listen range {p}")),
        BgpPeer::Interface(i) => return Err(format!("neighbor {i} named by its interface")),
    };
    if let Some(g) = n.resolved.gaps.first() {
        return Err(format!("neighbor {address}: {g}"));
    }
    let s = &n.resolved.settings;
    let remote = match s.remote_as.as_ref().map(|r| &r.value) {
        Some(RemoteAs::Asn(a)) => Asn(*a),
        Some(RemoteAs::Internal) => Asn(asn),
        Some(RemoteAs::External) => {
            return Err(format!("neighbor {address}: remote-as external"));
        }
        Some(RemoteAs::Auto) => return Err(format!("neighbor {address}: remote-as auto")),
        Some(RemoteAs::RouteMap(m)) => {
            return Err(format!("neighbor {address}: remote-as route-map {m}"));
        }
        Some(RemoteAs::Unreadable(t)) => {
            return Err(format!("neighbor {address}: remote-as {t} not read"));
        }
        None => return Err(format!("neighbor {address}: no remote-as")),
    };
    let mut out = Neighbor::new(address, remote);
    if let Some(l) = &s.local_as {
        let Some(a) = l.value.asn else {
            return Err(format!(
                "neighbor {address}: local-as {} not read",
                l.value.text
            ));
        };
        out.local_as = Some(LocalAs {
            asn: Asn(a),
            no_prepend: l.value.no_prepend,
            replace_as: l.value.replace_as,
            dual_as: l.value.dual_as,
        });
    }
    out.shutdown = s.shutdown.as_ref().is_some_and(|x| x.value);
    for (name, v) in &s.families {
        if let Some(f) = family_of(name) {
            if v.value {
                out.activated.insert(f);
            } else {
                out.deactivated.insert(f);
            }
        }
    }
    let mut chosen: Option<&AfSettings> = None;
    for f in &out.activated {
        let a = af.get(f);
        match (chosen, a) {
            (None, Some(a)) => chosen = Some(a),
            (Some(c), Some(a)) if c != a => {
                return Err(format!(
                    "neighbor {address}: address families with different settings"
                ));
            }
            _ => {}
        }
    }
    if let Some(a) = chosen {
        out.import_policy.clone_from(&a.import);
        out.export_policy.clone_from(&a.export);
        out.route_reflector_client = a.rr_client.unwrap_or(false);
        out.next_hop_self = a.next_hop_self.unwrap_or_default();
        out.send_community = a.send_community.unwrap_or(false);
        out.send_community_extended = a.send_community_extended.unwrap_or(false);
        out.remove_private_as = a.remove_private_as.unwrap_or(false);
    }
    let mut lines = vec![n.lines];
    lines.extend(n.resolved.lines.iter().copied());
    out.spans = lines.into_iter().map(|l| span(file, l)).collect();
    Ok(out)
}

/// True if the words of a BGP line of a process, a neighbour or an address
/// family start with a word of a line with no effect on the routes: the
/// description, the logging, the timers, the passwords, BFD, graceful
/// restart, the soft reconfiguration, the prefix limit, the multihop and
/// transport settings of the session, the capabilities and the event
/// history.
pub fn no_effect(words: &[&str]) -> bool {
    const FIRST: &[&str] = &[
        "description",
        "log-neighbor-changes",
        "timers",
        "password",
        "bfd",
        "graceful-restart",
        "graceful-restart-helper",
        "soft-reconfiguration",
        "maximum-prefix",
        "ebgp-multihop",
        "transport",
        "capability",
        "dont-capability-negotiate",
        "event-history",
        "fast-external-fallover",
        "ttl-security",
        "low-memory",
        "nsr",
        "advertise-pip",
        "dynamic-capability",
        "connection-mode",
    ];
    match words {
        [] => true,
        ["bgp", "log", ..] | ["bgp", "log-neighbor-changes", ..] => true,
        ["bgp", "graceful-restart", ..] => true,
        ["no", rest @ ..] => no_effect(rest),
        [w, ..] => FIRST.contains(w),
    }
}

/// The unicast families of a gap of a line below the address family
/// `family` of a process, or of the process itself for `None`.
pub fn families_of(family: Option<Family>) -> Vec<Family> {
    match family {
        Some(f) => vec![f],
        None => UNICAST.to_vec(),
    }
}
