//! The router ID of each BGP neighbour of an IOS-XE or IOS-XR device from
//! the neighbour detail: the section `bgp_neighbors`, and on IOS-XR also
//! `bgp_vrf_neighbors`, after HST `cisco_bgp.parse_neighbor_router_ids`.
//!
//! A neighbour block starts with `BGP neighbor is <address>`, with
//! `vrf <name>` on the same line for a VRF other than the default VRF. The
//! router ID of the peer is on the line with `remote router ID <address>`.
//! A block with no such line, or with the router ID 0.0.0.0, gives no
//! router ID. A neighbour with more than one block keeps the router ID of
//! its first block. The other vendors give no router ID.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use crate::bgp::{Answer, SessionSections};
use crate::bgp_peers::DEFAULT_VRF;

/// The section of the neighbour detail.
pub const NEIGHBORS: &str = "bgp_neighbors";
/// The section of the neighbour detail of the VRFs of IOS-XR.
pub const VRF_NEIGHBORS: &str = "bgp_vrf_neighbors";

/// The router ID of each neighbour by VRF and address.
pub type RouterIds = BTreeMap<(String, IpAddr), Ipv4Addr>;

/// The router IDs of the neighbours of a device of `vendor` from its
/// session sections.
pub fn router_ids(vendor: &str, s: &SessionSections) -> RouterIds {
    let mut out = RouterIds::new();
    if !matches!(vendor, "iosxe" | "iosxr") {
        return out;
    }
    for name in [NEIGHBORS, VRF_NEIGHBORS] {
        if let Some(Answer::Fresh(bytes, _)) = s.get(name).map(crate::bgp::Collected::answer) {
            read_text(&String::from_utf8_lossy(bytes), &mut out);
        }
    }
    out
}

/// The word after the first word of `words` that is `word` in any case,
/// with the commas at its end trimmed.
fn after<'a>(words: &[&'a str], word: &str) -> Option<&'a str> {
    let i = words.iter().position(|w| w.eq_ignore_ascii_case(word))?;
    words.get(i + 1).map(|w| w.trim_end_matches(','))
}

/// Adds the router IDs of the neighbour blocks of `text` to `out`.
pub fn read_text(text: &str, out: &mut RouterIds) {
    let mut key: Option<(String, IpAddr)> = None;
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let lower: Vec<String> = words.iter().map(|w| w.to_ascii_lowercase()).collect();
        if lower.len() >= 4 && lower[0] == "bgp" && lower[1] == "neighbor" && lower[2] == "is" {
            key = words[3]
                .trim_end_matches(',')
                .parse::<IpAddr>()
                .ok()
                .map(|a| {
                    let vrf = after(&words[4..], "vrf").unwrap_or(DEFAULT_VRF);
                    let vrf = if vrf.eq_ignore_ascii_case(DEFAULT_VRF) {
                        DEFAULT_VRF
                    } else {
                        vrf
                    };
                    (vrf.to_string(), a)
                });
            continue;
        }
        let Some(k) = &key else {
            continue;
        };
        let Some(i) = lower.windows(3).position(|w| {
            w[0] == "remote" && w[1] == "router" && w[2].trim_end_matches(':') == "id"
        }) else {
            continue;
        };
        let Some(rid) = words
            .get(i + 3)
            .and_then(|w| w.trim_end_matches(',').parse::<Ipv4Addr>().ok())
        else {
            continue;
        };
        if !rid.is_unspecified() {
            out.entry(k.clone()).or_insert(rid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_router_id_of_each_neighbour_block_is_read_by_vrf_and_address() {
        let text = "Mon Nov  2 08:00:00.000 UTC\n\
BGP neighbor is 192.0.2.1, vrf default,  remote AS 64496, external link\n  \
BGP version 4, remote router ID 198.51.100.1\n  BGP state = Established\n\n\
BGP neighbor is 192.0.2.5, vrf RED, remote AS 64497, external link\n \
Remote router ID 198.51.100.5\n\n\
BGP neighbor is 192.0.2.9\n  BGP version 4, remote router ID 0.0.0.0\n\n\
BGP neighbor is 192.0.2.1, vrf default\n  BGP version 4, remote router ID 198.51.100.99\n\n\
BGP neighbor is 2001:db8::1\n  BGP version 4, remote router ID 198.51.100.6\n";
        let mut out = RouterIds::new();
        read_text(text, &mut out);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let v4 = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert_eq!(
            out,
            RouterIds::from([
                (("default".to_string(), ip("192.0.2.1")), v4("198.51.100.1")),
                (("RED".to_string(), ip("192.0.2.5")), v4("198.51.100.5")),
                (
                    ("default".to_string(), ip("2001:db8::1")),
                    v4("198.51.100.6")
                ),
            ])
        );
    }
}
