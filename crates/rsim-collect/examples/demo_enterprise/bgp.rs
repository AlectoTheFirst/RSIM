//! The tables of the BGP neighbours of the section `bgp_routes`, from the
//! route tables of the devices.
//!
//! The accepted table of a neighbour holds the BGP routes of the device
//! whose next hop is the address of the neighbour, and the received table
//! holds the same paths. The advertised table holds the BGP routes of the
//! far end whose next hop is an address of the device. The AS path of a
//! route has the AS of each eBGP hop toward the device that originates it,
//! and a route that a device originates by redistribution has the origin
//! `?`. The provider of an internet edge sends the default route and
//! 192.0.2.0/24, and the import policy of the edge permits only the default
//! route. The edge advertises nothing to its provider.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::Ipv4Addr;

use serde_json::{Value, json};

use super::model::*;
use super::route::{Kind, Tables};

/// One path of a table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path {
    pub prefix: (Ipv4Addr, u8),
    pub next_hop: Ipv4Addr,
    pub as_path: Vec<u32>,
    pub origin: char,
    pub local_pref: Option<u32>,
    pub weight: u32,
    /// The peer from which the device learned the route, `None` for a
    /// route that it originates.
    pub from: Option<Ipv4Addr>,
}

/// The 3 tables of a neighbour.
#[derive(Clone, Debug, Default)]
pub struct NeighborTables {
    pub received: Vec<Path>,
    pub accepted: Vec<Path>,
    pub advertised: Vec<Path>,
}

impl NeighborTables {
    /// The tables in the order of the directions of the collector:
    /// received, accepted, advertised.
    pub fn all(&self) -> [&[Path]; 3] {
        [&self.received, &self.accepted, &self.advertised]
    }
}

/// The device and the VRF of each address of an interface of the twin.
/// A shared tunnel end belongs to the first device of its pair.
pub fn owners(e: &Estate) -> BTreeMap<Ipv4Addr, (usize, String)> {
    let mut out = BTreeMap::new();
    for (d, dev) in e.devs.iter().enumerate() {
        for i in dev
            .ifaces
            .iter()
            .filter(|i| !i.anycast && i.mode != Mode::Mgmt)
        {
            for (a, _) in i.addr.iter().chain(i.secondary.iter()) {
                out.entry(*a).or_insert((d, i.vrf.clone()));
            }
        }
    }
    out
}

fn bgp_kind(k: Kind) -> bool {
    matches!(k, Kind::Ebgp | Kind::Ibgp)
}

/// The AS path and the origin of the route of `prefix` at device `d` in
/// `vrf`, as the device holds it: the AS of each eBGP hop toward the
/// device that originates the route.
fn as_path(
    e: &Estate,
    t: &Tables,
    owners: &BTreeMap<Ipv4Addr, (usize, String)>,
    d: usize,
    vrf: &str,
    prefix: (Ipv4Addr, u8),
) -> (Vec<u32>, char) {
    let mut path = Vec::new();
    let (mut d, mut vrf) = (d, vrf.to_string());
    for _ in 0..e.devs.len() {
        let Some(r) = t.ribs[d]
            .iter()
            .find(|r| r.vrf == vrf && r.prefix == prefix && bgp_kind(r.kind))
        else {
            break;
        };
        let Some((x, xv)) = r
            .paths
            .iter()
            .find_map(|p| p.next_hop)
            .and_then(|nh| owners.get(&nh))
        else {
            break;
        };
        if r.kind == Kind::Ebgp
            && let Some(b) = &e.devs[*x].bgp
        {
            path.push(b.asn);
        }
        d = *x;
        vrf.clone_from(xv);
    }
    (path, '?')
}

/// The prefixes that the provider of an internet edge sends, with the
/// prefixes that the import policy permits.
const PROVIDER: [((Ipv4Addr, u8), bool); 2] = [
    ((Ipv4Addr::new(0, 0, 0, 0), 0), true),
    ((Ipv4Addr::new(192, 0, 2, 0), 24), false),
];

/// The tables of the neighbour `n` of device `d`.
pub fn tables(
    e: &Estate,
    t: &Tables,
    owners: &BTreeMap<Ipv4Addr, (usize, String)>,
    d: usize,
    n: &Neighbor,
) -> NeighborTables {
    let dev = &e.devs[d];
    let Some(bgp) = &dev.bgp else {
        return NeighborTables::default();
    };
    if !n.up {
        return NeighborTables::default();
    }
    if e.externals.iter().any(|x| x.ip == n.addr) {
        let path = |prefix| Path {
            prefix,
            next_hop: n.addr,
            as_path: vec![n.remote_as],
            origin: 'i',
            local_pref: None,
            weight: 0,
            from: Some(n.addr),
        };
        return NeighborTables {
            received: PROVIDER.iter().map(|(p, _)| path(*p)).collect(),
            accepted: PROVIDER
                .iter()
                .filter(|(_, ok)| *ok)
                .map(|(p, _)| path(*p))
                .collect(),
            advertised: Vec::new(),
        };
    }
    let ibgp = n.remote_as == bgp.asn;
    let mut accepted = Vec::new();
    for r in t.ribs[d]
        .iter()
        .filter(|r| r.vrf == n.vrf && bgp_kind(r.kind))
        .filter(|r| r.paths.iter().any(|p| p.next_hop == Some(n.addr)))
    {
        let (mut path, origin) = match owners.get(&n.addr) {
            Some((x, xv)) => as_path(e, t, owners, *x, xv, r.prefix),
            None => (Vec::new(), 'i'),
        };
        if !ibgp {
            path.insert(0, n.remote_as);
        }
        accepted.push(Path {
            prefix: r.prefix,
            next_hop: n.addr,
            as_path: path,
            origin,
            local_pref: ibgp.then_some(100),
            weight: 0,
            from: Some(n.addr),
        });
    }
    let mine: Vec<Ipv4Addr> = dev
        .ifaces
        .iter()
        .filter(|i| i.vrf == n.vrf)
        .filter_map(|i| i.addr.map(|a| a.0))
        .collect();
    let mut advertised = Vec::new();
    if let Some((x, xv)) = owners.get(&n.addr) {
        for r in t.ribs[*x]
            .iter()
            .filter(|r| &r.vrf == xv && r.kind == Kind::Ebgp)
            .filter(|r| {
                r.paths
                    .iter()
                    .any(|p| p.next_hop.is_some_and(|h| mine.contains(&h)))
            })
        {
            let own = t.ribs[d]
                .iter()
                .find(|o| o.vrf == n.vrf && o.prefix == r.prefix && bgp_kind(o.kind));
            let hop = own.and_then(|o| o.paths.iter().find_map(|p| p.next_hop));
            let (path, origin) = as_path(e, t, owners, d, &n.vrf, r.prefix);
            advertised.push(Path {
                prefix: r.prefix,
                next_hop: hop.unwrap_or(Ipv4Addr::UNSPECIFIED),
                as_path: path,
                origin,
                local_pref: None,
                weight: if hop.is_some() { 0 } else { 32_768 },
                from: hop,
            });
        }
    }
    NeighborTables {
        received: accepted.clone(),
        accepted,
        advertised,
    }
}

fn network(p: (Ipv4Addr, u8)) -> String {
    format!("{}/{}", p.0, p.1)
}

/// The network as IOS-XE prints it: with no length when the length is the
/// classful length.
fn classful_network(p: (Ipv4Addr, u8)) -> String {
    let first = p.0.octets()[0];
    let classful = match first {
        0 if p.0.is_unspecified() => 0,
        0..=127 => 8,
        128..=191 => 16,
        192..=223 => 24,
        _ => 255,
    };
    if p.1 == classful {
        p.0.to_string()
    } else {
        network(p)
    }
}

fn path_text(p: &Path) -> String {
    let mut words: Vec<String> = p.as_path.iter().map(ToString::to_string).collect();
    words.push(p.origin.to_string());
    words.join(" ")
}

/// One row of a table whose header has the network at column `n`, the next
/// hop at column 22, Metric, LocPrf and Weight ending at the columns 47, 54
/// and 61, and the path at column 63. A network that reaches the next-hop
/// column is alone on its line.
fn row(n: usize, status: &str, net: &str, p: &Path) -> String {
    let mut head = format!("{status:<n$}{net}");
    if head.len() > 21 {
        head.push('\n');
        head.push_str(&" ".repeat(22));
    } else {
        head = format!("{head:<22}");
    }
    let lp = p.local_pref.map(|x| x.to_string()).unwrap_or_default();
    format!(
        "{head}{:<16}{:>10}{lp:>7}{:>7} {}",
        p.next_hop.to_string(),
        "0",
        p.weight,
        path_text(p)
    )
}

/// The number of prefixes of a table.
fn prefixes(paths: &[Path]) -> usize {
    let mut p: Vec<(Ipv4Addr, u8)> = paths.iter().map(|x| x.prefix).collect();
    p.sort();
    p.dedup();
    p.len()
}

/// The status of a path: a received path is valid, an accepted path is
/// the best path, and the default route of an internet edge, which a
/// static route with a lower distance replaces, is a RIB failure.
fn status(direction: usize, p: &Path, dev: &Dev) -> &'static str {
    match direction {
        0 => "*",
        1 if dev.role == Role::Inet && p.prefix.1 == 0 => "r>",
        _ => "*>",
    }
}

/// The IOS-XE answer of one table.
pub fn iosxe(dev: &Dev, direction: usize, paths: &[Path]) -> String {
    let n = prefixes(paths);
    if paths.is_empty() {
        return format!("\nTotal number of prefixes {n} \n");
    }
    let rid = dev
        .bgp
        .as_ref()
        .map_or(Ipv4Addr::UNSPECIFIED, |b| b.router_id);
    let mut s = format!(
        "BGP table version is 14, local router ID is {rid}\nStatus codes: s suppressed, d damped, h history, * valid, > best, i - internal, \n              r RIB-failure, S Stale, m multipath, b backup-path, f RT-Filter, \n              x best-external, a additional-path, c RIB-compressed, \n              t secondary path, L long-lived-stale,\nOrigin codes: i - IGP, e - EGP, ? - incomplete\nRPKI validation codes: V valid, I invalid, N Not found\n\n     Network          Next Hop            Metric LocPrf Weight Path\n"
    );
    for p in paths {
        let st = format!(" {}", status(direction, p, dev));
        let _ = writeln!(s, "{}", row(5, &st, &classful_network(p.prefix), p));
    }
    let _ = write!(s, "\nTotal number of prefixes {n} \n");
    s
}

/// The IOS-XR answer of one table, after the time line `time`.
pub fn iosxr(dev: &Dev, direction: usize, paths: &[Path], time: &str) -> String {
    let n = prefixes(paths);
    let (rid, asn) = dev
        .bgp
        .as_ref()
        .map_or((Ipv4Addr::UNSPECIFIED, 0), |b| (b.router_id, b.asn));
    let mut s = format!(
        "{time}BGP router identifier {rid}, local AS number {asn}\nBGP generic scan interval 60 secs\nNon-stop routing is enabled\nBGP table state: Active\nTable ID: 0xe0000000   RD version: 214\nBGP main routing table version 214\nBGP NSR Initial initsync version 4 (Reached)\nBGP NSR/ISSU Sync-Group versions 0/0\nBGP scan interval 60 secs\n\n"
    );
    if direction == 2 {
        s.push_str("Network            Next Hop        From            AS Path\n");
        for p in paths {
            let from = p.from.map_or("Local".to_string(), |f| f.to_string());
            let _ = writeln!(
                s,
                "{:<19}{:<16}{from:<16}{}",
                network(p.prefix),
                p.next_hop.to_string(),
                path_text(p)
            );
        }
    } else if !paths.is_empty() {
        s.push_str("Status codes: s suppressed, d damped, h history, * valid, > best\n              i - internal, r RIB-failure, S stale, N Nexthop-discard\nOrigin codes: i - IGP, e - EGP, ? - incomplete\n   Network            Next Hop            Metric LocPrf Weight Path\n");
        for p in paths {
            let _ = writeln!(
                s,
                "{}",
                row(3, status(direction, p, dev), &network(p.prefix), p)
            );
        }
    }
    let _ = write!(s, "\nProcessed {n} prefixes, {} paths\n", paths.len());
    s
}

/// The NX-OS answer of one table.
pub fn nxos(vrf: &str, direction: usize, paths: &[Path]) -> String {
    if paths.is_empty() {
        return "{}\n".to_string();
    }
    let mut by: BTreeMap<(u32, u8), Vec<&Path>> = BTreeMap::new();
    for p in paths {
        by.entry((u32::from(p.prefix.0), p.prefix.1))
            .or_default()
            .push(p);
    }
    let rows: Vec<Value> = by
        .values()
        .map(|ps| {
            let list: Vec<Value> = ps
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    json!({
                        "pathnr": i.to_string(),
                        "ipnexthop": p.next_hop.to_string(),
                        "aspath": p.as_path.iter().map(ToString::to_string).collect::<Vec<_>>().join(" "),
                        "origin": p.origin.to_string(),
                        "localpref": p.local_pref.unwrap_or(100).to_string(),
                        "metric": "0",
                        "weight": p.weight.to_string(),
                        "best": (direction == 1 && i == 0).to_string(),
                    })
                })
                .collect();
            json!({
                "ipprefix": network(ps[0].prefix),
                "TABLE_path": {"ROW_path": list},
            })
        })
        .collect();
    super::nxos::pretty(&json!({
        "TABLE_vrf": {"ROW_vrf": [{
            "vrf-name-out": vrf,
            "TABLE_afi": {"ROW_afi": [{
                "afi": "1",
                "TABLE_safi": {"ROW_safi": [{
                    "safi": "1",
                    "af-name": "IPv4 Unicast",
                    "TABLE_prefix": {"ROW_prefix": rows},
                }]},
            }]},
        }]},
    }))
}

/// The neighbour detail of IOS-XE and IOS-XR: the AS, the router ID and the
/// state of each neighbour of `vrfs`.
pub fn neighbor_detail(dev: &Dev, vrfs: &dyn Fn(&str) -> bool, time: &str) -> String {
    let mut s = time.to_string();
    let Some(bgp) = &dev.bgp else {
        return s;
    };
    for n in bgp.neighbors.iter().filter(|n| vrfs(&n.vrf)) {
        let link = if n.remote_as == bgp.asn {
            "internal"
        } else {
            "external"
        };
        let state = if n.up {
            "Established, up for 5w6d"
        } else {
            "Idle"
        };
        let _ = writeln!(
            s,
            "BGP neighbor is {}, vrf {},  remote AS {}, {link} link\n  BGP version 4, remote router ID {}\n  BGP state = {state}\n",
            n.addr, n.vrf, n.remote_as, n.addr
        );
    }
    s
}

/// The NX-OS neighbour detail.
pub fn nxos_neighbors(dev: &Dev) -> String {
    let Some(bgp) = &dev.bgp else {
        return "{}\n".to_string();
    };
    let rows: Vec<Value> = bgp
        .neighbors
        .iter()
        .map(|n| {
            json!({
                "neighbor": n.addr.to_string(),
                "vrf": n.vrf,
                "remoteas": n.remote_as.to_string(),
                "remote-id": n.addr.to_string(),
                "state": if n.up { "Established" } else { "Idle" },
            })
        })
        .collect();
    super::nxos::pretty(&json!({"TABLE_neighbor": {"ROW_neighbor": rows}}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wan_router_accepts_the_networks_of_the_other_site_with_the_as_of_the_peer() {
        let e = super::super::build::estate(1);
        let t = super::super::route::tables(&e);
        let o = owners(&e);
        let w = e.devs.iter().position(|d| d.name == "fra-wan1").unwrap();
        let bgp = e.devs[w].bgp.as_ref().unwrap();
        let par = bgp.neighbors.iter().find(|n| n.desc == "par-wan1").unwrap();
        let x = tables(&e, &t, &o, w, par);
        assert!(!x.accepted.is_empty());
        assert!(x.accepted.iter().all(|p| p.as_path.first() == Some(&65020)));
        assert_eq!(x.received, x.accepted);
        let back = e.devs.iter().position(|d| d.name == "par-wan1").unwrap();
        let fra = e.devs[back]
            .bgp
            .as_ref()
            .unwrap()
            .neighbors
            .iter()
            .find(|n| n.desc == "fra-wan1")
            .unwrap();
        let y = tables(&e, &t, &o, back, fra);
        let sent: Vec<_> = x.advertised.iter().map(|p| p.prefix).collect();
        let got: Vec<_> = y.accepted.iter().map(|p| p.prefix).collect();
        assert_eq!(sent, got);
    }

    #[test]
    fn the_rows_line_up_with_the_columns_of_the_header() {
        let p = Path {
            prefix: (Ipv4Addr::new(10, 21, 10, 0), 24),
            next_hop: Ipv4Addr::new(10, 250, 0, 1),
            as_path: vec![65020],
            origin: '?',
            local_pref: Some(100),
            weight: 0,
            from: None,
        };
        let r = row(5, " *>", "10.21.10.0/24", &p);
        let header = "     Network          Next Hop            Metric LocPrf Weight Path";
        assert_eq!(r.find("10.250.0.1"), header.find("Next Hop"));
        assert_eq!(r.find("65020"), header.find("Path"));
        assert_eq!(&r[54..55], "0");
        assert_eq!(&r[52..55], "100");
    }
}
