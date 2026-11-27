//! The input of the OSPF database builder for one router: its OSPF config,
//! and the networks, static routes and addresses that the builder reads for
//! the redistribution and the router ID.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::Prefix;
use rsim_routing::Platform;
use rsim_routing::ospf::build::{Address, RouterInput};
use rsim_routing::ospf::config::RouterConfig;

/// One interface of a router in one form for all vendors.
pub struct Iface {
    pub name: String,
    pub vrf: String,
    pub up: bool,
    pub loopback: bool,
    /// The addresses with their prefix lengths.
    pub addresses: Vec<(IpAddr, u8)>,
}

/// An address with its prefix length, for example `192.0.2.1/24`.
pub fn address(s: &str) -> Option<(IpAddr, u8)> {
    let (a, l) = s.split_once('/')?;
    let a: IpAddr = a.parse().ok()?;
    let l: u8 = l.parse().ok()?;
    let max = if a.is_ipv4() { 32 } else { 128 };
    (l <= max).then_some((a, l))
}

/// True for the name of a loopback interface of each vendor.
pub fn loopback_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("loopback") || n == "lo" || n.starts_with("dum")
}

/// The builder input of one router. `statics` holds the prefixes of the
/// static routes of the config by VRF. `defaults` holds the VRFs whose
/// route table has a default route that is not from OSPF.
pub fn router_input(
    config: RouterConfig,
    platform: Platform,
    ifaces: &[Iface],
    statics: &[(String, Prefix)],
    defaults: BTreeSet<String>,
) -> RouterInput {
    let mut input = RouterInput::new(config, platform);
    for i in ifaces {
        for (a, l) in &i.addresses {
            let max = if a.is_ipv4() { 32 } else { 128 };
            if i.up && *l < max {
                input
                    .connected
                    .entry(i.vrf.clone())
                    .or_default()
                    .push(Prefix::new(*a, *l));
            }
            if let IpAddr::V4(v4) = a {
                input
                    .addresses
                    .entry(i.vrf.clone())
                    .or_default()
                    .push(Address {
                        interface: i.name.clone(),
                        address: *v4,
                        loopback: i.loopback,
                        up: i.up,
                    });
            }
        }
    }
    let mut static_map: BTreeMap<String, Vec<Prefix>> = BTreeMap::new();
    let mut default_vrfs = defaults;
    for (vrf, p) in statics {
        if p.len() == 0 {
            default_vrfs.insert(vrf.clone());
        }
        static_map.entry(vrf.clone()).or_default().push(*p);
    }
    for list in input.connected.values_mut().chain(static_map.values_mut()) {
        list.sort();
        list.dedup();
    }
    input.statics = static_map;
    input.default_route = default_vrfs;
    input
}
