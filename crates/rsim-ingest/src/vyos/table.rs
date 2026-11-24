//! The classification of the stanzas of a VyOS 1.4 or 1.5 configuration.

use std::collections::BTreeMap;

use super::config::NO_ROUTES;
use crate::coverage::{Entry, Reach, State, Table};
use crate::route_tables::{RouteTables, VRF, lines};
use crate::stanza::{Document, Stanza};
use Reach::{Node, Subtree};
use State::{Handled, Irrelevant, Unhandled};

/// The name of the main VRF in the collected route rows.
const DEFAULT_VRF: &str = "default";

const fn e(path: &'static str, state: State, reach: Reach) -> Entry {
    Entry { path, state, reach }
}

/// The interface kinds with handled stanzas.
const KINDS: &[&str] = &["ethernet", "dummy", "loopback", "pppoe", "wireguard"];

/// The firewall group kinds with the option of their members.
const GROUPS: &[(&str, &str)] = &[
    ("address-group", "address"),
    ("network-group", "network"),
    ("port-group", "port"),
    ("ipv6-address-group", "address"),
    ("ipv6-network-group", "network"),
];

/// The options of an interface or a VLAN subinterface, relative to the
/// interface.
const INTERFACE_OPTIONS: &[(&str, State, Reach)] = &[
    ("address", Handled, Subtree),
    ("disable", Handled, Subtree),
    ("description", Handled, Subtree),
    ("hw-id", Irrelevant, Subtree),
    ("mtu", Irrelevant, Subtree),
    ("ip/adjust-mss", Irrelevant, Subtree),
    ("ipv6/adjust-mss", Irrelevant, Subtree),
    ("ip", Handled, Node),
    ("ipv6", Handled, Node),
    ("ipv6/address", Handled, Subtree),
    ("duplex", Irrelevant, Subtree),
    ("speed", Irrelevant, Subtree),
    ("offload", Irrelevant, Subtree),
    ("ring-buffer", Irrelevant, Subtree),
    ("dhcpv6-options", Handled, Subtree),
    ("authentication", Irrelevant, Subtree),
    ("source-interface", Handled, Subtree),
    ("no-peer-dns", Irrelevant, Subtree),
    ("default-route", Handled, Subtree),
    ("private-key", Irrelevant, Subtree),
    ("port", Handled, Subtree),
    ("peer", Handled, Node),
    ("peer/*", Handled, Node),
    ("peer/*/allowed-ips", Handled, Subtree),
    ("peer/*/address", Handled, Subtree),
    ("peer/*/port", Handled, Subtree),
    ("peer/*/disable", Handled, Subtree),
    ("peer/*/public-key", Irrelevant, Subtree),
    ("peer/*/preshared-key", Irrelevant, Subtree),
    ("peer/*/persistent-keepalive", Irrelevant, Subtree),
    ("peer/*/description", Irrelevant, Subtree),
];

/// The options of a firewall or NAT rule, relative to the rule.
const RULE_OPTIONS: &[(&str, State, Reach)] = &[
    ("action", Handled, Subtree),
    ("disable", Handled, Subtree),
    ("protocol", Handled, Subtree),
    ("state", Handled, Subtree),
    ("description", Irrelevant, Subtree),
    ("log", Irrelevant, Subtree),
    ("source", Handled, Node),
    ("source/address", Handled, Subtree),
    ("source/port", Handled, Subtree),
    ("source/group", Handled, Node),
    ("source/group/address-group", Handled, Subtree),
    ("source/group/network-group", Handled, Subtree),
    ("source/group/port-group", Handled, Subtree),
    ("destination", Handled, Node),
    ("destination/address", Handled, Subtree),
    ("destination/port", Handled, Subtree),
    ("destination/group", Handled, Node),
    ("destination/group/address-group", Handled, Subtree),
    ("destination/group/network-group", Handled, Subtree),
    ("destination/group/port-group", Handled, Subtree),
    ("inbound-interface", Handled, Node),
    ("inbound-interface/name", Handled, Subtree),
    ("outbound-interface", Handled, Node),
    ("outbound-interface/name", Handled, Subtree),
    ("icmp", Handled, Node),
    ("icmp/type-name", Handled, Subtree),
    ("translation", Handled, Node),
    ("translation/address", Handled, Subtree),
    ("translation/port", Handled, Subtree),
];

/// The fixed entries.
const ENTRIES: &[Entry] = &[
    e("interfaces", Handled, Node),
    e("firewall", Handled, Node),
    e("firewall/zone", Handled, Node),
    e("firewall/zone/*", Handled, Node),
    e("firewall/zone/*/member", Handled, Node),
    e("firewall/zone/*/member/interface", Handled, Subtree),
    e("firewall/zone/*/member/vrf", Unhandled, Subtree),
    e("firewall/zone/*/from", Handled, Node),
    e("firewall/zone/*/from/*", Handled, Node),
    e("firewall/zone/*/from/*/firewall", Handled, Node),
    e("firewall/zone/*/from/*/firewall/name", Handled, Subtree),
    e(
        "firewall/zone/*/from/*/firewall/ipv6-name",
        Handled,
        Subtree,
    ),
    e("firewall/zone/*/default-action", Handled, Subtree),
    e("firewall/zone/*/intra-zone-filtering", Handled, Subtree),
    e("firewall/zone/*/local-zone", Handled, Subtree),
    e("firewall/zone/*/default-log", Irrelevant, Subtree),
    e("firewall/zone/*/description", Irrelevant, Subtree),
    e("firewall/ipv4", Handled, Node),
    e("firewall/ipv6", Handled, Node),
    e("firewall/ipv4/name", Handled, Node),
    e("firewall/ipv6/name", Handled, Node),
    e("firewall/ipv4/name/*", Handled, Node),
    e("firewall/ipv6/name/*", Handled, Node),
    e("firewall/ipv4/name/*/default-action", Handled, Subtree),
    e("firewall/ipv6/name/*/default-action", Handled, Subtree),
    e("firewall/ipv4/name/*/default-log", Irrelevant, Subtree),
    e("firewall/ipv6/name/*/default-log", Irrelevant, Subtree),
    e("firewall/ipv4/name/*/description", Irrelevant, Subtree),
    e("firewall/ipv6/name/*/description", Irrelevant, Subtree),
    e("firewall/ipv4/name/*/rule", Handled, Node),
    e("firewall/ipv6/name/*/rule", Handled, Node),
    e("firewall/ipv4/name/*/rule/*", Handled, Node),
    e("firewall/ipv6/name/*/rule/*", Handled, Node),
    e("firewall/group", Handled, Node),
    e("firewall/global-options", Handled, Node),
    e("firewall/global-options/state-policy", Handled, Subtree),
    e("firewall/global-options/all-ping", Irrelevant, Subtree),
    e(
        "firewall/global-options/broadcast-ping",
        Irrelevant,
        Subtree,
    ),
    e("firewall/global-options/ip-src-route", Irrelevant, Subtree),
    e(
        "firewall/global-options/ipv6-src-route",
        Irrelevant,
        Subtree,
    ),
    e(
        "firewall/global-options/receive-redirects",
        Irrelevant,
        Subtree,
    ),
    e(
        "firewall/global-options/ipv6-receive-redirects",
        Irrelevant,
        Subtree,
    ),
    e(
        "firewall/global-options/send-redirects",
        Irrelevant,
        Subtree,
    ),
    e("firewall/global-options/log-martians", Irrelevant, Subtree),
    e("firewall/global-options/syn-cookies", Irrelevant, Subtree),
    e(
        "firewall/global-options/twa-hazards-protection",
        Irrelevant,
        Subtree,
    ),
    e("nat", Handled, Node),
    e("nat/source", Handled, Node),
    e("nat/destination", Handled, Node),
    e("nat/source/rule", Handled, Node),
    e("nat/destination/rule", Handled, Node),
    e("nat/source/rule/*", Handled, Node),
    e("nat/destination/rule/*", Handled, Node),
    e("policy", Handled, Node),
    e("policy/route", Handled, Node),
    e("policy/route/*", Handled, Node),
    e("policy/route/*/interface", Handled, Subtree),
    e("policy/route/*/description", Irrelevant, Subtree),
    e("policy/route/*/rule", Handled, Node),
    e("policy/route/*/rule/*", Handled, Node),
    e("policy/route/*/rule/*/set", Handled, Node),
    e("policy/route/*/rule/*/set/table", Handled, Subtree),
    e("policy/route6", Unhandled, Subtree),
    e("policy/prefix-list", Irrelevant, Subtree),
    e("policy/prefix-list6", Irrelevant, Subtree),
    e("protocols", Handled, Node),
    e("protocols/static", Handled, Node),
    e("protocols/static/route", Handled, Subtree),
    e("protocols/static/route6", Handled, Subtree),
    e("protocols/static/table", Handled, Node),
    e("protocols/static/table/*", Handled, Node),
    e("protocols/static/table/*/route", Handled, Subtree),
    e("protocols/static/table/*/route6", Handled, Subtree),
    e("protocols/static/table/*/description", Irrelevant, Subtree),
    e("protocols/pim", Irrelevant, Subtree),
    e("protocols/igmp-proxy", Irrelevant, Subtree),
    e("qos", Handled, Subtree),
    e("service", Irrelevant, Subtree),
    e("system", Irrelevant, Subtree),
    e("container", Irrelevant, Subtree),
];

/// The classification table. The BGP configuration of a VRF with collected
/// route rows is known-irrelevant, because its routes come from the route
/// table; the BGP configuration of a VRF without rows is unhandled.
pub fn table(tables: &RouteTables) -> Table {
    let mut t = Table::new(ENTRIES);
    super::bgp::push_entries(&mut t, tables);
    t.push("protocols/bgp", tables.routing(DEFAULT_VRF), Subtree);
    tables.push_vrfs(&mut t, &["vrf", "name", VRF, "protocols", "bgp"]);
    for kind in KINDS {
        let base = format!("interfaces/{kind}");
        t.push(&base, Handled, Node);
        t.push(&format!("{base}/*/vif"), Handled, Node);
        for prefix in [format!("{base}/*"), format!("{base}/*/vif/*")] {
            t.push(&prefix, Handled, Node);
            for (opt, state, reach) in INTERFACE_OPTIONS {
                t.push(&format!("{prefix}/{opt}"), *state, *reach);
            }
        }
    }
    for (kind, field) in GROUPS {
        let base = format!("firewall/group/{kind}");
        t.push(&base, Handled, Node);
        t.push(&format!("{base}/*"), Handled, Node);
        t.push(&format!("{base}/*/{field}"), Handled, Subtree);
        t.push(&format!("{base}/*/include"), Handled, Subtree);
        t.push(&format!("{base}/*/description"), Irrelevant, Subtree);
    }
    let rules = [
        "policy/route/*/rule/*",
        "firewall/ipv4/name/*/rule/*",
        "firewall/ipv6/name/*/rule/*",
        "nat/source/rule/*",
        "nat/destination/rule/*",
    ];
    for rule in rules {
        for (opt, state, reach) in RULE_OPTIONS {
            t.push(&format!("{rule}/{opt}"), *state, *reach);
        }
    }
    t
}

/// The VRFs whose config has a routing protocol that adds routes, each
/// with the lines of its stanza: `protocols` gives the main VRF, and
/// `vrf name <name> protocols` gives that VRF.
pub fn dynamic_vrfs(doc: &Document) -> BTreeMap<String, Vec<(u32, u32)>> {
    let mut out: BTreeMap<String, Vec<(u32, u32)>> = BTreeMap::new();
    let mut add = |vrf: &str, protocols: &Stanza| {
        for p in protocols.children() {
            if !NO_ROUTES.contains(&p.key.as_str()) {
                out.entry(vrf.to_string()).or_default().push(lines(p));
            }
        }
    };
    if let Some(p) = doc.root.get("protocols") {
        add(DEFAULT_VRF, p);
    }
    if let Some(names) = doc.root.at(&["vrf", "name"]) {
        for v in names.children() {
            if let Some(p) = v.get("protocols") {
                add(&v.key, p);
            }
        }
    }
    out
}
