//! The classification of the lines of an NX-OS running config.

use std::collections::BTreeMap;

use crate::coverage::{Entry, Reach, State, Table};
use crate::route_tables::{RouteTables, VRF, lines, words};
use crate::stanza::Document;
use Reach::{Node, Subtree};
use State::{Handled, Irrelevant};

/// The VRF of an interface with no `vrf member` line.
const DEFAULT_VRF: &str = "default";

const fn e(path: &'static str, state: State, reach: Reach) -> Entry {
    Entry { path, state, reach }
}

/// The lines with no effect on the forwarding: the management of the
/// switch, the accounts, the logging and the time. Each line that can hold a
/// secret is here, so the report does not list it.
const ENTRIES: &[Entry] = &[
    e("version ..", Irrelevant, Subtree),
    e("hostname ..", Irrelevant, Subtree),
    e("switchname ..", Irrelevant, Subtree),
    e("vdc ..", Irrelevant, Subtree),
    e("feature ..", Irrelevant, Subtree),
    e("cfs ..", Irrelevant, Subtree),
    e("username ..", Irrelevant, Subtree),
    e("role ..", Irrelevant, Subtree),
    e("password ..", Irrelevant, Subtree),
    e("no password ..", Irrelevant, Subtree),
    e("ip domain-lookup", Irrelevant, Subtree),
    e("no ip domain-lookup", Irrelevant, Subtree),
    e("ip domain-name ..", Irrelevant, Subtree),
    e("ip domain-list ..", Irrelevant, Subtree),
    e("ip name-server ..", Irrelevant, Subtree),
    e("crypto key ..", Irrelevant, Subtree),
    e("ssh ..", Irrelevant, Subtree),
    e("tacacs-server ..", Irrelevant, Subtree),
    e("radius-server ..", Irrelevant, Subtree),
    e("ldap-server ..", Irrelevant, Subtree),
    e("aaa ..", Irrelevant, Subtree),
    e("key chain ..", Irrelevant, Subtree),
    e("copp ..", Irrelevant, Subtree),
    e("snmp-server ..", Irrelevant, Subtree),
    e("rmon ..", Irrelevant, Subtree),
    e("ntp ..", Irrelevant, Subtree),
    e("clock ..", Irrelevant, Subtree),
    e("logging ..", Irrelevant, Subtree),
    e("line ..", Irrelevant, Subtree),
    e("boot ..", Irrelevant, Subtree),
    e("callhome", Irrelevant, Subtree),
    e("cli alias ..", Irrelevant, Subtree),
    e("nxapi ..", Irrelevant, Subtree),
    e("license ..", Irrelevant, Subtree),
    e("spanning-tree ..", Irrelevant, Subtree),
    e("errdisable ..", Irrelevant, Subtree),
    e("power redundancy-mode ..", Irrelevant, Subtree),
    e("system jumbomtu ..", Irrelevant, Subtree),
    e("interface *", Handled, Node),
    e("interface */shutdown", Handled, Subtree),
    e("interface */no shutdown", Handled, Subtree),
    e("interface */no switchport", Handled, Subtree),
    e("interface */vrf member *", Handled, Subtree),
    e("interface */ip address ..", Handled, Subtree),
    e("interface */ipv6 address ..", Handled, Subtree),
    e("interface */ipv6 link-local ..", Handled, Subtree),
    e("interface */ip access-group * in", Handled, Subtree),
    e("interface */ip access-group * out", Handled, Subtree),
    e("interface */ip nat inside", Handled, Subtree),
    e("interface */ip nat outside", Handled, Subtree),
    e("interface */service-policy ..", Handled, Subtree),
    e("interface */switchport", Handled, Subtree),
    e("interface */switchport mode access", Handled, Subtree),
    e("interface */switchport mode trunk", Handled, Subtree),
    e("interface */switchport access vlan *", Handled, Subtree),
    e(
        "interface */switchport trunk native vlan *",
        Handled,
        Subtree,
    ),
    e(
        "interface */switchport trunk allowed vlan ..",
        Handled,
        Subtree,
    ),
    e("interface */channel-group ..", Handled, Subtree),
    e("interface */hsrp version *", Handled, Subtree),
    e("interface */hsrp *", Handled, Node),
    e("interface */hsrp */ip *", Handled, Subtree),
    e("interface */vrrp *", Handled, Node),
    e("interface */vrrp */address *", Handled, Subtree),
    e("interface */hsrp */preempt ..", Irrelevant, Subtree),
    e("interface */hsrp */priority ..", Irrelevant, Subtree),
    e("interface */hsrp */timers ..", Irrelevant, Subtree),
    e("interface */hsrp */authentication ..", Irrelevant, Subtree),
    e("interface */hsrp */name ..", Irrelevant, Subtree),
    e("interface */hsrp */track ..", Irrelevant, Subtree),
    e("interface */hsrp */mac-address ..", Irrelevant, Subtree),
    e("interface */hsrp */shutdown", Irrelevant, Subtree),
    e("interface */hsrp */no shutdown", Irrelevant, Subtree),
    e(
        "interface */hsrp */advertisement-interval ..",
        Irrelevant,
        Subtree,
    ),
    e("interface */vrrp */preempt ..", Irrelevant, Subtree),
    e("interface */vrrp */priority ..", Irrelevant, Subtree),
    e("interface */vrrp */timers ..", Irrelevant, Subtree),
    e("interface */vrrp */authentication ..", Irrelevant, Subtree),
    e("interface */vrrp */name ..", Irrelevant, Subtree),
    e("interface */vrrp */track ..", Irrelevant, Subtree),
    e("interface */vrrp */mac-address ..", Irrelevant, Subtree),
    e("interface */vrrp */shutdown", Irrelevant, Subtree),
    e("interface */vrrp */no shutdown", Irrelevant, Subtree),
    e(
        "interface */vrrp */advertisement-interval ..",
        Irrelevant,
        Subtree,
    ),
    e("interface */spanning-tree ..", Irrelevant, Subtree),
    e("interface */storm-control ..", Irrelevant, Subtree),
    e("interface */udld ..", Irrelevant, Subtree),
    e("interface */lacp ..", Irrelevant, Subtree),
    e("interface */errdisable ..", Irrelevant, Subtree),
    e("vlan *", Handled, Node),
    e("interface */vpc peer-link", Handled, Subtree),
    e("interface */vpc *", Handled, Subtree),
    e("vpc domain *", Handled, Node),
    e("vpc domain */peer-gateway", Handled, Subtree),
    e("vpc domain */peer-keepalive ..", Irrelevant, Subtree),
    e("vpc domain */role priority ..", Irrelevant, Subtree),
    e("vpc domain */system-priority ..", Irrelevant, Subtree),
    e("vpc domain */delay restore ..", Irrelevant, Subtree),
    e("vpc domain */auto-recovery ..", Irrelevant, Subtree),
    e("vpc domain */ip arp synchronize", Irrelevant, Subtree),
    e("vpc domain */ipv6 nd synchronize", Irrelevant, Subtree),
    e("vpc domain */peer-switch", Irrelevant, Subtree),
    e(
        "vpc domain */graceful consistency-check",
        Irrelevant,
        Subtree,
    ),
    e("vpc domain */system-mac ..", Irrelevant, Subtree),
    e("vlan */name ..", Irrelevant, Subtree),
    e("vlan */vn-segment *", Handled, Subtree),
    e("interface */source-interface *", Handled, Subtree),
    e(
        "interface */host-reachability protocol bgp",
        Handled,
        Subtree,
    ),
    e(
        "interface */global ingress-replication protocol bgp",
        Handled,
        Subtree,
    ),
    e("interface */global mcast-group ..", Handled, Subtree),
    e("interface */global suppress-arp", Irrelevant, Subtree),
    e("interface */member vni *", Handled, Node),
    e(
        "interface */member vni */ingress-replication protocol bgp",
        Handled,
        Subtree,
    ),
    e("interface */member vni */mcast-group ..", Handled, Subtree),
    e("interface */member vni */suppress-arp", Irrelevant, Subtree),
    e("nv overlay evpn", Irrelevant, Subtree),
    e("interface */advertise virtual-rmac", Irrelevant, Subtree),
    e("interface */member vni * associate-vrf", Handled, Subtree),
    e("interface */ip forward", Handled, Subtree),
    e(
        "interface */fabric forwarding mode anycast-gateway",
        Handled,
        Subtree,
    ),
    e("fabric forwarding anycast-gateway-mac *", Handled, Subtree),
    e("vrf context */vni *", Handled, Subtree),
    e("system default switchport", Handled, Subtree),
    e("no system default switchport", Handled, Subtree),
    e("interface */description ..", Handled, Subtree),
    e("interface */mtu ..", Irrelevant, Subtree),
    e("interface */speed ..", Irrelevant, Subtree),
    e("interface */duplex ..", Irrelevant, Subtree),
    e("interface */negotiate ..", Irrelevant, Subtree),
    e("interface */no negotiate ..", Irrelevant, Subtree),
    e("interface */link ..", Irrelevant, Subtree),
    e("interface */cdp ..", Irrelevant, Subtree),
    e("interface */no cdp ..", Irrelevant, Subtree),
    e("interface */lldp ..", Irrelevant, Subtree),
    e("interface */no lldp ..", Irrelevant, Subtree),
    e("interface */logging ..", Irrelevant, Subtree),
    e("interface */load-interval ..", Irrelevant, Subtree),
    e("interface */bandwidth ..", Irrelevant, Subtree),
    e("interface */delay ..", Irrelevant, Subtree),
    e("interface */carrier-delay ..", Irrelevant, Subtree),
    e("interface */ip redirects", Irrelevant, Subtree),
    e("interface */no ip redirects", Irrelevant, Subtree),
    e("interface */no ipv6 redirects", Irrelevant, Subtree),
    e("interface */ip unreachables", Irrelevant, Subtree),
    e("interface */no ip unreachables", Irrelevant, Subtree),
    e("interface */ip pim ..", Irrelevant, Subtree),
    e("interface */ip igmp ..", Irrelevant, Subtree),
    e("interface */snmp ..", Irrelevant, Subtree),
    e("interface */no snmp ..", Irrelevant, Subtree),
    e("ip access-list *", Handled, Node),
    e("ip access-list */*", Handled, Subtree),
    e("ip access-list */statistics per-entry", Irrelevant, Subtree),
    e("object-group ip address *", Handled, Node),
    e("object-group ip address */*", Handled, Subtree),
    e("object-group ip port *", Handled, Node),
    e("object-group ip port */*", Handled, Subtree),
    e("ip route ..", Handled, Subtree),
    e("vrf context *", Handled, Node),
    e("vrf context */ip route ..", Handled, Subtree),
    e("vrf context */description ..", Irrelevant, Subtree),
    e("vrf context */ip domain-name ..", Irrelevant, Subtree),
    e("vrf context */ip name-server ..", Irrelevant, Subtree),
    e("ip nat inside source ..", Handled, Subtree),
    e("ip nat pool ..", Handled, Subtree),
    e("ip nat translation ..", Irrelevant, Subtree),
    e("ipv6 route ..", Irrelevant, Subtree),
    e("ipv6 access-list ..", Irrelevant, Subtree),
];

/// The routing processes of NX-OS that can add IPv4 routes.
const PROCESSES: &[&str] = &[
    "router bgp",
    "router ospf",
    "router eigrp",
    "router isis",
    "router rip",
];

/// The classification table, with the mask of the secrets. The routing
/// lines of a VRF with collected route rows are known-irrelevant, because
/// its routes come from the route table; the routing lines of a VRF
/// without rows are unhandled. The route maps, the lists, the multicast
/// routing and the routing lines of an interface are known-irrelevant only
/// if each VRF with a dynamic protocol has rows. IPv6 is known-irrelevant,
/// because each IPv6 packet is unknown at the route lookup.
pub fn table(tables: &RouteTables) -> Table {
    let mut t = Table::new(ENTRIES).with_mask(super::mask);
    let default = tables.routing(DEFAULT_VRF);
    let shared = tables.shared();
    super::bgp::push_entries(&mut t, tables);
    for p in PROCESSES {
        t.push_levels(&[&format!("{p} ..")], default, Subtree);
        tables.push_vrfs(&mut t, &[&format!("{p} .."), &format!("vrf {VRF}")]);
    }
    for object in [
        "route-map ..",
        "ip prefix-list ..",
        "ip community-list ..",
        "ip as-path ..",
        "evpn",
        "ip pim ..",
        "ip igmp ..",
    ] {
        t.push_levels(&[object], shared, Subtree);
    }
    for option in ["ip ospf ..", "ip router .."] {
        t.push_levels(&["interface *", option], shared, Subtree);
    }
    for option in ["rd ..", "address-family .."] {
        tables.push_vrfs(&mut t, &[&format!("vrf context {VRF}"), option]);
    }
    t
}

/// The VRFs whose config has a dynamic routing protocol, each with the
/// lines that show it: a routing process gives the default VRF and each
/// VRF of its `vrf` lines; the route distinguisher or an address family of
/// a VRF gives that VRF; an `ip router` line of an interface gives the VRF
/// of the interface.
pub fn dynamic_vrfs(doc: &Document) -> BTreeMap<String, Vec<(u32, u32)>> {
    let mut out: BTreeMap<String, Vec<(u32, u32)>> = BTreeMap::new();
    let mut add = |vrf: &str, l: (u32, u32)| out.entry(vrf.to_string()).or_default().push(l);
    for s in doc.root.children() {
        let w = words(s);
        match w.as_slice() {
            ["router", p, ..] if PROCESSES.contains(&format!("router {p}").as_str()) => {
                add(DEFAULT_VRF, lines(s));
                for c in s.children() {
                    if let ["vrf", v] = words(c).as_slice() {
                        add(v, lines(c));
                    }
                }
            }
            ["vrf", "context", v] => {
                for c in s.children() {
                    if matches!(words(c).first(), Some(&("rd" | "address-family"))) {
                        add(v, lines(c));
                    }
                }
            }
            ["interface", _] => {
                let vrf = s
                    .children()
                    .iter()
                    .find_map(|c| match words(c).as_slice() {
                        ["vrf", "member", v] => Some((*v).to_string()),
                        _ => None,
                    })
                    .unwrap_or_else(|| DEFAULT_VRF.to_string());
                for c in s.children() {
                    if words(c).starts_with(&["ip", "router"]) {
                        add(&vrf, lines(c));
                    }
                }
            }
            _ => {}
        }
    }
    out
}
