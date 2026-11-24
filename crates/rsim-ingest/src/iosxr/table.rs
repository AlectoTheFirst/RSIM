//! The classification of the lines of an IOS-XR running config.

use std::collections::BTreeMap;

use super::profile::DEFAULT_VRF;
use crate::coverage::{Entry, Reach, State, Table};
use crate::route_tables::{RouteTables, VRF, lines, words};
use crate::stanza::Document;
use Reach::{Node, Subtree};
use State::{Handled, Irrelevant};

const fn e(path: &'static str, state: State, reach: Reach) -> Entry {
    Entry { path, state, reach }
}

/// The lines with no effect on the forwarding: the time and the build line
/// before the config, the management of the router, the accounts, the
/// logging and the time. Each line that can hold a secret is here, so the
/// report does not list it.
const ENTRIES: &[Entry] = &[
    e("Mon ..", Irrelevant, Subtree),
    e("Tue ..", Irrelevant, Subtree),
    e("Wed ..", Irrelevant, Subtree),
    e("Thu ..", Irrelevant, Subtree),
    e("Fri ..", Irrelevant, Subtree),
    e("Sat ..", Irrelevant, Subtree),
    e("Sun ..", Irrelevant, Subtree),
    e("Building configuration...", Irrelevant, Subtree),
    e("end", Irrelevant, Subtree),
    e("hostname ..", Irrelevant, Subtree),
    e("domain ..", Irrelevant, Subtree),
    e("username ..", Irrelevant, Subtree),
    e("aaa ..", Irrelevant, Subtree),
    e("tacacs-server ..", Irrelevant, Subtree),
    e("radius-server ..", Irrelevant, Subtree),
    e("snmp-server ..", Irrelevant, Subtree),
    e("ntp ..", Irrelevant, Subtree),
    e("clock ..", Irrelevant, Subtree),
    e("logging ..", Irrelevant, Subtree),
    e("line ..", Irrelevant, Subtree),
    e("vty-pool ..", Irrelevant, Subtree),
    e("ssh ..", Irrelevant, Subtree),
    e("telnet ..", Irrelevant, Subtree),
    e("http ..", Irrelevant, Subtree),
    e("grpc ..", Irrelevant, Subtree),
    e("netconf-yang ..", Irrelevant, Subtree),
    e("xml ..", Irrelevant, Subtree),
    e("call-home ..", Irrelevant, Subtree),
    e("lldp ..", Irrelevant, Subtree),
    e("cdp ..", Irrelevant, Subtree),
    e("banner ..", Irrelevant, Subtree),
    e("service ..", Irrelevant, Subtree),
    e("control-plane ..", Irrelevant, Subtree),
    e("lpts ..", Irrelevant, Subtree),
    e("crypto ..", Irrelevant, Subtree),
    e("key chain ..", Irrelevant, Subtree),
    e("license ..", Irrelevant, Subtree),
    e("hw-module ..", Irrelevant, Subtree),
    e("fpd ..", Irrelevant, Subtree),
    e("telemetry ..", Irrelevant, Subtree),
    e("interface *", Handled, Node),
    e("interface */shutdown", Handled, Subtree),
    e("interface */vrf *", Handled, Subtree),
    e("interface */ipv4 address ..", Handled, Subtree),
    e("interface */ipv6 address ..", Handled, Subtree),
    e("interface */ipv4 access-group * ingress", Handled, Subtree),
    e("interface */ipv4 access-group * egress", Handled, Subtree),
    e("interface */encapsulation dot1q ..", Handled, Subtree),
    e("interface */bundle id * mode ..", Handled, Subtree),
    e("interface */service-policy input *", Handled, Subtree),
    e("interface */service-policy output *", Handled, Subtree),
    e("interface */mtu *", Handled, Subtree),
    e("interface */description ..", Handled, Subtree),
    e("interface */load-interval ..", Irrelevant, Subtree),
    e("interface */negotiation ..", Irrelevant, Subtree),
    e("interface */carrier-delay ..", Irrelevant, Subtree),
    e("interface */dampening ..", Irrelevant, Subtree),
    e("interface */lldp ..", Irrelevant, Subtree),
    e("interface */cdp ..", Irrelevant, Subtree),
    e("interface */bfd ..", Irrelevant, Subtree),
    // The minimum of active members decides whether the bundle is up, and
    // the collected interface state shows that.
    e("interface */bundle minimum-active ..", Irrelevant, Subtree),
    e("vrf *", Handled, Node),
    e("vrf */description ..", Irrelevant, Subtree),
    e("ipv4 access-list *", Handled, Node),
    e("ipv4 access-list */*", Handled, Subtree),
    e("ipv6 access-list ..", Irrelevant, Subtree),
];

/// The lines of an IPv4 HSRP group: the addresses, the priority, the
/// preemption and the virtual MAC are read. The timers, the
/// authentication, the name, the tracking and BFD change no forwarding
/// state that `show hsrp` does not give.
const HSRP_GROUP: &[(&str, State)] = &[
    ("address *", Handled),
    ("address * secondary", Handled),
    ("priority *", Handled),
    ("preempt ..", Handled),
    ("mac-address *", Handled),
    ("timers ..", Irrelevant),
    ("authentication ..", Irrelevant),
    ("name ..", Irrelevant),
    ("track ..", Irrelevant),
    ("bfd ..", Irrelevant),
];

/// The entries of `router hsrp`. IPv6 groups are known-irrelevant, because
/// each IPv6 packet is unknown at the route lookup.
fn push_hsrp(t: &mut Table) {
    let base = ["router hsrp", "interface *"];
    t.push_levels(&base[..1], Handled, Node);
    t.push_levels(&base, Handled, Node);
    t.push_levels(&[base[0], base[1], "hsrp delay .."], Irrelevant, Subtree);
    t.push_levels(
        &[base[0], base[1], "address-family ipv6 .."],
        Irrelevant,
        Subtree,
    );
    let af = [base[0], base[1], "address-family ipv4"];
    t.push_levels(&af, Handled, Node);
    for group in ["hsrp *", "hsrp * version *"] {
        let g = [af[0], af[1], af[2], group];
        t.push_levels(&g, Handled, Node);
        for (line, state) in HSRP_GROUP {
            t.push_levels(&[g[0], g[1], g[2], g[3], line], *state, Subtree);
        }
    }
}

/// The routing processes of IOS-XR that can add IPv4 routes.
const PROCESSES: &[&str] = &[
    "router bgp",
    "router ospf",
    "router isis",
    "router eigrp",
    "router rip",
    "router static",
];

/// The classification table, with the mask of the secrets. The routing
/// lines of a VRF with collected route rows are known-irrelevant, because
/// its routes come from the route table; the routing lines of a VRF without
/// rows are unhandled. The route policies and the sets are known-irrelevant
/// only if each VRF with a dynamic protocol has rows. The `end-policy` and
/// `end-set` lines that close a policy or a set get the state of the policy
/// or the set. IPv6 access lists are known-irrelevant, because each IPv6
/// packet is unknown at the route lookup.
pub fn table(tables: &RouteTables) -> Table {
    let mut t = Table::new(ENTRIES).with_mask(super::mask);
    push_hsrp(&mut t);
    let default = tables.routing(DEFAULT_VRF);
    super::bgp::push_entries(&mut t, tables);
    for p in PROCESSES {
        t.push_levels(&[&format!("{p} ..")], default, Subtree);
        tables.push_vrfs(&mut t, &[&format!("{p} .."), &format!("vrf {VRF}")]);
    }
    for object in [
        "route-policy ..",
        "end-policy",
        "prefix-set ..",
        "community-set ..",
        "as-path-set ..",
        "extcommunity-set ..",
        "rpl ..",
        "end-set",
    ] {
        t.push_levels(&[object], tables.shared(), Subtree);
    }
    for option in ["address-family ..", "rd .."] {
        tables.push_vrfs(&mut t, &[&format!("vrf {VRF}"), option]);
    }
    t
}

/// The VRFs whose config has a dynamic routing protocol, each with the
/// lines that show it: a routing process other than `router static` gives
/// the default VRF and each VRF of its `vrf` lines; an address family or
/// a route distinguisher of a VRF gives that VRF.
pub fn dynamic_vrfs(doc: &Document) -> BTreeMap<String, Vec<(u32, u32)>> {
    let mut out: BTreeMap<String, Vec<(u32, u32)>> = BTreeMap::new();
    let mut add = |vrf: &str, l: (u32, u32)| out.entry(vrf.to_string()).or_default().push(l);
    for s in doc.root.children() {
        let w = words(s);
        match w.as_slice() {
            ["router", "static", ..] => {}
            ["router", p, ..] if PROCESSES.contains(&format!("router {p}").as_str()) => {
                add(DEFAULT_VRF, lines(s));
                for c in s.children() {
                    if let ["vrf", v] = words(c).as_slice() {
                        add(v, lines(c));
                    }
                }
            }
            ["vrf", v] => {
                for c in s.children() {
                    if matches!(words(c).first(), Some(&("rd" | "address-family"))) {
                        add(v, lines(c));
                    }
                }
            }
            _ => {}
        }
    }
    out
}
