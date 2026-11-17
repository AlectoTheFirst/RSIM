//! The classification of the lines of an NX-OS running config.

use crate::coverage::{Entry, Reach, State, Table};
use Reach::{Node, Subtree};
use State::{Handled, Irrelevant};

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
    e("interface */description ..", Irrelevant, Subtree),
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

/// The classification table, with the mask of the secrets. With a collected
/// route table, the routing protocols and their policies are known-irrelevant,
/// because the routes come from the route table. Without it, they are
/// unhandled. IPv6 is known-irrelevant, because each IPv6 packet is unknown
/// at the route lookup.
pub fn table(rib_collected: bool) -> Table {
    let mut t = Table::new(ENTRIES).with_mask(super::mask);
    let routing = if rib_collected {
        Irrelevant
    } else {
        State::Unhandled
    };
    for protocol in [
        "router bgp ..",
        "router ospf ..",
        "router eigrp ..",
        "router isis ..",
        "route-map ..",
        "ip prefix-list ..",
        "ip community-list ..",
        "ip as-path ..",
    ] {
        t.push_levels(&[protocol], routing, Subtree);
    }
    for option in ["ip ospf ..", "ip router .."] {
        t.push_levels(&["interface *", option], routing, Subtree);
    }
    for option in ["rd ..", "vni ..", "address-family .."] {
        t.push_levels(&["vrf context *", option], routing, Subtree);
    }
    t
}
