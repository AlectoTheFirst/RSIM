//! The classification of the lines of an IOS-XE running config.

use crate::coverage::{Entry, Reach, State, Table};
use Reach::{Node, Subtree};
use State::{Handled, Irrelevant};

const fn e(path: &'static str, state: State, reach: Reach) -> Entry {
    Entry { path, state, reach }
}

/// The lines with no effect on the forwarding: the build lines before the
/// config, the management of the device, the accounts, the logging, the
/// time and the banners. Each line that can hold a secret is here, so the
/// report does not list it.
const MANAGEMENT: &[Entry] = &[
    e("Building configuration...", Irrelevant, Subtree),
    e("Current configuration ..", Irrelevant, Subtree),
    e("end", Irrelevant, Subtree),
    e("version ..", Irrelevant, Subtree),
    e("service ..", Irrelevant, Subtree),
    e("no service ..", Irrelevant, Subtree),
    e("hostname ..", Irrelevant, Subtree),
    e("boot-start-marker", Irrelevant, Subtree),
    e("boot-end-marker", Irrelevant, Subtree),
    e("boot ..", Irrelevant, Subtree),
    e("logging ..", Irrelevant, Subtree),
    e("no logging ..", Irrelevant, Subtree),
    e("aaa ..", Irrelevant, Subtree),
    e("no aaa ..", Irrelevant, Subtree),
    e("username ..", Irrelevant, Subtree),
    e("enable ..", Irrelevant, Subtree),
    e("tacacs server ..", Irrelevant, Subtree),
    e("tacacs-server ..", Irrelevant, Subtree),
    e("radius server ..", Irrelevant, Subtree),
    e("radius-server ..", Irrelevant, Subtree),
    e("key chain ..", Irrelevant, Subtree),
    e("login ..", Irrelevant, Subtree),
    e("ip domain ..", Irrelevant, Subtree),
    e("ip domain-name ..", Irrelevant, Subtree),
    e("ip domain-lookup", Irrelevant, Subtree),
    e("no ip domain lookup", Irrelevant, Subtree),
    e("no ip domain-lookup", Irrelevant, Subtree),
    e("ip name-server ..", Irrelevant, Subtree),
    e("ip http ..", Irrelevant, Subtree),
    e("no ip http ..", Irrelevant, Subtree),
    e("ip ssh ..", Irrelevant, Subtree),
    e("ip scp ..", Irrelevant, Subtree),
    e("ip tftp ..", Irrelevant, Subtree),
    e("ip ftp ..", Irrelevant, Subtree),
    e("ip forward-protocol ..", Irrelevant, Subtree),
    e("ip sla ..", Irrelevant, Subtree),
    e("track ..", Irrelevant, Subtree),
    e("crypto ..", Irrelevant, Subtree),
    e("license ..", Irrelevant, Subtree),
    e("snmp-server ..", Irrelevant, Subtree),
    e("no snmp-server ..", Irrelevant, Subtree),
    e("snmp ..", Irrelevant, Subtree),
    e("ntp ..", Irrelevant, Subtree),
    e("clock ..", Irrelevant, Subtree),
    e("line ..", Irrelevant, Subtree),
    e("banner ..", Irrelevant, Subtree),
    e("control-plane ..", Irrelevant, Subtree),
    e("platform ..", Irrelevant, Subtree),
    e("no platform ..", Irrelevant, Subtree),
    e("redundancy ..", Irrelevant, Subtree),
    e("diagnostic ..", Irrelevant, Subtree),
    e("memory ..", Irrelevant, Subtree),
    e("archive ..", Irrelevant, Subtree),
    e("call-home ..", Irrelevant, Subtree),
    e("subscriber ..", Irrelevant, Subtree),
    e("multilink ..", Irrelevant, Subtree),
    e("switch * provision ..", Irrelevant, Subtree),
    e("transceiver ..", Irrelevant, Subtree),
    e("spanning-tree ..", Irrelevant, Subtree),
    e("vtp ..", Irrelevant, Subtree),
    e("cdp ..", Irrelevant, Subtree),
    e("lldp ..", Irrelevant, Subtree),
];

/// The handled lines and the options of the handled stanzas with no effect
/// on the forwarding. The speed, the duplex and the negotiation of a port
/// are known-irrelevant, because the collected interface state gives the
/// link state. IPv6 is known-irrelevant, because each IPv6 packet is
/// unknown at the route lookup; the IPv6 addresses of an interface are read.
const FORWARDING: &[Entry] = &[
    e("interface *", Handled, Node),
    e("interface */shutdown", Handled, Subtree),
    e("interface */no shutdown", Handled, Subtree),
    e("interface */vrf forwarding *", Handled, Subtree),
    e("interface */ip vrf forwarding *", Handled, Subtree),
    e("interface */ip address ..", Handled, Subtree),
    e("interface */no ip address", Handled, Subtree),
    e("interface */ipv6 address ..", Handled, Subtree),
    e("interface */ip access-group * in", Handled, Subtree),
    e("interface */ip access-group * out", Handled, Subtree),
    e("interface */ip nat inside", Handled, Subtree),
    e("interface */ip nat outside", Handled, Subtree),
    e("interface */service-policy input *", Handled, Subtree),
    e("interface */service-policy output *", Handled, Subtree),
    e("interface */mtu *", Handled, Subtree),
    e("interface */ip mtu *", Handled, Subtree),
    e("interface */encapsulation dot1Q ..", Handled, Subtree),
    e("interface */channel-group ..", Handled, Subtree),
    e("interface */switchport", Handled, Subtree),
    e("interface */no switchport", Handled, Subtree),
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
    e(
        "interface */switchport trunk encapsulation dot1q",
        Handled,
        Subtree,
    ),
    e("interface */switchport nonegotiate", Irrelevant, Subtree),
    e("interface */standby version *", Handled, Subtree),
    e("interface */standby * ip ..", Handled, Subtree),
    e("interface */standby * priority *", Handled, Subtree),
    e("interface */standby * preempt ..", Handled, Subtree),
    e("interface */standby * mac-address *", Handled, Subtree),
    e("interface */standby * timers ..", Irrelevant, Subtree),
    e(
        "interface */standby * authentication ..",
        Irrelevant,
        Subtree,
    ),
    e("interface */standby * track ..", Irrelevant, Subtree),
    e("interface */standby * name ..", Irrelevant, Subtree),
    e("interface */vrrp * ip ..", Handled, Subtree),
    e("interface */vrrp * priority *", Handled, Subtree),
    e("interface */vrrp * preempt ..", Handled, Subtree),
    e("interface */vrrp * timers ..", Irrelevant, Subtree),
    e("interface */vrrp * authentication ..", Irrelevant, Subtree),
    e("interface */vrrp * description ..", Irrelevant, Subtree),
    e("interface */vrrp * track ..", Irrelevant, Subtree),
    e("interface */description ..", Irrelevant, Subtree),
    e("interface */negotiation ..", Irrelevant, Subtree),
    e("interface */speed ..", Irrelevant, Subtree),
    e("interface */duplex ..", Irrelevant, Subtree),
    e("interface */load-interval ..", Irrelevant, Subtree),
    e("interface */carrier-delay ..", Irrelevant, Subtree),
    e("interface */keepalive ..", Irrelevant, Subtree),
    e("interface */no keepalive", Irrelevant, Subtree),
    e("interface */cdp ..", Irrelevant, Subtree),
    e("interface */no cdp ..", Irrelevant, Subtree),
    e("interface */lldp ..", Irrelevant, Subtree),
    e("interface */no lldp ..", Irrelevant, Subtree),
    e("interface */logging event ..", Irrelevant, Subtree),
    e("interface */no logging event ..", Irrelevant, Subtree),
    e("interface */power inline ..", Irrelevant, Subtree),
    e("interface */spanning-tree ..", Irrelevant, Subtree),
    e("interface */udld ..", Irrelevant, Subtree),
    e("interface */lacp ..", Irrelevant, Subtree),
    e("interface */bandwidth ..", Irrelevant, Subtree),
    e("interface */delay ..", Irrelevant, Subtree),
    e("interface */ip redirects", Irrelevant, Subtree),
    e("interface */no ip redirects", Irrelevant, Subtree),
    e("interface */ip unreachables", Irrelevant, Subtree),
    e("interface */no ip unreachables", Irrelevant, Subtree),
    e("interface */no ip proxy-arp", Irrelevant, Subtree),
    e("interface */no snmp trap link-status", Irrelevant, Subtree),
    e("interface */ipv6 ..", Irrelevant, Subtree),
    e("vrf definition *", Handled, Node),
    e("vrf definition */description ..", Irrelevant, Subtree),
    e("vrf definition */address-family ipv4", Handled, Node),
    e(
        "vrf definition */address-family ipv6 ..",
        Irrelevant,
        Subtree,
    ),
    e("vrf definition */exit-address-family", Irrelevant, Subtree),
    e("ip vrf *", Handled, Node),
    e("ip vrf */description ..", Irrelevant, Subtree),
    e("ip access-list extended *", Handled, Node),
    e("ip access-list extended */*", Handled, Subtree),
    e("ip access-list standard *", Handled, Node),
    e("ip access-list standard */*", Handled, Subtree),
    e("access-list ..", Handled, Subtree),
    e("ip route ..", Handled, Subtree),
    e("ip routing", Handled, Subtree),
    e("no ip routing", Handled, Subtree),
    e("ip nat inside source ..", Handled, Subtree),
    e("ip nat pool ..", Handled, Subtree),
    e("ip nat translation ..", Irrelevant, Subtree),
    e("vtp mode *", Handled, Subtree),
    e("vlan *", Handled, Node),
    e("vlan */name ..", Handled, Subtree),
    e("ipv6 ..", Irrelevant, Subtree),
];

/// The classification table, with the mask of the secrets. With a collected
/// route table, the routing protocols, the route maps, the lists of the
/// routing policies, the routing lines of an interface and the route
/// distinguishers and route targets of a VRF are known-irrelevant, because
/// the routes come from the route table. Without it, they are unhandled.
pub fn table(rib_collected: bool) -> Table {
    let mut t = Table::new(MANAGEMENT).with_mask(super::mask);
    for entry in FORWARDING {
        t.push(entry.path, entry.state, entry.reach);
    }
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
        "ip bgp-community ..",
    ] {
        t.push_levels(&[protocol], routing, Subtree);
    }
    for option in [
        "ip ospf ..",
        "ip router ..",
        "ip authentication ..",
        "ip summary-address ..",
    ] {
        t.push_levels(&["interface *", option], routing, Subtree);
    }
    for option in ["rd ..", "route-target .."] {
        t.push_levels(&["vrf definition *", option], routing, Subtree);
        t.push_levels(&["ip vrf *", option], routing, Subtree);
    }
    for option in ["route-target ..", "import ..", "export .."] {
        t.push_levels(
            &["vrf definition *", "address-family ipv4", option],
            routing,
            Subtree,
        );
    }
    t
}
