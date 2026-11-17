//! The classification of the lines of an NX-OS running config.

use crate::coverage::{Entry, Reach, State, Table};
use Reach::Subtree;
use State::Irrelevant;

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
];

/// The classification table, with the mask of the secrets. With a collected
/// route table, the routing protocols are known-irrelevant, because the
/// routes come from the route table. Without it, they are unhandled.
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
    ] {
        t.push_levels(&[protocol], routing, Subtree);
    }
    t
}
