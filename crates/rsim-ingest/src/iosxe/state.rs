//! The collected text sections of an IOS-XE router or switch that the
//! lowering reads, each parsed by its TextFSM template: the interface state,
//! the route table of each VRF, ARP of the global table and of each VRF, the
//! access lists, the LLDP and CDP neighbours, the HSRP and VRRP groups, the
//! MAC table, the spanning tree and the VLANs. Each row keeps the line range
//! of its record in the section.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{Prefix, SourceSpan};

use rsim_core::Mac;

use super::profile::{
    ARP_OWN_AGE, ARP_VRF_FAILED, ARP_VRF_LINE, DEFAULT_VRF, HSRP_LOCAL, PLATFORM,
    ROUTE_FLAGS_NOT_LOWERED, STATE_ADMIN_DOWN, STATE_DOWN, STATE_UP, STP_FORWARDING,
    STP_MST_HEADER, STP_NOT_FORWARDING, TABLE_HEADERS, VRF_HEADER,
};
use crate::collected::MacRow;
use crate::iosxr::state::{
    ArpRow, HsrpRow, IfState, Parsed, Rib, RoutePath, Section, UnreadRoute, cdp, hsrp, lldp,
    parse_on, prefix_on, speed,
};
use crate::nxos::names::Names;
use crate::nxos::state::mac;

/// The sections that the lowering reads, each with the command that selects
/// its template in the index.
pub const SECTIONS: &[(&str, &str)] = &[
    ("interfaces", "show interfaces"),
    ("rib", "show ip route vrf *"),
    ("rib_global", "show ip route"),
    ("arp", "show ip arp"),
    ("acls", "show ip access-lists"),
    ("lldp", "show lldp neighbors detail"),
    ("cdp", "show cdp neighbors detail"),
    ("hsrp", "show standby brief"),
    ("vrrp", "show vrrp brief"),
    ("mac_table", "show mac address-table"),
    ("spanning_tree", "show spanning-tree"),
    ("vlans", "show vlan brief"),
    ("hsrp_detail", "show standby"),
    ("vrrp_detail", "show vrrp"),
    ("arp_vrfs", "show ip arp"),
];

/// An access list of `show ip access-lists`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AclList {
    pub standard: bool,
    /// The sequence number and the action of each entry.
    pub entries: BTreeSet<(u64, String)>,
    pub span: Option<SourceSpan>,
}

/// An HSRP or VRRP group of `show standby` or `show vrrp`: the row of the
/// brief form, the virtual MAC, and for HSRP whether the active router is
/// the router itself (`None` if the section does not say).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupDetail {
    pub row: HsrpRow,
    pub vmac: Option<Mac>,
    pub active_local: Option<bool>,
}

/// The state of a port in the tree of a VLAN in `show spanning-tree`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StpState {
    Forwarding,
    NotForwarding,
    /// A state word that is not known.
    Unknown(String),
}

/// The state of each port in each VLAN: the port with the name of the
/// config, the VLAN, the state and the span of the row.
pub type Stp = BTreeMap<(String, u16), (StpState, SourceSpan)>;

/// A VLAN of `show vlan brief`: its number, its status word and its span.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VlanRow {
    pub vlan: u16,
    pub status: String,
    pub span: SourceSpan,
}

/// The ARP table of each VRF of the section `arp_vrfs`. A VRF whose
/// command failed gives an error.
pub type VrfArp = BTreeMap<String, Result<Vec<ArpRow>, String>>;

/// The collected sections of a router. The interface state, the route
/// table, ARP, the neighbours and the HSRP groups have the row types of
/// IOS-XR, so the lowering shares the route table, the next-hop resolution,
/// the summary and the hand-off.
#[derive(Clone, Debug, Default)]
pub struct State {
    pub l3: crate::iosxr::state::State,
    pub acls: Section<BTreeMap<String, AclList>>,
    /// The VRRP groups of `show vrrp brief`.
    pub vrrp: Section<Vec<HsrpRow>>,
    /// The HSRP groups of `show standby`.
    pub hsrp_detail: Section<Vec<GroupDetail>>,
    /// The VRRP groups of `show vrrp`.
    pub vrrp_detail: Section<Vec<GroupDetail>>,
    pub mac_table: Section<Vec<MacRow>>,
    pub stp: Section<Stp>,
    pub vlans: Section<Vec<VlanRow>>,
    pub arp_vrfs: Section<VrfArp>,
}

/// An IOS-XE answer has no line before it.
fn no_line(_: &str) -> bool {
    false
}

fn parse(section: &str, bytes: &[u8], file: &str) -> Result<Parsed, String> {
    let command = SECTIONS
        .iter()
        .find(|(n, _)| *n == section)
        .map_or("", |(_, c)| c);
    parse_on(PLATFORM, command, bytes, file, no_line)
}

fn section<T>(
    sections: &BTreeMap<String, (Vec<u8>, String)>,
    name: &str,
    read: impl FnOnce(&Parsed, &str) -> Result<T, String>,
) -> Section<T> {
    let (bytes, file) = sections.get(name)?;
    let text = String::from_utf8_lossy(bytes);
    Some(parse(name, bytes, file).and_then(|p| read(&p, &text)))
}

/// Reads the collected sections. `names` resolves the interface names of
/// the sections to the names of the config.
pub fn read(sections: &BTreeMap<String, (Vec<u8>, String)>, names: &Names) -> State {
    State {
        l3: crate::iosxr::state::State {
            interfaces: section(sections, "interfaces", |p, _| Ok(interfaces(p, names))),
            rib: routes(sections, names),
            arp: section(sections, "arp", |p, _| Ok(arp(p, names))),
            lldp: section(sections, "lldp", |p, _| Ok(lldp(p, names))),
            cdp: section(sections, "cdp", |p, _| Ok(cdp(p, names))),
            hsrp: section(sections, "hsrp", |p, _| hsrp(p, names)),
            ..Default::default()
        },
        acls: section(sections, "acls", |p, _| acls(p)),
        vrrp: section(sections, "vrrp", |p, _| hsrp(p, names)),
        hsrp_detail: section(sections, "hsrp_detail", |p, _| {
            groups(p, names, "VIRTUAL_IP", "ACTIVE_VIRTUAL_MAC")
        }),
        vrrp_detail: section(sections, "vrrp_detail", |p, _| {
            groups(p, names, "VIRTUAL_IP_ADDRESS", "VIRTUAL_MAC_ADDRESS")
        }),
        mac_table: section(sections, "mac_table", |p, _| Ok(mac_table(p))),
        stp: section(sections, "spanning_tree", |p, text| stp(p, text, names)),
        vlans: section(sections, "vlans", |p, _| vlans(p)),
        arp_vrfs: sections
            .get("arp_vrfs")
            .map(|(bytes, file)| arp_vrfs(&String::from_utf8_lossy(bytes), file, names)),
    }
}

/// The groups of `show standby` or `show vrrp` with the address field and
/// the virtual MAC field of the template. The HSRP field `ACTIVE_ROUTER`
/// gives whether the router itself is the active router.
fn groups(
    p: &Parsed,
    names: &Names,
    address: &str,
    vmac: &str,
) -> Result<Vec<GroupDetail>, String> {
    p.records()
        .map(|(r, span)| {
            let group = p.text(r, "GROUP");
            let active = p.text(r, "ACTIVE_ROUTER");
            Ok(GroupDetail {
                row: HsrpRow {
                    interface: names.resolve(p.text(r, "INTERFACE")),
                    group: group
                        .parse()
                        .map_err(|_| format!("the group {group:?} is not a number"))?,
                    state: p.text(r, "STATE").to_string(),
                    address: p.text(r, address).parse().ok(),
                    span,
                },
                vmac: mac(p.text(r, vmac)),
                active_local: if active.eq_ignore_ascii_case(HSRP_LOCAL) {
                    Some(true)
                } else if active.parse::<IpAddr>().is_ok() {
                    Some(false)
                } else {
                    None
                },
            })
        })
        .collect()
}

/// The rows of the MAC table. A row whose VLAN is not a number, such as
/// `All`, is not a row of a bridge domain. A row with more than one port
/// has no port.
fn mac_table(p: &Parsed) -> Vec<MacRow> {
    p.records()
        .filter_map(|(r, span)| {
            let vlan = p.text(r, "VLAN_ID").parse().ok()?;
            let ports = p.list(r, "DESTINATION_PORT");
            Some(MacRow {
                vlan,
                mac: p.text(r, "DESTINATION_ADDRESS").to_string(),
                port: match ports.as_slice() {
                    [one] => Some(one.clone()),
                    _ => None,
                },
                kind: Some(p.text(r, "TYPE").to_ascii_lowercase()),
                span,
            })
        })
        .collect()
}

/// The state of each port in the tree of each VLAN. The template carries
/// the VLAN of a tree down to the rows of the next tree, so a tree of
/// another form, such as an MST instance, makes the section not read.
fn stp(p: &Parsed, text: &str, names: &Names) -> Result<Stp, String> {
    if let Some(line) = text
        .lines()
        .find(|l| l.trim_start().starts_with(STP_MST_HEADER))
    {
        return Err(format!(
            "the tree {:?} is not the tree of a VLAN",
            line.trim()
        ));
    }
    let mut out = Stp::new();
    for (r, span) in p.records() {
        let vlan = p.text(r, "VLAN_ID");
        let Ok(vlan) = vlan.parse::<u16>() else {
            return Err(format!("the row at line {} has no VLAN", span.first_line));
        };
        let word = p.text(r, "STATUS").to_ascii_lowercase();
        let state = if STP_FORWARDING.contains(&word.as_str()) {
            StpState::Forwarding
        } else if STP_NOT_FORWARDING.contains(&word.as_str()) {
            StpState::NotForwarding
        } else {
            StpState::Unknown(p.text(r, "STATUS").to_string())
        };
        out.insert((names.resolve(p.text(r, "INTERFACE")), vlan), (state, span));
    }
    Ok(out)
}

/// The VLANs of `show vlan brief`.
fn vlans(p: &Parsed) -> Result<Vec<VlanRow>, String> {
    p.records()
        .map(|(r, span)| {
            let vlan = p.text(r, "VLAN_ID");
            Ok(VlanRow {
                vlan: vlan
                    .parse()
                    .map_err(|_| format!("the VLAN {vlan:?} is not a number"))?,
                status: p.text(r, "STATUS").to_string(),
                span,
            })
        })
        .collect()
}

/// The ARP table of each VRF of the section `arp_vrfs`: each line
/// `VRF: <name>` starts the answer of a VRF, and the line
/// `VRF: <name> failed` gives a VRF whose command failed. A text before
/// the first such line makes the section not read.
fn arp_vrfs(text: &str, file: &str, names: &Names) -> Result<VrfArp, String> {
    let lines: Vec<&str> = text.lines().collect();
    let starts: Vec<usize> = (0..lines.len())
        .filter(|&i| lines[i].starts_with(ARP_VRF_LINE))
        .collect();
    let first = starts.first().copied().unwrap_or(lines.len());
    if let Some(l) = lines[..first].iter().find(|l| !l.trim().is_empty()) {
        return Err(format!("the line {:?} is before the first VRF", l.trim()));
    }
    let mut out = VrfArp::new();
    for (k, &at) in starts.iter().enumerate() {
        let end = starts.get(k + 1).copied().unwrap_or(lines.len());
        let head = lines[at][ARP_VRF_LINE.len()..].trim();
        if let Some(name) = head.strip_suffix(ARP_VRF_FAILED) {
            let name = name.trim();
            out.insert(
                name.to_string(),
                Err(format!("the command of the ARP table of VRF {name} failed")),
            );
            continue;
        }
        let mut body = lines[at + 1..end].join("\n");
        body.push('\n');
        let rows = parse("arp_vrfs", body.as_bytes(), file).map(|mut p| {
            p.shift(at + 1);
            arp(&p, names)
        });
        out.insert(head.to_string(), rows);
    }
    Ok(out)
}

/// The route tables. With the section `rib_global`, the global table comes
/// from it, and the section `rib` gives only the tables of the VRFs.
/// Without it, the global table is the table before the first VRF header
/// of `rib`.
fn routes(sections: &BTreeMap<String, (Vec<u8>, String)>, names: &Names) -> Section<Rib> {
    let all = section(sections, "rib", |p, text| Ok(rib(p, text, names)));
    let global = section(sections, "rib_global", |p, text| Ok(rib(p, text, names)));
    let (Some(Ok(mut global)), Some(Ok(all))) = (global, all) else {
        return section(sections, "rib", |p, text| Ok(rib(p, text, names)));
    };
    let named = |vrf: &Option<String>| vrf.as_deref() != Some(DEFAULT_VRF);
    global
        .paths
        .extend(all.paths.into_iter().filter(|p| p.vrf != DEFAULT_VRF));
    global
        .unread
        .extend(all.unread.into_iter().filter(|u| named(&u.vrf)));
    Some(Ok(global))
}

/// The VRFs with a path or a line of the route table section, if the
/// section is in the snapshot and its template parses it.
pub fn rib_vrfs(sections: &BTreeMap<String, (Vec<u8>, String)>) -> BTreeSet<String> {
    match routes(sections, &Names::default()) {
        Some(Ok(r)) => crate::iosxr::state::vrfs_of(&r),
        _ => BTreeSet::new(),
    }
}

/// The first word of a state, so `up (connected)` is `up`; the whole state
/// for `administratively down`.
fn state_word(s: &str) -> &str {
    let s = s.trim();
    if s == STATE_ADMIN_DOWN {
        return s;
    }
    s.split_whitespace().next().unwrap_or_default()
}

fn interfaces(p: &Parsed, names: &Names) -> BTreeMap<String, IfState> {
    let mut out = BTreeMap::new();
    for (r, span) in p.records() {
        let link = state_word(p.text(r, "LINK_STATUS"));
        let protocol = state_word(p.text(r, "PROTOCOL_STATUS"));
        let oper_up = match (link, protocol) {
            (STATE_UP, STATE_UP) => Some(true),
            (STATE_DOWN | STATE_ADMIN_DOWN, _) | (_, STATE_DOWN) => Some(false),
            _ => None,
        };
        let duplex = p.text(r, "DUPLEX").trim().to_ascii_lowercase();
        out.insert(
            names.resolve(p.text(r, "INTERFACE")),
            IfState {
                oper_up,
                admin_down: link == STATE_ADMIN_DOWN,
                mac: mac(p.text(r, "MAC_ADDRESS")),
                speed_mbps: speed(p.text(r, "SPEED")),
                full_duplex: if duplex.starts_with("full") {
                    Some(true)
                } else if duplex.starts_with("half") {
                    Some(false)
                } else {
                    None
                },
                span,
            },
        );
    }
    out
}

fn arp(p: &Parsed, names: &Names) -> Vec<ArpRow> {
    p.records()
        .filter(|(r, _)| p.text(r, "AGE").trim() != ARP_OWN_AGE)
        .filter_map(|(r, span)| {
            let iface = p.text(r, "INTERFACE").trim();
            if iface.is_empty() {
                return None;
            }
            Some(ArpRow {
                ip: p.text(r, "IP_ADDRESS").parse().ok()?,
                mac: mac(p.text(r, "MAC_ADDRESS"))?,
                interface: names.resolve(iface),
                span,
            })
        })
        .collect()
}

/// The access lists with their entries. A header record opens a list.
fn acls(p: &Parsed) -> Result<BTreeMap<String, AclList>, String> {
    let mut out: BTreeMap<String, AclList> = BTreeMap::new();
    for (r, span) in p.records() {
        let name = p.text(r, "ACL_NAME");
        let list = out.entry(name.to_string()).or_default();
        list.standard = p.text(r, "ACL_TYPE") == "Standard";
        let seq = p.text(r, "LINE_NUM");
        if seq.is_empty() {
            list.span = Some(span);
            continue;
        }
        let n = seq
            .parse::<u64>()
            .map_err(|_| format!("the entry number {seq:?} of {name} is not a number"))?;
        list.entries.insert((n, p.text(r, "ACTION").to_string()));
    }
    Ok(out)
}

/// The route table of each line of the route table section, from line 1:
/// the global table, a VRF, or `None` for a table whose VRF is not known.
/// The global table is the table before the first header line of a VRF. A
/// table header after the routes of a table with no header line of a VRF
/// before it starts a table whose VRF is not known, as does a header line of
/// a VRF that does not have the form `Routing Table: <name>`.
fn tables(text: &str) -> Vec<Option<String>> {
    let mut out = Vec::new();
    // The table so far: `None` before the first table, `Some(None)` for a
    // table whose VRF is not known.
    let mut current: Option<Option<String>> = None;
    let mut content = false;
    for line in text.lines() {
        let t = line.trim_end();
        let words: Vec<&str> = t.split_whitespace().collect();
        let legend = t.starts_with(char::is_whitespace) && words.get(1) == Some(&"-");
        if let Some(rest) = t.strip_prefix(VRF_HEADER) {
            let name = rest.strip_prefix(' ').unwrap_or_default();
            let named = !name.is_empty() && !name.contains(char::is_whitespace);
            current = Some(named.then(|| name.to_string()));
            content = false;
        } else if TABLE_HEADERS.iter().any(|h| t.starts_with(h)) {
            if content || current.is_none() {
                current = Some(match current {
                    None => Some(DEFAULT_VRF.to_string()),
                    Some(_) => None,
                });
                content = false;
            }
        } else if !t.trim().is_empty() && !legend {
            if current.is_none() {
                current = Some(Some(DEFAULT_VRF.to_string()));
            }
            content = true;
        }
        out.push(current.clone().flatten());
    }
    out
}

/// The prefix of the route of an unread line: the prefix on the line, or
/// for a path line below a route line, the prefix of that route line. A
/// path line starts with a space and then `[` or `is directly connected`.
fn unread_prefix(lines: &[&str], line: usize) -> Option<Prefix> {
    let text = lines.get(line.checked_sub(1)?)?;
    if let Some(p) = prefix_on(text) {
        return Some(p);
    }
    let path = |t: &str| {
        t.starts_with(char::is_whitespace) && {
            let t = t.trim_start();
            t.starts_with('[') || t.starts_with("is directly connected")
        }
    };
    if !path(text) {
        return None;
    }
    let mut at = line - 1;
    while at > 0 {
        let above = lines[at - 1];
        if !path(above) {
            return if above.starts_with(char::is_whitespace) {
                None
            } else {
                prefix_on(above)
            };
        }
        at -= 1;
    }
    None
}

fn rib(p: &Parsed, text: &str, names: &Names) -> Rib {
    let lines: Vec<&str> = text.lines().collect();
    let tables = tables(text);
    let table_of = |line: usize| {
        line.checked_sub(1)
            .and_then(|i| tables.get(i))
            .cloned()
            .flatten()
    };
    let mut out = Rib::default();
    // The lines that no route path holds, each with its text.
    let mut unread: BTreeMap<usize, String> = BTreeMap::new();
    for ((r, span), (first, _)) in p.records().zip(&p.traced.lines) {
        let line_text = lines
            .get(first.saturating_sub(1))
            .map_or("", |l| l.trim())
            .to_string();
        if !p.text(r, "UNREAD").is_empty() {
            unread.insert(*first, line_text);
            continue;
        }
        let flag = p.text(r, "FLAG");
        let table = table_of(*first);
        let template_vrf = p.text(r, "VRF");
        let vrf = match table {
            Some(t) if t == DEFAULT_VRF && template_vrf.is_empty() => Some(t),
            Some(t) if t == template_vrf => Some(t),
            _ => None,
        };
        let prefix = format!("{}/{}", p.text(r, "NETWORK"), p.text(r, "PREFIX_LENGTH"))
            .parse::<Prefix>()
            .ok();
        let gateway = p.text(r, "NEXTHOP_IP").parse::<IpAddr>().ok();
        let iface = p.text(r, "NEXTHOP_IF").trim();
        let (Some(vrf), Some(prefix)) = (vrf, prefix) else {
            unread.insert(*first, line_text);
            continue;
        };
        if ROUTE_FLAGS_NOT_LOWERED.contains(&flag) || (gateway.is_none() && iface.is_empty()) {
            unread.insert(*first, line_text);
            continue;
        }
        let kind = p.text(r, "TYPE");
        let protocol = if kind.is_empty() {
            format!("{}{flag}", p.text(r, "PROTOCOL"))
        } else {
            format!("{}{flag} {kind}", p.text(r, "PROTOCOL"))
        };
        let other_vrf = p.text(r, "NEXTHOP_VRF");
        out.paths.push(RoutePath {
            other_vrf: (!other_vrf.is_empty() && other_vrf != vrf).then(|| other_vrf.to_string()),
            vrf,
            prefix,
            protocol,
            gateway,
            interface: (!iface.is_empty()).then(|| names.resolve(iface)),
            backup: false,
            span,
        });
    }
    for u in &p.traced.unread {
        unread.insert(u.line, u.text.trim().to_string());
    }
    for (line, text) in unread {
        // The header line of a VRF that the template does not read starts a
        // table whose VRF is not known; its routes are unread lines.
        if text.starts_with(VRF_HEADER) {
            continue;
        }
        out.unread.push(UnreadRoute {
            vrf: table_of(line),
            prefix: unread_prefix(&lines, line),
            text,
            span: p.span(line, line),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_index_gives_a_template_to_each_command() {
        let lib = crate::iosxr::state::library().unwrap();
        for (section, command) in SECTIONS {
            let (name, _) = lib.find(PLATFORM, command).unwrap();
            let want = match *section {
                "interfaces" => "cisco_ios_show_interfaces.textfsm",
                "rib" | "rib_global" => "cisco_ios_show_ip_route.textfsm",
                "lldp" => "cisco_ios_show_lldp_neighbors_detail.textfsm",
                "cdp" => "cisco_ios_show_cdp_neighbors_detail.textfsm",
                "hsrp" => "cisco_ios_show_standby_brief.textfsm",
                "vrrp" => "cisco_ios_show_vrrp_brief.textfsm",
                "mac_table" => "cisco_ios_show_mac-address-table.textfsm",
                "spanning_tree" => "cisco_ios_show_spanning-tree.textfsm",
                "vlans" => "cisco_ios_show_vlan.textfsm",
                "hsrp_detail" => "cisco_ios_show_standby.textfsm",
                "vrrp_detail" => "cisco_ios_show_vrrp_all.textfsm",
                "arp" | "arp_vrfs" => "cisco_ios_show_ip_arp.textfsm",
                "acls" => "cisco_ios_show_ip_access-lists.textfsm",
                other => panic!("no template is expected for {other}"),
            };
            assert_eq!(name, want, "{command}");
        }
    }

    #[test]
    fn the_table_of_each_line() {
        let text = "Codes: L - local\n       C - connected\n\nGateway of last resort is not set\n\nC  192.0.2.0/24 is directly connected, Gi1\n\nRouting Table: RED\nCodes: L - local\n\nC  192.0.2.0/24 is directly connected, Gi2\nCodes: L - local\nC  192.0.2.0/24 is directly connected, Gi3\nRouting Table:RED\nC  192.0.2.0/24 is directly connected, Gi4\n";
        let t = tables(text);
        let d = Some(DEFAULT_VRF.to_string());
        let red = Some("RED".to_string());
        assert_eq!(t[0], d);
        assert_eq!(t[5], d);
        assert_eq!(t[7], red);
        assert_eq!(t[10], red);
        assert_eq!(t[11], None, "a second table with no VRF header");
        assert_eq!(t[12], None);
        assert_eq!(t[14], None, "a VRF header of another form");
    }

    #[test]
    fn a_table_with_no_header_is_the_global_table() {
        let t = tables("S*  0.0.0.0/0 [1/0] via 192.0.2.1\nRouting Table: RED\n");
        assert_eq!(t[0].as_deref(), Some(DEFAULT_VRF));
        assert_eq!(t[1].as_deref(), Some("RED"));
    }
}
