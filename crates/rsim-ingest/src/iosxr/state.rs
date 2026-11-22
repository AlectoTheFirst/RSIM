//! The collected text sections of an IOS-XR router that the lowering reads,
//! each parsed by its TextFSM template: the interface state, the VRF
//! members, the route table, ARP, the LLDP and CDP neighbours and the HSRP
//! groups. Each row keeps the line range of its record in the section.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::OnceLock;

use rsim_core::{Mac, Prefix, SourceSpan};
use rsim_textfsm::{Field, Library, Traced};

use super::profile::{ARP_OWN, BACKUP_MARK, PLATFORM, STATE_ADMIN_DOWN, STATE_DOWN, STATE_UP};
use crate::links::Neighbour;
use crate::nxos::names::Names;
use crate::nxos::state::{mac, neighbour_name};

/// The sections that the lowering reads, each with the command that selects
/// its template in the index.
pub const SECTIONS: &[(&str, &str)] = &[
    ("interfaces", "show interfaces"),
    ("vrfs", "show vrf all detail"),
    ("rib", "show route vrf all ipv4"),
    ("arp", "show arp vrf all"),
    ("lldp", "show lldp neighbors detail"),
    ("cdp", "show cdp neighbors detail"),
    ("hsrp", "show hsrp"),
];

/// The state of an interface from `show interfaces`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfState {
    /// True if the interface and its line protocol are up, false if either
    /// is down, and `None` for another word.
    pub oper_up: Option<bool>,
    /// True if the interface state is `administratively down`.
    pub admin_down: bool,
    pub mac: Option<Mac>,
    /// The speed in Mbit/s and the duplex, if the record prints them.
    pub speed_mbps: Option<u64>,
    pub full_duplex: Option<bool>,
    pub span: SourceSpan,
}

/// An HSRP group of `show hsrp`, or an HSRP or VRRP group of a brief
/// form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HsrpRow {
    pub interface: String,
    pub group: u32,
    /// The state word as printed, for example `Active`.
    pub state: String,
    /// The group address: an IPv4 address, an IPv6 address, or `None` for
    /// another word.
    pub address: Option<IpAddr>,
    pub span: SourceSpan,
}

/// The members of a VRF from `show vrf all detail`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfMembers {
    pub vrf: String,
    pub interfaces: Vec<String>,
    pub span: SourceSpan,
}

/// One path of a route of `show route vrf all ipv4`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutePath {
    pub vrf: String,
    pub prefix: Prefix,
    /// The route code as printed, for example `O E2` or `S*`.
    pub protocol: String,
    /// The next hop, or `None` for a directly connected path.
    pub gateway: Option<IpAddr>,
    /// The egress interface, if the line has one.
    pub interface: Option<String>,
    /// The VRF of a next hop in another VRF, `(nexthop in vrf <name>)`.
    pub other_vrf: Option<String>,
    /// True for a backup path, marked `(!)`.
    pub backup: bool,
    pub span: SourceSpan,
}

/// A line of the route table section that the template did not read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnreadRoute {
    /// The VRF of the line, if a `VRF:` line came before it.
    pub vrf: Option<String>,
    /// The prefix of the route of the line: the prefix on the line, or for
    /// a path line, the prefix of the route line above it.
    pub prefix: Option<Prefix>,
    pub text: String,
    pub span: SourceSpan,
}

/// The route table section.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rib {
    pub paths: Vec<RoutePath>,
    pub unread: Vec<UnreadRoute>,
}

/// An ARP row with a MAC of a neighbour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArpRow {
    pub ip: IpAddr,
    pub mac: Mac,
    pub interface: String,
    pub span: SourceSpan,
}

/// A section that is not in the snapshot is `None`. A section that its
/// template cannot parse is an error with the reason.
pub type Section<T> = Option<Result<T, String>>;

/// The collected sections of a router.
#[derive(Clone, Debug, Default)]
pub struct State {
    pub interfaces: Section<BTreeMap<String, IfState>>,
    pub vrfs: Section<Vec<VrfMembers>>,
    pub rib: Section<Rib>,
    pub arp: Section<Vec<ArpRow>>,
    pub lldp: Section<Vec<Neighbour>>,
    pub cdp: Section<Vec<Neighbour>>,
    pub hsrp: Section<Vec<HsrpRow>>,
}

/// The templates that the crate carries.
pub(crate) fn library() -> Result<&'static Library, String> {
    static LIB: OnceLock<Result<Library, String>> = OnceLock::new();
    LIB.get_or_init(|| Library::builtin().map_err(|e| e.to_string()))
        .as_ref()
        .map_err(Clone::clone)
}

/// True for the time line that IOS-XR prints before each answer, for
/// example `Tue Nov 17 10:00:00.000 UTC`.
fn is_time_line(line: &str) -> bool {
    let w: Vec<&str> = line.split_whitespace().collect();
    matches!(
        w.first(),
        Some(&("Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun"))
    ) && w.len() >= 4
        && w[3].matches(':').count() == 2
}

/// The records of a section with the line ranges in the section.
pub(crate) struct Parsed {
    pub(crate) traced: Traced,
    /// The number of lines before the text that the template read.
    offset: usize,
    file: String,
}

impl Parsed {
    pub(crate) fn column(&self, name: &str) -> Option<usize> {
        self.traced.table.header.iter().position(|h| h == name)
    }

    pub(crate) fn text<'a>(&self, record: &'a [Field], name: &str) -> &'a str {
        self.column(name)
            .and_then(|i| record.get(i))
            .and_then(Field::as_text)
            .unwrap_or_default()
    }

    pub(crate) fn list(&self, record: &[Field], name: &str) -> Vec<String> {
        match self.column(name).and_then(|i| record.get(i)) {
            Some(Field::List(items)) => items
                .iter()
                .filter_map(|x| match x {
                    rsim_textfsm::Item::Text(t) => Some(t.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    pub(crate) fn span(&self, first: usize, last: usize) -> SourceSpan {
        let n = |x: usize| u32::try_from(x + self.offset).unwrap_or(u32::MAX);
        SourceSpan::new(&self.file, n(first), n(last.max(first)))
    }

    /// Moves the spans down by `lines` lines, for a text that starts below
    /// the first line of its section.
    pub(crate) fn shift(&mut self, lines: usize) {
        self.offset += lines;
    }

    /// Each record with its span.
    pub(crate) fn records(&self) -> impl Iterator<Item = (&[Field], SourceSpan)> {
        self.traced
            .table
            .records
            .iter()
            .zip(&self.traced.lines)
            .map(|(r, (a, b))| (r.as_slice(), self.span(*a, *b)))
    }
}

/// Parses a section with the template of its command. The time line before
/// the answer is removed first.
pub(crate) fn parse(command: &str, bytes: &[u8], file: &str) -> Result<Parsed, String> {
    parse_on(PLATFORM, command, bytes, file, is_time_line)
}

/// Parses a section with the template of a platform and a command. A first
/// line for which `skip` is true is removed first.
pub(crate) fn parse_on(
    platform: &str,
    command: &str,
    bytes: &[u8],
    file: &str,
    skip: fn(&str) -> bool,
) -> Result<Parsed, String> {
    let lib = library()?;
    let (name, template) = lib
        .find(platform, command)
        .ok_or_else(|| format!("no template for {command}"))?;
    let text = String::from_utf8_lossy(bytes);
    let mut lines = rsim_textfsm::split_lines(&text);
    let first = lines.next().unwrap_or_default();
    let (body, offset) = if skip(first) {
        let start = lines
            .next()
            .map_or(text.len(), |l| l.as_ptr() as usize - text.as_ptr() as usize);
        (&text[start..], 1)
    } else {
        (&text[..], 0)
    };
    let traced = template
        .parse_traced(body)
        .map_err(|e| format!("{name}: {e}"))?;
    Ok(Parsed {
        traced,
        offset,
        file: file.to_string(),
    })
}

/// The command of a section name.
fn command(section: &str) -> &'static str {
    SECTIONS
        .iter()
        .find(|(n, _)| *n == section)
        .map_or("", |(_, c)| c)
}

fn section<T>(
    sections: &BTreeMap<String, (Vec<u8>, String)>,
    name: &str,
    read: impl FnOnce(&Parsed) -> Result<T, String>,
) -> Section<T> {
    let (bytes, file) = sections.get(name)?;
    Some(parse(command(name), bytes, file).and_then(|p| read(&p)))
}

/// Reads the collected sections. `names` resolves the interface names of
/// the sections to the names of the config.
pub fn read(sections: &BTreeMap<String, (Vec<u8>, String)>, names: &Names) -> State {
    State {
        interfaces: section(sections, "interfaces", |p| Ok(interfaces(p, names))),
        vrfs: section(sections, "vrfs", |p| Ok(vrfs(p, names))),
        rib: section(sections, "rib", |p| Ok(rib(p, names))),
        arp: section(sections, "arp", |p| Ok(arp(p, names))),
        lldp: section(sections, "lldp", |p| Ok(lldp(p, names))),
        cdp: section(sections, "cdp", |p| Ok(cdp(p, names))),
        hsrp: section(sections, "hsrp", |p| hsrp(p, names)),
    }
}

/// The VRFs with a path or a line of the route table section, if the
/// section is in the snapshot and its template parses it.
pub fn rib_vrfs(sections: &BTreeMap<String, (Vec<u8>, String)>) -> BTreeSet<String> {
    match section(sections, "rib", |p| Ok(rib(p, &Names::default()))) {
        Some(Ok(r)) => vrfs_of(&r),
        _ => BTreeSet::new(),
    }
}

/// The VRFs with a path or a line of a route table.
pub(crate) fn vrfs_of(r: &Rib) -> BTreeSet<String> {
    r.paths
        .iter()
        .map(|p| p.vrf.clone())
        .chain(r.unread.iter().filter_map(|u| u.vrf.clone()))
        .collect()
}

fn interfaces(p: &Parsed, names: &Names) -> BTreeMap<String, IfState> {
    let mut out = BTreeMap::new();
    for (r, span) in p.records() {
        let link = p.text(r, "LINK_STATUS").trim();
        let protocol = p.text(r, "ADMIN_STATE").trim();
        let oper_up = match (link, protocol) {
            (STATE_UP, STATE_UP) => Some(true),
            (STATE_DOWN | STATE_ADMIN_DOWN, _) | (_, STATE_DOWN) => Some(false),
            _ => None,
        };
        out.insert(
            names.resolve(p.text(r, "INTERFACE")),
            IfState {
                oper_up,
                admin_down: link == STATE_ADMIN_DOWN,
                mac: mac(p.text(r, "MAC_ADDRESS")),
                speed_mbps: speed(p.text(r, "SPEED")),
                full_duplex: match p.text(r, "DUPLEX").trim().to_ascii_lowercase().as_str() {
                    "full" | "full-duplex" => Some(true),
                    "half" | "half-duplex" => Some(false),
                    _ => None,
                },
                span,
            },
        );
    }
    out
}

fn vrfs(p: &Parsed, names: &Names) -> Vec<VrfMembers> {
    p.records()
        .filter(|(r, _)| !p.text(r, "VRF").is_empty())
        .map(|(r, span)| VrfMembers {
            vrf: p.text(r, "VRF").to_string(),
            interfaces: p
                .list(r, "INTERFACES")
                .iter()
                .map(|i| names.resolve(i))
                .collect(),
            span,
        })
        .collect()
}

fn arp(p: &Parsed, names: &Names) -> Vec<ArpRow> {
    p.records()
        .filter(|(r, _)| p.text(r, "STATE") != ARP_OWN)
        .filter_map(|(r, span)| {
            Some(ArpRow {
                ip: p.text(r, "IP_ADDRESS").parse().ok()?,
                mac: mac(p.text(r, "MAC_ADDRESS"))?,
                interface: names.resolve(p.text(r, "INTERFACE")),
                span,
            })
        })
        .collect()
}

/// A speed of `show interfaces`, for example `1000Mb/s`, `10Gb/s` or
/// `1000Mbps`, in Mbit/s.
pub(crate) fn speed(s: &str) -> Option<u64> {
    let s = s.trim();
    let (n, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
    let n: u64 = n.parse().ok()?;
    match unit {
        "Kb/s" | "Kbps" => Some(n / 1000),
        "Mb/s" | "Mbps" => Some(n),
        "Gb/s" | "Gbps" => n.checked_mul(1000),
        _ => None,
    }
}

/// The LLDP neighbours. The port ID is the MAC of the far port if it has
/// the form of a MAC. The name is the field `NEIGHBOR`, else the field
/// `NEIGHBOR_NAME`.
pub(crate) fn lldp(p: &Parsed, names: &Names) -> Vec<Neighbour> {
    p.records()
        .filter(|(r, _)| !p.text(r, "LOCAL_INTERFACE").is_empty())
        .map(|(r, span)| {
            let remote = p.text(r, "NEIGHBOR_PORT_ID").trim();
            Neighbour {
                port: names.resolve(p.text(r, "LOCAL_INTERFACE")),
                name: neighbour_name(p.text(r, "NEIGHBOR"))
                    .or_else(|| neighbour_name(p.text(r, "NEIGHBOR_NAME"))),
                remote_port: (!remote.is_empty()).then(|| remote.to_string()),
                chassis: mac(p.text(r, "CHASSIS_ID")),
                port_mac: mac(remote),
                span,
            }
        })
        .collect()
}

/// The CDP neighbours. The name is the system name, else the device ID.
pub(crate) fn cdp(p: &Parsed, names: &Names) -> Vec<Neighbour> {
    p.records()
        .filter(|(r, _)| !p.text(r, "LOCAL_INTERFACE").trim().is_empty())
        .map(|(r, span)| {
            let remote = p.text(r, "NEIGHBOR_INTERFACE").trim();
            Neighbour {
                port: names.resolve(p.text(r, "LOCAL_INTERFACE").trim()),
                name: neighbour_name(p.text(r, "NEIGHBOR_NAME"))
                    .or_else(|| neighbour_name(p.text(r, "CHASSIS_ID"))),
                remote_port: (!remote.is_empty()).then(|| remote.to_string()),
                chassis: None,
                port_mac: mac(remote),
                span,
            }
        })
        .collect()
}

/// The HSRP or VRRP groups. The group address is the field `GROUP_ADDR`,
/// else the field `VIRTUAL_IP_ADDRESS`. A record with a group number that
/// is not a number makes the section unread.
pub(crate) fn hsrp(p: &Parsed, names: &Names) -> Result<Vec<HsrpRow>, String> {
    p.records()
        .map(|(r, span)| {
            let group = p.text(r, "GROUP");
            Ok(HsrpRow {
                interface: names.resolve(p.text(r, "INTERFACE")),
                group: group
                    .parse()
                    .map_err(|_| format!("group {group:?} not a number"))?,
                state: p.text(r, "STATE").to_string(),
                address: p
                    .text(r, "GROUP_ADDR")
                    .parse()
                    .or_else(|_| p.text(r, "VIRTUAL_IP_ADDRESS").parse())
                    .ok(),
                span,
            })
        })
        .collect()
}

/// The first IPv4 prefix among the first 3 words of a line.
pub(crate) fn prefix_on(line: &str) -> Option<Prefix> {
    line.split_whitespace().take(3).find_map(|w| {
        let (a, l) = w.split_once('/')?;
        a.parse::<std::net::Ipv4Addr>().ok()?;
        l.parse::<u8>().ok().filter(|l| *l <= 32)?;
        w.parse().ok()
    })
}

fn rib(p: &Parsed, names: &Names) -> Rib {
    let mut out = Rib::default();
    // The VRF and the prefix of the record that ends on each line.
    let mut ends: BTreeMap<usize, (Option<String>, Option<Prefix>)> = BTreeMap::new();
    for ((r, span), (_, last)) in p.records().zip(&p.traced.lines) {
        let vrf = p.text(r, "VRF");
        let prefix = format!("{}/{}", p.text(r, "NETWORK"), p.text(r, "PREFIX_LENGTH"))
            .parse::<Prefix>()
            .ok();
        let vrf = (!vrf.is_empty()).then(|| vrf.to_string());
        ends.insert(*last, (vrf.clone(), prefix));
        let hop = p.text(r, "NEXT_HOP");
        let gateway = hop.parse::<IpAddr>().ok();
        let (Some(vrf), Some(prefix)) = (vrf.clone(), prefix) else {
            out.unread.push(UnreadRoute {
                vrf,
                prefix,
                text: format!(
                    "{} {}/{} via {hop}",
                    p.text(r, "PROTOCOL"),
                    p.text(r, "NETWORK"),
                    p.text(r, "PREFIX_LENGTH")
                ),
                span,
            });
            continue;
        };
        if gateway.is_none() && hop != "connected" {
            out.unread.push(UnreadRoute {
                vrf: Some(vrf),
                prefix: Some(prefix),
                text: format!("{} {prefix} via {hop}", p.text(r, "PROTOCOL")),
                span,
            });
            continue;
        }
        let iface = p.text(r, "INTERFACE").trim();
        let (interface, other_vrf) = match iface.strip_prefix("vrf ") {
            Some(v) => (None, Some(v.trim().to_string())),
            None if iface.is_empty() => (None, None),
            None => (Some(names.resolve(iface)), None),
        };
        out.paths.push(RoutePath {
            vrf,
            prefix,
            protocol: p.text(r, "PROTOCOL").to_string(),
            gateway,
            interface,
            other_vrf,
            backup: p.text(r, "BACKUP") == BACKUP_MARK,
            span,
        });
    }
    let vrf_col = p.column("VRF");
    let unread_lines: BTreeSet<usize> = p.traced.unread.iter().map(|u| u.line).collect();
    // The VRF and the prefix of each unread line, in the order of the input,
    // so a path line takes the prefix of the unread route line above it.
    let mut found: BTreeMap<usize, (Option<String>, Option<Prefix>)> = BTreeMap::new();
    for u in &p.traced.unread {
        let vrf = vrf_col
            .and_then(|i| u.values.get(i))
            .filter(|v| !v.is_empty())
            .cloned();
        let prefix = prefix_on(&u.text).or_else(|| {
            if !u.text.starts_with(char::is_whitespace) || u.line < 2 {
                return None;
            }
            let above = u.line - 1;
            if unread_lines.contains(&above) {
                found.get(&above).and_then(|x| x.1)
            } else {
                ends.get(&above).and_then(|x| x.1)
            }
        });
        found.insert(u.line, (vrf.clone(), prefix));
        out.unread.push(UnreadRoute {
            vrf,
            prefix,
            text: u.text.trim().to_string(),
            span: p.span(u.line, u.line),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_index_gives_a_template_to_each_command() {
        let lib = library().unwrap();
        for (section, command) in SECTIONS {
            let (name, _) = lib.find(PLATFORM, command).unwrap();
            let want = match *section {
                "interfaces" => "cisco_xr_show_interfaces.textfsm",
                "vrfs" => "cisco_xr_show_vrf_all_detail.textfsm",
                "rib" => "cisco_xr_show_ip_route.textfsm",
                "arp" => "cisco_xr_show_arp.textfsm",
                "lldp" => "cisco_xr_show_lldp_neighbors_detail.textfsm",
                "cdp" => "cisco_xr_show_cdp_neighbors_detail.textfsm",
                _ => "cisco_xr_show_hsrp.textfsm",
            };
            assert_eq!(name, want, "{command}");
        }
    }

    #[test]
    fn a_speed_in_mbit() {
        assert_eq!(speed("1000Mb/s"), Some(1000));
        assert_eq!(speed("10Gb/s"), Some(10_000));
        assert_eq!(speed("fast"), None);
    }

    #[test]
    fn a_record_span_serves_its_own_lines_with_a_form_feed_and_a_lone_cr() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/iosxr/arp.txt"
        ))
        .unwrap();
        let text = text
            .replacen("UTC\n", "UTC\x0c", 1)
            .replacen("\n0/0/CPU0\n", "\r0/0/CPU0\n", 1)
            .replacen("\n\n", "\n\x0c", 1);
        assert_eq!(text.matches('\x0c').count(), 2);
        assert_eq!(text.matches('\r').count(), 1);
        let p = parse(command("arp"), text.as_bytes(), "r1/arp@x").unwrap();
        let served =
            crate::mask::section_lines("iosxr", "arp", rsim_store::Format::Text, text.as_bytes())
                .unwrap();
        let records: Vec<_> = p.records().collect();
        assert!(records.len() > 10);
        for (r, span) in &records {
            let (a, b) = (span.first_line as usize, span.last_line as usize);
            assert!(b <= served.len(), "{a}-{b} past {}", served.len());
            let got = &served[a - 1..b];
            assert_eq!(got.len(), 1, "{a}-{b}");
            assert!(
                got[0].starts_with(&format!("{} ", p.text(r, "IP_ADDRESS"))),
                "{a}: {got:?}"
            );
        }
        let (r, span) = records.last().unwrap();
        assert_eq!(p.text(r, "IP_ADDRESS"), "203.0.113.254");
        assert_eq!(span.last_line as usize, served.len());
    }

    #[test]
    fn the_time_line() {
        assert!(is_time_line("Tue Nov 17 10:00:00.000 UTC"));
        assert!(!is_time_line("VRF: default"));
        assert!(!is_time_line("Tue is a day"));
    }
}
