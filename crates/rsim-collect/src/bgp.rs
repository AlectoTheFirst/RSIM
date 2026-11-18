//! The BGP sections of a router: the setting of each device, the sections
//! that combine the answers of several commands, and the neighbours whose
//! tables a fetch reads.
//!
//! With [`CaptureBgp::Sessions`], a source reads the summary of each BGP
//! session: the state and the prefix counts. With [`CaptureBgp::All`], it
//! also reads the neighbour detail and the 3 tables of each IPv4 unicast
//! neighbour of the session answers of the same cycle. A listen range is
//! never a neighbour of a command; a dynamic peer that a session answer
//! lists is.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use serde_json::Value;

use crate::cli::CliRules;
use crate::{BoxFuture, RawSection, SectionSpec, Timeouts, TransportError, fetch_sections};

/// What the collector reads of the BGP of a router.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CaptureBgp {
    /// No BGP section.
    Off,
    /// The summary of each session.
    #[default]
    Sessions,
    /// The summaries, the neighbour detail and the tables of each neighbour.
    All,
}

impl CaptureBgp {
    /// The setting of a word: `off`, `sessions` or `all`.
    pub fn parse(word: &str) -> Option<CaptureBgp> {
        match word {
            "off" => Some(CaptureBgp::Off),
            "sessions" => Some(CaptureBgp::Sessions),
            "all" => Some(CaptureBgp::All),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            CaptureBgp::Off => "off",
            CaptureBgp::Sessions => "sessions",
            CaptureBgp::All => "all",
        }
    }

    /// True if the source reads the session sections.
    pub fn sessions(self) -> bool {
        self != CaptureBgp::Off
    }

    /// True if the source reads the neighbour detail and the tables.
    pub fn all(self) -> bool {
        self == CaptureBgp::All
    }
}

/// The setting of each device of a source. A device with no setting reads
/// the sessions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BgpCaptures(BTreeMap<String, CaptureBgp>);

impl BgpCaptures {
    pub fn set(&mut self, device: &str, capture: CaptureBgp) {
        self.0.insert(device.to_string(), capture);
    }

    pub fn of(&self, device: &str) -> CaptureBgp {
        self.0.get(device).copied().unwrap_or_default()
    }
}

/// The section of the summary of each session.
pub const SESSIONS: &str = "bgp_sessions";
/// The section of the neighbour detail.
pub const NEIGHBORS: &str = "bgp_neighbors";
/// The section of the 3 tables of each neighbour.
pub const ROUTES: &str = "bgp_routes";

/// The 3 tables of a neighbour, by the names of the combined sections: the
/// received table before the inbound policy, the accepted table and the
/// advertised table.
pub const DIRECTIONS: [&str; 3] = ["received-routes", "routes", "advertised-routes"];

/// The VRF of the global table.
pub const DEFAULT_VRF: &str = "default";

/// The line before the answer of each VRF in a combined text section of the
/// VRFs: `VRF: <name>`, or `VRF: <name> failed` for a failed command.
pub const VRF_LINE: &str = "VRF: ";
/// The line before the answer of each table of a neighbour in a combined
/// text section: `NEIGHBOR: <vrf> <address> <direction>`, or the same line
/// with ` failed` for a failed command.
pub const NEIGHBOR_LINE: &str = "NEIGHBOR: ";
/// The word after the head of a part whose command failed.
pub const FAILED: &str = "failed";

/// A neighbour whose tables a fetch reads.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Peer {
    pub vrf: String,
    pub address: Ipv4Addr,
}

/// One command of a combined section, with the head of its answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Part {
    pub head: String,
    pub command: String,
}

/// The parts of the tables of the neighbours: for each neighbour in order,
/// the 3 directions. `command` gives the command of a VRF, an address and
/// the index of a direction in [`DIRECTIONS`].
pub(crate) fn route_parts(
    peers: &BTreeSet<Peer>,
    command: impl Fn(&str, Ipv4Addr, usize) -> String,
) -> Vec<Part> {
    peers
        .iter()
        .flat_map(|p| {
            DIRECTIONS.iter().enumerate().map(|(i, d)| Part {
                head: format!("{} {} {d}", p.vrf, p.address),
                command: command(&p.vrf, p.address, i),
            })
        })
        .collect()
}

/// Reads the commands of the parts, with the class, the format and the
/// volatile parts of `spec`.
pub(crate) async fn fetch_parts<'a, F>(
    spec: &SectionSpec,
    parts: &[Part],
    timeouts: Timeouts,
    serial: bool,
    read: F,
) -> Vec<RawSection>
where
    F: Fn(String) -> BoxFuture<'a, Result<Vec<u8>, TransportError>>,
{
    let specs = parts
        .iter()
        .map(|p| SectionSpec {
            command: p.command.clone(),
            ..spec.clone()
        })
        .collect();
    fetch_sections(specs, timeouts, serial, read).await
}

/// True for the error of a device that cannot be reached.
fn unreachable(e: &TransportError) -> bool {
    matches!(e, TransportError::Connect(_) | TransportError::Timeout)
}

/// The result of a combined section. `parts` is the list of parts, or the
/// error of the section that names them; `what` names that section in the
/// error. A device that cannot be reached gives the error of the
/// connection, so the section keeps its last blob: when the section of the
/// parts fails in this way, and when each part fails in this way. Another
/// failure of the section of the parts makes the section absent.
pub(crate) fn combined(
    parts: Result<&[Part], &TransportError>,
    what: &str,
    answers: &[RawSection],
    combine: impl FnOnce(&[Part], &[RawSection]) -> Vec<u8>,
) -> Result<Vec<u8>, TransportError> {
    match parts {
        Err(e) if unreachable(e) => Err(e.clone()),
        Err(e) => Err(TransportError::NotFound(format!("{what} failed: {e}"))),
        Ok(parts) => match answers.first().map(|a| &a.result) {
            Some(Err(e))
                if answers
                    .iter()
                    .all(|a| a.result.as_ref().is_err_and(unreachable)) =>
            {
                Err(e.clone())
            }
            _ => Ok(combine(parts, answers)),
        },
    }
}

/// The answers as one text: for each part, the line `<line><head>` and its
/// answer, or the line `<line><head> failed`.
pub(crate) fn combine_text(line: &str, parts: &[Part], answers: &[RawSection]) -> Vec<u8> {
    let mut out = Vec::new();
    for (part, a) in parts.iter().zip(answers) {
        match &a.result {
            Ok(bytes) => {
                out.extend_from_slice(format!("{line}{}\n", part.head).as_bytes());
                out.extend_from_slice(bytes);
                if !bytes.is_empty() && !bytes.ends_with(b"\n") {
                    out.push(b'\n');
                }
            }
            Err(_) => out.extend_from_slice(format!("{line}{} {FAILED}\n", part.head).as_bytes()),
        }
    }
    out
}

/// The tables of the neighbours as one JSON object: VRF, then address, then
/// direction. Each direction is `{"answer": <answer>}`, with an answer that
/// is not JSON as a string, or `{"failed": <error>}`.
pub(crate) fn combine_json(peers: &BTreeSet<Peer>, answers: &[RawSection]) -> Vec<u8> {
    let mut top = serde_json::Map::new();
    let mut answers = answers.iter();
    for p in peers {
        let vrf = top
            .entry(p.vrf.clone())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        let mut tables = serde_json::Map::new();
        for d in DIRECTIONS {
            let Some(a) = answers.next() else { break };
            let v = match &a.result {
                Ok(bytes) => {
                    let answer = serde_json::from_slice::<Value>(bytes).unwrap_or_else(|_| {
                        Value::String(String::from_utf8_lossy(bytes).into_owned())
                    });
                    serde_json::json!({ "answer": answer })
                }
                Err(e) => serde_json::json!({ "failed": e.to_string() }),
            };
            tables.insert(d.to_string(), v);
        }
        if let Value::Object(m) = vrf {
            m.insert(p.address.to_string(), Value::Object(tables));
        }
    }
    Value::Object(top).to_string().into_bytes()
}

/// The commands of a section that come from the answers of the sections
/// before it: the parts or the error of the section that names them, the
/// name of that section for the error, and the line before each answer in
/// the combined text.
pub(crate) struct Plan {
    pub parts: Result<Vec<Part>, TransportError>,
    pub what: &'static str,
    pub line: &'static str,
}

/// Reads the text sections of a Cisco device. The sections named in
/// `derived` come last, in the order of `specs`; `plan` gives the commands
/// of each from the sections before it, after the rules. The rules apply
/// to each answer on its own, so that a rejection fails one part and the
/// banner is the head of all answers.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_text<'a, F>(
    specs: Vec<SectionSpec>,
    derived: &[&str],
    rules: &CliRules,
    banner_each: bool,
    timeouts: Timeouts,
    serial: bool,
    read: F,
    plan: impl Fn(&SectionSpec, &[RawSection]) -> Plan,
) -> Vec<RawSection>
where
    F: Fn(String) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> + Copy,
{
    let (fixed, later): (Vec<SectionSpec>, Vec<SectionSpec>) =
        specs.into_iter().partition(|s| !derived.contains(&s.name));
    let mut out = fetch_sections(fixed, timeouts, serial, read).await;
    let mut view = out.clone();
    rules.apply(&mut view, false);
    let mut pending = Vec::new();
    for spec in later {
        let p = plan(&spec, &view);
        let answers = match &p.parts {
            Ok(parts) => fetch_parts(&spec, parts, timeouts, serial, read).await,
            Err(_) => Vec::new(),
        };
        let mut seen = answers.clone();
        rules.apply(&mut seen, false);
        let result = combined(p.parts.as_deref(), p.what, &seen, |parts, a| {
            combine_text(p.line, parts, a)
        });
        view.push(RawSection {
            spec: spec.clone(),
            result,
        });
        pending.push((spec, p, answers));
    }
    let fixed_len = out.len();
    let lens: Vec<usize> = pending.iter().map(|(_, _, a)| a.len()).collect();
    for (_, _, answers) in &mut pending {
        out.append(answers);
    }
    rules.apply(&mut out, banner_each);
    let mut answers = out.split_off(fixed_len);
    for ((spec, p, _), len) in pending.into_iter().zip(lens) {
        let rest = answers.split_off(len);
        let result = combined(p.parts.as_deref(), p.what, &answers, |parts, a| {
            combine_text(p.line, parts, a)
        });
        answers = rest;
        out.push(RawSection { spec, result });
    }
    out
}

/// The text of a section of `sections` after the rules. A section that is
/// not there gives [`TransportError::NotFound`].
pub(crate) fn text_of(sections: &[RawSection], name: &str) -> Result<String, TransportError> {
    let s = sections
        .iter()
        .find(|s| s.spec.name == name)
        .ok_or_else(|| TransportError::NotFound(format!("the section {name} is not read")))?;
    s.result
        .as_ref()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .map_err(Clone::clone)
}

/// The parts of the session summaries of the VRFs of the running config:
/// `vrfs` reads the names from the config and `command` gives the command
/// of a VRF.
pub(crate) fn vrf_session_plan(
    view: &[RawSection],
    vrfs: impl Fn(&str) -> Vec<String>,
    command: impl Fn(&str) -> String,
) -> Plan {
    Plan {
        parts: text_of(view, "config").map(|config| {
            vrfs(&config)
                .into_iter()
                .map(|n| Part {
                    command: command(&n),
                    head: n,
                })
                .collect()
        }),
        what: "the running config",
        line: VRF_LINE,
    }
}

/// The parts of the tables of the IPv4 neighbours of the text summaries of
/// the global table, [`SESSIONS`], and of the VRFs, `vrf_sessions`.
pub(crate) fn text_route_plan(
    view: &[RawSection],
    vrf_sessions: &str,
    command: impl Fn(&str, Ipv4Addr, usize) -> String,
) -> Plan {
    Plan {
        parts: text_of(view, SESSIONS).map(|global| {
            let mut peers = BTreeSet::new();
            text_peers(&global, DEFAULT_VRF, &mut peers);
            if let Ok(vrfs) = text_of(view, vrf_sessions) {
                vrf_text_peers(&vrfs, &mut peers);
            }
            route_parts(&peers, command)
        }),
        what: "the session summary",
        line: NEIGHBOR_LINE,
    }
}

/// The IPv4 neighbours of a text summary: the first word of each line that
/// is an IPv4 address, after the mark `*` of a dynamic peer.
pub(crate) fn text_peers(text: &str, vrf: &str, out: &mut BTreeSet<Peer>) {
    for line in text.lines() {
        let Some(first) = line.split_whitespace().next() else {
            continue;
        };
        if let Ok(address) = first.trim_start_matches('*').parse::<Ipv4Addr>() {
            out.insert(Peer {
                vrf: vrf.to_string(),
                address,
            });
        }
    }
}

/// The IPv4 neighbours of the parts of a combined text section of the VRFs:
/// each line `VRF: <name>` starts the answer of a VRF.
pub(crate) fn vrf_text_peers(text: &str, out: &mut BTreeSet<Peer>) {
    let mut vrf: Option<&str> = None;
    for line in text.lines() {
        if let Some(head) = line.strip_prefix(VRF_LINE) {
            let head = head.trim();
            vrf = (!head.ends_with(&format!(" {FAILED}"))).then_some(head);
            continue;
        }
        if let Some(v) = vrf {
            text_peers(line, v, out);
        }
    }
}

/// The names of the VRFs of the BGP process in a Cisco running config: the
/// lines of the `router bgp` block, one level in, for which `vrf` gives a
/// name. The block ends at the next line with no indentation.
pub(crate) fn config_bgp_vrfs(config: &str, vrf: impl Fn(&str) -> Option<&str>) -> Vec<String> {
    let mut out = BTreeSet::new();
    let mut inside = false;
    for line in config.lines() {
        if !line.starts_with(' ') {
            inside = line.trim_end().starts_with("router bgp ");
            continue;
        }
        if inside
            && let Some(name) = vrf(line)
            && name.bytes().all(|b| b.is_ascii_graphic())
        {
            out.insert(name.to_string());
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_settings_read_and_the_default_reads_the_sessions() {
        assert_eq!(CaptureBgp::parse("all"), Some(CaptureBgp::All));
        assert_eq!(CaptureBgp::parse("off"), Some(CaptureBgp::Off));
        assert_eq!(CaptureBgp::parse("none"), None);
        let mut c = BgpCaptures::default();
        c.set("r1", CaptureBgp::All);
        assert_eq!(c.of("r1"), CaptureBgp::All);
        assert_eq!(c.of("r2"), CaptureBgp::Sessions);
    }

    #[test]
    fn the_peers_of_a_summary_skip_the_headers_and_keep_a_dynamic_peer() {
        let text = "BGP router identifier 192.0.2.1, local AS number 64500\n\
                    Neighbor        V    AS MsgRcvd\n\
                    192.0.2.2       4 64501     10\n\
                    *198.51.100.7   4 64502     11\n\
                    2001:db8::1     4 64503      1\n";
        let mut peers = BTreeSet::new();
        text_peers(text, "default", &mut peers);
        let got: Vec<String> = peers.iter().map(|p| p.address.to_string()).collect();
        assert_eq!(got, ["192.0.2.2", "198.51.100.7"]);
        let mut peers = BTreeSet::new();
        vrf_text_peers(
            "VRF: BLUE failed\nVRF: RED\n203.0.113.9 4 64504 1\n",
            &mut peers,
        );
        assert_eq!(
            peers.into_iter().collect::<Vec<_>>(),
            [Peer {
                vrf: "RED".into(),
                address: "203.0.113.9".parse().unwrap()
            }]
        );
    }

    #[test]
    fn the_vrfs_of_the_bgp_block_in_name_order() {
        let config = "vrf definition RED\n!\nrouter bgp 64500\n bgp log-neighbor-changes\n \
                      address-family ipv4 vrf RED\n  neighbor 192.0.2.2 activate\n \
                      exit-address-family\n address-family ipv4 vrf BLUE\n \
                      address-family ipv6 vrf GREEN\n!\nrouter ospf 1\n address-family ipv4 vrf X\n";
        let vrfs = config_bgp_vrfs(config, |l| {
            l.trim().strip_prefix("address-family ipv4 vrf ")
        });
        assert_eq!(vrfs, ["BLUE", "RED"]);
    }
}
