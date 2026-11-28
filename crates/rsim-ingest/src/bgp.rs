//! The BGP sessions of a router from its collected session sections, with
//! the outcome of the read and its scope: the pairs of a VRF and an address
//! family that the read covers. A neighbour outside the scope of a read is not
//! known to be absent.
//!
//! An answer with lines in the shape of session rows of which none is read
//! is `Failed`, and an answer with some such lines not read is `Partial`; a
//! misread answer is never `Complete` or `CompleteEmpty`. A section that the
//! setting of the collector does not read, or that the device does not
//! have, is `NotCaptured`, never an empty table. A section whose last read
//! failed is `Failed`, also when the store keeps an older blob.
//!
//! The session sections of the Cisco vendors are not confirmed on a device,
//! and the VyOS summary is confirmed on one router with one eBGP neighbour
//! in IPv4 unicast in the default VRF.

use std::collections::BTreeSet;
use std::net::IpAddr;

use rsim_core::SourceSpan;
use rsim_store::{SectionEntry, SectionStatus};

use crate::iosxr::state::parse_on;
use crate::stanza::{Body, Stanza, read_json};

/// The outcome of the read of a session section.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// Each row of the answer is read, and the answer has a row.
    Complete,
    /// The answer is read and states that it has no row.
    CompleteEmpty,
    /// Some rows or some parts of the answer are not read.
    Partial,
    /// The answer is not read, or the last read failed.
    Failed,
    /// The collector does not read the section, or the device does not
    /// have it.
    NotCaptured,
}

impl Outcome {
    /// The name of the outcome: `complete`, `complete-empty`, `partial`,
    /// `failed` or `not-captured`.
    pub fn name(self) -> &'static str {
        match self {
            Outcome::Complete => "complete",
            Outcome::CompleteEmpty => "complete-empty",
            Outcome::Partial => "partial",
            Outcome::Failed => "failed",
            Outcome::NotCaptured => "not-captured",
        }
    }
}

/// The pairs of a VRF and an address family that a read covers: the listed
/// pairs only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scope(pub BTreeSet<(String, String)>);

impl Scope {
    /// IPv4 unicast in each of the VRFs.
    fn ipv4_unicast(vrfs: impl IntoIterator<Item = String>) -> Scope {
        Scope(
            vrfs.into_iter()
                .map(|v| (v, IPV4_UNICAST.to_string()))
                .collect(),
        )
    }

    fn none() -> Scope {
        Scope::default()
    }

    /// True if the scope holds the address family in the VRF.
    pub fn covers(&self, vrf: &str, family: &str) -> bool {
        self.0.contains(&(vrf.to_string(), family.to_string()))
    }

    /// The VRFs of the pairs.
    pub fn vrfs(&self) -> BTreeSet<&str> {
        self.0.iter().map(|(v, _)| v.as_str()).collect()
    }
}

/// The outcome of a session section with its scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionOutcome {
    pub outcome: Outcome,
    pub scope: Scope,
    /// The reason of an outcome other than `Complete`, or the lines that
    /// are not read.
    pub detail: Option<String>,
}

impl SectionOutcome {
    fn new(outcome: Outcome, detail: impl Into<String>) -> SectionOutcome {
        SectionOutcome {
            outcome,
            scope: Scope::none(),
            detail: Some(detail.into()),
        }
    }
}

/// The address family of IPv4 unicast.
pub const IPV4_UNICAST: &str = "ipv4-unicast";

/// One BGP session as the device states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRow {
    pub vrf: String,
    pub peer: IpAddr,
    /// The address family, where the section states it.
    pub family: Option<String>,
    /// The AS of the neighbour as the device prints it, for example `64501`
    /// or `1.10`.
    pub peer_asn: Option<String>,
    /// The state word of the device, `Established` for a session whose row
    /// gives a prefix count in place of a state word.
    pub state: String,
    pub established: bool,
    pub prefixes_received: Option<u64>,
    pub prefixes_sent: Option<u64>,
    pub span: SourceSpan,
}

/// The sessions of a router and the outcome of their read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sessions {
    pub rows: Vec<SessionRow>,
    pub outcome: SectionOutcome,
}

impl Sessions {
    fn none(outcome: SectionOutcome) -> Sessions {
        Sessions {
            rows: Vec::new(),
            outcome,
        }
    }
}

/// A collected section as the readers see it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer<'a> {
    /// The snapshot has no such section.
    NotCollected,
    /// The device does not have the command, with the reason.
    Absent(&'a str),
    /// The last read failed, with the error.
    Failed(&'a str),
    /// The bytes of the read and the file name of the spans.
    Fresh(&'a [u8], &'a str),
}

impl<'a> Answer<'a> {
    /// The answer of a manifest entry and its blob. A section that is `Old`
    /// is a failed read: its blob is not the state of the snapshot.
    pub fn of(
        entry: Option<&'a SectionEntry>,
        bytes: Option<&'a [u8]>,
        file: &'a str,
    ) -> Answer<'a> {
        let Some(e) = entry else {
            return Answer::NotCollected;
        };
        match (&e.status, bytes) {
            (SectionStatus::Absent { reason }, _) => Answer::Absent(reason),
            (SectionStatus::Old { error } | SectionStatus::Missing { error }, _) => {
                Answer::Failed(error)
            }
            (SectionStatus::Fresh, Some(b)) => Answer::Fresh(b, file),
            (SectionStatus::Fresh, None) => Answer::Failed("blob not read"),
        }
    }
}

/// The section of the sessions of each vendor.
pub const SESSIONS: &str = "bgp_sessions";
/// The NX-OS section of the sessions of the global table, for a switch that
/// refuses the form of all VRFs.
pub const NXOS_SESSIONS_DEFAULT: &str = "bgp_sessions_default";
/// The IOS-XR and IOS-XE section of the summaries of the VRFs.
pub const VRF_SESSIONS: &str = "bgp_vrf_sessions";

/// The session sections that a vendor reads, the section of the tables of
/// its neighbours and the sections of the neighbour detail.
pub fn sections(vendor: &str) -> &'static [&'static str] {
    use crate::bgp_neighbors::{NEIGHBORS, VRF_NEIGHBORS};
    use crate::bgp_routes::ROUTES;
    match vendor {
        "vyos" => &[SESSIONS, ROUTES],
        "nxos" => &[SESSIONS, NXOS_SESSIONS_DEFAULT, ROUTES],
        "iosxr" => &[SESSIONS, VRF_SESSIONS, ROUTES, NEIGHBORS, VRF_NEIGHBORS],
        "iosxe" => &[SESSIONS, VRF_SESSIONS, ROUTES, NEIGHBORS],
        _ => &[],
    }
}

/// A collected session section that the snapshot has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Collected {
    /// The device does not have the command, with the reason.
    Absent(String),
    /// The last read failed, with the error.
    Failed(String),
    /// The bytes of the read and the file name of the spans.
    Fresh(Vec<u8>, String),
}

impl Collected {
    /// The section of a manifest entry and its blob, as [`Answer::of`]
    /// reads it.
    pub fn of(entry: &SectionEntry, bytes: Option<Vec<u8>>, file: String) -> Collected {
        match Answer::of(Some(entry), bytes.as_deref(), &file) {
            Answer::Absent(r) => Collected::Absent(r.to_string()),
            Answer::Failed(e) => Collected::Failed(e.to_string()),
            Answer::Fresh(..) => Collected::Fresh(bytes.unwrap_or_default(), file),
            Answer::NotCollected => unreachable!("the entry is given"),
        }
    }

    pub(crate) fn answer(&self) -> Answer<'_> {
        match self {
            Collected::Absent(r) => Answer::Absent(r),
            Collected::Failed(e) => Answer::Failed(e),
            Collected::Fresh(b, f) => Answer::Fresh(b, f),
        }
    }
}

/// The session sections of a device by name.
pub type SessionSections = std::collections::BTreeMap<String, Collected>;

/// The sessions of a device of a vendor from its session sections. A
/// section that the device does not have in the snapshot is not collected.
pub fn read(vendor: &str, s: &SessionSections) -> Sessions {
    let a = |name: &str| s.get(name).map_or(Answer::NotCollected, Collected::answer);
    match vendor {
        "vyos" => vyos(a(SESSIONS)),
        "nxos" => nxos(a(SESSIONS), a(NXOS_SESSIONS_DEFAULT)),
        "iosxr" => iosxr(a(SESSIONS), a(VRF_SESSIONS)),
        "iosxe" => iosxe(a(SESSIONS), a(VRF_SESSIONS)),
        _ => Sessions::none(not_fresh(Answer::NotCollected).expect("not fresh")),
    }
}

/// The outcome of an answer that is not fresh.
fn not_fresh(a: Answer<'_>) -> Option<SectionOutcome> {
    match a {
        Answer::NotCollected => Some(SectionOutcome::new(
            Outcome::NotCaptured,
            "section not collected",
        )),
        Answer::Absent(r) => Some(SectionOutcome::new(
            Outcome::NotCaptured,
            format!("command not on the device: {r}"),
        )),
        Answer::Failed(e) => Some(SectionOutcome::new(
            Outcome::Failed,
            format!("read failed: {e}"),
        )),
        Answer::Fresh(..) => None,
    }
}

/// The outcome of the rows and of the row-shaped parts that are not read.
fn rows_outcome(rows: usize, unread: &[String]) -> (Outcome, Option<String>) {
    let detail = (!unread.is_empty()).then(|| format!("not read: {}", unread.join(", ")));
    match (rows, unread.is_empty()) {
        (0, true) => (Outcome::CompleteEmpty, None),
        (_, true) => (Outcome::Complete, None),
        (0, false) => (Outcome::Failed, detail),
        (_, false) => (Outcome::Partial, detail),
    }
}

fn span(file: &str, s: &Stanza) -> SourceSpan {
    SourceSpan::new(file, s.first_line, s.last_line.max(s.first_line))
}

fn scalar<'s>(s: &'s Stanza, key: &str) -> Option<&'s str> {
    s.get(key).and_then(Stanza::text).filter(|t| *t != "null")
}

// VyOS: FRR `show bgp vrf all summary json`.

/// The address family keys of an FRR summary and the names of the families.
const FRR_FAMILIES: &[(&str, &str)] = &[
    ("ipv4Unicast", IPV4_UNICAST),
    ("ipv6Unicast", "ipv6-unicast"),
    ("ipv4Multicast", "ipv4-multicast"),
    ("ipv6Multicast", "ipv6-multicast"),
    ("ipv4LabeledUnicast", "ipv4-labeled-unicast"),
    ("ipv6LabeledUnicast", "ipv6-labeled-unicast"),
    ("ipv4Vpn", "ipv4-vpn"),
    ("ipv6Vpn", "ipv6-vpn"),
    ("ipv4Flowspec", "ipv4-flowspec"),
    ("ipv6Flowspec", "ipv6-flowspec"),
    ("l2VpnEvpn", "l2vpn-evpn"),
];

/// The session state of FRR.
const FRR_ESTABLISHED: &str = "Established";

/// The sessions of a VyOS router: each peer of each address family key of
/// each VRF. The scope is each pair of a VRF and an address family that the
/// answer lists with its peers, because the listing of a named VRF and of a family other than
/// IPv4 unicast is not confirmed. An empty answer `{}` has no session. A
/// member that is not a known address family of a VRF is not read.
pub fn vyos(answer: Answer<'_>) -> Sessions {
    if let Some(o) = not_fresh(answer) {
        return Sessions::none(o);
    }
    let Answer::Fresh(bytes, file) = answer else {
        unreachable!("not_fresh gives the other answers")
    };
    let doc = match read_json(bytes) {
        Ok(d) => d,
        Err(e) => {
            return Sessions::none(SectionOutcome::new(
                Outcome::Failed,
                format!("answer not JSON: {e}"),
            ));
        }
    };
    let Body::Object(top) = &doc.root.body else {
        return Sessions::none(SectionOutcome::new(
            Outcome::Failed,
            "answer not a JSON object",
        ));
    };
    let flat = top.iter().any(|s| family(&s.key).is_some());
    let vrfs: Vec<(&str, &Stanza)> = if flat {
        vec![("default", &doc.root)]
    } else {
        top.iter().map(|s| (s.key.as_str(), s)).collect()
    };
    let (mut rows, mut unread) = (Vec::new(), Vec::new());
    let mut scope = BTreeSet::new();
    for (vrf, v) in vrfs {
        let Body::Object(members) = &v.body else {
            unread.push(format!("VRF {vrf} not an object"));
            continue;
        };
        for m in members {
            let Some(fam) = family(&m.key) else {
                if !flat && matches!(m.body, Body::Object(_)) {
                    unread.push(format!("VRF {vrf} member {}", m.key));
                }
                continue;
            };
            let Some(peers) = m.get("peers") else {
                unread.push(format!("VRF {vrf} {fam} with no peers"));
                continue;
            };
            scope.insert((vrf.to_string(), fam.to_string()));
            for p in peers.children() {
                match frr_row(vrf, fam, p, file) {
                    Some(r) => rows.push(r),
                    None => unread.push(format!("VRF {vrf} {fam} peer {}", p.key)),
                }
            }
        }
    }
    let (outcome, detail) = rows_outcome(rows.len(), &unread);
    Sessions {
        rows,
        outcome: SectionOutcome {
            outcome,
            scope: Scope(scope),
            detail,
        },
    }
}

fn family(key: &str) -> Option<&'static str> {
    FRR_FAMILIES
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, f)| *f)
}

fn frr_row(vrf: &str, fam: &str, p: &Stanza, file: &str) -> Option<SessionRow> {
    let peer: IpAddr = p.key.parse().ok()?;
    let state = scalar(p, "state")?.to_string();
    let count = |k| scalar(p, k).and_then(|x| x.parse().ok());
    Some(SessionRow {
        vrf: vrf.to_string(),
        peer,
        family: Some(fam.to_string()),
        peer_asn: scalar(p, "remoteAs").map(str::to_string),
        established: state == FRR_ESTABLISHED,
        state,
        prefixes_received: count("pfxRcd"),
        prefixes_sent: count("pfxSnt"),
        span: span(file, p),
    })
}

// NX-OS: `show bgp sessions vrf all | json` and `show bgp sessions | json`.

/// The session state of NX-OS.
const NXOS_ESTABLISHED: &str = "Established";

/// The sessions of an NX-OS switch from the sessions of all VRFs, or from
/// the sessions of the global table when the switch refuses the form of all
/// VRFs. The answer gives no address family, and whether it lists the IPv6
/// and EVPN neighbours is not confirmed, so the scope is IPv4 unicast in
/// each VRF row with a table of neighbours, and only in `default` for the
/// global table. An answer with VRF rows and no table of neighbours is
/// `Failed`. An empty answer `{}` has no session and an empty scope.
pub fn nxos(all: Answer<'_>, default: Answer<'_>) -> Sessions {
    let (answer, global) = match (all, default) {
        (Answer::Fresh(..), _) => (all, false),
        (Answer::Absent(_), Answer::Fresh(..)) => (default, true),
        (Answer::Absent(_), Answer::Failed(_)) => (default, true),
        _ => (all, false),
    };
    if let Some(o) = not_fresh(answer) {
        return Sessions::none(o);
    }
    let Answer::Fresh(bytes, file) = answer else {
        unreachable!("not_fresh gives the other answers")
    };
    let doc = match read_json(bytes) {
        Ok(d) => d,
        Err(e) => {
            return Sessions::none(SectionOutcome::new(
                Outcome::Failed,
                format!("answer not JSON: {e}"),
            ));
        }
    };
    let empty = matches!(&doc.root.body, Body::Object(m) if m.is_empty());
    if empty {
        return Sessions {
            rows: Vec::new(),
            outcome: SectionOutcome {
                outcome: Outcome::CompleteEmpty,
                scope: if global {
                    Scope::ipv4_unicast(["default".to_string()])
                } else {
                    Scope::none()
                },
                detail: None,
            },
        };
    }
    let Some(table) = doc.root.get("TABLE_vrf") else {
        return Sessions::none(SectionOutcome::new(Outcome::Failed, "no TABLE_vrf"));
    };
    let (mut rows, mut unread, mut notes) = (Vec::new(), Vec::new(), Vec::new());
    let mut vrfs = BTreeSet::new();
    for vr in nx_rows(table, "ROW_vrf") {
        let vrf = scalar(vr, "vrf-name-out")
            .filter(|v| !v.is_empty())
            .unwrap_or("default")
            .to_string();
        let Some(t) = vr
            .get("TABLE_neighbor")
            .filter(|t| t.get("ROW_neighbor").is_some())
        else {
            notes.push(format!("VRF {vrf} with no table of neighbours"));
            continue;
        };
        vrfs.insert(vrf.clone());
        for n in nx_rows(t, "ROW_neighbor") {
            match nxos_row(&vrf, n, file) {
                Some(r) => rows.push(r),
                None => unread.push(format!("VRF {vrf} row at line {}", n.first_line)),
            }
        }
    }
    if global {
        vrfs.retain(|v| v == "default");
    }
    let (mut outcome, detail) = rows_outcome(rows.len(), &unread);
    if vrfs.is_empty() && !notes.is_empty() {
        outcome = Outcome::Failed;
    }
    notes.extend(detail);
    Sessions {
        rows,
        outcome: SectionOutcome {
            outcome,
            scope: Scope::ipv4_unicast(vrfs),
            detail: (!notes.is_empty()).then(|| notes.join(", ")),
        },
    }
}

/// The rows of a `ROW_x` of NX-OS: a list, or one object.
fn nx_rows<'s>(table: &'s Stanza, row: &str) -> Vec<&'s Stanza> {
    match table.get(row).map(|r| &r.body) {
        Some(Body::Array(items)) => items.iter().collect(),
        Some(Body::Object(_)) => table.get(row).into_iter().collect(),
        _ => Vec::new(),
    }
}

fn nxos_row(vrf: &str, n: &Stanza, file: &str) -> Option<SessionRow> {
    let peer: IpAddr = scalar(n, "neighbor-id")?.parse().ok()?;
    let state = scalar(n, "state")?.to_string();
    Some(SessionRow {
        vrf: vrf.to_string(),
        peer,
        family: None,
        peer_asn: scalar(n, "remoteas").map(str::to_string),
        established: state == NXOS_ESTABLISHED,
        state,
        prefixes_received: None,
        prefixes_sent: None,
        span: span(file, n),
    })
}

// IOS-XR and IOS-XE: the text summaries of the global table and of each VRF.

/// The head of the summary of a BGP process.
const CISCO_HEADER: &str = "BGP router identifier";
/// The start of the header of the neighbour columns. A summary with this
/// header and no row is not read.
const CISCO_COLUMNS: &str = "Neighbor";
/// The start of a line with which a Cisco device states that it has no BGP
/// process or no such VRF.
const CISCO_NOTE: &str = "%";
/// The line before the answer of each VRF in the section of the VRFs.
const VRF_LINE: &str = "VRF: ";
/// The word after the name of a VRF whose command failed.
const VRF_FAILED: &str = " failed";

/// The command of the template of the IOS-XE summary.
const IOSXE_COMMAND: &str = "show ip bgp summary";
/// The platform of the IOS-XE templates.
const IOSXE_PLATFORM: &str = "cisco_ios";

/// The vendor of a text summary.
#[derive(Clone, Copy)]
enum Cisco {
    Iosxr,
    Iosxe,
}

/// The sessions of an IOS-XR router from `show bgp summary` and the
/// summaries of the VRFs. Each row is read by its columns: the neighbour,
/// the speaker, the AS, 5 counters, the up or down time and the state or the
/// prefix count. The scope is IPv4 unicast in each VRF whose summary is
/// read.
pub fn iosxr(global: Answer<'_>, vrfs: Answer<'_>) -> Sessions {
    cisco(Cisco::Iosxr, global, vrfs)
}

/// The sessions of an IOS-XE router from `show ip bgp summary` and the
/// summaries of the VRFs, read by the TextFSM template after the removal of
/// the mark `*` of a dynamic peer. The scope is IPv4 unicast in each VRF
/// whose summary is read.
pub fn iosxe(global: Answer<'_>, vrfs: Answer<'_>) -> Sessions {
    cisco(Cisco::Iosxe, global, vrfs)
}

/// The read of one summary: its rows and its outcome.
struct Part {
    vrf: String,
    rows: Vec<SessionRow>,
    outcome: Outcome,
    detail: Option<String>,
}

fn cisco(vendor: Cisco, global: Answer<'_>, vrfs: Answer<'_>) -> Sessions {
    if matches!(global, Answer::NotCollected) && matches!(vrfs, Answer::NotCollected) {
        return Sessions::none(not_fresh(global).expect("not fresh"));
    }
    let mut parts = Vec::new();
    let mut notes = Vec::new();
    match global {
        Answer::Fresh(bytes, file) => {
            let text = String::from_utf8_lossy(bytes);
            parts.push(summary(vendor, "default", &text, 0, file));
        }
        a => {
            let o = not_fresh(a).expect("not fresh");
            notes.push(format!("default: {}", o.detail.unwrap_or_default()));
            parts.push(Part {
                vrf: "default".into(),
                rows: Vec::new(),
                outcome: o.outcome,
                detail: None,
            });
        }
    }
    match vrfs {
        Answer::Fresh(bytes, file) => {
            let text = String::from_utf8_lossy(bytes);
            parts.extend(vrf_parts(vendor, &text, file));
        }
        Answer::NotCollected => {}
        a => {
            let o = not_fresh(a).expect("not fresh");
            notes.push(format!("VRF summaries: {}", o.detail.unwrap_or_default()));
            parts.push(Part {
                vrf: String::new(),
                rows: Vec::new(),
                outcome: o.outcome,
                detail: None,
            });
        }
    }
    let read = |o: Outcome| matches!(o, Outcome::Complete | Outcome::CompleteEmpty);
    let scope: BTreeSet<String> = parts
        .iter()
        .filter(|p| read(p.outcome) || p.outcome == Outcome::Partial)
        .map(|p| p.vrf.clone())
        .collect();
    notes.extend(
        parts
            .iter()
            .filter_map(|p| p.detail.as_ref().map(|d| format!("{}: {d}", p.vrf))),
    );
    let outcome = if parts.iter().all(|p| p.outcome == Outcome::NotCaptured) {
        Outcome::NotCaptured
    } else if parts
        .iter()
        .all(|p| read(p.outcome) || p.outcome == Outcome::NotCaptured)
        && parts.iter().any(|p| read(p.outcome))
    {
        if parts.iter().any(|p| !p.rows.is_empty()) {
            Outcome::Complete
        } else {
            Outcome::CompleteEmpty
        }
    } else if scope.is_empty() {
        Outcome::Failed
    } else {
        Outcome::Partial
    };
    Sessions {
        rows: parts.into_iter().flat_map(|p| p.rows).collect(),
        outcome: SectionOutcome {
            outcome,
            scope: Scope::ipv4_unicast(scope),
            detail: (!notes.is_empty()).then(|| notes.join(", ")),
        },
    }
}

/// The parts of the section of the VRFs: each line `VRF: <name>` starts the
/// answer of a VRF, and `VRF: <name> failed` is a VRF whose command failed.
/// A text before the first such line is a part that is not read.
fn vrf_parts(vendor: Cisco, text: &str, file: &str) -> Vec<Part> {
    let lines: Vec<&str> = text.lines().collect();
    let starts: Vec<usize> = (0..lines.len())
        .filter(|&i| lines[i].starts_with(VRF_LINE))
        .collect();
    let mut out = Vec::new();
    let first = starts.first().copied().unwrap_or(lines.len());
    if lines[..first].iter().any(|l| !l.trim().is_empty()) {
        out.push(Part {
            vrf: String::new(),
            rows: Vec::new(),
            outcome: Outcome::Failed,
            detail: Some("text before the first VRF".into()),
        });
    }
    for (k, &at) in starts.iter().enumerate() {
        let end = starts.get(k + 1).copied().unwrap_or(lines.len());
        let head = lines[at][VRF_LINE.len()..].trim();
        if let Some(name) = head.strip_suffix(VRF_FAILED) {
            out.push(Part {
                vrf: name.trim().to_string(),
                rows: Vec::new(),
                outcome: Outcome::Failed,
                detail: Some("command failed".into()),
            });
            continue;
        }
        let mut body = lines[at + 1..end].join("\n");
        body.push('\n');
        out.push(summary(vendor, head, &body, at + 1, file));
    }
    out
}

/// True for the time line that IOS-XR prints before each answer.
fn time_line(line: &str) -> bool {
    let w: Vec<&str> = line.split_whitespace().collect();
    matches!(
        w.first(),
        Some(&("Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun"))
    ) && w.len() >= 4
        && w[3].matches(':').count() == 2
}

/// The neighbour address of a line in the shape of a session row: its first
/// word after the mark `*` of a dynamic peer.
fn row_address(line: &str) -> Option<IpAddr> {
    line.split_whitespace()
        .next()?
        .trim_start_matches('*')
        .parse()
        .ok()
}

/// The lines of a summary with a long address that the device prints alone
/// on its line joined to the rest of its row on the next line. Each line
/// keeps the number of its first line.
fn joined(text: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        let alone = l.split_whitespace().count() == 1 && row_address(l).is_some();
        match lines.get(i + 1) {
            Some(next) if alone && row_address(next).is_none() && !next.trim().is_empty() => {
                out.push((i, format!("{} {}", l.trim_end(), next.trim_start())));
                i += 2;
            }
            _ => {
                out.push((i, l.to_string()));
                i += 1;
            }
        }
    }
    out
}

/// Reads one summary. `offset` is the number of lines of the section before
/// the text.
fn summary(vendor: Cisco, vrf: &str, text: &str, offset: usize, file: &str) -> Part {
    let content: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !time_line(l))
        .collect();
    let part = |outcome, detail: Option<String>| Part {
        vrf: vrf.to_string(),
        rows: Vec::new(),
        outcome,
        detail,
    };
    if !content.is_empty() && content.iter().all(|l| l.starts_with(CISCO_NOTE)) {
        return part(Outcome::NotCaptured, Some(content.join(" ")));
    }
    if !content.iter().any(|l| l.starts_with(CISCO_HEADER)) {
        return part(
            Outcome::Failed,
            Some(format!("no line starting with {CISCO_HEADER:?}")),
        );
    }
    let shaped: Vec<(usize, String)> = joined(text)
        .into_iter()
        .filter(|(_, l)| row_address(l).is_some())
        .collect();
    if shaped.is_empty() && content.iter().any(|l| l.starts_with(CISCO_COLUMNS)) {
        return part(
            Outcome::Failed,
            Some("no row below the neighbour column header".into()),
        );
    }
    let (rows, unread) = match vendor {
        Cisco::Iosxr => xr_rows(vrf, &shaped, offset, file),
        Cisco::Iosxe => match xe_rows(vrf, text, &shaped, offset, file) {
            Ok(x) => x,
            Err(e) => return part(Outcome::Failed, Some(e)),
        },
    };
    let (outcome, detail) = rows_outcome(rows.len(), &unread);
    Part {
        vrf: vrf.to_string(),
        rows,
        outcome,
        detail,
    }
}

/// A count in the column of the state: the session is established.
fn state_or_count(words: &str) -> (String, bool, Option<u64>) {
    match words.parse::<u64>() {
        Ok(n) => ("Established".into(), true, Some(n)),
        Err(_) => (words.to_string(), false, None),
    }
}

fn line_span(file: &str, offset: usize, i: usize) -> SourceSpan {
    let n = u32::try_from(offset + i + 1).unwrap_or(u32::MAX);
    SourceSpan::new(file, n, n)
}

/// The rows of an IOS-XR summary by their columns.
fn xr_rows(
    vrf: &str,
    shaped: &[(usize, String)],
    offset: usize,
    file: &str,
) -> (Vec<SessionRow>, Vec<String>) {
    let (mut rows, mut unread) = (Vec::new(), Vec::new());
    for (i, line) in shaped {
        let w: Vec<&str> = line.split_whitespace().collect();
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        let asn = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || b == b'.');
        let ok = w.len() >= 10 && digits(w[1]) && asn(w[2]) && w[3..8].iter().all(|x| digits(x));
        let peer = row_address(line);
        match (ok, peer) {
            (true, Some(peer)) => {
                let (state, established, received) = state_or_count(&w[9..].join(" "));
                rows.push(SessionRow {
                    vrf: vrf.to_string(),
                    peer,
                    family: Some(IPV4_UNICAST.into()),
                    peer_asn: Some(w[2].to_string()),
                    state,
                    established,
                    prefixes_received: received,
                    prefixes_sent: None,
                    span: line_span(file, offset, *i),
                });
            }
            _ => unread.push(format!("line {}", offset + i + 1)),
        }
    }
    (rows, unread)
}

/// The rows of an IOS-XE summary by the TextFSM template. Each row-shaped
/// line that no record holds is not read.
fn xe_rows(
    vrf: &str,
    text: &str,
    shaped: &[(usize, String)],
    offset: usize,
    file: &str,
) -> Result<(Vec<SessionRow>, Vec<String>), String> {
    let unmarked: String = text
        .lines()
        .map(|l| match l.strip_prefix('*') {
            Some(rest) if row_address(rest).is_some() => format!("{rest}\n"),
            _ => format!("{l}\n"),
        })
        .collect();
    let mut parsed = parse_on(
        IOSXE_PLATFORM,
        IOSXE_COMMAND,
        unmarked.as_bytes(),
        file,
        |_| false,
    )?;
    parsed.shift(offset);
    let mut rows = Vec::new();
    let mut held = BTreeSet::new();
    for (record, span) in parsed.records() {
        let peer = parsed.text(record, "BGP_NEIGHBOR");
        let Ok(peer) = peer.parse::<IpAddr>() else {
            continue;
        };
        held.insert(span.first_line);
        let (state, established, received) =
            state_or_count(parsed.text(record, "STATE_OR_PREFIXES_RECEIVED").trim());
        let asn = parsed.text(record, "NEIGHBOR_AS");
        rows.push(SessionRow {
            vrf: vrf.to_string(),
            peer,
            family: Some(IPV4_UNICAST.into()),
            peer_asn: (!asn.is_empty()).then(|| asn.to_string()),
            state,
            established,
            prefixes_received: received,
            prefixes_sent: None,
            span,
        });
    }
    let unread = shaped
        .iter()
        .map(|(i, _)| offset + i + 1)
        .filter(|n| !held.contains(&u32::try_from(*n).unwrap_or(u32::MAX)))
        .map(|n| format!("line {n}"))
        .collect();
    Ok((rows, unread))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_address_alone_on_its_line_joins_the_next_line() {
        let text =
            "Neighbor V AS\n2001:db8:aaaa:bbbb::1\n                4 64501 1 1 1 0 0 00:01:00 2\n";
        let j = joined(text);
        assert_eq!(j.len(), 2);
        assert_eq!(j[1].0, 1);
        assert!(j[1].1.starts_with("2001:db8:aaaa:bbbb::1 4 64501"));
    }

    #[test]
    fn a_count_in_the_column_of_the_state_is_established() {
        assert_eq!(state_or_count("12"), ("Established".into(), true, Some(12)));
        assert_eq!(
            state_or_count("Idle (Admin)"),
            ("Idle (Admin)".into(), false, None)
        );
    }
}
