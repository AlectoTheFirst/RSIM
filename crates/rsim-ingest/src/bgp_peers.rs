//! The BGP neighbours of the config of a router with the inheritance of their
//! settings from peer groups, templates and session groups, and the peer
//! facts of a device: one for each configured neighbour, each listen range
//! and each observed peer with no neighbour, joined with the session rows.
//!
//! An inheritance that names a source that the config does not define, or
//! that comes back to a source on its own path, is a gap. A setting is known
//! only if the neighbour states it or a source taken before the first gap
//! states it, because the missing source can state it: else the AS of the
//! peer, the presented local AS and the shutdown state are `Unknown` with
//! the reason of the gap.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{Prefix, SourceSpan};

use crate::bgp::{SessionRow, Sessions};
use crate::links::{Asn, AsnValue, BgpPeer, BgpPeerFact, PeerSource};
use crate::stanza::Stanza;

/// The name of the default VRF.
pub const DEFAULT_VRF: &str = "default";

/// The start of the reason of an inheritance gap.
pub const INHERITANCE_GAP: &str = "inheritance gap";
/// The start of the reason of an AS number that does not resolve.
pub const ASN_NOT_RESOLVED: &str = "asn not resolved";

/// An AS number in asplain, for example `4200000001`, or in asdot, for
/// example `1.10`, as its asplain value. `None` for another text or a value
/// outside 32 bits.
pub fn parse_asn(text: &str) -> Option<u32> {
    let t = text.trim();
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    match t.split_once('.') {
        None if digits(t) => t.parse::<u32>().ok(),
        None => None,
        Some((h, l)) if digits(h) && digits(l) => {
            let (h, l) = (h.parse::<u32>().ok()?, l.parse::<u32>().ok()?);
            (h <= 0xFFFF && l <= 0xFFFF).then(|| h * 65536 + l)
        }
        Some(_) => None,
    }
}

/// The first and the last line of a stanza of the config.
pub type Lines = (u32, u32);

/// A value of the config with the lines that state it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sourced<T> {
    pub value: T,
    pub lines: Lines,
}

impl<T> Sourced<T> {
    pub fn new(value: T, lines: Lines) -> Sourced<T> {
        Sourced { value, lines }
    }
}

/// The remote AS of a neighbour as the config states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteAs {
    Asn(u32),
    /// The AS of the process.
    Internal,
    /// Any AS other than the AS of the process, learned from the session.
    External,
    /// The AS learned from the session.
    Auto,
    /// The AS that a route map accepts.
    RouteMap(String),
    /// A value that is not an AS number, through the mask of the vendor.
    Unreadable(String),
}

/// The local AS of a neighbour: `local-as` with its options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalAs {
    /// `None` for a value that is not an AS number.
    pub asn: Option<u32>,
    /// The words of the line through the mask of the vendor.
    pub text: String,
    pub no_prepend: bool,
    pub replace_as: bool,
    pub dual_as: bool,
}

impl LocalAs {
    /// Reads the words after `local-as`: the AS, then `no-prepend`,
    /// `replace-as` and `dual-as`. A word that is not one of these makes
    /// the AS unread.
    pub fn parse(words: &[&str], text: String) -> LocalAs {
        let mut l = LocalAs {
            asn: words.first().and_then(|w| parse_asn(w)),
            text,
            no_prepend: false,
            replace_as: false,
            dual_as: false,
        };
        for w in words.iter().skip(1) {
            match *w {
                "no-prepend" => l.no_prepend = true,
                "replace-as" => l.replace_as = true,
                "dual-as" => l.dual_as = true,
                _ => l.asn = None,
            }
        }
        l
    }
}

/// The settings of a neighbour, a peer group, a template or a session
/// group that the inheritance carries. Each is `None` when the stanza does
/// not state it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    pub remote_as: Option<Sourced<RemoteAs>>,
    pub local_as: Option<Sourced<LocalAs>>,
    /// The interface or the address of the update-source or local address.
    pub update_source: Option<Sourced<String>>,
    pub shutdown: Option<Sourced<bool>>,
    /// Each address family with true for an activation and false for a
    /// deactivation.
    pub families: BTreeMap<String, Sourced<bool>>,
    pub policy_in: Option<Sourced<String>>,
    pub policy_out: Option<Sourced<String>>,
}

impl Settings {
    /// Takes each setting of `parent` that this stanza does not state; the
    /// policies only with `policies`.
    pub fn inherit(&mut self, parent: &Settings, policies: bool) {
        fn fill<T: Clone>(own: &mut Option<T>, p: &Option<T>) {
            if own.is_none() {
                own.clone_from(p);
            }
        }
        fill(&mut self.remote_as, &parent.remote_as);
        fill(&mut self.local_as, &parent.local_as);
        fill(&mut self.update_source, &parent.update_source);
        fill(&mut self.shutdown, &parent.shutdown);
        if policies {
            fill(&mut self.policy_in, &parent.policy_in);
            fill(&mut self.policy_out, &parent.policy_out);
        }
        for (f, v) in &parent.families {
            self.families.entry(f.clone()).or_insert_with(|| v.clone());
        }
    }
}

/// A source of the inheritance that a stanza names: its kind, for example
/// `peer-group` or `template peer-session`, its name, its order among the
/// sources of the stanza, lower first, and whether it gives the policies of
/// IPv4 unicast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parent {
    pub kind: String,
    pub name: String,
    pub order: u32,
    /// False for a source that an address family other than IPv4 unicast
    /// inherits: it and its own sources give no policy of IPv4 unicast.
    pub ipv4_policy: bool,
}

impl Parent {
    pub fn new(kind: &str, name: &str, order: u32) -> Parent {
        Parent {
            kind: kind.to_string(),
            name: name.to_string(),
            order,
            ipv4_policy: true,
        }
    }

    /// The source with `ipv4_policy` set to `v`.
    pub fn with_ipv4_policy(mut self, v: bool) -> Parent {
        self.ipv4_policy = v;
        self
    }
}

/// A peer group, a template or a session group: its settings and the
/// sources that it inherits from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Template {
    pub settings: Settings,
    pub parents: Vec<Parent>,
    pub lines: Option<Lines>,
}

/// The templates of a device by kind and name.
pub type Templates = BTreeMap<(String, String), Template>;

/// The settings of a stanza after the inheritance.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resolved {
    pub settings: Settings,
    /// The sources that the stanza inherits from, as `<kind> <name>`.
    pub inherits: Vec<String>,
    pub gaps: Vec<String>,
    /// The lines of the templates that the stanza inherits from.
    pub lines: Vec<Lines>,
}

/// Resolves the settings of a stanza. The sources are taken in their order;
/// a source gives each setting that the stanza and the sources before it do
/// not state, and its own sources follow it. A source that is not defined,
/// or that is on its own path, is a gap, and no source after the first gap
/// gives a setting; each source is still listed in `inherits`.
pub fn resolve(own: &Settings, parents: &[Parent], templates: &Templates) -> Resolved {
    let mut out = Resolved {
        settings: own.clone(),
        ..Resolved::default()
    };
    let mut path = Vec::new();
    walk(parents, templates, &mut path, &mut out, true);
    out
}

fn walk(
    parents: &[Parent],
    templates: &Templates,
    path: &mut Vec<(String, String)>,
    out: &mut Resolved,
    policies: bool,
) {
    let mut ordered: Vec<&Parent> = parents.iter().collect();
    ordered.sort_by_key(|p| p.order);
    for p in ordered {
        let key = (p.kind.clone(), p.name.clone());
        let label = format!("{} {}", p.kind, p.name);
        if path.contains(&key) {
            out.gaps
                .push(format!("{INHERITANCE_GAP}: {label} inherits from itself"));
            continue;
        }
        let Some(t) = templates.get(&key) else {
            out.gaps
                .push(format!("{INHERITANCE_GAP}: {label} is not defined"));
            continue;
        };
        if !out.inherits.contains(&label) {
            out.inherits.push(label);
        }
        if let Some(l) = t.lines
            && !out.lines.contains(&l)
        {
            out.lines.push(l);
        }
        let policies = policies && p.ipv4_policy;
        if out.gaps.is_empty() {
            out.settings.inherit(&t.settings, policies);
        }
        path.push(key);
        walk(&t.parents, templates, path, out, policies);
        path.pop();
    }
}

/// A BGP neighbour or a listen range of the config after the inheritance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbour {
    pub vrf: String,
    pub peer: BgpPeer,
    pub resolved: Resolved,
    /// The lines of the stanza or of the first line of the neighbour.
    pub lines: Lines,
}

/// The confederation of a process.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Confederation {
    /// The identifier, or the masked text of a value that is not an AS.
    pub identifier: Option<Sourced<Result<u32, String>>>,
    /// The member ASes of the other sub-ASes, or the masked text of a line
    /// that is not read.
    pub peers: Option<Sourced<Result<BTreeSet<u32>, String>>>,
}

/// The BGP process of a VRF.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Process {
    /// The AS of the process, or the reason why it is not known.
    pub asn: Sourced<Result<u32, String>>,
    pub confederation: Confederation,
}

/// The BGP config of a device: the process of each VRF and the neighbours
/// and listen ranges after the inheritance.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BgpConfig {
    pub processes: BTreeMap<String, Process>,
    pub neighbours: Vec<Neighbour>,
}

/// The addresses of each interface of a device with its VRF.
pub type InterfaceAddresses = BTreeMap<String, (String, Vec<IpAddr>)>;

/// The local addresses of each VRF.
pub fn local_addresses(interfaces: &InterfaceAddresses) -> BTreeMap<String, BTreeSet<IpAddr>> {
    let mut out: BTreeMap<String, BTreeSet<IpAddr>> = BTreeMap::new();
    for (vrf, addrs) in interfaces.values() {
        out.entry(vrf.clone())
            .or_default()
            .extend(addrs.iter().copied());
    }
    out
}

/// The address of a text with a prefix length, for example `192.0.2.1/24`,
/// or without one.
pub fn address_of(text: &str) -> Option<IpAddr> {
    text.split('/').next()?.parse().ok()
}

fn asn(value: AsnValue, spans: Vec<SourceSpan>) -> Asn {
    Asn { value, spans }
}

fn unknown(reason: String) -> Asn {
    asn(AsnValue::Unknown(reason), Vec::new())
}

/// The first gap of a neighbour as a reason.
fn gap_reason(r: &Resolved) -> Option<String> {
    r.gaps.first().cloned()
}

/// The facts of one device: its name, the file of its config for the
/// spans, its BGP config, its sessions and the addresses of its
/// interfaces.
struct Ctx<'a> {
    device: &'a str,
    file: &'a str,
    cfg: &'a BgpConfig,
    sessions: &'a Sessions,
    interfaces: &'a InterfaceAddresses,
}

impl Ctx<'_> {
    fn span(&self, l: Lines) -> SourceSpan {
        SourceSpan::new(self.file, l.0, l.1.max(l.0))
    }

    /// The AS of the peer of a configured neighbour.
    fn peer_asn(&self, n: &Neighbour, process: Option<&Process>) -> Asn {
        let Some(remote) = &n.resolved.settings.remote_as else {
            return unknown(
                gap_reason(&n.resolved).unwrap_or_else(|| {
                    format!("{ASN_NOT_RESOLVED}: the neighbour has no remote-as")
                }),
            );
        };
        let span = self.span(remote.lines);
        match &remote.value {
            RemoteAs::Asn(a) => asn(AsnValue::Known(vec![*a]), vec![span]),
            RemoteAs::Internal => match process.map(|p| &p.asn) {
                Some(Sourced {
                    value: Ok(a),
                    lines,
                }) => asn(AsnValue::Known(vec![*a]), vec![span, self.span(*lines)]),
                Some(Sourced { value: Err(e), .. }) => {
                    unknown(format!("{ASN_NOT_RESOLVED}: remote-as internal: {e}"))
                }
                None => unknown(format!(
                    "{ASN_NOT_RESOLVED}: remote-as internal with no process AS"
                )),
            },
            RemoteAs::External => unknown(format!(
                "{ASN_NOT_RESOLVED}: remote-as external is learned from the session"
            )),
            RemoteAs::Auto => unknown(format!(
                "{ASN_NOT_RESOLVED}: remote-as auto is learned from the session"
            )),
            RemoteAs::RouteMap(m) => unknown(format!(
                "{ASN_NOT_RESOLVED}: remote-as route-map {m} accepts the AS of a route map"
            )),
            RemoteAs::Unreadable(t) => unknown(format!(
                "{ASN_NOT_RESOLVED}: remote-as {t} is not an AS number"
            )),
        }
    }

    /// The AS that the device presents to the peer outside a `local-as`: in
    /// a confederation, the AS of the process toward a member of the
    /// confederation and the identifier toward another peer; else the AS of
    /// the process.
    fn outward(&self, p: &Process, peer: &Asn) -> Asn {
        let own = match &p.asn.value {
            Ok(a) => *a,
            Err(e) => return unknown(format!("{ASN_NOT_RESOLVED}: {e}")),
        };
        let own_span = self.span(p.asn.lines);
        let c = &p.confederation;
        let Some(id) = &c.identifier else {
            return asn(AsnValue::Known(vec![own]), vec![own_span]);
        };
        let id_value = match &id.value {
            Ok(v) => *v,
            Err(t) => {
                return unknown(format!(
                    "{ASN_NOT_RESOLVED}: the confederation line {t} is not read"
                ));
            }
        };
        let (members, members_span) = match &c.peers {
            Some(Sourced {
                value: Ok(m),
                lines,
            }) => (m.clone(), Some(self.span(*lines))),
            Some(Sourced { value: Err(t), .. }) => {
                return unknown(format!(
                    "{ASN_NOT_RESOLVED}: the confederation line {t} is not read"
                ));
            }
            None => (BTreeSet::new(), None),
        };
        match &peer.value {
            AsnValue::Known(v) if v.iter().all(|a| *a == own || members.contains(a)) => {
                let mut spans = vec![own_span, self.span(id.lines)];
                spans.extend(members_span);
                asn(AsnValue::Known(vec![own]), spans)
            }
            AsnValue::Known(_) => asn(AsnValue::Known(vec![id_value]), vec![self.span(id.lines)]),
            AsnValue::Unknown(_) => unknown(format!(
                "{ASN_NOT_RESOLVED}: the AS of the peer decides between the confederation identifier and the member AS"
            )),
        }
    }

    /// The AS that the device presents to the peer: the `local-as` of the
    /// neighbour, with the outward AS too under `dual-as`, else the outward
    /// AS.
    fn local_asn(&self, n: &Neighbour, process: Option<&Process>, peer: &Asn) -> Asn {
        let Some(p) = process else {
            return unknown(format!(
                "{ASN_NOT_RESOLVED}: no BGP process for the VRF {}",
                n.vrf
            ));
        };
        let Some(l) = &n.resolved.settings.local_as else {
            return match gap_reason(&n.resolved) {
                Some(g) => unknown(g),
                None => self.outward(p, peer),
            };
        };
        let span = self.span(l.lines);
        match l.value.asn {
            None => unknown(format!(
                "{ASN_NOT_RESOLVED}: the line local-as {} is not read",
                l.value.text
            )),
            Some(a) if l.value.dual_as => {
                let out = self.outward(p, peer);
                match out.value {
                    AsnValue::Known(v) => {
                        let mut all = vec![a];
                        all.extend(v.into_iter().filter(|x| *x != a));
                        let mut spans = vec![span];
                        spans.extend(out.spans);
                        asn(AsnValue::Known(all), spans)
                    }
                    AsnValue::Unknown(r) => unknown(r),
                }
            }
            Some(a) => asn(AsnValue::Known(vec![a]), vec![span]),
        }
    }

    /// The fact of a configured neighbour or listen range, with the session
    /// rows of its peer.
    fn configured(
        &self,
        n: &Neighbour,
        peer: BgpPeer,
        source: PeerSource,
        rows: Vec<SessionRow>,
    ) -> BgpPeerFact {
        let process = self.cfg.processes.get(&n.vrf);
        let s = &n.resolved.settings;
        let peer_asn = self.peer_asn(n, process);
        let local_asn = self.local_asn(n, process, &peer_asn);
        let mut lines = vec![n.lines];
        let stated = [
            s.remote_as.as_ref().map(|x| x.lines),
            s.local_as.as_ref().map(|x| x.lines),
            s.update_source.as_ref().map(|x| x.lines),
            s.shutdown.as_ref().map(|x| x.lines),
        ];
        for l in n
            .resolved
            .lines
            .iter()
            .copied()
            .chain(stated.into_iter().flatten())
        {
            if !lines.contains(&l) {
                lines.push(l);
            }
        }
        let shutdown = match &s.shutdown {
            Some(v) => Some(v.value),
            None if n.resolved.gaps.is_empty() => Some(false),
            None => None,
        };
        let local = s
            .update_source
            .as_ref()
            .and_then(|u| local_address(&u.value, self.interfaces, &peer, &n.vrf));
        BgpPeerFact {
            device: self.device.to_string(),
            vrf: n.vrf.clone(),
            peer,
            source,
            update_source: s.update_source.as_ref().map(|u| u.value.clone()),
            local_address: local,
            local_asn,
            peer_asn,
            observed_asn: observed_asn(&rows),
            shutdown,
            families: s
                .families
                .iter()
                .filter(|(_, v)| v.value)
                .map(|(f, _)| f.clone())
                .collect(),
            policy_in: s.policy_in.as_ref().map(|p| p.value.clone()),
            policy_out: s.policy_out.as_ref().map(|p| p.value.clone()),
            inherits: n.resolved.inherits.clone(),
            gaps: n.resolved.gaps.clone(),
            sessions: rows,
            router_id: None,
            section: self.sessions.outcome.clone(),
            spans: lines.into_iter().map(|l| self.span(l)).collect(),
        }
    }

    /// The fact of an observed peer with no neighbour and no single listen
    /// range that resolves. `ranges` is the reason why the listen ranges
    /// that hold the peer do not resolve, if one or more hold it; the local
    /// AS is then not known, because a range can state a local-as.
    fn observed(
        &self,
        vrf: &str,
        peer: IpAddr,
        rows: Vec<SessionRow>,
        ranges: Option<String>,
    ) -> BgpPeerFact {
        let row_spans: Vec<SourceSpan> = rows.iter().map(|r| r.span.clone()).collect();
        let observed_asn = observed_asn(&rows);
        let peer_asn = match observed_asn {
            Some(a) => asn(AsnValue::Known(vec![a]), row_spans.clone()),
            None => unknown(format!(
                "{ASN_NOT_RESOLVED}: the session rows state no single AS"
            )),
        };
        let local_asn = match (self.cfg.processes.get(vrf), ranges) {
            (None, _) => unknown(format!(
                "{ASN_NOT_RESOLVED}: no BGP process for the VRF {vrf} in the config"
            )),
            (Some(_), Some(reason)) => unknown(reason),
            (Some(p), None) => self.outward(p, &peer_asn),
        };
        BgpPeerFact {
            device: self.device.to_string(),
            vrf: vrf.to_string(),
            peer: BgpPeer::Address(peer),
            source: PeerSource::Observed,
            update_source: None,
            local_address: None,
            local_asn,
            peer_asn,
            observed_asn,
            shutdown: None,
            families: rows.iter().filter_map(|r| r.family.clone()).collect(),
            policy_in: None,
            policy_out: None,
            inherits: Vec::new(),
            gaps: Vec::new(),
            sessions: rows,
            router_id: None,
            section: self.sessions.outcome.clone(),
            spans: row_spans,
        }
    }
}

/// The local address of an update-source toward a peer address in a VRF:
/// the address itself, or the one address of the family of the peer of the
/// named interface of that VRF. `None` for a peer that is not an address,
/// an address of another family, an interface of another VRF, and an
/// interface with no address or more than one address of the family.
fn local_address(
    source: &str,
    interfaces: &InterfaceAddresses,
    peer: &BgpPeer,
    vrf: &str,
) -> Option<IpAddr> {
    let BgpPeer::Address(p) = peer else {
        return None;
    };
    if let Some(a) = address_of(source) {
        return (a.is_ipv4() == p.is_ipv4()).then_some(a);
    }
    let (in_vrf, addrs) = interfaces.get(source).or_else(|| {
        interfaces
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(source))
            .map(|(_, v)| v)
    })?;
    if in_vrf != vrf {
        return None;
    }
    match addrs
        .iter()
        .filter(|a| a.is_ipv4() == p.is_ipv4())
        .collect::<Vec<_>>()
        .as_slice()
    {
        [a] => Some(**a),
        _ => None,
    }
}

/// The AS of the peer that the session rows state, when they state one.
fn observed_asn(rows: &[SessionRow]) -> Option<u32> {
    let asns: BTreeSet<u32> = rows
        .iter()
        .filter_map(|r| r.peer_asn.as_deref().and_then(parse_asn))
        .collect();
    match asns.len() {
        1 => asns.into_iter().next(),
        _ => None,
    }
}

/// The facts of the configured neighbours and listen ranges of a device,
/// joined with its session rows, and of its observed peers with no
/// neighbour. `file` names the config for the spans. An observed peer in
/// exactly one listen range of its VRF whose inheritance resolves takes the
/// settings of the range; an observed peer in a range with a gap or in more
/// than one range has no known local AS. The facts are in the order of the
/// VRF and the peer.
pub fn facts(
    device: &str,
    file: &str,
    cfg: &BgpConfig,
    sessions: &Sessions,
    interfaces: &InterfaceAddresses,
) -> Vec<BgpPeerFact> {
    let f = Ctx {
        device,
        file,
        cfg,
        sessions,
        interfaces,
    };
    let mut rows: BTreeMap<(String, IpAddr), Vec<SessionRow>> = BTreeMap::new();
    for r in &sessions.rows {
        rows.entry((r.vrf.clone(), r.peer))
            .or_default()
            .push(r.clone());
    }
    let mut out = Vec::new();
    for n in &cfg.neighbours {
        let (source, r) = match &n.peer {
            BgpPeer::Address(a) => (
                PeerSource::Configured,
                rows.remove(&(n.vrf.clone(), *a)).unwrap_or_default(),
            ),
            BgpPeer::Range(_) => (PeerSource::ListenRange, Vec::new()),
            BgpPeer::Interface(_) => (PeerSource::Configured, Vec::new()),
        };
        out.push(f.configured(n, n.peer.clone(), source, r));
    }
    for ((vrf, peer), r) in rows {
        let ranges: Vec<(&Neighbour, Prefix)> = cfg
            .neighbours
            .iter()
            .filter(|n| n.vrf == vrf)
            .filter_map(|n| match &n.peer {
                BgpPeer::Range(p) if p.contains(peer) => Some((n, *p)),
                _ => None,
            })
            .collect();
        match ranges.as_slice() {
            [] => out.push(f.observed(&vrf, peer, r, None)),
            [(n, range)] => match gap_reason(&n.resolved) {
                None => out.push(f.configured(
                    n,
                    BgpPeer::Address(peer),
                    PeerSource::Dynamic(*range),
                    r,
                )),
                Some(g) => out.push(f.observed(&vrf, peer, r, Some(g))),
            },
            more => {
                let names: Vec<String> = more.iter().map(|(_, p)| p.to_string()).collect();
                let reason = format!(
                    "{ASN_NOT_RESOLVED}: the peer is in more than one listen range: {}",
                    names.join(", ")
                );
                out.push(f.observed(&vrf, peer, r, Some(reason)));
            }
        }
    }
    out.sort_by(|a, b| (&a.vrf, &a.peer, a.source.name()).cmp(&(&b.vrf, &b.peer, b.source.name())));
    out
}

/// The address families of the vendor words of an address-family line,
/// for example `ipv4 unicast` or `vpnv4`, with the name of the family of the
/// session sections. `None` for words that name no family.
pub fn family(words: &[&str]) -> Option<String> {
    let w: Vec<String> = words.iter().map(|w| w.to_ascii_lowercase()).collect();
    let w: Vec<&str> = w.iter().map(String::as_str).collect();
    let name = match w.as_slice() {
        ["ipv4"] | ["ipv4", "unicast", ..] | ["ipv4-unicast"] => "ipv4-unicast",
        ["ipv6"] | ["ipv6", "unicast", ..] | ["ipv6-unicast"] => "ipv6-unicast",
        ["ipv4", "multicast", ..] | ["ipv4-multicast"] => "ipv4-multicast",
        ["ipv6", "multicast", ..] | ["ipv6-multicast"] => "ipv6-multicast",
        ["ipv4", "labeled-unicast", ..] | ["ipv4-labeled-unicast"] => "ipv4-labeled-unicast",
        ["ipv6", "labeled-unicast", ..] | ["ipv6-labeled-unicast"] => "ipv6-labeled-unicast",
        ["vpnv4", ..] | ["ipv4-vpn"] => "ipv4-vpn",
        ["vpnv6", ..] | ["ipv6-vpn"] => "ipv6-vpn",
        ["ipv4", "flowspec", ..] | ["ipv4-flowspec"] => "ipv4-flowspec",
        ["ipv6", "flowspec", ..] | ["ipv6-flowspec"] => "ipv6-flowspec",
        ["l2vpn", "evpn", ..] | ["l2vpn-evpn"] => "l2vpn-evpn",
        _ => return None,
    };
    Some(name.to_string())
}

/// The remote AS of the words after `remote-as`: an AS number, or the
/// masked words.
pub fn remote_as(words: &[&str], mask: &dyn Fn(&str) -> String) -> RemoteAs {
    match words {
        [a] => parse_asn(a).map_or_else(|| RemoteAs::Unreadable(mask(a)), RemoteAs::Asn),
        _ => RemoteAs::Unreadable(mask(&words.join(" "))),
    }
}

/// Reads the settings and the inheritance of a neighbour, a template or a
/// group of a config with a stanza for each neighbour, as NX-OS and IOS-XR
/// write it: `remote-as`, `update-source`, `shutdown`, `shutdown
/// inheritance-disable` as no shutdown, `local-as`, the lines that `inherit`
/// gives a source for, and each `address-family` stanza that names a family,
/// with the inheritance lines below it and the `<policy> <name> in` and
/// `out` lines of IPv4 unicast. A source inherited below a family other
/// than IPv4 unicast gives no policy. A `<policy> <name> in` or `out` line
/// of the stanza itself, as in an NX-OS peer-policy template, is a policy
/// of IPv4 unicast. Each line that it reads goes into `read`; the policy
/// lines keep the state of the routing lines.
pub fn block(
    s: &Stanza,
    read: &mut BTreeSet<u32>,
    mask: &dyn Fn(&str) -> String,
    settings: &mut Settings,
    parents: &mut Vec<Parent>,
    inherit: &dyn Fn(&[&str]) -> Option<Parent>,
    policy: &str,
) {
    for c in s.children() {
        let w: Vec<&str> = c.key.split_whitespace().collect();
        let lines = (c.first_line, c.last_line);
        if let Some(p) = inherit(&w) {
            read.insert(c.first_line);
            parents.push(p);
            continue;
        }
        match w.as_slice() {
            ["remote-as", "route-map", m] => {
                read.insert(c.first_line);
                settings.remote_as =
                    Some(Sourced::new(RemoteAs::RouteMap((*m).to_string()), lines));
            }
            ["remote-as", rest @ ..] => {
                read.insert(c.first_line);
                settings.remote_as = Some(Sourced::new(remote_as(rest, mask), lines));
            }
            ["update-source", i] => {
                read.insert(c.first_line);
                settings.update_source = Some(Sourced::new((*i).to_string(), lines));
            }
            ["shutdown"] => {
                read.insert(c.first_line);
                settings.shutdown = Some(Sourced::new(true, lines));
            }
            ["shutdown", "inheritance-disable"] => {
                read.insert(c.first_line);
                settings.shutdown = Some(Sourced::new(false, lines));
            }
            ["local-as", rest @ ..] => {
                read.insert(c.first_line);
                settings.local_as = Some(Sourced::new(LocalAs::parse(rest, mask(&c.key)), lines));
            }
            [word, m, dir @ ("in" | "out")] if *word == policy => {
                let v = Some(Sourced::new((*m).to_string(), lines));
                match *dir {
                    "in" => settings.policy_in = v,
                    _ => settings.policy_out = v,
                }
            }
            ["address-family", fam @ ..] => {
                let Some(f) = family(fam) else {
                    continue;
                };
                read.insert(c.first_line);
                settings
                    .families
                    .insert(f.clone(), Sourced::new(true, lines));
                for a in c.children() {
                    let aw: Vec<&str> = a.key.split_whitespace().collect();
                    if let Some(p) = inherit(&aw) {
                        read.insert(a.first_line);
                        parents.push(p.with_ipv4_policy(f == crate::bgp::IPV4_UNICAST));
                        continue;
                    }
                    if let [word, m, dir] = aw.as_slice()
                        && *word == policy
                        && f == crate::bgp::IPV4_UNICAST
                    {
                        let v = Some(Sourced::new((*m).to_string(), (a.first_line, a.last_line)));
                        match *dir {
                            "in" => settings.policy_in = v,
                            "out" => settings.policy_out = v,
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Reads a listen range or a neighbour address.
pub fn peer_of(text: &str) -> Option<BgpPeer> {
    if text.contains('/') {
        return text.parse::<Prefix>().ok().map(BgpPeer::Range);
    }
    text.parse::<IpAddr>().ok().map(BgpPeer::Address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asplain_and_asdot_give_the_asplain_value() {
        for (text, want) in [
            ("65001", Some(65001)),
            ("4200000001", Some(4_200_000_001)),
            ("1.10", Some(65546)),
            ("64086.59904", Some(64086 * 65536 + 59904)),
            ("0.65535", Some(65535)),
            ("65536.0", None),
            ("1.65536", None),
            ("4294967296", None),
            ("route-map", None),
            ("", None),
            ("1.", None),
            (".1", None),
        ] {
            assert_eq!(parse_asn(text), want, "{text}");
        }
    }

    fn span(n: u32) -> Lines {
        (n, n)
    }

    fn remote(a: u32, n: u32) -> Settings {
        Settings {
            remote_as: Some(Sourced::new(RemoteAs::Asn(a), span(n))),
            ..Settings::default()
        }
    }

    #[test]
    fn a_stanza_takes_the_settings_that_it_does_not_state_in_order() {
        let mut templates = Templates::new();
        let mut a = Template {
            settings: remote(64500, 1),
            parents: vec![Parent::new("session", "B", 0)],
            lines: Some((1, 1)),
        };
        a.settings.shutdown = Some(Sourced::new(true, span(2)));
        templates.insert(("session".into(), "A".into()), a);
        let mut b = Template::default();
        b.settings.update_source = Some(Sourced::new("Loopback0".into(), span(5)));
        b.settings.remote_as = Some(Sourced::new(RemoteAs::Asn(64999), span(6)));
        templates.insert(("session".into(), "B".into()), b);
        let own = Settings {
            shutdown: Some(Sourced::new(false, span(9))),
            ..Settings::default()
        };
        let r = resolve(&own, &[Parent::new("session", "A", 0)], &templates);
        assert!(r.gaps.is_empty());
        let s = &r.settings;
        assert_eq!(s.remote_as.as_ref().unwrap().value, RemoteAs::Asn(64500));
        assert!(!s.shutdown.as_ref().unwrap().value);
        assert_eq!(s.update_source.as_ref().unwrap().value, "Loopback0");
        assert_eq!(r.inherits, ["session A", "session B"]);
    }

    #[test]
    fn a_loop_and_a_missing_source_are_gaps() {
        let mut templates = Templates::new();
        templates.insert(
            ("t".into(), "A".into()),
            Template {
                parents: vec![Parent::new("t", "B", 0)],
                ..Template::default()
            },
        );
        templates.insert(
            ("t".into(), "B".into()),
            Template {
                parents: vec![Parent::new("t", "A", 0), Parent::new("t", "C", 1)],
                ..Template::default()
            },
        );
        let r = resolve(
            &Settings::default(),
            &[Parent::new("t", "A", 0)],
            &templates,
        );
        assert_eq!(
            r.gaps,
            [
                "inheritance gap: t A inherits from itself",
                "inheritance gap: t C is not defined"
            ]
        );
    }

    #[test]
    fn the_local_addresses_of_each_vrf_hold_the_loopbacks() {
        let a = |s: &str| s.parse::<IpAddr>().unwrap();
        let i = InterfaceAddresses::from([
            (
                "Loopback0".to_string(),
                ("default".to_string(), vec![a("192.0.2.1")]),
            ),
            (
                "Gi1".to_string(),
                ("default".to_string(), vec![a("198.51.100.1")]),
            ),
            (
                "Gi2".to_string(),
                ("RED".to_string(), vec![a("203.0.113.1"), a("2001:db8::1")]),
            ),
        ]);
        let l = local_addresses(&i);
        assert_eq!(
            l["default"],
            BTreeSet::from([a("192.0.2.1"), a("198.51.100.1")])
        );
        assert_eq!(l["RED"].len(), 2);
        let v4 = BgpPeer::Address(a("198.51.100.9"));
        assert_eq!(
            local_address("loopback0", &i, &v4, "default"),
            Some(a("192.0.2.1"))
        );
        assert_eq!(local_address("Gi9", &i, &v4, "default"), None);
    }

    #[test]
    fn a_gap_hides_the_settings_of_the_sources_after_it() {
        let mut templates = Templates::new();
        templates.insert(
            ("t".into(), "BEFORE".into()),
            Template {
                settings: Settings {
                    update_source: Some(Sourced::new("Loopback0".into(), span(1))),
                    ..Settings::default()
                },
                ..Template::default()
            },
        );
        let mut after = remote(64502, 5);
        after.shutdown = Some(Sourced::new(true, span(6)));
        templates.insert(
            ("t".into(), "AFTER".into()),
            Template {
                settings: after,
                ..Template::default()
            },
        );
        let r = resolve(
            &Settings::default(),
            &[
                Parent::new("t", "BEFORE", 0),
                Parent::new("t", "MISSING", 1),
                Parent::new("t", "AFTER", 2),
            ],
            &templates,
        );
        assert_eq!(r.gaps, ["inheritance gap: t MISSING is not defined"]);
        // The source before the gap gives its setting; the source after it
        // gives none.
        assert_eq!(
            r.settings.update_source.as_ref().map(|u| u.value.as_str()),
            Some("Loopback0")
        );
        assert_eq!(r.settings.remote_as, None);
        assert_eq!(r.settings.shutdown, None);
    }

    fn row(vrf: &str, peer: &str, asn: Option<&str>, line: u32) -> SessionRow {
        SessionRow {
            vrf: vrf.into(),
            peer: peer.parse().unwrap(),
            family: None,
            peer_asn: asn.map(Into::into),
            state: "Established".into(),
            established: true,
            prefixes_received: None,
            prefixes_sent: None,
            span: SourceSpan::new("r1/bgp_sessions@0", line, line),
        }
    }

    fn sessions(rows: Vec<SessionRow>) -> Sessions {
        Sessions {
            rows,
            outcome: crate::bgp::SectionOutcome {
                outcome: crate::bgp::Outcome::Complete,
                scope: crate::bgp::Scope::default(),
                detail: None,
            },
        }
    }

    fn process(asn: u32, confederation: Option<(u32, &[u32])>) -> Process {
        Process {
            asn: Sourced::new(Ok(asn), span(1)),
            confederation: Confederation {
                identifier: confederation.map(|(id, _)| Sourced::new(Ok(id), span(2))),
                peers: confederation
                    .map(|(_, m)| Sourced::new(Ok(m.iter().copied().collect()), span(3))),
            },
        }
    }

    fn observed_fact(cfg: &BgpConfig, rows: Vec<SessionRow>, peer: &str) -> BgpPeerFact {
        let f = facts("r1", "r1/config@0", cfg, &sessions(rows), &BTreeMap::new());
        f.into_iter()
            .find(|f| f.peer.to_string() == peer)
            .unwrap_or_else(|| panic!("no fact of {peer}"))
    }

    #[test]
    fn an_observed_peer_takes_the_as_that_the_confederation_presents() {
        let cfg = BgpConfig {
            processes: BTreeMap::from([(
                DEFAULT_VRF.to_string(),
                process(65001, Some((100, &[65002]))),
            )]),
            neighbours: Vec::new(),
        };
        let outside = observed_fact(
            &cfg,
            vec![row("default", "198.51.100.9", Some("200"), 12)],
            "198.51.100.9",
        );
        assert_eq!(outside.source, PeerSource::Observed);
        assert_eq!(outside.local_asn.value, AsnValue::Known(vec![100]));
        let member = observed_fact(
            &cfg,
            vec![row("default", "198.51.100.10", Some("65002"), 13)],
            "198.51.100.10",
        );
        assert_eq!(member.local_asn.value, AsnValue::Known(vec![65001]));
        // With no single AS of the peer, the presented AS is not known.
        let none = observed_fact(
            &cfg,
            vec![row("default", "198.51.100.11", None, 14)],
            "198.51.100.11",
        );
        assert!(matches!(none.local_asn.value, AsnValue::Unknown(_)));
        // With no process of the VRF, the presented AS is not known.
        let red = observed_fact(
            &cfg,
            vec![row("RED", "198.51.100.12", Some("200"), 15)],
            "198.51.100.12",
        );
        assert!(matches!(red.local_asn.value, AsnValue::Unknown(_)));
    }

    #[test]
    fn an_observed_peer_in_listen_ranges_that_do_not_resolve_has_no_known_local_as() {
        let range = |p: &str, gaps: Vec<String>| Neighbour {
            vrf: DEFAULT_VRF.into(),
            peer: BgpPeer::Range(p.parse().unwrap()),
            resolved: Resolved {
                settings: remote(64510, 20),
                gaps,
                ..Resolved::default()
            },
            lines: (20, 20),
        };
        let gap = format!("{INHERITANCE_GAP}: template peer-session MISSING is not defined");
        let cfg = |neighbours| BgpConfig {
            processes: BTreeMap::from([(DEFAULT_VRF.to_string(), process(65001, None))]),
            neighbours,
        };
        let rows = || vec![row("default", "198.51.100.5", Some("64510"), 12)];
        let gapped = observed_fact(
            &cfg(vec![range("198.51.100.0/24", vec![gap.clone()])]),
            rows(),
            "198.51.100.5",
        );
        assert_eq!(gapped.source, PeerSource::Observed);
        assert_eq!(gapped.local_asn.value, AsnValue::Unknown(gap));
        assert_eq!(gapped.shutdown, None);
        let two = observed_fact(
            &cfg(vec![
                range("198.51.100.0/24", Vec::new()),
                range("198.51.100.0/25", Vec::new()),
            ]),
            rows(),
            "198.51.100.5",
        );
        assert_eq!(two.source, PeerSource::Observed);
        assert!(
            matches!(&two.local_asn.value, AsnValue::Unknown(r) if r.contains("more than one listen range")),
            "{:?}",
            two.local_asn
        );
        // The provenance lists each session row once.
        assert_eq!(two.spans.len(), 1);
    }

    #[test]
    fn the_local_address_of_an_interface_has_the_family_of_the_peer() {
        let a = |s: &str| s.parse::<IpAddr>().unwrap();
        let i = InterfaceAddresses::from([
            (
                "Loopback0".to_string(),
                (
                    "default".to_string(),
                    vec![a("192.0.2.1"), a("2001:db8::1")],
                ),
            ),
            (
                "Loopback1".to_string(),
                ("default".to_string(), vec![a("192.0.2.2"), a("192.0.2.3")]),
            ),
            (
                "Loopback2".to_string(),
                ("RED".to_string(), vec![a("203.0.113.1")]),
            ),
        ]);
        let v4 = BgpPeer::Address(a("198.51.100.2"));
        let v6 = BgpPeer::Address(a("2001:db8::2"));
        let at = |s: &str, p: &BgpPeer, vrf: &str| local_address(s, &i, p, vrf);
        assert_eq!(at("Loopback0", &v4, "default"), Some(a("192.0.2.1")));
        assert_eq!(at("Loopback0", &v6, "default"), Some(a("2001:db8::1")));
        // No address of the family, more than one, another VRF, a range.
        assert_eq!(at("Loopback1", &v6, "default"), None);
        assert_eq!(at("Loopback1", &v4, "default"), None);
        assert_eq!(at("Loopback2", &v4, "default"), None);
        assert_eq!(at("Loopback2", &v4, "RED"), Some(a("203.0.113.1")));
        let range = BgpPeer::Range("198.51.100.0/24".parse().unwrap());
        assert_eq!(at("Loopback0", &range, "default"), None);
        assert_eq!(at("192.0.2.9", &v4, "default"), Some(a("192.0.2.9")));
        assert_eq!(at("192.0.2.9", &v6, "default"), None);
    }

    #[test]
    fn the_names_of_the_families() {
        assert_eq!(
            family(&["ipv4", "unicast"]).as_deref(),
            Some("ipv4-unicast")
        );
        assert_eq!(family(&["ipv4"]).as_deref(), Some("ipv4-unicast"));
        assert_eq!(family(&["vpnv4", "unicast"]).as_deref(), Some("ipv4-vpn"));
        assert_eq!(family(&["l2vpn", "evpn"]).as_deref(), Some("l2vpn-evpn"));
        assert_eq!(family(&["l2vpn-evpn"]).as_deref(), Some("l2vpn-evpn"));
        assert_eq!(family(&["rtfilter", "unicast"]), None);
    }
}
