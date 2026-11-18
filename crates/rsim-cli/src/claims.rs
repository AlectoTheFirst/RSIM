//! The claims of a loaded twin: the evidence rows of each claim on its
//! scope.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};

use rsim_contract::claim::{self, ClaimArgs, ClaimOut, ClaimResult, ClaimsOut, Evidence};
use rsim_contract::twin::TwinJson;
use rsim_core::{NetFunction, SourceSpan, VerdictKind};
use rsim_engine::{Answer, ReplyResult};
use rsim_functions::{Egress, LinkFacts, PortEgress};
use rsim_ingest::bgp::Outcome;
use rsim_ingest::links::{
    AddressValue, Asn, AsnValue, BgpFar, BgpPeer, BgpPeerFact, FarSide, PeerSource,
};
use serde_json::{Value, json};

use crate::commands::{self, Loaded};
use crate::error::{ErrorCode, QueryError};
use crate::json::VERSION;

/// The claim catalog.
pub fn catalog() -> ClaimsOut {
    ClaimsOut {
        rsim_json: VERSION,
        kind: "claims".into(),
        claims: claim::CLAIMS,
    }
}

fn spans(s: &[SourceSpan]) -> Vec<String> {
    s.iter()
        .map(|s| format!("{}:{}-{}", s.file, s.first_line, s.last_line))
        .collect()
}

fn invalid(d: String) -> QueryError {
    QueryError::new(ErrorCode::InvalidQuery, d)
}

/// The links of the functions that `keep` selects: the subject, the
/// device and the link facts, if the link has them.
fn links<'a>(
    t: &'a Loaded,
    keep: &dyn Fn(&dyn NetFunction) -> bool,
) -> Vec<(String, Option<&'a LinkFacts>)> {
    let mut out = Vec::new();
    for f in t.functions() {
        if !keep(f.as_ref()) {
            continue;
        }
        let any: &dyn Any = f.as_ref();
        if let Some(e) = any.downcast_ref::<Egress>() {
            if let Some(l) = &e.link
                && let Some(peer) = &l.peer
            {
                out.push((format!("{} to {peer}", f.id()), l.facts.as_ref()));
            }
        } else if let Some(p) = any.downcast_ref::<PortEgress>() {
            for peer in &p.peers {
                out.push((format!("{} to {}", f.id(), peer.target), peer.link.as_ref()));
            }
        }
    }
    out
}

pub(crate) fn speed_duplex(subject: String, facts: Option<&LinkFacts>) -> Evidence {
    let (local, remote) = match facts {
        Some(f) => (Some(&f.local), f.remote.as_ref()),
        None => (None, None),
    };
    let end = |e: Option<&rsim_functions::LinkEnd>| {
        e.map_or(
            Value::Null,
            |e| json!({"speed_mbps": e.speed_mbps, "full_duplex": e.full_duplex}),
        )
    };
    let pair = |a: Option<u64>, b: Option<u64>| (a, b);
    let (ls, rs) = pair(
        local.and_then(|e| e.speed_mbps),
        remote.and_then(|e| e.speed_mbps),
    );
    let (ld, rd) = (
        local.and_then(|e| e.full_duplex),
        remote.and_then(|e| e.full_duplex),
    );
    let mut mismatch = Vec::new();
    if let (Some(a), Some(b)) = (ls, rs)
        && a != b
    {
        mismatch.push(format!("speed {a} Mbit/s and {b} Mbit/s"));
    }
    if let (Some(a), Some(b)) = (ld, rd)
        && a != b
    {
        mismatch.push("full duplex and half duplex".to_string());
    }
    let known = ls.is_some() && rs.is_some() && ld.is_some() && rd.is_some();
    let (result, reason, detail) = if !mismatch.is_empty() {
        (ClaimResult::Refuted, "mismatch", mismatch.join("; "))
    } else if known {
        (ClaimResult::Confirmed, "match", String::new())
    } else {
        (
            ClaimResult::Unknown,
            "not_collected",
            "the speed or the duplex of an end is not collected".to_string(),
        )
    };
    Evidence {
        subject,
        result,
        expected: Some(end(local)),
        observed: Some(end(remote)),
        reason: reason.into(),
        detail,
        provenance: facts.map(|f| spans(&f.spans())).unwrap_or_default(),
    }
}

/// The functions of the branches of an answer and of its replies.
fn path_functions(a: &Answer, out: &mut BTreeSet<String>) {
    for b in a.branches() {
        out.extend(b.steps.iter().map(|s| s.function.to_string()));
    }
    for r in &a.replies {
        if let ReplyResult::Ran(x) = &r.result {
            path_functions(x, out);
        }
    }
}

fn no_unknown(a: &Answer, prefix: &str, out: &mut Vec<Evidence>) {
    // A summary part can be unknown when each of its branches ends in a
    // verdict, for example when the result depends on a field that the
    // query does not state.
    for (i, p) in a.summary.iter().enumerate() {
        let (kind, result) = match &p.summary {
            rsim_engine::Summary::Same(v) => (v.kind(), v.kind() == VerdictKind::Unknown),
            rsim_engine::Summary::SameKind(k) => (*k, *k == VerdictKind::Unknown),
            rsim_engine::Summary::DependsOnPath => continue,
        };
        if result {
            let detail = match p.summary.verdict() {
                Some(rsim_core::Verdict::Unknown(r)) => format!("{:?}: {}", r.code, r.detail),
                _ => String::new(),
            };
            out.push(Evidence {
                subject: format!("{prefix}summary part {i}"),
                result: ClaimResult::Refuted,
                expected: Some(json!("deliver or drop")),
                observed: Some(json!(format!("{kind:?}").to_lowercase())),
                reason: "unknown".into(),
                detail,
                provenance: Vec::new(),
            });
        }
    }
    for b in a.branches() {
        let (result, reason, detail) = match b.verdict {
            rsim_core::Verdict::Unknown(r) => (
                ClaimResult::Refuted,
                "unknown",
                format!("{:?}: {}", r.code, r.detail),
            ),
            v => (ClaimResult::Confirmed, "match", format!("{:?}", v.kind())),
        };
        out.push(Evidence {
            subject: format!("{prefix}branch {}", b.index),
            result,
            expected: Some(json!("deliver or drop")),
            observed: Some(json!(match b.verdict.kind() {
                VerdictKind::Deliver => "deliver",
                VerdictKind::Drop => "drop",
                VerdictKind::Unknown => "unknown",
            })),
            reason: reason.into(),
            detail,
            provenance: b
                .steps
                .last()
                .map(|s| spans(&s.provenance))
                .unwrap_or_default(),
        });
    }
    for r in &a.replies {
        if let ReplyResult::Ran(x) = &r.result {
            no_unknown(
                x,
                &format!("{prefix}reply of branch {} ", r.forward_branch),
                out,
            );
        }
    }
}

/// The BGP peer facts of each device.
pub type BgpFacts = BTreeMap<String, Vec<BgpPeerFact>>;

/// The neighbours that a BGP claim leaves out of its rows.
#[derive(Default)]
struct LeftOut {
    shutdown: usize,
    outside: usize,
}

impl LeftOut {
    /// The detail of the claim: the words `no BGP neighbour in scope` for a
    /// claim with no row, and the number of neighbours left out.
    fn detail(&self, rows: usize) -> String {
        let mut parts = Vec::new();
        if rows == 0 {
            parts.push("no BGP neighbour in scope".to_string());
        }
        if self.shutdown > 0 || self.outside > 0 {
            parts.push(format!(
                "left out: {} with shutdown, {} with the peer outside the twin",
                self.shutdown, self.outside
            ));
        }
        parts.join("; ")
    }
}

fn bgp_subject(f: &BgpPeerFact) -> String {
    format!("{} vrf {} neighbour {}", f.device, f.vrf, f.peer)
}

/// The spans of a fact, of its route lookup and of its session rows, each
/// once.
fn bgp_spans(f: &BgpPeerFact, out: &mut Vec<SourceSpan>) {
    let rows = f.sessions.iter().map(|r| &r.span);
    for s in f.spans.iter().chain(&f.source_spans).chain(rows) {
        if !out.contains(s) {
            out.push(s.clone());
        }
    }
}

/// The state words of the session rows of a fact.
fn states(f: &BgpPeerFact) -> Vec<String> {
    f.sessions.iter().map(|r| r.state.clone()).collect()
}

/// The rows of the claim `bgp-peers-up` on the devices that `keep`
/// selects: one for each configured neighbour and each dynamic peer of a
/// listen range, and the detail of the claim.
pub fn bgp_peers_up(bgp: &BgpFacts, keep: &dyn Fn(&str) -> bool) -> (Vec<Evidence>, String) {
    let mut left = LeftOut::default();
    let mut out = Vec::new();
    let gap = "an inheritance gap can hide a shutdown line";
    for f in bgp
        .iter()
        .filter(|(d, _)| keep(d))
        .flat_map(|(_, f)| f)
        .filter(|f| matches!(f.source, PeerSource::Configured | PeerSource::Dynamic(_)))
    {
        if f.shutdown == Some(true) {
            left.shutdown += 1;
            continue;
        }
        if f.far == Some(BgpFar::Outside) {
            left.outside += 1;
            continue;
        }
        let section = f.section.outcome;
        let (result, reason, detail) = if let BgpPeer::Interface(i) = &f.peer {
            (
                ClaimResult::Unknown,
                "not_collected",
                format!("the session rows of the neighbour of the interface {i} are not joined"),
            )
        } else if !f.sessions.is_empty() && f.sessions.iter().all(|r| r.established) {
            (ClaimResult::Confirmed, "match", String::new())
        } else if !f.sessions.is_empty() {
            let words = states(f).join(", ");
            match f.shutdown {
                None => (
                    ClaimResult::Unknown,
                    "unknown",
                    format!("state {words}; {gap}"),
                ),
                Some(_) => (ClaimResult::Refuted, "mismatch", format!("state {words}")),
            }
        } else if matches!(
            section,
            Outcome::NotCaptured | Outcome::Failed | Outcome::Partial
        ) {
            let mut d = format!("not collected: the session section is {}", section.name());
            if let Some(why) = &f.section.detail {
                d.push_str(&format!("; {why}"));
            }
            (ClaimResult::Unknown, "not_collected", d)
        } else if !f.in_scope() {
            let families = if f.families.is_empty() {
                "no activated address family".to_string()
            } else {
                f.families.iter().cloned().collect::<Vec<_>>().join(", ")
            };
            (
                ClaimResult::Unknown,
                "not_collected",
                format!(
                    "address family not collected: the session section does not cover VRF {} with {families}",
                    f.vrf
                ),
            )
        } else if f.shutdown.is_none() {
            (
                ClaimResult::Unknown,
                "unknown",
                format!("not in session table; {gap}"),
            )
        } else {
            (
                ClaimResult::Refuted,
                "mismatch",
                "not in session table".to_string(),
            )
        };
        let mut provenance = Vec::new();
        bgp_spans(f, &mut provenance);
        out.push(Evidence {
            subject: bgp_subject(f),
            result,
            expected: Some(json!("established")),
            observed: (!f.sessions.is_empty()).then(|| json!(states(f))),
            reason: reason.into(),
            detail,
            provenance: spans(&provenance),
        });
    }
    let detail = left.detail(out.len());
    (out, detail)
}

fn asn_json(a: &Asn) -> Value {
    match &a.value {
        AsnValue::Known(v) => json!(v),
        AsnValue::Unknown(r) => json!({ "unknown": r }),
    }
}

/// The findings of the comparison of the 2 sides of a peering.
#[derive(Default)]
struct Findings {
    refuted: Vec<String>,
    unknown: Vec<String>,
    notes: Vec<String>,
}

impl Findings {
    /// The AS that `x` expects of its peer against the AS that `y`
    /// presents to it.
    fn asn(&mut self, x: &BgpPeerFact, y: &BgpPeerFact) {
        let list = |v: &[u32]| {
            v.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" or ")
        };
        match (&x.peer_asn.value, &y.local_asn.value) {
            (AsnValue::Known(e), AsnValue::Known(p)) => {
                if !e.iter().any(|a| p.contains(a)) {
                    self.refuted.push(format!(
                        "asn mismatch: {} expects the AS {} of {}, which presents the AS {}",
                        x.device,
                        list(e),
                        y.device,
                        list(p)
                    ));
                }
            }
            (AsnValue::Unknown(r), _) => self
                .unknown
                .push(format!("the AS of the peer of {}: {r}", x.device)),
            (_, AsnValue::Unknown(r)) => self
                .unknown
                .push(format!("the AS that {} presents: {r}", y.device)),
        }
    }

    fn families(&mut self, a: &BgpPeerFact, b: &BgpPeerFact) {
        let list = |s: &BTreeSet<String>| s.iter().cloned().collect::<Vec<_>>().join(", ");
        if a.families.is_empty() || b.families.is_empty() {
            let d = if a.families.is_empty() { a } else { b };
            self.unknown.push(format!(
                "{} activates no address family for the peer",
                d.device
            ));
        } else if a.families.is_disjoint(&b.families) {
            self.refuted.push(format!(
                "no common address family: {} has {}, {} has {}",
                a.device,
                list(&a.families),
                b.device,
                list(&b.families)
            ));
        } else if a.families != b.families {
            self.notes.push(format!(
                "the address families differ: {} has {}, {} has {}",
                a.device,
                list(&a.families),
                b.device,
                list(&b.families)
            ));
        }
    }

    /// The session states and the prefix counts of the 2 sides, whose reads
    /// are seconds apart.
    fn sessions(&mut self, a: &BgpPeerFact, b: &BgpPeerFact) {
        let up = |f: &BgpPeerFact| {
            (!f.sessions.is_empty()).then(|| f.sessions.iter().all(|r| r.established))
        };
        if let (Some(x), Some(y)) = (up(a), up(b))
            && x != y
        {
            self.unknown.push(format!(
                "the session states differ: {} has {}, {} has {}; the reads are seconds apart",
                a.device,
                states(a).join(", "),
                b.device,
                states(b).join(", ")
            ));
        }
        let sum = |f: &BgpPeerFact, c: fn(&rsim_ingest::bgp::SessionRow) -> Option<u64>| {
            let v: Vec<u64> = f.sessions.iter().filter_map(c).collect();
            (!v.is_empty()).then(|| v.iter().sum::<u64>())
        };
        if let (Some(sent), Some(received)) =
            (sum(a, |r| r.prefixes_sent), sum(b, |r| r.prefixes_received))
            && b.policy_in.is_none()
            && sent != received
        {
            self.unknown.push(format!(
                "counts sampled at different times: {} sent {sent} prefixes, {} received {received}",
                a.device, b.device
            ));
        }
        if b.shutdown == Some(true) {
            self.notes
                .push(format!("the neighbour of {} has shutdown", b.device));
        }
    }
}

/// The rows of the claim `bgp-peers-agree` on the devices that `keep`
/// selects: one for each configured neighbour whose peer address is an
/// address of another device of the twin, and the detail of the claim.
pub fn bgp_peers_agree(bgp: &BgpFacts, keep: &dyn Fn(&str) -> bool) -> (Vec<Evidence>, String) {
    let mut left = LeftOut::default();
    let mut out = Vec::new();
    for a in bgp
        .iter()
        .filter(|(d, _)| keep(d))
        .flat_map(|(_, f)| f)
        .filter(|f| f.source == PeerSource::Configured)
    {
        let Some(far) = &a.far else {
            continue;
        };
        if a.shutdown == Some(true) {
            left.shutdown += 1;
            continue;
        }
        let mut f = Findings::default();
        let mut provenance = Vec::new();
        bgp_spans(a, &mut provenance);
        let source = match &a.source_address {
            AddressValue::Known(x) => x.to_string(),
            AddressValue::Unknown(_) => "the source address".to_string(),
        };
        let mut observed = None;
        match far {
            BgpFar::Outside => {
                left.outside += 1;
                continue;
            }
            BgpFar::Ambiguous(at) => {
                let at: Vec<String> = at.iter().map(|(d, v)| format!("{d} vrf {v}")).collect();
                f.unknown.push(format!(
                    "the peer address is an address of the device itself or of more than one device: {}",
                    at.join(", ")
                ));
            }
            BgpFar::Device { device, vrf, side } => {
                let far_fact = |i: usize| bgp.get(device).and_then(|v| v.get(i));
                observed = Some(json!({"device": device, "vrf": vrf}));
                match side {
                    FarSide::Unresolved(r) => f.unknown.push(r.clone()),
                    FarSide::Absent { read: true } => f.refuted.push(format!(
                        "one-sided peering: {device} has no neighbour and no listen range for {source} in VRF {vrf}"
                    )),
                    FarSide::Absent { read: false } => f.unknown.push(format!(
                        "{device} has no neighbour and no listen range for {source} in VRF {vrf}, and its BGP config is not read in full"
                    )),
                    FarSide::OtherAddress(i) => match far_fact(*i) {
                        Some(b) => {
                            bgp_spans(b, &mut provenance);
                            observed = Some(
                                json!({"device": device, "vrf": vrf, "peer": b.peer.to_string()}),
                            );
                            f.refuted.push(format!(
                                "source address mismatch: the neighbour of {device} is {}, the source address of {} is {source}",
                                b.peer, a.device
                            ));
                        }
                        None => f.unknown.push(format!("{device} has no such BGP peer")),
                    },
                    FarSide::Paired(i) => match far_fact(*i) {
                        Some(b) => {
                            bgp_spans(b, &mut provenance);
                            let mut o = json!({
                                "device": device,
                                "vrf": vrf,
                                "peer": b.peer.to_string(),
                                "local_asn": asn_json(&b.local_asn),
                                "peer_asn": asn_json(&b.peer_asn),
                            });
                            if let PeerSource::Dynamic(r) = &b.source {
                                o["listen_range"] = json!(r.to_string());
                            }
                            observed = Some(o);
                            f.asn(a, b);
                            f.asn(b, a);
                            f.families(a, b);
                            f.sessions(a, b);
                        }
                        None => f.unknown.push(format!("{device} has no such BGP peer")),
                    },
                }
            }
        }
        let (result, reason) = if !f.refuted.is_empty() {
            (ClaimResult::Refuted, "mismatch")
        } else if !f.unknown.is_empty() {
            (ClaimResult::Unknown, "unknown")
        } else {
            (ClaimResult::Confirmed, "match")
        };
        let detail: Vec<String> = f
            .refuted
            .into_iter()
            .chain(f.unknown)
            .chain(f.notes)
            .collect();
        out.push(Evidence {
            subject: bgp_subject(a),
            result,
            expected: Some(json!({
                "source": match &a.source_address {
                    AddressValue::Known(x) => json!(x.to_string()),
                    AddressValue::Unknown(r) => json!({ "unknown": r }),
                },
                "local_asn": asn_json(&a.local_asn),
                "peer_asn": asn_json(&a.peer_asn),
            })),
            observed,
            reason: reason.into(),
            detail: detail.join("; "),
            provenance: spans(&provenance),
        });
    }
    let detail = left.detail(out.len());
    (out, detail)
}

/// The output of a claim from its rows and its detail.
pub fn out(
    topology: &str,
    twin: TwinJson,
    claim: &str,
    scope: &str,
    evidence: Vec<Evidence>,
    detail: String,
) -> ClaimOut {
    let (result, counts) = claim::combine(&evidence);
    ClaimOut {
        rsim_json: VERSION,
        kind: "claim".into(),
        topology: topology.to_string(),
        twin,
        claim: claim.to_string(),
        scope: scope.into(),
        result,
        counts,
        detail,
        evidence,
    }
}

/// Runs a claim on its scope: a query answer with `query`, a set of
/// devices with `devices`, else the whole twin.
pub fn run(topology: &str, t: &Loaded, args: &ClaimArgs) -> Result<ClaimOut, QueryError> {
    let def = claim::claim(&args.claim).ok_or_else(|| {
        let names: Vec<&str> = claim::CLAIMS.iter().map(|c| c.name).collect();
        invalid(format!(
            "{} is not a claim; the claims are {}",
            args.claim,
            names.join(", ")
        ))
    })?;
    let scope = match (&args.query, &args.devices) {
        (Some(_), Some(_)) => {
            return Err(invalid("give a query or devices, not both".into()));
        }
        (Some(_), None) => "query",
        (None, Some(_)) => "devices",
        (None, None) => "twin",
    };
    if !def.scopes.contains(&scope) {
        return Err(invalid(format!(
            "{} runs on the scopes {}, not {scope}",
            def.name,
            def.scopes.join(", ")
        )));
    }
    let answer = match &args.query {
        Some(q) => {
            let mut q = q.clone();
            q.insert("topology".into(), json!(topology));
            let input = crate::args::query(&q, &[])?;
            Some(commands::run(&input, t)?)
        }
        None => None,
    };
    let on_path: Option<BTreeSet<String>> = answer.as_ref().map(|a| {
        let mut s = BTreeSet::new();
        path_functions(a, &mut s);
        s
    });
    let devices: Option<BTreeSet<&str>> = args
        .devices
        .as_ref()
        .map(|d| d.iter().map(String::as_str).collect());
    let keep = |f: &dyn NetFunction| -> bool {
        on_path.as_ref().is_none_or(|s| s.contains(f.id().as_str()))
            && devices
                .as_ref()
                .is_none_or(|d| f.device().is_some_and(|x| d.contains(x.as_str())))
    };
    // The devices of the scope for the BGP claims: the devices of the
    // functions on the paths of the answer, the given devices, or each
    // device.
    let path_devices: Option<BTreeSet<String>> = on_path.as_ref().map(|s| {
        t.functions()
            .filter(|f| s.contains(f.id().as_str()))
            .filter_map(|f| f.device().map(|d| d.to_string()))
            .collect()
    });
    let in_scope = |d: &str| {
        path_devices.as_ref().is_none_or(|s| s.contains(d))
            && devices.as_ref().is_none_or(|s| s.contains(d))
    };
    let mut evidence = Vec::new();
    let mut detail = String::new();
    match def.name {
        "link-speed-duplex" => {
            for (subject, facts) in links(t, &keep) {
                evidence.push(speed_duplex(subject, facts));
            }
        }
        "no-unknown" => {
            if let Some(a) = &answer {
                no_unknown(a, "", &mut evidence);
            }
        }
        "bgp-peers-up" => (evidence, detail) = bgp_peers_up(&t.bgp, &in_scope),
        "bgp-peers-agree" => (evidence, detail) = bgp_peers_agree(&t.bgp, &in_scope),
        _ => {}
    }
    Ok(out(
        topology,
        t.identity.clone(),
        def.name,
        scope,
        evidence,
        detail,
    ))
}
