//! The claims of a loaded twin: the evidence rows of each claim on its
//! scope.

use std::any::Any;
use std::collections::BTreeSet;

use rsim_contract::claim::{self, ClaimArgs, ClaimOut, ClaimResult, ClaimsOut, Evidence};
use rsim_core::{NetFunction, SourceSpan, VerdictKind};
use rsim_engine::{Answer, ReplyResult};
use rsim_functions::{Egress, LinkFacts, PortEgress};
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

fn speed_duplex(subject: String, facts: Option<&LinkFacts>) -> Evidence {
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
    let mut evidence = Vec::new();
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
        "bgp-peers-up" => evidence.push(Evidence {
            subject: format!("the BGP peers of the scope {scope}"),
            result: ClaimResult::Unknown,
            expected: Some(json!("established")),
            observed: None,
            reason: "not_collected".into(),
            detail: "no collector collects the BGP session state".into(),
            provenance: Vec::new(),
        }),
        _ => {}
    }
    let (result, counts) = claim::combine(&evidence);
    Ok(ClaimOut {
        rsim_json: VERSION,
        kind: "claim".into(),
        topology: topology.to_string(),
        twin: t.identity.clone(),
        claim: def.name.to_string(),
        scope: scope.into(),
        result,
        counts,
        evidence,
    })
}
