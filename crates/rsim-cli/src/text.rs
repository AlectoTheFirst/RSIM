//! The text output for persons. The text has no stability rule.

use std::fmt::Write;

use crate::error::QueryError;
use crate::json::{
    AnswerJson, BranchJson, DelayJson, DevicesOut, FieldJson, HeaderJson, PacketSetJson,
    PathAnswerOut, StepOut, SummaryResultJson, TopologiesOut, TraceStepJson, VerdictJson,
};

pub fn topologies(t: &TopologiesOut) -> String {
    let mut s = String::new();
    for n in &t.topologies {
        let _ = writeln!(s, "{n}");
    }
    s
}

pub fn devices(d: &DevicesOut) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "topology {}", d.topology);
    for dev in &d.devices {
        let _ = writeln!(s, "device {}", dev.device);
        for f in &dev.functions {
            let _ = writeln!(s, "  {:<40} {}", f.function, f.kind);
        }
    }
    for e in &d.endpoints {
        let _ = writeln!(
            s,
            "endpoint {} {} at {}",
            e.endpoint,
            e.addresses.join(", "),
            e.attachment
        );
    }
    s
}

pub fn path(p: &PathAnswerOut) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "topology {}, from {}", p.topology, p.query.from);
    answer(&mut s, &p.answer, "");
    for r in &p.answer.replies {
        let _ = write!(s, "reply of branch {}:", r.forward_branch);
        match (&r.answer, &r.not_run_reason) {
            (Some(a), _) => {
                let _ = writeln!(s);
                answer(&mut s, a, "  ");
            }
            (None, Some(why)) => {
                let _ = writeln!(s, " not run, {why}");
            }
            (None, None) => {
                let _ = writeln!(s, " not run");
            }
        }
    }
    s
}

pub fn step(st: &StepOut) -> String {
    let mut s = String::new();
    let _ = write!(s, "topology {}, from {}", st.topology, st.query.from);
    if let Some(r) = st.reply_of {
        let _ = write!(s, ", reply of branch {r}");
    }
    let _ = writeln!(s, ", branch {}, step {}", st.branch, st.step);
    let t = &st.trace_step;
    let _ = writeln!(s, "function   {} ({})", t.function, t.kind);
    let _ = writeln!(s, "device     {}", t.device.as_deref().unwrap_or("-"));
    let _ = writeln!(s, "input      {}", packets(&t.input));
    let _ = writeln!(s, "output     {}", packets(&t.output));
    let _ = writeln!(s, "outcome    {}", outcome(t));
    let _ = writeln!(s, "reason     {}: {}", t.reason.code, t.reason.detail);
    let _ = writeln!(s, "delay      {}", delay(&t.delay));
    for m in &t.delay.missing {
        let _ = writeln!(s, "no data    {} {}", m.kind, m.function);
    }
    for p in &t.provenance {
        let _ = writeln!(s, "source     {}:{}-{}", p.file, p.first_line, p.last_line);
    }
    if let Some(a) = &t.alternative {
        let _ = writeln!(
            s,
            "choice     {} alternative {} of {} ({})",
            a.choice,
            a.index + 1,
            a.count,
            a.label
        );
    }
    if let Some(r) = &t.rate_condition {
        let _ = writeln!(
            s,
            "rate       {} exceed {} evaluated {}",
            r.function, r.exceed_action, r.evaluated
        );
    }
    let _ = writeln!(s, "rib guard  {}", t.rib_guard);
    s
}

pub fn error(e: &QueryError) -> String {
    format!("{e}\n")
}

fn answer(s: &mut String, a: &AnswerJson, ind: &str) {
    let _ = writeln!(s, "{ind}packet {}", packets(&a.input));
    for part in &a.summary {
        let _ = writeln!(s, "{ind}summary {}", summary(&part.result));
    }
    for b in &a.branches {
        branch(s, b, ind);
    }
}

fn branch(s: &mut String, b: &BranchJson, ind: &str) {
    let _ = writeln!(
        s,
        "{ind}branch {}: {}, delay {}",
        b.index,
        verdict(&b.verdict),
        delay(&b.delay)
    );
    for t in &b.steps {
        let _ = writeln!(
            s,
            "{ind}  {:>3} {:<14} {:<36} {:<8} {}: {}",
            t.index,
            t.device.as_deref().unwrap_or("-"),
            t.function,
            t.outcome.kind,
            t.reason.code,
            t.reason.detail
        );
    }
}

fn summary(r: &SummaryResultJson) -> String {
    match (&r.verdict, &r.verdict_kind) {
        (Some(v), _) => format!("same on each path, {}", verdict(v)),
        (None, Some(k)) => format!("{k} on each path, with different details"),
        (None, None) => "depends on the path".to_string(),
    }
}

fn verdict(v: &VerdictJson) -> String {
    let mut s = v.kind.clone();
    if let Some(d) = &v.destination {
        if let Some(e) = &d.endpoint {
            let _ = write!(s, " to endpoint {e}");
        }
        if let Some(dev) = &d.device {
            let _ = write!(s, " to device {dev}");
        }
    }
    if let Some(r) = &v.reason {
        let _ = write!(s, " ({}: {})", r.code, r.detail);
    }
    s
}

fn outcome(t: &TraceStepJson) -> String {
    let mut s = t.outcome.kind.to_string();
    if let Some(n) = &t.outcome.next {
        let _ = write!(s, " to {n}");
    }
    if let Some(d) = &t.outcome.destination {
        if let Some(e) = &d.endpoint {
            let _ = write!(s, " to endpoint {e}");
        }
        if let Some(dev) = &d.device {
            let _ = write!(s, " to device {dev}");
        }
    }
    s
}

fn delay(d: &DelayJson) -> String {
    let mut s = format!("{} ns", d.known_ns);
    if d.lower_bound {
        let _ = write!(s, " or more, components with no data: {}", d.missing.len());
    }
    s
}

fn packets(p: &PacketSetJson) -> String {
    let parts: Vec<String> = p.members.iter().map(|m| header(&m.current)).collect();
    parts.join("; ")
}

fn field<T: std::fmt::Display>(f: &FieldJson<T>) -> String {
    match f {
        FieldJson::Known(v) => v.to_string(),
        FieldJson::Unstated => "*".to_string(),
        FieldJson::Unknown => "?".to_string(),
        FieldJson::Absent => "-".to_string(),
    }
}

fn header(h: &HeaderJson) -> String {
    format!(
        "{} {}:{} > {}:{}",
        field(&h.protocol),
        field(&h.src_ip),
        field(&h.src_port),
        field(&h.dst_ip),
        field(&h.dst_port)
    )
}
