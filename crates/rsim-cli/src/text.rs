//! The text output for persons. The text has no stability rule.

use std::fmt::Write;

use crate::error::QueryError;
use crate::json::{
    AnswerJson, BranchJson, DelayJson, DevicesOut, FieldJson, HeaderJson, PacketSetJson,
    PathAnswerOut, QueryJson, SetAnswerOut, StepOut, SummaryResultJson, TopologiesOut,
    TraceStepJson, VerdictJson,
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
        let _ = writeln!(s, "endpoint {} {}", e.endpoint, e.addresses.join(", "));
    }
    for a in &d.attachments {
        let _ = writeln!(
            s,
            "attachment {} {} at {}/{} ({})",
            a.address, a.host, a.device, a.interface, a.kind
        );
    }
    for e in &d.edge_interfaces {
        let _ = writeln!(
            s,
            "edge interface {}/{} {}",
            e.device,
            e.interface,
            e.networks.join(", ")
        );
    }
    s
}

pub fn path(p: &PathAnswerOut) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "topology {}, source {}, destination {}",
        p.topology, p.query.source_ip, p.query.destination_ip
    );
    answer(&mut s, &p.answer, "");
    replies(&mut s, &p.answer);
    s
}

fn replies(s: &mut String, a: &AnswerJson) {
    for r in &a.replies {
        let _ = write!(s, "reply of branch {}:", r.forward_branch);
        match (&r.answer, &r.not_run_reason) {
            (Some(a), _) => {
                let _ = writeln!(s);
                answer(s, a, "  ");
            }
            (None, Some(why)) => {
                let _ = writeln!(s, " not run, {why}");
            }
            (None, None) => {
                let _ = writeln!(s, " not run");
            }
        }
    }
}

pub fn set(p: &SetAnswerOut) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "topology {}, set query, source {}, destination {}",
        p.topology,
        p.query.source_ip.as_deref().unwrap_or("all"),
        p.query.destination_ip.as_deref().unwrap_or("all")
    );
    answer(&mut s, &p.answer, "");
    replies(&mut s, &p.answer);
    s
}

pub fn step(st: &StepOut) -> String {
    let mut s = String::new();
    let (src, dst) = match &st.query {
        QueryJson::Path(q) => (q.source_ip.clone(), q.destination_ip.clone()),
        QueryJson::Set(q) => (
            q.source_ip.clone().unwrap_or_else(|| "all".into()),
            q.destination_ip.clone().unwrap_or_else(|| "all".into()),
        ),
    };
    let _ = write!(
        s,
        "topology {}, source {src}, destination {dst}",
        st.topology
    );
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
    let _ = writeln!(s, "{ind}input {}", packets(&a.input));
    for i in &a.ingress {
        match (&i.device, &i.interface, &i.reason) {
            (Some(d), Some(f), _) => {
                let _ = write!(
                    s,
                    "{ind}ingress {d}/{f} by {}",
                    i.resolved_by.unwrap_or("-")
                );
                if !i.host_confirmed {
                    let _ = write!(s, ", host not confirmed");
                }
                let _ = writeln!(s);
            }
            (_, _, Some(r)) => {
                let _ = writeln!(s, "{ind}ingress not found ({}: {})", r.code, r.detail);
            }
            _ => {}
        }
    }
    for part in &a.summary {
        if a.summary.len() == 1 {
            let _ = writeln!(s, "{ind}summary {}", summary(&part.result));
        } else {
            let _ = writeln!(
                s,
                "{ind}summary for {}: {}",
                packets(&part.packets),
                summary(&part.result)
            );
        }
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
    let mut parts: Vec<String> = Vec::new();
    for m in &p.members {
        let h = header(&m.current, &m.original);
        if !parts.contains(&h) {
            parts.push(h);
        }
    }
    parts.join("; ")
}

fn field<T: std::fmt::Display>(f: &FieldJson<T>) -> String {
    match f {
        FieldJson::Known(v) => v.to_string(),
        FieldJson::In(vs) => {
            let items: Vec<String> = vs
                .iter()
                .map(|v| match v {
                    serde_json::Value::Array(a) if a.len() == 2 => {
                        let t = |x: &serde_json::Value| match x {
                            serde_json::Value::String(s) => s.clone(),
                            x => x.to_string(),
                        };
                        if a[0] == a[1] {
                            t(&a[0])
                        } else {
                            format!("{}-{}", t(&a[0]), t(&a[1]))
                        }
                    }
                    serde_json::Value::String(s) => s.clone(),
                    v => v.to_string(),
                })
                .collect();
            format!("{{{}}}", items.join(","))
        }
        FieldJson::Unknown => "?".to_string(),
        FieldJson::Absent => "-".to_string(),
        FieldJson::Original => "original".to_string(),
    }
}

/// The current header. A field with the value of the original request
/// shows the original values. An encapsulated header shows its inner
/// header after the outer header.
fn header(h: &HeaderJson, o: &HeaderJson) -> String {
    fn pick<T: std::fmt::Display>(c: &FieldJson<T>, o: &FieldJson<T>) -> String {
        match c {
            FieldJson::Original => field(o),
            c => field(c),
        }
    }
    let line = format!(
        "{} {}:{} > {}:{}",
        pick(&h.iana_number, &o.iana_number),
        pick(&h.source_ip, &o.source_ip),
        pick(&h.source_port, &o.source_port),
        pick(&h.destination_ip, &o.destination_ip),
        pick(&h.destination_port, &o.destination_port)
    );
    match &h.inner {
        Some(i) => format!("{line} [inner {}]", header(i, o)),
        None => line,
    }
}
