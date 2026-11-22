//! The JSON output, version 2: the types of `rsim-contract` and their
//! conversions from the engine values.

use std::fmt::Debug;

use rsim_core::{
    Alternative, Attr, Delay, DelayGap, Destination, EncapDesc, FieldValue, FloodCopy, HeaderDesc,
    HeaderField, Outcome, PacketSet, QosView, RateCondition, Reason, ReasonCode, SourceSpan,
    TraceStep, Uniform, Values, Verdict, VerdictKind, bits,
};
use rsim_engine::{Answer, BranchView, Ingress, IngressBasis, Mode, ReplyResult, Summary};

pub use rsim_contract::json::*;

/// Makes a JSON output value from an engine value.
pub trait FromEngine<S: ?Sized> {
    fn new(s: &S) -> Self;
}

/// The Rust name of an enumeration value in snake case.
pub fn snake<T: Debug>(v: &T) -> String {
    let name = format!("{v:?}");
    let mut out = String::with_capacity(name.len() + 4);
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

pub fn ingress_json(packets: &PacketSet, i: &Ingress) -> IngressJson {
    let mut j = IngressJson {
        packets: PacketSetJson::new(packets),
        found: false,
        device: None,
        interface: None,
        function: None,
        resolved_by: None,
        network: None,
        host_confirmed: i.host_confirmed(),
        provenance: Vec::new(),
        reason: None,
    };
    match i {
        Ingress::Found {
            device,
            interface,
            function,
            basis,
        } => {
            j.found = true;
            j.device = Some(device.to_string());
            j.interface = Some(interface.to_string());
            j.function = Some(function.to_string());
            let (by, spans) = match basis {
                IngressBasis::Explicit => ("explicit", &[][..]),
                IngressBasis::Attachment(s) => ("attachment", s.as_slice()),
                IngressBasis::ConnectedNetwork { network, spans } => {
                    j.network = Some(network.to_string());
                    ("connected_network", spans.as_slice())
                }
                IngressBasis::Reply => ("reply", &[][..]),
            };
            j.resolved_by = Some(by.into());
            j.provenance = spans.iter().map(SpanJson::new).collect();
        }
        Ingress::NotFound(r) => j.reason = Some(ReasonJson::new(r)),
    }
    j
}

impl FromEngine<Answer> for AnswerJson {
    fn new(a: &Answer) -> Self {
        AnswerJson {
            mode: match a.mode {
                Mode::Path => "path".into(),
                Mode::Set => "set".into(),
            },
            input: PacketSetJson::new(&a.input),
            ingress: a
                .runs
                .iter()
                .map(|r| ingress_json(&r.input, &r.ingress))
                .collect(),
            summary: a
                .summary
                .iter()
                .map(|p| PartJson {
                    packets: PacketSetJson::new(&p.packets),
                    result: SummaryResultJson::new(&p.summary),
                })
                .collect(),
            branches: a.branches().iter().map(BranchJson::new).collect(),
            replies: a
                .replies
                .iter()
                .map(|r| match &r.result {
                    ReplyResult::Ran(ans) => ReplyJson {
                        forward_branch: r.forward_branch,
                        ran: true,
                        not_run_reason: None,
                        answer: Some(AnswerJson::new(ans)),
                    },
                    ReplyResult::NotRun(why) => ReplyJson {
                        forward_branch: r.forward_branch,
                        ran: false,
                        not_run_reason: Some(why.clone()),
                        answer: None,
                    },
                })
                .collect(),
        }
    }
}

impl FromEngine<Summary> for SummaryResultJson {
    fn new(s: &Summary) -> Self {
        match s {
            Summary::Same(v) => SummaryResultJson {
                kind: "same".into(),
                verdict: Some(VerdictJson::new(v)),
                verdict_kind: Some(verdict_kind(v.kind())),
            },
            Summary::SameKind(k) => SummaryResultJson {
                kind: "same_kind".into(),
                verdict: None,
                verdict_kind: Some(verdict_kind(*k)),
            },
            Summary::DependsOnPath => SummaryResultJson {
                kind: "depends_on_path".into(),
                verdict: None,
                verdict_kind: None,
            },
        }
    }
}

fn verdict_kind(k: VerdictKind) -> String {
    snake(&k)
}

impl FromEngine<Verdict> for VerdictJson {
    fn new(v: &Verdict) -> Self {
        let (destination, reason) = match v {
            Verdict::Deliver(d) => (Some(DestinationJson::new(d)), None),
            Verdict::Exit(x) => (
                None,
                Some(ReasonJson {
                    code: snake(&ReasonCode::Exited),
                    detail: x.to_string(),
                }),
            ),
            Verdict::Drop(r) | Verdict::Unknown(r) => (None, Some(ReasonJson::new(r))),
        };
        VerdictJson {
            kind: verdict_kind(v.kind()),
            destination,
            reason,
        }
    }
}

impl FromEngine<Destination> for DestinationJson {
    fn new(d: &Destination) -> Self {
        match d {
            Destination::Endpoint(e) => DestinationJson {
                endpoint: Some(e.to_string()),
                device: None,
            },
            Destination::Device(d) => DestinationJson {
                endpoint: None,
                device: Some(d.to_string()),
            },
        }
    }
}

impl FromEngine<Reason> for ReasonJson {
    fn new(r: &Reason) -> Self {
        ReasonJson {
            code: snake(&r.code),
            detail: r.detail.clone(),
        }
    }
}

impl<'a> FromEngine<BranchView<'a>> for BranchJson {
    fn new(b: &BranchView<'a>) -> Self {
        BranchJson {
            index: b.index,
            verdict: VerdictJson::new(b.verdict),
            packets: PacketSetJson::new(b.packets),
            delay: DelayJson::new(&b.delay),
            steps: b
                .steps
                .iter()
                .enumerate()
                .map(|(i, s)| trace_step_json(i, s))
                .collect(),
        }
    }
}

impl FromEngine<Delay> for DelayJson {
    fn new(d: &Delay) -> Self {
        DelayJson {
            known_ns: d.known_ns(),
            lower_bound: d.is_lower_bound(),
            missing: d
                .missing()
                .iter()
                .map(|g| match g {
                    DelayGap::Processing(f) => DelayGapJson {
                        kind: "processing".into(),
                        function: f.to_string(),
                    },
                    DelayGap::Link(f) => DelayGapJson {
                        kind: "link".into(),
                        function: f.to_string(),
                    },
                    DelayGap::Queueing(f) => DelayGapJson {
                        kind: "queueing".into(),
                        function: f.to_string(),
                    },
                })
                .collect(),
        }
    }
}
pub fn trace_step_json(index: usize, s: &TraceStep) -> TraceStepJson {
    TraceStepJson {
        index,
        function: s.function.to_string(),
        kind: snake(&s.kind),
        device: s.device.as_ref().map(|d| d.to_string()),
        input: PacketSetJson::new(&s.input),
        output: PacketSetJson::new(&s.output),
        outcome: OutcomeJson::new(&s.outcome),
        reason: ReasonJson::new(&s.reason),
        provenance: s.provenance.iter().map(SpanJson::new).collect(),
        delay: DelayJson::new(&s.delay),
        alternative: s.alternative.as_ref().map(AlternativeJson::new),
        flood_copy: s.flood_copy.as_ref().map(FloodCopyJson::new),
        qos: QosJson::new(&s.qos),
        rate_condition: s.rate_condition.as_ref().map(RateConditionJson::new),
        rib_guard: snake(&s.rib_guard),
    }
}

impl FromEngine<Outcome> for OutcomeJson {
    fn new(o: &Outcome) -> Self {
        match o {
            Outcome::Forward(f) => OutcomeJson {
                kind: "forward".into(),
                next: Some(f.to_string()),
                destination: None,
            },
            Outcome::Deliver(d) => OutcomeJson {
                kind: "deliver".into(),
                next: None,
                destination: Some(DestinationJson::new(d)),
            },
            Outcome::Exit(_) => OutcomeJson {
                kind: "exit".into(),
                next: None,
                destination: None,
            },
            Outcome::Drop => OutcomeJson {
                kind: "drop".into(),
                next: None,
                destination: None,
            },
            Outcome::Unknown => OutcomeJson {
                kind: "unknown".into(),
                next: None,
                destination: None,
            },
        }
    }
}

impl FromEngine<SourceSpan> for SpanJson {
    fn new(s: &SourceSpan) -> Self {
        SpanJson {
            file: s.file.to_string(),
            first_line: s.first_line,
            last_line: s.last_line,
        }
    }
}

impl FromEngine<Alternative> for AlternativeJson {
    fn new(a: &Alternative) -> Self {
        AlternativeJson {
            choice: a.choice.to_string(),
            key: a.key.clone(),
            index: a.index,
            count: a.count,
            label: a.label.clone(),
        }
    }
}

impl FromEngine<FloodCopy> for FloodCopyJson {
    fn new(f: &FloodCopy) -> Self {
        FloodCopyJson {
            flood: f.flood.to_string(),
            port: f.port.to_string(),
            index: f.index,
            count: f.count,
        }
    }
}

impl FromEngine<QosView> for QosJson {
    fn new(q: &QosView) -> Self {
        QosJson {
            dscp: uniform(&q.dscp),
            ecn: uniform(&q.ecn),
            traffic_class: attr(&q.traffic_class),
            drop_precedence: attr(&q.drop_precedence),
            queue: attr(&q.queue),
        }
    }
}

fn uniform(u: &Uniform<FieldValue<u8>>) -> UniformJson {
    match u {
        Uniform::Value(FieldValue::Known(x)) => UniformJson::Value(FieldJson::Known(*x)),
        Uniform::Value(FieldValue::Unknown) => UniformJson::Value(FieldJson::Unknown),
        Uniform::Value(FieldValue::Absent) => UniformJson::Value(FieldJson::Absent),
        // A field with no constraint has all values.
        Uniform::Value(FieldValue::Unstated) | Uniform::Varies => UniformJson::Varies,
        Uniform::None => UniformJson::None,
    }
}

fn attr(a: &Attr<u8>) -> AttrJson {
    match a {
        Attr::Known(v) => AttrJson::Known(*v),
        Attr::Unset => AttrJson::Unset,
        Attr::Unknown => AttrJson::Unknown,
    }
}

impl FromEngine<RateCondition> for RateConditionJson {
    fn new(r: &RateCondition) -> Self {
        RateConditionJson {
            function: r.function.to_string(),
            rate_bps: r.rate_bps,
            exceed_action: r.exceed_action.clone(),
            evaluated: r.evaluated,
        }
    }
}
fn field_json<T>(f: HeaderField, v: &Values, known: impl Fn(u128) -> T) -> FieldJson<T> {
    match v {
        Values::Absent => FieldJson::Absent,
        Values::Unknown => FieldJson::Unknown,
        Values::Original => FieldJson::Original,
        Values::Prefixes(ps) => match ps.as_slice() {
            [one] if one.len() == if one.is_ipv4() { 32 } else { 128 } => {
                FieldJson::Known(known(bits::ip_bits(one.addr())))
            }
            _ => FieldJson::In(
                ps.iter()
                    .map(|p| serde_json::Value::String(p.to_string()))
                    .collect(),
            ),
        },
        Values::Ranges(rs) => match v.single() {
            Some(x) => FieldJson::Known(known(x)),
            None => FieldJson::In(rs.iter().map(|&(lo, hi)| range_json(f, lo, hi)).collect()),
        },
    }
}

/// One range of a field in the `in` form.
fn range_json(f: HeaderField, lo: u128, hi: u128) -> serde_json::Value {
    use serde_json::Value;
    match f {
        HeaderField::SrcMac | HeaderField::DstMac => Value::Array(vec![
            Value::String(mac_text(lo)),
            Value::String(mac_text(hi)),
        ]),
        HeaderField::Fragment => Value::Array(
            (lo..=hi)
                .map(|x| Value::String(fragment_text(x).to_string()))
                .collect(),
        ),
        _ => Value::Array(vec![Value::from(lo as u64), Value::from(hi as u64)]),
    }
}
impl FromEngine<PacketSet> for PacketSetJson {
    fn new(p: &PacketSet) -> Self {
        PacketSetJson {
            members: p
                .describe()
                .iter()
                .map(|m| MemberJson {
                    original: header_json(&m.original, m.original.encap.as_ref(), None),
                    current: header_json(&m.current, m.current.encap.as_ref(), Some(&m.original)),
                })
                .collect(),
        }
    }
}

fn mac_text(x: u128) -> String {
    format!("{:?}", bits::bits_mac(x))
}

fn fragment_text(x: u128) -> &'static str {
    match x {
        bits::FRAGMENT_UNFRAGMENTED => "unfragmented",
        bits::FRAGMENT_FIRST => "first",
        bits::FRAGMENT_LATER => "later",
        _ => "not_valid",
    }
}

/// True if a value of a tag field is hidden in the JSON: an absent field,
/// and a TPID of 0x8100 when `tpid`.
fn tag_hidden(v: &Values, tpid: bool) -> bool {
    matches!(v, Values::Absent) || (tpid && v.single() == Some(u128::from(bits::TPID_8021Q)))
}

/// The JSON value of a tag field, or `None` when it is hidden. A value
/// that equals the original request is shown when the original value is.
fn tag_json<T>(
    h: &HeaderDesc,
    original: Option<&HeaderDesc>,
    f: HeaderField,
    tpid: bool,
    conv: impl Fn(u128) -> T,
) -> Option<FieldJson<T>> {
    let v = h.get(f);
    let hidden = match v {
        Values::Original => original.is_none_or(|o| tag_hidden(o.get(f), tpid)),
        v => tag_hidden(v, tpid),
    };
    (!hidden).then(|| field_json(f, v, conv))
}

/// The JSON form of a header. `original` is the original request of a
/// current header or of its inner header.
pub fn header_json(
    h: &HeaderDesc,
    encap: Option<&EncapDesc>,
    original: Option<&HeaderDesc>,
) -> HeaderJson {
    let v6 = match h.get(HeaderField::SrcIp) {
        Values::Prefixes(ps) => ps.first().is_some_and(|p| !p.is_ipv4()),
        _ => match h.get(HeaderField::DstIp) {
            Values::Prefixes(ps) => ps.first().is_some_and(|p| !p.is_ipv4()),
            _ => false,
        },
    };
    let ip = move |x: u128| bits::bits_ip(v6, x).to_string();
    let f8 = |f: HeaderField| field_json(f, h.get(f), |x| x as u8);
    let f16 = |f: HeaderField| field_json(f, h.get(f), |x| x as u16);
    HeaderJson {
        source_mac: field_json(HeaderField::SrcMac, h.get(HeaderField::SrcMac), mac_text),
        destination_mac: field_json(HeaderField::DstMac, h.get(HeaderField::DstMac), mac_text),
        vlan_id: f16(HeaderField::Vlan),
        l2_priority: f8(HeaderField::L2Priority),
        vlan_tpid: tag_json(h, original, HeaderField::VlanTpid, true, |x| x as u16),
        inner_vlan_id: tag_json(h, original, HeaderField::InnerVlan, false, |x| x as u16),
        inner_l2_priority: tag_json(h, original, HeaderField::InnerL2Priority, false, |x| {
            x as u8
        }),
        inner_vlan_tpid: tag_json(h, original, HeaderField::InnerVlanTpid, true, |x| x as u16),
        source_ip: field_json(HeaderField::SrcIp, h.get(HeaderField::SrcIp), ip),
        destination_ip: field_json(HeaderField::DstIp, h.get(HeaderField::DstIp), ip),
        iana_number: f8(HeaderField::Protocol),
        dscp: f8(HeaderField::Dscp),
        ecn: f8(HeaderField::Ecn),
        fragment: field_json(HeaderField::Fragment, h.get(HeaderField::Fragment), |x| {
            fragment_text(x).to_string()
        }),
        source_port: f16(HeaderField::SrcPort),
        destination_port: f16(HeaderField::DstPort),
        tcp_flags: f8(HeaderField::TcpFlags),
        icmp_type: f8(HeaderField::IcmpType),
        icmp_code: f8(HeaderField::IcmpCode),
        mpls_tc: f8(HeaderField::MplsTrafficClass),
        encap: encap.map(EncapJson::new).into_iter().collect(),
        inner: h
            .inner
            .as_deref()
            .map(|i| Box::new(header_json(i, None, original))),
    }
}

impl FromEngine<EncapDesc> for EncapJson {
    fn new(e: &EncapDesc) -> Self {
        let addr = |v: &Values| {
            field_json(HeaderField::SrcIp, v, |x| {
                bits::bits_ip(false, x).to_string()
            })
        };
        let num = |v: &Values| field_json(HeaderField::Protocol, v, |x| x as u32);
        match e.kind {
            bits::ENCAP_GRE => EncapJson {
                kind: "gre".into(),
                src: Some(addr(&e.src)),
                dst: Some(addr(&e.dst)),
                vni: None,
                label: None,
            },
            bits::ENCAP_VXLAN => EncapJson {
                kind: "vxlan".into(),
                src: Some(addr(&e.src)),
                dst: Some(addr(&e.dst)),
                vni: Some(num(&e.vni)),
                label: None,
            },
            bits::ENCAP_WIREGUARD => EncapJson {
                kind: "wireguard".into(),
                src: Some(addr(&e.src)),
                dst: Some(addr(&e.dst)),
                vni: None,
                label: None,
            },
            _ => EncapJson {
                kind: "mpls".into(),
                src: None,
                dst: None,
                vni: None,
                label: Some(num(&e.label)),
            },
        }
    }
}

/// The brief form of an answer, made from the engine answer: no packet set
/// of a trace step is described, so it costs much less than the full
/// form. It has the same bytes as `AnswerBriefJson::from_answer` of the
/// full form.
pub fn brief_json(a: &Answer, form: rsim_contract::args::Form) -> AnswerBriefJson {
    let lines = form == rsim_contract::args::Form::Steps;
    AnswerBriefJson {
        mode: match a.mode {
            Mode::Path => "path".into(),
            Mode::Set => "set".into(),
        },
        ingress: a
            .runs
            .iter()
            .map(|r| {
                let i = ingress_json(&r.input, &r.ingress);
                IngressBriefJson {
                    found: i.found,
                    device: i.device,
                    interface: i.interface,
                    function: i.function,
                    resolved_by: i.resolved_by,
                    reason: i.reason,
                }
            })
            .collect(),
        summary: a
            .summary
            .iter()
            .map(|p| PartJson {
                packets: PacketSetJson::new(&p.packets),
                result: SummaryResultJson::new(&p.summary),
            })
            .collect(),
        branches: a
            .branches()
            .iter()
            .map(|b| BranchBriefJson {
                index: b.index,
                verdict: VerdictJson::new(b.verdict),
                delay: DelayJson::new(&b.delay),
                step_count: b.steps.len(),
                steps: if lines {
                    b.steps
                        .iter()
                        .enumerate()
                        .map(|(i, s)| StepLineJson {
                            index: i,
                            function: s.function.to_string(),
                            device: s.device.as_ref().map(ToString::to_string),
                            outcome: OutcomeJson::new(&s.outcome).kind,
                            reason: ReasonJson::new(&s.reason),
                        })
                        .collect()
                } else {
                    Vec::new()
                },
            })
            .collect(),
        replies: a
            .replies
            .iter()
            .map(|r| match &r.result {
                ReplyResult::Ran(ans) => ReplyBriefJson {
                    forward_branch: r.forward_branch,
                    ran: true,
                    not_run_reason: None,
                    answer: Some(Box::new(brief_json(ans, form))),
                },
                ReplyResult::NotRun(why) => ReplyBriefJson {
                    forward_branch: r.forward_branch,
                    ran: false,
                    not_run_reason: Some(why.clone()),
                    answer: None,
                },
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsim_core::{Encap, Header, Mac, PROTO_TCP, PROTO_UDP, SetArena};

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn only_an_encapsulated_header_has_an_inner_header() {
        let a = SetArena::standalone();
        let req = Header::request(ip("10.0.0.1"), ip("10.0.0.2"), PROTO_TCP).with_dst_port(22);
        let mut o = Header::request(ip("198.51.100.1"), ip("198.51.100.2"), PROTO_UDP)
            .with_src_port(49152)
            .with_dst_port(4789);
        o.dscp = FieldValue::Known(0);
        o.ecn = FieldValue::Known(0);
        o.src_mac = FieldValue::Known(Mac([0, 0, 0, 0, 2, 1]));
        o.dst_mac = FieldValue::Known(Mac([0, 0, 0, 0, 3, 1]));
        o = o.untagged();
        o.encap = vec![Encap::Vxlan {
            src: ip("198.51.100.1"),
            dst: ip("198.51.100.2"),
            vni: 10,
        }];
        let plain = PacketSet::single(&a, &req);
        let v = serde_json::to_value(PacketSetJson::new(&plain)).unwrap();
        assert!(v["members"][0]["current"].get("inner").is_none());
        let s = plain.encapsulate(&o).done;
        let v = serde_json::to_value(PacketSetJson::new(&s)).unwrap();
        let m = &v["members"][0];
        assert!(m["original"].get("inner").is_none());
        assert_eq!(m["current"]["destination.port"]["known"], 4789);
        assert_eq!(m["current"]["encap"][0]["kind"], "vxlan");
        assert_eq!(m["current"]["inner"]["destination.port"]["known"], 22);
        assert_eq!(m["current"]["inner"]["dscp"], "original");
        assert!(m["current"]["inner"].get("inner").is_none());
    }
}
