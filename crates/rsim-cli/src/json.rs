//! The JSON output, version 1.
//!
//! Each type serializes its fields in the order of declaration. An optional
//! value that is not there is `null`, and no field is left out. Enumeration
//! values are the Rust names in snake case.

use std::fmt::Debug;
use std::net::IpAddr;

use rsim_core::{
    Alternative, Attr, Delay, DelayGap, Destination, Encap, FieldValue, FloodCopy, Fragment,
    Header, Mac, Outcome, PacketSet, QosView, RateCondition, Reason, SourceSpan, TraceStep,
    Uniform, Verdict, VerdictKind,
};
use rsim_engine::{Answer, BranchView, ReplyResult, Summary};
use serde::{Serialize, Serializer};

use crate::error::QueryError;
use crate::query::QueryEcho;

/// The version number of the JSON output.
pub const VERSION: u32 = 1;

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

// ------------------------------------------------------------ top level

#[derive(Clone, Debug, Serialize)]
pub struct TopologiesOut {
    pub rsim_json: u32,
    pub kind: &'static str,
    pub topologies: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DevicesOut {
    pub rsim_json: u32,
    pub kind: &'static str,
    pub topology: String,
    pub devices: Vec<DeviceJson>,
    pub endpoints: Vec<EndpointJson>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeviceJson {
    pub device: String,
    pub functions: Vec<FunctionJson>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FunctionJson {
    pub function: String,
    pub kind: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointJson {
    pub endpoint: String,
    pub addresses: Vec<String>,
    pub attachment: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PathAnswerOut {
    pub rsim_json: u32,
    pub kind: &'static str,
    pub topology: String,
    pub query: QueryEcho,
    pub answer: AnswerJson,
}

#[derive(Clone, Debug, Serialize)]
pub struct StepOut {
    pub rsim_json: u32,
    pub kind: &'static str,
    pub topology: String,
    pub query: QueryEcho,
    pub reply_of: Option<usize>,
    pub branch: usize,
    pub step: usize,
    pub trace_step: TraceStepJson,
}

#[derive(Clone, Debug, Serialize)]
pub struct ErrorOut {
    pub rsim_json: u32,
    pub kind: &'static str,
    pub error: QueryError,
}

impl ErrorOut {
    pub fn new(error: QueryError) -> Self {
        ErrorOut {
            rsim_json: VERSION,
            kind: "error",
            error,
        }
    }
}

// ------------------------------------------------------------ answer

#[derive(Clone, Debug, Serialize)]
pub struct AnswerJson {
    pub start: String,
    pub input: PacketSetJson,
    pub summary: Vec<PartJson>,
    pub branches: Vec<BranchJson>,
    pub replies: Vec<ReplyJson>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PartJson {
    pub packets: PacketSetJson,
    pub result: SummaryResultJson,
}

#[derive(Clone, Debug, Serialize)]
pub struct SummaryResultJson {
    pub kind: &'static str,
    pub verdict: Option<VerdictJson>,
    pub verdict_kind: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VerdictJson {
    pub kind: String,
    pub destination: Option<DestinationJson>,
    pub reason: Option<ReasonJson>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DestinationJson {
    pub endpoint: Option<String>,
    pub device: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReasonJson {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BranchJson {
    pub index: usize,
    pub verdict: VerdictJson,
    pub packets: PacketSetJson,
    pub delay: DelayJson,
    pub steps: Vec<TraceStepJson>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReplyJson {
    pub forward_branch: usize,
    pub ran: bool,
    pub not_run_reason: Option<String>,
    pub answer: Option<AnswerJson>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DelayJson {
    pub known_ns: u64,
    pub lower_bound: bool,
    pub missing: Vec<DelayGapJson>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DelayGapJson {
    pub kind: &'static str,
    pub function: String,
}

impl AnswerJson {
    pub fn new(a: &Answer) -> Self {
        AnswerJson {
            start: a.start.to_string(),
            input: PacketSetJson::new(&a.input),
            summary: vec![PartJson {
                packets: PacketSetJson::new(&a.input),
                result: SummaryResultJson::new(&a.summary),
            }],
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

impl SummaryResultJson {
    pub fn new(s: &Summary) -> Self {
        match s {
            Summary::Same(v) => SummaryResultJson {
                kind: "same",
                verdict: Some(VerdictJson::new(v)),
                verdict_kind: Some(verdict_kind(v.kind())),
            },
            Summary::SameKind(k) => SummaryResultJson {
                kind: "same_kind",
                verdict: None,
                verdict_kind: Some(verdict_kind(*k)),
            },
            Summary::DependsOnPath => SummaryResultJson {
                kind: "depends_on_path",
                verdict: None,
                verdict_kind: None,
            },
        }
    }
}

fn verdict_kind(k: VerdictKind) -> String {
    snake(&k)
}

impl VerdictJson {
    pub fn new(v: &Verdict) -> Self {
        let (destination, reason) = match v {
            Verdict::Deliver(d) => (Some(DestinationJson::new(d)), None),
            Verdict::Drop(r) | Verdict::Unknown(r) => (None, Some(ReasonJson::new(r))),
        };
        VerdictJson {
            kind: verdict_kind(v.kind()),
            destination,
            reason,
        }
    }
}

impl DestinationJson {
    pub fn new(d: &Destination) -> Self {
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

impl ReasonJson {
    pub fn new(r: &Reason) -> Self {
        ReasonJson {
            code: snake(&r.code),
            detail: r.detail.clone(),
        }
    }
}

impl BranchJson {
    pub fn new(b: &BranchView<'_>) -> Self {
        BranchJson {
            index: b.index,
            verdict: VerdictJson::new(b.verdict),
            packets: PacketSetJson::new(b.packets),
            delay: DelayJson::new(&b.delay),
            steps: b
                .steps
                .iter()
                .enumerate()
                .map(|(i, s)| TraceStepJson::new(i, s))
                .collect(),
        }
    }
}

impl DelayJson {
    pub fn new(d: &Delay) -> Self {
        DelayJson {
            known_ns: d.known_ns(),
            lower_bound: d.is_lower_bound(),
            missing: d
                .missing()
                .iter()
                .map(|g| match g {
                    DelayGap::Processing(f) => DelayGapJson {
                        kind: "processing",
                        function: f.to_string(),
                    },
                    DelayGap::Link(f) => DelayGapJson {
                        kind: "link",
                        function: f.to_string(),
                    },
                    DelayGap::Queueing(f) => DelayGapJson {
                        kind: "queueing",
                        function: f.to_string(),
                    },
                })
                .collect(),
        }
    }
}

// ------------------------------------------------------------ trace step

#[derive(Clone, Debug, Serialize)]
pub struct TraceStepJson {
    pub index: usize,
    pub function: String,
    pub kind: String,
    pub device: Option<String>,
    pub input: PacketSetJson,
    pub output: PacketSetJson,
    pub outcome: OutcomeJson,
    pub reason: ReasonJson,
    pub provenance: Vec<SpanJson>,
    pub delay: DelayJson,
    pub alternative: Option<AlternativeJson>,
    pub flood_copy: Option<FloodCopyJson>,
    pub qos: QosJson,
    pub rate_condition: Option<RateConditionJson>,
    pub rib_guard: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct OutcomeJson {
    pub kind: &'static str,
    pub next: Option<String>,
    pub destination: Option<DestinationJson>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SpanJson {
    pub file: String,
    pub first_line: u32,
    pub last_line: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct AlternativeJson {
    pub choice: String,
    pub key: String,
    pub index: u32,
    pub count: u32,
    pub label: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct FloodCopyJson {
    pub flood: String,
    pub port: String,
    pub index: u32,
    pub count: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct QosJson {
    pub dscp: UniformJson,
    pub ecn: UniformJson,
    pub traffic_class: AttrJson,
    pub drop_precedence: AttrJson,
    pub queue: AttrJson,
}

#[derive(Clone, Debug, Serialize)]
pub struct RateConditionJson {
    pub function: String,
    pub rate_bps: Option<u64>,
    pub exceed_action: String,
    pub evaluated: bool,
}

/// A QoS header field over the members of a set: `{"value": field value}`,
/// `"varies"` or `"none"`.
#[derive(Clone, Debug)]
pub enum UniformJson {
    Value(FieldJson<u8>),
    Varies,
    None,
}

#[derive(Serialize)]
struct ValueWrap<'a, T: Serialize> {
    value: &'a T,
}

impl Serialize for UniformJson {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            UniformJson::Value(v) => ValueWrap { value: v }.serialize(s),
            UniformJson::Varies => s.serialize_str("varies"),
            UniformJson::None => s.serialize_str("none"),
        }
    }
}

/// A context attribute: `{"known": number}`, `"unset"` or `"unknown"`.
#[derive(Clone, Debug)]
pub enum AttrJson {
    Known(u8),
    Unset,
    Unknown,
}

#[derive(Serialize)]
struct KnownWrap<'a, T: Serialize> {
    known: &'a T,
}

impl Serialize for AttrJson {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            AttrJson::Known(v) => KnownWrap { known: v }.serialize(s),
            AttrJson::Unset => s.serialize_str("unset"),
            AttrJson::Unknown => s.serialize_str("unknown"),
        }
    }
}

impl TraceStepJson {
    pub fn new(index: usize, s: &TraceStep) -> Self {
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
}

impl OutcomeJson {
    pub fn new(o: &Outcome) -> Self {
        match o {
            Outcome::Forward(f) => OutcomeJson {
                kind: "forward",
                next: Some(f.to_string()),
                destination: None,
            },
            Outcome::Deliver(d) => OutcomeJson {
                kind: "deliver",
                next: None,
                destination: Some(DestinationJson::new(d)),
            },
            Outcome::Drop => OutcomeJson {
                kind: "drop",
                next: None,
                destination: None,
            },
            Outcome::Unknown => OutcomeJson {
                kind: "unknown",
                next: None,
                destination: None,
            },
        }
    }
}

impl SpanJson {
    pub fn new(s: &SourceSpan) -> Self {
        SpanJson {
            file: s.file.to_string(),
            first_line: s.first_line,
            last_line: s.last_line,
        }
    }
}

impl AlternativeJson {
    pub fn new(a: &Alternative) -> Self {
        AlternativeJson {
            choice: a.choice.to_string(),
            key: a.key.clone(),
            index: a.index,
            count: a.count,
            label: a.label.clone(),
        }
    }
}

impl FloodCopyJson {
    pub fn new(f: &FloodCopy) -> Self {
        FloodCopyJson {
            flood: f.flood.to_string(),
            port: f.port.to_string(),
            index: f.index,
            count: f.count,
        }
    }
}

impl QosJson {
    pub fn new(q: &QosView) -> Self {
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
        Uniform::Value(v) => UniformJson::Value(FieldJson::new(v)),
        Uniform::Varies => UniformJson::Varies,
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

impl RateConditionJson {
    pub fn new(r: &RateCondition) -> Self {
        RateConditionJson {
            function: r.function.to_string(),
            rate_bps: r.rate_bps,
            exceed_action: r.exceed_action.clone(),
            evaluated: r.evaluated,
        }
    }
}

// ------------------------------------------------------------ packet set

#[derive(Clone, Debug, Serialize)]
pub struct PacketSetJson {
    pub members: Vec<MemberJson>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MemberJson {
    pub original: HeaderJson,
    pub current: HeaderJson,
}

/// A header field value: `{"known": value}`, `"unstated"`, `"unknown"` or
/// `"absent"`.
#[derive(Clone, Debug)]
pub enum FieldJson<T> {
    Known(T),
    Unstated,
    Unknown,
    Absent,
}

impl<T: Clone> FieldJson<T> {
    fn new(v: &FieldValue<T>) -> Self {
        Self::map(v, T::clone)
    }
}

impl<T> FieldJson<T> {
    fn map<U>(v: &FieldValue<U>, f: impl FnOnce(&U) -> T) -> Self {
        match v {
            FieldValue::Known(x) => FieldJson::Known(f(x)),
            FieldValue::Unstated => FieldJson::Unstated,
            FieldValue::Unknown => FieldJson::Unknown,
            FieldValue::Absent => FieldJson::Absent,
        }
    }
}

impl<T: Serialize> Serialize for FieldJson<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            FieldJson::Known(v) => KnownWrap { known: v }.serialize(s),
            FieldJson::Unstated => s.serialize_str("unstated"),
            FieldJson::Unknown => s.serialize_str("unknown"),
            FieldJson::Absent => s.serialize_str("absent"),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct HeaderJson {
    pub src_mac: FieldJson<String>,
    pub dst_mac: FieldJson<String>,
    pub vlan: FieldJson<u16>,
    pub l2_priority: FieldJson<u8>,
    pub src_ip: FieldJson<String>,
    pub dst_ip: FieldJson<String>,
    pub protocol: FieldJson<u8>,
    pub dscp: FieldJson<u8>,
    pub ecn: FieldJson<u8>,
    pub fragment: FieldJson<&'static str>,
    pub src_port: FieldJson<u16>,
    pub dst_port: FieldJson<u16>,
    pub tcp_flags: FieldJson<u8>,
    pub icmp_type: FieldJson<u8>,
    pub icmp_code: FieldJson<u8>,
    pub mpls_tc: FieldJson<u8>,
    pub encap: Vec<EncapJson>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EncapJson {
    pub kind: &'static str,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub vni: Option<u32>,
    pub label: Option<u32>,
    pub traffic_class: Option<FieldJson<u8>>,
}

impl PacketSetJson {
    pub fn new(p: &PacketSet) -> Self {
        PacketSetJson {
            members: p
                .members()
                .iter()
                .map(|m| MemberJson {
                    original: HeaderJson::new(&m.original),
                    current: HeaderJson::new(&m.current),
                })
                .collect(),
        }
    }
}

fn mac_text(m: &Mac) -> String {
    let b = m.0;
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
}

fn ip_text(a: &IpAddr) -> String {
    a.to_string()
}

fn fragment_text(f: &Fragment) -> &'static str {
    match f {
        Fragment::Unfragmented => "unfragmented",
        Fragment::First => "first",
        Fragment::Later => "later",
    }
}

impl HeaderJson {
    pub fn new(h: &Header) -> Self {
        HeaderJson {
            src_mac: FieldJson::map(&h.src_mac, mac_text),
            dst_mac: FieldJson::map(&h.dst_mac, mac_text),
            vlan: FieldJson::new(&h.vlan),
            l2_priority: FieldJson::new(&h.l2_priority),
            src_ip: FieldJson::map(&h.src_ip, ip_text),
            dst_ip: FieldJson::map(&h.dst_ip, ip_text),
            protocol: FieldJson::new(&h.protocol),
            dscp: FieldJson::new(&h.dscp),
            ecn: FieldJson::new(&h.ecn),
            fragment: FieldJson::map(&h.fragment, fragment_text),
            src_port: FieldJson::new(&h.src_port),
            dst_port: FieldJson::new(&h.dst_port),
            tcp_flags: FieldJson::new(&h.tcp_flags),
            icmp_type: FieldJson::new(&h.icmp_type),
            icmp_code: FieldJson::new(&h.icmp_code),
            mpls_tc: FieldJson::new(&h.mpls_tc),
            encap: h.encap.iter().map(EncapJson::new).collect(),
        }
    }
}

impl EncapJson {
    pub fn new(e: &Encap) -> Self {
        match e {
            Encap::Gre { src, dst } => EncapJson {
                kind: "gre",
                src: Some(src.to_string()),
                dst: Some(dst.to_string()),
                vni: None,
                label: None,
                traffic_class: None,
            },
            Encap::Vxlan { src, dst, vni } => EncapJson {
                kind: "vxlan",
                src: Some(src.to_string()),
                dst: Some(dst.to_string()),
                vni: Some(*vni),
                label: None,
                traffic_class: None,
            },
            Encap::Mpls {
                label,
                traffic_class,
            } => EncapJson {
                kind: "mpls",
                src: None,
                dst: None,
                vni: None,
                label: Some(*label),
                traffic_class: Some(FieldJson::new(traffic_class)),
            },
        }
    }
}

/// The JSON text of a value: compact on one line, or indented.
pub fn to_text<T: Serialize>(v: &T, pretty: bool) -> String {
    let r = if pretty {
        serde_json::to_string_pretty(v)
    } else {
        serde_json::to_string(v)
    };
    match r {
        Ok(s) => s,
        Err(e) => unreachable!("the view types serialize to JSON without error: {e}"),
    }
}
