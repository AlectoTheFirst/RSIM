//! The JSON output, version 2.
//!
//! Each type serializes its fields in the order of declaration. An optional
//! value that is not there is `null`, and no field is left out. Enumeration
//! values are the Rust names in snake case.

use std::fmt::Debug;

use rsim_core::{
    Alternative, Attr, Delay, DelayGap, Destination, EncapDesc, FieldValue, FloodCopy, HeaderDesc,
    HeaderField, Outcome, PacketSet, QosView, RateCondition, Reason, SourceSpan, TraceStep,
    Uniform, Values, Verdict, VerdictKind, bits,
};
use rsim_engine::{Answer, BranchView, Ingress, IngressBasis, Mode, ReplyResult, Summary};
use serde::{Serialize, Serializer};

use crate::error::QueryError;
use crate::query::QueryEcho;
use crate::set_query::SetEcho;

/// The query input of an output: of a path query or of a set query.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum QueryJson {
    Path(Box<QueryEcho>),
    Set(Box<SetEcho>),
}

/// The version number of the JSON output.
pub const VERSION: u32 = 2;

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
    pub attachments: Vec<AttachmentJson>,
    pub edge_interfaces: Vec<EdgeInterfaceJson>,
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
}

#[derive(Clone, Debug, Serialize)]
pub struct AttachmentJson {
    pub address: String,
    pub device: String,
    pub interface: String,
    pub kind: String,
    pub host: String,
    pub provenance: Vec<SpanJson>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EdgeInterfaceJson {
    pub device: String,
    pub interface: String,
    pub networks: Vec<String>,
    pub provenance: Vec<SpanJson>,
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
pub struct SetAnswerOut {
    pub rsim_json: u32,
    pub kind: &'static str,
    pub topology: String,
    pub query: SetEcho,
    pub answer: AnswerJson,
}

#[derive(Clone, Debug, Serialize)]
pub struct StepOut {
    pub rsim_json: u32,
    pub kind: &'static str,
    pub topology: String,
    pub query: QueryJson,
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
    pub mode: &'static str,
    pub input: PacketSetJson,
    pub ingress: Vec<IngressJson>,
    pub summary: Vec<PartJson>,
    pub branches: Vec<BranchJson>,
    pub replies: Vec<ReplyJson>,
}

/// The ingress of one run of the answer: the packets of the run and the
/// interface where they enter, or the reason why the ingress is not known.
#[derive(Clone, Debug, Serialize)]
pub struct IngressJson {
    pub packets: PacketSetJson,
    pub found: bool,
    pub device: Option<String>,
    pub interface: Option<String>,
    pub function: Option<String>,
    pub resolved_by: Option<&'static str>,
    pub network: Option<String>,
    pub host_confirmed: bool,
    pub provenance: Vec<SpanJson>,
    pub reason: Option<ReasonJson>,
}

impl IngressJson {
    pub fn new(packets: &PacketSet, i: &Ingress) -> Self {
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
                j.resolved_by = Some(by);
                j.provenance = spans.iter().map(SpanJson::new).collect();
            }
            Ingress::NotFound(r) => j.reason = Some(ReasonJson::new(r)),
        }
        j
    }
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
            mode: match a.mode {
                Mode::Path => "path",
                Mode::Set => "set",
            },
            input: PacketSetJson::new(&a.input),
            ingress: a
                .runs
                .iter()
                .map(|r| IngressJson::new(&r.input, &r.ingress))
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

/// A packet set: its members. A member is a product of field values. The
/// members are disjoint and in the fixed order of the bit table.
#[derive(Clone, Debug, Serialize)]
pub struct PacketSetJson {
    pub members: Vec<MemberJson>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MemberJson {
    pub original: HeaderJson,
    pub current: HeaderJson,
}

/// A header field value: `{"known": value}`, `{"in": [...]}`, `"unknown"`,
/// `"absent"` or, in the current header and the inner header, `"original"`.
#[derive(Clone, Debug)]
pub enum FieldJson<T> {
    Known(T),
    In(Vec<serde_json::Value>),
    Unknown,
    Absent,
    Original,
}

#[derive(Serialize)]
struct InWrap<'a> {
    #[serde(rename = "in")]
    values: &'a [serde_json::Value],
}

impl<T: Serialize> Serialize for FieldJson<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            FieldJson::Known(v) => KnownWrap { known: v }.serialize(s),
            FieldJson::In(v) => InWrap { values: v }.serialize(s),
            FieldJson::Unknown => s.serialize_str("unknown"),
            FieldJson::Absent => s.serialize_str("absent"),
            FieldJson::Original => s.serialize_str("original"),
        }
    }
}

impl<T> FieldJson<T> {
    fn new(f: HeaderField, v: &Values, known: impl Fn(u128) -> T) -> Self {
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

#[derive(Clone, Debug, Serialize)]
pub struct HeaderJson {
    #[serde(rename = "source.mac")]
    pub source_mac: FieldJson<String>,
    #[serde(rename = "destination.mac")]
    pub destination_mac: FieldJson<String>,
    #[serde(rename = "network.vlan.id")]
    pub vlan_id: FieldJson<u16>,
    pub l2_priority: FieldJson<u8>,
    #[serde(rename = "source.ip")]
    pub source_ip: FieldJson<String>,
    #[serde(rename = "destination.ip")]
    pub destination_ip: FieldJson<String>,
    #[serde(rename = "network.iana_number")]
    pub iana_number: FieldJson<u8>,
    pub dscp: FieldJson<u8>,
    pub ecn: FieldJson<u8>,
    pub fragment: FieldJson<&'static str>,
    #[serde(rename = "source.port")]
    pub source_port: FieldJson<u16>,
    #[serde(rename = "destination.port")]
    pub destination_port: FieldJson<u16>,
    pub tcp_flags: FieldJson<u8>,
    pub icmp_type: FieldJson<u8>,
    pub icmp_code: FieldJson<u8>,
    pub mpls_tc: FieldJson<u8>,
    pub encap: Vec<EncapJson>,
    /// The inner header of an encapsulated current header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner: Option<Box<HeaderJson>>,
}

/// An encapsulation header. The values are field values.
#[derive(Clone, Debug, Serialize)]
pub struct EncapJson {
    pub kind: &'static str,
    pub src: Option<FieldJson<String>>,
    pub dst: Option<FieldJson<String>>,
    pub vni: Option<FieldJson<u32>>,
    pub label: Option<FieldJson<u32>>,
}

impl PacketSetJson {
    pub fn new(p: &PacketSet) -> Self {
        PacketSetJson {
            members: p
                .describe()
                .iter()
                .map(|m| MemberJson {
                    original: HeaderJson::new(&m.original, m.original.encap.as_ref()),
                    current: HeaderJson::new(&m.current, m.current.encap.as_ref()),
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

impl HeaderJson {
    pub fn new(h: &HeaderDesc, encap: Option<&EncapDesc>) -> Self {
        let v6 = match h.get(HeaderField::SrcIp) {
            Values::Prefixes(ps) => ps.first().is_some_and(|p| !p.is_ipv4()),
            _ => match h.get(HeaderField::DstIp) {
                Values::Prefixes(ps) => ps.first().is_some_and(|p| !p.is_ipv4()),
                _ => false,
            },
        };
        let ip = move |x: u128| bits::bits_ip(v6, x).to_string();
        let f8 = |f: HeaderField| FieldJson::new(f, h.get(f), |x| x as u8);
        let f16 = |f: HeaderField| FieldJson::new(f, h.get(f), |x| x as u16);
        HeaderJson {
            source_mac: FieldJson::new(HeaderField::SrcMac, h.get(HeaderField::SrcMac), mac_text),
            destination_mac: FieldJson::new(
                HeaderField::DstMac,
                h.get(HeaderField::DstMac),
                mac_text,
            ),
            vlan_id: f16(HeaderField::Vlan),
            l2_priority: f8(HeaderField::L2Priority),
            source_ip: FieldJson::new(HeaderField::SrcIp, h.get(HeaderField::SrcIp), ip),
            destination_ip: FieldJson::new(HeaderField::DstIp, h.get(HeaderField::DstIp), ip),
            iana_number: f8(HeaderField::Protocol),
            dscp: f8(HeaderField::Dscp),
            ecn: f8(HeaderField::Ecn),
            fragment: FieldJson::new(
                HeaderField::Fragment,
                h.get(HeaderField::Fragment),
                fragment_text,
            ),
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
                .map(|i| Box::new(HeaderJson::new(i, None))),
        }
    }
}

impl EncapJson {
    pub fn new(e: &EncapDesc) -> Self {
        let addr = |v: &Values| {
            FieldJson::new(HeaderField::SrcIp, v, |x| {
                bits::bits_ip(false, x).to_string()
            })
        };
        let num = |v: &Values| FieldJson::new(HeaderField::Protocol, v, |x| x as u32);
        match e.kind {
            bits::ENCAP_GRE => EncapJson {
                kind: "gre",
                src: Some(addr(&e.src)),
                dst: Some(addr(&e.dst)),
                vni: None,
                label: None,
            },
            bits::ENCAP_VXLAN => EncapJson {
                kind: "vxlan",
                src: Some(addr(&e.src)),
                dst: Some(addr(&e.dst)),
                vni: Some(num(&e.vni)),
                label: None,
            },
            _ => EncapJson {
                kind: "mpls",
                src: None,
                dst: None,
                vni: None,
                label: Some(num(&e.label)),
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
        o.vlan = FieldValue::Absent;
        o.l2_priority = FieldValue::Absent;
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
