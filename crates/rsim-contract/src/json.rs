//! The JSON output, version 2.
//!
//! Each type serializes its fields in the order of declaration. An optional
//! value that is not there is `null`, and no field is left out. Enumeration
//! values are the Rust names in snake case.

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::QueryError;
use crate::query::{QueryEcho, SetEcho};

/// The query input of an output: of a path query or of a set query.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum QueryJson {
    Path(Box<QueryEcho>),
    Set(Box<SetEcho>),
}

/// The version number of the JSON output.
pub const VERSION: u32 = 2;

// ------------------------------------------------------------ top level

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct TopologiesOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topologies: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DevicesOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: crate::twin::TwinJson,
    pub devices: Vec<DeviceJson>,
    pub endpoints: Vec<EndpointJson>,
    pub attachments: Vec<AttachmentJson>,
    pub edge_interfaces: Vec<EdgeInterfaceJson>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DeviceJson {
    pub device: String,
    pub functions: Vec<FunctionJson>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct FunctionJson {
    pub function: String,
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EndpointJson {
    pub endpoint: String,
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AttachmentJson {
    pub address: String,
    pub device: String,
    pub interface: String,
    pub kind: String,
    pub host: String,
    pub provenance: Vec<SpanJson>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EdgeInterfaceJson {
    pub device: String,
    pub interface: String,
    pub networks: Vec<String>,
    pub provenance: Vec<SpanJson>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PathAnswerOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: crate::twin::TwinJson,
    pub query: QueryEcho,
    pub answer: AnswerJson,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SetAnswerOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: crate::twin::TwinJson,
    pub query: SetEcho,
    pub answer: AnswerJson,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct StepOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: crate::twin::TwinJson,
    pub query: QueryJson,
    pub reply_of: Option<usize>,
    pub branch: usize,
    pub step: usize,
    pub trace_step: TraceStepJson,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ErrorOut {
    pub rsim_json: u32,
    pub kind: String,
    pub error: QueryError,
}

impl ErrorOut {
    pub fn new(error: QueryError) -> Self {
        ErrorOut {
            rsim_json: VERSION,
            kind: "error".into(),
            error,
        }
    }
}

// ------------------------------------------------------------ answer

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AnswerJson {
    pub mode: String,
    pub input: PacketSetJson,
    pub ingress: Vec<IngressJson>,
    pub summary: Vec<PartJson>,
    pub branches: Vec<BranchJson>,
    pub replies: Vec<ReplyJson>,
}

/// The ingress of one run of the answer: the packets of the run and the
/// interface where they enter, or the reason why the ingress is not known.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct IngressJson {
    pub packets: PacketSetJson,
    pub found: bool,
    pub device: Option<String>,
    pub interface: Option<String>,
    pub function: Option<String>,
    pub resolved_by: Option<String>,
    pub network: Option<String>,
    pub host_confirmed: bool,
    pub provenance: Vec<SpanJson>,
    pub reason: Option<ReasonJson>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PartJson {
    pub packets: PacketSetJson,
    pub result: SummaryResultJson,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SummaryResultJson {
    pub kind: String,
    pub verdict: Option<VerdictJson>,
    /// `deliver`, `exit`, `drop`, `unknown` or `null`.
    pub verdict_kind: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct VerdictJson {
    /// `deliver`, `exit`, `drop` or `unknown`. `exit`: the packets left the
    /// twin on an edge interface, which the reason names.
    pub kind: String,
    pub destination: Option<DestinationJson>,
    pub reason: Option<ReasonJson>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DestinationJson {
    pub endpoint: Option<String>,
    pub device: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ReasonJson {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BranchJson {
    pub index: usize,
    pub verdict: VerdictJson,
    pub packets: PacketSetJson,
    pub delay: DelayJson,
    pub steps: Vec<TraceStepJson>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ReplyJson {
    pub forward_branch: usize,
    pub ran: bool,
    pub not_run_reason: Option<String>,
    pub answer: Option<AnswerJson>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DelayJson {
    pub known_ns: u64,
    pub lower_bound: bool,
    pub missing: Vec<DelayGapJson>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DelayGapJson {
    pub kind: String,
    pub function: String,
}

// ------------------------------------------------------------ trace step

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
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

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct OutcomeJson {
    /// `forward`, `deliver`, `exit`, `drop` or `unknown`.
    pub kind: String,
    pub next: Option<String>,
    pub destination: Option<DestinationJson>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SpanJson {
    pub file: String,
    pub first_line: u32,
    pub last_line: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AlternativeJson {
    pub choice: String,
    pub key: String,
    pub index: u32,
    pub count: u32,
    pub label: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct FloodCopyJson {
    pub flood: String,
    pub port: String,
    pub index: u32,
    pub count: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct QosJson {
    pub dscp: UniformJson,
    pub ecn: UniformJson,
    pub traffic_class: AttrJson,
    pub drop_precedence: AttrJson,
    pub queue: AttrJson,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
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

// ------------------------------------------------------------ packet set

/// A packet set: its members. A member is a product of field values. The
/// members are disjoint and in the fixed order of the bit table.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PacketSetJson {
    pub members: Vec<MemberJson>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
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

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
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
    pub fragment: FieldJson<String>,
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
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EncapJson {
    pub kind: String,
    pub src: Option<FieldJson<String>>,
    pub dst: Option<FieldJson<String>>,
    pub vni: Option<FieldJson<u32>>,
    pub label: Option<FieldJson<u32>>,
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

// ------------------------------------------------------------ hand-written forms

#[derive(Deserialize)]
#[serde(untagged)]
enum WordOr<K> {
    Known { known: K },
    Word(String),
}

impl<'de> Deserialize<'de> for AttrJson {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match WordOr::<u8>::deserialize(d)? {
            WordOr::Known { known } => Ok(AttrJson::Known(known)),
            WordOr::Word(w) => match w.as_str() {
                "unset" => Ok(AttrJson::Unset),
                "unknown" => Ok(AttrJson::Unknown),
                _ => Err(D::Error::custom(format!("{w:?} is not unset or unknown"))),
            },
        }
    }
}

impl JsonSchema for AttrJson {
    fn schema_name() -> Cow<'static, str> {
        "AttrJson".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A context attribute: {\"known\": number}, \"unset\" or \"unknown\".",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {"known": {"type": "integer", "minimum": 0, "maximum": 255}},
                    "required": ["known"],
                    "additionalProperties": false
                },
                {"enum": ["unset", "unknown"]}
            ]
        })
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ValueOr {
    Value { value: FieldJson<u8> },
    Word(String),
}

impl<'de> Deserialize<'de> for UniformJson {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match ValueOr::deserialize(d)? {
            ValueOr::Value { value } => Ok(UniformJson::Value(value)),
            ValueOr::Word(w) => match w.as_str() {
                "varies" => Ok(UniformJson::Varies),
                "none" => Ok(UniformJson::None),
                _ => Err(D::Error::custom(format!("{w:?} is not varies or none"))),
            },
        }
    }
}

impl JsonSchema for UniformJson {
    fn schema_name() -> Cow<'static, str> {
        "UniformJson".into()
    }
    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let value = generator.subschema_for::<FieldJson<u8>>();
        json_schema!({
            "description": "A QoS header field over the members of a set: {\"value\": field value}, \"varies\" or \"none\".",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {"value": value},
                    "required": ["value"],
                    "additionalProperties": false
                },
                {"enum": ["varies", "none"]}
            ]
        })
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum FieldRepr<T> {
    Known {
        known: T,
    },
    In {
        #[serde(rename = "in")]
        values: Vec<serde_json::Value>,
    },
    Word(String),
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for FieldJson<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match FieldRepr::<T>::deserialize(d)? {
            FieldRepr::Known { known } => Ok(FieldJson::Known(known)),
            FieldRepr::In { values } => Ok(FieldJson::In(values)),
            FieldRepr::Word(w) => match w.as_str() {
                "unknown" => Ok(FieldJson::Unknown),
                "absent" => Ok(FieldJson::Absent),
                "original" => Ok(FieldJson::Original),
                _ => Err(D::Error::custom(format!(
                    "{w:?} is not unknown, absent or original"
                ))),
            },
        }
    }
}

impl<T: JsonSchema> JsonSchema for FieldJson<T> {
    fn schema_name() -> Cow<'static, str> {
        format!("Field_{}", T::schema_name()).into()
    }
    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let known = generator.subschema_for::<T>();
        json_schema!({
            "description": "A header field value: {\"known\": value}, {\"in\": [...]}, \"unknown\", \"absent\" or \"original\".",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {"known": known},
                    "required": ["known"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {"in": {"type": "array"}},
                    "required": ["in"],
                    "additionalProperties": false
                },
                {"enum": ["unknown", "absent", "original"]}
            ]
        })
    }
}

// ------------------------------------------------------------ brief forms

/// A path answer in the form `summary` or `steps`.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PathBriefOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: crate::twin::TwinJson,
    pub form: crate::args::Form,
    pub query: QueryEcho,
    pub answer: AnswerBriefJson,
}

/// A set answer in the form `summary` or `steps`.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SetBriefOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: crate::twin::TwinJson,
    pub form: crate::args::Form,
    pub query: SetEcho,
    pub answer: AnswerBriefJson,
}

/// An answer with no packet set in its ingress and its branches. The
/// summary parts keep their packet sets, because each part is a set.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AnswerBriefJson {
    pub mode: String,
    pub ingress: Vec<IngressBriefJson>,
    pub summary: Vec<PartJson>,
    pub branches: Vec<BranchBriefJson>,
    pub replies: Vec<ReplyBriefJson>,
}

/// The ingress of one run, with no packet set.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct IngressBriefJson {
    pub found: bool,
    pub device: Option<String>,
    pub interface: Option<String>,
    pub function: Option<String>,
    pub resolved_by: Option<String>,
    pub reason: Option<ReasonJson>,
}

/// A branch with its verdict, its delay, the number of its steps and, in
/// the form `steps`, one line for each step.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BranchBriefJson {
    pub index: usize,
    pub verdict: VerdictJson,
    pub delay: DelayJson,
    pub step_count: usize,
    pub steps: Vec<StepLineJson>,
}

/// One trace step with no packet set.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct StepLineJson {
    pub index: usize,
    pub function: String,
    pub device: Option<String>,
    /// `forward`, `deliver`, `exit`, `drop` or `unknown`.
    pub outcome: String,
    pub reason: ReasonJson,
}

/// The reply of a delivered branch in a brief form.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ReplyBriefJson {
    pub forward_branch: usize,
    pub ran: bool,
    pub not_run_reason: Option<String>,
    pub answer: Option<Box<AnswerBriefJson>>,
}

impl AnswerBriefJson {
    /// The brief form of a full answer. With `Form::Summary`, a branch has
    /// no step lines; with `Form::Steps`, it has one for each step.
    pub fn from_answer(a: &AnswerJson, form: crate::args::Form) -> Self {
        let lines = form == crate::args::Form::Steps;
        AnswerBriefJson {
            mode: a.mode.clone(),
            ingress: a
                .ingress
                .iter()
                .map(|i| IngressBriefJson {
                    found: i.found,
                    device: i.device.clone(),
                    interface: i.interface.clone(),
                    function: i.function.clone(),
                    resolved_by: i.resolved_by.clone(),
                    reason: i.reason.clone(),
                })
                .collect(),
            summary: a.summary.clone(),
            branches: a
                .branches
                .iter()
                .map(|b| BranchBriefJson {
                    index: b.index,
                    verdict: b.verdict.clone(),
                    delay: b.delay.clone(),
                    step_count: b.steps.len(),
                    steps: if lines {
                        b.steps
                            .iter()
                            .map(|s| StepLineJson {
                                index: s.index,
                                function: s.function.clone(),
                                device: s.device.clone(),
                                outcome: s.outcome.kind.clone(),
                                reason: s.reason.clone(),
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
                .map(|r| ReplyBriefJson {
                    forward_branch: r.forward_branch,
                    ran: r.ran,
                    not_run_reason: r.not_run_reason.clone(),
                    answer: r
                        .answer
                        .as_ref()
                        .map(|x| Box::new(AnswerBriefJson::from_answer(x, form))),
                })
                .collect(),
        }
    }
}

impl PathBriefOut {
    /// The brief form of a full path answer.
    pub fn from_full(o: &PathAnswerOut, form: crate::args::Form) -> Self {
        PathBriefOut {
            rsim_json: o.rsim_json,
            kind: "path_brief".into(),
            topology: o.topology.clone(),
            twin: o.twin.clone(),
            form,
            query: o.query.clone(),
            answer: AnswerBriefJson::from_answer(&o.answer, form),
        }
    }
}

impl SetBriefOut {
    /// The brief form of a full set answer.
    pub fn from_full(o: &SetAnswerOut, form: crate::args::Form) -> Self {
        SetBriefOut {
            rsim_json: o.rsim_json,
            kind: "set_brief".into(),
            topology: o.topology.clone(),
            twin: o.twin.clone(),
            form,
            query: o.query.clone(),
            answer: AnswerBriefJson::from_answer(&o.answer, form),
        }
    }
}
