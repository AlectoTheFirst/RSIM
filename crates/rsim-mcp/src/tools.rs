//! The tools of the server: their definitions and their calls.

use std::collections::BTreeMap;

use rsim_cli::json::{self, ErrorOut};
use rsim_cli::{QueryError, Twin, args, commands};
use serde::Serialize;
use serde_json::{Map, Value, json};

/// The result of a tool: the output object as compact JSON, and true if it
/// is the error object.
pub struct Output {
    pub json: String,
    pub is_error: bool,
}

/// Runs tools. It keeps the twin of each topology that a call named, and no
/// answer.
#[derive(Default)]
pub struct Tools {
    twins: BTreeMap<String, Twin>,
}

impl Tools {
    fn twin(&mut self, topology: &str) -> Result<&Twin, QueryError> {
        if !self.twins.contains_key(topology) {
            let twin = commands::load(topology)?;
            self.twins.insert(topology.to_string(), twin);
        }
        match self.twins.get(topology) {
            Some(t) => Ok(t),
            None => unreachable!("the twin was inserted"),
        }
    }

    /// Calls the tool `name`. `None` is a name that is not a tool.
    pub fn call(&mut self, name: &str, arguments: &Map<String, Value>) -> Option<Output> {
        let r = match name {
            "list_devices" => args::topology(arguments)
                .and_then(|t| self.twin(&t).map(|twin| commands::devices(&t, twin)))
                .map(|o| text(&o)),
            "path_query" => args::query(arguments, &[])
                .and_then(|q| self.twin(&q.topology).and_then(|t| commands::path(&q, t)))
                .map(|o| text(&o)),
            "explain_step" => args::step(arguments)
                .and_then(|(q, at)| {
                    self.twin(&q.topology)
                        .and_then(|t| commands::explain(&q, at, t))
                })
                .map(|o| text(&o)),
            _ => return None,
        };
        Some(match r {
            Ok(json) => Output {
                json,
                is_error: false,
            },
            Err(e) => Output {
                json: text(&ErrorOut::new(e)),
                is_error: true,
            },
        })
    }
}

fn text<T: Serialize>(v: &T) -> String {
    json::to_text(v, false)
}

/// The tool definitions: `list_devices`, `path_query` and `explain_step`.
pub fn definitions() -> Value {
    let topology = json!({
        "type": "string",
        "enum": commands::topology_names(),
        "description": "A built-in topology."
    });
    let mut query = Map::new();
    let text = |d: &str| json!({"type": "string", "description": d});
    for (k, v) in [
        ("topology", topology.clone()),
        (
            "ingress",
            text(
                "The ingress point as <device>/<interface>. Without it, the attachment records of the source address give the ingress.",
            ),
        ),
        ("source.ip", text("The source IP address.")),
        ("destination.ip", text("The destination IP address.")),
        ("network.iana_number", int(255, "The protocol number.")),
        (
            "network.transport",
            json!({
                "type": "string",
                "enum": ["tcp", "udp", "icmp", "icmpv6"],
                "description": "The protocol name. Give network.iana_number or network.transport."
            }),
        ),
        ("source.port", int(65535, "The source port.")),
        ("destination.port", int(65535, "The destination port.")),
        (
            "source.mac",
            text("The source MAC address: 6 hexadecimal bytes with colons."),
        ),
        (
            "destination.mac",
            text("The destination MAC address: 6 hexadecimal bytes with colons."),
        ),
        ("network.vlan.id", int(4095, "The VLAN tag.")),
        (
            "l2_priority",
            int(7, "The layer 2 priority. It needs network.vlan.id."),
        ),
        (
            "tcp_flags",
            json!({
                "type": "array",
                "items": {"enum": ["fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"]},
                "description": "The TCP flags that are set."
            }),
        ),
        (
            "icmp_type",
            json!({
                "description": "0 to 255, echo-request or echo-reply.",
                "anyOf": [
                    {"type": "string", "enum": ["echo-request", "echo-reply"]},
                    {"type": "integer", "minimum": 0, "maximum": 255}
                ]
            }),
        ),
        ("icmp_code", int(255, "The ICMP code.")),
        ("dscp", int(63, "The DSCP.")),
        ("ecn", int(3, "The ECN.")),
        (
            "fragment",
            json!({
                "type": "string",
                "enum": ["unfragmented", "first", "later"],
                "description": "The fragment state."
            }),
        ),
        (
            "reply",
            json!({"type": "boolean", "description": "Run the reply. The default is true."}),
        ),
    ] {
        query.insert(k.to_string(), v);
    }
    let query_required = json!(["topology", "source.ip", "destination.ip"]);
    let mut step = query.clone();
    step.insert(
        "branch".to_string(),
        int(u32::MAX as u64, "The branch index."),
    );
    step.insert(
        "step".to_string(),
        int(u32::MAX as u64, "The step index in the branch."),
    );
    step.insert(
        "reply_of".to_string(),
        int(
            u32::MAX as u64,
            "Select the reply of this forward branch. Then branch and step are indexes in the reply.",
        ),
    );

    json!([
        {
            "name": "list_devices",
            "description": "The devices, their functions and the endpoints of a built-in topology.",
            "inputSchema": {
                "type": "object",
                "properties": {"topology": topology},
                "required": ["topology"],
                "additionalProperties": false
            },
            "outputSchema": output_schema("devices", &["topology", "devices", "endpoints"])
        },
        {
            "name": "path_query",
            "description": "The answer for one packet: the ingress, each branch with its verdict, its delay and its trace, and the reply of each delivered branch. A field that the query does not state is not known.",
            "inputSchema": {
                "type": "object",
                "properties": query,
                "required": query_required,
                "additionalProperties": false
            },
            "outputSchema": output_schema("path_answer", &["topology", "query", "answer"])
        },
        {
            "name": "explain_step",
            "description": "One trace step of a path query, with its function, its reason and its source spans. The tool runs the query again.",
            "inputSchema": {
                "type": "object",
                "properties": step,
                "required": ["topology", "source.ip", "destination.ip", "branch", "step"],
                "additionalProperties": false
            },
            "outputSchema": output_schema(
                "step",
                &["topology", "query", "reply_of", "branch", "step", "trace_step"]
            )
        }
    ])
}

fn int(max: u64, description: &str) -> Value {
    json!({"type": "integer", "minimum": 0, "maximum": max, "description": description})
}

/// The output object of kind `kind`, or the error object.
fn output_schema(kind: &str, fields: &[&str]) -> Value {
    let mut required = vec!["rsim_json", "kind"];
    required.extend_from_slice(fields);
    json!({
        "type": "object",
        "anyOf": [
            {
                "type": "object",
                "properties": {
                    "rsim_json": {"const": json::VERSION},
                    "kind": {"const": kind}
                },
                "required": required
            },
            {
                "type": "object",
                "properties": {
                    "rsim_json": {"const": json::VERSION},
                    "kind": {"const": "error"},
                    "error": {
                        "type": "object",
                        "properties": {
                            "code": {"enum": [
                                "unknown_topology", "unknown_ingress", "invalid_query",
                                "no_such_step", "start_requires_context",
                                "contract_violation", "internal"
                            ]},
                            "detail": {"type": "string"}
                        },
                        "required": ["code", "detail"]
                    }
                },
                "required": ["rsim_json", "kind", "error"]
            }
        ]
    })
}
