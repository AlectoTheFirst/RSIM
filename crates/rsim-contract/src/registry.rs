//! The registry of the operations. The MCP tools, the CLI commands and the
//! HTTP routes come from it.

use serde_json::{Value, json};

use crate::args::{
    PathQueryArgs, SetQueryArgs, StepArgs, TableQueryArgs, TopologyArgs, TopologyViewArgs,
};
use crate::claim::{ClaimArgs, ClaimOut, ClaimsOut};
use crate::json::{
    DevicesOut, ErrorOut, PathAnswerOut, PathBriefOut, SetAnswerOut, SetBriefOut, StepOut,
    TopologiesOut,
};
use crate::schema;
use crate::table::{SummarizeOut, TableOut, TablesOut, UniqueOut};
use crate::topology::TopologyOut;

/// What an operation changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// It changes nothing.
    Read,
    /// It writes scenario files.
    ScenarioWrite,
}

/// An HTTP method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

/// One operation of the registry.
#[derive(Clone, Copy, Debug)]
pub struct Operation {
    /// The `operationId` of the OpenAPI document.
    pub id: &'static str,
    pub description: &'static str,
    pub effect: Effect,
    /// The name of the MCP tool, if the operation is a tool.
    pub tool: Option<&'static str>,
    /// The command of `rsim`, if the operation is a command.
    pub command: Option<&'static str>,
    /// The HTTP method and path, if the operation is an HTTP operation.
    pub http: Option<(Method, &'static str)>,
    /// The schema of the arguments, if the operation takes arguments.
    pub input: Option<fn() -> Value>,
    /// The schemas of the success outputs.
    pub outputs: &'static [fn() -> Value],
}

/// The operations, in a fixed order.
pub const OPERATIONS: &[Operation] = &[
    Operation {
        id: "listTopologies",
        description: "The names of the built-in topologies.",
        effect: Effect::Read,
        tool: None,
        command: Some("topologies"),
        http: Some((Method::Get, "/v1/twins")),
        input: None,
        outputs: &[schema::<TopologiesOut>],
    },
    Operation {
        id: "listDevices",
        description: "The devices, their functions and the endpoints of a topology.",
        effect: Effect::Read,
        tool: Some("list_devices"),
        command: Some("devices"),
        http: Some((Method::Get, "/v1/twins/{twin}/tables/devices/rows")),
        input: Some(schema::<TopologyArgs>),
        outputs: &[schema::<DevicesOut>],
    },
    Operation {
        id: "runPathQuery",
        description: "The answer for one packet: the ingress, each branch with its verdict, its delay and its trace, and the reply of each delivered branch. A field that the query does not state is not known, or takes its default value with unstated defaults; the notes of the answer name each default.",
        effect: Effect::Read,
        tool: Some("path_query"),
        command: Some("path"),
        http: Some((Method::Post, "/v1/twins/{twin}/queries")),
        input: Some(schema::<PathQueryArgs>),
        outputs: &[schema::<PathBriefOut>, schema::<PathAnswerOut>],
    },
    Operation {
        id: "runSetQuery",
        description: "The answer for a set of packets: the parts of the set with their results, the ingress of each part, each branch with its trace, and the replies. A field that is not given has all values.",
        effect: Effect::Read,
        tool: Some("set_query"),
        command: Some("set"),
        http: Some((Method::Post, "/v1/twins/{twin}/queries")),
        input: Some(schema::<SetQueryArgs>),
        outputs: &[schema::<SetBriefOut>, schema::<SetAnswerOut>],
    },
    Operation {
        id: "getStep",
        description: "One trace step of a path query or of a set query, with its function, its reason and its source spans. The query runs again.",
        effect: Effect::Read,
        tool: Some("explain_step"),
        command: Some("explain"),
        http: Some((
            Method::Get,
            "/v1/twins/{twin}/queries/{qid}/branches/{b}/steps/{s}",
        )),
        input: Some(schema::<StepArgs>),
        outputs: &[schema::<StepOut>],
    },
    Operation {
        id: "listTables",
        description: "The catalog of the tables: each table with its key, its columns with their types and meanings, its verbs, and the data that it needs.",
        effect: Effect::Read,
        tool: Some("list_tables"),
        command: Some("tables"),
        http: Some((Method::Get, "/v1/tables")),
        input: Some(empty),
        outputs: &[schema::<TablesOut>],
    },
    Operation {
        id: "queryTable",
        description: "A table of a twin with a verb: show the rows with filters, columns, sort and pages; summarize; unique values; top rows; or the longest prefix match of an address. A table with no rows for a built-in topology needs data that only a store has.",
        effect: Effect::Read,
        tool: Some("table_query"),
        command: Some("<twin> <table>"),
        http: Some((Method::Get, "/v1/twins/{twin}/tables/{table}/rows")),
        input: Some(schema::<TableQueryArgs>),
        outputs: &[
            schema::<TableOut>,
            schema::<UniqueOut>,
            schema::<SummarizeOut>,
        ],
    },
    Operation {
        id: "listClaims",
        description: "The catalog of the claims: assessment questions about the network, with their scopes and the data that they read.",
        effect: Effect::Read,
        tool: Some("list_claims"),
        command: Some("<twin> claim list"),
        http: Some((Method::Get, "/v1/claims")),
        input: Some(empty),
        outputs: &[schema::<ClaimsOut>],
    },
    Operation {
        id: "runClaim",
        description: "A claim on a scope: the whole twin, a set of devices, or the paths of a path query. The result is confirmed, refuted or unknown, with evidence rows; data that is not collected gives unknown.",
        effect: Effect::Read,
        tool: Some("run_claim"),
        command: Some("<twin> claim run"),
        http: Some((Method::Get, "/v1/twins/{twin}/claims/{claim}")),
        input: Some(schema::<ClaimArgs>),
        outputs: &[schema::<ClaimOut>],
    },
    Operation {
        id: "getTopology",
        description: "The topology of a twin for a drawing: the nodes at the level device or function, and the edges of the layers physical and overlay, or function, with the link facts and the result of the claim link-speed-duplex on each edge.",
        effect: Effect::Read,
        tool: Some("get_topology"),
        command: Some("<twin> topology"),
        http: Some((Method::Get, "/v1/twins/{twin}/topology")),
        input: Some(schema::<TopologyViewArgs>),
        outputs: &[schema::<TopologyOut>],
    },
];

/// The schema of an operation with no arguments.
fn empty() -> Value {
    json!({"type": "object", "properties": {}})
}

/// The operation of an MCP tool.
pub fn by_tool(tool: &str) -> Option<&'static Operation> {
    OPERATIONS.iter().find(|o| o.tool == Some(tool))
}

/// The input schema of a tool: the schema of its arguments, with the
/// topology names as an enumeration and no other field.
pub fn tool_input(op: &Operation, topologies: &[&str]) -> Value {
    let mut s = op.input.map_or_else(|| json!({"type": "object"}), |f| f());
    if let Some(t) = s.pointer_mut("/properties/topology") {
        t["enum"] = json!(topologies);
    }
    s["additionalProperties"] = json!(false);
    s
}

/// The output schema of a tool: one of its success outputs, or the error
/// object.
pub fn tool_output(op: &Operation) -> Value {
    let mut any: Vec<Value> = op.outputs.iter().map(|f| strip(f())).collect();
    any.push(strip(schema::<ErrorOut>()));
    let mut defs = serde_json::Map::new();
    for s in op.outputs.iter().map(|f| f()).chain([schema::<ErrorOut>()]) {
        if let Some(Value::Object(d)) = s.get("$defs") {
            for (k, v) in d {
                defs.insert(k.clone(), v.clone());
            }
        }
    }
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "anyOf": any,
        "$defs": defs
    })
}

/// A schema with no `$schema` and no `$defs`, for a place inside another
/// schema that holds the definitions.
fn strip(mut s: Value) -> Value {
    if let Value::Object(m) = &mut s {
        m.remove("$schema");
        m.remove("$defs");
    }
    s
}
