//! The registry of the operations. The MCP tools, the CLI commands and the
//! HTTP routes come from it.

use serde_json::{Value, json};

use crate::args::{
    LayerArgs, PathQueryArgs, SetQueryArgs, StepArgs, TableQueryArgs, TopologyArgs,
    TopologyViewArgs,
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
    /// True if the tool takes the layers of [`LayerArgs`] on a store twin.
    pub layers: bool,
    /// The schemas of the success outputs.
    pub outputs: &'static [fn() -> Value],
}

/// The operations, in a fixed order.
pub const OPERATIONS: &[Operation] = &[
    Operation {
        id: "listTopologies",
        description: "Twins",
        effect: Effect::Read,
        tool: None,
        command: None,
        http: Some((Method::Get, "/v1/twins")),
        input: None,
        layers: false,
        outputs: &[schema::<TopologiesOut>],
    },
    Operation {
        id: "listDevices",
        description: "Devices",
        effect: Effect::Read,
        tool: Some("list_devices"),
        command: Some("devices"),
        http: Some((Method::Get, "/v1/twins/{twin}/tables/devices/rows")),
        input: Some(schema::<TopologyArgs>),
        layers: false,
        outputs: &[schema::<DevicesOut>],
    },
    Operation {
        id: "runPathQuery",
        description: "Path query",
        effect: Effect::Read,
        tool: Some("path_query"),
        command: Some("path"),
        http: Some((Method::Post, "/v1/twins/{twin}/queries")),
        input: Some(schema::<PathQueryArgs>),
        layers: true,
        outputs: &[schema::<PathBriefOut>, schema::<PathAnswerOut>],
    },
    Operation {
        id: "runSetQuery",
        description: "Set query",
        effect: Effect::Read,
        tool: Some("set_query"),
        command: Some("set"),
        http: Some((Method::Post, "/v1/twins/{twin}/queries")),
        input: Some(schema::<SetQueryArgs>),
        layers: true,
        outputs: &[schema::<SetBriefOut>, schema::<SetAnswerOut>],
    },
    Operation {
        id: "getStep",
        description: "Trace step",
        effect: Effect::Read,
        tool: Some("explain_step"),
        command: Some("explain"),
        http: Some((
            Method::Get,
            "/v1/twins/{twin}/queries/{qid}/branches/{b}/steps/{s}",
        )),
        input: Some(schema::<StepArgs>),
        layers: true,
        outputs: &[schema::<StepOut>],
    },
    Operation {
        id: "listTables",
        description: "Table catalog",
        effect: Effect::Read,
        tool: Some("list_tables"),
        command: Some("tables"),
        http: Some((Method::Get, "/v1/tables")),
        input: Some(empty),
        layers: false,
        outputs: &[schema::<TablesOut>],
    },
    Operation {
        id: "queryTable",
        description: "Table query",
        effect: Effect::Read,
        tool: Some("table_query"),
        command: Some("<twin> <table>"),
        http: Some((Method::Get, "/v1/twins/{twin}/tables/{table}/rows")),
        input: Some(schema::<TableQueryArgs>),
        layers: true,
        outputs: &[
            schema::<TableOut>,
            schema::<UniqueOut>,
            schema::<SummarizeOut>,
        ],
    },
    Operation {
        id: "listClaims",
        description: "Claim catalog",
        effect: Effect::Read,
        tool: Some("list_claims"),
        command: Some("<twin> claim list"),
        http: Some((Method::Get, "/v1/claims")),
        input: Some(empty),
        layers: false,
        outputs: &[schema::<ClaimsOut>],
    },
    Operation {
        id: "runClaim",
        description: "Claim result",
        effect: Effect::Read,
        tool: Some("run_claim"),
        command: Some("<twin> claim run"),
        http: Some((Method::Get, "/v1/twins/{twin}/claims/{claim}")),
        input: Some(schema::<ClaimArgs>),
        layers: true,
        outputs: &[schema::<ClaimOut>],
    },
    Operation {
        id: "getTopology",
        description: "Topology",
        effect: Effect::Read,
        tool: Some("get_topology"),
        command: Some("<twin> topology"),
        http: Some((Method::Get, "/v1/twins/{twin}/topology")),
        input: Some(schema::<TopologyViewArgs>),
        layers: false,
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

/// The input schema of a tool: the schema of its arguments and, with
/// `layers`, the fields of [`LayerArgs`], with the topology names as an
/// enumeration and no other field.
pub fn tool_input(op: &Operation, topologies: &[&str]) -> Value {
    let mut s = op.input.map_or_else(|| json!({"type": "object"}), |f| f());
    if op.layers
        && let (Some(Value::Object(props)), Value::Object(extra)) = (
            s.get_mut("properties"),
            schema::<LayerArgs>()["properties"].take(),
        )
    {
        props.extend(extra);
    }
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
