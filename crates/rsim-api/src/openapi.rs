//! The OpenAPI 3.1 document of the API, generated from the route table and
//! the schemas of the contract types.

use serde_json::{Map, Value, json};

use rsim_contract::args::{PathQueryArgs, SetQueryArgs};
use rsim_contract::claim::{ClaimOut, ClaimsOut};
use rsim_contract::json::{PathAnswerOut, PathBriefOut, SetAnswerOut, SetBriefOut, StepOut};
use rsim_contract::schema;
use rsim_contract::table::{SummarizeOut, TableOut, TablesOut, UniqueOut};
use rsim_contract::topology::TopologyOut;

use crate::handler::contract_version;

/// One HTTP operation of the API.
pub struct Route {
    pub method: &'static str,
    pub path: &'static str,
    pub id: &'static str,
    pub summary: &'static str,
    /// The query parameters: name and description.
    pub query: &'static [(&'static str, &'static str)],
    /// The schemas of the request body, if the operation takes one.
    pub body: &'static [fn() -> Value],
    /// The status of a success and the schemas of its body.
    pub ok: (u16, &'static [fn() -> Value]),
}

fn object() -> Value {
    json!({"type": "object"})
}

const SELECTION: &[(&str, &str)] = &[
    ("columns", "The columns of the output, separated by commas."),
    (
        "sort",
        "The order: column names separated by commas, - before a name for a falling order.",
    ),
    ("limit", "The number of rows of a page."),
    ("cursor", "The cursor of the next page."),
];

/// The routes, in a fixed order.
pub const ROUTES: &[Route] = &[
    Route {
        method: "get",
        path: "/v1",
        id: "getEntry",
        summary: "The entry point: the links, the contract version and the limits.",
        query: &[],
        body: &[],
        ok: (200, &[object]),
    },
    Route {
        method: "get",
        path: "/v1/openapi.json",
        id: "getOpenApi",
        summary: "This document.",
        query: &[],
        body: &[],
        ok: (200, &[object]),
    },
    Route {
        method: "get",
        path: "/v1/tables",
        id: "listTables",
        summary: "The catalog of the tables.",
        query: &[],
        body: &[],
        ok: (200, &[schema::<TablesOut>]),
    },
    Route {
        method: "get",
        path: "/v1/claims",
        id: "listClaims",
        summary: "The catalog of the claims.",
        query: &[],
        body: &[],
        ok: (200, &[schema::<ClaimsOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins",
        id: "listTopologies",
        summary: "The twins of the server: the built-in topologies, and the alias store.",
        query: &[],
        body: &[],
        ok: (200, &[object]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}",
        id: "getTwin",
        summary: "A twin: its identity and its links. The alias store redirects to its snapshot.",
        query: &[],
        body: &[],
        ok: (200, &[object]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/tables/{table}/rows",
        id: "queryTable",
        summary: "The rows of a table. Each other parameter <column>=v1,v2 is an equality filter, and <column>.<op>=v a typed filter with the op contains, prefix, gt, lt or in_prefix.",
        query: SELECTION,
        body: &[],
        ok: (200, &[schema::<TableOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/tables/{table}/summary",
        id: "summarizeTable",
        summary: "The counts of a table and of each column, with the filters of the rows.",
        query: &[],
        body: &[],
        ok: (200, &[schema::<SummarizeOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/tables/{table}/unique",
        id: "uniqueTable",
        summary: "The distinct values of the columns with their counts.",
        query: &[("columns", "The columns, separated by commas.")],
        body: &[],
        ok: (200, &[schema::<UniqueOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/tables/{table}/top",
        id: "topTable",
        summary: "The rows with the largest values of a column.",
        query: &[
            ("column", "The column."),
            ("count", "The number of rows; 5 if not given."),
            ("ascending", "true for the smallest values."),
        ],
        body: &[],
        ok: (200, &[schema::<TableOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/tables/{table}/lpm",
        id: "lpmTable",
        summary: "The rows of the longest prefix that contains an address.",
        query: &[
            ("address", "The address."),
            ("column", "The prefix column; prefix if not given."),
        ],
        body: &[],
        ok: (200, &[schema::<TableOut>]),
    },
    Route {
        method: "post",
        path: "/v1/twins/{twin}/queries",
        id: "createQuery",
        summary: "Makes a query resource from the arguments of a path query, or of a set query with mode set. The answer is 303 to the resource.",
        query: &[],
        body: &[schema::<PathQueryArgs>, schema::<SetQueryArgs>],
        ok: (303, &[object]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/queries/{qid}",
        id: "getQuery",
        summary: "The answer of a query. The query runs again on each request.",
        query: &[("form", "summary (the default), steps or full.")],
        body: &[],
        ok: (
            200,
            &[
                schema::<PathBriefOut>,
                schema::<SetBriefOut>,
                schema::<PathAnswerOut>,
                schema::<SetAnswerOut>,
            ],
        ),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/queries/{qid}/branches/{branch}/steps/{step}",
        id: "getStep",
        summary: "One trace step of the answer of a query.",
        query: &[("reply_of", "Select the reply of this forward branch.")],
        body: &[],
        ok: (200, &[schema::<StepOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/queries/{qid}/claims/{claim}",
        id: "runQueryClaim",
        summary: "A claim on the paths of a path query.",
        query: &[],
        body: &[],
        ok: (200, &[schema::<ClaimOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/claims/{claim}",
        id: "runClaim",
        summary: "A claim on the twin, or on the devices of the parameter device.",
        query: &[("device", "The devices of the scope, separated by commas.")],
        body: &[],
        ok: (200, &[schema::<ClaimOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/topology",
        id: "getTopology",
        summary: "The topology of a twin for a drawing: nodes and edges at the level device or function, with the layers physical and overlay, or function.",
        query: &[
            ("level", "device (the default) or function."),
            ("layer", "The layers, separated by commas."),
            ("device", "Only these devices, separated by commas."),
            ("around", "Only the devices near this device."),
            ("hops", "The number of links of around; 1 if not given."),
            ("claims", "The claims of each edge: link-speed-duplex."),
            ("format", "json (the default), mermaid, d2 or graphml."),
        ],
        body: &[],
        ok: (200, &[schema::<TopologyOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/queries/{qid}/topology",
        id: "getPathDrawing",
        summary: "The drawing of the paths of a query: each hop with its branches, and for a tunnel the overlay edge and the underlay edges that name it.",
        query: &[("format", "json (the default), mermaid, d2 or graphml.")],
        body: &[],
        ok: (200, &[schema::<TopologyOut>]),
    },
    Route {
        method: "post",
        path: "/v1/twins/{twin}/batch",
        id: "runBatch",
        summary: "Many queries, claims and table queries in one request: an object with a list items, each with op query, claim or table. The answer is NDJSON with one line for each item, its result or its problem object. At most 100 items.",
        query: &[],
        body: &[object],
        ok: (200, &[object]),
    },
    Route {
        method: "post",
        path: "/mcp",
        id: "mcpMessage",
        summary: "The Model Context Protocol through its Streamable HTTP transport, revision 2026-07-28: one JSON-RPC message in the body; the headers MCP-Protocol-Version, Mcp-Method and, for tools/call, Mcp-Name must agree with it. A request gets its response; a notification gets 202. The tools are the tools of rsim-mcp.",
        query: &[],
        body: &[object],
        ok: (200, &[object]),
    },
];

/// Moves the definitions of a schema into `components`, with each
/// reference to them, and gives a reference to the schema.
fn component(mut s: Value, components: &mut Map<String, Value>) -> Value {
    fn rewrite(v: &mut Value) {
        match v {
            Value::Object(m) => {
                if let Some(Value::String(r)) = m.get_mut("$ref")
                    && let Some(rest) = r.strip_prefix("#/$defs/")
                {
                    *r = format!("#/components/schemas/{rest}");
                }
                for c in m.values_mut() {
                    rewrite(c);
                }
            }
            Value::Array(a) => a.iter_mut().for_each(rewrite),
            _ => {}
        }
    }
    rewrite(&mut s);
    let Value::Object(mut m) = s else {
        return s;
    };
    m.remove("$schema");
    if let Some(Value::Object(defs)) = m.remove("$defs") {
        for (k, v) in defs {
            components.insert(k, v);
        }
    }
    match m.get("title").and_then(Value::as_str).map(str::to_string) {
        Some(name)
            if m.get("type").is_some() || m.get("oneOf").is_some() || m.get("anyOf").is_some() =>
        {
            components.insert(name.clone(), Value::Object(m));
            json!({"$ref": format!("#/components/schemas/{name}")})
        }
        _ => Value::Object(m),
    }
}

fn one_of(list: &[fn() -> Value], components: &mut Map<String, Value>) -> Value {
    let v: Vec<Value> = list.iter().map(|f| component(f(), components)).collect();
    match v.as_slice() {
        [one] => one.clone(),
        _ => json!({"oneOf": v}),
    }
}

/// The OpenAPI document.
pub fn document() -> Value {
    let mut components = Map::new();
    let mut paths = Map::new();
    for r in ROUTES {
        let mut params: Vec<Value> = r
            .path
            .split('/')
            .filter_map(|seg| seg.strip_prefix('{')?.strip_suffix('}'))
            .map(|name| {
                json!({"name": name, "in": "path", "required": true, "schema": {"type": "string"}})
            })
            .collect();
        params.extend(r.query.iter().map(|(name, d)| {
            json!({"name": name, "in": "query", "required": false, "description": d, "schema": {"type": "string"}})
        }));
        let ok = one_of(r.ok.1, &mut components);
        let mut op = json!({
            "operationId": r.id,
            "summary": r.summary,
            "parameters": params,
            "responses": {
                r.ok.0.to_string(): {
                    "description": "Success",
                    "content": {"application/json": {"schema": ok}}
                },
                "default": {
                    "description": "A problem",
                    "content": {"application/problem+json": {"schema": {"$ref": "#/components/schemas/Problem"}}}
                }
            },
            "security": [{"rsim": ["rsim.read"]}]
        });
        if !r.body.is_empty() {
            op["requestBody"] = json!({
                "required": true,
                "content": {"application/json": {"schema": one_of(r.body, &mut components)}}
            });
        }
        let entry = paths.entry(r.path.to_string()).or_insert_with(|| json!({}));
        entry[r.method] = op;
    }
    components.insert(
        "Problem".into(),
        json!({
            "type": "object",
            "description": "A problem object of RFC 9457 with the rsim error code.",
            "properties": {
                "type": {"type": "string"},
                "title": {"type": "string"},
                "status": {"type": "integer"},
                "detail": {"type": "string"},
                "code": {"type": "string"},
                "rsim_json": {"type": "integer"}
            },
            "required": ["type", "title", "status", "detail", "code", "rsim_json"]
        }),
    );
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "rsim",
            "version": contract_version(),
            "description": "The REST API of the rsim network digital twin. Each table, query and claim is below its twin. GraphQL, Cypher and gRPC are not used.",
            "license": {"name": "MIT", "identifier": "MIT"}
        },
        "jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
        "paths": paths,
        "components": {
            "schemas": components,
            "securitySchemes": {
                "rsim": {
                    "type": "oauth2",
                    "description": "Not checked yet: the server listens only on a loopback address. The scope rsim.scenario.write is for the what-if scenarios.",
                    "flows": {
                        "clientCredentials": {
                            "tokenUrl": "/oauth/token",
                            "scopes": {
                                "rsim.read": "Read the twins, the tables, the queries and the claims.",
                                "rsim.scenario.write": "Make and change what-if scenarios."
                            }
                        }
                    }
                }
            }
        }
    })
}
