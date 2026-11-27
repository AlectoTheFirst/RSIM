//! The OpenAPI 3.1 document of the API, generated from the route table and
//! the schemas of the contract types.

use serde_json::{Map, Value, json};

use rsim_contract::args::{PathQueryArgs, SetQueryArgs};
use rsim_contract::claim::{ClaimOut, ClaimsOut};
use rsim_contract::diff::{ClaimDiffOut, QueryDiffOut};
use rsim_contract::json::{PathAnswerOut, PathBriefOut, SetAnswerOut, SetBriefOut, StepOut};
use rsim_contract::schema;
use rsim_contract::source::SourceLinesOut;
use rsim_contract::table::{SummarizeOut, TableDiffOut, TableOut, TablesOut, UniqueOut};
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
    ("columns", "Columns"),
    ("sort", "Sort order"),
    ("limit", "Page size"),
    ("cursor", "Cursor"),
];

/// The routes, in a fixed order.
pub const ROUTES: &[Route] = &[
    Route {
        method: "get",
        path: "/v1",
        id: "getEntry",
        summary: "Entry point",
        query: &[],
        body: &[],
        ok: (200, &[object]),
    },
    Route {
        method: "get",
        path: "/v1/openapi.json",
        id: "getOpenApi",
        summary: "OpenAPI document",
        query: &[],
        body: &[],
        ok: (200, &[object]),
    },
    Route {
        method: "get",
        path: "/v1/tables",
        id: "listTables",
        summary: "Table catalog",
        query: &[],
        body: &[],
        ok: (200, &[schema::<TablesOut>]),
    },
    Route {
        method: "get",
        path: "/v1/claims",
        id: "listClaims",
        summary: "Claim catalog",
        query: &[],
        body: &[],
        ok: (200, &[schema::<ClaimsOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins",
        id: "listTopologies",
        summary: "Twins",
        query: &[],
        body: &[],
        ok: (200, &[object]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}",
        id: "getTwin",
        summary: "Twin",
        query: &[],
        body: &[],
        ok: (200, &[object]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/tables/{table}/rows",
        id: "queryTable",
        summary: "Table rows",
        query: SELECTION,
        body: &[],
        ok: (200, &[schema::<TableOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/tables/{table}/summary",
        id: "summarizeTable",
        summary: "Table summary",
        query: &[],
        body: &[],
        ok: (200, &[schema::<SummarizeOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/tables/{table}/unique",
        id: "uniqueTable",
        summary: "Distinct values",
        query: &[("columns", "Columns")],
        body: &[],
        ok: (200, &[schema::<UniqueOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/tables/{table}/top",
        id: "topTable",
        summary: "Top rows",
        query: &[
            ("column", "Column"),
            ("count", "Row count"),
            ("ascending", "Ascending"),
        ],
        body: &[],
        ok: (200, &[schema::<TableOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/tables/{table}/lpm",
        id: "lpmTable",
        summary: "Longest prefix match",
        query: &[("address", "Address"), ("column", "Prefix column")],
        body: &[],
        ok: (200, &[schema::<TableOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/tables/{table}/export",
        id: "exportTable",
        summary: "Table export",
        query: &[
            ("format", "File format"),
            ("columns", "Columns"),
            ("sort", "Sort order"),
        ],
        body: &[],
        ok: (200, &[]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/tables/{table}/diff",
        id: "diffTable",
        summary: "Table difference",
        query: &[
            ("against", "Compared twin"),
            ("columns", "Columns"),
            ("limit", "Page size"),
            ("cursor", "Cursor"),
        ],
        body: &[],
        ok: (200, &[schema::<TableDiffOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/coverage",
        id: "getCoverage",
        summary: "Coverage report",
        query: &[("limit", "Page size"), ("cursor", "Cursor")],
        body: &[],
        ok: (200, &[schema::<TableOut>]),
    },
    Route {
        method: "post",
        path: "/v1/twins/{twin}/queries",
        id: "createQuery",
        summary: "New query",
        query: &[],
        body: &[schema::<PathQueryArgs>, schema::<SetQueryArgs>],
        ok: (303, &[object]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/queries/{qid}",
        id: "getQuery",
        summary: "Query answer",
        query: &[("form", "Answer form")],
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
        summary: "Trace step",
        query: &[
            ("reply_of", "Reply of branch"),
            ("source_lines", "Source lines"),
        ],
        body: &[],
        ok: (200, &[schema::<StepOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/sources",
        id: "getSourceLines",
        summary: "Source lines",
        query: &[("file", "Source file"), ("lines", "Line range")],
        body: &[],
        ok: (200, &[schema::<SourceLinesOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/queries/{qid}/claims/{claim}",
        id: "runQueryClaim",
        summary: "Query claim",
        query: &[("min", "Minimum MTU")],
        body: &[],
        ok: (200, &[schema::<ClaimOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/claims/{claim}",
        id: "runClaim",
        summary: "Claim",
        query: &[("device", "Devices"), ("min", "Minimum MTU")],
        body: &[],
        ok: (200, &[schema::<ClaimOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/claims/{claim}/diff",
        id: "diffClaim",
        summary: "Claim difference",
        query: &[
            ("against", "Compared twin"),
            ("device", "Devices"),
            ("min", "Minimum MTU"),
        ],
        body: &[],
        ok: (200, &[schema::<ClaimDiffOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/topology",
        id: "getTopology",
        summary: "Topology",
        query: &[
            ("level", "Level"),
            ("layer", "Layers"),
            ("device", "Devices"),
            ("around", "Around device"),
            ("hops", "Hops"),
            ("claims", "Claims"),
            ("format", "Format"),
        ],
        body: &[],
        ok: (200, &[schema::<TopologyOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/queries/{qid}/topology",
        id: "getPathDrawing",
        summary: "Path drawing",
        query: &[("format", "Format")],
        body: &[],
        ok: (200, &[schema::<TopologyOut>]),
    },
    Route {
        method: "get",
        path: "/v1/twins/{twin}/queries/{qid}/diff",
        id: "diffQuery",
        summary: "Query difference",
        query: &[("against", "Compared twin")],
        body: &[],
        ok: (200, &[schema::<QueryDiffOut>]),
    },
    Route {
        method: "post",
        path: "/v1/twins/{twin}/batch",
        id: "runBatch",
        summary: "Batch",
        query: &[],
        body: &[object],
        ok: (200, &[object]),
    },
    Route {
        method: "post",
        path: "/mcp",
        id: "mcpMessage",
        summary: "MCP message",
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

/// Each route of the API: the twin routes, the inventory routes and the
/// sign-in and admin routes.
pub fn all_routes() -> impl Iterator<Item = &'static Route> {
    ROUTES
        .iter()
        .chain(crate::inventory::ROUTES)
        .chain(crate::auth::ROUTES)
}

/// The security requirement of a gate: none for an open route, a session
/// for a route of the browser session, else a session or a token with the
/// scope.
fn security(g: crate::auth::Gate) -> Value {
    use crate::auth::Gate;
    match g {
        Gate::Open => json!([]),
        Gate::Session => json!([{"session": []}]),
        Gate::SignedIn => json!([{"session": []}, {"token": []}]),
        Gate::Scope(s) => json!([{"session": [s]}, {"token": [s]}]),
    }
}

/// The OpenAPI document.
/// The operations whose success is a file, with the media types of the
/// file.
const FILES: &[(&str, &[&str])] = &[(
    "exportTable",
    &["text/csv", "application/vnd.apache.parquet"],
)];

pub fn document() -> Value {
    let mut components = Map::new();
    let mut paths = Map::new();
    for r in all_routes() {
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
        let files = FILES.iter().find(|(id, _)| *id == r.id).map(|f| f.1);
        let success = if let Some(media) = files {
            let content: Map<String, Value> = media
                .iter()
                .map(|m| {
                    (
                        m.to_string(),
                        json!({"schema": {"type": "string", "format": "binary"}}),
                    )
                })
                .collect();
            json!({"description": "Success", "content": content})
        } else if r.ok.1.is_empty() {
            json!({"description": "Success"})
        } else {
            json!({
                "description": "Success",
                "content": {"application/json": {"schema": one_of(r.ok.1, &mut components)}}
            })
        };
        let mut op = json!({
            "operationId": r.id,
            "summary": r.summary,
            "parameters": params,
            "responses": {
                r.ok.0.to_string(): success,
                "default": {
                    "description": "Problem",
                    "content": {"application/problem+json": {"schema": {"$ref": "#/components/schemas/Problem"}}}
                }
            },
            "security": security(crate::auth::gate_of(r))
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
            "description": "Problem",
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
            "description": "rsim REST API",
            "license": {"name": "Apache-2.0", "identifier": "Apache-2.0"}
        },
        "jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
        "paths": paths,
        "components": {
            "schemas": components,
            "securitySchemes": {
                "session": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": crate::auth::COOKIE_HTTPS,
                    "description": "Session cookie"
                },
                "token": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "API token"
                }
            }
        }
    })
}
