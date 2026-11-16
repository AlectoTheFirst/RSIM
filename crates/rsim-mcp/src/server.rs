//! The MCP protocol on stdio: one JSON-RPC 2.0 message on each line.
//!
//! The server serves the revisions `2026-07-28` and `2025-11-25`. A request
//! with no handshake uses `2026-07-28` and carries its revision in
//! `params._meta`. An `initialize` request selects `2025-11-25` for the rest
//! of the process.

use std::io::{BufRead, Write};

use serde::Serialize;
use serde_json::value::RawValue;
use serde_json::{Map, Value, json};

use crate::tools::{Output, Tools, definitions};

pub const MODERN: &str = "2026-07-28";
pub const LEGACY: &str = "2025-11-25";
const SUPPORTED: [&str; 2] = [MODERN, LEGACY];

const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";
const TTL_MS: u64 = 3_600_000;

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const UNSUPPORTED_VERSION: i64 = -32022;

/// A JSON-RPC error.
#[derive(Debug, Serialize)]
pub struct RpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        RpcError {
            code,
            message: message.into(),
            data: None,
        }
    }
}

#[derive(Serialize)]
struct Response<'a, R: Serialize> {
    jsonrpc: &'static str,
    id: &'a Value,
    result: R,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    jsonrpc: &'static str,
    id: &'a Value,
    error: RpcError,
}

#[derive(Serialize)]
struct TextItem<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    text: &'a str,
}

#[derive(Serialize)]
struct ToolResult<'a> {
    #[serde(rename = "resultType", skip_serializing_if = "Option::is_none")]
    result_type: Option<&'static str>,
    content: [TextItem<'a>; 1],
    #[serde(rename = "structuredContent")]
    structured_content: &'a RawValue,
    #[serde(rename = "isError")]
    is_error: bool,
}

/// The state of one server process.
#[derive(Default)]
pub struct Server {
    /// True after an `initialize` request: the process uses `2025-11-25`.
    legacy: bool,
    tools: Tools,
}

impl Server {
    /// A server with these tools.
    pub fn new(tools: Tools) -> Server {
        Server {
            legacy: false,
            tools,
        }
    }
}

fn server_info() -> Value {
    json!({"name": "rsim-mcp", "version": env!("CARGO_PKG_VERSION")})
}

fn capabilities() -> Value {
    json!({"tools": {"listChanged": false}})
}

fn to_line<T: Serialize>(v: &T) -> String {
    match serde_json::to_string(v) {
        Ok(s) => s,
        Err(e) => unreachable!("the protocol types serialize to JSON without error: {e}"),
    }
}

fn error_line(id: &Value, error: RpcError) -> String {
    to_line(&ErrorResponse {
        jsonrpc: "2.0",
        id,
        error,
    })
}

impl Server {
    /// Reads messages until the end of the input and writes one response
    /// line for each request.
    pub fn serve(
        &mut self,
        mut input: impl BufRead,
        mut output: impl Write,
    ) -> std::io::Result<()> {
        let mut line = Vec::new();
        loop {
            line.clear();
            if input.read_until(b'\n', &mut line)? == 0 {
                return Ok(());
            }
            if let Some(out) = self.handle_line(&line) {
                output.write_all(out.as_bytes())?;
                output.write_all(b"\n")?;
                output.flush()?;
            }
        }
    }

    /// The response to one line, or `None` for a notification, a response
    /// or an empty line.
    pub fn handle_line(&mut self, line: &[u8]) -> Option<String> {
        if line.trim_ascii().is_empty() {
            return None;
        }
        let msg: Value = match serde_json::from_slice(line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("rsim-mcp: a line is not JSON: {e}");
                return Some(error_line(
                    &Value::Null,
                    RpcError::new(PARSE_ERROR, "Parse error"),
                ));
            }
        };
        let Some(obj) = msg.as_object() else {
            return Some(error_line(
                &Value::Null,
                RpcError::new(INVALID_REQUEST, "Invalid Request: not an object"),
            ));
        };
        let method = obj.get("method").and_then(Value::as_str);
        let id = obj.get("id");
        if method.is_none()
            && id.is_some()
            && (obj.contains_key("result") || obj.contains_key("error"))
        {
            // A response from the client. The server sends no request, so
            // there is nothing to match.
            return None;
        }
        let valid_id = matches!(id, None | Some(Value::String(_)) | Some(Value::Number(_)));
        let (Some(method), true, Some("2.0")) =
            (method, valid_id, obj.get("jsonrpc").and_then(Value::as_str))
        else {
            let id = id.filter(|_| valid_id).unwrap_or(&Value::Null);
            return Some(error_line(
                id,
                RpcError::new(INVALID_REQUEST, "Invalid Request"),
            ));
        };
        let params = obj.get("params");
        let Some(id) = id else {
            // A notification. `notifications/initialized` and all other
            // notifications need no action.
            return None;
        };
        Some(match self.request(method, params) {
            Ok(result) => {
                let result = match RawValue::from_string(result) {
                    Ok(r) => r,
                    Err(e) => unreachable!("a result is JSON: {e}"),
                };
                to_line(&Response {
                    jsonrpc: "2.0",
                    id,
                    result: &result,
                })
            }
            Err(e) => {
                eprintln!("rsim-mcp: {method}: error {}: {}", e.code, e.message);
                error_line(id, e)
            }
        })
    }

    /// The result of a request as JSON text.
    fn request(&mut self, method: &str, params: Option<&Value>) -> Result<String, RpcError> {
        if method == "initialize" {
            self.legacy = true;
            return Ok(to_line(&json!({
                "protocolVersion": LEGACY,
                "capabilities": capabilities(),
                "serverInfo": server_info()
            })));
        }
        if self.legacy {
            return match method {
                "ping" => Ok("{}".to_string()),
                "tools/list" => Ok(to_line(&json!({"tools": definitions(&self.tools.names())}))),
                "tools/call" => self.tools_call(params, None),
                _ => Err(not_found(method)),
            };
        }
        if !matches!(method, "server/discover" | "tools/list" | "tools/call") {
            return Err(not_found(method));
        }
        check_meta(params)?;
        match method {
            "server/discover" => Ok(to_line(&json!({
                "resultType": "complete",
                "supportedVersions": SUPPORTED,
                "capabilities": capabilities(),
                "_meta": {META_SERVER_INFO: server_info()},
                "ttlMs": TTL_MS,
                "cacheScope": "public"
            }))),
            "tools/list" => Ok(to_line(&json!({
                "resultType": "complete",
                "tools": definitions(&self.tools.names()),
                "ttlMs": TTL_MS,
                "cacheScope": "public"
            }))),
            _ => self.tools_call(params, Some("complete")),
        }
    }

    fn tools_call(
        &mut self,
        params: Option<&Value>,
        result_type: Option<&'static str>,
    ) -> Result<String, RpcError> {
        let params = params.and_then(Value::as_object).ok_or_else(|| {
            RpcError::new(INVALID_PARAMS, "Invalid params: params is not an object")
        })?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, "Invalid params: name is not a string"))?;
        let empty = Map::new();
        let arguments = match params.get("arguments") {
            None | Some(Value::Null) => &empty,
            Some(Value::Object(m)) => m,
            Some(_) => {
                return Err(RpcError::new(
                    INVALID_PARAMS,
                    "Invalid params: arguments is not an object",
                ));
            }
        };
        let Some(Output { json, is_error }) = self.tools.call(name, arguments) else {
            return Err(RpcError::new(
                INVALID_PARAMS,
                format!("Unknown tool: {name}"),
            ));
        };
        let raw = match RawValue::from_string(json.clone()) {
            Ok(r) => r,
            Err(e) => unreachable!("the tool output is JSON: {e}"),
        };
        Ok(to_line(&ToolResult {
            result_type,
            content: [TextItem {
                kind: "text",
                text: &json,
            }],
            structured_content: &raw,
            is_error,
        }))
    }
}

fn not_found(method: &str) -> RpcError {
    RpcError::new(METHOD_NOT_FOUND, format!("Method not found: {method}"))
}

/// Checks the request metadata of a request with no handshake. The error
/// for a revision other than `2026-07-28` lists only `2026-07-28` as
/// supported.
fn check_meta(params: Option<&Value>) -> Result<(), RpcError> {
    let missing = |what: &str| RpcError::new(INVALID_PARAMS, format!("Invalid params: {what}"));
    let meta = params
        .and_then(|p| p.get("_meta"))
        .and_then(Value::as_object)
        .ok_or_else(|| missing("params._meta is not given"))?;
    let version = meta
        .get(META_VERSION)
        .and_then(Value::as_str)
        .ok_or_else(|| missing(&format!("params._meta[\"{META_VERSION}\"] is not given")))?;
    if !meta.get(META_CAPABILITIES).is_some_and(Value::is_object) {
        return Err(missing(&format!(
            "params._meta[\"{META_CAPABILITIES}\"] is not given"
        )));
    }
    if version != MODERN {
        return Err(RpcError {
            code: UNSUPPORTED_VERSION,
            message: "Unsupported protocol version".to_string(),
            data: Some(json!({"supported": [MODERN], "requested": version})),
        });
    }
    Ok(())
}
