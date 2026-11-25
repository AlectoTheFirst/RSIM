//! Problem details of RFC 9457, with the rsim error code.

use serde::Serialize;

use crate::handler::Response;

/// One problem object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub kind: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub code: String,
    pub rsim_json: u32,
}

/// The fixed title of an error code.
pub fn title(code: &str) -> &'static str {
    match code {
        "unknown_twin" => "Twin not known",
        "snapshot_replaced" => "Snapshot replaced",
        "unknown_topology" => "Topology not known",
        "unknown_table" => "Table not known",
        "no_such_step" => "Trace step not in the answer",
        "no_such_query" => "Query identifier not known",
        "not_found" => "Resource not known",
        "invalid_query" => "Query not valid",
        "invalid_filter" => "Filter not valid",
        "unknown_ingress" => "Ingress not known",
        "start_requires_context" => "Start function without context",
        "invalid_body" => "Body not valid",
        "method_not_allowed" => "Method not allowed",
        "too_large" => "Body too large",
        "too_many_queries" => "Too many queries",
        "too_many_probes" => "Too many probes",
        "request_timeout" => "Request too slow",
        "forbidden_origin" => "Origin not allowed",
        "forbidden_host" => "Host not allowed",
        "store" => "Store not readable",
        "contract_violation" => "Function contract broken",
        "conflict" => "Conflict",
        "invalid_record" => "Record not valid",
        "no_inventory" => "No inventory database",
        "inventory_unavailable" => "Inventory database not usable",
        _ => "Internal error",
    }
}

/// The problem object of a status, a code and a detail.
pub fn problem(status: u16, code: &str, detail: String) -> Problem {
    Problem {
        kind: format!("urn:rsim:error:{code}"),
        title: title(code).to_string(),
        status,
        detail,
        code: code.to_string(),
        rsim_json: rsim_contract::json::VERSION,
    }
}

impl Problem {
    pub fn response(&self) -> Response {
        let mut headers = vec![("content-type".into(), "application/problem+json".into())];
        if self.status == 503 {
            headers.push(("retry-after".into(), "1".into()));
        }
        Response {
            status: self.status,
            headers,
            body: rsim_contract::json::to_text(self, false).into_bytes(),
        }
    }
}
