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

/// The title of an error code: a fixed text for each code.
pub fn title(code: &str) -> &'static str {
    match code {
        "unknown_twin" => "The twin is not known",
        "unknown_topology" => "The topology is not known",
        "unknown_table" => "The table is not known",
        "no_such_step" => "The trace step is not in the answer",
        "no_such_query" => "The query identifier is not known",
        "not_found" => "The resource is not known",
        "invalid_query" => "The query is not valid",
        "invalid_filter" => "The filter is not valid",
        "unknown_ingress" => "The ingress is not known",
        "start_requires_context" => "The start function needs a context",
        "invalid_body" => "The body is not valid",
        "method_not_allowed" => "The method is not allowed",
        "too_large" => "The body is too large",
        "too_many_queries" => "Too many queries run now",
        "forbidden_origin" => "The origin is not allowed",
        "forbidden_host" => "The host is not allowed",
        "store" => "The store cannot be read",
        "contract_violation" => "A function broke its contract",
        "conflict" => "The change conflicts with another record",
        "invalid_record" => "The record is not valid",
        "no_inventory" => "The server has no inventory database",
        "inventory_unavailable" => "The inventory database cannot be used",
        _ => "An internal error",
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
