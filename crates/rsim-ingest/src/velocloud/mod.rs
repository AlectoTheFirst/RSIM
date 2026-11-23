//! Arista VeloCloud SD-WAN: one store device for each enterprise of an
//! orchestrator, and one twin device for each edge of the enterprise.

pub mod coverage;
pub mod effective;
pub mod join;
pub mod json;
pub mod lower;
pub mod mask;
pub mod profile;
pub mod reader;
pub mod routes;
pub mod rules;

pub use join::summaries;
pub use json::Parsed;
pub use lower::{HubChoice, Lowered, lower};
pub use profile::profile;
pub use reader::{Edge, Enterprise, read};

/// The sections of an enterprise device.
pub const SECTIONS: &[&str] = &[
    "aggregates",
    "edges",
    "edge_state",
    "profiles",
    "route_table",
    "edges_v2",
    "edge_modules",
    "sdwan_peers",
    "object_groups",
    "bgp_sessions",
];

/// The twin device of an edge of the store device of an enterprise.
pub fn device_name(store_device: &str, edge: &str) -> String {
    format!("{store_device}/edge/{edge}")
}

/// The enterprise logicalId of a store device: the longest logicalId of
/// `aggregates` that ends the device name after a dash, else the enterprise
/// of the `_href` of the first edge row, else an empty text.
pub fn enterprise_of(store_device: &str, p: &Parsed) -> String {
    let ids: Vec<String> = p
        .root("aggregates")
        .map(|r| {
            let rows = match r.get("enterprises") {
                Some(e) => e.rows(),
                None => r.rows(),
            };
            rows.into_iter()
                .filter_map(|x| x.text("logicalId"))
                .collect()
        })
        .unwrap_or_default();
    let found = ids
        .into_iter()
        .filter(|id| store_device.ends_with(&format!("-{id}")))
        .max_by_key(String::len);
    if let Some(id) = found {
        return id;
    }
    ["edges", "edges_v2"]
        .iter()
        .filter_map(|s| p.root(s))
        .flat_map(json::J::rows)
        .find_map(|r| {
            let href = r.str("_href")?;
            let (_, rest) = href.split_once("/enterprises/")?;
            rest.split('/').next().map(str::to_string)
        })
        .unwrap_or_default()
}
