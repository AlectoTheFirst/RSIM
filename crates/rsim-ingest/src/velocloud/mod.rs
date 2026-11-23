//! Arista VeloCloud SD-WAN: one store device for each enterprise of an
//! orchestrator, and one twin device for each edge of the enterprise.

pub mod coverage;
pub mod effective;
pub mod json;
pub mod mask;
pub mod reader;
pub mod routes;
pub mod rules;

pub use json::Parsed;
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
