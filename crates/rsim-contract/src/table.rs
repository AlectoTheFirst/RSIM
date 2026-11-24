//! The tables: the catalog of their columns, the selection of rows with
//! filters, sorting, pages and the verbs `show`, `summarize`, `unique`,
//! `top` and `lpm`, and the output of a table request. Each table has the
//! same parameters.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::twin::TwinJson;

/// Column type
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ColumnType {
    Text,
    Integer,
    Boolean,
    /// Address
    Address,
    /// Prefix
    Prefix,
    /// Text list
    List,
}

/// Column
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
pub struct Column {
    pub name: &'static str,
    pub description: &'static str,
    #[serde(rename = "type")]
    pub kind: ColumnType,
    /// Semantic type
    pub semantic: &'static str,
    pub unit: Option<&'static str>,
    /// Reference
    pub refers_to: Option<(&'static str, &'static str)>,
}

/// Table
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
pub struct TableDef {
    pub name: &'static str,
    pub description: &'static str,
    /// Key columns
    pub key: &'static [&'static str],
    pub columns: &'static [Column],
    /// Verbs
    pub verbs: &'static [&'static str],
    /// Needed data
    pub needs: &'static str,
}

impl TableDef {
    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
    }
}

const fn col(
    name: &'static str,
    kind: ColumnType,
    semantic: &'static str,
    description: &'static str,
) -> Column {
    Column {
        name,
        description,
        kind,
        semantic,
        unit: None,
        refers_to: None,
    }
}

const fn refers(mut c: Column, table: &'static str, column: &'static str) -> Column {
    c.refers_to = Some((table, column));
    c
}

const DEVICE: Column = refers(
    col("device", ColumnType::Text, "device", "Device"),
    "devices",
    "device",
);
const BASE_VERBS: &[&str] = &["show", "summarize", "unique", "top"];

/// The tables, in a fixed order.
pub const TABLES: &[TableDef] = &[
    TableDef {
        name: "devices",
        description: "Devices",
        key: &["device"],
        columns: &[
            col("device", ColumnType::Text, "device", "Device"),
            col("vendor", ColumnType::Text, "vendor", "Vendor"),
            col("vendor_reason", ColumnType::Text, "reason", "Vendor reason"),
            col("platform", ColumnType::Text, "platform", "Platform"),
            col(
                "platform_reason",
                ColumnType::Text,
                "reason",
                "Platform reason",
            ),
            col("os_version", ColumnType::Text, "os_version", "OS version"),
            col(
                "os_version_reason",
                ColumnType::Text,
                "reason",
                "OS version reason",
            ),
            col("serial", ColumnType::Text, "serial", "Serial"),
            col("serial_reason", ColumnType::Text, "reason", "Serial reason"),
            col(
                "management_address",
                ColumnType::Text,
                "address",
                "Management address",
            ),
            col(
                "management_address_reason",
                ColumnType::Text,
                "reason",
                "Management address reason",
            ),
            col("collected_at", ColumnType::Text, "time", "Manifest time"),
            col(
                "collected_at_reason",
                ColumnType::Text,
                "reason",
                "Manifest time reason",
            ),
            col("store_device", ColumnType::Text, "device", "Store device"),
            col(
                "provenance",
                ColumnType::List,
                "source_span",
                "Source spans",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "the twin and a store snapshot for the facts",
    },
    TableDef {
        name: "functions",
        description: "Network functions",
        key: &["function"],
        columns: &[
            col("function", ColumnType::Text, "function", "Function"),
            DEVICE,
            col("kind", ColumnType::Text, "function_kind", "Function type"),
            col(
                "provenance",
                ColumnType::List,
                "source_span",
                "Source spans",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "the twin",
    },
    TableDef {
        name: "endpoints",
        description: "Endpoints",
        key: &["endpoint"],
        columns: &[
            col("endpoint", ColumnType::Text, "endpoint", "Endpoint"),
            col("addresses", ColumnType::List, "address", "Addresses"),
        ],
        verbs: BASE_VERBS,
        needs: "the twin",
    },
    TableDef {
        name: "attachments",
        description: "Attachment records",
        key: &["address", "device", "interface"],
        columns: &[
            col("address", ColumnType::Address, "address", "Address"),
            DEVICE,
            col("interface", ColumnType::Text, "interface", "Interface"),
            col("kind", ColumnType::Text, "attachment_kind", "Record kind"),
            refers(
                col("host", ColumnType::Text, "endpoint", "Host"),
                "endpoints",
                "endpoint",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "the twin",
    },
    TableDef {
        name: "edge-interfaces",
        description: "Edge interfaces",
        key: &["device", "interface"],
        columns: &[
            DEVICE,
            col("interface", ColumnType::Text, "interface", "Interface"),
            col("networks", ColumnType::List, "prefix", "Connected networks"),
        ],
        verbs: BASE_VERBS,
        needs: "the twin",
    },
    TableDef {
        name: "fib",
        description: "Forwarding table",
        key: &["device", "vrf", "prefix", "function"],
        columns: &[
            DEVICE,
            col("vrf", ColumnType::Text, "vrf", "VRF"),
            col("prefix", ColumnType::Prefix, "prefix", "Prefix"),
            col("kind", ColumnType::Text, "route_kind", "Route kind"),
            refers(
                col(
                    "function",
                    ColumnType::Text,
                    "function",
                    "Route lookup function",
                ),
                "functions",
                "function",
            ),
            col("next_hops", ColumnType::List, "next_hop", "Next hops"),
            col(
                "provenance",
                ColumnType::List,
                "source_span",
                "Source spans",
            ),
        ],
        verbs: &["show", "summarize", "unique", "top", "lpm"],
        needs: "the twin",
    },
    TableDef {
        name: "coverage",
        description: "Unhandled config stanzas",
        key: &["device", "path"],
        columns: &[
            DEVICE,
            col("path", ColumnType::Text, "config_path", "Config path"),
            col("stanzas", ColumnType::Integer, "count", "Stanzas"),
            col("lines", ColumnType::Integer, "count", "Lines"),
        ],
        verbs: BASE_VERBS,
        needs: "a twin of a store snapshot",
    },
    TableDef {
        name: "neighbours",
        description: "External neighbours",
        key: &["device", "port", "neighbour", "protocol"],
        columns: &[
            DEVICE,
            col("port", ColumnType::Text, "interface", "Local port"),
            col("neighbour", ColumnType::Text, "device", "Neighbour"),
            col("remote_port", ColumnType::Text, "interface", "Remote port"),
            col(
                "protocol",
                ColumnType::Text,
                "neighbour_protocol",
                "Protocol",
            ),
            col("provenance", ColumnType::List, "source_span", "Source span"),
        ],
        verbs: BASE_VERBS,
        needs: "a twin of a store snapshot with an LLDP or CDP section",
    },
    TableDef {
        name: "fabric-connections",
        description: "Fabric connections",
        key: &["device", "connection"],
        columns: &[
            DEVICE,
            col("connection", ColumnType::Text, "circuit", "Connection"),
            col("name", ColumnType::Text, "name", "Name"),
            col("type", ColumnType::Text, "circuit_type", "Type"),
            col("state", ColumnType::Text, "circuit_state", "State"),
            col("a_end", ColumnType::Text, "circuit_end", "A end"),
            col("z_end", ColumnType::Text, "circuit_end", "Z end"),
            col("result", ColumnType::Text, "circuit_result", "Result"),
            col("reason", ColumnType::Text, "reason", "Reason"),
            col(
                "provenance",
                ColumnType::List,
                "source_span",
                "Source spans",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "a twin of a store snapshot with an Equinix account",
    },
    TableDef {
        name: "bgp-sessions",
        description: "BGP peers",
        key: &["device", "vrf", "peer"],
        columns: &[
            DEVICE,
            col("vrf", ColumnType::Text, "vrf", "VRF"),
            col("peer", ColumnType::Text, "bgp_peer", "Peer"),
            col("source", ColumnType::Text, "bgp_peer_source", "Peer source"),
            col("range", ColumnType::Prefix, "prefix", "Listen range"),
            col(
                "local_address",
                ColumnType::Address,
                "address",
                "Local address",
            ),
            col(
                "update_source",
                ColumnType::Text,
                "interface",
                "Update source",
            ),
            col("local_asn", ColumnType::List, "asn", "Presented AS"),
            col(
                "local_asn_reason",
                ColumnType::Text,
                "reason",
                "Presented AS reason",
            ),
            col("peer_asn", ColumnType::Integer, "asn", "Peer AS"),
            col(
                "peer_asn_reason",
                ColumnType::Text,
                "reason",
                "Peer AS reason",
            ),
            col("observed_asn", ColumnType::Integer, "asn", "Observed AS"),
            col("shutdown", ColumnType::Boolean, "admin_state", "Shutdown"),
            col(
                "families",
                ColumnType::List,
                "address_family",
                "Address families",
            ),
            col("policy_in", ColumnType::Text, "policy", "Inbound policy"),
            col("policy_out", ColumnType::Text, "policy", "Outbound policy"),
            col("inherits", ColumnType::List, "bgp_template", "Inheritance"),
            col("gaps", ColumnType::List, "reason", "Inheritance gaps"),
            col("state", ColumnType::List, "bgp_state", "Session states"),
            col(
                "established",
                ColumnType::Boolean,
                "bgp_state",
                "Established",
            ),
            col(
                "prefixes_received",
                ColumnType::Integer,
                "count",
                "Received prefixes",
            ),
            col(
                "prefixes_sent",
                ColumnType::Integer,
                "count",
                "Sent prefixes",
            ),
            col("router_id", ColumnType::Address, "address", "Router ID"),
            col(
                "outcome",
                ColumnType::Text,
                "section_outcome",
                "Section outcome",
            ),
            col("in_scope", ColumnType::Boolean, "bgp_scope", "In scope"),
            col(
                "provenance",
                ColumnType::List,
                "source_span",
                "Source spans",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "a twin of a store snapshot with a BGP config or a BGP session section",
    },
    TableDef {
        name: "sdwan-paths",
        description: "SD-WAN paths",
        key: &["function", "tunnel"],
        columns: &[
            DEVICE,
            refers(
                col("function", ColumnType::Text, "function", "Tunnel selection"),
                "functions",
                "function",
            ),
            col("segment", ColumnType::Integer, "segment", "Segment"),
            col("tunnel", ColumnType::Text, "tunnel", "Tunnel"),
            col("interface", ColumnType::Text, "interface", "WAN interface"),
            col("transport", ColumnType::Text, "transport", "Transport"),
            col("peer", ColumnType::Address, "address", "Peer address"),
            refers(
                col("far", ColumnType::Text, "device", "Far device"),
                "devices",
                "device",
            ),
            col(
                "far_interface",
                ColumnType::Text,
                "interface",
                "Far interface",
            ),
            col("state", ColumnType::Text, "tunnel_state", "State"),
            col("state_reason", ColumnType::Text, "reason", "State reason"),
            col("far_paths", ColumnType::Integer, "count", "Far end paths"),
            col(
                "provenance",
                ColumnType::List,
                "source_span",
                "Source spans",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "the twin",
    },
];

/// The table of a name.
pub fn table(name: &str) -> Option<&'static TableDef> {
    TABLES.iter().find(|t| t.name == name)
}

/// The selection of rows: the filters, the order, the columns and the page.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct Selection {
    /// Equality filters
    #[serde(default)]
    pub filters: BTreeMap<String, Vec<String>>,
    /// Typed filters
    #[serde(default)]
    pub typed: BTreeMap<String, String>,
    /// Columns
    pub columns: Option<Vec<String>>,
    /// Sort order
    pub sort: Option<Vec<String>>,
    /// Page size
    pub limit: Option<usize>,
    /// Cursor
    pub cursor: Option<String>,
}

/// Table rows
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct TableOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: TwinJson,
    pub table: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    /// Total rows
    pub total: usize,
    /// Next cursor
    pub next_cursor: Option<String>,
}

/// Distinct values
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct UniqueOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: TwinJson,
    pub table: String,
    /// Columns
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
}

/// Table summary
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SummarizeOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: TwinJson,
    pub table: String,
    pub total: usize,
    pub columns: Vec<ColumnSummary>,
}

/// Column summary
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ColumnSummary {
    pub column: String,
    pub distinct: usize,
    pub nulls: usize,
    /// Most frequent values
    pub top: Vec<(Value, usize)>,
}

/// Table catalog
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct TablesOut {
    pub rsim_json: u32,
    pub kind: String,
    pub tables: &'static [TableDef],
}
