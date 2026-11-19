//! The tables: the catalog of their columns, the selection of rows with
//! filters, sorting, pages and the verbs `show`, `summarize`, `unique`,
//! `top` and `lpm`, and the output of a table request. Each table has the
//! same parameters.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::twin::TwinJson;

/// The type of the values of a column.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ColumnType {
    Text,
    Integer,
    Boolean,
    /// An IPv4 or IPv6 address.
    Address,
    /// An address with a prefix length.
    Prefix,
    /// A list of text values.
    List,
}

/// One column of a table.
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
pub struct Column {
    pub name: &'static str,
    pub description: &'static str,
    #[serde(rename = "type")]
    pub kind: ColumnType,
    /// The meaning of the values, for example `device`, `interface`, `vrf`.
    pub semantic: &'static str,
    pub unit: Option<&'static str>,
    /// The table and the column that a value refers to.
    pub refers_to: Option<(&'static str, &'static str)>,
}

/// One table of the catalog.
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
pub struct TableDef {
    pub name: &'static str,
    pub description: &'static str,
    /// The key columns, which give the default order of the rows.
    pub key: &'static [&'static str],
    pub columns: &'static [Column],
    /// The verbs of the table.
    pub verbs: &'static [&'static str],
    /// The data that the table needs, so a client knows why it is empty.
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
    col("device", ColumnType::Text, "device", "The device."),
    "devices",
    "device",
);
const BASE_VERBS: &[&str] = &["show", "summarize", "unique", "top"];

/// The tables, in a fixed order.
pub const TABLES: &[TableDef] = &[
    TableDef {
        name: "devices",
        description: "The devices of the twin with their facts: each device with a function and each device of the snapshot, where a UniFi console gives a row for each device record of its `devices` section and a row of its own only when that section gives no device. A fact that is not known is null, and its column `<fact>_reason` gives not_collected (the snapshot has no section or record that gives it) or not_read (no reader gives it from the section, or the value is a placeholder).",
        key: &["device"],
        columns: &[
            col("device", ColumnType::Text, "device", "The device."),
            col(
                "vendor",
                ColumnType::Text,
                "vendor",
                "The vendor of the device manifest.",
            ),
            col(
                "vendor_reason",
                ColumnType::Text,
                "reason",
                "Why the vendor is not known.",
            ),
            col(
                "platform",
                ColumnType::Text,
                "platform",
                "The model of the device.",
            ),
            col(
                "platform_reason",
                ColumnType::Text,
                "reason",
                "Why the model is not known.",
            ),
            col(
                "os_version",
                ColumnType::Text,
                "os_version",
                "The version of the operating system.",
            ),
            col(
                "os_version_reason",
                ColumnType::Text,
                "reason",
                "Why the version is not known.",
            ),
            col(
                "serial",
                ColumnType::Text,
                "serial",
                "The serial of the chassis.",
            ),
            col(
                "serial_reason",
                ColumnType::Text,
                "reason",
                "Why the serial is not known.",
            ),
            col(
                "management_address",
                ColumnType::Text,
                "address",
                "The host name or the address to which the collector connected, or for a UniFi device the address of its record.",
            ),
            col(
                "management_address_reason",
                ColumnType::Text,
                "reason",
                "Why the management address is not known.",
            ),
            col(
                "collected_at",
                ColumnType::Text,
                "time",
                "The time of the device manifest in UTC, as YYYY-MM-DDTHH:MM:SSZ.",
            ),
            col(
                "collected_at_reason",
                ColumnType::Text,
                "reason",
                "Why the time is not known.",
            ),
            col(
                "store_device",
                ColumnType::Text,
                "device",
                "The device of the store whose manifest gives the facts: the console of a UniFi device, else the device itself; null with no facts.",
            ),
            col(
                "provenance",
                ColumnType::List,
                "source_span",
                "The source spans of the facts: file:first-last.",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "the twin; the facts need a twin of a store snapshot",
    },
    TableDef {
        name: "functions",
        description: "The network functions of the twin, with the source lines from which each came.",
        key: &["function"],
        columns: &[
            col(
                "function",
                ColumnType::Text,
                "function",
                "The function identifier.",
            ),
            DEVICE,
            col(
                "kind",
                ColumnType::Text,
                "function_kind",
                "The function type.",
            ),
            col(
                "provenance",
                ColumnType::List,
                "source_span",
                "The source spans: file:first-last.",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "the twin",
    },
    TableDef {
        name: "endpoints",
        description: "The endpoints of the twin.",
        key: &["endpoint"],
        columns: &[
            col("endpoint", ColumnType::Text, "endpoint", "The endpoint."),
            col(
                "addresses",
                ColumnType::List,
                "address",
                "The addresses of the endpoint.",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "the twin",
    },
    TableDef {
        name: "attachments",
        description: "The attachment records: where an address attaches to the network.",
        key: &["address", "device", "interface"],
        columns: &[
            col("address", ColumnType::Address, "address", "The address."),
            DEVICE,
            col(
                "interface",
                ColumnType::Text,
                "interface",
                "The interface of the device.",
            ),
            col(
                "kind",
                ColumnType::Text,
                "attachment_kind",
                "The kind of the record.",
            ),
            refers(
                col("host", ColumnType::Text, "endpoint", "The host."),
                "endpoints",
                "endpoint",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "the twin",
    },
    TableDef {
        name: "edge-interfaces",
        description: "The edge interfaces with the connected networks behind them.",
        key: &["device", "interface"],
        columns: &[
            DEVICE,
            col("interface", ColumnType::Text, "interface", "The interface."),
            col(
                "networks",
                ColumnType::List,
                "prefix",
                "The connected networks.",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "the twin",
    },
    TableDef {
        name: "fib",
        description: "The forwarding table of each device and VRF that the twin uses. Each row is one prefix.",
        key: &["device", "vrf", "prefix", "function"],
        columns: &[
            DEVICE,
            col("vrf", ColumnType::Text, "vrf", "The VRF."),
            col("prefix", ColumnType::Prefix, "prefix", "The prefix."),
            col(
                "kind",
                ColumnType::Text,
                "route_kind",
                "connected, static, local or null.",
            ),
            refers(
                col(
                    "function",
                    ColumnType::Text,
                    "function",
                    "The route lookup function.",
                ),
                "functions",
                "function",
            ),
            col(
                "next_hops",
                ColumnType::List,
                "next_hop",
                "The next hops as <gateway>@<interface>, or the interface of a connected network.",
            ),
            col(
                "provenance",
                ColumnType::List,
                "source_span",
                "The source spans: file:first-last.",
            ),
        ],
        verbs: &["show", "summarize", "unique", "top", "lpm"],
        needs: "the twin",
    },
    TableDef {
        name: "coverage",
        description: "The config stanzas that the ingestion does not handle, for each device. Each key goes through the mask of the secrets.",
        key: &["device", "path"],
        columns: &[
            DEVICE,
            col(
                "path",
                ColumnType::Text,
                "config_path",
                "The path of the unhandled stanzas.",
            ),
            col(
                "stanzas",
                ColumnType::Integer,
                "count",
                "The number of stanzas.",
            ),
            col(
                "lines",
                ColumnType::Integer,
                "count",
                "The number of lines.",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "a twin of a store snapshot; a built-in topology has no coverage report",
    },
    TableDef {
        name: "neighbours",
        description: "The LLDP and CDP records of the twin that name a neighbour with no device in the twin: no device has its name or its host name, and its MACs name no device.",
        key: &["device", "port", "neighbour", "protocol"],
        columns: &[
            DEVICE,
            col("port", ColumnType::Text, "interface", "The local port."),
            col(
                "neighbour",
                ColumnType::Text,
                "device",
                "The name of the neighbour.",
            ),
            col(
                "remote_port",
                ColumnType::Text,
                "interface",
                "The port of the neighbour as it sends it.",
            ),
            col(
                "protocol",
                ColumnType::Text,
                "neighbour_protocol",
                "lldp or cdp.",
            ),
            col(
                "provenance",
                ColumnType::List,
                "source_span",
                "The source span of the record: file:first-last.",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "a twin of a store snapshot with an LLDP or CDP section",
    },
    TableDef {
        name: "bgp-sessions",
        description: "The BGP peers of each device: each configured neighbour and listen range after the inheritance, joined with the session rows of the device, and each observed peer with no neighbour.",
        key: &["device", "vrf", "peer"],
        columns: &[
            DEVICE,
            col("vrf", ColumnType::Text, "vrf", "The VRF of the peer."),
            col(
                "peer",
                ColumnType::Text,
                "bgp_peer",
                "The address of the peer, the prefix of a listen range, or the interface of a neighbour with no address.",
            ),
            col(
                "source",
                ColumnType::Text,
                "bgp_peer_source",
                "configured, listen-range, dynamic (an observed peer in one listen range) or observed (no neighbour in the config).",
            ),
            col(
                "range",
                ColumnType::Prefix,
                "prefix",
                "The listen range of a dynamic peer.",
            ),
            col(
                "local_address",
                ColumnType::Address,
                "address",
                "The local address of the update-source or local address line.",
            ),
            col(
                "update_source",
                ColumnType::Text,
                "interface",
                "The interface or the address of the update-source or local address line.",
            ),
            col(
                "local_asn",
                ColumnType::List,
                "asn",
                "The ASes that the device presents to the peer, 2 with dual-as; empty when not known.",
            ),
            col(
                "local_asn_reason",
                ColumnType::Text,
                "reason",
                "Why the presented AS is not known.",
            ),
            col(
                "peer_asn",
                ColumnType::Integer,
                "asn",
                "The AS of the peer from the config, or from the session rows of an observed peer.",
            ),
            col(
                "peer_asn_reason",
                ColumnType::Text,
                "reason",
                "Why the AS of the peer is not known.",
            ),
            col(
                "observed_asn",
                ColumnType::Integer,
                "asn",
                "The AS of the peer as the session rows state it.",
            ),
            col(
                "shutdown",
                ColumnType::Boolean,
                "admin_state",
                "True with a shutdown line; null when an inheritance gap can hide one.",
            ),
            col(
                "families",
                ColumnType::List,
                "address_family",
                "The activated address families, for example ipv4-unicast.",
            ),
            col(
                "policy_in",
                ColumnType::Text,
                "policy",
                "The inbound policy of IPv4 unicast.",
            ),
            col(
                "policy_out",
                ColumnType::Text,
                "policy",
                "The outbound policy of IPv4 unicast.",
            ),
            col(
                "inherits",
                ColumnType::List,
                "bgp_template",
                "The peer groups, templates and session groups of the inheritance.",
            ),
            col(
                "gaps",
                ColumnType::List,
                "reason",
                "The sources of the inheritance that are not defined or that inherit from themselves.",
            ),
            col(
                "state",
                ColumnType::List,
                "bgp_state",
                "The state word of each session row of the peer.",
            ),
            col(
                "established",
                ColumnType::Boolean,
                "bgp_state",
                "True if each session row is established; null with no row.",
            ),
            col(
                "prefixes_received",
                ColumnType::Integer,
                "count",
                "The received prefixes of the session rows that state a count.",
            ),
            col(
                "prefixes_sent",
                ColumnType::Integer,
                "count",
                "The sent prefixes of the session rows that state a count.",
            ),
            col(
                "router_id",
                ColumnType::Address,
                "address",
                "The router ID of the peer as the device states it.",
            ),
            col(
                "outcome",
                ColumnType::Text,
                "section_outcome",
                "The outcome of the session section: complete, complete-empty, partial, failed or not-captured.",
            ),
            col(
                "in_scope",
                ColumnType::Boolean,
                "bgp_scope",
                "True if the scope of the session section covers each activated address family of the peer in its VRF.",
            ),
            col(
                "provenance",
                ColumnType::List,
                "source_span",
                "The source spans: file:first-last.",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "a twin of a store snapshot with a BGP config or a BGP session section; a built-in topology has no BGP peers",
    },
];

/// The table of a name.
pub fn table(name: &str) -> Option<&'static TableDef> {
    TABLES.iter().find(|t| t.name == name)
}

/// The selection of rows: the filters, the order, the columns and the page.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct Selection {
    /// Equality filters: a row matches if the value of the column is one of
    /// the values. A list value matches if one element is one of the
    /// values. Different columns are an AND.
    #[serde(default)]
    pub filters: BTreeMap<String, Vec<String>>,
    /// Typed filters as `<column>.<op>` with the op `contains`, `prefix`,
    /// `gt`, `lt` or `in_prefix`.
    #[serde(default)]
    pub typed: BTreeMap<String, String>,
    /// The columns of the output. All columns if not given.
    pub columns: Option<Vec<String>>,
    /// The order: column names, `-` before a name for a falling order.
    /// The key order if not given.
    pub sort: Option<Vec<String>>,
    /// The number of rows of a page.
    pub limit: Option<usize>,
    /// The cursor of the next page, from the output of the page before.
    pub cursor: Option<String>,
}

/// The rows of a table.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct TableOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: TwinJson,
    pub table: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    /// The number of rows that match the filters, on all pages.
    pub total: usize,
    /// The cursor of the next page, or `null` on the last page.
    pub next_cursor: Option<String>,
}

/// The distinct values of columns with their counts.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct UniqueOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: TwinJson,
    pub table: String,
    /// The columns, then `count`.
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
}

/// The counts of a table and of each column.
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

/// The counts of one column.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ColumnSummary {
    pub column: String,
    pub distinct: usize,
    pub nulls: usize,
    /// The most frequent values with their counts, at most 5, the most
    /// frequent first.
    pub top: Vec<(Value, usize)>,
}

/// The table catalog.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct TablesOut {
    pub rsim_json: u32,
    pub kind: String,
    pub tables: &'static [TableDef],
}
