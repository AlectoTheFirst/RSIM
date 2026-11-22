//! The arguments of the operations: the JSON objects of the MCP tools and
//! of the request bodies, with the same field names as the CLI flags.
//!
//! These types give the schemas. The reader of the arguments in `rsim-cli`
//! checks the rules between fields, which a schema cannot state.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::query::{FragmentName, TcpFlag};

/// Topology arguments
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TopologyArgs {
    /// Topology
    pub topology: String,
}

/// Protocol
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

/// ICMP echo type
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum IcmpName {
    EchoRequest,
    EchoReply,
}

/// ICMP type
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum IcmpTypeArg {
    Name(IcmpName),
    Number(u8),
}

/// Answer form
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Form {
    /// Summary
    #[default]
    Summary,
    /// Steps
    Steps,
    /// Full answer
    Full,
}

/// Unstated fields
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Unstated {
    /// All values
    #[default]
    All,
    /// Default values
    Defaults,
}

impl std::str::FromStr for Unstated {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "all" => Ok(Unstated::All),
            "defaults" => Ok(Unstated::Defaults),
            _ => Err(format!("unstated {s:?} is not all or defaults")),
        }
    }
}

/// Path query fields
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PathQueryArgs {
    /// Topology
    pub topology: String,
    /// Ingress
    pub ingress: Option<String>,
    /// Source address
    #[serde(rename = "source.ip")]
    pub source_ip: String,
    /// Destination address
    #[serde(rename = "destination.ip")]
    pub destination_ip: String,
    /// Protocol number
    #[serde(rename = "network.iana_number")]
    pub iana_number: Option<u8>,
    /// Protocol
    #[serde(rename = "network.transport")]
    pub transport: Option<Transport>,
    /// Source port
    #[serde(rename = "source.port")]
    pub source_port: Option<u16>,
    /// Destination port
    #[serde(rename = "destination.port")]
    pub destination_port: Option<u16>,
    /// Source MAC
    #[serde(rename = "source.mac")]
    pub source_mac: Option<String>,
    /// Destination MAC
    #[serde(rename = "destination.mac")]
    pub destination_mac: Option<String>,
    /// VLAN
    #[serde(rename = "network.vlan.id")]
    #[schemars(range(max = 4095))]
    pub vlan_id: Option<u16>,
    /// Layer 2 priority
    #[schemars(range(max = 7))]
    pub l2_priority: Option<u8>,
    /// TPID
    #[serde(rename = "network.vlan.tpid")]
    pub vlan_tpid: Option<u16>,
    /// Inner VLAN
    #[serde(rename = "network.inner.vlan.id")]
    #[schemars(range(max = 4095))]
    pub inner_vlan_id: Option<u16>,
    /// Inner layer 2 priority
    #[schemars(range(max = 7))]
    pub inner_l2_priority: Option<u8>,
    /// Inner TPID
    #[serde(rename = "network.inner.vlan.tpid")]
    pub inner_vlan_tpid: Option<u16>,
    /// TCP flags
    pub tcp_flags: Option<Vec<TcpFlag>>,
    /// ICMP type
    pub icmp_type: Option<IcmpTypeArg>,
    /// ICMP code
    pub icmp_code: Option<u8>,
    /// DSCP
    #[schemars(range(max = 63))]
    pub dscp: Option<u8>,
    /// ECN
    #[schemars(range(max = 3))]
    pub ecn: Option<u8>,
    /// Fragment
    pub fragment: Option<FragmentName>,
    /// Reply
    pub reply: Option<bool>,
    /// Unstated fields
    pub unstated: Option<Unstated>,
    /// Answer form
    pub form: Option<Form>,
}

/// Set item
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum SetItem {
    Text(String),
    Number(u64),
}

/// Set
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum SetArg {
    Text(String),
    Number(u64),
    List(Vec<SetItem>),
}

/// Set query fields
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetQueryArgs {
    /// Topology
    pub topology: String,
    /// Ingress
    pub ingress: Option<String>,
    /// Source addresses
    #[serde(rename = "source.ip")]
    pub source_ip: Option<SetArg>,
    /// Destination addresses
    #[serde(rename = "destination.ip")]
    pub destination_ip: Option<SetArg>,
    /// Protocol numbers
    #[serde(rename = "network.iana_number")]
    pub iana_number: Option<SetArg>,
    /// Protocols
    #[serde(rename = "network.transport")]
    pub transport: Option<SetArg>,
    /// Source ports
    #[serde(rename = "source.port")]
    pub source_port: Option<SetArg>,
    /// Destination ports
    #[serde(rename = "destination.port")]
    pub destination_port: Option<SetArg>,
    /// Source MACs
    #[serde(rename = "source.mac")]
    pub source_mac: Option<SetArg>,
    /// Destination MACs
    #[serde(rename = "destination.mac")]
    pub destination_mac: Option<SetArg>,
    /// VLANs
    #[serde(rename = "network.vlan.id")]
    pub vlan_id: Option<SetArg>,
    /// Layer 2 priorities
    pub l2_priority: Option<SetArg>,
    /// TPIDs
    #[serde(rename = "network.vlan.tpid")]
    pub vlan_tpid: Option<SetArg>,
    /// Inner VLANs
    #[serde(rename = "network.inner.vlan.id")]
    pub inner_vlan_id: Option<SetArg>,
    /// Inner layer 2 priorities
    pub inner_l2_priority: Option<SetArg>,
    /// Inner TPIDs
    #[serde(rename = "network.inner.vlan.tpid")]
    pub inner_vlan_tpid: Option<SetArg>,
    /// TCP flags
    pub tcp_flags: Option<SetArg>,
    /// ICMP types
    pub icmp_type: Option<SetArg>,
    /// ICMP codes
    pub icmp_code: Option<SetArg>,
    /// DSCP values
    pub dscp: Option<SetArg>,
    /// ECN values
    pub ecn: Option<SetArg>,
    /// Fragments
    pub fragment: Option<SetArg>,
    /// Replies
    pub reply: Option<bool>,
    /// Answer form
    pub form: Option<Form>,
}

/// Query kind
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMode {
    #[default]
    Path,
    Set,
}

/// Trace step
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct StepArgs {
    #[serde(flatten)]
    pub query: SetQueryArgs,
    /// Query kind
    pub mode: Option<QueryMode>,
    /// Unstated fields
    pub unstated: Option<Unstated>,
    /// Branch
    pub branch: u32,
    /// Step
    pub step: u32,
    /// Reply of branch
    pub reply_of: Option<u32>,
    /// Source lines
    pub source_lines: Option<bool>,
}

/// Table verb
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TableVerb {
    /// Rows
    #[default]
    Show,
    /// Counts
    Summarize,
    /// Distinct values
    Unique,
    /// Top rows
    Top,
    /// Longest prefix match
    Lpm,
}

/// Table query
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TableQueryArgs {
    /// Topology
    pub topology: String,
    /// Table
    pub table: String,
    /// Verb
    pub verb: Option<TableVerb>,
    #[serde(flatten)]
    pub selection: crate::table::Selection,
    /// Column
    pub column: Option<String>,
    /// Row count
    pub count: Option<usize>,
    /// Ascending
    pub ascending: Option<bool>,
    /// Address
    pub address: Option<String>,
}

/// Topology view
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TopologyViewArgs {
    /// Topology
    #[serde(default)]
    pub topology: String,
    /// Level
    pub level: Option<String>,
    /// Layers
    pub layers: Option<Vec<String>>,
    /// Devices
    pub devices: Option<Vec<String>>,
    /// Around device
    pub around: Option<String>,
    /// Hops
    pub hops: Option<usize>,
    /// Claims
    pub claims: Option<Vec<String>>,
}
