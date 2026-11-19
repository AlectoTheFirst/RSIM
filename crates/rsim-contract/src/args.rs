//! The arguments of the operations: the JSON objects of the MCP tools and
//! of the request bodies, with the same field names as the CLI flags.
//!
//! These types give the schemas. The reader of the arguments in `rsim-cli`
//! checks the rules between fields, which a schema cannot state.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::query::{FragmentName, TcpFlag};

/// The arguments of an operation on one topology.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TopologyArgs {
    /// A built-in topology, or `store` for the newest snapshot of the store
    /// of the server.
    pub topology: String,
}

/// A protocol name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

/// The name of an ICMP echo type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum IcmpName {
    EchoRequest,
    EchoReply,
}

/// An ICMP type: a number, or the name of the echo request or the echo
/// reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum IcmpTypeArg {
    Name(IcmpName),
    Number(u8),
}

/// The form of an answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Form {
    /// The verdicts, the parts and the branches with no trace steps.
    #[default]
    Summary,
    /// The summary, and one line for each trace step, with no packet sets.
    Steps,
    /// The full answer with each packet set.
    Full,
}

/// How a path query treats a field that it does not state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Unstated {
    /// An unstated field has all values.
    #[default]
    All,
    /// An unstated field takes its default value where it has one: dscp 0,
    /// ecn 0, an untagged frame, an unfragmented packet, the TCP flag SYN,
    /// an ICMP or ICMPv6 echo request with code 0, and a source port in the
    /// range 49152 to 65535. The MAC addresses and the destination port
    /// have no default. The answer names each default in its notes.
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

/// The fields of a path query. A field that the query does not state is
/// not known, or takes its default value with `unstated` `defaults`.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PathQueryArgs {
    /// A built-in topology, or `store` for the newest snapshot of the store
    /// of the server.
    pub topology: String,
    /// The ingress point as <device>/<interface>. Without it, the
    /// attachment records of the source address give the ingress.
    pub ingress: Option<String>,
    /// The source IP address.
    #[serde(rename = "source.ip")]
    pub source_ip: String,
    /// The destination IP address.
    #[serde(rename = "destination.ip")]
    pub destination_ip: String,
    /// The protocol number.
    #[serde(rename = "network.iana_number")]
    pub iana_number: Option<u8>,
    /// The protocol name. Give network.iana_number or network.transport.
    #[serde(rename = "network.transport")]
    pub transport: Option<Transport>,
    /// The source port.
    #[serde(rename = "source.port")]
    pub source_port: Option<u16>,
    /// The destination port.
    #[serde(rename = "destination.port")]
    pub destination_port: Option<u16>,
    /// The source MAC address: 6 hexadecimal bytes with colons.
    #[serde(rename = "source.mac")]
    pub source_mac: Option<String>,
    /// The destination MAC address: 6 hexadecimal bytes with colons.
    #[serde(rename = "destination.mac")]
    pub destination_mac: Option<String>,
    /// The VLAN tag.
    #[serde(rename = "network.vlan.id")]
    #[schemars(range(max = 4095))]
    pub vlan_id: Option<u16>,
    /// The layer 2 priority. It needs network.vlan.id.
    #[schemars(range(max = 7))]
    pub l2_priority: Option<u8>,
    /// The TCP flags that are set.
    pub tcp_flags: Option<Vec<TcpFlag>>,
    /// The ICMP type: 0 to 255, echo-request or echo-reply.
    pub icmp_type: Option<IcmpTypeArg>,
    /// The ICMP code.
    pub icmp_code: Option<u8>,
    /// The DSCP.
    #[schemars(range(max = 63))]
    pub dscp: Option<u8>,
    /// The ECN.
    #[schemars(range(max = 3))]
    pub ecn: Option<u8>,
    /// The fragment state.
    pub fragment: Option<FragmentName>,
    /// Run the reply. The default is true.
    pub reply: Option<bool>,
    /// all (the default): an unstated field has all values. defaults: an
    /// unstated field takes its default value where it has one.
    pub unstated: Option<Unstated>,
    /// The form of the answer. The default is summary.
    pub form: Option<Form>,
}

/// One item of a set list.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum SetItem {
    Text(String),
    Number(u64),
}

/// A set: an address, a prefix, a number, a range such as 1-1023, or a
/// comma list. A field that is not given has all values.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum SetArg {
    Text(String),
    Number(u64),
    List(Vec<SetItem>),
}

/// The fields of a set query. Each field takes a set. A field that is not
/// given has all values.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetQueryArgs {
    /// A built-in topology, or `store` for the newest snapshot of the store
    /// of the server.
    pub topology: String,
    /// The ingress point as <device>/<interface>. Without it, the
    /// attachment records of the source addresses give the ingress.
    pub ingress: Option<String>,
    /// The source addresses.
    #[serde(rename = "source.ip")]
    pub source_ip: Option<SetArg>,
    /// The destination addresses.
    #[serde(rename = "destination.ip")]
    pub destination_ip: Option<SetArg>,
    /// The protocol numbers.
    #[serde(rename = "network.iana_number")]
    pub iana_number: Option<SetArg>,
    /// The protocol names.
    #[serde(rename = "network.transport")]
    pub transport: Option<SetArg>,
    /// The source ports.
    #[serde(rename = "source.port")]
    pub source_port: Option<SetArg>,
    /// The destination ports.
    #[serde(rename = "destination.port")]
    pub destination_port: Option<SetArg>,
    /// The source MAC addresses.
    #[serde(rename = "source.mac")]
    pub source_mac: Option<SetArg>,
    /// The destination MAC addresses.
    #[serde(rename = "destination.mac")]
    pub destination_mac: Option<SetArg>,
    /// The VLAN tags.
    #[serde(rename = "network.vlan.id")]
    pub vlan_id: Option<SetArg>,
    /// The layer 2 priorities.
    pub l2_priority: Option<SetArg>,
    /// The TCP flag values: numbers, ranges, or flag names joined with +.
    pub tcp_flags: Option<SetArg>,
    /// The ICMP types.
    pub icmp_type: Option<SetArg>,
    /// The ICMP codes.
    pub icmp_code: Option<SetArg>,
    /// The DSCP values.
    pub dscp: Option<SetArg>,
    /// The ECN values.
    pub ecn: Option<SetArg>,
    /// The fragment states.
    pub fragment: Option<SetArg>,
    /// Run the replies. The default is true.
    pub reply: Option<bool>,
    /// The form of the answer. The default is summary.
    pub form: Option<Form>,
}

/// The kind of a query.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMode {
    #[default]
    Path,
    Set,
}

/// One trace step of a path query or of a set query. The fields of the
/// query take the set form; in path mode, each set has one value.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct StepArgs {
    #[serde(flatten)]
    pub query: SetQueryArgs,
    /// The kind of the query: path (the default) or set.
    pub mode: Option<QueryMode>,
    /// The treatment of the unstated fields of a path query: all (the
    /// default) or defaults. A set query does not take it.
    pub unstated: Option<Unstated>,
    /// The branch index.
    pub branch: u32,
    /// The step index in the branch.
    pub step: u32,
    /// Select the reply of this forward branch. Then the branch index and
    /// the step index are indexes in the reply.
    pub reply_of: Option<u32>,
    /// True to add the source lines of each span of the step, with the
    /// secrets masked; only the lines inside a source span of a function of
    /// the twin are given. A built-in topology has no source text.
    pub source_lines: Option<bool>,
}

/// A verb of a table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TableVerb {
    /// The selected rows.
    #[default]
    Show,
    /// The counts of the table and of each column.
    Summarize,
    /// The distinct values of the selected columns, with their counts.
    Unique,
    /// The rows with the largest values of `column`, or the smallest with
    /// `ascending`.
    Top,
    /// The rows of the longest prefix of `column` that contains `address`.
    Lpm,
}

/// A query of a table of a twin.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TableQueryArgs {
    /// A built-in topology, or `store` for the newest snapshot of the store
    /// of the server.
    pub topology: String,
    /// The table. The tool `list_tables` gives the tables and their
    /// columns.
    pub table: String,
    /// The verb. The default is show.
    pub verb: Option<TableVerb>,
    #[serde(flatten)]
    pub selection: crate::table::Selection,
    /// The column of the verbs top and lpm. The default of lpm is prefix.
    pub column: Option<String>,
    /// The number of rows of the verb top. The default is 5.
    pub count: Option<usize>,
    /// With the verb top: the smallest values first.
    pub ascending: Option<bool>,
    /// The address of the verb lpm.
    pub address: Option<String>,
}

/// The view of a topology.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TopologyViewArgs {
    /// A built-in topology, or `store` for the newest snapshot of the store
    /// of the server. Not used in an HTTP path, which names the twin.
    #[serde(default)]
    pub topology: String,
    /// `device` (the default) or `function`.
    pub level: Option<String>,
    /// The layers of the edges: `physical` and `overlay` at the device
    /// level, `function` at the function level. All layers of the level if
    /// not given.
    pub layers: Option<Vec<String>>,
    /// Only these devices.
    pub devices: Option<Vec<String>>,
    /// Only the devices within `hops` links of this device.
    pub around: Option<String>,
    /// The number of links of `around`; 1 if not given.
    pub hops: Option<usize>,
    /// The claims whose result each edge gets: `link-speed-duplex`.
    pub claims: Option<Vec<String>>,
}
