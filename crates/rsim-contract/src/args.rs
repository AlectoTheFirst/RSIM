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

/// The fields of a path query. A field that the query does not state is
/// not known.
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
    /// 0 to 255, echo-request or echo-reply.
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
    /// The branch index.
    pub branch: u32,
    /// The step index in the branch.
    pub step: u32,
    /// Select the reply of this forward branch. Then the branch index and
    /// the step index are indexes in the reply.
    pub reply_of: Option<u32>,
}
