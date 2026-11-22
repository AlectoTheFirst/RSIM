//! The query input types of the JSON output.

use std::borrow::Cow;
use std::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize};

/// TCP flag
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TcpFlag {
    Fin,
    Syn,
    Rst,
    Psh,
    Ack,
    Urg,
    Ece,
    Cwr,
}

impl TcpFlag {
    /// The flags in the order of their bits, from the lowest bit.
    pub const ALL: [TcpFlag; 8] = [
        TcpFlag::Fin,
        TcpFlag::Syn,
        TcpFlag::Rst,
        TcpFlag::Psh,
        TcpFlag::Ack,
        TcpFlag::Urg,
        TcpFlag::Ece,
        TcpFlag::Cwr,
    ];

    pub fn bit(self) -> u8 {
        1 << (self as u8)
    }

    pub fn name(self) -> &'static str {
        match self {
            TcpFlag::Fin => "fin",
            TcpFlag::Syn => "syn",
            TcpFlag::Rst => "rst",
            TcpFlag::Psh => "psh",
            TcpFlag::Ack => "ack",
            TcpFlag::Urg => "urg",
            TcpFlag::Ece => "ece",
            TcpFlag::Cwr => "cwr",
        }
    }
}

impl FromStr for TcpFlag {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        TcpFlag::ALL
            .into_iter()
            .find(|f| f.name() == s)
            .ok_or_else(|| {
                format!("TCP flag {s:?} is not one of fin, syn, rst, psh, ack, urg, ece, cwr")
            })
    }
}

/// Fragment
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FragmentName {
    Unfragmented,
    First,
    Later,
}

impl FromStr for FragmentName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unfragmented" => Ok(FragmentName::Unfragmented),
            "first" => Ok(FragmentName::First),
            "later" => Ok(FragmentName::Later),
            _ => Err(format!(
                "fragment {s:?} is not unfragmented, first or later"
            )),
        }
    }
}

/// An ingress point: a device and an interface, as `<device>/<interface>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngressRef {
    pub device: String,
    pub interface: String,
}

impl FromStr for IngressRef {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('/') {
            Some((d, i)) if !d.is_empty() && !i.is_empty() => Ok(IngressRef {
                device: d.to_string(),
                interface: i.to_string(),
            }),
            _ => Err(format!("ingress {s:?} is not <device>/<interface>")),
        }
    }
}

impl Serialize for IngressRef {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{}/{}", self.device, self.interface))
    }
}

/// Query input
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueryEcho {
    pub topology: String,
    pub ingress: Option<IngressRef>,
    #[serde(rename = "source.ip")]
    pub source_ip: String,
    #[serde(rename = "destination.ip")]
    pub destination_ip: String,
    #[serde(rename = "network.iana_number")]
    pub iana_number: Option<u8>,
    #[serde(rename = "network.transport")]
    pub transport: Option<String>,
    #[serde(rename = "source.port")]
    pub source_port: Option<u16>,
    #[serde(rename = "destination.port")]
    pub destination_port: Option<u16>,
    #[serde(rename = "source.mac")]
    pub source_mac: Option<String>,
    #[serde(rename = "destination.mac")]
    pub destination_mac: Option<String>,
    #[serde(rename = "network.vlan.id")]
    pub vlan_id: Option<u16>,
    pub l2_priority: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "network.vlan.tpid")]
    pub vlan_tpid: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "network.inner.vlan.id")]
    pub inner_vlan_id: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inner_l2_priority: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "network.inner.vlan.tpid")]
    pub inner_vlan_tpid: Option<u16>,
    pub tcp_flags: Option<Vec<TcpFlag>>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub dscp: Option<u8>,
    pub ecn: Option<u8>,
    pub fragment: Option<FragmentName>,
    pub reply: Option<bool>,
    /// Unstated fields
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unstated: Option<crate::args::Unstated>,
}

/// Set query input
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SetEcho {
    pub topology: String,
    pub ingress: Option<IngressRef>,
    #[serde(rename = "source.ip")]
    pub source_ip: Option<String>,
    #[serde(rename = "destination.ip")]
    pub destination_ip: Option<String>,
    #[serde(rename = "network.iana_number")]
    pub iana_number: Option<String>,
    #[serde(rename = "network.transport")]
    pub transport: Option<String>,
    #[serde(rename = "source.port")]
    pub source_port: Option<String>,
    #[serde(rename = "destination.port")]
    pub destination_port: Option<String>,
    #[serde(rename = "source.mac")]
    pub source_mac: Option<String>,
    #[serde(rename = "destination.mac")]
    pub destination_mac: Option<String>,
    #[serde(rename = "network.vlan.id")]
    pub vlan_id: Option<String>,
    pub l2_priority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "network.vlan.tpid")]
    pub vlan_tpid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "network.inner.vlan.id")]
    pub inner_vlan_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inner_l2_priority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "network.inner.vlan.tpid")]
    pub inner_vlan_tpid: Option<String>,
    pub tcp_flags: Option<String>,
    pub icmp_type: Option<String>,
    pub icmp_code: Option<String>,
    pub dscp: Option<String>,
    pub ecn: Option<String>,
    pub fragment: Option<String>,
    pub reply: Option<bool>,
}

impl<'de> Deserialize<'de> for IngressRef {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for IngressRef {
    fn schema_name() -> Cow<'static, str> {
        "IngressRef".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": "^[^/]+/.+$",
            "description": "Ingress"
        })
    }
}
