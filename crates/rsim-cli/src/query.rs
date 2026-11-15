//! The query input of a path query: its fields, its validation and the
//! request header that it gives.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use rsim_core::{
    DeviceId, FieldValue, Fragment, Header, InterfaceId, Mac, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP,
    PROTO_UDP,
};
use rsim_engine::{Query, Twin};
use serde::Serialize;

use crate::error::{ErrorCode, QueryError};

/// An IP protocol number. The names `tcp`, `udp`, `icmp` and `icmpv6`
/// stand for their numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protocol(pub u8);

impl Protocol {
    /// The name of the protocol, if it has one.
    pub fn name(self) -> Option<&'static str> {
        match self.0 {
            PROTO_TCP => Some("tcp"),
            PROTO_UDP => Some("udp"),
            PROTO_ICMP => Some("icmp"),
            PROTO_ICMPV6 => Some("icmpv6"),
            _ => None,
        }
    }

    fn has_ports(self) -> bool {
        self.0 == PROTO_TCP || self.0 == PROTO_UDP
    }

    fn is_icmp(self) -> bool {
        self.0 == PROTO_ICMP || self.0 == PROTO_ICMPV6
    }
}

impl FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Protocol(PROTO_TCP)),
            "udp" => Ok(Protocol(PROTO_UDP)),
            "icmp" => Ok(Protocol(PROTO_ICMP)),
            "icmpv6" => Ok(Protocol(PROTO_ICMPV6)),
            _ => s.parse::<u8>().map(Protocol).map_err(|_| {
                format!("protocol {s:?} is not tcp, udp, icmp, icmpv6 or a number 0 to 255")
            }),
        }
    }
}

/// The name of the protocol if it has one, else its number.
impl Serialize for Protocol {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.name() {
            Some(n) => s.serialize_str(n),
            None => s.serialize_u8(self.0),
        }
    }
}

/// One TCP flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
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

/// An ICMP type: a number, or the name of the echo request or the echo
/// reply. The number of a name depends on the protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpType {
    Number(u8),
    EchoRequest,
    EchoReply,
}

impl IcmpType {
    pub fn number(self, protocol: Protocol) -> u8 {
        let v6 = protocol.0 == PROTO_ICMPV6;
        match self {
            IcmpType::Number(n) => n,
            IcmpType::EchoRequest if v6 => 128,
            IcmpType::EchoRequest => 8,
            IcmpType::EchoReply if v6 => 129,
            IcmpType::EchoReply => 0,
        }
    }
}

impl FromStr for IcmpType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "echo-request" => Ok(IcmpType::EchoRequest),
            "echo-reply" => Ok(IcmpType::EchoReply),
            _ => s.parse::<u8>().map(IcmpType::Number).map_err(|_| {
                format!("ICMP type {s:?} is not a number 0 to 255, echo-request or echo-reply")
            }),
        }
    }
}

/// The fragment state of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
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

/// A MAC address as text with colons.
pub fn parse_mac(s: &str) -> Result<Mac, String> {
    let parts: Vec<&str> = s.split(':').collect();
    let err = || format!("MAC address {s:?} is not 6 hexadecimal bytes with colons");
    if parts.len() != 6 {
        return Err(err());
    }
    let mut b = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 {
            return Err(err());
        }
        b[i] = u8::from_str_radix(p, 16).map_err(|_| err())?;
    }
    Ok(Mac(b))
}

/// The fields of a path query. The CLI flags and the MCP tool arguments
/// give the same fields with the same names. `None` is a field that is not
/// given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryInput {
    pub topology: String,
    pub ingress: Option<IngressRef>,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub iana_number: Option<u8>,
    pub transport: Option<Protocol>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub source_mac: Option<Mac>,
    pub destination_mac: Option<Mac>,
    pub vlan_id: Option<u16>,
    pub l2_priority: Option<u8>,
    pub tcp_flags: Option<Vec<TcpFlag>>,
    pub icmp_type: Option<IcmpType>,
    pub icmp_code: Option<u8>,
    pub dscp: Option<u8>,
    pub ecn: Option<u8>,
    pub fragment: Option<FragmentName>,
    pub reply: Option<bool>,
}

/// The query input in the JSON output. Each field is there, and a field
/// that is not given is `null`. The protocol is a number and has its name
/// if it has one, the ICMP type is a number, and the TCP flags are in the
/// order of their bits with no repeat.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
    pub transport: Option<&'static str>,
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
    pub tcp_flags: Option<Vec<TcpFlag>>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub dscp: Option<u8>,
    pub ecn: Option<u8>,
    pub fragment: Option<FragmentName>,
    pub reply: Option<bool>,
}

impl QueryInput {
    /// The protocol from `network.iana_number` or `network.transport`.
    pub fn protocol(&self) -> Option<Protocol> {
        self.iana_number.map(Protocol).or(self.transport)
    }

    pub fn echo(&self) -> QueryEcho {
        let p = self.protocol();
        QueryEcho {
            topology: self.topology.clone(),
            ingress: self.ingress.clone(),
            source_ip: self.source_ip.to_string(),
            destination_ip: self.destination_ip.to_string(),
            iana_number: p.map(|p| p.0),
            transport: p.and_then(Protocol::name),
            source_port: self.source_port,
            destination_port: self.destination_port,
            source_mac: self.source_mac.map(|m| format!("{m:?}")),
            destination_mac: self.destination_mac.map(|m| format!("{m:?}")),
            vlan_id: self.vlan_id,
            l2_priority: self.l2_priority,
            tcp_flags: self.tcp_flags.as_ref().map(|fs| {
                let mut fs = fs.clone();
                fs.sort();
                fs.dedup();
                fs
            }),
            icmp_type: match (self.icmp_type, p) {
                (Some(t), Some(p)) => Some(t.number(p)),
                _ => None,
            },
            icmp_code: self.icmp_code,
            dscp: self.dscp,
            ecn: self.ecn,
            fragment: self.fragment,
            reply: self.reply,
        }
    }

    /// Checks the rules between the fields and the value ranges.
    pub fn validate(&self) -> Result<Protocol, QueryError> {
        let invalid = |d: String| Err(QueryError::new(ErrorCode::InvalidQuery, d));
        let p = match (self.iana_number, self.transport) {
            (Some(n), Some(t)) if n != t.0 => {
                return invalid(format!(
                    "network.iana_number {n} and network.transport {} are different protocols",
                    ProtocolText(t)
                ));
            }
            (Some(n), _) => Protocol(n),
            (None, Some(t)) => t,
            (None, None) => {
                return invalid(
                    "network.iana_number or network.transport is not given".to_string(),
                );
            }
        };
        if self.source_ip.is_ipv4() != self.destination_ip.is_ipv4() {
            return invalid(format!(
                "source.ip {} and destination.ip {} are of different address families",
                self.source_ip, self.destination_ip
            ));
        }
        if !p.has_ports() && (self.source_port.is_some() || self.destination_port.is_some()) {
            return invalid(format!("protocol {} has no ports", ProtocolText(p)));
        }
        if p.0 != PROTO_TCP && self.tcp_flags.is_some() {
            return invalid(format!(
                "tcp_flags is given and protocol {} is not tcp",
                ProtocolText(p)
            ));
        }
        if !p.is_icmp() && (self.icmp_type.is_some() || self.icmp_code.is_some()) {
            return invalid(format!(
                "an ICMP field is given and protocol {} is not icmp or icmpv6",
                ProtocolText(p)
            ));
        }
        let transport = self.source_port.is_some()
            || self.destination_port.is_some()
            || self.tcp_flags.is_some()
            || self.icmp_type.is_some()
            || self.icmp_code.is_some();
        if self.fragment == Some(FragmentName::Later) && transport {
            return invalid("a transport field is given with fragment later".to_string());
        }
        if let Some(d) = self.dscp
            && d > 63
        {
            return invalid(format!("dscp {d} is not 0 to 63"));
        }
        if let Some(e) = self.ecn
            && e > 3
        {
            return invalid(format!("ecn {e} is not 0 to 3"));
        }
        if let Some(v) = self.vlan_id
            && v > 4095
        {
            return invalid(format!("network.vlan.id {v} is not 0 to 4095"));
        }
        if let Some(l) = self.l2_priority
            && l > 7
        {
            return invalid(format!("l2_priority {l} is not 0 to 7"));
        }
        if self.l2_priority.is_some() && self.vlan_id.is_none() {
            return invalid("l2_priority is given and network.vlan.id is not".to_string());
        }
        Ok(p)
    }

    /// The request header of the query.
    pub fn header(&self) -> Result<Header, QueryError> {
        let p = self.validate()?;
        let mut h = Header::request(self.source_ip, self.destination_ip, p.0);
        if let Some(x) = self.source_port {
            h = h.with_src_port(x);
        }
        if let Some(x) = self.destination_port {
            h = h.with_dst_port(x);
        }
        if let Some(fs) = &self.tcp_flags {
            h = h.with_tcp_flags(fs.iter().fold(0, |b, f| b | f.bit()));
        }
        if let Some(t) = self.icmp_type {
            h.icmp_type = FieldValue::Known(t.number(p));
        }
        if let Some(c) = self.icmp_code {
            h.icmp_code = FieldValue::Known(c);
        }
        if let Some(d) = self.dscp {
            h = h.with_dscp(d);
        }
        if let Some(e) = self.ecn {
            h = h.with_ecn(e);
        }
        if let Some(m) = self.source_mac {
            h.src_mac = FieldValue::Known(m);
        }
        if let Some(m) = self.destination_mac {
            h.dst_mac = FieldValue::Known(m);
        }
        if let Some(v) = self.vlan_id {
            h.vlan = FieldValue::Known(v);
        }
        if let Some(l) = self.l2_priority {
            h.l2_priority = FieldValue::Known(l);
        }
        match self.fragment {
            Some(FragmentName::Later) => h = h.as_later_fragment(),
            Some(FragmentName::First) => h.fragment = FieldValue::Known(Fragment::First),
            Some(FragmentName::Unfragmented) | None => {}
        }
        Ok(h)
    }

    /// Validates the input and makes the engine query for one packet.
    pub fn to_query(&self, twin: &Twin) -> Result<Query, QueryError> {
        let h = self.header()?;
        let mut q = Query::path(twin, &h);
        if let Some(i) = &self.ingress {
            let (d, f) = (DeviceId::new(&i.device), InterfaceId::new(&i.interface));
            if twin.ingress(&d, &f).is_none() {
                return Err(QueryError::new(
                    ErrorCode::UnknownIngress,
                    format!(
                        "{}/{} is not an interface with an ingress function",
                        i.device, i.interface
                    ),
                ));
            }
            q = q.with_ingress(d, f);
        }
        q.reply = self.reply.unwrap_or(true);
        Ok(q)
    }
}

/// The protocol in a detail text: its name, or its number.
struct ProtocolText(Protocol);

impl fmt::Display for ProtocolText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.name() {
            Some(n) => f.write_str(n),
            None => write!(f, "{}", self.0.0),
        }
    }
}
