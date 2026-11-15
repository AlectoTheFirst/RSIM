//! The query input of a path query: its fields, its validation and the
//! request header that it gives.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use rsim_core::{EndpointId, FieldValue, Header, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
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
    fn number(self, protocol: Protocol) -> u8 {
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

/// The fields of a path query. The CLI flags and the MCP tool arguments
/// give the same fields. `None` is a field that is not given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryInput {
    pub topology: String,
    pub from: String,
    pub dst: IpAddr,
    pub protocol: Protocol,
    pub src: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<Vec<TcpFlag>>,
    pub icmp_type: Option<IcmpType>,
    pub icmp_code: Option<u8>,
    pub dscp: Option<u8>,
    pub ecn: Option<u8>,
    pub later_fragment: Option<bool>,
    pub reply: Option<bool>,
}

/// The query input in the JSON output. Each field is there, and a field
/// that is not given is `null`. The protocol has its name if it has one,
/// the ICMP type is a number, and the TCP flags are in the order of their
/// bits with no repeat.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QueryEcho {
    pub topology: String,
    pub from: String,
    pub dst: String,
    pub protocol: Protocol,
    pub src: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<Vec<TcpFlag>>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub dscp: Option<u8>,
    pub ecn: Option<u8>,
    pub later_fragment: Option<bool>,
    pub reply: Option<bool>,
}

impl QueryInput {
    pub fn echo(&self) -> QueryEcho {
        QueryEcho {
            topology: self.topology.clone(),
            from: self.from.clone(),
            dst: self.dst.to_string(),
            protocol: self.protocol,
            src: self.src.map(|a| a.to_string()),
            src_port: self.src_port,
            dst_port: self.dst_port,
            tcp_flags: self.tcp_flags.as_ref().map(|fs| {
                let mut fs = fs.clone();
                fs.sort();
                fs.dedup();
                fs
            }),
            icmp_type: self.icmp_type.map(|t| t.number(self.protocol)),
            icmp_code: self.icmp_code,
            dscp: self.dscp,
            ecn: self.ecn,
            later_fragment: self.later_fragment,
            reply: self.reply,
        }
    }

    /// Checks the rules between the fields and the value ranges.
    pub fn validate(&self) -> Result<(), QueryError> {
        let invalid = |d: String| Err(QueryError::new(ErrorCode::InvalidQuery, d));
        let p = self.protocol;
        if let Some(src) = self.src
            && src.is_ipv4() != self.dst.is_ipv4()
        {
            return invalid(format!(
                "src {src} and dst {} are of different address families",
                self.dst
            ));
        }
        if !p.has_ports() && (self.src_port.is_some() || self.dst_port.is_some()) {
            return invalid(format!("protocol {} has no ports", ProtocolText(p)));
        }
        if p.0 != PROTO_TCP && self.tcp_flags.is_some() {
            return invalid(format!(
                "TCP flags are given and protocol {} is not tcp",
                ProtocolText(p)
            ));
        }
        if !p.is_icmp() && (self.icmp_type.is_some() || self.icmp_code.is_some()) {
            return invalid(format!(
                "an ICMP field is given and protocol {} is not icmp or icmpv6",
                ProtocolText(p)
            ));
        }
        let transport = self.src_port.is_some()
            || self.dst_port.is_some()
            || self.tcp_flags.is_some()
            || self.icmp_type.is_some()
            || self.icmp_code.is_some();
        if self.later_fragment == Some(true) && transport {
            return invalid("a transport field is given with later_fragment".to_string());
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
        Ok(())
    }

    /// Validates the input and makes the engine query for one packet from
    /// the endpoint `from`.
    pub fn to_query(&self, twin: &Twin) -> Result<Query, QueryError> {
        self.validate()?;
        let endpoint = twin.endpoint(&EndpointId::new(&self.from)).ok_or_else(|| {
            QueryError::new(
                ErrorCode::UnknownEndpoint,
                format!("endpoint {} is not in the twin", self.from),
            )
        })?;
        let src = match self.src {
            Some(a) => a,
            None => *endpoint.addresses.first().ok_or_else(|| {
                QueryError::new(
                    ErrorCode::InvalidQuery,
                    format!(
                        "endpoint {} has no address, so src must be given",
                        self.from
                    ),
                )
            })?,
        };
        if src.is_ipv4() != self.dst.is_ipv4() {
            return Err(QueryError::new(
                ErrorCode::InvalidQuery,
                format!(
                    "src {src} and dst {} are of different address families",
                    self.dst
                ),
            ));
        }
        let mut h = Header::request(src, self.dst, self.protocol.0);
        if let Some(p) = self.src_port {
            h = h.with_src_port(p);
        }
        if let Some(p) = self.dst_port {
            h = h.with_dst_port(p);
        }
        if let Some(fs) = &self.tcp_flags {
            h = h.with_tcp_flags(fs.iter().fold(0, |b, f| b | f.bit()));
        }
        if let Some(t) = self.icmp_type {
            h.icmp_type = FieldValue::Known(t.number(self.protocol));
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
        if self.later_fragment == Some(true) {
            h = h.as_later_fragment();
        }
        let mut q =
            Query::from_endpoint(twin, &endpoint.id, h).map_err(|e| QueryError::from_exec(&e))?;
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
