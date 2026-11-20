//! The query input of a path query: its fields, its validation and the
//! request header that it gives.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use rsim_core::{
    DefaultValue, DeviceId, FieldValue, Fragment, Header, HeaderField, InterfaceId, Mac,
    PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, PacketSet, UnstatedDefault,
};
use rsim_engine::{Query, Twin};
use serde::Serialize;

pub use rsim_contract::args::Unstated;
pub use rsim_contract::query::{FragmentName, IngressRef, QueryEcho, TcpFlag};

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

    /// A name in any case: `tcp`, `UDP` and `Icmp` are names.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
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
    pub vlan_tpid: Option<u16>,
    pub inner_vlan_id: Option<u16>,
    pub inner_l2_priority: Option<u8>,
    pub inner_vlan_tpid: Option<u16>,
    pub tcp_flags: Option<Vec<TcpFlag>>,
    pub icmp_type: Option<IcmpType>,
    pub icmp_code: Option<u8>,
    pub dscp: Option<u8>,
    pub ecn: Option<u8>,
    pub fragment: Option<FragmentName>,
    pub reply: Option<bool>,
    pub unstated: Option<Unstated>,
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
            transport: p.and_then(Protocol::name).map(str::to_string),
            source_port: self.source_port,
            destination_port: self.destination_port,
            source_mac: self.source_mac.map(|m| format!("{m:?}")),
            destination_mac: self.destination_mac.map(|m| format!("{m:?}")),
            vlan_id: self.vlan_id,
            l2_priority: self.l2_priority,
            vlan_tpid: self.vlan_tpid,
            inner_vlan_id: self.inner_vlan_id,
            inner_l2_priority: self.inner_l2_priority,
            inner_vlan_tpid: self.inner_vlan_tpid,
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
            unstated: self.unstated,
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
        if let Some(v) = self.inner_vlan_id
            && v > 4095
        {
            return invalid(format!("network.inner.vlan.id {v} is not 0 to 4095"));
        }
        if let Some(l) = self.inner_l2_priority
            && l > 7
        {
            return invalid(format!("inner_l2_priority {l} is not 0 to 7"));
        }
        let outer = [
            ("network.vlan.tpid", self.vlan_tpid.is_some()),
            ("network.inner.vlan.id", self.inner_vlan_id.is_some()),
            ("inner_l2_priority", self.inner_l2_priority.is_some()),
            ("network.inner.vlan.tpid", self.inner_vlan_tpid.is_some()),
        ];
        if let (Some((name, _)), None) = (outer.iter().find(|(_, g)| *g), self.vlan_id) {
            return invalid(format!("{name} is given and network.vlan.id is not"));
        }
        for (name, given) in [
            ("inner_l2_priority", self.inner_l2_priority.is_some()),
            ("network.inner.vlan.tpid", self.inner_vlan_tpid.is_some()),
        ] {
            if given && self.inner_vlan_id.is_none() {
                return invalid(format!("{name} is given and network.inner.vlan.id is not"));
            }
        }
        Ok(p)
    }

    /// The request header of the query.
    pub fn header(&self) -> Result<Header, QueryError> {
        Ok(self.header_with_defaults()?.0)
    }

    /// The notes of the answer: one note that names each default that
    /// applied, for example `defaults: dscp 0, ecn 0, no VLAN, tcp syn,
    /// source.port 49152-65535`. A query that does not give its header has
    /// no notes.
    pub fn notes(&self) -> Vec<String> {
        let Ok((_, applied)) = self.header_with_defaults() else {
            return Vec::new();
        };
        if applied.is_empty() {
            return Vec::new();
        }
        let untagged = applied.iter().any(|d| d.field == HeaderField::Vlan);
        let parts: Vec<String> = applied
            .iter()
            .filter(|d| !(untagged && d.field == HeaderField::L2Priority))
            .map(default_text)
            .collect();
        vec![format!("defaults: {}", parts.join(", "))]
    }

    /// The request header of the query, and the defaults that applied with
    /// `unstated` `defaults`.
    fn header_with_defaults(&self) -> Result<(Header, Vec<UnstatedDefault>), QueryError> {
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
        if let Some(t) = self.vlan_tpid {
            h.vlan_tpid = FieldValue::Known(t);
        }
        if let Some(v) = self.inner_vlan_id {
            h.inner_vlan = FieldValue::Known(v);
        }
        if let Some(l) = self.inner_l2_priority {
            h.inner_l2_priority = FieldValue::Known(l);
        }
        if let Some(t) = self.inner_vlan_tpid {
            h.inner_vlan_tpid = FieldValue::Known(t);
        }
        match self.fragment {
            Some(FragmentName::Later) => h = h.as_later_fragment(),
            Some(FragmentName::First) => h.fragment = FieldValue::Known(Fragment::First),
            Some(FragmentName::Unfragmented) | None => {}
        }
        let defaults = match self.unstated.unwrap_or_default() {
            Unstated::All => Vec::new(),
            Unstated::Defaults => h.apply_defaults(),
        };
        Ok((h, defaults))
    }

    /// Validates the input and makes the engine query for one packet.
    pub fn to_query(&self, twin: &Twin) -> Result<Query, QueryError> {
        let (h, applied) = self.header_with_defaults()?;
        let mut q = Query::path(twin, &h);
        let ranges = UnstatedDefault::ranges(&applied);
        if ranges != rsim_core::SetSpec::default() {
            q.packets = q
                .packets
                .intersect(&PacketSet::from_spec(q.packets.arena(), &ranges));
        }
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

/// The short text of a default in the note of an answer.
fn default_text(d: &UnstatedDefault) -> String {
    let name = field_name(d.field);
    match (d.field, d.value, d.protocol) {
        (HeaderField::Vlan, DefaultValue::Absent, _) => "no VLAN".to_string(),
        (_, DefaultValue::Absent, _) => format!("no {name}"),
        (HeaderField::TcpFlags, DefaultValue::Number(n), _) => {
            let flags = TcpFlag::ALL
                .iter()
                .filter(|f| n & f.bit() != 0)
                .map(|f| f.name())
                .collect::<Vec<_>>()
                .join("+");
            format!("tcp {flags}")
        }
        (HeaderField::IcmpType, DefaultValue::Number(8), Some(PROTO_ICMP))
        | (HeaderField::IcmpType, DefaultValue::Number(128), Some(PROTO_ICMPV6)) => {
            format!("{name} echo-request")
        }
        (_, DefaultValue::Number(n), _) => format!("{name} {n}"),
        (_, DefaultValue::Fragment(Fragment::Unfragmented), _) => "unfragmented".to_string(),
        (_, DefaultValue::Fragment(Fragment::First), _) => "first fragment".to_string(),
        (_, DefaultValue::Fragment(Fragment::Later), _) => "later fragment".to_string(),
        (_, DefaultValue::PortRange(lo, hi), _) => format!("{name} {lo}-{hi}"),
        (_, DefaultValue::Tpid(t), _) => format!("{name} {t:#06x}"),
    }
}

/// The name of the query field of a header field.
fn field_name(f: HeaderField) -> &'static str {
    match f {
        HeaderField::SrcMac => "source.mac",
        HeaderField::DstMac => "destination.mac",
        HeaderField::Vlan => "network.vlan.id",
        HeaderField::L2Priority => "l2_priority",
        HeaderField::VlanTpid => "network.vlan.tpid",
        HeaderField::InnerVlan => "network.inner.vlan.id",
        HeaderField::InnerL2Priority => "inner_l2_priority",
        HeaderField::InnerVlanTpid => "network.inner.vlan.tpid",
        HeaderField::SrcIp => "source.ip",
        HeaderField::DstIp => "destination.ip",
        HeaderField::Protocol => "network.iana_number",
        HeaderField::Dscp => "dscp",
        HeaderField::Ecn => "ecn",
        HeaderField::Fragment => "fragment",
        HeaderField::SrcPort => "source.port",
        HeaderField::DstPort => "destination.port",
        HeaderField::TcpFlags => "tcp_flags",
        HeaderField::IcmpType => "icmp_type",
        HeaderField::IcmpCode => "icmp_code",
        HeaderField::MplsTrafficClass => "mpls_tc",
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

#[cfg(test)]
mod protocol_case_tests {
    use super::Protocol;

    #[test]
    fn a_protocol_name_is_read_in_any_case() {
        for (a, b) in [
            ("UDP", "udp"),
            ("Tcp", "tcp"),
            ("ICMP", "icmp"),
            ("ICMPv6", "icmpv6"),
        ] {
            assert_eq!(a.parse::<Protocol>(), b.parse::<Protocol>());
        }
        assert!("Udp6".parse::<Protocol>().is_err());
    }
}
