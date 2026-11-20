//! The input of a set query: each field takes a set. A field that is not
//! given has all values.

use rsim_core::{DeviceId, Fragment, InterfaceId, Mac, PacketSet, Prefix, SetSpec};
use rsim_engine::{Query, Twin};

pub use rsim_contract::query::SetEcho;

use crate::error::{ErrorCode, QueryError};
use crate::query::{FragmentName, IngressRef, Protocol, TcpFlag, parse_mac};

/// A list of inclusive ranges of a number field: `n`, `a-b` or a comma list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ranges(pub Vec<(u32, u32)>);

impl Ranges {
    /// Parses the list and checks each value against `max`.
    pub fn parse(s: &str, name: &str, max: u32) -> Result<Ranges, String> {
        let mut v = Vec::new();
        for item in s.split(',').map(str::trim) {
            let err = || format!("{name} {item:?} is not a number 0 to {max} or a range a-b");
            let (lo, hi) = match item.split_once('-') {
                Some((a, b)) => (
                    a.parse::<u32>().map_err(|_| err())?,
                    b.parse::<u32>().map_err(|_| err())?,
                ),
                None => {
                    let n = item.parse::<u32>().map_err(|_| err())?;
                    (n, n)
                }
            };
            if lo > hi || hi > max {
                return Err(err());
            }
            v.push((lo, hi));
        }
        v.sort_unstable();
        v.dedup();
        Ok(Ranges(v))
    }

    fn u8s(&self) -> Vec<(u8, u8)> {
        self.0.iter().map(|&(a, b)| (a as u8, b as u8)).collect()
    }

    fn u16s(&self) -> Vec<(u16, u16)> {
        self.0.iter().map(|&(a, b)| (a as u16, b as u16)).collect()
    }

    fn text(&self) -> String {
        self.0
            .iter()
            .map(|&(a, b)| {
                if a == b {
                    a.to_string()
                } else {
                    format!("{a}-{b}")
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// A comma list of addresses and prefixes.
pub fn parse_prefixes(s: &str, name: &str) -> Result<Vec<Prefix>, String> {
    let mut v = Vec::new();
    for item in s.split(',').map(str::trim) {
        let p = item
            .parse::<Prefix>()
            .map_err(|_| format!("{name} {item:?} is not an address or a prefix"))?;
        v.push(p);
    }
    v.sort();
    v.dedup();
    Ok(v)
}

/// A comma list of protocol names.
pub fn parse_transports(s: &str) -> Result<Vec<Protocol>, String> {
    let mut v = Vec::new();
    for item in s.split(',').map(str::trim) {
        match item.parse::<Protocol>() {
            Ok(p) if p.name().is_some() => v.push(p),
            _ => {
                return Err(format!(
                    "network.transport {item:?} is not tcp, udp, icmp or icmpv6"
                ));
            }
        }
    }
    v.sort_by_key(|p| p.0);
    v.dedup();
    Ok(v)
}

/// A comma list of MAC addresses.
pub fn parse_macs(s: &str) -> Result<Vec<Mac>, String> {
    let mut v = Vec::new();
    for item in s.split(',').map(str::trim) {
        v.push(parse_mac(item)?);
    }
    v.sort();
    v.dedup();
    Ok(v)
}

/// A comma list of TCP flag values: a number, a range, or flag names joined
/// with `+`, for example `syn+ack`.
pub fn parse_tcp_flags(s: &str) -> Result<Ranges, String> {
    let mut items = Vec::new();
    for item in s.split(',').map(str::trim) {
        if item.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
            let mut bits = 0u32;
            for name in item.split('+') {
                bits |= u32::from(name.parse::<TcpFlag>()?.bit());
            }
            items.push(bits.to_string());
        } else {
            items.push(item.to_string());
        }
    }
    Ranges::parse(&items.join(","), "tcp_flags", 255)
}

/// A comma list of fragment states.
pub fn parse_fragments(s: &str) -> Result<Vec<FragmentName>, String> {
    let mut v = Vec::new();
    for item in s.split(',').map(str::trim) {
        v.push(item.parse::<FragmentName>()?);
    }
    v.sort_by_key(|f| *f as u8);
    v.dedup();
    Ok(v)
}

/// The fields of a set query. `None` is a field that is not given.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetInput {
    pub topology: String,
    pub ingress: Option<IngressRef>,
    pub source_ip: Option<Vec<Prefix>>,
    pub destination_ip: Option<Vec<Prefix>>,
    pub iana_number: Option<Ranges>,
    pub transport: Option<Vec<Protocol>>,
    pub source_port: Option<Ranges>,
    pub destination_port: Option<Ranges>,
    pub source_mac: Option<Vec<Mac>>,
    pub destination_mac: Option<Vec<Mac>>,
    pub vlan_id: Option<Ranges>,
    pub l2_priority: Option<Ranges>,
    pub vlan_tpid: Option<Ranges>,
    pub inner_vlan_id: Option<Ranges>,
    pub inner_l2_priority: Option<Ranges>,
    pub inner_vlan_tpid: Option<Ranges>,
    pub tcp_flags: Option<Ranges>,
    pub icmp_type: Option<Ranges>,
    pub icmp_code: Option<Ranges>,
    pub dscp: Option<Ranges>,
    pub ecn: Option<Ranges>,
    pub fragment: Option<Vec<FragmentName>>,
    pub reply: Option<bool>,
}

fn join<T>(v: &Option<Vec<T>>, f: impl Fn(&T) -> String) -> Option<String> {
    v.as_ref()
        .map(|v| v.iter().map(f).collect::<Vec<_>>().join(","))
}

impl SetInput {
    pub fn echo(&self) -> SetEcho {
        SetEcho {
            topology: self.topology.clone(),
            ingress: self.ingress.clone(),
            source_ip: join(&self.source_ip, |p| p.to_string()),
            destination_ip: join(&self.destination_ip, |p| p.to_string()),
            iana_number: self.iana_number.as_ref().map(Ranges::text),
            transport: join(&self.transport, |p| p.name().unwrap_or("").to_string()),
            source_port: self.source_port.as_ref().map(Ranges::text),
            destination_port: self.destination_port.as_ref().map(Ranges::text),
            source_mac: join(&self.source_mac, |m| format!("{m:?}")),
            destination_mac: join(&self.destination_mac, |m| format!("{m:?}")),
            vlan_id: self.vlan_id.as_ref().map(Ranges::text),
            l2_priority: self.l2_priority.as_ref().map(Ranges::text),
            vlan_tpid: self.vlan_tpid.as_ref().map(Ranges::text),
            inner_vlan_id: self.inner_vlan_id.as_ref().map(Ranges::text),
            inner_l2_priority: self.inner_l2_priority.as_ref().map(Ranges::text),
            inner_vlan_tpid: self.inner_vlan_tpid.as_ref().map(Ranges::text),
            tcp_flags: self.tcp_flags.as_ref().map(Ranges::text),
            icmp_type: self.icmp_type.as_ref().map(Ranges::text),
            icmp_code: self.icmp_code.as_ref().map(Ranges::text),
            dscp: self.dscp.as_ref().map(Ranges::text),
            ecn: self.ecn.as_ref().map(Ranges::text),
            fragment: join(&self.fragment, |f| {
                serde_json::to_value(f)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default()
            }),
            reply: self.reply,
        }
    }

    /// The constraints of the query. Without `source.ip`, an ingress gives
    /// its attached addresses: the addresses of its attachment records, or
    /// the networks of its edge interface.
    pub fn spec(&self, twin: &Twin) -> SetSpec {
        let protocol = match (&self.iana_number, &self.transport) {
            (None, None) => None,
            (Some(r), None) => Some(r.u8s()),
            (None, Some(t)) => Some(t.iter().map(|p| (p.0, p.0)).collect()),
            (Some(r), Some(t)) => Some(
                t.iter()
                    .filter(|p| {
                        r.0.iter()
                            .any(|&(lo, hi)| lo <= u32::from(p.0) && u32::from(p.0) <= hi)
                    })
                    .map(|p| (p.0, p.0))
                    .collect(),
            ),
        };
        let source = self.source_ip.clone().or_else(|| {
            let i = self.ingress.as_ref()?;
            let at =
                |d: &DeviceId, f: &InterfaceId| d.as_str() == i.device && f.as_str() == i.interface;
            let hosts: Vec<Prefix> = twin
                .attachments()
                .iter()
                .filter(|a| at(&a.device, &a.interface))
                .map(|a| Prefix::host(a.address))
                .collect();
            let nets: Vec<Prefix> = twin
                .edge_interfaces()
                .iter()
                .filter(|e| at(&e.device, &e.interface))
                .flat_map(|e| e.networks.iter().copied())
                .collect();
            let mut v = if hosts.is_empty() { nets } else { hosts };
            v.sort();
            v.dedup();
            (!v.is_empty()).then_some(v)
        });
        SetSpec {
            src_ip: source,
            dst_ip: self.destination_ip.clone(),
            protocol,
            src_port: self.source_port.as_ref().map(Ranges::u16s),
            dst_port: self.destination_port.as_ref().map(Ranges::u16s),
            src_mac: self.source_mac.clone(),
            dst_mac: self.destination_mac.clone(),
            vlan: self.vlan_id.as_ref().map(Ranges::u16s),
            l2_priority: self.l2_priority.as_ref().map(Ranges::u8s),
            vlan_tpid: self.vlan_tpid.as_ref().map(Ranges::u16s),
            inner_vlan: self.inner_vlan_id.as_ref().map(Ranges::u16s),
            inner_l2_priority: self.inner_l2_priority.as_ref().map(Ranges::u8s),
            inner_vlan_tpid: self.inner_vlan_tpid.as_ref().map(Ranges::u16s),
            tcp_flags: self.tcp_flags.as_ref().map(Ranges::u8s),
            icmp_type: self.icmp_type.as_ref().map(Ranges::u8s),
            icmp_code: self.icmp_code.as_ref().map(Ranges::u8s),
            dscp: self.dscp.as_ref().map(Ranges::u8s),
            ecn: self.ecn.as_ref().map(Ranges::u8s),
            fragment: self.fragment.as_ref().map(|v| {
                v.iter()
                    .map(|f| match f {
                        FragmentName::Unfragmented => Fragment::Unfragmented,
                        FragmentName::First => Fragment::First,
                        FragmentName::Later => Fragment::Later,
                    })
                    .collect()
            }),
        }
    }

    /// Makes the engine query. A set with no packet is not valid.
    pub fn to_query(&self, twin: &Twin) -> Result<Query, QueryError> {
        let arena = twin.arena(None);
        let packets = PacketSet::from_spec(&arena, &self.spec(twin));
        if packets.is_empty() {
            return Err(QueryError::new(
                ErrorCode::InvalidQuery,
                "the set of the query has no packet",
            ));
        }
        let mut q = Query::set(packets);
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
