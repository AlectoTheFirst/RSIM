//! The packet header (section 4) with layer 2, layer 3, transport, QoS and
//! encapsulation fields.

use std::net::IpAddr;

use crate::addr::Mac;
use crate::field::{FieldValue, Tri};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// The fragment state of an IP packet. A later fragment has no transport header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Fragment {
    Unfragmented,
    First,
    Later,
}

/// One outer encapsulation header. The list is extensible; step 1 functions
/// do not add or remove encapsulation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Encap {
    Gre {
        src: IpAddr,
        dst: IpAddr,
    },
    Vxlan {
        src: IpAddr,
        dst: IpAddr,
        vni: u32,
    },
    Mpls {
        label: u32,
        traffic_class: FieldValue<u8>,
    },
}

/// The names of the header fields. Functions declare which fields they read
/// and which QoS fields they write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HeaderField {
    SrcMac,
    DstMac,
    Vlan,
    L2Priority,
    SrcIp,
    DstIp,
    Protocol,
    Dscp,
    Ecn,
    Fragment,
    SrcPort,
    DstPort,
    TcpFlags,
    IcmpType,
    IcmpCode,
    MplsTrafficClass,
}

impl HeaderField {
    /// The QoS header fields (section 16).
    pub const QOS: [HeaderField; 4] = [
        HeaderField::Dscp,
        HeaderField::Ecn,
        HeaderField::L2Priority,
        HeaderField::MplsTrafficClass,
    ];
}

/// A packet header. Each field carries its knowledge state; see [`FieldValue`].
///
/// The ingress device, the ingress interface and the VRF are not header
/// fields here. They are context attributes ([`crate::context::Context`]) and
/// the start point of a query. This follows the forwarding state of the HST
/// model, where location and execution context are separate from the header.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Header {
    // Layer 2.
    pub src_mac: FieldValue<Mac>,
    pub dst_mac: FieldValue<Mac>,
    /// Absent for an untagged frame.
    pub vlan: FieldValue<u16>,
    /// Absent for an untagged frame.
    pub l2_priority: FieldValue<u8>,
    // Layer 3.
    pub src_ip: FieldValue<IpAddr>,
    pub dst_ip: FieldValue<IpAddr>,
    pub protocol: FieldValue<u8>,
    pub dscp: FieldValue<u8>,
    pub ecn: FieldValue<u8>,
    pub fragment: FieldValue<Fragment>,
    // Transport. Absent where the transport header is absent.
    pub src_port: FieldValue<u16>,
    pub dst_port: FieldValue<u16>,
    pub tcp_flags: FieldValue<u8>,
    pub icmp_type: FieldValue<u8>,
    pub icmp_code: FieldValue<u8>,
    /// Present only with an MPLS encapsulation.
    pub mpls_tc: FieldValue<u8>,
    /// Outer headers, outermost first.
    pub encap: Vec<Encap>,
}

impl Header {
    /// A layer 3 request from `src` to `dst` with protocol `protocol`.
    ///
    /// The request states the addresses, the protocol and an unfragmented
    /// packet. It does not state the ports, the TCP flags, the ICMP fields,
    /// the marking or the MAC addresses. Fields of headers that the protocol
    /// does not have are absent. The VLAN tag is unstated, and the MPLS
    /// traffic class is absent because there is no MPLS encapsulation.
    pub fn request(src: IpAddr, dst: IpAddr, protocol: u8) -> Self {
        let has_ports = protocol == PROTO_TCP || protocol == PROTO_UDP;
        let ports = if has_ports {
            FieldValue::Unstated
        } else {
            FieldValue::Absent
        };
        let tcp_flags = if protocol == PROTO_TCP {
            FieldValue::Unstated
        } else {
            FieldValue::Absent
        };
        let icmp = if protocol == PROTO_ICMP {
            FieldValue::Unstated
        } else {
            FieldValue::Absent
        };
        Header {
            src_mac: FieldValue::Unstated,
            dst_mac: FieldValue::Unstated,
            vlan: FieldValue::Unstated,
            l2_priority: FieldValue::Unstated,
            src_ip: FieldValue::Known(src),
            dst_ip: FieldValue::Known(dst),
            protocol: FieldValue::Known(protocol),
            dscp: FieldValue::Unstated,
            ecn: FieldValue::Unstated,
            fragment: FieldValue::Known(Fragment::Unfragmented),
            src_port: ports,
            dst_port: ports,
            tcp_flags,
            icmp_type: icmp,
            icmp_code: icmp,
            mpls_tc: FieldValue::Absent,
            encap: Vec::new(),
        }
    }

    pub fn with_src_port(mut self, p: u16) -> Self {
        assert!(self.src_port.is_present(), "the protocol has no ports");
        self.src_port = FieldValue::Known(p);
        self
    }

    pub fn with_dst_port(mut self, p: u16) -> Self {
        assert!(self.dst_port.is_present(), "the protocol has no ports");
        self.dst_port = FieldValue::Known(p);
        self
    }

    pub fn with_dscp(mut self, dscp: u8) -> Self {
        self.dscp = FieldValue::Known(dscp);
        self
    }

    pub fn with_ecn(mut self, ecn: u8) -> Self {
        self.ecn = FieldValue::Known(ecn);
        self
    }

    pub fn with_tcp_flags(mut self, flags: u8) -> Self {
        assert!(self.tcp_flags.is_present(), "the protocol is not TCP");
        self.tcp_flags = FieldValue::Known(flags);
        self
    }

    /// Makes the packet a later fragment. The transport fields become absent.
    pub fn as_later_fragment(mut self) -> Self {
        self.fragment = FieldValue::Known(Fragment::Later);
        self.src_port = FieldValue::Absent;
        self.dst_port = FieldValue::Absent;
        self.tcp_flags = FieldValue::Absent;
        self.icmp_type = FieldValue::Absent;
        self.icmp_code = FieldValue::Absent;
        self
    }

    /// The header of the reply: addresses and ports swapped. The other fields
    /// stay as they are.
    pub fn swapped(&self) -> Header {
        let mut h = self.clone();
        std::mem::swap(&mut h.src_ip, &mut h.dst_ip);
        std::mem::swap(&mut h.src_port, &mut h.dst_port);
        std::mem::swap(&mut h.src_mac, &mut h.dst_mac);
        h
    }
}

/// The flow identity of a header: addresses, protocol and ports. Firewall
/// sessions and NAT bindings use it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    pub src_ip: FieldValue<IpAddr>,
    pub dst_ip: FieldValue<IpAddr>,
    pub protocol: FieldValue<u8>,
    pub src_port: FieldValue<u16>,
    pub dst_port: FieldValue<u16>,
}

impl FlowKey {
    pub fn of(h: &Header) -> Self {
        FlowKey {
            src_ip: h.src_ip,
            dst_ip: h.dst_ip,
            protocol: h.protocol,
            src_port: h.src_port,
            dst_port: h.dst_port,
        }
    }

    /// The key of the reply direction.
    pub fn reversed(&self) -> Self {
        FlowKey {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            protocol: self.protocol,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }

    /// Compares the key with a header.
    ///
    /// A key comes from a packet of the same query. An unstated field in the
    /// key and an unstated field in the header at the same position are the
    /// same unstated value of that one request, so they match. An unstated
    /// field against a known field can be equal or not, and a field that a
    /// function made unknown cannot be compared: both give `Tri::Unknown`.
    pub fn matches(&self, h: &Header) -> Tri {
        fn cmp<T: PartialEq + Copy>(k: FieldValue<T>, v: FieldValue<T>) -> Tri {
            match (k, v) {
                (FieldValue::Unknown, _) | (_, FieldValue::Unknown) => Tri::Unknown,
                // An unstated value can be equal to the known value.
                (FieldValue::Unstated, FieldValue::Known(_))
                | (FieldValue::Known(_), FieldValue::Unstated) => Tri::Unknown,
                (a, b) => Tri::from(a == b),
            }
        }
        cmp(self.src_ip, h.src_ip)
            .and(cmp(self.dst_ip, h.dst_ip))
            .and(cmp(self.protocol, h.protocol))
            .and(cmp(self.src_port, h.src_port))
            .and(cmp(self.dst_port, h.dst_port))
    }
}
