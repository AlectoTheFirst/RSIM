//! The packet header with layer 2, layer 3, transport, QoS and
//! encapsulation fields.

use std::net::IpAddr;

use crate::addr::Mac;
use crate::field::FieldValue;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

/// The fragment state of an IP packet. A later fragment has no transport header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Fragment {
    Unfragmented,
    First,
    Later,
}

/// One outer encapsulation header.
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
    /// The name of the field in a reason text.
    pub fn name(&self) -> &'static str {
        match self {
            HeaderField::SrcMac => "source MAC",
            HeaderField::DstMac => "destination MAC",
            HeaderField::Vlan => "VLAN",
            HeaderField::L2Priority => "layer 2 priority",
            HeaderField::SrcIp => "source IP",
            HeaderField::DstIp => "destination IP",
            HeaderField::Protocol => "protocol",
            HeaderField::Dscp => "DSCP",
            HeaderField::Ecn => "ECN",
            HeaderField::Fragment => "fragment",
            HeaderField::SrcPort => "source port",
            HeaderField::DstPort => "destination port",
            HeaderField::TcpFlags => "TCP flags",
            HeaderField::IcmpType => "ICMP type",
            HeaderField::IcmpCode => "ICMP code",
            HeaderField::MplsTrafficClass => "MPLS traffic class",
        }
    }

    /// The QoS header fields.
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
/// the start point of a query.
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
        let icmp = if protocol == PROTO_ICMP || protocol == PROTO_ICMPV6 {
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

    /// The header of the reply to this packet.
    ///
    /// The addresses, the ports and the MAC addresses are swapped. An ICMP or
    /// ICMPv6 echo request gives an echo reply. TCP flags with only SYN give
    /// SYN and ACK. All other TCP flags and ICMP types are unstated in the
    /// reply. The DSCP and the ECN are unstated, because the host that
    /// replies sets them. A field of an absent header stays absent.
    pub fn reply(&self) -> Header {
        fn unstated<T: Copy>(v: &mut FieldValue<T>) {
            if v.is_present() {
                *v = FieldValue::Unstated;
            }
        }
        let mut h = self.clone();
        std::mem::swap(&mut h.src_ip, &mut h.dst_ip);
        std::mem::swap(&mut h.src_port, &mut h.dst_port);
        std::mem::swap(&mut h.src_mac, &mut h.dst_mac);
        match self.tcp_flags {
            FieldValue::Known(TCP_SYN) => h.tcp_flags = FieldValue::Known(TCP_SYN | TCP_ACK),
            _ => unstated(&mut h.tcp_flags),
        }
        let echo_reply = match (self.protocol, self.icmp_type) {
            (FieldValue::Known(PROTO_ICMP), FieldValue::Known(ICMP_ECHO_REQUEST)) => {
                Some(ICMP_ECHO_REPLY)
            }
            (FieldValue::Known(PROTO_ICMPV6), FieldValue::Known(ICMPV6_ECHO_REQUEST)) => {
                Some(ICMPV6_ECHO_REPLY)
            }
            _ => None,
        };
        match echo_reply {
            Some(t) => {
                h.icmp_type = FieldValue::Known(t);
                h.icmp_code = FieldValue::Known(0);
            }
            None => {
                unstated(&mut h.icmp_type);
                unstated(&mut h.icmp_code);
            }
        }
        unstated(&mut h.dscp);
        unstated(&mut h.ecn);
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn tcp() -> Header {
        Header::request(ip("10.0.0.1"), ip("10.0.0.2"), PROTO_TCP)
            .with_src_port(40000)
            .with_dst_port(22)
    }

    fn icmp(protocol: u8, icmp_type: u8) -> Header {
        let (a, b) = if protocol == PROTO_ICMPV6 {
            ("2001:db8::1", "2001:db8::2")
        } else {
            ("10.0.0.1", "10.0.0.2")
        };
        let mut h = Header::request(ip(a), ip(b), protocol);
        h.icmp_type = FieldValue::Known(icmp_type);
        h.icmp_code = FieldValue::Known(0);
        h
    }

    #[test]
    fn a_reply_swaps_addresses_and_ports() {
        let r = tcp().reply();
        assert_eq!(r.src_ip, FieldValue::Known(ip("10.0.0.2")));
        assert_eq!(r.dst_ip, FieldValue::Known(ip("10.0.0.1")));
        assert_eq!(r.src_port, FieldValue::Known(22));
        assert_eq!(r.dst_port, FieldValue::Known(40000));
    }

    #[test]
    fn the_reply_to_a_syn_is_syn_and_ack() {
        let r = tcp().with_tcp_flags(0x02).reply();
        assert_eq!(r.tcp_flags, FieldValue::Known(0x12));
    }

    #[test]
    fn the_reply_to_other_tcp_flags_has_unstated_flags() {
        assert_eq!(
            tcp().with_tcp_flags(0x10).reply().tcp_flags,
            FieldValue::Unstated
        );
        assert_eq!(
            tcp().with_tcp_flags(0x12).reply().tcp_flags,
            FieldValue::Unstated
        );
        assert_eq!(tcp().reply().tcp_flags, FieldValue::Unstated);
    }

    #[test]
    fn the_reply_to_an_echo_request_is_an_echo_reply() {
        let r = icmp(PROTO_ICMP, 8).reply();
        assert_eq!(r.icmp_type, FieldValue::Known(0));
        assert_eq!(r.icmp_code, FieldValue::Known(0));
    }

    #[test]
    fn the_reply_to_an_icmpv6_echo_request_is_an_echo_reply() {
        let r = icmp(PROTO_ICMPV6, 128).reply();
        assert_eq!(r.icmp_type, FieldValue::Known(129));
        assert_eq!(r.icmp_code, FieldValue::Known(0));
    }

    #[test]
    fn the_reply_to_other_icmp_types_has_unstated_type_and_code() {
        let r = icmp(PROTO_ICMP, 13).reply();
        assert_eq!(r.icmp_type, FieldValue::Unstated);
        assert_eq!(r.icmp_code, FieldValue::Unstated);
        // Type 8 is an echo request only in ICMP, and type 128 only in ICMPv6.
        assert_eq!(
            icmp(PROTO_ICMPV6, 8).reply().icmp_type,
            FieldValue::Unstated
        );
    }

    #[test]
    fn the_reply_has_unstated_dscp_and_ecn() {
        let r = tcp().with_dscp(46).with_ecn(1).reply();
        assert_eq!(r.dscp, FieldValue::Unstated);
        assert_eq!(r.ecn, FieldValue::Unstated);
    }

    #[test]
    fn absent_fields_stay_absent_in_the_reply() {
        let r = tcp().as_later_fragment().reply();
        assert_eq!(r.tcp_flags, FieldValue::Absent);
        assert_eq!(r.src_port, FieldValue::Absent);
        let udp = Header::request(ip("10.0.0.1"), ip("10.0.0.2"), PROTO_UDP).reply();
        assert_eq!(udp.tcp_flags, FieldValue::Absent);
        assert_eq!(udp.icmp_type, FieldValue::Absent);
    }
}
