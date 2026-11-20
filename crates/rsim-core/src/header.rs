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
    /// A WireGuard transport packet: UDP from the local tunnel end to the
    /// endpoint of the peer.
    Wireguard {
        src: IpAddr,
        dst: IpAddr,
    },
}

/// How a path query treats a field that it does not state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Unstated {
    /// An unstated field has all values.
    #[default]
    All,
    /// An unstated field with an entry in [`UNSTATED_DEFAULTS`] takes its
    /// default value; each other unstated field has all values.
    Defaults,
}

/// The default value of a field of a path query with [`Unstated::Defaults`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultValue {
    /// The header of the field is absent.
    Absent,
    /// A number.
    Number(u8),
    /// A fragment state.
    Fragment(Fragment),
    /// A TPID.
    Tpid(u16),
    /// A port range, inclusive. A header holds one value, so the field of
    /// the header stays unstated and the packet set of the query holds the
    /// range ([`crate::SetSpec`] of [`UnstatedDefault::ranges`]).
    PortRange(u16, u16),
}

/// One default of [`UNSTATED_DEFAULTS`]: the field, the protocol for which
/// it applies (`None` for each protocol) and the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnstatedDefault {
    pub field: HeaderField,
    pub protocol: Option<u8>,
    pub value: DefaultValue,
}

const fn default(field: HeaderField, protocol: Option<u8>, value: DefaultValue) -> UnstatedDefault {
    UnstatedDefault {
        field,
        protocol,
        value,
    }
}

/// The first port of the ephemeral range of IANA.
pub const EPHEMERAL_FIRST: u16 = 49152;

/// The default value of each field that a path query with
/// [`Unstated::Defaults`] does not state, in the order of application:
/// DSCP 0, ECN 0, an untagged frame (no VLAN tag, so no layer 2 priority),
/// an unfragmented packet, the TCP flags of the first packet of a
/// connection (SYN), an echo request for ICMP (type 8, code 0) and ICMPv6
/// (type 128, code 0), and a source port in the ephemeral range 49152 to
/// 65535. The layer 2 priority is absent only when the VLAN tag is absent.
/// A frame with a stated inner tag has the outer TPID `0x88a8`; each other
/// TPID that the query does not state is `0x8100`. A default applies only to a field whose header the packet has. The MAC
/// addresses and the destination port have no default.
pub const UNSTATED_DEFAULTS: [UnstatedDefault; 12] = [
    default(HeaderField::Dscp, None, DefaultValue::Number(0)),
    default(HeaderField::Ecn, None, DefaultValue::Number(0)),
    default(HeaderField::Vlan, None, DefaultValue::Absent),
    default(HeaderField::L2Priority, None, DefaultValue::Absent),
    default(
        HeaderField::VlanTpid,
        None,
        DefaultValue::Tpid(crate::bits::TPID_8021AD),
    ),
    default(
        HeaderField::Fragment,
        None,
        DefaultValue::Fragment(Fragment::Unfragmented),
    ),
    default(
        HeaderField::TcpFlags,
        Some(PROTO_TCP),
        DefaultValue::Number(TCP_SYN),
    ),
    default(
        HeaderField::IcmpType,
        Some(PROTO_ICMP),
        DefaultValue::Number(ICMP_ECHO_REQUEST),
    ),
    default(
        HeaderField::IcmpCode,
        Some(PROTO_ICMP),
        DefaultValue::Number(0),
    ),
    default(
        HeaderField::IcmpType,
        Some(PROTO_ICMPV6),
        DefaultValue::Number(ICMPV6_ECHO_REQUEST),
    ),
    default(
        HeaderField::IcmpCode,
        Some(PROTO_ICMPV6),
        DefaultValue::Number(0),
    ),
    default(
        HeaderField::SrcPort,
        None,
        DefaultValue::PortRange(EPHEMERAL_FIRST, u16::MAX),
    ),
];

impl UnstatedDefault {
    /// The constraints of the defaults that a header cannot hold: the port
    /// ranges of `applied`. The other fields have no constraint.
    pub fn ranges(applied: &[UnstatedDefault]) -> crate::SetSpec {
        let mut spec = crate::SetSpec::default();
        for d in applied {
            if let (HeaderField::SrcPort, DefaultValue::PortRange(lo, hi)) = (d.field, d.value) {
                spec.src_port = Some(vec![(lo, hi)]);
            }
            if let (HeaderField::DstPort, DefaultValue::PortRange(lo, hi)) = (d.field, d.value) {
                spec.dst_port = Some(vec![(lo, hi)]);
            }
        }
        spec
    }
}

/// The names of the header fields. Functions declare which fields they read
/// and which QoS fields they write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HeaderField {
    SrcMac,
    DstMac,
    Vlan,
    L2Priority,
    VlanTpid,
    InnerVlan,
    InnerL2Priority,
    InnerVlanTpid,
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
            HeaderField::VlanTpid => "VLAN TPID",
            HeaderField::InnerVlan => "inner VLAN",
            HeaderField::InnerL2Priority => "inner layer 2 priority",
            HeaderField::InnerVlanTpid => "inner VLAN TPID",
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
    /// The TPID of the outer tag. Absent for an untagged frame.
    pub vlan_tpid: FieldValue<u16>,
    /// The VLAN of the inner tag. Absent for a frame with less than 2 tags.
    pub inner_vlan: FieldValue<u16>,
    /// The priority of the inner tag.
    pub inner_l2_priority: FieldValue<u8>,
    /// The TPID of the inner tag.
    pub inner_vlan_tpid: FieldValue<u16>,
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
    /// The encapsulation of this header: empty or 1 item. With an
    /// encapsulation, the fields of this header are the outer header, and
    /// `inner` is the encapsulated packet.
    pub encap: Vec<Encap>,
    /// The inner header of an encapsulated packet. It is present exactly
    /// when `encap` is not empty, and it has no encapsulation.
    pub inner: Option<Box<Header>>,
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
            vlan_tpid: FieldValue::Unstated,
            inner_vlan: FieldValue::Unstated,
            inner_l2_priority: FieldValue::Unstated,
            inner_vlan_tpid: FieldValue::Unstated,
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
            inner: None,
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

    /// Gives each unstated field of [`UNSTATED_DEFAULTS`] its default value,
    /// and returns the defaults that applied, in the order of the table. A
    /// stated field keeps its value, a field whose header is absent takes
    /// no default, and a default for another protocol does not apply. A port
    /// range applies to the packet set and not to the header: the port of
    /// the header stays unstated, and [`UnstatedDefault::ranges`] gives its
    /// constraint.
    pub fn apply_defaults(&mut self) -> Vec<UnstatedDefault> {
        fn fill<T: Copy>(slot: &mut FieldValue<T>, v: FieldValue<T>) -> bool {
            if slot.is_unstated() {
                *slot = v;
                true
            } else {
                false
            }
        }
        let mut out = Vec::new();
        for d in UNSTATED_DEFAULTS {
            if d.protocol.is_some() && self.protocol.known() != d.protocol {
                continue;
            }
            let done = match (d.field, d.value) {
                (HeaderField::Vlan, DefaultValue::Absent) => {
                    fill(&mut self.vlan, FieldValue::Absent)
                }
                (HeaderField::L2Priority, DefaultValue::Absent) => {
                    !self.vlan.is_present() && fill(&mut self.l2_priority, FieldValue::Absent)
                }
                (HeaderField::VlanTpid, DefaultValue::Tpid(t)) => {
                    let stated = !self.inner_vlan.is_unstated() && self.inner_vlan.is_present();
                    stated && fill(&mut self.vlan_tpid, FieldValue::Known(t))
                }
                (HeaderField::Dscp, DefaultValue::Number(n)) => {
                    fill(&mut self.dscp, FieldValue::Known(n))
                }
                (HeaderField::Ecn, DefaultValue::Number(n)) => {
                    fill(&mut self.ecn, FieldValue::Known(n))
                }
                (HeaderField::Fragment, DefaultValue::Fragment(x)) => {
                    fill(&mut self.fragment, FieldValue::Known(x))
                }
                (HeaderField::TcpFlags, DefaultValue::Number(n)) => {
                    fill(&mut self.tcp_flags, FieldValue::Known(n))
                }
                (HeaderField::IcmpType, DefaultValue::Number(n)) => {
                    fill(&mut self.icmp_type, FieldValue::Known(n))
                }
                (HeaderField::IcmpCode, DefaultValue::Number(n)) => {
                    fill(&mut self.icmp_code, FieldValue::Known(n))
                }
                (HeaderField::SrcPort, DefaultValue::PortRange(..)) => self.src_port.is_unstated(),
                (HeaderField::DstPort, DefaultValue::PortRange(..)) => self.dst_port.is_unstated(),
                _ => false,
            };
            if done {
                out.push(d);
            }
        }
        out
    }

    /// Makes the frame untagged: both VLAN tags are absent.
    pub fn untagged(mut self) -> Self {
        self.vlan = FieldValue::Absent;
        self.l2_priority = FieldValue::Absent;
        self.vlan_tpid = FieldValue::Absent;
        self.inner_vlan = FieldValue::Absent;
        self.inner_l2_priority = FieldValue::Absent;
        self.inner_vlan_tpid = FieldValue::Absent;
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
    /// replies sets them. A field of an absent header stays absent. The
    /// reply of an encapsulated header is the reply of its outer header
    /// with no encapsulation and no MPLS traffic class.
    pub fn reply(&self) -> Header {
        fn unstated<T: Copy>(v: &mut FieldValue<T>) {
            if v.is_present() {
                *v = FieldValue::Unstated;
            }
        }
        let mut h = self.clone();
        if !h.encap.is_empty() {
            h.encap.clear();
            h.inner = None;
            h.mpls_tc = FieldValue::Absent;
        }
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

    /// This header inside `outer`, or `None` if this header has an
    /// encapsulation already. `outer` has one encapsulation, no inner
    /// header and no unstated field.
    pub fn encapsulate(&self, outer: &Header) -> Option<Header> {
        assert!(
            outer.is_outer(),
            "an outer header has one encapsulation, no inner header and no unstated field"
        );
        if !self.encap.is_empty() {
            return None;
        }
        let mut h = outer.clone();
        h.inner = Some(Box::new(self.clone()));
        Some(h)
    }

    /// The inner header, or `None` if this header has no encapsulation.
    pub fn decapsulate(&self) -> Option<Header> {
        self.inner.as_deref().cloned()
    }

    /// True if the header can be the outer header of an encapsulation.
    pub fn is_outer(&self) -> bool {
        self.encap.len() == 1 && self.inner.is_none() && !self.has_unstated_field()
    }

    /// The presence of the outer tag and of the inner tag: `Some(false)` for
    /// an absent tag, `Some(true)` for a present tag and `None` for an outer
    /// tag that the header does not state. A field of a tag that is absent
    /// makes the tag absent, and an inner tag that the header does not state
    /// is absent. A stated field of the inner tag makes the outer tag
    /// present, and an absent outer tag makes the inner tag absent.
    pub fn tag_presence(&self) -> (Option<bool>, Option<bool>) {
        fn presence(fields: [FieldValue<()>; 3]) -> Option<bool> {
            if fields.contains(&FieldValue::Absent) {
                Some(false)
            } else if fields.iter().all(FieldValue::is_unstated) {
                None
            } else {
                Some(true)
            }
        }
        let unit = |v: FieldValue<u16>| v.map(|_| ());
        let outer = presence([
            unit(self.vlan),
            self.l2_priority.map(|_| ()),
            unit(self.vlan_tpid),
        ]);
        let inner = presence([
            unit(self.inner_vlan),
            self.inner_l2_priority.map(|_| ()),
            unit(self.inner_vlan_tpid),
        ]);
        match (outer, inner) {
            (Some(false), _) | (_, None | Some(false)) => (outer, Some(false)),
            (_, Some(true)) => (Some(true), Some(true)),
        }
    }

    /// True if a field of the header is unstated. The encapsulation and the
    /// inner header are not fields of the header, the fields of an absent
    /// tag are absent, and a TPID that the header does not state is
    /// `0x8100`.
    pub fn has_unstated_field(&self) -> bool {
        let (outer, inner) = self.tag_presence();
        [
            self.src_mac.is_unstated(),
            self.dst_mac.is_unstated(),
            outer != Some(false) && (self.vlan.is_unstated() || self.l2_priority.is_unstated()),
            inner == Some(true)
                && (self.inner_vlan.is_unstated() || self.inner_l2_priority.is_unstated()),
            self.src_ip.is_unstated(),
            self.dst_ip.is_unstated(),
            self.protocol.is_unstated(),
            self.dscp.is_unstated(),
            self.ecn.is_unstated(),
            self.fragment.is_unstated(),
            self.src_port.is_unstated(),
            self.dst_port.is_unstated(),
            self.tcp_flags.is_unstated(),
            self.icmp_type.is_unstated(),
            self.icmp_code.is_unstated(),
            self.mpls_tc.is_unstated(),
        ]
        .contains(&true)
    }

    /// True if the inner header is present exactly with an encapsulation,
    /// and the inner header has no encapsulation.
    pub(crate) fn has_valid_encap(&self) -> bool {
        match (&self.inner, self.encap.len()) {
            (None, 0) => true,
            (Some(i), 1) => i.encap.is_empty() && i.inner.is_none(),
            _ => false,
        }
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

    fn outer() -> Header {
        let mut o = Header::request(ip("198.51.100.1"), ip("198.51.100.2"), PROTO_UDP)
            .with_src_port(49152)
            .with_dst_port(4789);
        o.dscp = FieldValue::Known(0);
        o.ecn = FieldValue::Known(0);
        o.src_mac = FieldValue::Unknown;
        o.dst_mac = FieldValue::Unknown;
        o = o.untagged();
        o.encap = vec![Encap::Vxlan {
            src: ip("198.51.100.1"),
            dst: ip("198.51.100.2"),
            vni: 10,
        }];
        o
    }

    #[test]
    fn an_encapsulation_keeps_the_header_inside_the_outer_header() {
        let e = tcp().encapsulate(&outer()).unwrap();
        assert_eq!(e.dst_port, FieldValue::Known(4789));
        assert_eq!(e.inner.as_deref(), Some(&tcp()));
        assert_eq!(e.decapsulate(), Some(tcp()));
        assert_eq!(e.encapsulate(&outer()), None);
        assert_eq!(tcp().decapsulate(), None);
    }

    #[test]
    fn the_reply_to_an_encapsulated_header_is_the_reply_to_its_outer_header() {
        let r = tcp().encapsulate(&outer()).unwrap().reply();
        assert!(r.encap.is_empty() && r.inner.is_none());
        assert_eq!(r.src_ip, FieldValue::Known(ip("198.51.100.2")));
        assert_eq!(r.dst_port, FieldValue::Known(49152));
    }

    #[test]
    fn an_outer_header_states_each_field() {
        assert!(outer().is_outer());
        let mut o = outer();
        o.dscp = FieldValue::Unstated;
        assert!(!o.is_outer());
        assert!(!tcp().is_outer());
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

    fn fields(applied: &[UnstatedDefault]) -> Vec<HeaderField> {
        applied.iter().map(|d| d.field).collect()
    }

    #[test]
    fn each_default_applies_to_an_unstated_tcp_field_and_a_stated_field_keeps_its_value() {
        let mut h = Header::request(ip("10.0.0.1"), ip("10.0.0.2"), PROTO_TCP).with_dst_port(22);
        h.fragment = FieldValue::Unstated;
        let applied = h.apply_defaults();
        assert_eq!(
            fields(&applied),
            vec![
                HeaderField::Dscp,
                HeaderField::Ecn,
                HeaderField::Vlan,
                HeaderField::L2Priority,
                HeaderField::Fragment,
                HeaderField::TcpFlags,
                HeaderField::SrcPort,
            ]
        );
        assert_eq!(h.vlan, FieldValue::Absent);
        assert_eq!(h.l2_priority, FieldValue::Absent);
        assert_eq!(h.dscp, FieldValue::Known(0));
        assert_eq!(h.ecn, FieldValue::Known(0));
        assert_eq!(h.fragment, FieldValue::Known(Fragment::Unfragmented));
        assert_eq!(h.tcp_flags, FieldValue::Known(TCP_SYN));
        assert!(h.src_mac.is_unstated() && h.dst_mac.is_unstated());
        assert_eq!(h.dst_port, FieldValue::Known(22));
        // The header holds one value: the source port range is a constraint
        // of the packet set.
        assert!(h.src_port.is_unstated());
        let spec = UnstatedDefault::ranges(&applied);
        assert_eq!(spec.src_port, Some(vec![(49152, 65535)]));
        assert_eq!(spec.dst_port, None);

        let mut tagged = tcp().with_dscp(46).with_tcp_flags(TCP_ACK);
        tagged.vlan = FieldValue::Known(10);
        assert_eq!(fields(&tagged.apply_defaults()), vec![HeaderField::Ecn]);
        assert_eq!(tagged.dscp, FieldValue::Known(46));
        assert_eq!(tagged.tcp_flags, FieldValue::Known(TCP_ACK));
        assert_eq!(tagged.src_port, FieldValue::Known(40000));
        assert_eq!(tagged.l2_priority, FieldValue::Unstated);
    }

    #[test]
    fn the_syn_of_the_default_gives_a_reply_with_syn_and_ack() {
        let mut h = Header::request(ip("10.0.0.1"), ip("10.0.0.2"), PROTO_TCP)
            .with_src_port(40000)
            .with_dst_port(22);
        h.apply_defaults();
        assert_eq!(h.reply().tcp_flags, FieldValue::Known(TCP_SYN | TCP_ACK));
    }

    #[test]
    fn icmp_and_icmpv6_take_an_echo_request_and_udp_takes_no_tcp_or_icmp_default() {
        let mut v4 = Header::request(ip("10.0.0.1"), ip("10.0.0.2"), PROTO_ICMP);
        let applied = v4.apply_defaults();
        assert!(fields(&applied).contains(&HeaderField::IcmpType));
        assert!(fields(&applied).contains(&HeaderField::IcmpCode));
        assert!(!fields(&applied).contains(&HeaderField::SrcPort));
        assert_eq!(v4.icmp_type, FieldValue::Known(ICMP_ECHO_REQUEST));
        assert_eq!(v4.icmp_code, FieldValue::Known(0));
        assert_eq!(UnstatedDefault::ranges(&applied), crate::SetSpec::default());

        let mut v6 = Header::request(ip("2001:db8::1"), ip("2001:db8::2"), PROTO_ICMPV6);
        v6.apply_defaults();
        assert_eq!(v6.icmp_type, FieldValue::Known(ICMPV6_ECHO_REQUEST));
        assert_eq!(v6.icmp_code, FieldValue::Known(0));

        let mut stated = icmp(PROTO_ICMP, 0);
        stated.apply_defaults();
        assert_eq!(stated.icmp_type, FieldValue::Known(0));

        let mut udp = Header::request(ip("10.0.0.1"), ip("10.0.0.2"), PROTO_UDP).with_dst_port(53);
        let applied = udp.apply_defaults();
        assert!(!fields(&applied).contains(&HeaderField::TcpFlags));
        assert!(!fields(&applied).contains(&HeaderField::IcmpType));
        assert!(fields(&applied).contains(&HeaderField::SrcPort));
        assert_eq!(udp.tcp_flags, FieldValue::Absent);
        assert_eq!(udp.icmp_type, FieldValue::Absent);
    }
}
