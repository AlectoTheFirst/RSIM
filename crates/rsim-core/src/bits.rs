//! The bit table: the order of the header fields in the decision diagram and
//! the bit width of each field.
//!
//! Each bit has 4 adjacent levels: the original request, the current header,
//! the work level and the inner level. Only a relation operation uses the
//! work level. The inner level holds the inner header of an encapsulated
//! packet; for a packet with no encapsulation it is free.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::addr::Mac;
use crate::field::FieldValue;
use crate::header::{Encap, Fragment, Header, HeaderField};

/// The number of bits of one header.
pub const BITS: u32 = 763;
/// The number of levels: 4 for each bit.
pub const LEVELS: u32 = 4 * BITS;

/// One of the 4 levels of a bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bank {
    Original = 0,
    Current = 1,
    Work = 2,
    Inner = 3,
}

/// The level of `bit` in `bank`.
pub const fn level(bit: u32, bank: Bank) -> u32 {
    4 * bit + bank as u32
}

// The presence bits.
pub const P_PORTS: u32 = 0;
pub const P_TCP: u32 = 1;
pub const P_ICMP: u32 = 2;
pub const P_VLAN: u32 = 3;
pub const P_MPLS: u32 = 4;

// The unknown bits.
pub const U_SRC_IP: u32 = 5;
pub const U_DST_IP: u32 = 6;
pub const U_SRC_PORT: u32 = 7;
pub const U_DST_PORT: u32 = 8;
pub const U_DSCP: u32 = 9;
pub const U_ECN: u32 = 10;
pub const U_L2_PRIORITY: u32 = 11;
pub const U_MPLS_TC: u32 = 12;
pub const U_SRC_MAC: u32 = 13;
pub const U_DST_MAC: u32 = 14;
pub const U_VLAN: u32 = 15;

/// The address family: 0 for IPv4, 1 for IPv6.
pub const AF: u32 = 16;

/// The bits of one field: its value bits, most significant bit first, its
/// presence bit and its unknown bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldBits {
    pub start: u32,
    pub width: u32,
    pub presence: Option<u32>,
    pub unknown: Option<u32>,
}

impl FieldBits {
    const fn new(start: u32, width: u32, presence: Option<u32>, unknown: Option<u32>) -> Self {
        FieldBits {
            start,
            width,
            presence,
            unknown,
        }
    }

    /// The value bits.
    pub fn value_bits(&self) -> std::ops::Range<u32> {
        self.start..self.start + self.width
    }

    /// The value bits, the presence bit and the unknown bit.
    pub fn all_bits(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.value_bits().collect();
        v.extend(self.presence);
        v.extend(self.unknown);
        v
    }
}

pub const PROTOCOL: FieldBits = FieldBits::new(17, 8, None, None);
pub const DST_IP: FieldBits = FieldBits::new(25, 128, None, Some(U_DST_IP));
pub const SRC_IP: FieldBits = FieldBits::new(153, 128, None, Some(U_SRC_IP));
pub const DST_PORT: FieldBits = FieldBits::new(281, 16, Some(P_PORTS), Some(U_DST_PORT));
pub const SRC_PORT: FieldBits = FieldBits::new(297, 16, Some(P_PORTS), Some(U_SRC_PORT));
pub const TCP_FLAGS: FieldBits = FieldBits::new(313, 8, Some(P_TCP), None);
pub const ICMP_TYPE: FieldBits = FieldBits::new(321, 8, Some(P_ICMP), None);
pub const ICMP_CODE: FieldBits = FieldBits::new(329, 8, Some(P_ICMP), None);
pub const DSCP: FieldBits = FieldBits::new(337, 6, None, Some(U_DSCP));
pub const ECN: FieldBits = FieldBits::new(343, 2, None, Some(U_ECN));
pub const FRAGMENT: FieldBits = FieldBits::new(345, 2, None, None);
pub const VLAN: FieldBits = FieldBits::new(347, 12, Some(P_VLAN), Some(U_VLAN));
pub const L2_PRIORITY: FieldBits = FieldBits::new(359, 3, Some(P_VLAN), Some(U_L2_PRIORITY));
pub const DST_MAC: FieldBits = FieldBits::new(362, 48, None, Some(U_DST_MAC));
pub const SRC_MAC: FieldBits = FieldBits::new(410, 48, None, Some(U_SRC_MAC));
pub const MPLS_TC: FieldBits = FieldBits::new(458, 3, Some(P_MPLS), Some(U_MPLS_TC));
pub const ENCAP_KIND: FieldBits = FieldBits::new(461, 2, None, None);
pub const ENCAP_SRC: FieldBits = FieldBits::new(463, 128, None, None);
pub const ENCAP_DST: FieldBits = FieldBits::new(591, 128, None, None);
pub const ENCAP_VNI: FieldBits = FieldBits::new(719, 24, None, None);
pub const ENCAP_LABEL: FieldBits = FieldBits::new(743, 20, None, None);

/// The encapsulation kinds in [`ENCAP_KIND`].
pub const ENCAP_NONE: u128 = 0;
pub const ENCAP_GRE: u128 = 1;
pub const ENCAP_VXLAN: u128 = 2;
pub const ENCAP_MPLS: u128 = 3;

/// The fragment states in [`FRAGMENT`].
pub const FRAGMENT_UNFRAGMENTED: u128 = 0;
pub const FRAGMENT_FIRST: u128 = 1;
pub const FRAGMENT_LATER: u128 = 2;

/// The fields of a presence bit.
pub fn presence_group(p: u32) -> Vec<FieldBits> {
    match p {
        P_PORTS => vec![SRC_PORT, DST_PORT],
        P_TCP => vec![TCP_FLAGS],
        P_ICMP => vec![ICMP_TYPE, ICMP_CODE],
        P_VLAN => vec![VLAN, L2_PRIORITY],
        P_MPLS => vec![MPLS_TC],
        _ => Vec::new(),
    }
}

/// The bits of a header field.
pub fn field_bits(f: HeaderField) -> FieldBits {
    match f {
        HeaderField::SrcMac => SRC_MAC,
        HeaderField::DstMac => DST_MAC,
        HeaderField::Vlan => VLAN,
        HeaderField::L2Priority => L2_PRIORITY,
        HeaderField::SrcIp => SRC_IP,
        HeaderField::DstIp => DST_IP,
        HeaderField::Protocol => PROTOCOL,
        HeaderField::Dscp => DSCP,
        HeaderField::Ecn => ECN,
        HeaderField::Fragment => FRAGMENT,
        HeaderField::SrcPort => SRC_PORT,
        HeaderField::DstPort => DST_PORT,
        HeaderField::TcpFlags => TCP_FLAGS,
        HeaderField::IcmpType => ICMP_TYPE,
        HeaderField::IcmpCode => ICMP_CODE,
        HeaderField::MplsTrafficClass => MPLS_TC,
    }
}

/// The bits of the flow identity: the address family, the protocol, the
/// addresses and the ports, with their presence bit and unknown bits.
pub fn flow_bits() -> Vec<u32> {
    let mut v = vec![AF];
    for f in [PROTOCOL, SRC_IP, DST_IP, SRC_PORT, DST_PORT] {
        v.extend(f.all_bits());
    }
    v.sort_unstable();
    v.dedup();
    v
}

/// The pairs of bits that a reply swaps: the source and destination
/// addresses, ports and MAC addresses, with their unknown bits.
pub fn swap_pairs() -> Vec<(u32, u32)> {
    let mut v = Vec::new();
    for (a, b) in [(SRC_IP, DST_IP), (SRC_PORT, DST_PORT), (SRC_MAC, DST_MAC)] {
        v.extend(a.value_bits().zip(b.value_bits()));
        if let (Some(x), Some(y)) = (a.unknown, b.unknown) {
            v.push((x, y));
        }
    }
    v
}

/// The value of a bit in a header: fixed, or free with the same value in
/// the original request and the current header.
pub(crate) type BitValue = Option<bool>;

/// The bits of one header as a set with one request. A field that the
/// header does not state has free value bits.
pub(crate) fn encode(h: &Header) -> Vec<BitValue> {
    let mut bits: Vec<BitValue> = vec![Some(false); BITS as usize];
    // With no known address, the addresses of a GRE or VXLAN encapsulation
    // give the address family.
    let v6 = match (h.src_ip, h.dst_ip, h.encap.first()) {
        (FieldValue::Known(a), _, _) | (_, FieldValue::Known(a), _) => Some(a.is_ipv6()),
        (_, _, Some(Encap::Gre { src, .. } | Encap::Vxlan { src, .. })) => Some(src.is_ipv6()),
        _ => None,
    };
    bits[AF as usize] = v6;
    put(&mut bits, PROTOCOL, h.protocol.map(u128::from));
    put(&mut bits, DST_IP, h.dst_ip.map(ip_bits));
    put(&mut bits, SRC_IP, h.src_ip.map(ip_bits));
    if v6 == Some(false) {
        // An IPv4 address uses the low 32 bits.
        for f in [DST_IP, SRC_IP] {
            for b in f.start..f.start + 96 {
                bits[b as usize] = Some(false);
            }
        }
    }
    put(&mut bits, DST_PORT, h.dst_port.map(u128::from));
    put(&mut bits, SRC_PORT, h.src_port.map(u128::from));
    put(&mut bits, TCP_FLAGS, h.tcp_flags.map(u128::from));
    put(&mut bits, ICMP_TYPE, h.icmp_type.map(u128::from));
    put(&mut bits, ICMP_CODE, h.icmp_code.map(u128::from));
    put(&mut bits, DSCP, h.dscp.map(u128::from));
    put(&mut bits, ECN, h.ecn.map(u128::from));
    put(&mut bits, FRAGMENT, h.fragment.map(fragment_code));
    put(&mut bits, VLAN, h.vlan.map(u128::from));
    put(&mut bits, L2_PRIORITY, h.l2_priority.map(u128::from));
    // The tag is free only when the request states neither field of it.
    let tag = match (h.vlan, h.l2_priority) {
        (FieldValue::Unstated, FieldValue::Unstated) => None,
        (FieldValue::Absent, _) | (_, FieldValue::Absent) => Some(false),
        _ => Some(true),
    };
    bits[P_VLAN as usize] = tag;
    if tag == Some(false) {
        for f in [VLAN, L2_PRIORITY] {
            put(&mut bits, f, FieldValue::Absent);
        }
    }
    put(&mut bits, DST_MAC, h.dst_mac.map(mac_bits));
    put(&mut bits, SRC_MAC, h.src_mac.map(mac_bits));
    put(&mut bits, MPLS_TC, h.mpls_tc.map(u128::from));
    if let Some(e) = h.encap.first() {
        let (kind, src, dst, vni, label) = match e {
            Encap::Gre { src, dst } => (ENCAP_GRE, ip_bits(*src), ip_bits(*dst), 0, 0),
            Encap::Vxlan { src, dst, vni } => (
                ENCAP_VXLAN,
                ip_bits(*src),
                ip_bits(*dst),
                u128::from(*vni),
                0,
            ),
            Encap::Mpls { label, .. } => (ENCAP_MPLS, 0, 0, 0, u128::from(*label)),
        };
        for (f, v) in [
            (ENCAP_KIND, kind),
            (ENCAP_SRC, src),
            (ENCAP_DST, dst),
            (ENCAP_VNI, vni),
            (ENCAP_LABEL, label),
        ] {
            put(&mut bits, f, FieldValue::Known(v));
        }
    }
    bits
}

fn put(bits: &mut [BitValue], f: FieldBits, v: FieldValue<u128>) {
    let set_value = |bits: &mut [BitValue], x: Option<u128>| {
        for (i, b) in f.value_bits().enumerate() {
            let shift = f.width - 1 - i as u32;
            bits[b as usize] = x.map(|x| x >> shift & 1 == 1);
        }
    };
    let (present, unknown, value) = match v {
        FieldValue::Known(x) => (Some(true), false, Some(x)),
        FieldValue::Unstated => (Some(true), false, None),
        FieldValue::Unknown if f.unknown.is_some() => (Some(true), true, Some(0)),
        FieldValue::Unknown => (Some(true), false, None),
        FieldValue::Absent => (Some(false), false, Some(0)),
    };
    set_value(bits, value);
    if let Some(p) = f.presence {
        bits[p as usize] = present;
    }
    if let Some(u) = f.unknown {
        bits[u as usize] = Some(unknown);
    }
}

/// The 128 value bits of an address. An IPv4 address uses the low 32 bits.
pub fn ip_bits(a: IpAddr) -> u128 {
    match a {
        IpAddr::V4(a) => u128::from(u32::from(a)),
        IpAddr::V6(a) => u128::from(a),
    }
}

/// The address of 128 value bits.
pub fn bits_ip(v6: bool, x: u128) -> IpAddr {
    if v6 {
        IpAddr::V6(Ipv6Addr::from(x))
    } else {
        IpAddr::V4(Ipv4Addr::from(x as u32))
    }
}

pub fn mac_bits(m: Mac) -> u128 {
    m.0.iter().fold(0u128, |acc, b| acc << 8 | u128::from(*b))
}

pub fn bits_mac(x: u128) -> Mac {
    let mut b = [0u8; 6];
    for (i, v) in b.iter_mut().enumerate() {
        *v = (x >> (8 * (5 - i)) & 0xff) as u8;
    }
    Mac(b)
}

pub fn fragment_code(f: Fragment) -> u128 {
    match f {
        Fragment::Unfragmented => FRAGMENT_UNFRAGMENTED,
        Fragment::First => FRAGMENT_FIRST,
        Fragment::Later => FRAGMENT_LATER,
    }
}

pub fn code_fragment(x: u128) -> Option<Fragment> {
    match x {
        FRAGMENT_UNFRAGMENTED => Some(Fragment::Unfragmented),
        FRAGMENT_FIRST => Some(Fragment::First),
        FRAGMENT_LATER => Some(Fragment::Later),
        _ => None,
    }
}

/// The value of the value bits of `f`, from a function that gives each bit.
pub fn value_of(f: FieldBits, bit: &dyn Fn(u32) -> bool) -> u128 {
    f.value_bits()
        .fold(0u128, |acc, b| acc << 1 | u128::from(bit(b)))
}

/// The state of a field from its presence bit, its unknown bit and its
/// value bits.
fn state(f: FieldBits, bit: &dyn Fn(u32) -> bool) -> FieldValue<u128> {
    if let Some(p) = f.presence
        && !bit(p)
    {
        return FieldValue::Absent;
    }
    if let Some(u) = f.unknown
        && bit(u)
    {
        return FieldValue::Unknown;
    }
    FieldValue::Known(value_of(f, bit))
}

/// The bits of the header below the encapsulation fields. They move to the
/// inner level when a packet is encapsulated.
pub fn header_bits() -> std::ops::Range<u32> {
    0..ENCAP_KIND.start
}

/// The header of one assignment of the bits. `inner` gives the bits of the
/// inner level, which hold the inner header of an encapsulated packet.
pub(crate) fn decode_with(bit: &dyn Fn(u32) -> bool, inner: &dyn Fn(u32) -> bool) -> Header {
    let mut h = decode(bit);
    if !h.encap.is_empty() {
        h.inner = Some(Box::new(decode(inner)));
    }
    h
}

/// The header of one assignment of the bits.
pub(crate) fn decode(bit: &dyn Fn(u32) -> bool) -> Header {
    let v6 = bit(AF);
    let n8 = |f| state(f, bit).map(|x| x as u8);
    let n16 = |f| state(f, bit).map(|x| x as u16);
    let kind = value_of(ENCAP_KIND, bit);
    let encap = match kind {
        ENCAP_GRE => vec![Encap::Gre {
            src: bits_ip(v6, value_of(ENCAP_SRC, bit)),
            dst: bits_ip(v6, value_of(ENCAP_DST, bit)),
        }],
        ENCAP_VXLAN => vec![Encap::Vxlan {
            src: bits_ip(v6, value_of(ENCAP_SRC, bit)),
            dst: bits_ip(v6, value_of(ENCAP_DST, bit)),
            vni: value_of(ENCAP_VNI, bit) as u32,
        }],
        ENCAP_MPLS => vec![Encap::Mpls {
            label: value_of(ENCAP_LABEL, bit) as u32,
            traffic_class: n8(MPLS_TC),
        }],
        _ => Vec::new(),
    };
    Header {
        src_mac: state(SRC_MAC, bit).map(bits_mac),
        dst_mac: state(DST_MAC, bit).map(bits_mac),
        vlan: n16(VLAN),
        l2_priority: n8(L2_PRIORITY),
        src_ip: state(SRC_IP, bit).map(|x| bits_ip(v6, x)),
        dst_ip: state(DST_IP, bit).map(|x| bits_ip(v6, x)),
        protocol: n8(PROTOCOL),
        dscp: n8(DSCP),
        ecn: n8(ECN),
        fragment: match state(FRAGMENT, bit) {
            FieldValue::Known(x) => match code_fragment(x) {
                Some(f) => FieldValue::Known(f),
                None => FieldValue::Unknown,
            },
            _ => FieldValue::Unknown,
        },
        src_port: n16(SRC_PORT),
        dst_port: n16(DST_PORT),
        tcp_flags: n8(TCP_FLAGS),
        icmp_type: n8(ICMP_TYPE),
        icmp_code: n8(ICMP_CODE),
        mpls_tc: n8(MPLS_TC),
        encap,
        inner: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_has_763_bits_in_order() {
        let fields = [
            PROTOCOL,
            DST_IP,
            SRC_IP,
            DST_PORT,
            SRC_PORT,
            TCP_FLAGS,
            ICMP_TYPE,
            ICMP_CODE,
            DSCP,
            ECN,
            FRAGMENT,
            VLAN,
            L2_PRIORITY,
            DST_MAC,
            SRC_MAC,
            MPLS_TC,
            ENCAP_KIND,
            ENCAP_SRC,
            ENCAP_DST,
            ENCAP_VNI,
            ENCAP_LABEL,
        ];
        let mut next = AF + 1;
        for f in fields {
            assert_eq!(f.start, next);
            next += f.width;
        }
        assert_eq!(next, BITS);
    }

    #[test]
    fn a_known_header_decodes_to_itself() {
        let h = Header::request(
            "10.0.0.1".parse().unwrap(),
            "2.2.2.2".parse().unwrap(),
            crate::header::PROTO_TCP,
        )
        .with_src_port(40000)
        .with_dst_port(22)
        .with_tcp_flags(0x02)
        .with_dscp(46)
        .with_ecn(1);
        let mut h = h;
        h.src_mac = FieldValue::Known(Mac([1, 2, 3, 4, 5, 6]));
        h.dst_mac = FieldValue::Known(Mac([0xa, 0xb, 0xc, 0xd, 0xe, 0xf]));
        h.vlan = FieldValue::Absent;
        h.l2_priority = FieldValue::Absent;
        let bits = encode(&h);
        assert!(bits.iter().all(Option::is_some));
        let back = decode(&|b| bits[b as usize] == Some(true));
        assert_eq!(back, h);
    }
}
