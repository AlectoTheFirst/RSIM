//! The description of a packet set as a list of members. A member is a
//! product of field values. The members are disjoint, and they are in a
//! fixed order that comes from the bit table.

use rsim_dd::{DdError, Edge};

use crate::addr::Prefix;
use crate::bits::{self, Bank, FieldBits, level};
use crate::header::HeaderField;
use crate::packet_set::PacketSet;
use crate::set::Ops;

/// The values of one field in one member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Values {
    /// The header of the field is not present.
    Absent,
    /// A function made the field unknown.
    Unknown,
    /// In the current header: the value of the same field of the original
    /// request.
    Original,
    /// Inclusive ranges of a number field, in increasing order.
    Ranges(Vec<(u128, u128)>),
    /// The prefixes of an address field, in increasing order.
    Prefixes(Vec<Prefix>),
}

impl Values {
    /// The value, if the field has exactly one value.
    pub fn single(&self) -> Option<u128> {
        match self {
            Values::Ranges(r) if r.len() == 1 && r[0].0 == r[0].1 => Some(r[0].0),
            _ => None,
        }
    }
}

/// The encapsulation of a member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncapDesc {
    /// One of [`bits::ENCAP_GRE`], [`bits::ENCAP_VXLAN`] and [`bits::ENCAP_MPLS`].
    pub kind: u128,
    pub src: Values,
    pub dst: Values,
    pub vni: Values,
    pub label: Values,
}

/// One header of a member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderDesc {
    /// The fields, in the order of [`HEADER_FIELDS`].
    pub fields: Vec<(HeaderField, Values)>,
    pub encap: Option<EncapDesc>,
}

impl HeaderDesc {
    pub fn get(&self, f: HeaderField) -> &Values {
        match self.fields.iter().find(|(g, _)| *g == f) {
            Some((_, v)) => v,
            None => unreachable!("a header description has each field"),
        }
    }
}

/// One member: a product of the values of the original request and of the
/// current header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub original: HeaderDesc,
    pub current: HeaderDesc,
}

/// The header fields in the order of the JSON form.
pub const HEADER_FIELDS: [HeaderField; 16] = [
    HeaderField::SrcMac,
    HeaderField::DstMac,
    HeaderField::Vlan,
    HeaderField::L2Priority,
    HeaderField::SrcIp,
    HeaderField::DstIp,
    HeaderField::Protocol,
    HeaderField::Dscp,
    HeaderField::Ecn,
    HeaderField::Fragment,
    HeaderField::SrcPort,
    HeaderField::DstPort,
    HeaderField::TcpFlags,
    HeaderField::IcmpType,
    HeaderField::IcmpCode,
    HeaderField::MplsTrafficClass,
];

/// The value fields in the order of the bit table.
const VALUE_FIELDS: [FieldBits; 20] = [
    bits::PROTOCOL,
    bits::DST_IP,
    bits::SRC_IP,
    bits::DST_PORT,
    bits::SRC_PORT,
    bits::TCP_FLAGS,
    bits::ICMP_TYPE,
    bits::ICMP_CODE,
    bits::DSCP,
    bits::ECN,
    bits::FRAGMENT,
    bits::VLAN,
    bits::L2_PRIORITY,
    bits::DST_MAC,
    bits::SRC_MAC,
    bits::MPLS_TC,
    bits::ENCAP_SRC,
    bits::ENCAP_DST,
    bits::ENCAP_VNI,
    bits::ENCAP_LABEL,
];

/// The flag bits: the presence bits, the unknown bits, the address family
/// and the encapsulation kind.
fn flag_bits() -> Vec<u32> {
    let mut v: Vec<u32> = (0..=bits::AF).collect();
    v.extend(bits::ENCAP_KIND.value_bits());
    v
}

impl PacketSet {
    /// The members of the set. An empty set has no member.
    pub fn describe(&self) -> Vec<Member> {
        let e = self.edge();
        self.arena()
            .run(|ops| describe_edge(ops, e))
            .unwrap_or_default()
    }
}

fn describe_edge(ops: &mut Ops<'_>, s: Edge) -> Result<Vec<Member>, DdError> {
    let flags = flag_bits();
    let mut flag_levels = Vec::new();
    for &b in &flags {
        flag_levels.push(level(b, Bank::Original));
        flag_levels.push(level(b, Bank::Current));
    }
    let flag_cube = ops.dd.cube(&flag_levels)?;
    let mut out = Vec::new();
    let mut rest = s;
    while rest != Edge::FALSE {
        let Some(path) = ops.dd.pick_one(rest)? else {
            break;
        };
        let value = |l: u32| path.iter().find(|(x, _)| *x == l).is_some_and(|(_, v)| *v);
        let lits: Vec<(u32, bool)> = flag_levels.iter().map(|&l| (l, value(l))).collect();
        let a = ops.dd.literals(&lits)?;
        let part = ops.dd.and(rest, a)?;
        rest = ops.dd.diff(rest, part)?;
        let r = ops.dd.exists(part, flag_cube)?;
        let flag = |b: u32, bank: Bank| value(level(b, bank));
        for row in decompose(ops, r, 0)? {
            out.push(Member {
                original: header(&row, Bank::Original, &flag),
                current: header(&row, Bank::Current, &flag),
            });
        }
    }
    Ok(out)
}

/// The values of each value field for one bank, with the flags.
fn header(row: &[(Values, Values)], bank: Bank, flag: &dyn Fn(u32, Bank) -> bool) -> HeaderDesc {
    let pick = |f: FieldBits| -> Values {
        if let Some(p) = f.presence
            && !flag(p, bank)
        {
            return Values::Absent;
        }
        if let Some(u) = f.unknown
            && flag(u, bank)
        {
            return Values::Unknown;
        }
        let i = VALUE_FIELDS
            .iter()
            .position(|g| *g == f)
            .unwrap_or_else(|| unreachable!("a value field is in the list"));
        let (o, c) = &row[i];
        let v = if bank == Bank::Original { o } else { c };
        match (v, f == bits::SRC_IP || f == bits::DST_IP) {
            (Values::Ranges(rs), true) => Values::Prefixes(prefixes(rs, flag(bits::AF, bank))),
            _ => v.clone(),
        }
    };
    let fields = HEADER_FIELDS
        .iter()
        .map(|f| (*f, pick(bits::field_bits(*f))))
        .collect();
    let kind = u128::from(flag(bits::ENCAP_KIND.start, bank)) << 1
        | u128::from(flag(bits::ENCAP_KIND.start + 1, bank));
    let encap = (kind != bits::ENCAP_NONE).then(|| EncapDesc {
        kind,
        src: pick(bits::ENCAP_SRC),
        dst: pick(bits::ENCAP_DST),
        vni: pick(bits::ENCAP_VNI),
        label: pick(bits::ENCAP_LABEL),
    });
    HeaderDesc { fields, encap }
}

/// The aligned intervals of an address field as prefixes. An IPv4 address
/// uses the low 32 bits.
fn prefixes(rs: &[(u128, u128)], v6: bool) -> Vec<Prefix> {
    let mut out = Vec::new();
    for &(lo, hi) in rs {
        // The walk gives aligned intervals before the merge, so split each
        // range into aligned blocks again.
        let mut x = lo;
        loop {
            let fits = |size: u32| {
                if size >= 128 {
                    x == 0 && hi == u128::MAX
                } else {
                    x + ((1u128 << size) - 1) <= hi
                }
            };
            let mut size = if x == 0 { 128 } else { x.trailing_zeros() };
            while size > 0 && !fits(size) {
                size -= 1;
            }
            let len = 128 - size;
            let len = if v6 { len } else { len.saturating_sub(96) };
            out.push(Prefix::new(bits::bits_ip(v6, x), len as u8));
            let end = if size >= 128 {
                u128::MAX
            } else {
                x + ((1u128 << size) - 1)
            };
            if end >= hi {
                break;
            }
            x = end + 1;
        }
    }
    out
}

/// The rows of the value fields from field `i` on: for each field, the
/// values of the original request and of the current header.
fn decompose(ops: &mut Ops<'_>, r: Edge, i: usize) -> Result<Vec<Vec<(Values, Values)>>, DdError> {
    if i == VALUE_FIELDS.len() {
        return Ok(vec![Vec::new()]);
    }
    let f = VALUE_FIELDS[i];
    let mut f_levels = Vec::new();
    for b in f.value_bits() {
        f_levels.push(level(b, Bank::Original));
        f_levels.push(level(b, Bank::Current));
    }
    let mut rest_levels = Vec::new();
    for g in &VALUE_FIELDS[i + 1..] {
        for b in g.value_bits() {
            rest_levels.push(level(b, Bank::Original));
            rest_levels.push(level(b, Bank::Current));
        }
    }
    let cube_f = ops.dd.cube(&f_levels)?;
    let cube_rest = ops.dd.cube(&rest_levels)?;
    let mut out = Vec::new();
    let mut rem = r;
    while rem != Edge::FALSE {
        let Some(path) = ops.dd.pick_one(rem)? else {
            break;
        };
        let lits: Vec<(u32, bool)> = f_levels
            .iter()
            .map(|&l| (l, path.iter().any(|&(x, v)| x == l && v)))
            .collect();
        let v0 = ops.dd.literals(&lits)?;
        let at = ops.dd.and(rem, v0)?;
        let residual = ops.dd.exists(at, cube_f)?;
        let d = ops.dd.xor(rem, residual)?;
        let bad = ops.dd.exists(d, cube_rest)?;
        let proj = ops.dd.exists(rem, cube_rest)?;
        let group = ops.dd.diff(proj, bad)?;
        rem = ops.dd.diff(rem, group)?;
        let tails = decompose(ops, residual, i + 1)?;
        for (o, c) in field_values(ops, group, f)? {
            for t in &tails {
                let mut row = vec![(o.clone(), c.clone())];
                row.extend(t.iter().cloned());
                out.push(row);
            }
        }
    }
    Ok(out)
}

/// The values of a field relation `g` over the original and the current
/// bits of `f`: one product, the relation "current equals original", or
/// more products.
fn field_values(
    ops: &mut Ops<'_>,
    g: Edge,
    f: FieldBits,
) -> Result<Vec<(Values, Values)>, DdError> {
    let bits: Vec<u32> = f.value_bits().collect();
    let orig: Vec<u32> = bits.iter().map(|&b| level(b, Bank::Original)).collect();
    let cur: Vec<u32> = bits.iter().map(|&b| level(b, Bank::Current)).collect();
    let co = ops.dd.cube(&orig)?;
    let cc = ops.dd.cube(&cur)?;
    let o = ops.dd.exists(g, cc)?;
    let c = ops.dd.exists(g, co)?;
    let product = ops.dd.and(o, c)?;
    let c_vals = ranges(ops, c, f, Bank::Current)?;
    let single_c = matches!(&c_vals, Values::Ranges(r) if r.len() == 1 && r[0].0 == r[0].1);
    if product == g && single_c {
        return Ok(vec![(ranges(ops, o, f, Bank::Original)?, c_vals)]);
    }
    let mut eq = Edge::TRUE;
    {
        let mut b = ops.builder();
        for &x in bits.iter().rev() {
            eq = b.eq_bit(x, Bank::Original, Bank::Current, eq)?;
        }
    }
    let same = ops.dd.and(o, eq)?;
    if same == g {
        return Ok(vec![(ranges(ops, o, f, Bank::Original)?, Values::Original)]);
    }
    if product == g {
        return Ok(vec![(ranges(ops, o, f, Bank::Original)?, c_vals)]);
    }
    // Group the original values by the set of their current values.
    let mut out = Vec::new();
    let mut rem = g;
    while rem != Edge::FALSE {
        let Some(path) = ops.dd.pick_one(rem)? else {
            break;
        };
        let lits: Vec<(u32, bool)> = orig
            .iter()
            .map(|&l| (l, path.iter().any(|&(x, v)| x == l && v)))
            .collect();
        let o0 = ops.dd.literals(&lits)?;
        let at = ops.dd.and(rem, o0)?;
        let c0 = ops.dd.exists(at, co)?;
        let d = ops.dd.xor(rem, c0)?;
        let bad = ops.dd.exists(d, cc)?;
        let proj = ops.dd.exists(rem, cc)?;
        let group = ops.dd.diff(proj, bad)?;
        rem = ops.dd.diff(rem, group)?;
        out.push((
            ranges(ops, group, f, Bank::Original)?,
            ranges(ops, c0, f, Bank::Current)?,
        ));
    }
    Ok(out)
}

/// The values of a function of the bits of `f` in `bank` as ranges.
fn ranges(ops: &mut Ops<'_>, e: Edge, f: FieldBits, bank: Bank) -> Result<Values, DdError> {
    let mut out: Vec<(u128, u128)> = Vec::new();
    // (edge, depth, prefix value)
    let mut stack = vec![(e, 0u32, 0u128)];
    while let Some((e, depth, p)) = stack.pop() {
        if e == Edge::FALSE {
            continue;
        }
        let left = f.width - depth;
        if e == Edge::TRUE {
            let lo = if left >= 128 { 0 } else { p << left };
            let hi = if left >= 128 {
                u128::MAX
            } else {
                lo | ((1u128 << left) - 1)
            };
            out.push((lo, hi));
            continue;
        }
        if depth == f.width {
            return Err(DdError::InvariantBroken(
                "a field value set reads a level outside its field".to_string(),
            ));
        }
        let l = level(f.start + depth, bank);
        let (lo, hi) = match ops.dd.branch(e)? {
            Some((top, lo, hi)) if top == l => (lo, hi),
            Some((top, _, _)) if top > l => (e, e),
            _ => {
                return Err(DdError::InvariantBroken(
                    "a field value set reads a level outside its field".to_string(),
                ));
            }
        };
        // The 1 child first on the stack, so the 0 child comes out first.
        stack.push((hi, depth + 1, p << 1 | 1));
        stack.push((lo, depth + 1, p << 1));
    }
    let mut merged: Vec<(u128, u128)> = Vec::new();
    for (lo, hi) in out {
        match merged.last_mut() {
            Some(last) if last.1 != u128::MAX && last.1 + 1 == lo => last.1 = hi,
            _ => merged.push((lo, hi)),
        }
    }
    Ok(Values::Ranges(merged))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldValue;
    use crate::header::{Header, PROTO_TCP};
    use crate::packet_set::Rewrite;
    use crate::set::SetArena;

    /// An untagged TCP request.
    fn h() -> Header {
        let mut h = Header::request(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            PROTO_TCP,
        )
        .with_src_port(40000)
        .with_dst_port(22);
        h.vlan = FieldValue::Absent;
        h.l2_priority = FieldValue::Absent;
        h
    }

    #[test]
    fn a_request_has_one_member_with_its_stated_values() {
        let a = SetArena::standalone();
        let mut req = h();
        req.vlan = FieldValue::Unstated;
        req.l2_priority = FieldValue::Unstated;
        // A VLAN tag that the request does not state can be absent.
        let m = PacketSet::single(&a, &req).describe();
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].original.get(HeaderField::Vlan), &Values::Absent);
        assert_eq!(
            m[1].original.get(HeaderField::Vlan),
            &Values::Ranges(vec![(0, 4095)])
        );
        assert_eq!(m[1].current.get(HeaderField::L2Priority), &Values::Original);
        let m = PacketSet::single(&a, &h()).describe();
        assert_eq!(m.len(), 1);
        let o = &m[0].original;
        let c = &m[0].current;
        assert_eq!(
            o.get(HeaderField::SrcIp),
            &Values::Prefixes(vec!["10.0.0.1/32".parse().unwrap()])
        );
        assert_eq!(c.get(HeaderField::DstPort).single(), Some(22));
        assert_eq!(o.get(HeaderField::IcmpType), &Values::Absent);
        // A field that the request does not state has all values, and the
        // current header keeps the value of the original request.
        assert_eq!(o.get(HeaderField::Dscp), &Values::Ranges(vec![(0, 63)]));
        assert_eq!(c.get(HeaderField::Dscp), &Values::Original);
        assert_eq!(c.get(HeaderField::TcpFlags), &Values::Original);
        assert!(o.encap.is_none());
    }

    #[test]
    fn a_rewrite_shows_in_the_current_header() {
        let a = SetArena::standalone();
        let s = PacketSet::single(&a, &h()).rewrite(&Rewrite {
            src_ip: Some(FieldValue::Known("192.0.2.1".parse().unwrap())),
            src_port: Some(FieldValue::Unknown),
            ..Rewrite::default()
        });
        let m = s.describe();
        assert_eq!(m.len(), 1);
        assert_eq!(
            m[0].current.get(HeaderField::SrcIp),
            &Values::Prefixes(vec!["192.0.2.1/32".parse().unwrap()])
        );
        assert_eq!(m[0].current.get(HeaderField::SrcPort), &Values::Unknown);
        assert_eq!(
            m[0].original.get(HeaderField::SrcPort).single(),
            Some(40000)
        );
    }

    #[test]
    fn a_union_of_two_requests_has_two_members_in_bit_order() {
        let a = SetArena::standalone();
        let x = PacketSet::single(&a, &h().with_dst_port(80));
        let y = PacketSet::single(&a, &h());
        let m = x.union(&y).describe();
        // The source port joins the 2 requests into 1 member with 2 values of
        // the destination port.
        assert_eq!(m.len(), 1);
        assert_eq!(
            m[0].original.get(HeaderField::DstPort),
            &Values::Ranges(vec![(22, 22), (80, 80)])
        );
        let z = PacketSet::single(&a, &h().with_src_port(1).with_dst_port(80));
        let m = y.union(&z).describe();
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].original.get(HeaderField::DstPort).single(), Some(22));
        assert_eq!(m[1].original.get(HeaderField::DstPort).single(), Some(80));
    }
}
