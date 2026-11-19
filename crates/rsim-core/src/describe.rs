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
    /// In the current header or the inner header: the value of the same
    /// field of the original request.
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
    /// One of [`bits::ENCAP_GRE`], [`bits::ENCAP_VXLAN`], [`bits::ENCAP_MPLS`]
    /// and [`bits::ENCAP_WIREGUARD`].
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
    /// The inner header of an encapsulated current header.
    pub inner: Option<Box<HeaderDesc>>,
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

/// The values of one value field in one member: the original request, the
/// current header and, for an encapsulated member, the inner header.
type Cell = (Values, Values, Option<Values>);

/// The flag bits: the presence bits, the unknown bits, the address family
/// and the encapsulation kind.
fn flag_bits() -> Vec<u32> {
    let mut v: Vec<u32> = (0..=bits::AF).collect();
    v.extend(bits::ENCAP_KIND.value_bits());
    v
}

/// True if the inner level of field `f` holds a field of the inner header.
fn has_inner(f: FieldBits) -> bool {
    bits::header_bits().contains(&f.start)
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
    let mut plain_levels = Vec::new();
    for &b in &flags {
        plain_levels.push(level(b, Bank::Original));
        plain_levels.push(level(b, Bank::Current));
    }
    // An encapsulated member has the flags of its inner header too.
    let mut encap_levels = plain_levels.clone();
    encap_levels.extend((0..=bits::AF).map(|b| level(b, Bank::Inner)));
    let plain_cube = ops.dd.cube(&plain_levels)?;
    let encap_cube = ops.dd.cube(&encap_levels)?;
    let mut out = Vec::new();
    let mut rest = s;
    while rest != Edge::FALSE {
        let Some(path) = ops.dd.pick_one(rest)? else {
            break;
        };
        let value = |l: u32| path.iter().find(|(x, _)| *x == l).is_some_and(|(_, v)| *v);
        let flag = |b: u32, bank: Bank| value(level(b, bank));
        let inner = encap_kind(&flag, Bank::Current) != bits::ENCAP_NONE;
        let (flag_levels, flag_cube) = if inner {
            (&encap_levels, encap_cube)
        } else {
            (&plain_levels, plain_cube)
        };
        let lits: Vec<(u32, bool)> = flag_levels.iter().map(|&l| (l, value(l))).collect();
        let a = ops.dd.literals(&lits)?;
        let part = ops.dd.and(rest, a)?;
        rest = ops.dd.diff(rest, part)?;
        let r = ops.dd.exists(part, flag_cube)?;
        for row in decompose(ops, r, 0, inner)? {
            let mut current = header(&row, Bank::Current, &flag);
            if inner {
                current.inner = Some(Box::new(header(&row, Bank::Inner, &flag)));
            }
            out.push(Member {
                original: header(&row, Bank::Original, &flag),
                current,
            });
        }
    }
    Ok(out)
}

/// The encapsulation kind of `bank` from the flags.
fn encap_kind(flag: &dyn Fn(u32, Bank) -> bool, bank: Bank) -> u128 {
    bits::ENCAP_KIND
        .value_bits()
        .fold(0, |k, b| k << 1 | u128::from(flag(b, bank)))
}

/// The values of each value field for one bank, with the flags.
fn header(row: &[Cell], bank: Bank, flag: &dyn Fn(u32, Bank) -> bool) -> HeaderDesc {
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
        let (o, c, inner) = &row[i];
        let v = match bank {
            Bank::Original => o,
            Bank::Current => c,
            Bank::Inner | Bank::Work => inner
                .as_ref()
                .unwrap_or_else(|| unreachable!("an encapsulated member has the inner values")),
        };
        match (v, f == bits::SRC_IP || f == bits::DST_IP) {
            (Values::Ranges(rs), true) => Values::Prefixes(prefixes(rs, flag(bits::AF, bank))),
            _ => v.clone(),
        }
    };
    let fields = HEADER_FIELDS
        .iter()
        .map(|f| (*f, pick(bits::field_bits(*f))))
        .collect();
    // The inner header has no encapsulation.
    let kind = match bank {
        Bank::Inner => bits::ENCAP_NONE,
        _ => encap_kind(flag, bank),
    };
    let encap = (kind != bits::ENCAP_NONE).then(|| EncapDesc {
        kind,
        src: pick(bits::ENCAP_SRC),
        dst: pick(bits::ENCAP_DST),
        vni: pick(bits::ENCAP_VNI),
        label: pick(bits::ENCAP_LABEL),
    });
    HeaderDesc {
        fields,
        encap,
        inner: None,
    }
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

/// The levels of the value bits of `f`: the original request, the current
/// header and, if `inner` and the field has an inner level, the inner header.
fn value_levels(f: FieldBits, inner: bool) -> Vec<u32> {
    let mut v = Vec::new();
    for b in f.value_bits() {
        v.push(level(b, Bank::Original));
        v.push(level(b, Bank::Current));
        if inner && has_inner(f) {
            v.push(level(b, Bank::Inner));
        }
    }
    v
}

/// The rows of the value fields from field `i` on: for each field, the
/// values of the original request, of the current header and, if `inner`,
/// of the inner header.
fn decompose(ops: &mut Ops<'_>, r: Edge, i: usize, inner: bool) -> Result<Vec<Vec<Cell>>, DdError> {
    if i == VALUE_FIELDS.len() {
        return Ok(vec![Vec::new()]);
    }
    let f = VALUE_FIELDS[i];
    let f_levels = value_levels(f, inner);
    let rest_levels: Vec<u32> = VALUE_FIELDS[i + 1..]
        .iter()
        .flat_map(|g| value_levels(*g, inner))
        .collect();
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
        let tails = decompose(ops, residual, i + 1, inner)?;
        for cell in field_values(ops, group, f, inner && has_inner(f))? {
            for t in &tails {
                let mut row = vec![cell.clone()];
                row.extend(t.iter().cloned());
                out.push(row);
            }
        }
    }
    Ok(out)
}

/// The values of a field relation `g` over the original and the current
/// bits of `f`, and the inner bits if `inner`: one product, with the
/// relation "equals the original request" for the current or the inner
/// header, or more products.
fn field_values(
    ops: &mut Ops<'_>,
    g: Edge,
    f: FieldBits,
    inner: bool,
) -> Result<Vec<Cell>, DdError> {
    if inner {
        return field_values_inner(ops, g, f);
    }
    let bits: Vec<u32> = f.value_bits().collect();
    let orig: Vec<u32> = bits.iter().map(|&b| level(b, Bank::Original)).collect();
    let cur: Vec<u32> = bits.iter().map(|&b| level(b, Bank::Current)).collect();
    let co = ops.dd.cube(&orig)?;
    let cc = ops.dd.cube(&cur)?;
    let o = ops.dd.exists(g, cc)?;
    let c = ops.dd.exists(g, co)?;
    let product = ops.dd.and(o, c)?;
    let c_vals = ranges(ops, c, f, Bank::Current)?;
    if product == g && c_vals.single().is_some() {
        return Ok(vec![(ranges(ops, o, f, Bank::Original)?, c_vals, None)]);
    }
    let eq = eq_original(ops, f, Bank::Current)?;
    let same = ops.dd.and(o, eq)?;
    if same == g {
        return Ok(vec![(
            ranges(ops, o, f, Bank::Original)?,
            Values::Original,
            None,
        )]);
    }
    if product == g {
        return Ok(vec![(ranges(ops, o, f, Bank::Original)?, c_vals, None)]);
    }
    // Group the original values by the set of their current values.
    let mut out = Vec::new();
    for (og, c0) in group_by(ops, g, &orig, co, cc)? {
        out.push((
            ranges(ops, og, f, Bank::Original)?,
            ranges(ops, c0, f, Bank::Current)?,
            None,
        ));
    }
    Ok(out)
}

/// [`field_values`] with the inner bits.
fn field_values_inner(ops: &mut Ops<'_>, g: Edge, f: FieldBits) -> Result<Vec<Cell>, DdError> {
    let bits: Vec<u32> = f.value_bits().collect();
    let orig: Vec<u32> = bits.iter().map(|&b| level(b, Bank::Original)).collect();
    let cur: Vec<u32> = bits.iter().map(|&b| level(b, Bank::Current)).collect();
    let inn: Vec<u32> = bits.iter().map(|&b| level(b, Bank::Inner)).collect();
    let co = ops.dd.cube(&orig)?;
    let cc = ops.dd.cube(&cur)?;
    let ci = ops.dd.cube(&inn)?;
    let cci = ops.dd.and(cc, ci)?;
    let coi = ops.dd.and(co, ci)?;
    let coc = ops.dd.and(co, cc)?;
    let o = ops.dd.exists(g, cci)?;
    let c = ops.dd.exists(g, coi)?;
    let i = ops.dd.exists(g, coc)?;
    let mut forms = Vec::new();
    for (e, bank) in [(c, Bank::Current), (i, Bank::Inner)] {
        let vals = ranges(ops, e, f, bank)?;
        let eq = eq_original(ops, f, bank)?;
        // A single value first, then the original value, then a product.
        forms.push(if vals.single().is_some() {
            [(vals, e), (Values::Original, eq)]
        } else {
            [(Values::Original, eq), (vals, e)]
        });
    }
    for (cv, ce) in &forms[0] {
        for (iv, ie) in &forms[1] {
            let r = ops.dd.and(o, *ce)?;
            let r = ops.dd.and(r, *ie)?;
            if r == g {
                return Ok(vec![(
                    ranges(ops, o, f, Bank::Original)?,
                    cv.clone(),
                    Some(iv.clone()),
                )]);
            }
        }
    }
    // Group the original values by the relation of their current and inner
    // values, and then the current values by the set of their inner values.
    let mut out = Vec::new();
    for (og, r0) in group_by(ops, g, &orig, co, cci)? {
        let ov = ranges(ops, og, f, Bank::Original)?;
        for (cg, i0) in group_by(ops, r0, &cur, cc, ci)? {
            out.push((
                ov.clone(),
                ranges(ops, cg, f, Bank::Current)?,
                Some(ranges(ops, i0, f, Bank::Inner)?),
            ));
        }
    }
    Ok(out)
}

/// The relation "the bits of `f` in `bank` equal the original request".
fn eq_original(ops: &mut Ops<'_>, f: FieldBits, bank: Bank) -> Result<Edge, DdError> {
    let mut eq = Edge::TRUE;
    let mut b = ops.builder();
    for x in f.value_bits().rev() {
        eq = b.eq_bit(x, Bank::Original, bank, eq)?;
    }
    Ok(eq)
}

/// The groups of a relation `rel` over the levels `a` (with the cube `ca`)
/// and the levels of the cube `cb`: each group is a set of values of `a`
/// with the same set of values of `cb`, and that set.
fn group_by(
    ops: &mut Ops<'_>,
    rel: Edge,
    a: &[u32],
    ca: Edge,
    cb: Edge,
) -> Result<Vec<(Edge, Edge)>, DdError> {
    let mut out = Vec::new();
    let mut rem = rel;
    while rem != Edge::FALSE {
        let Some(path) = ops.dd.pick_one(rem)? else {
            break;
        };
        let lits: Vec<(u32, bool)> = a
            .iter()
            .map(|&l| (l, path.iter().any(|&(x, v)| x == l && v)))
            .collect();
        let a0 = ops.dd.literals(&lits)?;
        let at = ops.dd.and(rem, a0)?;
        let b0 = ops.dd.exists(at, ca)?;
        let d = ops.dd.xor(rem, b0)?;
        let bad = ops.dd.exists(d, cb)?;
        let proj = ops.dd.exists(rem, cb)?;
        let group = ops.dd.diff(proj, bad)?;
        rem = ops.dd.diff(rem, group)?;
        out.push((group, b0));
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
    fn an_encapsulated_request_has_the_original_request_as_its_inner_header() {
        use crate::header::{Encap, PROTO_UDP};
        let a = SetArena::standalone();
        let vtep = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        let mut o = Header::request(vtep("198.51.100.1"), vtep("198.51.100.2"), PROTO_UDP)
            .with_src_port(49152)
            .with_dst_port(4789);
        o.dscp = FieldValue::Known(0);
        o.ecn = FieldValue::Known(0);
        o.src_mac = FieldValue::Unknown;
        o.dst_mac = FieldValue::Unknown;
        o.vlan = FieldValue::Absent;
        o.l2_priority = FieldValue::Absent;
        o.encap = vec![Encap::Vxlan {
            src: vtep("198.51.100.1"),
            dst: vtep("198.51.100.2"),
            vni: 10010,
        }];
        let mut req = h();
        req.dscp = FieldValue::Known(46);
        let m = PacketSet::single(&a, &req).encapsulate(&o).done.describe();
        assert_eq!(m.len(), 1);
        let c = &m[0].current;
        assert_eq!(c.get(HeaderField::DstPort).single(), Some(4789));
        assert_eq!(
            c.get(HeaderField::DstIp),
            &Values::Prefixes(vec!["198.51.100.2/32".parse().unwrap()])
        );
        let e = c.encap.as_ref().unwrap();
        assert_eq!(e.kind, bits::ENCAP_VXLAN);
        assert_eq!(e.vni.single(), Some(10010));
        let i = c.inner.as_deref().unwrap();
        // The inner header is the original request: each field has the
        // original value, and a single value shows as that value.
        assert_eq!(i.get(HeaderField::DstPort).single(), Some(22));
        assert_eq!(i.get(HeaderField::Dscp).single(), Some(46));
        assert_eq!(i.get(HeaderField::SrcMac), &Values::Original);
        assert!(i.encap.is_none() && i.inner.is_none());
        assert!(m[0].original.inner.is_none());
        // A request with unstated fields: the inner header keeps the
        // relation to the original request.
        let m = PacketSet::single(&a, &h()).encapsulate(&o).done.describe();
        assert_eq!(m.len(), 1);
        let i = m[0].current.inner.as_deref().unwrap();
        assert_eq!(i.get(HeaderField::Dscp), &Values::Original);
        assert_eq!(
            m[0].original.get(HeaderField::Dscp),
            &Values::Ranges(vec![(0, 63)])
        );
    }

    #[test]
    fn an_inner_header_that_is_not_a_product_gives_a_member_for_each_group() {
        use crate::header::{Encap, PROTO_UDP};
        let a = SetArena::standalone();
        let vtep = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        let mut o = Header::request(vtep("198.51.100.1"), vtep("198.51.100.2"), PROTO_UDP)
            .with_src_port(49152)
            .with_dst_port(4789);
        o.dscp = FieldValue::Known(0);
        o.ecn = FieldValue::Known(0);
        o.src_mac = FieldValue::Unknown;
        o.dst_mac = FieldValue::Unknown;
        o.vlan = FieldValue::Absent;
        o.l2_priority = FieldValue::Absent;
        o.encap = vec![Encap::Gre {
            src: vtep("198.51.100.1"),
            dst: vtep("198.51.100.2"),
        }];
        // Port 22 goes to port 80 and port 23 goes to port 81: the inner
        // ports are not a product with the original ports.
        let to = |from: u16, to: u16| {
            PacketSet::single(&a, &h().with_dst_port(from)).rewrite(&Rewrite {
                dst_port: Some(FieldValue::Known(to)),
                ..Rewrite::default()
            })
        };
        let s = to(22, 80).union(&to(23, 81)).encapsulate(&o).done;
        let m = s.describe();
        assert_eq!(m.len(), 2);
        for (member, (from, to)) in m.iter().zip([(22, 80), (23, 81)]) {
            assert_eq!(
                member.original.get(HeaderField::DstPort).single(),
                Some(from)
            );
            assert_eq!(
                member.current.get(HeaderField::DstPort).single(),
                Some(4789)
            );
            let i = member.current.inner.as_deref().unwrap();
            assert_eq!(i.get(HeaderField::DstPort).single(), Some(to));
        }
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
