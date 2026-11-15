//! The packet set.
//!
//! A packet set is a region of header space. It holds pairs of the original
//! request header and the current header. The representation is a decision
//! diagram in the arena of its query. Functions use only the operations of
//! this interface. A field with no constraint has all values.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use rsim_dd::{DdError, Edge};

use crate::addr::{Mac, Prefix};
use crate::bits::{self, Bank, FieldBits, level};
use crate::field::FieldValue;
use crate::header::{Header, HeaderField, PROTO_ICMP, PROTO_ICMPV6};
use crate::predicate::RulePredicate;
use crate::prefix_table::PrefixTable;
use crate::set::{Builder, MapKind, Ops, SetArena, prefix_lits};

const MEMO_ORIGINAL: u8 = 0;
const MEMO_DSCP: u8 = 1;
const MEMO_ECN: u8 = 2;

/// One member of a packet set: the original request header and the current header.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PacketPair {
    pub original: Header,
    pub current: Header,
}

/// A set of packet pairs in the arena of one query. Two sets of one query
/// with the same members have the same edge.
#[derive(Clone)]
pub struct PacketSet {
    arena: Arc<SetArena>,
    edge: Edge,
}

impl PartialEq for PacketSet {
    fn eq(&self, other: &Self) -> bool {
        self.edge == other.edge && Arc::ptr_eq(&self.arena, &other.arena)
    }
}

impl Eq for PacketSet {}

impl PartialOrd for PacketSet {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The order is by edge, and then by arena. Only membership tests of the
/// executor use it. No output order depends on it.
impl Ord for PacketSet {
    fn cmp(&self, other: &Self) -> Ordering {
        self.edge.cmp(&other.edge).then_with(|| {
            (Arc::as_ptr(&self.arena) as usize).cmp(&(Arc::as_ptr(&other.arena) as usize))
        })
    }
}

impl Hash for PacketSet {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.edge.hash(state);
    }
}

impl fmt::Debug for PacketSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.witness() {
            None => write!(f, "PacketSet(empty)"),
            Some(w) => write!(f, "PacketSet({:?} {:?}, ...)", self.edge, w.current),
        }
    }
}

/// The result of a split by a predicate with match bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Split {
    /// Packets in the definite match set `M-`.
    pub matched: PacketSet,
    /// Packets in `M+` and not in `M-`.
    pub uncertain: PacketSet,
    /// Packets not in `M+`.
    pub unmatched: PacketSet,
}

/// Which address field a prefix partition reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddrField {
    Src,
    Dst,
}

/// The result of a partition by a prefix table with longest-prefix match.
#[derive(Debug)]
pub struct PrefixPartition<'t, V> {
    /// For each matched prefix, in prefix order: the value and the packets.
    pub matched: Vec<(Prefix, &'t V, PacketSet)>,
    /// Packets with a known address that no prefix contains.
    pub unmatched: PacketSet,
    /// Packets where the address is unknown.
    pub uncertain: PacketSet,
}

/// A rewrite of the current header. `None` leaves a field as it is.
/// A rewrite never changes the original request header.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rewrite {
    pub src_ip: Option<FieldValue<std::net::IpAddr>>,
    pub dst_ip: Option<FieldValue<std::net::IpAddr>>,
    pub src_port: Option<FieldValue<u16>>,
    pub dst_port: Option<FieldValue<u16>>,
    pub dscp: Option<FieldValue<u8>>,
    pub ecn: Option<FieldValue<u8>>,
    pub src_mac: Option<FieldValue<Mac>>,
    pub dst_mac: Option<FieldValue<Mac>>,
    pub vlan: Option<FieldValue<u16>>,
    pub l2_priority: Option<FieldValue<u8>>,
    pub mpls_tc: Option<FieldValue<u8>>,
}

impl Rewrite {
    pub fn is_identity(&self) -> bool {
        *self == Rewrite::default()
    }

    /// The rewrite of one header. A rewrite does not create a header that
    /// is absent.
    pub fn apply_to(&self, h: &mut Header) {
        fn set<T: Copy>(slot: &mut FieldValue<T>, v: Option<FieldValue<T>>) {
            if let Some(v) = v
                && slot.is_present()
            {
                *slot = v;
            }
        }
        set(&mut h.src_ip, self.src_ip);
        set(&mut h.dst_ip, self.dst_ip);
        set(&mut h.src_port, self.src_port);
        set(&mut h.dst_port, self.dst_port);
        set(&mut h.dscp, self.dscp);
        set(&mut h.ecn, self.ecn);
        set(&mut h.src_mac, self.src_mac);
        set(&mut h.dst_mac, self.dst_mac);
        set(&mut h.vlan, self.vlan);
        set(&mut h.l2_priority, self.l2_priority);
        set(&mut h.mpls_tc, self.mpls_tc);
    }

    /// The fields of the rewrite with their bits and their new values.
    fn fields(&self) -> Vec<(FieldBits, FieldValue<u128>)> {
        let ip = |v: FieldValue<std::net::IpAddr>| v.map(bits::ip_bits);
        let n = |v: FieldValue<u16>| v.map(u128::from);
        let b = |v: FieldValue<u8>| v.map(u128::from);
        let m = |v: FieldValue<Mac>| v.map(bits::mac_bits);
        let mut out = Vec::new();
        let mut push = |f: FieldBits, v: Option<FieldValue<u128>>| {
            if let Some(v) = v {
                out.push((f, v));
            }
        };
        push(bits::SRC_IP, self.src_ip.map(ip));
        push(bits::DST_IP, self.dst_ip.map(ip));
        push(bits::SRC_PORT, self.src_port.map(n));
        push(bits::DST_PORT, self.dst_port.map(n));
        push(bits::DSCP, self.dscp.map(b));
        push(bits::ECN, self.ecn.map(b));
        push(bits::SRC_MAC, self.src_mac.map(m));
        push(bits::DST_MAC, self.dst_mac.map(m));
        push(bits::VLAN, self.vlan.map(n));
        push(bits::L2_PRIORITY, self.l2_priority.map(b));
        push(bits::MPLS_TC, self.mpls_tc.map(b));
        out
    }
}

/// A QoS header field over the members of a set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Uniform<T> {
    Value(T),
    /// The members of the set have different values.
    Varies,
    /// The set is empty.
    None,
}

/// A binary trie of prefixes of one address family, for the prefix
/// partition of a set.
struct Trie {
    nodes: Vec<TrieNode>,
}

#[derive(Clone, Copy)]
struct TrieNode {
    child: [Option<usize>; 2],
    /// The index of the prefix in the list that built the trie.
    entry: Option<usize>,
}

impl Trie {
    fn new(prefixes: impl Iterator<Item = Prefix>) -> Trie {
        let mut nodes = vec![TrieNode {
            child: [None, None],
            entry: None,
        }];
        for (i, p) in prefixes.enumerate() {
            let mut n = 0;
            for d in 0..p.len() {
                let b = usize::from(p.bit(d));
                n = match nodes[n].child[b] {
                    Some(c) => c,
                    None => {
                        nodes.push(TrieNode {
                            child: [None, None],
                            entry: None,
                        });
                        let c = nodes.len() - 1;
                        nodes[n].child[b] = Some(c);
                        c
                    }
                };
            }
            nodes[n].entry = Some(i);
        }
        Trie { nodes }
    }
}

/// The direction of a session lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SessionDirection {
    /// The packets of the flow that created the session.
    Forward,
    /// The packets of the reply flow.
    Reply,
}

/// The result of a session lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSplit {
    /// The packets that match the session, translated by its binding.
    pub matched: PacketSet,
    /// The packets that can match the session: an unknown port against a
    /// known port.
    pub uncertain: PacketSet,
    /// The packets whose flow has more than one binding in the session.
    /// Headers cannot decide which binding applies.
    pub ambiguous: PacketSet,
    /// The packets that do not match the session.
    pub unmatched: PacketSet,
}

impl PacketSet {
    fn with(&self, edge: Edge) -> PacketSet {
        PacketSet {
            arena: Arc::clone(&self.arena),
            edge,
        }
    }

    /// The arena of the query of this set.
    pub fn arena(&self) -> &Arc<SetArena> {
        &self.arena
    }

    /// Runs `f` on the arena of this set and the edges of `others`. Sets of
    /// another query are a fault.
    fn run<R>(
        &self,
        others: &[&PacketSet],
        f: impl FnOnce(&mut Ops<'_>) -> Result<R, DdError>,
    ) -> Option<R> {
        if others.iter().any(|o| !Arc::ptr_eq(&o.arena, &self.arena)) {
            self.arena.record(DdError::InvariantBroken(
                "an operation on packet sets of two queries".to_string(),
            ));
            return None;
        }
        self.arena.run(f)
    }

    fn op(
        &self,
        others: &[&PacketSet],
        f: impl FnOnce(&mut Ops<'_>) -> Result<Edge, DdError>,
    ) -> PacketSet {
        let e = self.run(others, f).unwrap_or(Edge::FALSE);
        self.with(e)
    }

    /// The empty set of the same query.
    pub fn empty(&self) -> PacketSet {
        self.with(Edge::FALSE)
    }

    /// The set of one request: the original request is the header itself.
    /// A field that the header does not state has all values, with the
    /// same value in the original request and the current header.
    pub fn single(arena: &Arc<SetArena>, h: &Header) -> PacketSet {
        let enc = bits::encode(h);
        let e = arena
            .run(|ops| {
                let mut b = ops.builder();
                let mut acc = Edge::TRUE;
                for x in (0..bits::BITS).rev() {
                    acc = match enc[x as usize] {
                        Some(v) => {
                            b.dd.literals(&[
                                (level(x, Bank::Original), v),
                                (level(x, Bank::Current), v),
                            ])
                            .and_then(|l| b.dd.and(l, acc))?
                        }
                        None => b.eq_bit(x, Bank::Original, Bank::Current, acc)?,
                    };
                }
                // A free presence bit: an absent header has zero bits.
                for p in [
                    bits::P_PORTS,
                    bits::P_TCP,
                    bits::P_ICMP,
                    bits::P_VLAN,
                    bits::P_MPLS,
                ] {
                    if enc[p as usize].is_none() {
                        let z = b.absent_zero(p, Bank::Current)?;
                        acc = b.dd.and(acc, z)?;
                    }
                }
                Ok(acc)
            })
            .unwrap_or(Edge::FALSE);
        PacketSet {
            arena: Arc::clone(arena),
            edge: e,
        }
    }

    /// The set of one pair of headers. Each header must state all fields.
    /// A header with no known address has the address family of the other
    /// header.
    pub fn pair(arena: &Arc<SetArena>, p: &PacketPair) -> PacketSet {
        let mut o = bits::encode(&p.original);
        let mut c = bits::encode(&p.current);
        let af = bits::AF as usize;
        if c[af].is_none() {
            c[af] = o[af];
        }
        if o[af].is_none() {
            o[af] = c[af];
        }
        let e = arena
            .run(|ops| {
                let mut lits = Vec::new();
                for x in 0..bits::BITS {
                    if let Some(v) = o[x as usize] {
                        lits.push((level(x, Bank::Original), v));
                    }
                    if let Some(v) = c[x as usize] {
                        lits.push((level(x, Bank::Current), v));
                    }
                }
                ops.dd.literals(&lits)
            })
            .unwrap_or(Edge::FALSE);
        PacketSet {
            arena: Arc::clone(arena),
            edge: e,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.edge == Edge::FALSE
    }

    pub fn intersect(&self, other: &PacketSet) -> PacketSet {
        self.op(&[other], |ops| ops.dd.and(self.edge, other.edge))
    }

    pub fn union(&self, other: &PacketSet) -> PacketSet {
        self.op(&[other], |ops| ops.dd.or(self.edge, other.edge))
    }

    pub fn difference(&self, other: &PacketSet) -> PacketSet {
        self.op(&[other], |ops| ops.dd.diff(self.edge, other.edge))
    }

    /// True if each member of this set is in `other`.
    pub fn is_subset(&self, other: &PacketSet) -> bool {
        self.difference(other).is_empty()
    }

    /// True if the set holds the pair.
    pub fn contains(&self, p: &PacketPair) -> bool {
        let o = bits::encode(&p.original);
        let c = bits::encode(&p.current);
        let bit = |l: u32| -> bool {
            let (x, bank) = (l / 3, l % 3);
            let v = match bank {
                0 => o[x as usize],
                1 => c[x as usize],
                _ => Some(false),
            };
            v == Some(true)
        };
        let edge = self.edge;
        self.arena
            .run(|ops| ops.dd.eval(edge, bit))
            .unwrap_or(false)
    }

    /// One member, if the set is not empty. The engine uses it for reports
    /// and tests. A function must not branch on it. Free bits are 0.
    pub fn witness(&self) -> Option<PacketPair> {
        let path = self.arena.run(|ops| ops.dd.pick_one(self.edge)).flatten()?;
        let mut o = vec![false; bits::BITS as usize];
        let mut c = vec![false; bits::BITS as usize];
        for (l, v) in path {
            match l % 3 {
                0 => o[(l / 3) as usize] = v,
                1 => c[(l / 3) as usize] = v,
                _ => {}
            }
        }
        Some(PacketPair {
            original: bits::decode(&|b| o[b as usize]),
            current: bits::decode(&|b| c[b as usize]),
        })
    }

    /// The projection to the original request headers. Each member of the
    /// result has the original request as both headers.
    pub fn project_original(&self) -> PacketSet {
        self.op(&[], |ops| {
            if let Some(&e) = ops.memo.get(&(MEMO_ORIGINAL, self.edge)) {
                return Ok(e);
            }
            let o = ops.dd.exists(self.edge, ops.base.cur_cube)?;
            let e = ops.dd.and(o, ops.base.eq)?;
            ops.memo.insert((MEMO_ORIGINAL, self.edge), e);
            Ok(e)
        })
    }

    /// The projection to fields of the current header. The other fields
    /// and the original request have all values.
    pub fn project(&self, fields: &[HeaderField]) -> PacketSet {
        self.op(&[], |ops| {
            let keep: Vec<u32> = fields
                .iter()
                .flat_map(|f| bits::field_bits(*f).all_bits())
                .collect();
            let drop: Vec<u32> = (0..bits::BITS).filter(|b| !keep.contains(b)).collect();
            let c1 = ops.cube(&drop, Bank::Current)?;
            let all: Vec<u32> = (0..bits::BITS).collect();
            let c2 = ops.cube(&all, Bank::Original)?;
            let cube = ops.dd.and(c1, c2)?;
            ops.dd.exists(self.edge, cube)
        })
    }

    /// The fields that `pred` reads and that are unknown in a part of the set.
    pub fn open_fields(&self, pred: &RulePredicate) -> Vec<HeaderField> {
        pred.reads()
            .into_iter()
            .filter(|f| {
                let Some(u) = bits::field_bits(*f).unknown else {
                    return false;
                };
                self.run(&[], |ops| {
                    let v = ops.builder().var(u, Bank::Current)?;
                    ops.dd.and(self.edge, v)
                })
                .is_some_and(|e| e != Edge::FALSE)
            })
            .collect()
    }

    /// Splits the set by a predicate on the current header.
    pub fn split(&self, pred: &RulePredicate) -> Split {
        let r = self.run(&[], |ops| {
            let d = ops.predicate(&pred.definite, false)?;
            let u = ops.predicate(&pred.upper, true)?;
            let matched = ops.dd.and(self.edge, d)?;
            let rest = ops.dd.diff(self.edge, d)?;
            let unmatched = ops.dd.diff(rest, u)?;
            let uncertain = ops.dd.diff(rest, unmatched)?;
            Ok((matched, uncertain, unmatched))
        });
        let (m, u, n) = r.unwrap_or((Edge::FALSE, Edge::FALSE, Edge::FALSE));
        Split {
            matched: self.with(m),
            uncertain: self.with(u),
            unmatched: self.with(n),
        }
    }

    /// Partitions the set by longest-prefix match of an address field.
    pub fn partition_by_prefix<'t, V, T>(
        &self,
        field: AddrField,
        table: &'t T,
    ) -> PrefixPartition<'t, V>
    where
        T: PrefixTable<V> + ?Sized,
    {
        let f = match field {
            AddrField::Src => bits::SRC_IP,
            AddrField::Dst => bits::DST_IP,
        };
        let Some(u) = f.unknown else {
            unreachable!("an address field has an unknown bit")
        };
        let split = self.run(&[], |ops| {
            let uv = ops.builder().var(u, Bank::Current)?;
            Ok((ops.dd.and(self.edge, uv)?, ops.dd.diff(self.edge, uv)?))
        });
        let (unc, known) = split.unwrap_or((Edge::FALSE, Edge::FALSE));
        let uncertain = self.with(unc);
        let known = self.with(known);
        let mut matched: Vec<(Prefix, &'t V, PacketSet)> = Vec::new();
        // One address: one lookup in the table.
        if let Some(w) = known.witness() {
            let addr = match field {
                AddrField::Src => w.current.src_ip,
                AddrField::Dst => w.current.dst_ip,
            };
            if let FieldValue::Known(a) = addr {
                let one = known.in_prefix(f, &Prefix::host(a));
                if one == known {
                    return match table.longest_match(a) {
                        Some((p, v)) => PrefixPartition {
                            matched: vec![(p, v, known.clone())],
                            unmatched: self.empty(),
                            uncertain,
                        },
                        None => PrefixPartition {
                            matched: Vec::new(),
                            unmatched: known,
                            uncertain,
                        },
                    };
                }
            }
        }
        // A walk along a binary trie of the entries. It visits only the
        // trie nodes that hold packets of the set.
        let entries = table.entries();
        let mut parts: Vec<Option<PacketSet>> = vec![None; entries.len()];
        let mut unmatched = self.empty();
        for v6 in [false, true] {
            let trie = Trie::new(
                entries
                    .iter()
                    .map(|(p, _)| *p)
                    .filter(|p| p.is_ipv4() != v6),
            );
            let ids: Vec<usize> = entries
                .iter()
                .enumerate()
                .filter(|(_, (p, _))| p.is_ipv4() != v6)
                .map(|(i, _)| i)
                .collect();
            let fam = known.in_family(v6);
            if fam.is_empty() {
                continue;
            }
            let off = if v6 { 0 } else { 96 };
            let width = if v6 { 128 } else { 32 };
            // (trie node, depth, packets, best entry above)
            let mut stack = vec![(0usize, 0u32, fam, None::<usize>)];
            while let Some((n, depth, set, best)) = stack.pop() {
                let node = &trie.nodes[n];
                let best = node.entry.map(|e| ids[e]).or(best);
                let mut give = |set: PacketSet, best: Option<usize>| match best {
                    Some(e) => {
                        parts[e] = Some(match parts[e].take() {
                            Some(x) => x.union(&set),
                            None => set,
                        });
                    }
                    None => unmatched = unmatched.union(&set),
                };
                if depth == width || node.child == [None, None] {
                    give(set, best);
                    continue;
                }
                let (zero, one) = set.split_bit(f.start + off + depth);
                for (b, part) in [(1usize, one), (0usize, zero)] {
                    if part.is_empty() {
                        continue;
                    }
                    match node.child[b] {
                        Some(c) => stack.push((c, depth + 1, part, best)),
                        None => give(part, best),
                    }
                }
            }
        }
        for (i, part) in parts.into_iter().enumerate() {
            if let Some(set) = part {
                let (p, v) = entries[i];
                matched.push((p, v, set));
            }
        }
        matched.sort_by_key(|(p, _, _)| *p);
        PrefixPartition {
            matched,
            unmatched,
            uncertain,
        }
    }

    /// The members with the address family `v6` in the current header.
    fn in_family(&self, v6: bool) -> PacketSet {
        self.op(&[], |ops| {
            let e = ops.dd.literals(&[(level(bits::AF, Bank::Current), v6)])?;
            ops.dd.and(self.edge, e)
        })
    }

    /// The members with 0 and with 1 in a bit of the current header.
    fn split_bit(&self, bit: u32) -> (PacketSet, PacketSet) {
        let r = self.run(&[], |ops| {
            let v = ops.dd.var(level(bit, Bank::Current))?;
            Ok((ops.dd.diff(self.edge, v)?, ops.dd.and(self.edge, v)?))
        });
        let (z, o) = r.unwrap_or((Edge::FALSE, Edge::FALSE));
        (self.with(z), self.with(o))
    }

    /// The members whose current address field `f` is in `p`.
    fn in_prefix(&self, f: FieldBits, p: &Prefix) -> PacketSet {
        self.op(&[], |ops| {
            let lits = prefix_lits(f, Bank::Current, p);
            let e = ops.dd.literals(&lits)?;
            ops.dd.and(self.edge, e)
        })
    }

    /// Rewrites fields of the current header. The original request stays.
    /// A rewrite does not create a header that is absent.
    pub fn rewrite(&self, rw: &Rewrite) -> PacketSet {
        if rw.is_identity() {
            return self.clone();
        }
        let fields = rw.fields();
        self.op(&[], |ops| {
            let mut s = self.edge;
            for (f, v) in fields {
                s = rewrite_field(ops, s, f, v)?;
            }
            Ok(s)
        })
    }

    /// The reply packets of the current header. The addresses, the ports
    /// and the MAC addresses swap. An echo request gives an echo reply. TCP
    /// flags with only SYN give SYN and ACK. All other TCP flags and ICMP
    /// types and codes have all values. The DSCP and the ECN have all
    /// values. The reply is a new request, so its original request is the
    /// reply header.
    pub fn reply(&self) -> PacketSet {
        self.op(&[], |ops| {
            let orig = ops.base.orig_cube;
            let mut e = ops.dd.exists(self.edge, orig)?;
            let sw = ops.map(MapKind::ReplySwap)?;
            e = ops.dd.rename(e, sw)?;
            let c = Bank::Current;
            // TCP flags.
            let p_tcp = ops.builder().var(bits::P_TCP, c)?;
            let syn = ops.builder().value(bits::TCP_FLAGS, c, 0x02)?;
            let syn_ack = ops.builder().value(bits::TCP_FLAGS, c, 0x12)?;
            let flags: Vec<u32> = bits::TCP_FLAGS.value_bits().collect();
            let flags_cube = ops.cube(&flags, c)?;
            let with_tcp = ops.dd.and(e, p_tcp)?;
            let no_tcp = ops.dd.diff(e, p_tcp)?;
            let only_syn = ops.dd.and(with_tcp, syn)?;
            let other = ops.dd.diff(with_tcp, syn)?;
            let a = ops.dd.exists(only_syn, flags_cube)?;
            let a = ops.dd.and(a, syn_ack)?;
            let b = ops.dd.exists(other, flags_cube)?;
            let ab = ops.dd.or(a, b)?;
            e = ops.dd.or(ab, no_tcp)?;
            // ICMP type and code.
            let p_icmp = ops.builder().var(bits::P_ICMP, c)?;
            let icmp_bits: Vec<u32> = bits::ICMP_TYPE
                .value_bits()
                .chain(bits::ICMP_CODE.value_bits())
                .collect();
            let icmp_cube = ops.cube(&icmp_bits, c)?;
            let mut done = Edge::FALSE;
            let mut echo = Edge::FALSE;
            for (proto, request, reply) in [(PROTO_ICMP, 8u8, 0u8), (PROTO_ICMPV6, 128, 129)] {
                let mut b = ops.builder();
                let pr = b.value(bits::PROTOCOL, c, u128::from(proto))?;
                let req = b.value(bits::ICMP_TYPE, c, u128::from(request))?;
                let rep = b.value(bits::ICMP_TYPE, c, u128::from(reply))?;
                let code0 = b.value(bits::ICMP_CODE, c, 0)?;
                let cond = b.dd.and(pr, req)?;
                let cond = b.dd.and(cond, p_icmp)?;
                echo = b.dd.or(echo, cond)?;
                let part = b.dd.and(e, cond)?;
                let part = b.dd.exists(part, icmp_cube)?;
                let rep = b.dd.and(rep, code0)?;
                let part = b.dd.and(part, rep)?;
                done = b.dd.or(done, part)?;
            }
            let with_icmp = ops.dd.and(e, p_icmp)?;
            let other = ops.dd.diff(with_icmp, echo)?;
            let other = ops.dd.exists(other, icmp_cube)?;
            let no_icmp = ops.dd.diff(e, p_icmp)?;
            let d = ops.dd.or(done, other)?;
            e = ops.dd.or(d, no_icmp)?;
            // DSCP and ECN.
            let mut q: Vec<u32> = bits::DSCP
                .value_bits()
                .chain(bits::ECN.value_bits())
                .collect();
            q.extend([bits::U_DSCP, bits::U_ECN]);
            let qc = ops.cube(&q, c)?;
            e = ops.dd.exists(e, qc)?;
            let z = ops.builder().zeros(&[bits::U_DSCP, bits::U_ECN], c)?;
            e = ops.dd.and(e, z)?;
            ops.dd.and(e, ops.base.eq)
        })
    }

    /// A QoS field of the current header, where all members agree.
    fn uniform(&self, f: FieldBits, get: fn(&Header) -> FieldValue<u8>) -> Uniform<FieldValue<u8>> {
        let Some(w) = self.witness() else {
            return Uniform::None;
        };
        let v = get(&w.current);
        let x = match v {
            FieldValue::Known(x) => Some(u128::from(x)),
            _ => None,
        };
        let same = self.run(&[], |ops| {
            let mut b = ops.builder();
            let e = match (x, f.unknown) {
                (Some(x), Some(u)) => {
                    let val = b.value(f, Bank::Current, x)?;
                    let uv = b.var(u, Bank::Current)?;
                    b.dd.and(val, uv.not())?
                }
                (Some(x), None) => b.value(f, Bank::Current, x)?,
                (None, Some(u)) => b.var(u, Bank::Current)?,
                (None, None) => Edge::TRUE,
            };
            b.dd.diff(self.edge, e)
        });
        match same {
            Some(e) if e == Edge::FALSE => Uniform::Value(v),
            _ => Uniform::Varies,
        }
    }

    pub fn dscp(&self) -> Uniform<FieldValue<u8>> {
        self.uniform_memo(MEMO_DSCP, bits::DSCP, |h| h.dscp)
    }

    pub fn ecn(&self) -> Uniform<FieldValue<u8>> {
        self.uniform_memo(MEMO_ECN, bits::ECN, |h| h.ecn)
    }

    /// [`PacketSet::uniform`] with the result kept in the arena.
    fn uniform_memo(
        &self,
        kind: u8,
        f: FieldBits,
        get: fn(&Header) -> FieldValue<u8>,
    ) -> Uniform<FieldValue<u8>> {
        let key = (kind, self.edge);
        if let Some(Some(u)) = self.run(&[], |ops| Ok(ops.qos.get(&key).copied())) {
            return u;
        }
        let u = self.uniform(f, get);
        self.run(&[], |ops| {
            ops.qos.insert(key, u);
            Ok(())
        });
        u
    }

    /// The session relation of packets that a session lookup saw as this
    /// set and that reach the session commit as `commit`. A pair of flows is
    /// in the relation if one original request has the first flow at the
    /// lookup and the second flow at the commit. The original bank holds
    /// the flow at the lookup, and the current bank holds the flow at the
    /// commit. The other fields have all values.
    pub fn session_relation(&self, commit: &PacketSet) -> PacketSet {
        self.op(&[commit], |ops| {
            let flow = bits::flow_bits();
            let rest: Vec<u32> = (0..bits::BITS).filter(|b| !flow.contains(b)).collect();
            let rest_cur = ops.cube(&rest, Bank::Current)?;
            // The flows at the lookup and at the commit, with the original
            // requests.
            let at_lookup = ops.dd.exists(self.edge, rest_cur)?;
            let at_commit = ops.dd.exists(commit.edge, rest_cur)?;
            let cw = ops.map(MapKind::CurrentWorkFlow)?;
            let a = ops.dd.rename(at_lookup, cw)?;
            let t = ops.dd.and_exists(a, at_commit, ops.base.orig_cube)?;
            let wo = ops.map(MapKind::OriginalWorkFlow)?;
            ops.dd.rename(t, wo)
        })
    }

    /// True if the set holds a pair with different flows in the original
    /// bank and the current bank. A session relation with such a pair has
    /// a NAT binding.
    pub fn changes_flow(&self) -> bool {
        self.run(&[], |ops| ops.dd.diff(self.edge, ops.base.eq_flow))
            .is_some_and(|e| e != Edge::FALSE)
    }

    /// True if a flow field of the current bank is unknown in a part of the set.
    pub fn has_unknown_flow_field(&self) -> bool {
        self.run(&[], |ops| {
            let mut b = ops.builder();
            let items: Vec<_> = [
                bits::U_SRC_IP,
                bits::U_DST_IP,
                bits::U_SRC_PORT,
                bits::U_DST_PORT,
            ]
            .into_iter()
            .map(|u| b.var(u, Bank::Current))
            .collect();
            let any = b.any_of(items)?;
            b.dd.and(self.edge, any)
        })
        .is_some_and(|e| e != Edge::FALSE)
    }

    /// Looks up a session relation for the current header. The matched
    /// packets get the flow of the other side of the relation. In the reply
    /// direction, the relation applies in reverse: a reply of the flow at
    /// the commit gets the reply of the flow at the lookup.
    pub fn session_lookup(&self, relation: &PacketSet, dir: SessionDirection) -> SessionSplit {
        let r = self.run(&[relation], |ops| {
            let mut rel = relation.edge;
            if dir == SessionDirection::Reply {
                let m = ops.map(MapKind::ReverseFlow)?;
                rel = ops.dd.rename(rel, m)?;
            }
            // The flows of the lookup side, on the current bank.
            let dom = ops.dd.exists(rel, ops.base.cur_cube)?;
            let oc = ops.map(MapKind::OriginalCurrentFlow)?;
            let dom = ops.dd.rename(dom, oc)?;
            // An unknown port can be equal to each known port.
            let c = Bank::Current;
            let mut b = ops.builder();
            let usp = b.var(bits::U_SRC_PORT, c)?;
            let udp = b.var(bits::U_DST_PORT, c)?;
            let unk = b.dd.or(usp, udp)?;
            let mut ports: Vec<u32> = bits::SRC_PORT
                .value_bits()
                .chain(bits::DST_PORT.value_bits())
                .collect();
            ports.extend([bits::U_SRC_PORT, bits::U_DST_PORT]);
            let pc = ops.cube(&ports, c)?;
            let dom_unk = ops.dd.and(dom, unk)?;
            let w1 = ops.dd.exists(dom_unk, pc)?;
            let wide = ops.dd.exists(dom, pc)?;
            let w2 = ops.dd.and(wide, unk)?;
            let up = ops.dd.or(dom, w1)?;
            let up = ops.dd.or(up, w2)?;
            // The flows of the lookup side with more than one flow on the
            // other side.
            let cw = ops.map(MapKind::CurrentWorkFlow)?;
            let other = ops.dd.rename(rel, cw)?;
            let both = ops.dd.and(rel, other)?;
            let mut eq_cw = Edge::TRUE;
            {
                let mut b = ops.builder();
                for x in bits::flow_bits().into_iter().rev() {
                    eq_cw = b.eq_bit(x, Bank::Current, Bank::Work, eq_cw)?;
                }
            }
            let two = ops.dd.diff(both, eq_cw)?;
            let flow = bits::flow_bits();
            let cur_flow = ops.cube(&flow, Bank::Current)?;
            let work_flow = ops.cube(&flow, Bank::Work)?;
            let cube2 = ops.dd.and(cur_flow, work_flow)?;
            let many = ops.dd.exists(two, cube2)?;
            let many = ops.dd.rename(many, oc)?;
            let in_dom = ops.dd.and(self.edge, dom)?;
            let ambiguous = ops.dd.and(in_dom, many)?;
            let matched = ops.dd.diff(in_dom, many)?;
            let rest = ops.dd.diff(self.edge, dom)?;
            let uncertain = ops.dd.and(rest, up)?;
            let unmatched = ops.dd.diff(rest, up)?;
            // The image of the matched packets under the relation.
            let m2 = ops.dd.rename(matched, cw)?;
            let owf = ops.map(MapKind::OriginalWorkFlow)?;
            let r2 = ops.dd.rename(rel, owf)?;
            let flow = bits::flow_bits();
            let wc = ops.cube(&flow, Bank::Work)?;
            let image = ops.dd.and_exists(m2, r2, wc)?;
            Ok((image, uncertain, ambiguous, unmatched))
        });
        let (m, u, a, n) = r.unwrap_or((Edge::FALSE, Edge::FALSE, Edge::FALSE, Edge::FALSE));
        SessionSplit {
            matched: self.with(m),
            uncertain: self.with(u),
            ambiguous: self.with(a),
            unmatched: self.with(n),
        }
    }

    /// The same set in another arena of the same base.
    pub fn copy_to(&self, arena: &Arc<SetArena>) -> PacketSet {
        if Arc::ptr_eq(arena, &self.arena) {
            return self.clone();
        }
        let src = self.arena.lock();
        let e = arena
            .run(|ops| ops.dd.import(&src.dd, self.edge))
            .unwrap_or(Edge::FALSE);
        PacketSet {
            arena: Arc::clone(arena),
            edge: e,
        }
    }

    /// Splits the set on the first bit of the original request, in the
    /// fixed order of the bit table, for which the two parts are not empty.
    /// The 0 part comes first. A set with one original request gives `None`.
    pub fn split_on_first_bit(&self) -> Option<(PacketSet, PacketSet)> {
        for x in 0..bits::BITS {
            let r = self.run(&[], |ops| {
                let v = ops.builder().var(x, Bank::Original)?;
                Ok((ops.dd.diff(self.edge, v)?, ops.dd.and(self.edge, v)?))
            })?;
            if r.0 != Edge::FALSE && r.1 != Edge::FALSE {
                return Some((self.with(r.0), self.with(r.1)));
            }
        }
        None
    }

    pub(crate) fn from_edge(arena: &Arc<SetArena>, edge: Edge) -> PacketSet {
        PacketSet {
            arena: Arc::clone(arena),
            edge,
        }
    }

    /// The edge of the set, for the description of a set.
    pub(crate) fn edge(&self) -> Edge {
        self.edge
    }
}

/// Rewrites one field of the current header of the set `s`.
fn rewrite_field(
    ops: &mut Ops<'_>,
    s: Edge,
    f: FieldBits,
    v: FieldValue<u128>,
) -> Result<Edge, DdError> {
    let c = Bank::Current;
    let mut b: Builder<'_> = ops.builder();
    let enc = match v {
        FieldValue::Known(x) => {
            let val = b.value(f, c, x)?;
            match f.unknown {
                Some(u) => {
                    let uv = b.var(u, c)?;
                    b.dd.and(val, uv.not())?
                }
                None => val,
            }
        }
        FieldValue::Unknown => match f.unknown {
            Some(u) => {
                let uv = b.var(u, c)?;
                let bits: Vec<u32> = f.value_bits().collect();
                let z = b.zeros(&bits, c)?;
                b.dd.and(uv, z)?
            }
            None => Edge::TRUE,
        },
        FieldValue::Unstated => match f.unknown {
            Some(u) => b.var(u, c)?.not(),
            None => Edge::TRUE,
        },
        FieldValue::Absent => return Ok(s),
    };
    let (present, absent) = match f.presence {
        Some(p) => {
            let pv = b.var(p, c)?;
            (b.dd.and(s, pv)?, b.dd.diff(s, pv)?)
        }
        None => (s, Edge::FALSE),
    };
    let mut fb: Vec<u32> = f.value_bits().collect();
    fb.extend(f.unknown);
    let cube = ops.cube(&fb, c)?;
    let e = ops.dd.exists(present, cube)?;
    let e = ops.dd.and(e, enc)?;
    ops.dd.or(e, absent)
}
