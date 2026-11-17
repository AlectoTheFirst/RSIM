//! The arenas of the packet sets: the frozen base of a twin and the scratch
//! arena of one query.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use rsim_dd::{Dd, DdError, Edge, Frozen, MapId};

use crate::addr::Prefix;
use crate::bits::{self, Bank, FieldBits, level};
use crate::field::FieldValue;
use crate::packet_set::Uniform;
use crate::predicate::{AddrCond, FlagsCond, FragmentCond, MacCond, Match, PortCond, ValueCond};

/// The frozen base of the packet sets of one twin: the relation "original
/// request equals current header" and the compiled predicates of the twin.
#[derive(Debug)]
pub struct SetBase {
    pub(crate) frozen: Arc<Frozen>,
    /// The original request equals the current header on each bit.
    pub(crate) eq: Edge,
    /// The cube of all levels of the original bank.
    pub(crate) orig_cube: Edge,
    /// The cube of all levels of the current bank.
    pub(crate) cur_cube: Edge,
    /// The cube of the inner levels of the header bits below the
    /// encapsulation fields.
    pub(crate) inner_cube: Edge,
    /// The original bank equals the current bank on the flow bits.
    pub(crate) eq_flow: Edge,
    pub(crate) definite: BTreeMap<Match, Edge>,
    pub(crate) upper: BTreeMap<Match, Edge>,
}

impl SetBase {
    /// Builds the base with the predicates of a twin. The validator checks
    /// the frozen arena.
    pub fn build<'a>(
        predicates: impl IntoIterator<Item = &'a crate::predicate::RulePredicate>,
    ) -> Result<Arc<SetBase>, DdError> {
        let mut dd = Dd::new(bits::LEVELS);
        dd.set_shadow(false);
        let mut b = Builder { dd: &mut dd };
        let eq = b.eq_banks(Bank::Original, Bank::Current, 0..bits::BITS)?;
        let orig: Vec<u32> = (0..bits::BITS).map(|x| level(x, Bank::Original)).collect();
        let orig_cube = b.dd.cube(&orig)?;
        let cur: Vec<u32> = (0..bits::BITS).map(|x| level(x, Bank::Current)).collect();
        let cur_cube = b.dd.cube(&cur)?;
        let inner: Vec<u32> = bits::header_bits().map(|x| level(x, Bank::Inner)).collect();
        let inner_cube = b.dd.cube(&inner)?;
        let mut eq_flow = Edge::TRUE;
        for x in bits::flow_bits().into_iter().rev() {
            eq_flow = b.eq_bit(x, Bank::Original, Bank::Current, eq_flow)?;
        }
        let mut definite = BTreeMap::new();
        let mut upper = BTreeMap::new();
        for p in predicates {
            if !definite.contains_key(&p.definite) {
                let e = b.compile(&p.definite, false)?;
                definite.insert(p.definite.clone(), e);
            }
            if !upper.contains_key(&p.upper) {
                let e = b.compile(&p.upper, true)?;
                upper.insert(p.upper.clone(), e);
            }
        }
        let frozen = dd.freeze()?;
        Ok(Arc::new(SetBase {
            frozen,
            eq,
            orig_cube,
            cur_cube,
            inner_cube,
            eq_flow,
            definite,
            upper,
        }))
    }

    /// Validates the frozen arena.
    pub fn validate(&self) -> Result<(), DdError> {
        self.frozen.validate()
    }

    /// The number of nodes of the frozen arena.
    pub fn node_count(&self) -> usize {
        self.frozen.node_count()
    }
}

/// The level maps that the operations register once in each arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum MapKind {
    /// The current and the work levels of the flow bits swap.
    CurrentWorkFlow,
    /// The original and the work levels of the flow bits swap.
    OriginalWorkFlow,
    /// The original and the current levels of the flow bits swap.
    OriginalCurrentFlow,
    /// A flow relation in the reverse direction: source and destination
    /// swap, and the two banks swap.
    ReverseFlow,
    /// The source and destination fields of the current bank swap.
    ReplySwap,
    /// The current and the inner levels of the header bits below the
    /// encapsulation fields swap.
    CurrentInner,
}

pub(crate) struct Inner {
    pub(crate) dd: Dd,
    pub(crate) fault: Option<DdError>,
    pub(crate) definite: BTreeMap<Match, Edge>,
    pub(crate) upper: BTreeMap<Match, Edge>,
    maps: BTreeMap<MapKind, MapId>,
    cubes: BTreeMap<(Vec<u32>, Bank), Edge>,
    /// Results of unary operations by kind and edge.
    pub(crate) memo: BTreeMap<(u8, Edge), Edge>,
    /// The QoS field values of sets by field and edge.
    pub(crate) qos: BTreeMap<(u8, Edge), Uniform<FieldValue<u8>>>,
}

/// The arena of the packet sets of one query: a scratch arena on the base
/// of the twin, with an optional node budget. The first fault of an
/// operation is the fault of the query. After a fault, each operation gives
/// the empty set.
#[derive(Debug)]
pub struct SetArena {
    pub(crate) base: Arc<SetBase>,
    budget: Option<usize>,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("nodes", &self.dd.local_nodes())
            .field("fault", &self.fault)
            .finish()
    }
}

impl SetArena {
    pub fn new(base: &Arc<SetBase>, budget: Option<usize>) -> Arc<SetArena> {
        let mut dd = Dd::scratch(Arc::clone(&base.frozen), budget);
        dd.set_shadow(false);
        dd.reserve(budget.unwrap_or(1 << 16).min(1 << 16));
        Arc::new(SetArena {
            base: Arc::clone(base),
            budget,
            inner: Mutex::new(Inner {
                dd,
                fault: None,
                definite: BTreeMap::new(),
                upper: BTreeMap::new(),
                maps: BTreeMap::new(),
                cubes: BTreeMap::new(),
                memo: BTreeMap::new(),
                qos: BTreeMap::new(),
            }),
        })
    }

    /// An arena on a base with no predicates and with no budget, for a
    /// function that runs outside a twin.
    ///
    /// # Panics
    ///
    /// Panics if the base does not build. A base with no predicates has a
    /// fixed size, and a test of this crate builds it.
    pub fn standalone() -> Arc<SetArena> {
        let base = SetBase::build([]).expect("a base with no predicates builds");
        SetArena::new(&base, None)
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The node budget of the arena.
    pub fn budget(&self) -> Option<usize> {
        self.budget
    }

    /// True if the arena and `base` are the same base.
    pub fn has_base(&self, base: &Arc<SetBase>) -> bool {
        Arc::ptr_eq(&self.base, base)
    }

    /// The first fault of an operation, if there is one.
    pub fn fault(&self) -> Option<DdError> {
        self.lock().fault.clone()
    }

    /// The number of nodes of this arena, without the base.
    pub fn local_nodes(&self) -> usize {
        self.lock().dd.local_nodes()
    }

    /// Runs `f` on the arena. A fault before or in `f` gives `None`, and the
    /// first fault stays as the fault of the query.
    pub(crate) fn run<R>(&self, f: impl FnOnce(&mut Ops<'_>) -> Result<R, DdError>) -> Option<R> {
        let mut g = self.lock();
        if g.fault.is_some() {
            return None;
        }
        let inner = &mut *g;
        let mut ops = Ops {
            dd: &mut inner.dd,
            base: &self.base,
            definite: &mut inner.definite,
            upper: &mut inner.upper,
            maps: &mut inner.maps,
            cubes: &mut inner.cubes,
            memo: &mut inner.memo,
            qos: &mut inner.qos,
        };
        match f(&mut ops) {
            Ok(r) => Some(r),
            Err(e) => {
                g.fault = Some(e);
                None
            }
        }
    }

    /// Records a fault, if the arena has none.
    pub(crate) fn record(&self, e: DdError) {
        let mut g = self.lock();
        if g.fault.is_none() {
            g.fault = Some(e);
        }
    }
}

/// The operations on one locked arena.
pub(crate) struct Ops<'a> {
    pub(crate) dd: &'a mut Dd,
    pub(crate) base: &'a SetBase,
    definite: &'a mut BTreeMap<Match, Edge>,
    upper: &'a mut BTreeMap<Match, Edge>,
    maps: &'a mut BTreeMap<MapKind, MapId>,
    cubes: &'a mut BTreeMap<(Vec<u32>, Bank), Edge>,
    pub(crate) memo: &'a mut BTreeMap<(u8, Edge), Edge>,
    pub(crate) qos: &'a mut BTreeMap<(u8, Edge), Uniform<FieldValue<u8>>>,
}

impl Ops<'_> {
    pub(crate) fn builder(&mut self) -> Builder<'_> {
        Builder { dd: self.dd }
    }

    /// The match set of a predicate on the current header: the definite
    /// match set, or the upper match bound.
    pub(crate) fn predicate(&mut self, m: &Match, upper: bool) -> Result<Edge, DdError> {
        let found = if upper {
            self.base.upper.get(m).or_else(|| self.upper.get(m))
        } else {
            self.base.definite.get(m).or_else(|| self.definite.get(m))
        };
        if let Some(&e) = found {
            return Ok(e);
        }
        let e = Builder { dd: self.dd }.compile(m, upper)?;
        if upper {
            self.upper.insert(m.clone(), e);
        } else {
            self.definite.insert(m.clone(), e);
        }
        Ok(e)
    }

    pub(crate) fn map(&mut self, kind: MapKind) -> Result<MapId, DdError> {
        if let Some(&m) = self.maps.get(&kind) {
            return Ok(m);
        }
        let swap = |a: Bank, b: Bank, bits: &[u32]| -> Vec<(u32, u32)> {
            bits.iter()
                .flat_map(|&x| [(level(x, a), level(x, b)), (level(x, b), level(x, a))])
                .collect()
        };
        let flow = bits::flow_bits();
        let pairs = match kind {
            MapKind::CurrentWorkFlow => swap(Bank::Current, Bank::Work, &flow),
            MapKind::OriginalWorkFlow => swap(Bank::Original, Bank::Work, &flow),
            MapKind::OriginalCurrentFlow => swap(Bank::Original, Bank::Current, &flow),
            MapKind::CurrentInner => {
                let header: Vec<u32> = bits::header_bits().collect();
                swap(Bank::Current, Bank::Inner, &header)
            }
            MapKind::ReverseFlow => {
                let pairs = bits::swap_pairs();
                let sw = swapped(&pairs);
                flow.iter()
                    .flat_map(|&x| {
                        let y = sw(x);
                        [
                            (level(x, Bank::Original), level(y, Bank::Current)),
                            (level(x, Bank::Current), level(y, Bank::Original)),
                        ]
                    })
                    .collect()
            }
            MapKind::ReplySwap => bits::swap_pairs()
                .into_iter()
                .flat_map(|(a, b)| {
                    let (a, b) = (level(a, Bank::Current), level(b, Bank::Current));
                    [(a, b), (b, a)]
                })
                .collect(),
        };
        let m = self.dd.map(&pairs)?;
        self.maps.insert(kind, m);
        Ok(m)
    }

    /// The cube of the levels of `bits` in `bank`.
    pub(crate) fn cube(&mut self, bits: &[u32], bank: Bank) -> Result<Edge, DdError> {
        let key = (bits.to_vec(), bank);
        if let Some(&e) = self.cubes.get(&key) {
            return Ok(e);
        }
        let ls: Vec<u32> = bits.iter().map(|&b| level(b, bank)).collect();
        let e = self.dd.cube(&ls)?;
        self.cubes.insert(key, e);
        Ok(e)
    }
}

/// The function that gives the partner of a bit in a list of swap pairs.
fn swapped(pairs: &[(u32, u32)]) -> impl Fn(u32) -> u32 + '_ {
    move |x| {
        for &(a, b) in pairs {
            if x == a {
                return b;
            }
            if x == b {
                return a;
            }
        }
        x
    }
}

/// Builds the functions of fields on one arena.
pub(crate) struct Builder<'a> {
    pub(crate) dd: &'a mut Dd,
}

impl Builder<'_> {
    pub(crate) fn var(&mut self, bit: u32, bank: Bank) -> Result<Edge, DdError> {
        self.dd.var(level(bit, bank))
    }

    /// The value bits of `f` in `bank` are `x`.
    pub(crate) fn value(&mut self, f: FieldBits, bank: Bank, x: u128) -> Result<Edge, DdError> {
        if f.width < 128 && x >> f.width != 0 {
            return Ok(Edge::FALSE);
        }
        let lits = value_lits(f, bank, x);
        self.dd.literals(&lits)
    }

    /// The bits of `bits` in `bank` are 0.
    pub(crate) fn zeros(&mut self, bits: &[u32], bank: Bank) -> Result<Edge, DdError> {
        let lits: Vec<(u32, bool)> = bits.iter().map(|&b| (level(b, bank), false)).collect();
        self.dd.literals(&lits)
    }

    /// The value bits of `f` in `bank` are in the range `lo..=hi`.
    pub(crate) fn range(
        &mut self,
        f: FieldBits,
        bank: Bank,
        lo: u128,
        hi: u128,
    ) -> Result<Edge, DdError> {
        let max = if f.width >= 128 {
            u128::MAX
        } else {
            (1u128 << f.width) - 1
        };
        let hi = hi.min(max);
        if lo > hi {
            return Ok(Edge::FALSE);
        }
        let mut le = Edge::TRUE;
        let mut ge = Edge::TRUE;
        for i in (0..f.width).rev() {
            let x = self.dd.var(level(f.start + i, bank))?;
            let shift = f.width - 1 - i;
            le = if hi >> shift & 1 == 1 {
                self.dd.ite(x, le, Edge::TRUE)?
            } else {
                self.dd.ite(x, Edge::FALSE, le)?
            };
            ge = if lo >> shift & 1 == 1 {
                self.dd.ite(x, ge, Edge::FALSE)?
            } else {
                self.dd.ite(x, Edge::TRUE, ge)?
            };
        }
        self.dd.and(le, ge)
    }

    /// The address field `f` in `bank` is in the prefix `p`.
    pub(crate) fn prefix(&mut self, f: FieldBits, bank: Bank, p: &Prefix) -> Result<Edge, DdError> {
        let lits = prefix_lits(f, bank, p);
        self.dd.literals(&lits)
    }

    pub(crate) fn any_of(
        &mut self,
        items: impl IntoIterator<Item = Result<Edge, DdError>>,
    ) -> Result<Edge, DdError> {
        let mut acc = Edge::FALSE;
        for e in items {
            let e = e?;
            acc = self.dd.or(acc, e)?;
        }
        Ok(acc)
    }

    /// The fields of the presence bit `p` have zero bits where `p` is 0.
    pub(crate) fn absent_zero(&mut self, p: u32, bank: Bank) -> Result<Edge, DdError> {
        let bits: Vec<u32> = bits::presence_group(p)
            .iter()
            .flat_map(|f| f.all_bits())
            .filter(|b| *b != p)
            .collect();
        let z = self.zeros(&bits, bank)?;
        let pv = self.var(p, bank)?;
        self.dd.or(pv, z)
    }

    /// Bank `a` equals bank `b` on each bit of `range`.
    pub(crate) fn eq_banks(
        &mut self,
        a: Bank,
        b: Bank,
        range: std::ops::Range<u32>,
    ) -> Result<Edge, DdError> {
        let mut acc = Edge::TRUE;
        for x in range.rev() {
            acc = self.eq_bit(x, a, b, acc)?;
        }
        Ok(acc)
    }

    /// `rest` and bank `a` equals bank `b` on bit `x`. `rest` has no
    /// variable above the levels of `x`.
    pub(crate) fn eq_bit(&mut self, x: u32, a: Bank, b: Bank, rest: Edge) -> Result<Edge, DdError> {
        let va = self.var(x, a)?;
        let vb = self.var(x, b)?;
        let hi = self.dd.and(vb, rest)?;
        let lo = self.dd.and(vb.not(), rest)?;
        self.dd.ite(va, hi, lo)
    }

    /// The match set of a predicate on the current header. The definite
    /// match set does not hold a packet with an unknown value of a field
    /// that the predicate reads. The upper match bound holds it. A field
    /// of an absent header does not match.
    pub(crate) fn compile(&mut self, m: &Match, upper: bool) -> Result<Edge, DdError> {
        use bits::*;
        let bank = Bank::Current;
        let mut acc = Edge::TRUE;
        let conds: Vec<(FieldBits, Option<Edge>)> = vec![
            (SRC_IP, self.addr_cond(SRC_IP, &m.src_ip)?),
            (DST_IP, self.addr_cond(DST_IP, &m.dst_ip)?),
            (PROTOCOL, self.value_cond(PROTOCOL, &m.protocol)?),
            (SRC_PORT, self.port_cond(SRC_PORT, &m.src_port)?),
            (DST_PORT, self.port_cond(DST_PORT, &m.dst_port)?),
            (DSCP, self.value_cond(DSCP, &m.dscp)?),
            (ECN, self.value_cond(ECN, &m.ecn)?),
            (FRAGMENT, self.fragment_cond(&m.fragment)?),
            (TCP_FLAGS, self.flags_cond(&m.tcp_flags)?),
            (ICMP_TYPE, self.value_cond(ICMP_TYPE, &m.icmp_type)?),
            (ICMP_CODE, self.value_cond(ICMP_CODE, &m.icmp_code)?),
            (SRC_MAC, self.mac_cond(SRC_MAC, &m.src_mac)?),
            (DST_MAC, self.mac_cond(DST_MAC, &m.dst_mac)?),
            (VLAN, self.port_cond(VLAN, &m.vlan)?),
            (L2_PRIORITY, self.value_cond(L2_PRIORITY, &m.l2_priority)?),
            (MPLS_TC, self.value_cond(MPLS_TC, &m.mpls_tc)?),
        ];
        for (f, c) in conds {
            let Some(c) = c else { continue };
            let mut e = match f.unknown {
                Some(u) => {
                    let uv = self.var(u, bank)?;
                    if upper {
                        self.dd.or(uv, c)?
                    } else {
                        self.dd.and(uv.not(), c)?
                    }
                }
                None => c,
            };
            if let Some(p) = f.presence {
                let pv = self.var(p, bank)?;
                e = self.dd.and(pv, e)?;
            }
            acc = self.dd.and(acc, e)?;
        }
        Ok(acc)
    }

    fn addr_cond(&mut self, f: FieldBits, c: &AddrCond) -> Result<Option<Edge>, DdError> {
        match c {
            AddrCond::Any => Ok(None),
            AddrCond::In(ps) => {
                let items: Vec<_> = ps
                    .iter()
                    .map(|p| self.prefix(f, Bank::Current, p))
                    .collect();
                self.any_of(items).map(Some)
            }
        }
    }

    fn value_cond(&mut self, f: FieldBits, c: &ValueCond) -> Result<Option<Edge>, DdError> {
        match c {
            ValueCond::Any => Ok(None),
            ValueCond::In(s) => {
                let items: Vec<_> = s
                    .iter()
                    .map(|v| self.value(f, Bank::Current, u128::from(*v)))
                    .collect();
                self.any_of(items).map(Some)
            }
        }
    }

    fn port_cond(&mut self, f: FieldBits, c: &PortCond) -> Result<Option<Edge>, DdError> {
        match c {
            PortCond::Any => Ok(None),
            PortCond::In(rs) => {
                let items: Vec<_> = rs
                    .iter()
                    .map(|&(lo, hi)| self.range(f, Bank::Current, u128::from(lo), u128::from(hi)))
                    .collect();
                self.any_of(items).map(Some)
            }
        }
    }

    fn flags_cond(&mut self, c: &FlagsCond) -> Result<Option<Edge>, DdError> {
        match c {
            FlagsCond::Any => Ok(None),
            FlagsCond::Bits { mask, value } => {
                if value & !mask != 0 {
                    return Ok(Some(Edge::FALSE));
                }
                let f = bits::TCP_FLAGS;
                let lits: Vec<(u32, bool)> = (0..8u32)
                    .filter(|i| mask >> i & 1 == 1)
                    .map(|i| {
                        (
                            level(f.start + f.width - 1 - i, Bank::Current),
                            value >> i & 1 == 1,
                        )
                    })
                    .collect();
                self.dd.literals(&lits).map(Some)
            }
        }
    }

    fn fragment_cond(&mut self, c: &FragmentCond) -> Result<Option<Edge>, DdError> {
        match c {
            FragmentCond::Any => Ok(None),
            FragmentCond::In(s) => {
                let items: Vec<_> = s
                    .iter()
                    .map(|v| self.value(bits::FRAGMENT, Bank::Current, bits::fragment_code(*v)))
                    .collect();
                self.any_of(items).map(Some)
            }
        }
    }

    fn mac_cond(&mut self, f: FieldBits, c: &MacCond) -> Result<Option<Edge>, DdError> {
        match c {
            MacCond::Any => Ok(None),
            MacCond::In(s) => {
                let items: Vec<_> = s
                    .iter()
                    .map(|m| self.value(f, Bank::Current, bits::mac_bits(*m)))
                    .collect();
                self.any_of(items).map(Some)
            }
        }
    }
}

/// The literals of the value `x` of the value bits of `f` in `bank`.
pub(crate) fn value_lits(f: FieldBits, bank: Bank, x: u128) -> Vec<(u32, bool)> {
    f.value_bits()
        .enumerate()
        .map(|(i, b)| (level(b, bank), x >> (f.width - 1 - i as u32) & 1 == 1))
        .collect()
}

/// The literals of the prefix `p` of the address field `f` in `bank`, with
/// the address family.
pub(crate) fn prefix_lits(f: FieldBits, bank: Bank, p: &Prefix) -> Vec<(u32, bool)> {
    let off = if p.is_ipv4() { 96 } else { 0 };
    let mut lits = vec![(level(bits::AF, bank), !p.is_ipv4())];
    for i in 0..p.len() {
        lits.push((level(f.start + off + u32::from(i), bank), p.bit(i)));
    }
    lits
}
