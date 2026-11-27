//! The rows of a table as columns, and the selection of rows on them.
//!
//! Each column is an Arrow dictionary array: one `u32` key for each row over
//! the distinct values of the column, with a null key for a null value. A
//! table provider fills a [`FrameBuilder`] once for each twin and table;
//! [`FrameBuilder::finish`] puts the rows in key order. A selection
//! evaluates each filter once for each distinct value, scans the keys in
//! chunks on `rayon`, orders row numbers by the ranks of the distinct values
//! with the row number as the last key, and makes JSON only for the rows of
//! its answer.
//!
//! A slot is the place of a value in the per-value vectors: slot 0 is null
//! and slot `k + 1` is the distinct value `k`.
//!
//! The indexes of a frame are built when a selection first needs them. In a
//! table whose first key column is `device`, the rows of each device are 1
//! range. A column with the semantic type `mac` has the rows of each slot.
//! A text column of type address or prefix has its distinct values in the
//! prefix table of `rsim-core`.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock};

use arrow_array::builder::{ListBuilder, StringBuilder};
use arrow_array::cast::AsArray;
use arrow_array::types::{UInt32Type, UInt64Type};
use arrow_array::{
    Array, ArrayRef, BooleanArray, DictionaryArray, RecordBatch, StringArray, UInt32Array,
    UInt64Array,
};
use rayon::prelude::*;
use rsim_contract::table::{
    ColumnSummary, ColumnType, DiffCounts, DiffRow, RowChange, Selection, TableDef,
};
use rsim_core::Prefix;
use rsim_core::addr::addr_bit;
use rsim_core::prefix_table::{PrefixTable, TriePrefixTable};
use serde_json::Value;

/// The number of rows of one chunk of a parallel scan.
#[cfg(not(test))]
const CHUNK: usize = 1 << 16;
/// The number of rows of one chunk of a parallel scan: small in the tests,
/// so a scan of a test table has many chunks.
#[cfg(test)]
const CHUNK: usize = 16;

/// The key of a null value while a column is built.
const NULL: u32 = u32::MAX;

/// The value kind of a column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Text,
    Integer,
    Boolean,
    List,
}

fn kind(t: ColumnType) -> Kind {
    match t {
        ColumnType::Text | ColumnType::Address | ColumnType::Prefix => Kind::Text,
        ColumnType::Integer => Kind::Integer,
        ColumnType::Boolean => Kind::Boolean,
        ColumnType::List => Kind::List,
    }
}

/// One value of a row for a [`FrameBuilder`].
#[derive(Clone, Copy, Debug)]
pub enum Cell<'a> {
    Null,
    Text(&'a str),
    Integer(u64),
    Boolean(bool),
    List(&'a [String]),
}

/// The distinct values of a column while it is built, with their keys.
enum Distinct {
    Text(HashMap<String, u32>),
    Integer(HashMap<u64, u32>),
    Boolean(HashMap<bool, u32>),
    List(HashMap<Vec<String>, u32>),
}

struct ColumnBuilder {
    keys: Vec<u32>,
    distinct: Distinct,
}

fn key_of<K, Q>(map: &mut HashMap<K, u32>, v: &Q) -> u32
where
    K: std::hash::Hash + Eq + std::borrow::Borrow<Q>,
    Q: std::hash::Hash + Eq + ToOwned<Owned = K> + ?Sized,
{
    if let Some(k) = map.get(v) {
        return *k;
    }
    let k = u32::try_from(map.len()).expect("fewer than 2^32 distinct values");
    map.insert(v.to_owned(), k);
    k
}

impl ColumnBuilder {
    fn push(&mut self, c: Cell) {
        let k = match (&mut self.distinct, c) {
            (_, Cell::Null) => NULL,
            (Distinct::Text(m), Cell::Text(s)) => key_of(m, s),
            (Distinct::Integer(m), Cell::Integer(n)) => key_of(m, &n),
            (Distinct::Boolean(m), Cell::Boolean(b)) => key_of(m, &b),
            (Distinct::List(m), Cell::List(l)) => key_of(m, l),
            (_, c) => panic!("the value {c:?} does not have the type of its column"),
        };
        self.keys.push(k);
    }

    /// The distinct values in key order.
    fn values(self) -> (Vec<u32>, ArrayRef) {
        fn by_key<K>(m: HashMap<K, u32>) -> Vec<K> {
            let mut v: Vec<(u32, K)> = m.into_iter().map(|(k, i)| (i, k)).collect();
            v.sort_unstable_by_key(|x| x.0);
            v.into_iter().map(|x| x.1).collect()
        }
        let values: ArrayRef = match self.distinct {
            Distinct::Text(m) => Arc::new(StringArray::from_iter_values(by_key(m))),
            Distinct::Integer(m) => Arc::new(UInt64Array::from(by_key(m))),
            Distinct::Boolean(m) => Arc::new(BooleanArray::from(by_key(m))),
            Distinct::List(m) => {
                let mut b = ListBuilder::new(StringBuilder::new());
                for l in by_key(m) {
                    for s in &l {
                        b.values().append_value(s);
                    }
                    b.append(true);
                }
                Arc::new(b.finish())
            }
        };
        (self.keys, values)
    }
}

/// The rows of one table, filled once for each twin and table.
pub struct FrameBuilder {
    def: &'static TableDef,
    columns: Vec<ColumnBuilder>,
}

impl FrameBuilder {
    pub fn new(def: &'static TableDef) -> Self {
        let columns = def
            .columns
            .iter()
            .map(|c| ColumnBuilder {
                keys: Vec::new(),
                distinct: match kind(c.kind) {
                    Kind::Text => Distinct::Text(HashMap::new()),
                    Kind::Integer => Distinct::Integer(HashMap::new()),
                    Kind::Boolean => Distinct::Boolean(HashMap::new()),
                    Kind::List => Distinct::List(HashMap::new()),
                },
            })
            .collect();
        FrameBuilder { def, columns }
    }

    /// Adds a row: one cell for each column of the table, in column order.
    pub fn push(&mut self, row: &[Cell]) {
        assert_eq!(row.len(), self.columns.len(), "a row of {}", self.def.name);
        for (c, v) in self.columns.iter_mut().zip(row) {
            c.push(*v);
        }
    }

    /// Adds a row of JSON values: a string, an unsigned integer, a boolean,
    /// a list of strings or null for each column.
    pub fn push_values(&mut self, row: &[Value]) {
        let lists: Vec<Vec<String>> = row
            .iter()
            .map(|v| match v {
                Value::Array(a) => a
                    .iter()
                    .map(|e| {
                        e.as_str()
                            .expect("a list value of a table is a list of strings")
                            .to_string()
                    })
                    .collect(),
                _ => Vec::new(),
            })
            .collect();
        let cells: Vec<Cell> = row
            .iter()
            .zip(&lists)
            .map(|(v, l)| match v {
                Value::Null => Cell::Null,
                Value::String(s) => Cell::Text(s),
                Value::Number(n) => Cell::Integer(
                    n.as_u64()
                        .expect("an integer value of a table is an unsigned integer"),
                ),
                Value::Bool(b) => Cell::Boolean(*b),
                Value::Array(_) => Cell::List(l),
                Value::Object(_) => panic!("a table value is not an object"),
            })
            .collect();
        self.push(&cells);
    }

    /// The frame, with its rows in the key order of the table: the key
    /// columns compare by their text, where `key_text` can give the text of
    /// a string value, and a null compares as `null`; rows with the same
    /// key keep the order in which they were added.
    pub fn finish(self, key_text: &(dyn Fn(&str) -> Option<String> + Sync)) -> Frame {
        let def = self.def;
        let n = self.columns.first().map_or(0, |c| c.keys.len());
        assert!(u32::try_from(n).is_ok(), "fewer than 2^32 rows");
        let parts: Vec<(Kind, Vec<u32>, ArrayRef)> = self
            .columns
            .into_iter()
            .zip(def.columns)
            .map(|(b, c)| {
                let (keys, values) = b.values();
                (kind(c.kind), keys, values)
            })
            .collect();
        let ranks: Vec<(usize, Vec<u32>)> = def
            .key
            .iter()
            .filter_map(|k| def.columns.iter().position(|c| c.name == *k))
            .map(|i| {
                let (kind, _, values) = &parts[i];
                (i, key_ranks(*kind, values, key_text))
            })
            .collect();
        let slot = |k: u32| if k == NULL { 0 } else { k as usize + 1 };
        let mut order: Vec<u32> = (0..n as u32).collect();
        if !ranks.is_empty() {
            order.par_sort_unstable_by(|a, b| {
                ranks
                    .iter()
                    .map(|(i, r)| {
                        let keys = &parts[*i].1;
                        r[slot(keys[*a as usize])].cmp(&r[slot(keys[*b as usize])])
                    })
                    .find(|o| *o != Ordering::Equal)
                    .unwrap_or_else(|| a.cmp(b))
            });
        }
        let columns = parts
            .into_iter()
            .zip(def.columns)
            .map(|((kind, keys, values), c)| {
                let mut counts = vec![0usize; values.len() + 1];
                for k in &keys {
                    counts[slot(*k)] += 1;
                }
                let ordered: UInt32Array = order
                    .iter()
                    .map(|r| {
                        let k = keys[*r as usize];
                        (k != NULL).then_some(k)
                    })
                    .collect();
                FrameColumn {
                    kind,
                    prefixes: kind == Kind::Text
                        && matches!(c.kind, ColumnType::Address | ColumnType::Prefix),
                    data: DictionaryArray::new(ordered, values),
                    counts,
                    order: OnceLock::new(),
                    postings: OnceLock::new(),
                    trie: OnceLock::new(),
                    sorted: OnceLock::new(),
                }
            })
            .collect();
        let device = (def.key.first() == Some(&"device"))
            .then(|| def.columns.iter().position(|c| c.name == "device"))
            .flatten();
        Frame {
            rows: n,
            columns,
            device,
            ranges: OnceLock::new(),
        }
    }
}

/// The dense ranks of the slots of `n` values by `cmp`, with null at rank 0
/// and equal values at the same rank.
fn dense_ranks(n: usize, cmp: impl Fn(usize, usize) -> Ordering + Sync) -> Vec<u32> {
    let mut idx: Vec<usize> = (0..n).collect();
    idx.par_sort_unstable_by(|a, b| cmp(*a, *b));
    let mut ranks = vec![0u32; n + 1];
    let mut rank = 0u32;
    for (j, e) in idx.iter().enumerate() {
        if j == 0 || cmp(idx[j - 1], *e) != Ordering::Equal {
            rank += 1;
        }
        ranks[e + 1] = rank;
    }
    ranks
}

/// The compact JSON text of the list `e` of a list array.
fn list_json(values: &ArrayRef, e: usize) -> String {
    let l = values.as_list::<i32>();
    let items = l.value(e);
    let s = items.as_string::<i32>();
    Value::Array(
        s.iter()
            .map(|x| Value::String(x.unwrap_or_default().to_string()))
            .collect(),
    )
    .to_string()
}

/// The ranks of the slots of a key column: by the text of each value, with
/// null as the text `null`.
fn key_ranks(
    kind: Kind,
    values: &ArrayRef,
    key_text: &(dyn Fn(&str) -> Option<String> + Sync),
) -> Vec<u32> {
    let n = values.len();
    let mut texts: Vec<String> = (0..n)
        .into_par_iter()
        .with_min_len(CHUNK)
        .map(|e| match kind {
            Kind::Text => {
                let s = values.as_string::<i32>().value(e);
                key_text(s).unwrap_or_else(|| s.to_string())
            }
            Kind::Integer => values.as_primitive::<UInt64Type>().value(e).to_string(),
            Kind::Boolean => values.as_boolean().value(e).to_string(),
            Kind::List => list_json(values, e),
        })
        .collect();
    texts.push("null".to_string());
    // The null text is the last value; its rank goes to slot 0.
    let all = dense_ranks(n + 1, |a, b| texts[a].cmp(&texts[b]));
    let mut ranks = Vec::with_capacity(n + 1);
    ranks.push(all[n + 1]);
    ranks.extend_from_slice(&all[1..=n]);
    ranks
}

/// One column of a frame.
pub struct FrameColumn {
    kind: Kind,
    data: DictionaryArray<UInt32Type>,
    /// The number of rows of each slot.
    counts: Vec<usize>,
    /// The ranks of the slots in the order of a sort.
    order: OnceLock<Vec<u32>>,
    /// True for a text column of type address or prefix.
    prefixes: bool,
    /// The rows of each slot: the rows of slot `s` are
    /// `rows[offsets[s]..offsets[s + 1]]`, in row order.
    postings: OnceLock<(Vec<u32>, Vec<u32>)>,
    /// The distinct values that are an address or a prefix, each with the
    /// slots of its texts.
    trie: OnceLock<TriePrefixTable<Vec<u32>>>,
    /// The distinct values of a text column in the order of their text.
    sorted: OnceLock<Vec<u32>>,
}

/// The prefix of `<address>/<length>`, or of an address alone with the full
/// length, with the host bits 0.
fn prefix_of(s: &str) -> Option<Prefix> {
    parse_prefix(s).map(to_prefix)
}

/// The prefix of the parsed `(network, length, width)`, with the host bits
/// 0.
fn to_prefix((a, len, bits): (u128, u32, u32)) -> Prefix {
    let addr = if bits == 32 {
        IpAddr::V4(Ipv4Addr::from(a as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(a))
    };
    Prefix::new(addr, len as u8)
}

impl FrameColumn {
    /// The rows of each slot, built at the first call.
    fn postings(&self) -> (&[u32], &[u32]) {
        let (offsets, rows) = self.postings.get_or_init(|| {
            let mut offsets = Vec::with_capacity(self.counts.len() + 1);
            let mut sum = 0u32;
            offsets.push(0);
            for c in &self.counts {
                sum += *c as u32;
                offsets.push(sum);
            }
            let mut next = offsets.clone();
            let mut rows = vec![0u32; sum as usize];
            for r in 0..sum as usize {
                let s = self.slot(r);
                rows[next[s] as usize] = r as u32;
                next[s] += 1;
            }
            (offsets, rows)
        });
        (offsets, rows)
    }

    /// The prefix table of the distinct values, built at the first call.
    fn trie(&self) -> &TriePrefixTable<Vec<u32>> {
        self.trie.get_or_init(|| {
            let mut by: BTreeMap<Prefix, Vec<u32>> = BTreeMap::new();
            for s in 1..self.slots() {
                if let Some(p) = prefix_of(self.text(s - 1)) {
                    by.entry(p).or_default().push(s as u32);
                }
            }
            let mut t = TriePrefixTable::new();
            for (p, slots) in by {
                t.insert(p, slots);
            }
            t
        })
    }

    /// The mask of the slots whose value is inside `p`.
    fn inside_mask(&self, p: Prefix) -> Vec<bool> {
        let mut mask = vec![false; self.slots()];
        for s in self.inside_slots(p) {
            mask[s as usize] = true;
        }
        mask
    }

    /// The slots whose value is inside `p`, in slot order: an address or a
    /// prefix of the family of `p`, with a length of at least the length of
    /// `p` and its network in `p`.
    fn inside_slots(&self, p: Prefix) -> Vec<u32> {
        let mut out = Vec::new();
        let t = self.trie();
        let Some(root) = t.walk_root(!p.is_ipv4()) else {
            return out;
        };
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            let w = t.walk_node(n);
            let d = w.depth.min(p.len());
            if Prefix::new(w.key, d) != Prefix::new(p.addr(), d) {
                continue;
            }
            if let Some((_, e, slots)) = w.entry
                && e.len() >= p.len()
            {
                out.extend_from_slice(slots);
            }
            stack.extend(w.children.into_iter().flatten());
        }
        out.sort_unstable();
        out
    }

    /// The slots of the prefixes with a `/` that contain `addr`, each with
    /// the length of its prefix.
    fn containing(&self, addr: IpAddr) -> HashMap<usize, u32> {
        let mut out = HashMap::new();
        let t = self.trie();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let mut node = t.walk_root(addr.is_ipv6());
        while let Some(n) = node {
            let w = t.walk_node(n);
            if !Prefix::new(w.key, w.depth).contains(addr) {
                break;
            }
            if let Some((_, e, slots)) = w.entry {
                for s in slots {
                    if self.text(*s as usize - 1).contains('/') {
                        out.insert(*s as usize, u32::from(e.len()));
                    }
                }
            }
            if w.depth >= max {
                break;
            }
            node = w.children[usize::from(addr_bit(addr, w.depth))];
        }
        out
    }

    /// The slot of the value of a row.
    #[inline]
    fn slot(&self, row: usize) -> usize {
        let keys = self.data.keys();
        if keys.is_null(row) {
            0
        } else {
            keys.value(row) as usize + 1
        }
    }

    fn slots(&self) -> usize {
        self.counts.len()
    }

    fn text(&self, e: usize) -> &str {
        self.data.values().as_string::<i32>().value(e)
    }

    fn integer(&self, e: usize) -> u64 {
        self.data.values().as_primitive::<UInt64Type>().value(e)
    }

    fn boolean(&self, e: usize) -> bool {
        self.data.values().as_boolean().value(e)
    }

    /// The elements of the list `e`.
    fn list(&self, e: usize) -> Vec<&str> {
        let l = self.data.values().as_list::<i32>();
        let offsets = l.value_offsets();
        let s: &StringArray = l.values().as_string::<i32>();
        (offsets[e] as usize..offsets[e + 1] as usize)
            .map(|i| s.value(i))
            .collect()
    }

    /// The JSON value of a slot.
    fn json(&self, slot: usize) -> Value {
        if slot == 0 {
            return Value::Null;
        }
        let e = slot - 1;
        match self.kind {
            Kind::Text => Value::String(self.text(e).to_string()),
            Kind::Integer => Value::from(self.integer(e)),
            Kind::Boolean => Value::Bool(self.boolean(e)),
            Kind::List => Value::Array(
                self.list(e)
                    .into_iter()
                    .map(|s| Value::String(s.to_string()))
                    .collect(),
            ),
        }
    }

    /// True if `f` holds for one element of the value of a slot: the value
    /// itself, or one element of a list. `f` takes the text of the element
    /// and its number, if it is a number. Null has no element.
    fn any(&self, slot: usize, f: &dyn Fn(&str, Option<f64>) -> bool) -> bool {
        if slot == 0 {
            return false;
        }
        let e = slot - 1;
        match self.kind {
            Kind::Text => f(self.text(e), None),
            Kind::Integer => {
                let n = self.integer(e);
                f(&n.to_string(), Some(n as f64))
            }
            Kind::Boolean => f(if self.boolean(e) { "true" } else { "false" }, None),
            Kind::List => self.list(e).into_iter().any(|s| f(s, None)),
        }
    }

    /// The slots of a text column whose text is one of `vs`, in slot
    /// order, from the distinct values in the order of their text, built at
    /// the first call.
    fn equal_slots(&self, vs: &[String]) -> Vec<u32> {
        let sorted = self.sorted.get_or_init(|| {
            let mut v: Vec<u32> = (0..self.slots() as u32 - 1).collect();
            v.par_sort_unstable_by(|a, b| self.text(*a as usize).cmp(self.text(*b as usize)));
            v
        });
        let mut slots: Vec<u32> = vs
            .iter()
            .filter_map(|want| {
                let i = sorted
                    .binary_search_by(|e| self.text(*e as usize).cmp(want.as_str()))
                    .ok()?;
                Some(sorted[i] + 1)
            })
            .collect();
        slots.sort_unstable();
        slots.dedup();
        slots
    }

    /// The ranks of the slots for a sort: null first, numbers by their
    /// value and other values by their text, a list by its JSON text.
    fn order(&self) -> &[u32] {
        self.order.get_or_init(|| {
            let n = self.slots() - 1;
            match self.kind {
                Kind::Text => {
                    let idx = arrow_ord::sort::sort_to_indices(self.data.values(), None, None)
                        .expect("a string array sorts");
                    let mut ranks = vec![0u32; n + 1];
                    for (j, e) in idx.values().iter().enumerate() {
                        ranks[*e as usize + 1] = j as u32 + 1;
                    }
                    ranks
                }
                Kind::Integer => dense_ranks(n, |a, b| {
                    (self.integer(a) as f64)
                        .partial_cmp(&(self.integer(b) as f64))
                        .unwrap_or(Ordering::Equal)
                }),
                Kind::Boolean => dense_ranks(n, |a, b| self.boolean(a).cmp(&self.boolean(b))),
                Kind::List => {
                    let texts: Vec<String> = (0..n)
                        .into_par_iter()
                        .with_min_len(CHUNK)
                        .map(|e| list_json(self.data.values(), e))
                        .collect();
                    dense_ranks(n, |a, b| texts[a].cmp(&texts[b]))
                }
            }
        })
    }
}

/// The rows of one table as columns, in key order.
pub struct Frame {
    rows: usize,
    columns: Vec<FrameColumn>,
    /// The column `device` of a table whose first key column is `device`.
    device: Option<usize>,
    /// The rows of each slot of the column `device`, as 1 range for each
    /// slot; none if the rows of a slot are not 1 range.
    ranges: OnceLock<Option<Vec<(u32, u32)>>>,
}

impl Frame {
    /// The row range of each slot of the column `device`, built at the
    /// first call.
    fn ranges(&self) -> Option<&[(u32, u32)]> {
        let d = self.device?;
        self.ranges
            .get_or_init(|| {
                let c = &self.columns[d];
                let mut ranges = vec![(0u32, 0u32); c.slots()];
                let mut seen = vec![false; c.slots()];
                let mut start = 0;
                for r in 1..=self.rows {
                    if r < self.rows && c.slot(r) == c.slot(start) {
                        continue;
                    }
                    let s = c.slot(start);
                    if seen[s] {
                        return None;
                    }
                    seen[s] = true;
                    ranges[s] = (start as u32, r as u32);
                    start = r;
                }
                Some(ranges)
            })
            .as_deref()
    }

    /// The number of rows.
    pub fn len(&self) -> usize {
        self.rows
    }

    pub fn is_empty(&self) -> bool {
        self.rows == 0
    }

    /// The JSON value of a column of a row.
    pub fn value(&self, row: usize, column: usize) -> Value {
        let c = &self.columns[column];
        c.json(c.slot(row))
    }
}

/// The address bits, the length and the address width of
/// `<address>/<length>`, or of an address alone with the full length.
fn parse_prefix(s: &str) -> Option<(u128, u32, u32)> {
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (s, None),
    };
    let (a, bits) = match addr.parse::<IpAddr>().ok()? {
        IpAddr::V4(a) => (u128::from(u32::from(a)), 32),
        IpAddr::V6(a) => (u128::from(a), 128),
    };
    let len = match len {
        Some(l) => l.parse::<u32>().ok().filter(|l| *l <= bits)?,
        None => bits,
    };
    Some((a, len, bits))
}

/// True if `addr`, an address or an `<address>/<length>`, is inside the
/// parsed prefix `(network, length, width)`: a prefix is inside when its
/// length is at least the length of the prefix and its network is in it.
fn inside(addr: &str, (n, len, bits): (u128, u32, u32)) -> bool {
    let Some((a, alen, abits)) = parse_prefix(addr) else {
        return false;
    };
    if abits != bits || alen < len {
        return false;
    }
    let shift = bits - len;
    len == 0 || (a >> shift) == (n >> shift)
}

/// One condition of a filter on the elements of a value.
enum Cond<'a> {
    Eq(&'a [String]),
    Contains(&'a str),
    Prefix(&'a str),
    InPrefix((u128, u32, u32)),
    Gt(f64),
    Lt(f64),
}

impl Cond<'_> {
    fn holds(&self, t: &str, n: Option<f64>) -> bool {
        match self {
            Cond::Eq(vs) => vs.iter().any(|v| v.as_str() == t),
            Cond::Contains(w) => t.contains(*w),
            Cond::Prefix(w) => t.starts_with(*w),
            Cond::InPrefix(p) => inside(t, *p),
            Cond::Gt(w) => n.is_some_and(|x| x > *w),
            Cond::Lt(w) => n.is_some_and(|x| x < *w),
        }
    }
}

/// The slots of a column that a filter keeps: a flag for each slot, or the
/// kept slots in slot order.
enum Mask {
    Dense(Vec<bool>),
    Sparse(Vec<u32>),
}

impl Mask {
    #[inline]
    fn has(&self, slot: usize) -> bool {
        match self {
            Mask::Dense(m) => m[slot],
            Mask::Sparse(v) => v.binary_search(&(slot as u32)).is_ok(),
        }
    }

    /// The kept slots, in slot order.
    fn kept(&self) -> Vec<usize> {
        match self {
            Mask::Dense(m) => m
                .iter()
                .enumerate()
                .filter(|(_, ok)| **ok)
                .map(|(s, _)| s)
                .collect(),
            Mask::Sparse(v) => v.iter().map(|s| *s as usize).collect(),
        }
    }
}

/// The filters of a selection as one mask of slots for each filtered
/// column, and the sort keys.
struct Plan {
    masks: Vec<(usize, Mask)>,
    sort: Vec<(usize, bool)>,
    /// The ranges of rows that hold each matching row, from an index.
    candidates: Option<Vec<(u32, u32)>>,
}

fn index(def: &TableDef, name: &str) -> Result<usize, String> {
    def.columns
        .iter()
        .position(|c| c.name == name)
        .ok_or_else(|| format!("{name} is not a column of {}", def.name))
}

fn plan(def: &TableDef, frame: &Frame, sel: &Selection) -> Result<Plan, String> {
    let mut conds: BTreeMap<usize, Vec<Cond>> = BTreeMap::new();
    for (k, vs) in &sel.filters {
        conds.entry(index(def, k)?).or_default().push(Cond::Eq(vs));
    }
    for (k, v) in &sel.typed {
        let (c, op) = k
            .rsplit_once('.')
            .ok_or_else(|| format!("{k} is not <column>.<op>"))?;
        if !["contains", "prefix", "gt", "lt", "in_prefix"].contains(&op) {
            return Err(format!("{op} is not contains, prefix, gt, lt or in_prefix"));
        }
        let invalid = || format!("{v} is not a value of the filter {k}");
        let cond = match op {
            "in_prefix" => Cond::InPrefix(
                v.contains('/')
                    .then(|| parse_prefix(v))
                    .flatten()
                    .ok_or_else(invalid)?,
            ),
            "gt" | "lt" => {
                let w = v
                    .parse::<f64>()
                    .ok()
                    .filter(|w| w.is_finite())
                    .ok_or_else(invalid)?;
                if op == "gt" { Cond::Gt(w) } else { Cond::Lt(w) }
            }
            "contains" => Cond::Contains(v),
            _ => Cond::Prefix(v),
        };
        conds.entry(index(def, c)?).or_default().push(cond);
    }
    let mut sort = Vec::new();
    for s in sel.sort.iter().flatten() {
        let (desc, name) = match s.strip_prefix('-') {
            Some(n) => (true, n),
            None => (false, s.as_str()),
        };
        sort.push((index(def, name)?, desc));
    }
    let masks: Vec<(usize, Mask)> = conds
        .into_iter()
        .map(|(i, cs)| {
            let col = &frame.columns[i];
            if let [Cond::Eq(vs)] = cs.as_slice()
                && col.kind == Kind::Text
                && col.slots() > CHUNK
            {
                return (i, Mask::Sparse(col.equal_slots(vs)));
            }
            if let [Cond::InPrefix(p)] = cs.as_slice()
                && col.prefixes
            {
                return (i, Mask::Sparse(col.inside_slots(to_prefix(*p))));
            }
            // The masks of the conditions that the prefix table evaluates.
            let indexed: Vec<Option<Vec<bool>>> = cs
                .iter()
                .map(|c| match c {
                    Cond::InPrefix(p) if col.prefixes => Some(col.inside_mask(to_prefix(*p))),
                    _ => None,
                })
                .collect();
            let mask = Mask::Dense(
                (0..col.slots())
                    .into_par_iter()
                    .with_min_len(CHUNK)
                    .map(|s| {
                        cs.iter().zip(&indexed).all(|(c, m)| match m {
                            Some(m) => m[s],
                            None => col.any(s, &|t, n| c.holds(t, n)),
                        })
                    })
                    .collect(),
            );
            (i, mask)
        })
        .collect();
    let candidates = candidates(def, frame, &masks);
    Ok(Plan {
        masks,
        sort,
        candidates,
    })
}

/// The number of rows of the slots of a mask.
fn mask_rows(col: &FrameColumn, mask: &Mask) -> usize {
    mask.kept().into_iter().map(|s| col.counts[s]).sum()
}

/// The ranges of rows that hold each matching row, from the index with the
/// fewest rows: the row range of each device of the mask of the column
/// `device`, or the rows of each value of a sparse mask or of the mask of a
/// column of the semantic type `mac` when they are at most a quarter of the
/// rows. None if no index applies.
fn candidates(def: &TableDef, frame: &Frame, masks: &[(usize, Mask)]) -> Option<Vec<(u32, u32)>> {
    let mut best: Option<(usize, Vec<(u32, u32)>)> = None;
    if let Some(d) = frame.device
        && let Some((_, m)) = masks.iter().find(|(i, _)| *i == d)
        && let Some(ranges) = frame.ranges()
    {
        let mut rs: Vec<(u32, u32)> = m
            .kept()
            .into_iter()
            .map(|s| ranges[s])
            .filter(|r| r.0 < r.1)
            .collect();
        rs.sort_unstable();
        best = Some((mask_rows(&frame.columns[d], m), rs));
    }
    for (i, m) in masks {
        let col = &frame.columns[*i];
        let sparse = matches!(m, Mask::Sparse(_));
        if !sparse && (def.columns[*i].semantic != "mac" || col.kind != Kind::Text) {
            continue;
        }
        let n = mask_rows(col, m);
        if best.as_ref().is_some_and(|(b, _)| *b <= n) || n > frame.rows / 4 {
            continue;
        }
        let (offsets, rows) = col.postings();
        let mut hit: Vec<u32> = m
            .kept()
            .into_iter()
            .flat_map(|s| {
                rows[offsets[s] as usize..offsets[s + 1] as usize]
                    .iter()
                    .copied()
            })
            .collect();
        hit.par_sort_unstable();
        best = Some((n, hit.into_iter().map(|r| (r, r + 1)).collect()));
    }
    best.map(|(_, rs)| rs)
}

impl Plan {
    #[inline]
    fn matches(&self, frame: &Frame, row: usize) -> bool {
        self.masks
            .iter()
            .all(|(i, m)| m.has(frame.columns[*i].slot(row)))
    }

    /// The matching rows that `keep` takes, as a parallel scan of the
    /// candidates of the index, or of all rows.
    fn scan<T: Send>(
        &self,
        frame: &Frame,
        keep: impl Fn(u32) -> Option<T> + Sync + Send,
    ) -> Vec<T> {
        let keep = |r: u32| {
            if self.matches(frame, r as usize) {
                keep(r)
            } else {
                None
            }
        };
        match &self.candidates {
            Some(c) => c
                .par_iter()
                .flat_map_iter(|(a, b)| (*a..*b).filter_map(&keep))
                .collect(),
            None => (0..frame.rows as u32)
                .into_par_iter()
                .with_min_len(CHUNK)
                .filter_map(keep)
                .collect(),
        }
    }

    /// The number of matching rows.
    fn count(&self, frame: &Frame) -> usize {
        match self.masks.as_slice() {
            [] => frame.rows,
            [(i, m)] => mask_rows(&frame.columns[*i], m),
            _ => self.scan(frame, |_| Some(())).len(),
        }
    }

    /// The matching rows, in key order.
    fn rows(&self, frame: &Frame) -> Vec<u32> {
        if self.masks.is_empty() {
            return (0..frame.rows as u32).collect();
        }
        self.scan(frame, Some)
    }

    /// The matching rows from the match `start` to the match before `end`,
    /// in key order. The scan stops at the end of the page.
    fn range(&self, frame: &Frame, start: usize, end: usize) -> Vec<u32> {
        if self.masks.is_empty() {
            return (start as u32..end as u32).collect();
        }
        let mut out = Vec::with_capacity(end - start);
        let mut seen = 0;
        let all = [(0, frame.rows as u32)];
        let ranges = self.candidates.as_deref().unwrap_or(&all);
        for r in ranges.iter().flat_map(|(a, b)| *a..*b) {
            if out.len() == end - start {
                break;
            }
            if self.matches(frame, r as usize) {
                if seen >= start {
                    out.push(r);
                }
                seen += 1;
            }
        }
        out
    }

    /// Puts the first `end` rows in the order of the sort keys, ties in key
    /// order, and drops the rest.
    fn order(&self, frame: &Frame, rows: &mut Vec<u32>, end: usize) {
        if self.sort.is_empty() {
            rows.truncate(end);
            return;
        }
        let keys: Vec<(&FrameColumn, &[u32], bool)> = self
            .sort
            .iter()
            .map(|(i, desc)| {
                let c = &frame.columns[*i];
                (c, c.order(), *desc)
            })
            .collect();
        let cmp = |a: &u32, b: &u32| {
            keys.iter()
                .map(|(c, r, desc)| {
                    let o = r[c.slot(*a as usize)].cmp(&r[c.slot(*b as usize)]);
                    if *desc { o.reverse() } else { o }
                })
                .find(|o| *o != Ordering::Equal)
                .unwrap_or_else(|| a.cmp(b))
        };
        if end < rows.len() {
            if end == 0 {
                rows.clear();
                return;
            }
            rows.select_nth_unstable_by(end, cmp);
            rows.truncate(end);
        }
        rows.par_sort_unstable_by(cmp);
    }
}

/// One page of rows: the column names, the rows, the number of matching
/// rows and the cursor of the next page.
pub struct Page {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub total: usize,
    pub next: Option<String>,
}

/// The columns of the output, with their indexes.
fn projection(def: &TableDef, sel: &Selection) -> Result<(Vec<String>, Vec<usize>), String> {
    let names: Vec<String> = match &sel.columns {
        Some(c) => c.clone(),
        None => def.columns.iter().map(|c| c.name.to_string()).collect(),
    };
    let idx = names
        .iter()
        .map(|n| index(def, n))
        .collect::<Result<_, _>>()?;
    Ok((names, idx))
}

/// The largest number of rows of a page. A selection with no limit or a
/// larger limit gets a page of at most this size.
pub const MAX_ROWS: usize = 10_000;

/// The first and the end match of the page.
fn bounds(sel: &Selection, total: usize) -> Result<(usize, usize), String> {
    let start = match &sel.cursor {
        None => 0,
        Some(c) => c
            .strip_prefix('o')
            .and_then(|n| n.parse::<usize>().ok())
            .filter(|n| *n <= total)
            .ok_or_else(|| format!("{c} is not a cursor of this table"))?,
    };
    let end = match sel.limit {
        Some(0) => return Err("the limit is 0".into()),
        Some(l) => start.saturating_add(l.min(MAX_ROWS)).min(total),
        None => start.saturating_add(MAX_ROWS).min(total),
    };
    Ok((start, end))
}

fn page_of(
    frame: &Frame,
    (names, idx): (Vec<String>, Vec<usize>),
    rows: &[u32],
    total: usize,
    end: usize,
) -> Page {
    let rows = rows
        .iter()
        .map(|r| idx.iter().map(|i| frame.value(*r as usize, *i)).collect())
        .collect();
    Page {
        columns: names,
        rows,
        total,
        next: (end < total).then(|| format!("o{end}")),
    }
}

/// A change of a row between the frames `before` and `after` of 1 table,
/// with the row numbers in each frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Added(u32),
    Removed(u32),
    Changed(u32, u32),
}

/// The text of each slot of a column: slot 0 has the text `null`, and a
/// value has the text of [`key_ranks`].
fn slot_texts(
    c: &FrameColumn,
    key_text: &(dyn Fn(&str) -> Option<String> + Sync),
    null: &str,
) -> Vec<String> {
    let n = c.slots() - 1;
    let mut t = Vec::with_capacity(n + 1);
    t.push(null.to_string());
    for e in 0..n {
        t.push(match c.kind {
            Kind::Text => {
                let s = c.text(e);
                key_text(s).unwrap_or_else(|| s.to_string())
            }
            Kind::Integer => c.integer(e).to_string(),
            Kind::Boolean => c.boolean(e).to_string(),
            Kind::List => list_json(c.data.values(), e),
        });
    }
    t
}

/// The ids of the slots of 1 column in 2 frames: equal texts have equal
/// ids, and the ids are in the order of the texts.
fn joint_ids(a: &[String], b: &[String]) -> (Vec<u32>, Vec<u32>) {
    let mut all: Vec<&str> = a.iter().chain(b).map(String::as_str).collect();
    all.sort_unstable();
    all.dedup();
    let id = |t: &String| all.binary_search(&t.as_str()).unwrap_or(0) as u32;
    (a.iter().map(id).collect(), b.iter().map(id).collect())
}

/// The changes from the frame `before` to the frame `after`, in key order.
/// A key matches the rows with equal key values; a column with the semantic
/// type `source_span` is not compared. In a key with rows on both sides,
/// each row of `before` pairs with a row of `after` with equal values. If 1
/// row is left on each side, it is changed; else each row left in `before`
/// is removed and each row left in `after` is added.
pub fn diff(
    def: &TableDef,
    before: &Frame,
    after: &Frame,
    key_text: &(dyn Fn(&str) -> Option<String> + Sync),
) -> Vec<Change> {
    let keys: Vec<usize> = def
        .key
        .iter()
        .filter_map(|k| def.columns.iter().position(|c| c.name == *k))
        .collect();
    let values: Vec<usize> = (0..def.columns.len())
        .filter(|i| !keys.contains(i) && def.columns[*i].semantic != "source_span")
        .collect();
    // For each column: its index and the ids of its slots in each frame.
    type Ids = Vec<(usize, Vec<u32>, Vec<u32>)>;
    let ids = |cols: &[usize], null: &str| -> Ids {
        cols.iter()
            .map(|i| {
                let a = slot_texts(&before.columns[*i], key_text, null);
                let b = slot_texts(&after.columns[*i], key_text, null);
                let (x, y) = joint_ids(&a, &b);
                (*i, x, y)
            })
            .collect()
    };
    let kid = ids(&keys, "null");
    // A null value is not equal to the text `null`.
    let vid = ids(&values, "\0");
    // The ids of a row of `before` (side 0) or `after` (side 1).
    let id = |ids: &Ids, side: usize, row: usize| -> Vec<u32> {
        ids.iter()
            .map(|(c, x, y)| {
                if side == 0 {
                    x[before.columns[*c].slot(row)]
                } else {
                    y[after.columns[*c].slot(row)]
                }
            })
            .collect()
    };
    let (na, nb) = (before.len(), after.len());
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < na || j < nb {
        let o = if i == na {
            Ordering::Greater
        } else if j == nb {
            Ordering::Less
        } else {
            id(&kid, 0, i).cmp(&id(&kid, 1, j))
        };
        match o {
            Ordering::Less => {
                out.push(Change::Removed(i as u32));
                i += 1;
            }
            Ordering::Greater => {
                out.push(Change::Added(j as u32));
                j += 1;
            }
            Ordering::Equal => {
                let k = id(&kid, 0, i);
                let mut ie = i + 1;
                while ie < na && id(&kid, 0, ie) == k {
                    ie += 1;
                }
                let mut je = j + 1;
                while je < nb && id(&kid, 1, je) == k {
                    je += 1;
                }
                let bv: Vec<Vec<u32>> = (j..je).map(|r| id(&vid, 1, r)).collect();
                let mut used = vec![false; bv.len()];
                let mut left_a = Vec::new();
                for r in i..ie {
                    let v = id(&vid, 0, r);
                    match (0..bv.len()).find(|x| !used[*x] && bv[*x] == v) {
                        Some(x) => used[x] = true,
                        None => left_a.push(r as u32),
                    }
                }
                let left_b: Vec<u32> = (0..bv.len())
                    .filter(|x| !used[*x])
                    .map(|x| (j + x) as u32)
                    .collect();
                if let ([a], [b]) = (left_a.as_slice(), left_b.as_slice()) {
                    out.push(Change::Changed(*a, *b));
                } else {
                    out.extend(left_a.into_iter().map(Change::Removed));
                    out.extend(left_b.into_iter().map(Change::Added));
                }
                i = ie;
                j = je;
            }
        }
    }
    out
}

/// One page of the changes of a table, with the counts of all changes.
pub struct DiffPage {
    pub columns: Vec<String>,
    pub rows: Vec<DiffRow>,
    pub counts: DiffCounts,
    pub total: usize,
    pub next: Option<String>,
}

/// The page of the changes from `before` to `after`, with at most
/// [`MAX_ROWS`] rows. The selection takes only `columns`, `limit` and
/// `cursor`.
pub fn diff_page(
    def: &TableDef,
    before: &Frame,
    after: &Frame,
    sel: &Selection,
    key_text: &(dyn Fn(&str) -> Option<String> + Sync),
) -> Result<DiffPage, String> {
    if !sel.filters.is_empty() || !sel.typed.is_empty() || sel.sort.is_some() {
        return Err("a difference takes only columns, limit and cursor".into());
    }
    let (names, idx) = projection(def, sel)?;
    let changes = diff(def, before, after, key_text);
    let mut counts = DiffCounts::default();
    for c in &changes {
        match c {
            Change::Added(_) => counts.added += 1,
            Change::Removed(_) => counts.removed += 1,
            Change::Changed(..) => counts.changed += 1,
        }
    }
    let total = changes.len();
    let (start, end) = bounds(sel, total)?;
    let row =
        |f: &Frame, r: u32| -> Vec<Value> { idx.iter().map(|i| f.value(r as usize, *i)).collect() };
    let rows = changes[start..end]
        .iter()
        .map(|c| match *c {
            Change::Added(b) => DiffRow {
                change: RowChange::Added,
                row: row(after, b),
                before: None,
            },
            Change::Removed(a) => DiffRow {
                change: RowChange::Removed,
                row: row(before, a),
                before: None,
            },
            Change::Changed(a, b) => DiffRow {
                change: RowChange::Changed,
                row: row(after, b),
                before: Some(row(before, a)),
            },
        })
        .collect();
    Ok(DiffPage {
        columns: names,
        rows,
        counts,
        total,
        next: (end < total).then(|| format!("o{end}")),
    })
}

/// The page of the rows that match the filters, in the order of the
/// selection, with at most [`MAX_ROWS`] rows. An error names a column, an
/// op, a filter value, a cursor or a limit that is not valid.
pub fn show(def: &TableDef, frame: &Frame, sel: &Selection) -> Result<Page, String> {
    let plan = plan(def, frame, sel)?;
    let proj = projection(def, sel)?;
    if plan.sort.is_empty() {
        let total = plan.count(frame);
        let (start, end) = bounds(sel, total)?;
        let rows = plan.range(frame, start, end);
        return Ok(page_of(frame, proj, &rows, total, end));
    }
    let mut rows = plan.rows(frame);
    let total = rows.len();
    let (start, end) = bounds(sel, total)?;
    plan.order(frame, &mut rows, end);
    Ok(page_of(frame, proj, &rows[start..], total, end))
}

/// The page of the matching rows whose column `column`, of type prefix,
/// holds the longest prefix that contains `address`. An error names a
/// column that is not a prefix column or an address that is not valid.
pub fn lpm(
    def: &TableDef,
    frame: &Frame,
    sel: &Selection,
    column: &str,
    address: &str,
) -> Result<Page, String> {
    let mut plan = plan(def, frame, sel)?;
    let i = def
        .columns
        .iter()
        .position(|c| c.name == column && c.kind == ColumnType::Prefix)
        .ok_or_else(|| format!("{column} is not a prefix column of {}", def.name))?;
    let addr = address
        .parse::<IpAddr>()
        .map_err(|_| format!("{address} is not an address"))?;
    let proj = projection(def, sel)?;
    let col = &frame.columns[i];
    // The length of the prefix of each slot that contains the address.
    let hit = col.containing(addr);
    let mut kept: Vec<u32> = hit.keys().map(|s| *s as u32).collect();
    kept.sort_unstable();
    plan.masks.push((i, Mask::Sparse(kept)));
    let rows = plan.rows(frame);
    let best = rows
        .iter()
        .filter_map(|r| hit.get(&col.slot(*r as usize)))
        .max()
        .copied();
    let mut rows: Vec<u32> = match best {
        Some(b) => rows
            .into_iter()
            .filter(|r| hit.get(&col.slot(*r as usize)) == Some(&b))
            .collect(),
        None => Vec::new(),
    };
    let total = rows.len();
    let (start, end) = bounds(sel, total)?;
    plan.order(frame, &mut rows, end);
    Ok(page_of(frame, proj, &rows[start..], total, end))
}

/// The entries of a count, the most frequent first, then in the order of
/// the JSON text of the key.
fn by_count<K: Send>(mut v: Vec<(K, String, usize)>) -> Vec<(K, usize)> {
    v.par_sort_unstable_by(|a, b| b.2.cmp(&a.2).then_with(|| a.1.cmp(&b.1)));
    v.into_iter().map(|(k, _, n)| (k, n)).collect()
}

/// The distinct values of the columns `names` in the matching rows, with
/// their counts, the most frequent first, then in the order of their JSON
/// text.
pub fn unique(
    def: &TableDef,
    frame: &Frame,
    sel: &Selection,
    names: &[String],
) -> Result<Vec<Vec<Value>>, String> {
    let plan = plan(def, frame, sel)?;
    let idx: Vec<usize> = names
        .iter()
        .map(|n| index(def, n))
        .collect::<Result<_, _>>()?;
    let counts: Vec<(Vec<usize>, usize)> = match idx.as_slice() {
        [i] => {
            let c = &frame.columns[*i];
            let counts = if plan.masks.is_empty() {
                c.counts.clone()
            } else {
                let mut counts = vec![0usize; c.slots()];
                for r in plan.rows(frame) {
                    counts[c.slot(r as usize)] += 1;
                }
                counts
            };
            counts
                .into_iter()
                .enumerate()
                .filter(|(_, n)| *n > 0)
                .map(|(s, n)| (vec![s], n))
                .collect()
        }
        _ => {
            let mut map: HashMap<Vec<usize>, usize> = HashMap::new();
            let mut key = Vec::with_capacity(idx.len());
            for r in plan.rows(frame) {
                key.clear();
                key.extend(idx.iter().map(|i| frame.columns[*i].slot(r as usize)));
                match map.get_mut(key.as_slice()) {
                    Some(n) => *n += 1,
                    None => {
                        map.insert(key.clone(), 1);
                    }
                }
            }
            map.into_iter().collect()
        }
    };
    let keyed: Vec<(Vec<Value>, String, usize)> = counts
        .into_par_iter()
        .with_min_len(CHUNK)
        .map(|(slots, n)| {
            let key: Vec<Value> = idx
                .iter()
                .zip(&slots)
                .map(|(i, s)| frame.columns[*i].json(*s))
                .collect();
            let text = serde_json::to_string(&key).unwrap_or_default();
            (key, text, n)
        })
        .collect();
    Ok(by_count(keyed)
        .into_iter()
        .map(|(mut k, n)| {
            k.push(Value::from(n));
            k
        })
        .collect())
}

/// The at most 5 most frequent values of `counts`, then in the order of
/// their JSON text; only the values with a count of at least the fifth
/// count get a JSON text.
fn top5<K: Send>(
    counts: Vec<(K, usize)>,
    json: impl Fn(&K) -> Value + Sync,
) -> Vec<(Value, usize)> {
    let mut sizes: Vec<usize> = counts.iter().map(|c| c.1).collect();
    let floor = if sizes.len() > 5 {
        *sizes.select_nth_unstable_by(4, |a, b| b.cmp(a)).1
    } else {
        0
    };
    let keyed: Vec<(Value, String, usize)> = counts
        .into_par_iter()
        .filter(|c| c.1 >= floor)
        .map(|(k, n)| {
            let v = json(&k);
            let text = serde_json::to_string(&v).unwrap_or_default();
            (v, text, n)
        })
        .collect();
    let mut top = by_count(keyed);
    top.truncate(5);
    top
}

/// The number of matching rows and the counts of each column.
pub fn summarize(
    def: &TableDef,
    frame: &Frame,
    sel: &Selection,
) -> Result<(usize, Vec<ColumnSummary>), String> {
    let plan = plan(def, frame, sel)?;
    let rows = (!plan.masks.is_empty()).then(|| plan.rows(frame));
    let total = rows.as_ref().map_or(frame.rows, Vec::len);
    let columns = def
        .columns
        .par_iter()
        .zip(frame.columns.par_iter())
        .map(|(d, c)| {
            let counts = match &rows {
                None => c.counts.clone(),
                Some(rows) => {
                    let mut counts = vec![0usize; c.slots()];
                    for r in rows {
                        counts[c.slot(*r as usize)] += 1;
                    }
                    counts
                }
            };
            let nulls = counts[0];
            let (distinct, top) = if c.kind == Kind::List {
                let mut elements: HashMap<&str, usize> = HashMap::new();
                for (s, n) in counts.iter().enumerate().skip(1) {
                    if *n > 0 {
                        for e in c.list(s - 1) {
                            *elements.entry(e).or_default() += n;
                        }
                    }
                }
                let distinct = elements.len();
                let top = top5(elements.into_iter().collect(), |e| {
                    Value::String(e.to_string())
                });
                (distinct, top)
            } else {
                let present: Vec<(usize, usize)> = counts
                    .iter()
                    .enumerate()
                    .skip(1)
                    .filter(|(_, n)| **n > 0)
                    .map(|(s, n)| (s, *n))
                    .collect();
                (present.len(), top5(present, |s| c.json(*s)))
            };
            ColumnSummary {
                column: d.name.to_string(),
                distinct,
                nulls,
                top,
            }
        })
        .collect();
    Ok((total, columns))
}

/// The rows of an export: the column names, the column indexes and each
/// matching row in the order of the selection. An export takes no limit and
/// no cursor.
pub struct Export {
    pub columns: Vec<String>,
    index: Vec<usize>,
    pub rows: Vec<u32>,
}

/// All matching rows in the order of the selection. An error names a
/// column, an op or a filter value that is not valid, or a limit or a
/// cursor.
pub fn export(def: &TableDef, frame: &Frame, sel: &Selection) -> Result<Export, String> {
    if sel.limit.is_some() || sel.cursor.is_some() {
        return Err("an export takes no limit and no cursor".into());
    }
    let plan = plan(def, frame, sel)?;
    let (columns, index) = projection(def, sel)?;
    let mut rows = plan.rows(frame);
    let n = rows.len();
    plan.order(frame, &mut rows, n);
    Ok(Export {
        columns,
        index,
        rows,
    })
}

/// Adds a CSV field: a text with a comma, a quote, a CR or an LF, and the
/// empty text, in quotes with each quote doubled.
fn csv_field(out: &mut String, s: &str) {
    if s.is_empty() || s.contains([',', '"', '\r', '\n']) {
        out.push('"');
        out.push_str(&s.replace('"', "\"\""));
        out.push('"');
    } else {
        out.push_str(s);
    }
}

/// The rows of an export as CSV (RFC 4180): a header line with the column
/// names, then 1 line for each row, each line with CR LF at its end. A null
/// is an empty field, and a list is its JSON text.
pub fn csv(frame: &Frame, e: &Export) -> Vec<u8> {
    let mut out = String::new();
    for (j, name) in e.columns.iter().enumerate() {
        if j > 0 {
            out.push(',');
        }
        csv_field(&mut out, name);
    }
    out.push_str("\r\n");
    for r in &e.rows {
        for (j, i) in e.index.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            let c = &frame.columns[*i];
            let s = c.slot(*r as usize);
            if s == 0 {
                continue;
            }
            match c.kind {
                Kind::Text => csv_field(&mut out, c.text(s - 1)),
                Kind::Integer => out.push_str(&c.integer(s - 1).to_string()),
                Kind::Boolean => out.push_str(if c.boolean(s - 1) { "true" } else { "false" }),
                Kind::List => csv_field(&mut out, &list_json(c.data.values(), s - 1)),
            }
        }
        out.push_str("\r\n");
    }
    out.into_bytes()
}

/// The values of a column for some rows as a plain Arrow array.
fn plain(c: &FrameColumn, rows: &[u32]) -> ArrayRef {
    let slot = |r: &u32| c.slot(*r as usize).checked_sub(1);
    match c.kind {
        Kind::Text => Arc::new(StringArray::from_iter(
            rows.iter().map(|r| slot(r).map(|e| c.text(e))),
        )),
        Kind::Integer => Arc::new(UInt64Array::from_iter(
            rows.iter().map(|r| slot(r).map(|e| c.integer(e))),
        )),
        Kind::Boolean => Arc::new(BooleanArray::from_iter(
            rows.iter().map(|r| slot(r).map(|e| c.boolean(e))),
        )),
        Kind::List => {
            let mut b = ListBuilder::new(StringBuilder::new());
            for r in rows {
                match slot(r) {
                    None => b.append(false),
                    Some(e) => {
                        for v in c.list(e) {
                            b.values().append_value(v);
                        }
                        b.append(true);
                    }
                }
            }
            Arc::new(b.finish())
        }
    }
}

/// The rows of an export as a Parquet file with Snappy compression: 1
/// column for each column of the export, text as UTF-8, an integer as an
/// unsigned 64-bit integer, a list as a list of UTF-8 texts, and each
/// column nullable.
pub fn parquet(frame: &Frame, e: &Export) -> Result<Vec<u8>, String> {
    use arrow_schema::{DataType, Field, Schema};
    use parquet::arrow::ArrowWriter;
    use parquet::basic::Compression;
    use parquet::file::properties::WriterProperties;

    let fields: Vec<Field> = e
        .index
        .iter()
        .zip(&e.columns)
        .map(|(i, name)| {
            let t = match frame.columns[*i].kind {
                Kind::Text => DataType::Utf8,
                Kind::Integer => DataType::UInt64,
                Kind::Boolean => DataType::Boolean,
                Kind::List => DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            };
            Field::new(name, t, true)
        })
        .collect();
    let schema = Arc::new(Schema::new(fields));
    let props = WriterProperties::builder()
        .set_compression(Compression::SNAPPY)
        .set_created_by("rsim".to_string())
        .build();
    let mut buf = Vec::new();
    let mut w =
        ArrowWriter::try_new(&mut buf, schema.clone(), Some(props)).map_err(|e| e.to_string())?;
    for rows in e.rows.chunks(CHUNK) {
        let columns: Vec<ArrayRef> = e
            .index
            .iter()
            .map(|i| plain(&frame.columns[*i], rows))
            .collect();
        let batch = RecordBatch::try_new(schema.clone(), columns).map_err(|e| e.to_string())?;
        w.write(&batch).map_err(|e| e.to_string())?;
    }
    w.close().map_err(|e| e.to_string())?;
    Ok(buf)
}

#[cfg(test)]
mod tests;
