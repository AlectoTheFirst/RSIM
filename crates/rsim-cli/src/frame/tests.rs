use super::*;
use rsim_contract::table;
use serde_json::json;

/// The selection on rows of JSON values, one value for each column: the
/// oracle of the selection on columns.
mod oracle {
    use super::super::parse_prefix;
    use rsim_contract::table::{ColumnSummary, ColumnType, Selection, TableDef};
    use serde_json::Value;
    use std::cmp::Ordering;
    use std::collections::BTreeMap;
    use std::net::IpAddr;

    fn text(v: &Value) -> String {
        match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        }
    }

    fn values(v: &Value) -> Vec<&Value> {
        match v {
            Value::Array(a) => a.iter().collect(),
            Value::Null => Vec::new(),
            other => vec![other],
        }
    }

    fn in_prefix(addr: &str, prefix: &str) -> Option<bool> {
        let (a, alen, abits) = parse_prefix(addr)?;
        if !prefix.contains('/') {
            return None;
        }
        let (n, len, bits) = parse_prefix(prefix)?;
        if abits != bits || alen < len {
            return Some(false);
        }
        let shift = bits - len;
        Some(len == 0 || (a >> shift) == (n >> shift))
    }

    fn compare(a: &Value, b: &Value) -> Ordering {
        match (a, b) {
            (Value::Number(x), Value::Number(y)) => x
                .as_f64()
                .partial_cmp(&y.as_f64())
                .unwrap_or(Ordering::Equal),
            (Value::Null, Value::Null) => Ordering::Equal,
            (Value::Null, _) => Ordering::Less,
            (_, Value::Null) => Ordering::Greater,
            _ => text(a).cmp(&text(b)),
        }
    }

    fn index(def: &TableDef, name: &str) -> Result<usize, String> {
        def.columns
            .iter()
            .position(|c| c.name == name)
            .ok_or_else(|| format!("{name} is not a column of {}", def.name))
    }

    pub fn key_order(def: &TableDef, rows: &mut [Vec<Value>]) {
        let key: Vec<usize> = def
            .key
            .iter()
            .filter_map(|k| def.columns.iter().position(|c| c.name == *k))
            .collect();
        let sort_text = |v: &Value| -> String {
            match v.as_str().and_then(crate::tables::key_text) {
                Some(t) => t,
                None => text(v),
            }
        };
        rows.sort_by_cached_key(|r| key.iter().map(|i| sort_text(&r[*i])).collect::<Vec<_>>());
    }

    pub fn filter(
        def: &TableDef,
        rows: &[Vec<Value>],
        sel: &Selection,
    ) -> Result<Vec<Vec<Value>>, String> {
        let mut eq = Vec::new();
        for (k, vs) in &sel.filters {
            eq.push((index(def, k)?, vs));
        }
        let mut typed = Vec::new();
        for (k, v) in &sel.typed {
            let (c, op) = k
                .rsplit_once('.')
                .ok_or_else(|| format!("{k} is not <column>.<op>"))?;
            if !["contains", "prefix", "gt", "lt", "in_prefix"].contains(&op) {
                return Err(format!("{op} is not contains, prefix, gt, lt or in_prefix"));
            }
            let valid = match op {
                "in_prefix" => v.contains('/') && parse_prefix(v).is_some(),
                "gt" | "lt" => v.parse::<f64>().is_ok_and(f64::is_finite),
                _ => true,
            };
            if !valid {
                return Err(format!("{v} is not a value of the filter {k}"));
            }
            typed.push((index(def, c)?, op, v));
        }
        let mut out: Vec<Vec<Value>> = Vec::new();
        for r in rows {
            let ok_eq = eq
                .iter()
                .all(|(i, vs)| values(&r[*i]).iter().any(|v| vs.contains(&text(v))));
            let ok_typed = typed.iter().all(|(i, op, want)| {
                values(&r[*i]).iter().any(|v| {
                    let t = text(v);
                    match *op {
                        "contains" => t.contains(want.as_str()),
                        "prefix" => t.starts_with(want.as_str()),
                        "in_prefix" => in_prefix(&t, want) == Some(true),
                        "gt" | "lt" => match (v.as_f64(), want.parse::<f64>()) {
                            (Some(x), Ok(w)) if *op == "gt" => x > w,
                            (Some(x), Ok(w)) => x < w,
                            _ => false,
                        },
                        _ => false,
                    }
                })
            });
            if ok_eq && ok_typed {
                out.push(r.clone());
            }
        }
        if let Some(sort) = &sel.sort {
            let mut keys = Vec::new();
            for s in sort {
                let (desc, name) = match s.strip_prefix('-') {
                    Some(n) => (true, n),
                    None => (false, s.as_str()),
                };
                keys.push((index(def, name)?, desc));
            }
            out.sort_by(|a, b| {
                keys.iter()
                    .map(|(i, desc)| {
                        let o = compare(&a[*i], &b[*i]);
                        if *desc { o.reverse() } else { o }
                    })
                    .find(|o| *o != Ordering::Equal)
                    .unwrap_or(Ordering::Equal)
            });
        }
        Ok(out)
    }

    #[allow(clippy::type_complexity)]
    pub fn page(
        def: &TableDef,
        matching: Vec<Vec<Value>>,
        sel: &Selection,
    ) -> Result<(Vec<String>, Vec<Vec<Value>>, usize, Option<String>), String> {
        let names: Vec<String> = match &sel.columns {
            Some(c) => c.clone(),
            None => def.columns.iter().map(|c| c.name.to_string()).collect(),
        };
        let mut idx = Vec::new();
        for n in &names {
            idx.push(index(def, n)?);
        }
        let total = matching.len();
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
            Some(l) => start.saturating_add(l).min(total),
            None => total,
        };
        let rows = matching[start..end]
            .iter()
            .map(|r| idx.iter().map(|i| r[*i].clone()).collect())
            .collect();
        let next = (end < total).then(|| format!("o{end}"));
        Ok((names, rows, total, next))
    }

    pub fn unique(
        def: &TableDef,
        matching: &[Vec<Value>],
        names: &[String],
    ) -> Result<Vec<Vec<Value>>, String> {
        let mut idx = Vec::new();
        for n in names {
            idx.push(index(def, n)?);
        }
        let mut counts: BTreeMap<String, (Vec<Value>, usize)> = BTreeMap::new();
        for r in matching {
            let key: Vec<Value> = idx.iter().map(|i| r[*i].clone()).collect();
            let k = serde_json::to_string(&key).unwrap_or_default();
            counts.entry(k).or_insert((key, 0)).1 += 1;
        }
        let mut v: Vec<(Vec<Value>, usize)> = counts.into_values().collect();
        v.sort_by_key(|x| std::cmp::Reverse(x.1));
        Ok(v.into_iter()
            .map(|(mut k, n)| {
                k.push(Value::from(n));
                k
            })
            .collect())
    }

    pub fn summarize(def: &TableDef, matching: &[Vec<Value>]) -> Vec<ColumnSummary> {
        def.columns
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let mut counts: BTreeMap<String, (Value, usize)> = BTreeMap::new();
                let mut nulls = 0;
                for r in matching {
                    if r[i].is_null() {
                        nulls += 1;
                        continue;
                    }
                    for v in values(&r[i]) {
                        let k = serde_json::to_string(v).unwrap_or_default();
                        counts.entry(k).or_insert((v.clone(), 0)).1 += 1;
                    }
                }
                let distinct = counts.len();
                let mut top: Vec<(Value, usize)> = counts.into_values().collect();
                top.sort_by_key(|x| std::cmp::Reverse(x.1));
                top.truncate(5);
                ColumnSummary {
                    column: c.name.to_string(),
                    distinct,
                    nulls,
                    top,
                }
            })
            .collect()
    }

    pub fn lpm(
        def: &TableDef,
        matching: &[Vec<Value>],
        column: &str,
        address: &str,
    ) -> Result<Vec<Vec<Value>>, String> {
        let i = def
            .columns
            .iter()
            .position(|c| c.name == column && c.kind == ColumnType::Prefix)
            .ok_or_else(|| format!("{column} is not a prefix column of {}", def.name))?;
        address
            .parse::<IpAddr>()
            .map_err(|_| format!("{address} is not an address"))?;
        let len = |v: &Value| -> Option<u32> {
            let t = text(v);
            let (_, l) = t.split_once('/')?;
            l.parse().ok()
        };
        let best = matching
            .iter()
            .filter(|r| in_prefix(address, &text(&r[i])) == Some(true))
            .filter_map(|r| len(&r[i]))
            .max();
        Ok(matching
            .iter()
            .filter(|r| {
                in_prefix(address, &text(&r[i])) == Some(true)
                    && best.is_some()
                    && len(&r[i]) == best
            })
            .cloned()
            .collect())
    }
}

/// A small deterministic generator.
struct Gen(u64);

impl Gen {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a>(&mut self, v: &[&'a str]) -> &'a str {
        v[self.below(v.len())]
    }
}

const TEXTS: &[&str] = &[
    "r1",
    "r2",
    "a",
    "a b",
    "a!",
    "\"q\"",
    "10.0.0.0/8",
    "null",
    "",
    "x/y",
    "9",
    "10",
    "true",
    "eth0",
];
const PREFIXES: &[&str] = &[
    "10.0.0.0/24",
    "10.0.0.0/16",
    "10.0.1.0/24",
    "192.0.2.0/24",
    "2001:db8::/32",
    "2001:db8::/48",
    "0.0.0.0/0",
    "10.0.0.7/32",
    "10.0.0.0/8",
];
const ADDRESSES: &[&str] = &["10.0.0.7", "192.0.2.1", "2001:db8::1", "10.0.1.9"];
const ELEMENTS: &[&str] = &[
    "eth0",
    "10.0.0.1@eth0",
    "a b",
    "\"q\"",
    "9",
    "10.0.0.0/8",
    "a",
];
const WORDS: &[&str] = &[
    "r1",
    "a",
    "a b",
    "9",
    "10",
    "eth0",
    "null",
    "true",
    "10.0.0.0/8",
    "1",
    "0",
    "x",
];

fn value(g: &mut Gen, t: ColumnType) -> Value {
    if g.below(6) == 0 && t != ColumnType::List {
        return Value::Null;
    }
    match t {
        ColumnType::Text => json!(g.pick(TEXTS)),
        ColumnType::Prefix => json!(g.pick(PREFIXES)),
        ColumnType::Address => json!(g.pick(ADDRESSES)),
        ColumnType::Integer => json!([0u64, 9, 10, 100, 64501, 7][g.below(6)]),
        ColumnType::Boolean => json!(g.below(2) == 0),
        ColumnType::List => {
            let n = g.below(4);
            Value::from((0..n).map(|_| g.pick(ELEMENTS)).collect::<Vec<_>>())
        }
    }
}

fn column(g: &mut Gen, def: &TableDef) -> String {
    if g.below(40) == 0 {
        "colour".into()
    } else {
        def.columns[g.below(def.columns.len())].name.to_string()
    }
}

fn selection(g: &mut Gen, def: &TableDef, n: usize) -> Selection {
    let mut sel = Selection::default();
    for _ in 0..g.below(3) {
        let c = column(g, def);
        let vs = (0..1 + g.below(2))
            .map(|_| g.pick(WORDS).to_string())
            .collect();
        sel.filters.insert(c, vs);
    }
    for _ in 0..g.below(3) {
        let c = column(g, def);
        let op = g.pick(&["contains", "prefix", "gt", "lt", "in_prefix", "like"]);
        let v = match op {
            "in_prefix" => g.pick(&["10.0.0.0/8", "0.0.0.0/0", "2001:db8::/32", "10.0.0.1"]),
            "gt" | "lt" => g.pick(&["5", "9.5", "0", "ten", "64501"]),
            _ => g.pick(WORDS),
        };
        sel.typed.insert(format!("{c}.{op}"), v.to_string());
    }
    if g.below(2) == 0 {
        sel.sort = Some(
            (0..1 + g.below(3))
                .map(|_| {
                    let c = column(g, def);
                    if g.below(2) == 0 { format!("-{c}") } else { c }
                })
                .collect(),
        );
    }
    if g.below(4) == 0 {
        sel.columns = Some((0..1 + g.below(3)).map(|_| column(g, def)).collect());
    }
    sel.limit = match g.below(5) {
        0 => None,
        1 => Some(0),
        2 => Some(usize::MAX),
        _ => Some(1 + g.below(5)),
    };
    sel.cursor = match g.below(4) {
        0 => Some(format!("o{}", g.below(n + 3))),
        1 if g.below(4) == 0 => Some("x".into()),
        _ => None,
    };
    sel
}

fn frame_of(def: &'static TableDef, rows: &[Vec<Value>]) -> Frame {
    let mut b = FrameBuilder::new(def);
    for r in rows {
        b.push_values(r);
    }
    b.finish(&crate::tables::key_text)
}

#[allow(clippy::type_complexity)]
fn page_parts(p: Page) -> (Vec<String>, Vec<Vec<Value>>, usize, Option<String>) {
    (p.columns, p.rows, p.total, p.next)
}

#[test]
fn the_selection_on_columns_gives_the_answer_of_the_selection_on_json_rows() {
    let mut g = Gen(0x9e37_79b9_7f4a_7c15);
    for name in ["fib", "bgp-sessions", "coverage", "devices"] {
        let def = table::table(name).unwrap();
        for round in 0..62 {
            // The last rounds have tables of many chunks of a parallel scan.
            let n = if round >= 60 {
                3000
            } else {
                [0, 1, 3, 12, 40, 150][round % 6]
            };
            let rows: Vec<Vec<Value>> = (0..n)
                .map(|_| def.columns.iter().map(|c| value(&mut g, c.kind)).collect())
                .collect();
            let frame = frame_of(def, &rows);
            let mut keyed = rows.clone();
            oracle::key_order(def, &mut keyed);
            for _ in 0..40 {
                let sel = selection(&mut g, def, n);
                let want =
                    oracle::filter(def, &keyed, &sel).and_then(|m| oracle::page(def, m, &sel));
                let got = show(def, &frame, &sel).map(page_parts);
                assert_eq!(got, want, "{name} show {sel:?}");

                let names: Vec<String> = sel
                    .columns
                    .clone()
                    .unwrap_or_else(|| vec![column(&mut g, def)]);
                let want =
                    oracle::filter(def, &keyed, &sel).and_then(|m| oracle::unique(def, &m, &names));
                let got = unique(def, &frame, &sel, &names);
                assert_eq!(got, want, "{name} unique {names:?} {sel:?}");

                let as_json = |r: Result<(usize, Vec<ColumnSummary>), String>| {
                    r.map(|(n, c)| (n, serde_json::to_string(&c).unwrap()))
                };
                let want = oracle::filter(def, &keyed, &sel)
                    .map(|m| (m.len(), oracle::summarize(def, &m)));
                let got = summarize(def, &frame, &sel);
                assert_eq!(as_json(got), as_json(want), "{name} summarize {sel:?}");

                let column = g.pick(&["prefix", "range", "device", "nope"]);
                let address = g.pick(&["10.0.0.7", "10.0.1.1", "2001:db8::5", "8.8.8.8", "ten"]);
                let want = oracle::filter(def, &keyed, &sel)
                    .and_then(|m| oracle::lpm(def, &m, column, address))
                    .and_then(|m| oracle::page(def, m, &sel));
                let got = lpm(def, &frame, &sel, column, address).map(page_parts);
                assert_eq!(got, want, "{name} lpm {column} {address} {sel:?}");
            }
        }
    }
}

fn fib_rows() -> Vec<Vec<Value>> {
    let row = |d: &str, vrf: &str, p: &str, kind: &str, hop: &str| {
        vec![
            json!(d),
            json!(vrf),
            json!(p),
            json!(kind),
            json!(format!("{d}/route")),
            json!([hop]),
            json!([]),
        ]
    };
    vec![
        row("r1", "default", "10.0.0.0/24", "static", "10.0.0.1@eth0"),
        row("r1", "default", "10.0.1.0/24", "connected", "eth1"),
        row("r2", "blue", "192.0.2.0/24", "static", "192.0.2.1@eth0"),
        row("r1", "default", "10.0.0.0/16", "static", "10.0.0.9@eth0"),
    ]
}

#[test]
fn the_rows_are_in_key_order_with_the_prefixes_in_numeric_order() {
    let def = table::table("fib").unwrap();
    let f = frame_of(def, &fib_rows());
    let prefixes: Vec<Value> = (0..f.len()).map(|r| f.value(r, 2)).collect();
    assert_eq!(
        prefixes,
        vec![
            json!("10.0.0.0/16"),
            json!("10.0.0.0/24"),
            json!("10.0.1.0/24"),
            json!("192.0.2.0/24")
        ]
    );
}

#[test]
fn filters_sort_and_pages_select_rows() {
    let def = table::table("fib").unwrap();
    let f = frame_of(def, &fib_rows());
    let mut sel = Selection::default();
    sel.filters.insert("device".into(), vec!["r1".into()]);
    assert_eq!(show(def, &f, &sel).unwrap().total, 3);
    sel.typed
        .insert("prefix.in_prefix".into(), "10.0.1.0/24".into());
    assert_eq!(show(def, &f, &sel).unwrap().total, 1);
    let sel = Selection {
        sort: Some(vec!["-prefix".into()]),
        limit: Some(2),
        ..Selection::default()
    };
    let page1 = show(def, &f, &sel).unwrap();
    assert_eq!(
        (page1.columns.len(), page1.rows.len(), page1.total),
        (7, 2, 4)
    );
    assert_eq!(page1.rows[0][2], json!("192.0.2.0/24"));
    let sel2 = Selection {
        cursor: page1.next.clone(),
        ..sel.clone()
    };
    let page2 = show(def, &f, &sel2).unwrap();
    assert_eq!(page2.rows.len(), 2);
    assert_eq!(page2.next, None);
    let all = Selection {
        sort: sel.sort.clone(),
        ..Selection::default()
    };
    let all = show(def, &f, &all).unwrap();
    let mut joined = page1.rows;
    joined.extend(page2.rows);
    assert_eq!(joined, all.rows);
}

#[test]
fn a_column_an_op_or_a_value_that_the_table_does_not_have_is_an_error() {
    let def = table::table("fib").unwrap();
    let f = frame_of(def, &fib_rows());
    let mut sel = Selection::default();
    sel.filters.insert("colour".into(), vec!["red".into()]);
    assert!(show(def, &f, &sel).is_err());
    for (k, v) in [
        ("prefix.like", "10"),
        ("prefix.in_prefix", "10.0.0.10"),
        ("prefix.in_prefix", "10.0.0.0/33"),
        ("prefix.in_prefix", "ten/8"),
        ("prefix.gt", "ten"),
        ("prefix.lt", "nan"),
        ("prefix.gt", "inf"),
    ] {
        let mut sel = Selection::default();
        sel.typed.insert(k.into(), v.into());
        assert!(show(def, &f, &sel).is_err(), "{k}={v}");
    }
}

#[test]
fn the_largest_limit_after_a_cursor_gives_the_rest_of_the_rows() {
    let def = table::table("fib").unwrap();
    let f = frame_of(def, &fib_rows());
    let sel = Selection {
        limit: Some(usize::MAX),
        cursor: Some("o1".into()),
        ..Selection::default()
    };
    let p = show(def, &f, &sel).unwrap();
    assert_eq!((p.rows.len(), p.total, p.next), (3, 4, None));
}

#[test]
fn unique_and_summarize_count_values() {
    let def = table::table("fib").unwrap();
    let f = frame_of(def, &fib_rows());
    let all = Selection::default();
    let u = unique(def, &f, &all, &["kind".into()]).unwrap();
    assert_eq!(u[0], vec![json!("static"), json!(3)]);
    let (total, s) = summarize(def, &f, &all).unwrap();
    assert_eq!(total, 4);
    assert_eq!(s[0].distinct, 2);
    assert_eq!(s[0].top[0], (json!("r1"), 3));
}

#[test]
fn lpm_gives_the_longest_prefix_that_contains_the_address() {
    let def = table::table("fib").unwrap();
    let f = frame_of(def, &fib_rows());
    let all = Selection::default();
    let r = lpm(def, &f, &all, "prefix", "10.0.0.7").unwrap();
    assert_eq!(r.rows.len(), 1);
    assert_eq!(r.rows[0][2], json!("10.0.0.0/24"));
    let r = lpm(def, &f, &all, "prefix", "10.0.9.1").unwrap();
    assert_eq!(r.rows[0][2], json!("10.0.0.0/16"));
    let r = lpm(def, &f, &all, "prefix", "198.51.100.1").unwrap();
    assert!(r.rows.is_empty());
    assert!(lpm(def, &f, &all, "device", "10.0.0.7").is_err());
}
