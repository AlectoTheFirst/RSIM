//! The tables: the catalog of their columns, and the selection of rows with
//! filters, sorting, pages and the verbs `show`, `summarize`, `unique` and
//! `top`. A table provider gives all rows of a table in key order; this
//! module selects from them, so each table has the same parameters.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::twin::TwinJson;

/// The type of the values of a column.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ColumnType {
    Text,
    Integer,
    Boolean,
    /// An IPv4 or IPv6 address.
    Address,
    /// An address with a prefix length.
    Prefix,
    /// A list of text values.
    List,
}

/// One column of a table.
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
pub struct Column {
    pub name: &'static str,
    pub description: &'static str,
    #[serde(rename = "type")]
    pub kind: ColumnType,
    /// The meaning of the values, for example `device`, `interface`, `vrf`.
    pub semantic: &'static str,
    pub unit: Option<&'static str>,
    /// The table and the column that a value refers to.
    pub refers_to: Option<(&'static str, &'static str)>,
}

/// One table of the catalog.
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
pub struct TableDef {
    pub name: &'static str,
    pub description: &'static str,
    /// The key columns, which give the default order of the rows.
    pub key: &'static [&'static str],
    pub columns: &'static [Column],
    /// The verbs of the table.
    pub verbs: &'static [&'static str],
    /// The data that the table needs, so a client knows why it is empty.
    pub needs: &'static str,
}

impl TableDef {
    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
    }
}

const fn col(
    name: &'static str,
    kind: ColumnType,
    semantic: &'static str,
    description: &'static str,
) -> Column {
    Column {
        name,
        description,
        kind,
        semantic,
        unit: None,
        refers_to: None,
    }
}

const fn refers(mut c: Column, table: &'static str, column: &'static str) -> Column {
    c.refers_to = Some((table, column));
    c
}

const DEVICE: Column = refers(
    col("device", ColumnType::Text, "device", "The device."),
    "devices",
    "device",
);
const BASE_VERBS: &[&str] = &["show", "summarize", "unique", "top"];

/// The tables, in a fixed order.
pub const TABLES: &[TableDef] = &[
    TableDef {
        name: "devices",
        description: "The devices of the twin.",
        key: &["device"],
        columns: &[
            col("device", ColumnType::Text, "device", "The device."),
            col(
                "functions",
                ColumnType::Integer,
                "count",
                "The number of functions of the device.",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "the twin",
    },
    TableDef {
        name: "functions",
        description: "The network functions of the twin, with the source lines from which each came.",
        key: &["function"],
        columns: &[
            col(
                "function",
                ColumnType::Text,
                "function",
                "The function identifier.",
            ),
            DEVICE,
            col(
                "kind",
                ColumnType::Text,
                "function_kind",
                "The function type.",
            ),
            col(
                "provenance",
                ColumnType::List,
                "source_span",
                "The source spans: file:first-last.",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "the twin",
    },
    TableDef {
        name: "endpoints",
        description: "The endpoints of the twin.",
        key: &["endpoint"],
        columns: &[
            col("endpoint", ColumnType::Text, "endpoint", "The endpoint."),
            col(
                "addresses",
                ColumnType::List,
                "address",
                "The addresses of the endpoint.",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "the twin",
    },
    TableDef {
        name: "attachments",
        description: "The attachment records: where an address attaches to the network.",
        key: &["address", "device", "interface"],
        columns: &[
            col("address", ColumnType::Address, "address", "The address."),
            DEVICE,
            col(
                "interface",
                ColumnType::Text,
                "interface",
                "The interface of the device.",
            ),
            col(
                "kind",
                ColumnType::Text,
                "attachment_kind",
                "The kind of the record.",
            ),
            refers(
                col("host", ColumnType::Text, "endpoint", "The host."),
                "endpoints",
                "endpoint",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "the twin",
    },
    TableDef {
        name: "edge-interfaces",
        description: "The edge interfaces with the connected networks behind them.",
        key: &["device", "interface"],
        columns: &[
            DEVICE,
            col("interface", ColumnType::Text, "interface", "The interface."),
            col(
                "networks",
                ColumnType::List,
                "prefix",
                "The connected networks.",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "the twin",
    },
    TableDef {
        name: "fib",
        description: "The forwarding table of each device and VRF that the twin uses. Each row is one prefix.",
        key: &["device", "vrf", "prefix", "function"],
        columns: &[
            DEVICE,
            col("vrf", ColumnType::Text, "vrf", "The VRF."),
            col("prefix", ColumnType::Prefix, "prefix", "The prefix."),
            col(
                "kind",
                ColumnType::Text,
                "route_kind",
                "connected, static, local or null.",
            ),
            refers(
                col(
                    "function",
                    ColumnType::Text,
                    "function",
                    "The route lookup function.",
                ),
                "functions",
                "function",
            ),
            col(
                "next_hops",
                ColumnType::List,
                "next_hop",
                "The next hops as <gateway>@<interface>, or the interface of a connected network.",
            ),
            col(
                "provenance",
                ColumnType::List,
                "source_span",
                "The source spans: file:first-last.",
            ),
        ],
        verbs: &["show", "summarize", "unique", "top", "lpm"],
        needs: "the twin",
    },
    TableDef {
        name: "coverage",
        description: "The config stanzas that the ingestion does not handle, for each device. Each key goes through the mask of the secrets.",
        key: &["device", "path"],
        columns: &[
            DEVICE,
            col(
                "path",
                ColumnType::Text,
                "config_path",
                "The path of the unhandled stanzas.",
            ),
            col(
                "stanzas",
                ColumnType::Integer,
                "count",
                "The number of stanzas.",
            ),
            col(
                "lines",
                ColumnType::Integer,
                "count",
                "The number of lines.",
            ),
        ],
        verbs: BASE_VERBS,
        needs: "a twin of a store snapshot; a built-in topology has no coverage report",
    },
];

/// The table of a name.
pub fn table(name: &str) -> Option<&'static TableDef> {
    TABLES.iter().find(|t| t.name == name)
}

/// The selection of rows: the filters, the order, the columns and the page.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct Selection {
    /// Equality filters: a row matches if the value of the column is one of
    /// the values. A list value matches if one element is one of the
    /// values. Different columns are an AND.
    #[serde(default)]
    pub filters: BTreeMap<String, Vec<String>>,
    /// Typed filters as `<column>.<op>` with the op `contains`, `prefix`,
    /// `gt`, `lt` or `in_prefix`.
    #[serde(default)]
    pub typed: BTreeMap<String, String>,
    /// The columns of the output. All columns if not given.
    pub columns: Option<Vec<String>>,
    /// The order: column names, `-` before a name for a falling order.
    /// The key order if not given.
    pub sort: Option<Vec<String>>,
    /// The number of rows of a page.
    pub limit: Option<usize>,
    /// The cursor of the next page, from the output of the page before.
    pub cursor: Option<String>,
}

/// The rows of a table.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct TableOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: TwinJson,
    pub table: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    /// The number of rows that match the filters, on all pages.
    pub total: usize,
    /// The cursor of the next page, or `null` on the last page.
    pub next_cursor: Option<String>,
}

/// The distinct values of columns with their counts.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct UniqueOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: TwinJson,
    pub table: String,
    /// The columns, then `count`.
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
}

/// The counts of a table and of each column.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SummarizeOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: TwinJson,
    pub table: String,
    pub total: usize,
    pub columns: Vec<ColumnSummary>,
}

/// The counts of one column.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ColumnSummary {
    pub column: String,
    pub distinct: usize,
    pub nulls: usize,
    /// The most frequent values with their counts, at most 5, the most
    /// frequent first.
    pub top: Vec<(Value, usize)>,
}

/// The text of a value for the equality filters.
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

/// True if `addr` is in `prefix` (`<address>/<length>`).
fn in_prefix(addr: &str, prefix: &str) -> Option<bool> {
    let addr: IpAddr = addr.split('/').next()?.parse().ok()?;
    let (net, len) = prefix.split_once('/')?;
    let net: IpAddr = net.parse().ok()?;
    let len: u32 = len.parse().ok()?;
    let (a, n, bits) = match (addr, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => (u128::from(u32::from(a)), u128::from(u32::from(n)), 32),
        (IpAddr::V6(a), IpAddr::V6(n)) => (u128::from(a), u128::from(n), 128),
        _ => return Some(false),
    };
    if len > bits {
        return None;
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

/// The rows that match the filters, in the order of the selection, with
/// the indexes of all columns. An error names a column or an op that the
/// table does not have.
pub fn filter(
    def: &TableDef,
    rows: &[Vec<Value>],
    sel: &Selection,
) -> Result<Vec<Vec<Value>>, String> {
    let index = |name: &str| -> Result<usize, String> {
        def.columns
            .iter()
            .position(|c| c.name == name)
            .ok_or_else(|| format!("{name} is not a column of {}", def.name))
    };
    let mut eq = Vec::new();
    for (k, vs) in &sel.filters {
        eq.push((index(k)?, vs));
    }
    let mut typed = Vec::new();
    for (k, v) in &sel.typed {
        let (c, op) = k
            .rsplit_once('.')
            .ok_or_else(|| format!("{k} is not <column>.<op>"))?;
        if !["contains", "prefix", "gt", "lt", "in_prefix"].contains(&op) {
            return Err(format!("{op} is not contains, prefix, gt, lt or in_prefix"));
        }
        typed.push((index(c)?, op, v));
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
            keys.push((index(name)?, desc));
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

/// The page and the columns of the matching rows: the column names, the
/// rows, the total and the next cursor.
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
        idx.push(
            def.columns
                .iter()
                .position(|c| c.name == n)
                .ok_or_else(|| format!("{n} is not a column of {}", def.name))?,
        );
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
        Some(l) => (start + l).min(total),
        None => total,
    };
    let rows = matching[start..end]
        .iter()
        .map(|r| idx.iter().map(|i| r[*i].clone()).collect())
        .collect();
    let next = (end < total).then(|| format!("o{end}"));
    Ok((names, rows, total, next))
}

/// The distinct values of the columns `names` in the matching rows, with
/// their counts, the most frequent first, then in value order.
pub fn unique(
    def: &TableDef,
    matching: &[Vec<Value>],
    names: &[String],
) -> Result<Vec<Vec<Value>>, String> {
    let mut idx = Vec::new();
    for n in names {
        idx.push(
            def.columns
                .iter()
                .position(|c| c.name == n)
                .ok_or_else(|| format!("{n} is not a column of {}", def.name))?,
        );
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

/// The counts of each column of the matching rows.
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

/// The rows whose column `column`, of type prefix, holds the longest
/// prefix that contains `address`. An error names a column that is not a
/// prefix column or an address that is not valid.
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
            in_prefix(address, &text(&r[i])) == Some(true) && best.is_some() && len(&r[i]) == best
        })
        .cloned()
        .collect())
}

/// The table catalog.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct TablesOut {
    pub rsim_json: u32,
    pub kind: String,
    pub tables: &'static [TableDef],
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(d: &str, vrf: &str, p: &str, kind: &str, hop: &str) -> Vec<Value> {
        vec![
            json!(d),
            json!(vrf),
            json!(p),
            json!(kind),
            json!(format!("{d}/route")),
            json!([hop]),
            json!([]),
        ]
    }

    fn rows() -> Vec<Vec<Value>> {
        vec![
            row("r1", "default", "10.0.0.0/24", "static", "10.0.0.1@eth0"),
            row("r1", "default", "10.0.1.0/24", "connected", "eth1"),
            row("r2", "blue", "192.0.2.0/24", "static", "192.0.2.1@eth0"),
            row("r1", "default", "10.0.0.0/16", "static", "10.0.0.9@eth0"),
        ]
    }

    #[test]
    fn filters_sort_and_pages_select_rows() {
        let def = table("fib").unwrap();
        let mut sel = Selection::default();
        sel.filters.insert("device".into(), vec!["r1".into()]);
        let m = filter(def, &rows(), &sel).unwrap();
        assert_eq!(m.len(), 3);
        sel.typed
            .insert("prefix.in_prefix".into(), "10.0.1.0/24".into());
        assert_eq!(filter(def, &rows(), &sel).unwrap().len(), 1);
        let sel = Selection {
            sort: Some(vec!["-prefix".into()]),
            limit: Some(2),
            ..Selection::default()
        };
        let m = filter(def, &rows(), &sel).unwrap();
        let (cols, page1, total, next) = page(def, m.clone(), &sel).unwrap();
        assert_eq!((cols.len(), page1.len(), total), (7, 2, 4));
        assert_eq!(page1[0][2], json!("192.0.2.0/24"));
        let sel2 = Selection {
            cursor: next,
            ..sel.clone()
        };
        let (_, page2, _, next2) = page(def, m.clone(), &sel2).unwrap();
        assert_eq!(page2.len(), 2);
        assert_eq!(next2, None);
        let mut joined = page1;
        joined.extend(page2);
        assert_eq!(joined, m);
    }

    #[test]
    fn a_column_or_an_op_that_the_table_does_not_have_is_an_error() {
        let def = table("fib").unwrap();
        let mut sel = Selection::default();
        sel.filters.insert("colour".into(), vec!["red".into()]);
        assert!(filter(def, &rows(), &sel).is_err());
        let mut sel = Selection::default();
        sel.typed.insert("prefix.like".into(), "10".into());
        assert!(filter(def, &rows(), &sel).is_err());
    }

    #[test]
    fn unique_and_summarize_count_values() {
        let def = table("fib").unwrap();
        let u = unique(def, &rows(), &["kind".into()]).unwrap();
        assert_eq!(u[0], vec![json!("static"), json!(3)]);
        let s = summarize(def, &rows());
        assert_eq!(s[0].distinct, 2);
        assert_eq!(s[0].top[0], (json!("r1"), 3));
    }

    #[test]
    fn lpm_gives_the_longest_prefix_that_contains_the_address() {
        let def = table("fib").unwrap();
        let r = lpm(def, &rows(), "prefix", "10.0.0.7").unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0][2], json!("10.0.0.0/24"));
        assert_eq!(
            lpm(def, &rows(), "prefix", "10.0.9.1").unwrap()[0][2],
            json!("10.0.0.0/16")
        );
        assert!(
            lpm(def, &rows(), "prefix", "198.51.100.1")
                .unwrap()
                .is_empty()
        );
        assert!(lpm(def, &rows(), "device", "10.0.0.7").is_err());
    }
}
