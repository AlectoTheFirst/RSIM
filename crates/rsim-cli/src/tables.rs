//! The table providers: all rows of each table of a loaded twin, in key
//! order, and the table commands.

use std::any::Any;
use std::collections::BTreeMap;

use rsim_contract::table::{
    self, Selection, SummarizeOut, TableDef, TableOut, TablesOut, UniqueOut,
};
use rsim_core::SourceSpan;
use rsim_functions::RouteLookup;
use serde_json::{Value, json};

use crate::commands::Loaded;
use crate::error::{ErrorCode, QueryError};
use crate::json::{VERSION, snake};

fn spans(s: &[SourceSpan]) -> Value {
    Value::from(
        s.iter()
            .map(|s| format!("{}:{}-{}", s.file, s.first_line, s.last_line))
            .collect::<Vec<_>>(),
    )
}

/// The catalog of the tables.
pub fn catalog() -> TablesOut {
    TablesOut {
        rsim_json: VERSION,
        kind: "tables".into(),
        tables: table::TABLES,
    }
}

/// The definition of a table, or the error `unknown_table`.
pub fn def(name: &str) -> Result<&'static TableDef, QueryError> {
    table::table(name).ok_or_else(|| {
        let names: Vec<&str> = table::TABLES.iter().map(|t| t.name).collect();
        QueryError::new(
            ErrorCode::UnknownTable,
            format!("{name} is not a table; the tables are {}", names.join(", ")),
        )
    })
}

/// All rows of a table, in key order.
pub fn rows(t: &Loaded, def: &TableDef) -> Vec<Vec<Value>> {
    let mut rows: Vec<Vec<Value>> = match def.name {
        "devices" => {
            let mut count: BTreeMap<String, usize> = BTreeMap::new();
            for f in t.functions() {
                if let Some(d) = f.device() {
                    *count.entry(d.to_string()).or_default() += 1;
                }
            }
            t.devices()
                .iter()
                .map(|d| {
                    vec![
                        json!(d.to_string()),
                        json!(count.get(d.as_str()).copied().unwrap_or(0)),
                    ]
                })
                .collect()
        }
        "functions" => t
            .functions()
            .map(|f| {
                vec![
                    json!(f.id().to_string()),
                    f.device().map_or(Value::Null, |d| json!(d.to_string())),
                    json!(snake(&f.kind())),
                    spans(f.provenance()),
                ]
            })
            .collect(),
        "endpoints" => t
            .endpoints()
            .map(|e| {
                vec![
                    json!(e.id.to_string()),
                    Value::from(
                        e.addresses
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>(),
                    ),
                ]
            })
            .collect(),
        "attachments" => t
            .attachments()
            .iter()
            .map(|a| {
                vec![
                    json!(a.address.to_string()),
                    json!(a.device.to_string()),
                    json!(a.interface.to_string()),
                    json!(snake(&a.kind)),
                    json!(a.host),
                ]
            })
            .collect(),
        "edge-interfaces" => t
            .edge_interfaces()
            .iter()
            .map(|e| {
                vec![
                    json!(e.device.to_string()),
                    json!(e.interface.to_string()),
                    Value::from(
                        e.networks
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>(),
                    ),
                ]
            })
            .collect(),
        "fib" => {
            let mut v = Vec::new();
            for f in t.functions() {
                let any: &dyn Any = f.as_ref();
                let Some(rl) = any.downcast_ref::<RouteLookup>() else {
                    continue;
                };
                let device = f.device().map_or(Value::Null, |d| json!(d.to_string()));
                for (vrf, fib) in &rl.tables {
                    for (prefix, route) in fib.entries() {
                        let hops: Vec<String> = route
                            .next_hops()
                            .iter()
                            .map(|h| match h.gateway {
                                Some(g) => format!("{g}@{}", h.interface),
                                None => h.interface.to_string(),
                            })
                            .collect();
                        v.push(vec![
                            device.clone(),
                            json!(vrf.to_string()),
                            json!(prefix.to_string()),
                            json!(route.kind.name()),
                            json!(f.id().to_string()),
                            Value::from(hops),
                            spans(&route.spans),
                        ]);
                    }
                }
            }
            v
        }
        "coverage" => t
            .coverage
            .iter()
            .flat_map(|(d, c)| {
                c.unhandled.iter().map(move |(path, (stanzas, lines))| {
                    vec![json!(d), json!(path), json!(stanzas), json!(lines)]
                })
            })
            .collect(),
        _ => Vec::new(),
    };
    // The key order. A prefix sorts by its address bits and its length, so
    // the order of the prefixes is numeric.
    let key: Vec<usize> = def
        .key
        .iter()
        .filter_map(|k| def.columns.iter().position(|c| c.name == *k))
        .collect();
    let sort_text = |v: &Value| -> String {
        match v.as_str().and_then(|s| s.parse::<rsim_core::Prefix>().ok()) {
            Some(p) => format!(
                "{}{:039}/{:03}",
                if p.is_ipv4() { 4 } else { 6 },
                rsim_core::bits::ip_bits(p.addr()),
                p.len()
            ),
            None => match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            },
        }
    };
    rows.sort_by_cached_key(|r| key.iter().map(|i| sort_text(&r[*i])).collect::<Vec<_>>());
    rows
}

fn invalid(e: String) -> QueryError {
    QueryError::new(ErrorCode::InvalidFilter, e)
}

/// The verb `show`: the selected rows.
pub fn show(
    topology: &str,
    t: &Loaded,
    name: &str,
    sel: &Selection,
) -> Result<TableOut, QueryError> {
    let d = def(name)?;
    let m = table::filter(d, &rows(t, d), sel).map_err(invalid)?;
    let (columns, rows, total, next) = table::page(d, m, sel).map_err(invalid)?;
    Ok(TableOut {
        rsim_json: VERSION,
        kind: "table_rows".into(),
        topology: topology.to_string(),
        twin: t.identity.clone(),
        table: d.name.to_string(),
        columns,
        rows,
        total,
        next_cursor: next,
    })
}

/// The verb `top`: the `n` rows with the largest values of a column, or
/// the smallest with `ascending`.
pub fn top(
    topology: &str,
    t: &Loaded,
    name: &str,
    column: &str,
    n: usize,
    ascending: bool,
    sel: &Selection,
) -> Result<TableOut, QueryError> {
    let mut s = sel.clone();
    s.sort = Some(vec![if ascending {
        column.to_string()
    } else {
        format!("-{column}")
    }]);
    s.limit = Some(n);
    s.cursor = None;
    show(topology, t, name, &s)
}

/// The verb `lpm`: the rows of the longest prefix of a prefix column that
/// contains an address.
pub fn lpm(
    topology: &str,
    t: &Loaded,
    name: &str,
    column: &str,
    address: &str,
    sel: &Selection,
) -> Result<TableOut, QueryError> {
    let d = def(name)?;
    let m = table::filter(d, &rows(t, d), sel).map_err(invalid)?;
    let m = table::lpm(d, &m, column, address).map_err(invalid)?;
    let (columns, rows, total, next) = table::page(d, m, sel).map_err(invalid)?;
    Ok(TableOut {
        rsim_json: VERSION,
        kind: "table_rows".into(),
        topology: topology.to_string(),
        twin: t.identity.clone(),
        table: d.name.to_string(),
        columns,
        rows,
        total,
        next_cursor: next,
    })
}

/// The verb `unique`: the distinct values of columns with their counts.
pub fn unique(
    topology: &str,
    t: &Loaded,
    name: &str,
    columns: &[String],
    sel: &Selection,
) -> Result<UniqueOut, QueryError> {
    let d = def(name)?;
    let m = table::filter(d, &rows(t, d), sel).map_err(invalid)?;
    let rows = table::unique(d, &m, columns).map_err(invalid)?;
    let mut cols = columns.to_vec();
    cols.push("count".into());
    Ok(UniqueOut {
        rsim_json: VERSION,
        kind: "table_unique".into(),
        topology: topology.to_string(),
        twin: t.identity.clone(),
        table: d.name.to_string(),
        columns: cols,
        rows,
    })
}

/// The verb `summarize`: the counts of the table and of each column.
pub fn summarize(
    topology: &str,
    t: &Loaded,
    name: &str,
    sel: &Selection,
) -> Result<SummarizeOut, QueryError> {
    let d = def(name)?;
    let m = table::filter(d, &rows(t, d), sel).map_err(invalid)?;
    Ok(SummarizeOut {
        rsim_json: VERSION,
        kind: "table_summary".into(),
        topology: topology.to_string(),
        twin: t.identity.clone(),
        table: d.name.to_string(),
        total: m.len(),
        columns: table::summarize(d, &m),
    })
}
