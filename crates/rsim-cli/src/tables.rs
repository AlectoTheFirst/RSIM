//! The table providers: the rows of each table of a loaded twin as columns,
//! built once for each twin and table, and the table commands.

use std::any::Any;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::OnceLock;

use rsim_contract::table::{
    self, Selection, SummarizeOut, TableDef, TableOut, TablesOut, UniqueOut,
};
use rsim_core::SourceSpan;
use rsim_functions::RouteLookup;
use rsim_ingest::links::{AsnValue, BgpPeerFact, PeerSource};
use serde_json::{Value, json};

use crate::commands::Loaded;
use crate::error::{ErrorCode, QueryError};
use crate::frame::{self, Cell, Frame, FrameBuilder};
use crate::json::{VERSION, snake};

fn spans(s: &[SourceSpan]) -> Vec<String> {
    s.iter()
        .map(|s| format!("{}:{}-{}", s.file, s.first_line, s.last_line))
        .collect()
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

/// The columns of each table of a twin, built when a request first names
/// the table and kept with the twin.
pub struct TableCache(Vec<OnceLock<Frame>>);

impl Default for TableCache {
    fn default() -> Self {
        TableCache(table::TABLES.iter().map(|_| OnceLock::new()).collect())
    }
}

/// The columns of a table of a loaded twin.
pub fn frame<'a>(t: &'a Loaded, def: &'static TableDef) -> &'a Frame {
    let i = table::TABLES
        .iter()
        .position(|d| d.name == def.name)
        .expect("a table of the catalog");
    t.tables.0[i].get_or_init(|| build(t, def))
}

/// The text by which a prefix sorts in the key order: its family, its
/// address bits and its length, so the order of the prefixes is numeric.
pub fn key_text(s: &str) -> Option<String> {
    let p = s.parse::<rsim_core::Prefix>().ok()?;
    Some(format!(
        "{}{:039}/{:03}",
        if p.is_ipv4() { 4 } else { 6 },
        rsim_core::bits::ip_bits(p.addr()),
        p.len()
    ))
}

/// All rows of a table as columns, in key order.
fn build(t: &Loaded, def: &'static TableDef) -> Frame {
    let mut b = FrameBuilder::new(def);
    match def.name {
        "devices" => {
            let mut count: BTreeMap<String, usize> = BTreeMap::new();
            for f in t.functions() {
                if let Some(d) = f.device() {
                    *count.entry(d.to_string()).or_default() += 1;
                }
            }
            for d in t.devices() {
                let n = count.get(d.as_str()).copied().unwrap_or(0);
                b.push(&[Cell::Text(d.as_str()), Cell::Integer(n as u64)]);
            }
        }
        "functions" => {
            for f in t.functions() {
                let device = f.device().map(|d| d.to_string());
                b.push(&[
                    Cell::Text(&f.id().to_string()),
                    device.as_deref().map_or(Cell::Null, Cell::Text),
                    Cell::Text(&snake(&f.kind())),
                    Cell::List(&spans(f.provenance())),
                ]);
            }
        }
        "endpoints" => {
            for e in t.endpoints() {
                let addresses: Vec<String> = e.addresses.iter().map(ToString::to_string).collect();
                b.push(&[Cell::Text(&e.id.to_string()), Cell::List(&addresses)]);
            }
        }
        "attachments" => {
            for a in t.attachments() {
                b.push_values(&[
                    json!(a.address.to_string()),
                    json!(a.device.to_string()),
                    json!(a.interface.to_string()),
                    json!(snake(&a.kind)),
                    json!(a.host),
                ]);
            }
        }
        "edge-interfaces" => {
            for e in t.edge_interfaces() {
                let networks: Vec<String> = e.networks.iter().map(ToString::to_string).collect();
                b.push(&[
                    Cell::Text(&e.device.to_string()),
                    Cell::Text(&e.interface.to_string()),
                    Cell::List(&networks),
                ]);
            }
        }
        "fib" => {
            let mut prefix = String::new();
            for f in t.functions() {
                let any: &dyn Any = f.as_ref();
                let Some(rl) = any.downcast_ref::<RouteLookup>() else {
                    continue;
                };
                let device = f.device().map(|d| d.to_string());
                let id = f.id().to_string();
                for (vrf, fib) in &rl.tables {
                    let vrf = vrf.to_string();
                    for (p, route) in fib.entries() {
                        prefix.clear();
                        let _ = write!(prefix, "{p}");
                        let hops: Vec<String> = route
                            .next_hops()
                            .iter()
                            .map(|h| match h.gateway {
                                Some(g) => format!("{g}@{}", h.interface),
                                None => h.interface.to_string(),
                            })
                            .collect();
                        b.push(&[
                            device.as_deref().map_or(Cell::Null, Cell::Text),
                            Cell::Text(&vrf),
                            Cell::Text(&prefix),
                            Cell::Text(route.kind.name()),
                            Cell::Text(&id),
                            Cell::List(&hops),
                            Cell::List(&spans(&route.spans)),
                        ]);
                    }
                }
            }
        }
        "coverage" => {
            for (d, c) in &t.coverage {
                for (path, (stanzas, lines)) in &c.unhandled {
                    b.push_values(&[json!(d), json!(path), json!(stanzas), json!(lines)]);
                }
            }
        }
        "bgp-sessions" => {
            for facts in t.bgp.values() {
                for f in facts {
                    b.push_values(&bgp_row(f));
                }
            }
        }
        _ => {}
    }
    b.finish(&key_text)
}

/// The row of a BGP peer fact.
fn bgp_row(f: &BgpPeerFact) -> Vec<Value> {
    let opt = |v: Option<String>| v.map_or(Value::Null, Value::from);
    let (local, local_reason) = match &f.local_asn.value {
        AsnValue::Known(v) => (
            Value::from(v.iter().map(ToString::to_string).collect::<Vec<_>>()),
            Value::Null,
        ),
        AsnValue::Unknown(r) => (Value::from(Vec::<String>::new()), json!(r)),
    };
    let (peer, peer_reason) = match &f.peer_asn.value {
        AsnValue::Known(v) => (v.first().map_or(Value::Null, |a| json!(a)), Value::Null),
        AsnValue::Unknown(r) => (Value::Null, json!(r)),
    };
    let sum = |c: fn(&rsim_ingest::bgp::SessionRow) -> Option<u64>| {
        let counts: Vec<u64> = f.sessions.iter().filter_map(c).collect();
        if counts.is_empty() {
            Value::Null
        } else {
            json!(counts.iter().sum::<u64>())
        }
    };
    let range = match &f.source {
        PeerSource::Dynamic(p) => json!(p.to_string()),
        _ => Value::Null,
    };
    let mut provenance: Vec<SourceSpan> = f.spans.clone();
    for r in &f.sessions {
        if !provenance.contains(&r.span) {
            provenance.push(r.span.clone());
        }
    }
    vec![
        json!(f.device),
        json!(f.vrf),
        json!(f.peer.to_string()),
        json!(f.source.name()),
        range,
        opt(f.local_address.map(|a| a.to_string())),
        opt(f.update_source.clone()),
        local,
        local_reason,
        peer,
        peer_reason,
        f.observed_asn.map_or(Value::Null, |a| json!(a)),
        f.shutdown.map_or(Value::Null, Value::from),
        Value::from(f.families.iter().cloned().collect::<Vec<_>>()),
        opt(f.policy_in.clone()),
        opt(f.policy_out.clone()),
        Value::from(f.inherits.clone()),
        Value::from(f.gaps.clone()),
        Value::from(
            f.sessions
                .iter()
                .map(|r| r.state.clone())
                .collect::<Vec<_>>(),
        ),
        if f.sessions.is_empty() {
            Value::Null
        } else {
            json!(f.sessions.iter().all(|r| r.established))
        },
        sum(|r| r.prefixes_received),
        sum(|r| r.prefixes_sent),
        opt(f.router_id.map(|a| a.to_string())),
        json!(f.section.outcome.name()),
        json!(f.in_scope()),
        Value::from(spans(&provenance)),
    ]
}

fn invalid(e: String) -> QueryError {
    QueryError::new(ErrorCode::InvalidFilter, e)
}

/// The rows of a page as the output of a table request.
fn rows_out(topology: &str, t: &Loaded, d: &TableDef, p: frame::Page) -> TableOut {
    TableOut {
        rsim_json: VERSION,
        kind: "table_rows".into(),
        topology: topology.to_string(),
        twin: t.identity.clone(),
        table: d.name.to_string(),
        columns: p.columns,
        rows: p.rows,
        total: p.total,
        next_cursor: p.next,
    }
}

/// The verb `show`: the selected rows.
pub fn show(
    topology: &str,
    t: &Loaded,
    name: &str,
    sel: &Selection,
) -> Result<TableOut, QueryError> {
    let d = def(name)?;
    let p = frame::show(d, frame(t, d), sel).map_err(invalid)?;
    Ok(rows_out(topology, t, d, p))
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
    let p = frame::lpm(d, frame(t, d), sel, column, address).map_err(invalid)?;
    Ok(rows_out(topology, t, d, p))
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
    let rows = frame::unique(d, frame(t, d), sel, columns).map_err(invalid)?;
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
    let (total, columns) = frame::summarize(d, frame(t, d), sel).map_err(invalid)?;
    Ok(SummarizeOut {
        rsim_json: VERSION,
        kind: "table_summary".into(),
        topology: topology.to_string(),
        twin: t.identity.clone(),
        table: d.name.to_string(),
        total,
        columns,
    })
}
