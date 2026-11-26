//! The table providers: the rows of each table of a loaded twin as columns,
//! built once for each twin and table, and the table commands.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::net::IpAddr;
use std::sync::OnceLock;

use arrow_array::cast::AsArray;
use arrow_array::types::UInt64Type;
use arrow_array::{Array, RecordBatch};
use rsim_contract::table::{
    self, Selection, SummarizeOut, TableDef, TableOut, TablesOut, UniqueOut,
};
use rsim_core::{FunctionId, SourceSpan};
use rsim_functions::{OverlaySelect, RouteLookup, TunnelState, VcmpEncap};
use rsim_ingest::facts::{DeviceFacts, Reason};
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
pub struct TableCache(Vec<OnceLock<Result<Frame, String>>>);

impl Default for TableCache {
    fn default() -> Self {
        TableCache(table::TABLES.iter().map(|_| OnceLock::new()).collect())
    }
}

/// The columns of a table of a loaded twin, or the error `store` if a
/// store table of the table is not readable.
pub fn frame<'a>(t: &'a Loaded, def: &'static TableDef) -> Result<&'a Frame, QueryError> {
    let i = table::TABLES
        .iter()
        .position(|d| d.name == def.name)
        .expect("a table of the catalog");
    t.tables.0[i]
        .get_or_init(|| build(t, def))
        .as_ref()
        .map_err(|e| QueryError::new(ErrorCode::Store, e.clone()))
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
fn build(t: &Loaded, def: &'static TableDef) -> Result<Frame, String> {
    let mut b = FrameBuilder::new(def);
    if !def.collected.is_empty() {
        collected_rows(t, def, &mut b)?;
        return Ok(b.finish(&key_text));
    }
    match def.name {
        "devices" => {
            let mut names: BTreeSet<String> = t.devices().iter().map(ToString::to_string).collect();
            names.extend(t.facts.keys().cloned());
            for d in &names {
                b.push_values(&device_row(d, t.facts.get(d)));
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
        "neighbours" => {
            for n in &t.seen {
                b.push(&[
                    Cell::Text(&n.device),
                    Cell::Text(&n.port),
                    Cell::Text(&n.name),
                    n.remote_port.as_deref().map_or(Cell::Null, Cell::Text),
                    Cell::Text(n.protocol),
                    Cell::List(&spans(std::slice::from_ref(&n.span))),
                ]);
            }
        }
        "fabric-connections" => {
            for (device, rows) in &t.fabric {
                for c in rows {
                    let (result, reason) = match &c.verdict {
                        rsim_ingest::equinix::Verdict::Lowered => ("lowered", None),
                        rsim_ingest::equinix::Verdict::Ended => ("ended", None),
                        rsim_ingest::equinix::Verdict::Unknown(r) => ("unknown", Some(r.as_str())),
                    };
                    b.push(&[
                        Cell::Text(device),
                        Cell::Text(&c.uuid),
                        c.name.as_deref().map_or(Cell::Null, Cell::Text),
                        c.kind.as_deref().map_or(Cell::Null, Cell::Text),
                        c.state.as_deref().map_or(Cell::Null, Cell::Text),
                        Cell::Text(&c.a),
                        Cell::Text(&c.z),
                        Cell::Text(result),
                        reason.map_or(Cell::Null, Cell::Text),
                        Cell::List(&spans(&c.spans)),
                    ]);
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
        "sdwan-paths" => {
            for row in sdwan_rows(t) {
                b.push_values(&row);
            }
        }
        _ => {}
    }
    Ok(b.finish(&key_text))
}

/// A value of a store table.
enum Owned {
    Null,
    Text(String),
    Integer(u64),
    Boolean(bool),
    List(Vec<String>),
}

impl Owned {
    fn cell(&self) -> Cell<'_> {
        match self {
            Owned::Null => Cell::Null,
            Owned::Text(s) => Cell::Text(s),
            Owned::Integer(n) => Cell::Integer(*n),
            Owned::Boolean(v) => Cell::Boolean(*v),
            Owned::List(v) => Cell::List(v),
        }
    }

    /// The value as text, for a key and for a list column; none for null.
    fn text(&self) -> Option<String> {
        match self {
            Owned::Null | Owned::List(_) => None,
            Owned::Text(s) => Some(s.clone()),
            Owned::Integer(n) => Some(n.to_string()),
            Owned::Boolean(v) => Some(v.to_string()),
        }
    }
}

/// The value of the column `name` in a row of a store table: null if the
/// table has no such column or the cell is null.
fn store_value(batch: &RecordBatch, name: &str, row: usize) -> Owned {
    let Some(c) = batch.column_by_name(name) else {
        return Owned::Null;
    };
    if c.is_null(row) {
        return Owned::Null;
    }
    if let Some(a) = c.as_string_opt::<i32>() {
        Owned::Text(a.value(row).to_string())
    } else if let Some(a) = c.as_primitive_opt::<UInt64Type>() {
        Owned::Integer(a.value(row))
    } else if let Some(a) = c.as_boolean_opt() {
        Owned::Boolean(a.value(row))
    } else {
        Owned::Null
    }
}

/// The source span of a row of a store table, as text.
fn row_span(device: &str, table: &str, batch: &RecordBatch, row: usize) -> String {
    let blob = store_value(batch, "blob", row).text().unwrap_or_default();
    let index = match store_value(batch, "index", row) {
        Owned::Integer(n) => n,
        _ => 0,
    };
    spans(&[rsim_ingest::collected::row_span(
        device, table, &blob, index,
    )])
    .remove(0)
}

/// The rows of a table of the collected state, read from the store tables
/// of its registry row (`TableDef::collected`). A twin with no store has no
/// rows.
fn collected_rows(t: &Loaded, def: &TableDef, b: &mut FrameBuilder) -> Result<(), String> {
    let Some(src) = &t.source else {
        return Ok(());
    };
    let mut tables = Vec::new();
    for name in def.collected {
        let schema =
            rsim_store::table(name).ok_or_else(|| format!("{name} is not a store table"))?;
        let batches = src
            .store
            .read_table(&src.snapshot, schema)
            .map_err(|e| e.to_string())?;
        tables.push((*name, batches));
    }
    if let [(name, batches)] = tables.as_slice() {
        for (device, batch) in batches {
            for row in 0..batch.num_rows() {
                let values: Vec<Owned> = def
                    .columns
                    .iter()
                    .map(|c| match c.name {
                        "device" => Owned::Text(device.clone()),
                        "provenance" => Owned::List(vec![row_span(device, name, batch, row)]),
                        n => store_value(batch, n, row),
                    })
                    .collect();
                let cells: Vec<Cell> = values.iter().map(Owned::cell).collect();
                b.push(&cells);
            }
        }
        return Ok(());
    }
    // 2 or more store tables: the rows of each distinct key, in the order
    // of the store tables.
    let key: Vec<&str> = def.key.iter().copied().filter(|k| *k != "device").collect();
    type Rows<'a> = Vec<(&'a str, &'a RecordBatch, usize)>;
    let mut by_key: BTreeMap<(String, Vec<Option<String>>), Rows<'_>> = BTreeMap::new();
    for (name, batches) in &tables {
        for (device, batch) in batches {
            for row in 0..batch.num_rows() {
                let k = key
                    .iter()
                    .map(|c| store_value(batch, c, row).text())
                    .collect();
                by_key
                    .entry((device.clone(), k))
                    .or_default()
                    .push((*name, batch, row));
            }
        }
    }
    for ((device, _), rows) in &by_key {
        let values: Vec<Owned> = def
            .columns
            .iter()
            .map(|c| match (c.name, c.kind) {
                ("device", _) => Owned::Text(device.clone()),
                ("provenance", _) => Owned::List(
                    rows.iter()
                        .map(|(name, batch, row)| row_span(device, name, batch, *row))
                        .collect(),
                ),
                (n, table::ColumnType::List) => Owned::List(
                    rows.iter()
                        .filter_map(|(_, batch, row)| store_value(batch, n, *row).text())
                        .collect(),
                ),
                (n, _) => rows
                    .iter()
                    .find(|(_, batch, _)| batch.column_by_name(n).is_some())
                    .map_or(Owned::Null, |(_, batch, row)| store_value(batch, n, *row)),
            })
            .collect();
        let cells: Vec<Cell> = values.iter().map(Owned::cell).collect();
        b.push(&cells);
    }
    Ok(())
}

/// The row of a device: its facts, each with its reason, or with no facts
/// each fact `not_collected`.
fn device_row(device: &str, facts: Option<&DeviceFacts>) -> Vec<Value> {
    let not_collected = json!(Reason::NotCollected.name());
    let Some(f) = facts else {
        let mut row = vec![json!(device)];
        for _ in 0..6 {
            row.push(Value::Null);
            row.push(not_collected.clone());
        }
        row.push(Value::Null);
        row.push(json!(Vec::<String>::new()));
        return row;
    };
    let mut row = vec![json!(device), json!(f.vendor), Value::Null];
    for fact in [&f.platform, &f.os_version, &f.serial, &f.management_address] {
        row.push(fact.value().map_or(Value::Null, |v| json!(v)));
        row.push(fact.reason().map_or(Value::Null, |r| json!(r.name())));
    }
    row.push(json!(utc_time(f.collected_at)));
    row.push(Value::Null);
    row.push(json!(f.store_device));
    let spans: Vec<SourceSpan> = f.spans().into_iter().cloned().collect();
    row.push(json!(self::spans(&spans)));
    row
}

/// A time in milliseconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utc_time(ms: u64) -> String {
    let secs = ms / 1000;
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX / 2);
    let rest = secs % 86_400;
    // The civil date of a day number, from the algorithm of Howard Hinnant.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

/// The rows of the tunnels of each tunnel selection of an SD-WAN: the
/// encapsulation of the tunnel gives the WAN interface and the peer
/// address, the one device of the twin with the tunnel end of the peer is
/// the far device, and its VCMP encapsulation from the peer address gives
/// the far interface.
fn sdwan_rows(t: &Loaded) -> Vec<Vec<Value>> {
    let mut encaps: BTreeMap<&FunctionId, &VcmpEncap> = BTreeMap::new();
    let mut sources: BTreeMap<(String, IpAddr), String> = BTreeMap::new();
    let mut selects: Vec<(String, String, &OverlaySelect)> = Vec::new();
    for f in t.functions() {
        let any: &dyn Any = f.as_ref();
        let device = f.device().map(ToString::to_string).unwrap_or_default();
        if let Some(v) = any.downcast_ref::<VcmpEncap>() {
            encaps.insert(f.id(), v);
            sources
                .entry((device, v.source))
                .or_insert_with(|| v.interface.to_string());
        } else if let Some(s) = any.downcast_ref::<OverlaySelect>() {
            selects.push((device, f.id().to_string(), s));
        }
    }
    let ends = crate::topology::vcmp_ends(t);
    let mut rows = Vec::new();
    for (device, id, s) in selects {
        for tunnel in &s.tunnels {
            let encap = encaps.get(&tunnel.next).copied();
            let far = encap.and_then(|v| {
                match crate::topology::vcmp_far(&ends, &device, v.peer).as_slice() {
                    [one] => Some(one.clone()),
                    _ => None,
                }
            });
            let far_interface = far
                .as_ref()
                .zip(encap)
                .and_then(|(d, v)| sources.get(&(d.clone(), v.peer)).cloned());
            let (state, reason) = match tunnel.state {
                TunnelState::Up | TunnelState::Down => (json!(snake(&tunnel.state)), Value::Null),
                TunnelState::NotCollected => (
                    Value::Null,
                    json!(match tunnel.state_reason {
                        Some(r) => snake(&r),
                        None => snake(&tunnel.state),
                    }),
                ),
            };
            rows.push(vec![
                json!(device),
                json!(id),
                json!(s.segment),
                json!(tunnel.label()),
                encap.map_or(Value::Null, |v| json!(v.interface.to_string())),
                json!(tunnel.transport),
                encap.map_or(Value::Null, |v| json!(v.peer.to_string())),
                far.map_or(Value::Null, Value::from),
                far_interface.map_or(Value::Null, Value::from),
                state,
                reason,
                tunnel.far_paths.map_or(Value::Null, |n| json!(n)),
                json!(spans(&tunnel.spans)),
            ]);
        }
    }
    rows
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
    let p = frame::show(d, frame(t, d)?, sel).map_err(invalid)?;
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
    let p = frame::lpm(d, frame(t, d)?, sel, column, address).map_err(invalid)?;
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
    let rows = frame::unique(d, frame(t, d)?, sel, columns).map_err(invalid)?;
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
    let (total, columns) = frame::summarize(d, frame(t, d)?, sel).map_err(invalid)?;
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rsim_contract::table::Selection;
    use rsim_contract::twin::TwinJson;
    use serde_json::{Value, json};

    use super::utc_time;
    use crate::commands::Loaded;

    fn loaded(twin: rsim_engine::Twin, name: &str) -> Loaded {
        Loaded {
            twin,
            identity: TwinJson::builtin(name).unwrap(),
            coverage: BTreeMap::new(),
            bgp: BTreeMap::new(),
            facts: BTreeMap::new(),
            seen: Vec::new(),
            fabric: BTreeMap::new(),
            tables: Default::default(),
            source: None,
        }
    }

    fn sdwan_paths(t: &Loaded) -> Vec<Vec<Value>> {
        super::show("sdwan", t, "sdwan-paths", &Selection::default())
            .unwrap()
            .rows
    }

    #[test]
    fn each_tunnel_of_a_tunnel_selection_is_a_row_with_its_far_end_and_its_state() {
        let twin = rsim_topologies::sdwan_site(rsim_topologies::SdwanOpts {
            private_tunnel: rsim_functions::TunnelState::Down,
            ..Default::default()
        })
        .build()
        .expect("the twin builds");
        let rows = sdwan_paths(&loaded(twin, "sdwan"));
        let row = |device: &str,
                   far: &str,
                   link: &str,
                   transport: &str,
                   peer: &str,
                   state: Option<&str>| {
            let line = if link == "wan1" { 23 } else { 24 };
            json!([
                device,
                format!("{device}/sdwan/select/0/{far}"),
                0,
                format!("{link}~{far}:{link}"),
                link,
                transport,
                peer,
                far,
                link,
                state,
                null,
                null,
                [format!("{device}.conf:{line}-{line}")],
            ])
        };
        let want = vec![
            row(
                "branch1",
                "hub1",
                "wan1",
                "public",
                "203.0.113.1",
                Some("up"),
            ),
            row(
                "branch1",
                "hub1",
                "wan2",
                "mpls",
                "172.16.9.1",
                Some("down"),
            ),
            row(
                "hub1",
                "branch1",
                "wan1",
                "public",
                "198.51.100.1",
                Some("up"),
            ),
            row("hub1", "branch1", "wan2", "mpls", "172.16.1.1", Some("up")),
        ];
        let got: Vec<Value> = rows.into_iter().map(Value::from).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn a_twin_with_no_sdwan_has_no_sdwan_path() {
        let twin = rsim_topologies::builtin("leaf-spine").unwrap();
        assert!(sdwan_paths(&loaded(twin, "leaf-spine")).is_empty());
    }

    #[test]
    fn a_time_prints_as_its_utc_date_and_time() {
        assert_eq!(utc_time(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_time(951_782_400_000), "2000-02-29T00:00:00Z");
        assert_eq!(utc_time(1_700_000_000_999), "2023-11-14T22:13:20Z");
        assert_eq!(utc_time(4_107_542_399_000), "2100-02-28T23:59:59Z");
    }
}
