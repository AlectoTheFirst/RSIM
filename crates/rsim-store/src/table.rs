//! The schemas of the Parquet tables of the collected state.
//!
//! Each table starts with the columns of [`PREFIX_COLUMNS`]: the device, the
//! blob of the section that gave the row, and the index of the row in that
//! section. The schemas are the same for all vendors.

use std::sync::Arc;

use arrow_array::builder::{BooleanBuilder, StringBuilder, UInt64Builder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema};

use crate::StoreError;

/// The type of a column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColType {
    Str,
    U64,
    Bool,
}

/// A column of a table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Column {
    pub name: &'static str,
    pub ty: ColType,
    pub nullable: bool,
}

const fn col(name: &'static str, ty: ColType, nullable: bool) -> Column {
    Column { name, ty, nullable }
}

/// The schema of a table.
#[derive(Debug, PartialEq, Eq)]
pub struct TableSchema {
    pub name: &'static str,
    pub version: u32,
    /// The columns after the prefix columns.
    pub columns: &'static [Column],
}

/// The value of a cell.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cell {
    Null,
    Str(String),
    U64(u64),
    Bool(bool),
}

/// The cells of a row, in the order of the columns after the prefix.
pub type Row = Vec<Cell>;

/// The prefix columns of each table.
pub const PREFIX_COLUMNS: &[Column] = &[
    col("device", ColType::Str, false),
    col("blob", ColType::Str, false),
    col("index", ColType::U64, false),
];

use ColType::{Bool, Str, U64};

/// IPv4 ARP and IPv6 neighbour entries.
pub const NEIGHBOURS: TableSchema = TableSchema {
    name: "neighbours",
    version: 1,
    columns: &[
        col("interface", Str, false),
        col("ip", Str, false),
        col("mac", Str, true),
        col("state", Str, true),
    ],
};

/// Interface addresses.
pub const ADDRESSES: TableSchema = TableSchema {
    name: "addresses",
    version: 1,
    columns: &[col("interface", Str, false), col("prefix", Str, false)],
};

/// Link state of the interfaces.
pub const LINKS: TableSchema = TableSchema {
    name: "links",
    version: 1,
    columns: &[
        col("interface", Str, false),
        col("mac", Str, true),
        col("mtu", U64, true),
        col("admin_up", Bool, false),
        col("oper_state", Str, true),
        col("parent", Str, true),
        col("vlan", U64, true),
    ],
};

/// Link speeds in Mbit/s and the duplex.
pub const LINK_SPEEDS: TableSchema = TableSchema {
    name: "link_speeds",
    version: 1,
    columns: &[
        col("interface", Str, false),
        col("mbps", U64, true),
        col("duplex", Str, true),
    ],
};

/// The collected RIB.
pub const ROUTES: TableSchema = TableSchema {
    name: "routes",
    version: 1,
    columns: &[
        col("vrf", Str, false),
        col("prefix", Str, false),
        col("protocol", Str, false),
        col("selected", Bool, false),
        col("distance", U64, true),
        col("metric", U64, true),
        col("next_hop", Str, true),
        col("interface", Str, true),
    ],
};

/// Client attachment: a client with its access point or switch port.
pub const CLIENTS: TableSchema = TableSchema {
    name: "clients",
    version: 1,
    columns: &[
        col("mac", Str, false),
        col("ip", Str, true),
        col("hostname", Str, true),
        col("network", Str, true),
        col("vlan", U64, true),
        col("wired", Bool, false),
        col("ap_mac", Str, true),
        col("switch_mac", Str, true),
        col("switch_port", U64, true),
    ],
};

/// All tables, sorted by name.
pub const TABLES: &[&TableSchema] = &[
    &ADDRESSES,
    &CLIENTS,
    &LINK_SPEEDS,
    &LINKS,
    &NEIGHBOURS,
    &ROUTES,
];

/// The schema of a table by name.
pub fn table(name: &str) -> Option<&'static TableSchema> {
    TABLES.iter().copied().find(|t| t.name == name)
}

impl TableSchema {
    /// All columns with the prefix columns.
    pub fn all_columns(&self) -> impl Iterator<Item = &'static Column> + use<> {
        PREFIX_COLUMNS.iter().chain(self.columns.iter())
    }

    pub fn arrow_schema(&self) -> Arc<Schema> {
        let fields: Vec<Field> = self
            .all_columns()
            .map(|c| {
                let ty = match c.ty {
                    ColType::Str => DataType::Utf8,
                    ColType::U64 => DataType::UInt64,
                    ColType::Bool => DataType::Boolean,
                };
                Field::new(c.name, ty, c.nullable)
            })
            .collect();
        Arc::new(Schema::new(fields))
    }

    /// Checks that each row has the columns of the table with the right
    /// types.
    pub fn check(&self, rows: &[Row]) -> Result<(), StoreError> {
        for (i, r) in rows.iter().enumerate() {
            if r.len() != self.columns.len() {
                return Err(StoreError::Invalid(format!(
                    "row {i} of {} has {} cells, the table has {} columns",
                    self.name,
                    r.len(),
                    self.columns.len()
                )));
            }
            for (c, v) in self.columns.iter().zip(r) {
                let ok = matches!(
                    (c.ty, v),
                    (ColType::Str, Cell::Str(_))
                        | (ColType::U64, Cell::U64(_))
                        | (ColType::Bool, Cell::Bool(_))
                ) || (c.nullable && *v == Cell::Null);
                if !ok {
                    return Err(StoreError::Invalid(format!(
                        "row {i} of {}: {v:?} is not valid for column {}",
                        self.name, c.name
                    )));
                }
            }
        }
        Ok(())
    }

    /// The record batch of rows with their prefix cells. Each item is the
    /// device, the blob, and the rows of that section in order.
    pub(crate) fn batch<'a>(
        &self,
        parts: impl Iterator<Item = (&'a str, &'a str, &'a [Row])> + Clone,
    ) -> Result<RecordBatch, StoreError> {
        let n: usize = parts.clone().map(|p| p.2.len()).sum();
        let mut device = StringBuilder::new();
        let mut blob = StringBuilder::new();
        let mut index = UInt64Builder::with_capacity(n);
        for (d, b, rows) in parts.clone() {
            for i in 0..rows.len() {
                device.append_value(d);
                blob.append_value(b);
                index.append_value(i as u64);
            }
        }
        let mut cols: Vec<ArrayRef> = vec![
            Arc::new(device.finish()),
            Arc::new(blob.finish()),
            Arc::new(index.finish()),
        ];
        for (k, c) in self.columns.iter().enumerate() {
            let cells = parts.clone().flat_map(|p| p.2.iter().map(move |r| &r[k]));
            let array: ArrayRef = match c.ty {
                ColType::Str => {
                    let mut b = StringBuilder::new();
                    for v in cells {
                        match v {
                            Cell::Str(s) => b.append_value(s),
                            _ => b.append_null(),
                        }
                    }
                    Arc::new(b.finish())
                }
                ColType::U64 => {
                    let mut b = UInt64Builder::with_capacity(n);
                    for v in cells {
                        match v {
                            Cell::U64(x) => b.append_value(*x),
                            _ => b.append_null(),
                        }
                    }
                    Arc::new(b.finish())
                }
                ColType::Bool => {
                    let mut b = BooleanBuilder::with_capacity(n);
                    for v in cells {
                        match v {
                            Cell::Bool(x) => b.append_value(*x),
                            _ => b.append_null(),
                        }
                    }
                    Arc::new(b.finish())
                }
            };
            cols.push(array);
        }
        Ok(RecordBatch::try_new(self.arrow_schema(), cols)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_list_is_sorted_and_names_are_unique() {
        let names: Vec<&str> = TABLES.iter().map(|t| t.name).collect();
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(names, sorted);
        assert_eq!(table("routes"), Some(&ROUTES));
    }

    #[test]
    fn a_row_with_a_wrong_cell_is_rejected() {
        let ok = vec![Cell::Str("eth0".into()), Cell::U64(1000), Cell::Null];
        assert!(LINK_SPEEDS.check(std::slice::from_ref(&ok)).is_ok());
        let null_ok = vec![Cell::Str("eth0".into()), Cell::Null, Cell::Null];
        assert!(LINK_SPEEDS.check(&[null_ok]).is_ok());
        let bad = vec![Cell::Null, Cell::U64(1000), Cell::Null];
        assert!(LINK_SPEEDS.check(&[bad]).is_err());
        assert!(
            LINK_SPEEDS
                .check(&[vec![Cell::Str("eth0".into())]])
                .is_err()
        );
    }
}
