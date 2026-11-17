//! The collected state of a device: the rows of the tables of the snapshot
//! store.

use arrow_array::cast::AsArray;
use arrow_array::types::UInt64Type;
use arrow_array::{Array, RecordBatch};
use rsim_core::SourceSpan;
use rsim_store::{
    ADDRESSES, LINK_SPEEDS, LINKS, MAC_TABLE, NEIGHBOURS, ROUTES, Snapshot, Store, StoreError,
    TableSchema,
};

/// An address of an interface, for example `192.0.2.1/24`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressRow {
    pub interface: String,
    pub prefix: String,
    pub span: SourceSpan,
}

/// A route of the collected RIB.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRow {
    pub vrf: String,
    pub prefix: String,
    pub protocol: String,
    pub selected: bool,
    pub next_hop: Option<String>,
    pub interface: Option<String>,
    pub span: SourceSpan,
}

/// An entry of the ARP or the IPv6 neighbour table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeighbourRow {
    pub interface: String,
    pub ip: String,
    pub mac: Option<String>,
    pub state: Option<String>,
    pub span: SourceSpan,
}

/// A link of the device: the interface, its MAC and its parent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkRow {
    pub interface: String,
    pub mac: Option<String>,
    pub parent: Option<String>,
    pub vlan: Option<u64>,
    pub span: SourceSpan,
}

/// The speed and the duplex of an interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpeedRow {
    pub interface: String,
    pub mbps: Option<u64>,
    pub duplex: Option<String>,
    pub span: SourceSpan,
}

/// An entry of the MAC table: the VLAN, the MAC, the port and the kind of
/// the entry, for example `dynamic` or `static`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacRow {
    pub vlan: u64,
    pub mac: String,
    pub port: Option<String>,
    pub kind: Option<String>,
    pub span: SourceSpan,
}

/// The collected state of one device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Collected {
    pub addresses: Vec<AddressRow>,
    /// The routes. Empty if the device has no collected RIB.
    pub routes: Vec<RouteRow>,
    pub neighbours: Vec<NeighbourRow>,
    pub links: Vec<LinkRow>,
    pub speeds: Vec<SpeedRow>,
    pub macs: Vec<MacRow>,
}

/// The source span of a row: the device, the table, the blob of its section
/// and its index in the section, from 1.
pub fn row_span(device: &str, table: &str, blob: &str, index: u64) -> SourceSpan {
    let line = u32::try_from(index + 1).unwrap_or(u32::MAX);
    SourceSpan::line(format!("{device}/{table}@{blob}"), line)
}

struct Cols<'a> {
    batch: &'a RecordBatch,
}

impl Cols<'_> {
    fn s(&self, name: &str, row: usize) -> Option<String> {
        let c = self.batch.column_by_name(name)?.as_string::<i32>();
        (!c.is_null(row)).then(|| c.value(row).to_string())
    }
    fn u(&self, name: &str, row: usize) -> Option<u64> {
        let c = self
            .batch
            .column_by_name(name)?
            .as_primitive::<UInt64Type>();
        (!c.is_null(row)).then(|| c.value(row))
    }
    fn b(&self, name: &str, row: usize) -> Option<bool> {
        let c = self.batch.column_by_name(name)?.as_boolean();
        (!c.is_null(row)).then(|| c.value(row))
    }
    fn span(&self, device: &str, table: &str, row: usize) -> SourceSpan {
        row_span(
            device,
            table,
            &self.s("blob", row).unwrap_or_default(),
            self.u("index", row).unwrap_or(0),
        )
    }
}

fn rows<T>(
    store: &Store,
    snapshot: &Snapshot,
    table: &TableSchema,
    device: &str,
    f: impl Fn(&Cols, usize) -> Option<T>,
) -> Result<Vec<T>, StoreError> {
    let mut out = Vec::new();
    for (d, batch) in store.read_table(snapshot, table)? {
        if d != device {
            continue;
        }
        let cols = Cols { batch: &batch };
        out.extend((0..batch.num_rows()).filter_map(|i| f(&cols, i)));
    }
    Ok(out)
}

/// Reads the collected state of a device at a snapshot.
pub fn read(store: &Store, snapshot: &Snapshot, device: &str) -> Result<Collected, StoreError> {
    Ok(Collected {
        addresses: rows(store, snapshot, &ADDRESSES, device, |c, i| {
            Some(AddressRow {
                interface: c.s("interface", i)?,
                prefix: c.s("prefix", i)?,
                span: c.span(device, ADDRESSES.name, i),
            })
        })?,
        routes: rows(store, snapshot, &ROUTES, device, |c, i| {
            Some(RouteRow {
                vrf: c.s("vrf", i)?,
                prefix: c.s("prefix", i)?,
                protocol: c.s("protocol", i)?,
                selected: c.b("selected", i).unwrap_or(false),
                next_hop: c.s("next_hop", i),
                interface: c.s("interface", i),
                span: c.span(device, ROUTES.name, i),
            })
        })?,
        neighbours: rows(store, snapshot, &NEIGHBOURS, device, |c, i| {
            Some(NeighbourRow {
                interface: c.s("interface", i)?,
                ip: c.s("ip", i)?,
                mac: c.s("mac", i),
                state: c.s("state", i),
                span: c.span(device, NEIGHBOURS.name, i),
            })
        })?,
        links: rows(store, snapshot, &LINKS, device, |c, i| {
            Some(LinkRow {
                interface: c.s("interface", i)?,
                mac: c.s("mac", i),
                parent: c.s("parent", i),
                vlan: c.u("vlan", i),
                span: c.span(device, LINKS.name, i),
            })
        })?,
        speeds: rows(store, snapshot, &LINK_SPEEDS, device, |c, i| {
            Some(SpeedRow {
                interface: c.s("interface", i)?,
                mbps: c.u("mbps", i),
                duplex: c.s("duplex", i),
                span: c.span(device, LINK_SPEEDS.name, i),
            })
        })?,
        macs: rows(store, snapshot, &MAC_TABLE, device, |c, i| {
            Some(MacRow {
                vlan: c.u("vlan", i)?,
                mac: c.s("mac", i)?,
                port: c.s("port", i),
                kind: c.s("kind", i),
                span: c.span(device, MAC_TABLE.name, i),
            })
        })?,
    })
}
