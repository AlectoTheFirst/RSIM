//! The append-only snapshot store of rsim.
//!
//! The store holds encrypted raw sections, Parquet tables of the collected
//! state, a manifest for each device collection and a manifest for each
//! snapshot. The writer adds files and never changes a file, except the
//! `HEAD` file that names the newest snapshot. The reader uses no clock and
//! no randomness.
//!
//! ```text
//! store/
//!   blobs/<blob name>                encrypted raw section bytes
//!   devices/<manifest hash>          device manifests
//!   tables/<table>/<cycle>.parquet   rows of the devices that changed in the cycle
//!   snapshots/<cycle>                snapshot manifests
//!   HEAD                             the number of the newest snapshot
//! ```

mod blob;
mod canonical;
mod error;
mod hash;
mod manifest;
mod store;
mod table;

pub use blob::Entropy;
pub use canonical::{Format, canonical, change_hash, strip_volatile};
pub use error::StoreError;
pub use hash::{Hash, Keys};
pub use manifest::{
    CHECKPOINT_INTERVAL, Class, DeviceManifest, SectionEntry, SectionStatus, SnapshotManifest,
    TableRef,
};
pub use store::{Cycle, DeviceUpdate, Prepared, Snapshot, Store};
pub use table::{
    ADDRESSES, CLIENTS, Cell, ColType, Column, LINK_SPEEDS, LINKS, NEIGHBOURS, PREFIX_COLUMNS,
    ROUTES, Row, TABLES, TableSchema, table,
};
