//! The snapshot store of rsim.
//!
//! The store holds encrypted raw sections, Parquet tables of the collected
//! state, a manifest for each device collection and a manifest for each
//! snapshot. The writer adds files and changes no file, except the `HEAD`
//! file that names the newest snapshot and the prune. The prune deletes the
//! snapshots older than the history, keeps the newest snapshot, makes the
//! oldest kept snapshot a checkpoint and deletes the files that no kept
//! snapshot names. Each snapshot has its own second. The reader uses no
//! clock and no randomness.
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
mod prune;
mod store;
mod table;

pub use blob::Entropy;
pub use canonical::{Format, canonical, change_hash, change_hash_kept, keep_only, strip_volatile};
pub use error::StoreError;
pub use hash::{Hash, Keys};
pub use manifest::{
    CHECKPOINT_INTERVAL, Class, DeviceManifest, SectionEntry, SectionStatus, SnapshotManifest,
    TableRef,
};
pub use prune::Pruned;
pub use store::{Cycle, DeviceUpdate, Prepared, Snapshot, Store};
pub use table::{
    ADDRESSES, CLIENTS, Cell, ColType, Column, LINK_SPEEDS, LINKS, MAC_TABLE, NEIGHBOURS,
    PREFIX_COLUMNS, ROUTES, Row, TABLES, TableSchema, VELOCLOUD_BGP_SESSION, VELOCLOUD_EDGE_STATE,
    VELOCLOUD_LINK_STATE, VELOCLOUD_ROUTE, table,
};
