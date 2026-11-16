use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Format, Hash};

/// Each cycle with a number that is a multiple of this value is a
/// checkpoint. A checkpoint lists the manifests of all devices.
pub const CHECKPOINT_INTERVAL: u64 = 60;

/// The class of a section. It controls the work that a change causes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// The device compiles again.
    Configuration,
    /// The collected state of the device changes.
    Observation,
    /// No work. Stored only with a forced full collection.
    Volatile,
}

/// The state of a section in a device manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum SectionStatus {
    /// The read of `collected_at` gave the blob.
    Fresh,
    /// The last read failed. The blob is the last good read.
    Old { error: String },
    /// No read was successful. The section has no blob.
    Missing { error: String },
}

/// One section of a device manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionEntry {
    /// The name of the section, unique in the device.
    pub name: String,
    /// The command or the API path that read the section.
    pub command: String,
    pub class: Class,
    pub format: Format,
    /// The hash of the canonical form without the volatile parts.
    pub change_hash: Option<Hash>,
    /// The name of the blob with the raw bytes.
    pub blob: Option<Hash>,
    pub status: SectionStatus,
    /// The time of the read that gave the blob, in milliseconds since the
    /// Unix epoch.
    pub collected_at: Option<u64>,
}

/// The rows of one device in one table file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableRef {
    /// The cycle that wrote the file `tables/<table>/<cycle>.parquet`.
    pub cycle: u64,
    /// The schema version of the file.
    pub version: u32,
    pub first_row: u64,
    pub rows: u64,
}

/// The manifest of one device collection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceManifest {
    pub device: String,
    pub vendor: String,
    /// The time of the collection that made this manifest, in milliseconds
    /// since the Unix epoch.
    pub collected_at: u64,
    pub sections: Vec<SectionEntry>,
    /// The rows of the device in each table, by table name.
    pub tables: BTreeMap<String, TableRef>,
}

impl DeviceManifest {
    pub fn section(&self, name: &str) -> Option<&SectionEntry> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// True if the 2 manifests differ in more than the collection time.
    pub fn differs(&self, other: &DeviceManifest) -> bool {
        self.device != other.device
            || self.vendor != other.vendor
            || self.sections != other.sections
            || self.tables != other.tables
    }
}

/// The manifest of one snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub cycle: u64,
    /// The time of the cycle, in milliseconds since the Unix epoch.
    pub time: u64,
    pub parent: Option<u64>,
    /// True if `devices` lists all devices. Otherwise it lists the devices
    /// that changed since the parent.
    pub checkpoint: bool,
    /// The schema version of each table that this build writes.
    pub schemas: BTreeMap<String, u32>,
    /// The manifest of each listed device, by device.
    pub devices: BTreeMap<String, Hash>,
}
