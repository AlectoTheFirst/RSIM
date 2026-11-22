use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use arrow_array::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;

use crate::blob::{self, Entropy};
use crate::{
    CHECKPOINT_INTERVAL, DeviceManifest, Hash, Keys, Row, SectionEntry, SnapshotManifest,
    StoreError, TABLES, TableRef, TableSchema,
};

/// The error of a walk of the parents of a snapshot.
pub(crate) enum Walk {
    /// A parent manifest does not exist.
    Parent(StoreError),
    Other(StoreError),
}

impl From<Walk> for StoreError {
    fn from(w: Walk) -> StoreError {
        match w {
            Walk::Parent(e) | Walk::Other(e) => e,
        }
    }
}

/// A snapshot store in a directory.
#[derive(Debug)]
pub struct Store {
    dir: PathBuf,
    keys: Keys,
}

/// The state of all devices at one snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub manifest: SnapshotManifest,
    /// The newest manifest of each device, by device.
    pub devices: BTreeMap<String, DeviceManifest>,
}

/// The new state of one device in a cycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceUpdate {
    pub device: String,
    pub vendor: String,
    pub collected_at: u64,
    pub sections: Vec<SectionEntry>,
    /// New rows by table name. Each item is the blob of a section and the
    /// rows of that section. A table that is not in the map keeps the rows
    /// of the previous manifest of the device.
    pub tables: BTreeMap<String, Vec<(Hash, Vec<Row>)>>,
    /// The host name or the address to which the collector connected.
    pub management_address: Option<String>,
}

/// A cycle that collects device updates and writes them as one snapshot.
#[derive(Debug)]
pub struct Cycle<'a> {
    store: &'a Store,
    base: Option<Snapshot>,
    cycle: u64,
    time: u64,
    updates: BTreeMap<String, DeviceUpdate>,
    removed: BTreeSet<String>,
    inventory_version: Option<u64>,
}

/// A cycle with all its files written except `HEAD`. A reader does not see
/// it until [`Prepared::publish`].
#[derive(Debug)]
#[must_use = "a prepared cycle is not visible until it is published"]
pub struct Prepared<'a> {
    store: &'a Store,
    snapshot: Snapshot,
}

/// Writes a file that must not exist. The file is complete before it gets
/// its name, and a hard link gives the name only if no file has it, so an
/// existing file never changes. Returns `false` if the file exists.
fn write_once(path: &Path, bytes: &[u8]) -> Result<bool, StoreError> {
    if path.exists() {
        return Ok(false);
    }
    let tmp = write_tmp(path, bytes)?;
    let linked = fs::hard_link(&tmp, path);
    let _ = fs::remove_file(&tmp);
    match linked {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(StoreError::io(path, e)),
    }
}

/// Writes a file that only one cycle number names, such as a table file or
/// a snapshot manifest. If the file exists, another writer took the same
/// cycle number, and the cycle fails with [`StoreError::Conflict`].
fn write_cycle_file(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    if write_once(path, bytes)? {
        Ok(())
    } else {
        Err(StoreError::Conflict(format!(
            "{} exists: another writer wrote the same cycle",
            path.display()
        )))
    }
}

/// Writes the files with [`write_once`] on some threads at the same time.
fn write_all_once(files: &[(PathBuf, Vec<u8>)]) -> Result<(), StoreError> {
    const THREADS: usize = 16;
    if files.len() < 2 * THREADS {
        for (p, b) in files {
            write_once(p, b)?;
        }
        return Ok(());
    }
    let chunk = files.len().div_ceil(THREADS);
    std::thread::scope(|scope| {
        let handles: Vec<_> = files
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || {
                    for (p, b) in part {
                        write_once(p, b)?;
                    }
                    Ok::<(), StoreError>(())
                })
            })
            .collect();
        handles
            .into_iter()
            .try_for_each(|h| h.join().expect("a writer thread does not panic"))
    })
}

/// Replaces a file atomically.
pub(crate) fn write_replace(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let tmp = write_tmp(path, bytes)?;
    fs::rename(&tmp, path).map_err(|e| StoreError::io(path, e))
}

/// Writes the bytes to a new temporary file next to `path`, with a name
/// that no other writer uses.
fn write_tmp(path: &Path, bytes: &[u8]) -> Result<PathBuf, StoreError> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .map_or_else(Default::default, |f| f.to_string_lossy());
    let tmp = path.with_file_name(format!(".{name}.{}.{n}.tmp", std::process::id()));
    let mut f = fs::File::create_new(&tmp).map_err(|e| StoreError::io(&tmp, e))?;
    f.write_all(bytes).map_err(|e| StoreError::io(&tmp, e))?;
    f.sync_all().map_err(|e| StoreError::io(&tmp, e))?;
    Ok(tmp)
}

pub(crate) fn read(path: &Path) -> Result<Vec<u8>, StoreError> {
    fs::read(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => StoreError::NotFound(path.display().to_string()),
        _ => StoreError::io(path, e),
    })
}

pub(crate) fn cycle_name(cycle: u64) -> String {
    format!("{cycle:020}")
}

impl Store {
    /// Opens the store in `dir` and makes its directories if they do not
    /// exist.
    pub fn open(dir: impl Into<PathBuf>, keys: Keys) -> Result<Store, StoreError> {
        let dir = dir.into();
        for sub in ["blobs", "devices", "snapshots"] {
            let p = dir.join(sub);
            fs::create_dir_all(&p).map_err(|e| StoreError::io(&p, e))?;
        }
        for t in TABLES {
            let p = dir.join("tables").join(t.name);
            fs::create_dir_all(&p).map_err(|e| StoreError::io(&p, e))?;
        }
        Ok(Store { dir, keys })
    }

    /// Opens an existing store in `dir` to read it. It writes nothing.
    pub fn open_read(dir: impl Into<PathBuf>, keys: Keys) -> Result<Store, StoreError> {
        let dir = dir.into();
        let p = dir.join("snapshots");
        if !p.is_dir() {
            return Err(StoreError::NotFound(format!(
                "{} is not a store",
                dir.display()
            )));
        }
        Ok(Store { dir, keys })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    pub(crate) fn blob_path(&self, h: &Hash) -> PathBuf {
        self.dir.join("blobs").join(h.to_string())
    }

    pub(crate) fn table_path(&self, table: &str, cycle: u64) -> PathBuf {
        self.dir
            .join("tables")
            .join(table)
            .join(format!("{}.parquet", cycle_name(cycle)))
    }

    pub(crate) fn snapshot_path(&self, cycle: u64) -> PathBuf {
        self.dir.join("snapshots").join(cycle_name(cycle))
    }

    /// Stores the raw bytes of a section, and returns the blob name. Bytes
    /// that the store has already cost no write.
    pub fn put_blob(&self, plain: &[u8], entropy: &mut dyn Entropy) -> Result<Hash, StoreError> {
        let name = self.keys.hash(plain);
        let path = self.blob_path(&name);
        if !path.exists() {
            write_once(&path, &blob::encrypt(&self.keys, &name, plain, entropy))?;
        }
        Ok(name)
    }

    /// The raw bytes of a blob.
    pub fn read_blob(&self, name: &Hash) -> Result<Vec<u8>, StoreError> {
        blob::decrypt(&self.keys, name, &read(&self.blob_path(name))?)
    }

    /// The number of the newest published snapshot.
    pub fn head(&self) -> Result<Option<u64>, StoreError> {
        let path = self.dir.join("HEAD");
        match fs::read_to_string(&path) {
            Ok(s) => s
                .trim()
                .parse()
                .map(Some)
                .map_err(|_| StoreError::Invalid(format!("HEAD {s:?} is not a cycle number"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::io(&path, e)),
        }
    }

    /// The newest published snapshot.
    pub fn latest(&self) -> Result<Option<Snapshot>, StoreError> {
        self.head()?.map(|c| self.snapshot(c)).transpose()
    }

    /// The manifest of the snapshot of a cycle.
    pub fn snapshot_manifest(&self, cycle: u64) -> Result<SnapshotManifest, StoreError> {
        let m: SnapshotManifest = serde_json::from_slice(&read(&self.snapshot_path(cycle))?)?;
        if m.cycle != cycle {
            return Err(StoreError::Integrity(format!(
                "snapshot file {cycle} holds cycle {}",
                m.cycle
            )));
        }
        Ok(m)
    }

    /// The device manifest with this name.
    pub fn device_manifest(&self, name: &Hash) -> Result<DeviceManifest, StoreError> {
        let bytes = read(&self.dir.join("devices").join(name.to_string()))?;
        if self.keys.hash(&bytes) != *name {
            return Err(StoreError::Integrity(format!(
                "device manifest {name} does not have its name"
            )));
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// The snapshot of a cycle. The reader walks the parents back to the
    /// newest checkpoint, and the newest manifest of each device wins. A
    /// device that a snapshot removes is not in it, and is not in the
    /// snapshots after it until one of them lists the device again. The
    /// parent of a snapshot has a smaller cycle number, so the walk ends. A
    /// parent that a prune deletes during the walk starts the walk again.
    pub fn snapshot(&self, cycle: u64) -> Result<Snapshot, StoreError> {
        const WALKS: usize = 3;
        let mut walk = 1;
        let (top, names) = loop {
            match self.chain_names(cycle) {
                Ok(v) => break v,
                Err(Walk::Parent(_)) if walk < WALKS => walk += 1,
                Err(w) => return Err(w.into()),
            }
        };
        let mut devices = BTreeMap::new();
        for (d, h) in names {
            devices.insert(d, self.device_manifest(&h)?);
        }
        Ok(Snapshot {
            manifest: top,
            devices,
        })
    }

    /// The manifest of a cycle and the device manifest name of each device
    /// of its snapshot.
    pub(crate) fn chain_names(
        &self,
        cycle: u64,
    ) -> Result<(SnapshotManifest, BTreeMap<String, Hash>), Walk> {
        let top = self.snapshot_manifest(cycle).map_err(Walk::Other)?;
        let mut chain = vec![top.clone()];
        loop {
            let last = chain.last().expect("the chain is not empty");
            if last.checkpoint {
                break;
            }
            let parent = last.parent.ok_or_else(|| {
                Walk::Other(StoreError::Integrity(format!(
                    "snapshot {cycle} has no checkpoint before it"
                )))
            })?;
            if parent >= last.cycle {
                return Err(Walk::Other(StoreError::Integrity(format!(
                    "snapshot {} names the parent {parent}, which is not older",
                    last.cycle
                ))));
            }
            chain.push(self.snapshot_manifest(parent).map_err(|e| match e {
                StoreError::NotFound(_) => Walk::Parent(e),
                e => Walk::Other(e),
            })?);
        }
        let mut names: BTreeMap<String, Hash> = BTreeMap::new();
        for m in chain.iter().rev() {
            for d in &m.removed {
                names.remove(d);
            }
            names.extend(m.devices.iter().map(|(d, h)| (d.clone(), *h)));
        }
        Ok((top, names))
    }

    /// The manifest of the newest published snapshot.
    pub fn head_manifest(&self) -> Result<Option<SnapshotManifest>, StoreError> {
        self.head()?.map(|c| self.snapshot_manifest(c)).transpose()
    }

    /// The cycle of the snapshot of the second `second` since the Unix
    /// epoch, on the parents of the newest snapshot.
    pub fn cycle_at(&self, second: u64) -> Result<Option<u64>, StoreError> {
        let Some(mut m) = self.head_manifest()? else {
            return Ok(None);
        };
        loop {
            let s = m.time / 1000;
            if s == second {
                return Ok(Some(m.cycle));
            }
            let Some(parent) = m.parent.filter(|p| s > second && *p < m.cycle) else {
                return Ok(None);
            };
            m = match self.snapshot_manifest(parent) {
                Ok(m) => m,
                Err(StoreError::NotFound(_)) => return Ok(None),
                Err(e) => return Err(e),
            };
        }
    }

    /// Starts a cycle at `time`, in milliseconds since the Unix epoch. The
    /// cycle builds on the newest published snapshot. It takes the next
    /// cycle number that no file uses, so files that a stopped cycle left
    /// are never changed. The second of `time` is after the second of the
    /// newest snapshot, so each snapshot has its own second; another time
    /// fails with [`StoreError::Invalid`].
    pub fn begin(&self, time: u64) -> Result<Cycle<'_>, StoreError> {
        let base = self.latest()?;
        if let Some(b) = base
            .as_ref()
            .filter(|b| time / 1000 <= b.manifest.time / 1000)
        {
            return Err(StoreError::Invalid(format!(
                "the time {time} is not in a second after the time {} of snapshot {}",
                b.manifest.time, b.manifest.cycle
            )));
        }
        let mut cycle = base.as_ref().map_or(0, |s| s.manifest.cycle + 1);
        while self.snapshot_path(cycle).exists()
            || TABLES
                .iter()
                .any(|t| self.table_path(t.name, cycle).exists())
        {
            cycle += 1;
        }
        Ok(Cycle {
            store: self,
            base,
            cycle,
            time,
            updates: BTreeMap::new(),
            removed: BTreeSet::new(),
            inventory_version: None,
        })
    }

    /// The rows of all devices of the snapshot in one table, sorted by
    /// device. Each item is one device with its rows.
    pub fn read_table(
        &self,
        snapshot: &Snapshot,
        table: &TableSchema,
    ) -> Result<Vec<(String, RecordBatch)>, StoreError> {
        let mut files: BTreeMap<u64, RecordBatch> = BTreeMap::new();
        let mut out = Vec::new();
        for (device, m) in &snapshot.devices {
            let Some(r) = m.tables.get(table.name) else {
                continue;
            };
            if r.version != table.version {
                return Err(StoreError::SchemaVersion {
                    table: table.name.to_string(),
                    found: r.version,
                    expected: table.version,
                });
            }
            if let std::collections::btree_map::Entry::Vacant(v) = files.entry(r.cycle) {
                v.insert(self.read_table_file(table, r.cycle)?);
            }
            let batch = &files[&r.cycle];
            let end = r.first_row.checked_add(r.rows);
            if end.is_none_or(|e| e > batch.num_rows() as u64) {
                return Err(StoreError::Integrity(format!(
                    "{} rows {} and {} after it of cycle {} are outside the file",
                    table.name, r.first_row, r.rows, r.cycle
                )));
            }
            out.push((
                device.clone(),
                batch.slice(r.first_row as usize, r.rows as usize),
            ));
        }
        Ok(out)
    }

    fn read_table_file(&self, table: &TableSchema, cycle: u64) -> Result<RecordBatch, StoreError> {
        let path = self.table_path(table.name, cycle);
        let file = fs::File::open(&path).map_err(|e| StoreError::io(&path, e))?;
        let reader = ParquetRecordBatchReaderBuilder::try_new(file)?.build()?;
        let schema = table.arrow_schema();
        let mut batches = Vec::new();
        for b in reader {
            batches.push(b?);
        }
        if let Some(b) = batches.first()
            && b.schema() != schema
        {
            return Err(StoreError::Integrity(format!(
                "{} has a schema that is not the schema of version {}",
                path.display(),
                table.version
            )));
        }
        Ok(arrow_select::concat::concat_batches(&schema, &batches)?)
    }
}

impl<'a> Cycle<'a> {
    pub fn number(&self) -> u64 {
        self.cycle
    }

    /// The snapshot that the cycle builds on.
    pub fn base(&self) -> Option<&Snapshot> {
        self.base.as_ref()
    }

    /// Adds the update of a device. A second update of the same device
    /// replaces the first, and an update cancels a removal of the device in
    /// this cycle.
    pub fn add(&mut self, update: DeviceUpdate) -> Result<(), StoreError> {
        for (name, parts) in &update.tables {
            let schema = crate::table(name)
                .ok_or_else(|| StoreError::Invalid(format!("no table {name}")))?;
            for (_, rows) in parts {
                schema.check(rows)?;
            }
        }
        self.removed.remove(&update.device);
        self.updates.insert(update.device.clone(), update);
        Ok(())
    }

    /// Sets the version of the inventory database that the cycle read. The
    /// snapshot manifest records it.
    pub fn set_inventory_version(&mut self, version: Option<u64>) {
        self.inventory_version = version;
    }

    /// Removes a device from the snapshot of this cycle and from the
    /// snapshots after it, until a later cycle adds the device again. It
    /// drops an update of the device in this cycle. A device that the base
    /// does not have needs no removal, and the call does nothing for it.
    pub fn remove(&mut self, device: &str) {
        self.updates.remove(device);
        if self
            .base
            .as_ref()
            .is_some_and(|s| s.devices.contains_key(device))
        {
            self.removed.insert(device.to_string());
        }
    }

    /// Writes the table files, the device manifests and the snapshot
    /// manifest. A device manifest that differs from the base in no more
    /// than the collection time is not written. The snapshot manifest lists
    /// the removed devices, and a checkpoint leaves them out. If no device
    /// changed and no device is removed, the cycle writes nothing and gives
    /// `None`. If another writer wrote a
    /// table file or the snapshot manifest of the same cycle number, the
    /// cycle fails with [`StoreError::Conflict`].
    pub fn prepare(self) -> Result<Option<Prepared<'a>>, StoreError> {
        let store = self.store;
        let prev = |d: &str| self.base.as_ref().and_then(|s| s.devices.get(d));
        let mut table_files: Vec<(PathBuf, Vec<u8>)> = Vec::new();
        let mut manifests: BTreeMap<String, DeviceManifest> = BTreeMap::new();
        for (d, u) in &self.updates {
            manifests.insert(
                d.clone(),
                DeviceManifest {
                    device: u.device.clone(),
                    vendor: u.vendor.clone(),
                    collected_at: u.collected_at,
                    sections: u.sections.clone(),
                    tables: prev(d).map(|m| m.tables.clone()).unwrap_or_default(),
                    management_address: u.management_address.clone(),
                },
            );
        }

        // Each table file holds the new rows of the devices in device order.
        for t in TABLES {
            let mut parts: Vec<(&str, String, &[Row])> = Vec::new();
            let mut first = 0u64;
            let mut used = false;
            for (d, u) in &self.updates {
                let Some(sections) = u.tables.get(t.name) else {
                    continue;
                };
                used = true;
                let rows: u64 = sections.iter().map(|(_, r)| r.len() as u64).sum();
                let m = manifests.get_mut(d).expect("each update has a manifest");
                m.tables.insert(
                    t.name.to_string(),
                    TableRef {
                        cycle: self.cycle,
                        version: t.version,
                        first_row: first,
                        rows,
                    },
                );
                first += rows;
                for (b, r) in sections {
                    parts.push((d.as_str(), b.to_string(), r.as_slice()));
                }
            }
            if !used {
                continue;
            }
            let batch = t.batch(parts.iter().map(|(d, b, r)| (*d, b.as_str(), *r)))?;
            let props = WriterProperties::builder()
                .set_compression(Compression::SNAPPY)
                .set_created_by("rsim-store".to_string())
                .build();
            let mut buf = Vec::new();
            let mut w = ArrowWriter::try_new(&mut buf, batch.schema(), Some(props))?;
            w.write(&batch)?;
            w.close()?;
            table_files.push((store.table_path(t.name, self.cycle), buf));
        }

        let changed: BTreeMap<String, DeviceManifest> = manifests
            .into_iter()
            .filter(|(d, m)| prev(d).is_none_or(|p| m.differs(p)))
            .collect();
        if changed.is_empty() && self.removed.is_empty() {
            return Ok(None);
        }
        for (path, buf) in &table_files {
            write_cycle_file(path, buf)?;
        }

        let mut files = Vec::with_capacity(changed.len());
        let mut names = BTreeMap::new();
        for (d, m) in &changed {
            let bytes = serde_json::to_vec_pretty(m)?;
            let name = store.keys.hash(&bytes);
            files.push((store.dir.join("devices").join(name.to_string()), bytes));
            names.insert(d.clone(), name);
        }
        write_all_once(&files)?;

        let checkpoint = self.base.is_none() || self.cycle.is_multiple_of(CHECKPOINT_INTERVAL);
        let mut devices: BTreeMap<String, DeviceManifest> = self
            .base
            .as_ref()
            .map(|s| s.devices.clone())
            .unwrap_or_default();
        devices.retain(|d, _| !self.removed.contains(d));
        devices.extend(changed);
        if checkpoint {
            for (d, m) in &devices {
                if !names.contains_key(d) {
                    let bytes = serde_json::to_vec_pretty(m)?;
                    names.insert(d.clone(), store.keys.hash(&bytes));
                }
            }
        }
        let manifest = SnapshotManifest {
            cycle: self.cycle,
            time: self.time,
            parent: self.base.as_ref().map(|s| s.manifest.cycle),
            checkpoint,
            schemas: TABLES
                .iter()
                .map(|t| (t.name.to_string(), t.version))
                .collect(),
            devices: names,
            removed: self.removed,
            inventory_version: self.inventory_version,
        };
        write_cycle_file(
            &store.snapshot_path(self.cycle),
            &serde_json::to_vec_pretty(&manifest)?,
        )?;
        Ok(Some(Prepared {
            store,
            snapshot: Snapshot { manifest, devices },
        }))
    }
}

impl Prepared<'_> {
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// Makes the snapshot the newest snapshot of the store.
    pub fn publish(self) -> Result<Snapshot, StoreError> {
        write_replace(
            &self.store.dir.join("HEAD"),
            format!("{}\n", self.snapshot.manifest.cycle).as_bytes(),
        )?;
        Ok(self.snapshot)
    }
}
