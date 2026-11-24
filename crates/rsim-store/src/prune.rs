//! The deletion of the snapshots that are older than the history of the
//! store.

use std::collections::BTreeSet;
use std::fs::{self, TryLockError};
use std::path::Path;

use crate::store::write_replace;
use crate::{Hash, SnapshotManifest, Store, StoreError, TABLES};

/// The result of a prune.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pruned {
    /// The deleted snapshot manifests.
    pub snapshots: usize,
    /// The deleted device manifests, blobs and table files.
    pub files: usize,
    /// The oldest kept snapshot when the prune makes it a checkpoint.
    pub checkpoint: Option<u64>,
}

/// The cycle of a file name `<20 digits>` with the suffix `suffix`.
fn cycle_of(name: &str, suffix: &str) -> Option<u64> {
    let digits = name.strip_suffix(suffix)?;
    (digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}

/// The file names of a folder, sorted.
fn names(dir: &Path) -> Result<Vec<String>, StoreError> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).map_err(|e| StoreError::io(dir, e))? {
        let e = e.map_err(|e| StoreError::io(dir, e))?;
        out.push(e.file_name().to_string_lossy().into_owned());
    }
    out.sort();
    Ok(out)
}

/// Deletes a file. `false` for a file that does not exist.
fn delete(path: &Path) -> Result<bool, StoreError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(StoreError::io(path, e)),
    }
}

impl Store {
    /// The cycles of the snapshot manifests in the store, in order.
    fn cycles(&self) -> Result<Vec<u64>, StoreError> {
        Ok(names(&self.dir().join("snapshots"))?
            .iter()
            .filter_map(|n| cycle_of(n, ""))
            .collect())
    }

    /// Deletes each snapshot whose time is before `cutoff`, in milliseconds
    /// since the Unix epoch, except the newest snapshot. The kept snapshots
    /// are the newest snapshot and its parents with a time at or after
    /// `cutoff`. The steps:
    ///
    /// 1. The oldest kept snapshot that is not a checkpoint becomes a
    ///    checkpoint with no parent, written with an atomic rename.
    /// 2. Each other snapshot manifest older than the newest snapshot is
    ///    deleted, the oldest first.
    /// 3. Each device manifest, blob and table file that no kept snapshot
    ///    names is deleted. A table file of a cycle after the newest
    ///    snapshot stays.
    ///
    /// After each step the kept snapshots read. A store whose oldest
    /// snapshot is at or after `cutoff` is not changed.
    ///
    /// A prune that deletes a snapshot holds the exclusive lock on the file
    /// `LOCK` and then takes the shared lock of the store again. It fails
    /// with [`StoreError::Conflict`] and changes nothing while another
    /// [`Store`] opened to write holds its shared lock. A prune of a store
    /// opened to read fails with [`StoreError::Invalid`].
    pub fn prune(&self, cutoff: u64) -> Result<Pruned, StoreError> {
        let Some(lock) = self.lock_file() else {
            return Err(StoreError::Invalid(
                "a store opened to read is not pruned".into(),
            ));
        };
        if !self.has_old_snapshot(cutoff)? {
            return Ok(Pruned::default());
        }
        let path = self.dir().join("LOCK");
        lock.unlock().map_err(|e| StoreError::io(&path, e))?;
        if let Err(e) = lock.try_lock() {
            lock.lock_shared().map_err(|e| StoreError::io(&path, e))?;
            return Err(match e {
                TryLockError::WouldBlock => {
                    StoreError::Conflict("another writer has the store open".into())
                }
                TryLockError::Error(e) => StoreError::io(&path, e),
            });
        }
        let out = self.prune_locked(cutoff);
        let shared = lock
            .unlock()
            .and_then(|()| lock.lock_shared())
            .map_err(|e| StoreError::io(&path, e));
        let out = out?;
        shared?;
        Ok(out)
    }

    /// Whether the oldest snapshot is older than the newest snapshot and
    /// has a time before `cutoff`.
    fn has_old_snapshot(&self, cutoff: u64) -> Result<bool, StoreError> {
        let Some(head) = self.head()? else {
            return Ok(false);
        };
        Ok(match self.cycles()?.first() {
            Some(&c) => c != head && self.snapshot_manifest(c)?.time < cutoff,
            None => false,
        })
    }

    /// [`Store::prune`] with the exclusive lock held.
    fn prune_locked(&self, cutoff: u64) -> Result<Pruned, StoreError> {
        let mut out = Pruned::default();
        if !self.has_old_snapshot(cutoff)? {
            return Ok(out);
        }
        let Some(head) = self.head()? else {
            return Ok(out);
        };
        let cycles = self.cycles()?;

        // The walk keeps the cycle and the device manifests of each kept
        // snapshot, and the whole manifest of the oldest one.
        let mut keep: BTreeSet<u64> = BTreeSet::new();
        let mut devices: BTreeSet<Hash> = BTreeSet::new();
        let mut first: SnapshotManifest = self.snapshot_manifest(head)?;
        loop {
            keep.insert(first.cycle);
            devices.extend(first.devices.values().copied());
            let Some(parent) = first.parent else { break };
            if parent >= first.cycle {
                return Err(StoreError::Integrity(format!(
                    "snapshot {} names the parent {parent}, which is not older",
                    first.cycle
                )));
            }
            let m = match self.snapshot_manifest(parent) {
                Ok(m) => m,
                Err(StoreError::NotFound(_)) => break,
                Err(e) => return Err(e),
            };
            if m.time < cutoff {
                break;
            }
            first = m;
        }

        if !first.checkpoint {
            let (_, names) = self.chain_names(first.cycle)?;
            first.checkpoint = true;
            first.parent = None;
            first.removed.clear();
            first.devices = names;
            devices.extend(first.devices.values().copied());
            write_replace(
                &self.snapshot_path(first.cycle),
                &serde_json::to_vec_pretty(&first)?,
            )?;
            out.checkpoint = Some(first.cycle);
        }

        for c in cycles {
            if c < head && !keep.contains(&c) && delete(&self.snapshot_path(c))? {
                out.snapshots += 1;
            }
        }
        let mut blobs: BTreeSet<Hash> = BTreeSet::new();
        let mut tables: BTreeSet<(String, u64)> = BTreeSet::new();
        for h in &devices {
            let d = self.device_manifest(h)?;
            blobs.extend(d.sections.iter().filter_map(|s| s.blob));
            tables.extend(d.tables.iter().map(|(t, r)| (t.clone(), r.cycle)));
        }

        for (folder, marked) in [("devices", &devices), ("blobs", &blobs)] {
            let dir = self.dir().join(folder);
            for n in names(&dir)? {
                let Ok(h) = n.parse::<Hash>() else { continue };
                if !marked.contains(&h) && delete(&dir.join(&n))? {
                    out.files += 1;
                }
            }
        }
        for t in TABLES {
            let dir = self.dir().join("tables").join(t.name);
            for n in names(&dir)? {
                let Some(c) = cycle_of(&n, ".parquet") else {
                    continue;
                };
                if c <= head && !tables.contains(&(t.name.to_string(), c)) && delete(&dir.join(&n))?
                {
                    out.files += 1;
                }
            }
        }
        Ok(out)
    }
}
