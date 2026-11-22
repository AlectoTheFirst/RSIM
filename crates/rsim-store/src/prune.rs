//! The deletion of the snapshots that are older than the history of the
//! store.

use std::collections::BTreeSet;
use std::fs;
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
    pub fn prune(&self, cutoff: u64) -> Result<Pruned, StoreError> {
        let mut out = Pruned::default();
        let Some(head) = self.head()? else {
            return Ok(out);
        };
        let cycles = self.cycles()?;
        match cycles.first() {
            Some(&c) if c != head && self.snapshot_manifest(c)?.time < cutoff => {}
            _ => return Ok(out),
        }

        let mut kept: Vec<SnapshotManifest> = vec![self.snapshot_manifest(head)?];
        loop {
            let last = kept.last().expect("the newest snapshot is kept");
            let Some(parent) = last.parent else { break };
            if parent >= last.cycle {
                return Err(StoreError::Integrity(format!(
                    "snapshot {} names the parent {parent}, which is not older",
                    last.cycle
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
            kept.push(m);
        }

        let first = kept.last_mut().expect("the newest snapshot is kept");
        if !first.checkpoint {
            let (_, devices) = self.chain_names(first.cycle)?;
            first.checkpoint = true;
            first.parent = None;
            first.removed.clear();
            first.devices = devices;
            write_replace(
                &self.snapshot_path(first.cycle),
                &serde_json::to_vec_pretty(&*first)?,
            )?;
            out.checkpoint = Some(first.cycle);
        }

        let keep: BTreeSet<u64> = kept.iter().map(|m| m.cycle).collect();
        for c in cycles {
            if c < head && !keep.contains(&c) && delete(&self.snapshot_path(c))? {
                out.snapshots += 1;
            }
        }

        let mut devices: BTreeSet<Hash> = BTreeSet::new();
        for m in &kept {
            devices.extend(m.devices.values().copied());
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
