//! The seed of a new store from the recorded replies of a demo estate,
//! through the fake transport and the sources of the vendors, with no
//! network.
//!
//! A demo folder holds `devices.txt`, with one line `<id> <vendor>
//! <address>` for each device, and one folder `cycle-<n>` for each cycle,
//! from 1. The folder of a device in a cycle holds `commands.txt`, with one
//! line `<file><TAB><command>` for each command that the source sends, and
//! the reply files. A cycle folder holds only the files that differ from the
//! cycle before it: the replies of a cycle are the files of the cycles up to
//! it, and a file of a later cycle replaces the file of the same name.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rsim_store::{SectionStatus, Store};

use crate::fake::FakeTransport;
use crate::iosxe::IosxeSource;
use crate::iosxr::IosxrSource;
use crate::nxos::NxosSource;
use crate::{CaptureBgp, Clock, Collector, CycleReport, Device, Limits, Schedule, Vendor};

/// The time of the first cycle: 2026-11-02 08:00:00 UTC, in milliseconds
/// since the Unix epoch.
pub const START_MS: u64 = 1_793_606_400_000;

/// The time between 2 cycles: one hour.
pub const CYCLE_MS: u64 = 3_600_000;

/// The file of the devices of a demo folder.
pub const DEVICES: &str = "devices.txt";

/// The file of the commands of a device in a cycle.
pub const COMMANDS: &str = "commands.txt";

/// The folder of cycle `n`, from 1.
pub fn cycle_dir(n: usize) -> String {
    format!("cycle-{n}")
}

/// A clock that shows the time that the seed sets.
#[derive(Debug, Default)]
struct SetClock(AtomicU64);

impl Clock for SetClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// The devices of a demo folder.
pub fn devices(folder: &Path) -> Result<Vec<Device>, String> {
    let path = folder.join(DEVICES);
    let text = String::from_utf8(read(&path)?)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            let [id, vendor, address] = w.as_slice() else {
                return Err(format!("{}: the line {l:?} is not <id> <vendor> <address>", path.display()));
            };
            let vendor = Vendor::ALL
                .into_iter()
                .find(|v| v.name() == *vendor)
                .ok_or_else(|| format!("{}: {vendor} is not a vendor", path.display()))?;
            Ok(Device {
                id: (*id).to_string(),
                vendor,
                address: (*address).to_string(),
                credential: "demo".into(),
                site: None,
                capture_bgp: CaptureBgp::Sessions,
                route: Default::default(),
            })
        })
        .collect()
}

/// The cycle folders of a demo folder, from cycle 1 with no gap.
fn cycles(folder: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    while folder.join(cycle_dir(out.len() + 1)).is_dir() {
        out.push(folder.join(cycle_dir(out.len() + 1)));
    }
    if out.is_empty() {
        return Err(format!("{}: no folder {}", folder.display(), cycle_dir(1)));
    }
    Ok(out)
}

/// Adds the files of the device folders of a cycle to `files`, by device
/// and file name.
fn overlay(cycle: &Path, files: &mut BTreeMap<(String, String), Vec<u8>>) -> Result<(), String> {
    let entries = std::fs::read_dir(cycle).map_err(|e| format!("{}: {e}", cycle.display()))?;
    for d in entries {
        let d = d.map_err(|e| format!("{}: {e}", cycle.display()))?;
        if !d.path().is_dir() {
            continue;
        }
        let device = d.file_name().to_string_lossy().into_owned();
        let inner = std::fs::read_dir(d.path()).map_err(|e| format!("{}: {e}", d.path().display()))?;
        for f in inner {
            let f = f.map_err(|e| format!("{}: {e}", d.path().display()))?;
            let name = f.file_name().to_string_lossy().into_owned();
            files.insert((device.clone(), name), read(&f.path())?);
        }
    }
    Ok(())
}

/// Sets the replies of a device from its files.
fn load(
    fake: &FakeTransport,
    device: &str,
    files: &BTreeMap<(String, String), Vec<u8>>,
) -> Result<(), String> {
    let commands = files
        .get(&(device.to_string(), COMMANDS.to_string()))
        .ok_or_else(|| format!("{device}: no {COMMANDS}"))?;
    let text = String::from_utf8_lossy(commands);
    fake.clear(device);
    for line in text.lines().filter(|l| !l.is_empty()) {
        let (file, command) = line
            .split_once('\t')
            .ok_or_else(|| format!("{device}/{COMMANDS}: the line {line:?} has no tab"))?;
        let bytes = files
            .get(&(device.to_string(), file.to_string()))
            .ok_or_else(|| format!("{device}: no file {file}"))?;
        fake.reply(device, command, Ok(bytes.clone()));
    }
    Ok(())
}

/// Writes the cycles of a demo folder into a store that has no snapshot.
/// Each cycle runs at its own time from [`START_MS`]. A failed device, a
/// failed extract or a section that is not fresh or absent is an error.
pub async fn seed(store: Store, folder: &Path) -> Result<Vec<CycleReport>, String> {
    if store.latest().map_err(|e| e.to_string())?.is_some() {
        return Err(format!(
            "{}: the store has a snapshot; the seed writes only a new store",
            store.dir().display()
        ));
    }
    let devices = devices(folder)?;
    let cycles = cycles(folder)?;
    let fake = Arc::new(FakeTransport::new(Duration::ZERO));
    let clock = Arc::new(SetClock::default());
    let mut collector = Collector::new(
        store,
        Box::new(devices.clone()),
        Schedule {
            spread: false,
            ..Schedule::default()
        },
        Limits::default(),
        clock.clone(),
    )
    .map_err(|e| e.to_string())?
    .with_source(Arc::new(NxosSource::new(fake.clone())))
    .with_source(Arc::new(IosxeSource::new(fake.clone())))
    .with_source(Arc::new(IosxrSource::new(fake.clone())));
    let mut files = BTreeMap::new();
    let mut reports = Vec::new();
    for (i, cycle) in cycles.iter().enumerate() {
        overlay(cycle, &mut files)?;
        for d in &devices {
            load(&fake, &d.id, &files)?;
        }
        let step = u64::try_from(i).unwrap_or(u64::MAX);
        clock
            .0
            .store(START_MS + step * CYCLE_MS, Ordering::SeqCst);
        let r = collector.run_cycle().await.map_err(|e| e.to_string())?;
        let name = cycle_dir(i + 1);
        if !r.failed.is_empty() {
            return Err(format!("{name}: the devices {:?} failed", r.failed));
        }
        if let Some((d, s, e)) = r.extract_errors.first() {
            return Err(format!("{name}: {d}/{s}: the extract failed: {e}"));
        }
        let snap = collector
            .store()
            .latest()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("{name}: no snapshot"))?;
        for (d, m) in &snap.devices {
            for s in &m.sections {
                match &s.status {
                    SectionStatus::Fresh | SectionStatus::Absent { .. } => {}
                    SectionStatus::Old { error } | SectionStatus::Missing { error } => {
                        return Err(format!("{name}: {d}/{}: {error}", s.name));
                    }
                }
            }
        }
        reports.push(r);
    }
    Ok(reports)
}
