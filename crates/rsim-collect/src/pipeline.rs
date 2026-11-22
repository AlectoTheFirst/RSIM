use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rsim_store::{
    Class, DeviceManifest, DeviceUpdate, Entropy, Hash, Pruned, Row, Snapshot, Store, StoreError,
};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

use crate::{
    Capture, Classified, Device, Due, Inventory, Schedule, Scheduler, Source, Timeouts, Vendor,
    classify,
};

/// The time in milliseconds since the Unix epoch.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// A clock that follows the `tokio` time from a start time. With paused
/// `tokio` time, it moves only when the runtime moves the time.
#[derive(Clone, Copy, Debug)]
pub struct TokioClock {
    epoch_ms: u64,
    start: tokio::time::Instant,
}

impl TokioClock {
    /// A clock that shows `epoch_ms` now.
    pub fn new(epoch_ms: u64) -> TokioClock {
        TokioClock {
            epoch_ms,
            start: tokio::time::Instant::now(),
        }
    }

    /// A clock that starts at the system time.
    pub fn system() -> TokioClock {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        TokioClock::new(now)
    }
}

impl Clock for TokioClock {
    fn now_ms(&self) -> u64 {
        let e = self.start.elapsed().as_millis();
        self.epoch_ms
            .saturating_add(u64::try_from(e).unwrap_or(u64::MAX))
    }
}

/// Random bytes from the operating system.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn key(&mut self) -> [u8; 32] {
        os_random()
    }
    fn nonce(&mut self) -> [u8; 24] {
        os_random()
    }
}

/// `N` random bytes from the operating system.
fn os_random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("the operating system gives random bytes");
    bytes
}

/// Receives the devices that changed in a published snapshot.
pub trait Sink: Send + Sync {
    fn changed(&self, snapshot: u64, devices: &[(String, Vec<Class>)]);
}

/// The limits of a collection cycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The devices with a fetch in flight.
    pub devices: usize,
    /// The devices of one vendor with a fetch in flight.
    pub per_vendor: usize,
    /// The capacity of each channel between 2 stages.
    pub channel: usize,
    /// The time for one section.
    pub section_timeout: Duration,
    /// The time for all sections of one device. The sections that are read
    /// in this time keep their results.
    pub device_timeout: Duration,
    /// The captures that the classify and hash stage processes at the same
    /// time.
    pub workers: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            devices: 512,
            per_vendor: 512,
            channel: 256,
            section_timeout: Duration::from_secs(20),
            device_timeout: Duration::from_secs(45),
            workers: 32,
        }
    }
}

/// The time limits of the reads of one device, in place of the times of
/// the `Limits` of the cycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeLimits {
    /// The time for one section.
    pub section: Duration,
    /// The time for all sections of the device.
    pub device: Duration,
}

/// An error that stops a cycle.
#[derive(Debug)]
pub enum CollectError {
    Store(StoreError),
    /// A stage task stopped with a fault.
    Stage(String),
    /// The inventory has two devices with one id.
    Inventory(String),
}

impl fmt::Display for CollectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CollectError::Store(e) => write!(f, "store: {e}"),
            CollectError::Stage(e) => write!(f, "stage: {e}"),
            CollectError::Inventory(e) => write!(f, "inventory: {e}"),
        }
    }
}

impl std::error::Error for CollectError {}

impl From<StoreError> for CollectError {
    fn from(e: StoreError) -> Self {
        CollectError::Store(e)
    }
}

/// The result of one cycle.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CycleReport {
    /// The time of the cycle, in milliseconds since the Unix epoch.
    pub time: u64,
    /// The number of devices that were due.
    pub due: usize,
    /// The published snapshot. `None` if no device changed.
    pub snapshot: Option<u64>,
    /// The devices with no successful section.
    pub failed: Vec<String>,
    /// The devices with new content, with the classes of the changed
    /// sections.
    pub changed: Vec<(String, Vec<Class>)>,
    /// The device, the section and the error of each extract that failed.
    pub extract_errors: Vec<(String, String, String)>,
    /// The devices of the store that are not in the inventory. The
    /// published snapshot removes them.
    pub removed: Vec<String>,
    /// The prune after the published snapshot, if one runs.
    pub pruned: Option<Pruned>,
    /// The error of the prune. The collector goes on.
    pub prune_error: Option<String>,
}

/// The history of the store with no setting.
pub const DEFAULT_HISTORY: Duration = Duration::from_secs(30 * 86_400);

/// The least time between 2 prunes of the store.
pub const PRUNE_INTERVAL: Duration = Duration::from_secs(3_600);

/// The longest wait between 2 cycles, and so between 2 reads of the
/// inventory.
pub const WAKE_LIMIT: Duration = Duration::from_secs(60);

/// Collects the devices of an inventory into a store.
pub struct Collector {
    store: Arc<Store>,
    inventory: Box<dyn Inventory>,
    sources: BTreeMap<Vendor, Arc<dyn Source>>,
    scheduler: Scheduler,
    limits: Limits,
    times: Arc<BTreeMap<String, TimeLimits>>,
    clock: Arc<dyn Clock>,
    sinks: Vec<Arc<dyn Sink>>,
    state: Arc<BTreeMap<String, DeviceManifest>>,
    /// The time of the newest snapshot of the store.
    newest: Option<u64>,
    history: Duration,
    /// The time of the last prune.
    pruned_at: Option<u64>,
}

impl fmt::Debug for Collector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Collector")
            .field("store", &self.store.dir())
            .field("vendors", &self.sources.keys().collect::<Vec<_>>())
            .field("limits", &self.limits)
            .field("times", &self.times)
            .finish()
    }
}

impl Collector {
    /// A collector that continues from the newest snapshot of the store.
    pub fn new(
        store: Store,
        inventory: Box<dyn Inventory>,
        schedule: Schedule,
        limits: Limits,
        clock: Arc<dyn Clock>,
    ) -> Result<Collector, CollectError> {
        let latest = store.latest()?;
        let newest = latest.as_ref().map(|s| s.manifest.time);
        let state = latest.map(|s| s.devices).unwrap_or_default();
        Ok(Collector {
            newest,
            history: DEFAULT_HISTORY,
            pruned_at: None,
            store: Arc::new(store),
            inventory,
            sources: BTreeMap::new(),
            scheduler: Scheduler::new(schedule),
            limits: Limits {
                devices: limits.devices.max(1),
                per_vendor: limits.per_vendor.max(1),
                channel: limits.channel.max(1),
                workers: limits.workers.max(1),
                ..limits
            },
            times: Arc::new(BTreeMap::new()),
            clock,
            sinks: Vec::new(),
            state: Arc::new(state),
        })
    }

    /// Adds the source of a vendor.
    pub fn with_source(mut self, source: Arc<dyn Source>) -> Collector {
        self.sources.insert(source.vendor(), source);
        self
    }

    /// Sets the time limits of the device with the id `device`.
    pub fn with_time_limits(mut self, device: &str, limits: TimeLimits) -> Collector {
        Arc::make_mut(&mut self.times).insert(device.to_string(), limits);
        self
    }

    /// Replaces the inventory, the sources and the time limits of the
    /// devices before a cycle. The schedule state of each device stays.
    pub fn reconfigure(
        &mut self,
        inventory: Box<dyn Inventory>,
        sources: Vec<Arc<dyn Source>>,
        times: BTreeMap<String, TimeLimits>,
    ) {
        self.inventory = inventory;
        self.sources = sources.into_iter().map(|s| (s.vendor(), s)).collect();
        self.times = Arc::new(times);
    }

    /// Sets the history of the store: a prune deletes the snapshots that
    /// are older, except the newest snapshot.
    pub fn set_history(&mut self, history: Duration) {
        self.history = history;
    }

    /// Adds a sink.
    pub fn with_sink(mut self, sink: Arc<dyn Sink>) -> Collector {
        self.sinks.push(sink);
        self
    }

    /// The time of the clock of the collector.
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    pub fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The time of the next cycle: the earliest due time of the devices of
    /// the inventory, `now` for a device of the store that the inventory
    /// does not have, and at most [`WAKE_LIMIT`] after `now`.
    pub fn next_wake(&self, now: u64) -> u64 {
        let devices = self.inventory.devices();
        let limit = now.saturating_add(u64::try_from(WAKE_LIMIT.as_millis()).unwrap_or(u64::MAX));
        if self
            .state
            .keys()
            .any(|d| !devices.iter().any(|x| x.id == *d))
        {
            return now;
        }
        self.scheduler
            .next_due(&devices)
            .map_or(limit, |t| t.min(limit))
    }

    /// Runs a cycle at each wake time of [`Collector::next_wake`] until
    /// `stop` is ready, and gives each report to `report`. A store error
    /// stops the collector.
    pub async fn run(
        &mut self,
        stop: impl Future<Output = ()>,
        mut report: impl FnMut(&CycleReport),
    ) -> Result<(), CollectError> {
        tokio::pin!(stop);
        loop {
            let now = self.clock.now_ms();
            let wait = Duration::from_millis(self.next_wake(now).saturating_sub(now));
            tokio::select! {
                _ = &mut stop => return Ok(()),
                _ = tokio::time::sleep(wait) => {
                    report(&self.run_cycle().await?);
                }
            }
        }
    }

    /// Collects the due devices and writes one snapshot. The snapshot
    /// removes each device of the store that is not in the inventory. A
    /// cycle with a due device or a removal in the second of the newest
    /// snapshot, or before it, first waits for the next second, so each
    /// snapshot has its own second.
    /// After a written snapshot, and at most once in [`PRUNE_INTERVAL`],
    /// the store deletes the snapshots that are older than the history.
    pub async fn run_cycle(&mut self) -> Result<CycleReport, CollectError> {
        let mut now = self.clock.now_ms();
        let devices = self.inventory.devices();
        let inventory_version = self.inventory.version();
        let mut ids = BTreeSet::new();
        if let Some(d) = devices.iter().find(|d| !ids.insert(d.id.clone())) {
            return Err(CollectError::Inventory(format!(
                "two devices have the id {}",
                d.id
            )));
        }
        let due = self.scheduler.due(now, &devices);
        if due.is_empty() && self.state.keys().all(|d| ids.contains(d)) {
            return Ok(CycleReport {
                time: now,
                ..CycleReport::default()
            });
        }
        if let Some(newest) = self.newest.filter(|t| t / 1000 >= now / 1000) {
            let next = (newest / 1000 + 1) * 1000;
            tokio::time::sleep(Duration::from_millis(next - now)).await;
            now = self.clock.now_ms().max(next);
        }
        let mut report = CycleReport {
            time: now,
            due: due.len(),
            ..CycleReport::default()
        };

        let cap = self.limits.channel;
        let (job_tx, job_rx) = mpsc::channel::<Due>(cap);
        let (cap_tx, cap_rx) = mpsc::channel::<(Capture, bool)>(cap);
        let (cls_tx, cls_rx) = mpsc::channel::<(Result<Classified, StoreError>, bool)>(cap);

        let feeder = tokio::spawn(async move {
            for d in due {
                if job_tx.send(d).await.is_err() {
                    break;
                }
            }
        });
        let fetch = tokio::spawn(fetch_stage(
            job_rx,
            cap_tx,
            self.sources.clone(),
            self.limits,
            self.times.clone(),
            self.clock.clone(),
        ));
        let process = tokio::spawn(process_stage(
            cap_rx,
            cls_tx,
            self.store.clone(),
            self.state.clone(),
            self.limits.workers,
        ));
        // The store stage runs on its own thread for the whole cycle.
        let store = self.store.clone();
        let prune_interval = u64::try_from(PRUNE_INTERVAL.as_millis()).unwrap_or(u64::MAX);
        let cutoff = self
            .pruned_at
            .is_none_or(|t| now.saturating_sub(t) >= prune_interval)
            .then(|| {
                now.saturating_sub(u64::try_from(self.history.as_millis()).unwrap_or(u64::MAX))
            });
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("rsim-store-writer".into())
            .spawn(move || {
                let _ = done_tx.send(store_stage(
                    cls_rx,
                    &store,
                    now,
                    &ids,
                    inventory_version,
                    cutoff,
                ));
            })
            .map_err(|e| CollectError::Stage(e.to_string()))?;

        let stage = |e: tokio::task::JoinError| CollectError::Stage(e.to_string());
        let Stored {
            snapshot,
            mut results,
            removed,
            pruned,
        } = done_rx
            .await
            .map_err(|_| CollectError::Stage("the store stage stopped".into()))??;
        results.sort_by(|a, b| a.device.id.cmp(&b.device.id));
        feeder.await.map_err(stage)?;
        fetch.await.map_err(stage)?;
        process.await.map_err(stage)?;

        for r in &results {
            self.scheduler.record(&r.device.id, now, r.forced, r.failed);
            if r.failed {
                report.failed.push(r.device.id.clone());
            }
            for (section, e) in &r.extract_errors {
                report
                    .extract_errors
                    .push((r.device.id.clone(), section.clone(), e.clone()));
            }
        }
        if let Some(p) = pruned {
            self.pruned_at = Some(now);
            match p {
                Ok(p) => report.pruned = Some(p),
                Err(e) => report.prune_error = Some(e.to_string()),
            }
        }
        if let Some(s) = snapshot {
            self.newest = Some(s.manifest.time);
            report.snapshot = Some(s.manifest.cycle);
            for d in &removed {
                self.scheduler.forget(d);
            }
            report.removed = removed;
            report.changed = results
                .iter()
                .filter(|r| !r.changed.is_empty())
                .map(|r| (r.device.id.clone(), r.changed.clone()))
                .collect();
            self.state = Arc::new(s.devices);
            if !report.changed.is_empty() {
                for sink in &self.sinks {
                    sink.changed(s.manifest.cycle, &report.changed);
                }
            }
        }
        report.failed.sort();
        report.changed.sort();
        report.extract_errors.sort();
        Ok(report)
    }
}

/// Fetches the due devices within the limits. A device in `times` gets its
/// own time limits. A fetch keeps its permits until the next stage takes
/// its capture, so a full channel stops new fetches.
pub(crate) async fn fetch_stage(
    mut jobs: mpsc::Receiver<Due>,
    out: mpsc::Sender<(Capture, bool)>,
    sources: BTreeMap<Vendor, Arc<dyn Source>>,
    limits: Limits,
    times: Arc<BTreeMap<String, TimeLimits>>,
    clock: Arc<dyn Clock>,
) {
    let global = Arc::new(Semaphore::new(limits.devices));
    let per: BTreeMap<Vendor, Arc<Semaphore>> = Vendor::ALL
        .into_iter()
        .map(|v| (v, Arc::new(Semaphore::new(limits.per_vendor))))
        .collect();
    let mut tasks = JoinSet::new();
    while let Some(job) = jobs.recv().await {
        let Ok(g) = global.clone().acquire_owned().await else {
            break;
        };
        let Ok(v) = per[&job.device.vendor].clone().acquire_owned().await else {
            break;
        };
        let source = sources.get(&job.device.vendor).cloned();
        let out = out.clone();
        let clock = clock.clone();
        let time = times.get(&job.device.id).copied().unwrap_or(TimeLimits {
            section: limits.section_timeout,
            device: limits.device_timeout,
        });
        tasks.spawn(async move {
            let collected_at = clock.now_ms();
            let sections = match source {
                Some(s) => {
                    let timeouts = Timeouts {
                        section: time.section,
                        deadline: Some(tokio::time::Instant::now() + time.device),
                    };
                    s.fetch(&job.device, timeouts).await
                }
                None => Vec::new(),
            };
            let capture = Capture {
                device: job.device,
                collected_at,
                sections,
            };
            let _ = out.send((capture, job.forced)).await;
            drop((g, v));
        });
        while tasks.try_join_next().is_some() {}
    }
    while tasks.join_next().await.is_some() {}
}

/// Classifies the captures and stores their new blobs, with up to
/// `workers` captures at the same time. The blobs are written before the
/// snapshot that names them.
async fn process_stage(
    mut captures: mpsc::Receiver<(Capture, bool)>,
    out: mpsc::Sender<(Result<Classified, StoreError>, bool)>,
    store: Arc<Store>,
    state: Arc<BTreeMap<String, DeviceManifest>>,
    workers: usize,
) {
    let permits = Arc::new(Semaphore::new(workers));
    let mut tasks = JoinSet::new();
    while let Some((capture, forced)) = captures.recv().await {
        let Ok(permit) = permits.clone().acquire_owned().await else {
            break;
        };
        let store = store.clone();
        let state = state.clone();
        let out = out.clone();
        tasks.spawn(async move {
            let c = tokio::task::spawn_blocking(move || {
                let prev = state.get(&capture.device.id);
                let old = |h: &Hash| store.read_blob(h).ok();
                let c = classify(store.keys(), &capture, prev, forced, &old);
                let mut entropy = OsEntropy;
                for (_, bytes) in &c.blobs {
                    store.put_blob(bytes, &mut entropy)?;
                }
                Ok(c)
            })
            .await;
            if let Ok(c) = c {
                let _ = out.send((c, forced)).await;
            }
            drop(permit);
        });
        while tasks.try_join_next().is_some() {}
    }
    while tasks.join_next().await.is_some() {}
}

struct DeviceResult {
    device: Device,
    forced: bool,
    failed: bool,
    changed: Vec<Class>,
    extract_errors: Vec<(String, String)>,
}

/// The output of the store stage.
struct Stored {
    /// The published snapshot. `None` if no device changed and no device
    /// is removed.
    snapshot: Option<Snapshot>,
    results: Vec<DeviceResult>,
    removed: Vec<String>,
    /// The prune after the published snapshot, if one runs.
    pruned: Option<Result<Pruned, StoreError>>,
}

/// Writes the classified devices as one snapshot that removes each device
/// of the base snapshot that is not in `inventory` and records the
/// inventory version. With `cutoff`, a published snapshot is followed by a
/// prune of the snapshots before `cutoff`.
fn store_stage(
    mut rx: mpsc::Receiver<(Result<Classified, StoreError>, bool)>,
    store: &Store,
    time: u64,
    inventory: &BTreeSet<String>,
    inventory_version: Option<u64>,
    cutoff: Option<u64>,
) -> Result<Stored, StoreError> {
    let mut cycle = store.begin(time)?;
    cycle.set_inventory_version(inventory_version);
    let removed: Vec<String> = cycle
        .base()
        .map(|s| {
            s.devices
                .keys()
                .filter(|d| !inventory.contains(*d))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    for d in &removed {
        cycle.remove(d);
    }
    let mut results = Vec::new();
    while let Some((c, forced)) = rx.blocking_recv() {
        let c = c?;
        let tables: BTreeMap<String, Vec<(Hash, Vec<Row>)>> = c
            .tables
            .iter()
            .map(|(t, parts)| {
                let parts = parts
                    .iter()
                    .filter_map(|(i, rows)| c.sections[*i].blob.map(|b| (b, rows.clone())))
                    .collect();
                (t.clone(), parts)
            })
            .collect();
        // A device that the collector did not reach keeps the address of
        // its previous manifest.
        let management_address = if c.failed {
            cycle
                .base()
                .and_then(|s| s.devices.get(&c.device.id))
                .and_then(|m| m.management_address.clone())
        } else {
            Some(c.device.address.clone())
        };
        cycle.add(DeviceUpdate {
            device: c.device.id.clone(),
            vendor: c.device.vendor.name().to_string(),
            collected_at: c.collected_at,
            sections: c.sections,
            tables,
            management_address,
        })?;
        results.push(DeviceResult {
            device: c.device,
            forced,
            failed: c.failed,
            changed: c.changed.into_iter().collect(),
            extract_errors: c.extract_errors,
        });
    }
    let snapshot = match cycle.prepare()? {
        Some(p) => Some(p.publish()?),
        None => None,
    };
    let pruned = cutoff
        .filter(|_| snapshot.is_some())
        .map(|c| store.prune(c));
    Ok(Stored {
        snapshot,
        results,
        removed,
        pruned,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeTransport;
    use crate::{RawSection, SectionSpec, TransportError};
    use rsim_store::Format;

    struct OneSection(Arc<FakeTransport>);

    impl Source for OneSection {
        fn vendor(&self) -> Vendor {
            Vendor::Vyos
        }
        fn sections(&self, _: &Device) -> Vec<SectionSpec> {
            vec![SectionSpec {
                name: "config",
                command: "show".into(),
                class: Class::Configuration,
                format: Format::Text,
                volatile: &[],
                extracts: &[],
                keep: &[],
                optional: false,
            }]
        }
        fn fetch<'a>(
            &'a self,
            device: &'a Device,
            timeouts: Timeouts,
        ) -> crate::BoxFuture<'a, Vec<RawSection>> {
            let t = self.0.clone();
            Box::pin(crate::fetch_sections(
                self.sections(device),
                timeouts,
                false,
                move |c| {
                    let t = t.clone();
                    let d = device.clone();
                    Box::pin(async move { crate::Ssh::run(t.as_ref(), &d, &c).await })
                },
            ))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_channel_stops_the_fetch() {
        let t = Arc::new(FakeTransport::new(Duration::from_millis(10)));
        let mut sources: BTreeMap<Vendor, Arc<dyn Source>> = BTreeMap::new();
        sources.insert(Vendor::Vyos, Arc::new(OneSection(t.clone())));
        let limits = Limits {
            devices: 2,
            per_vendor: 2,
            channel: 1,
            ..Limits::default()
        };
        let (job_tx, job_rx) = mpsc::channel(100);
        // The test does not read the output channel.
        let (out_tx, mut out_rx) = mpsc::channel(1);
        for i in 0..20 {
            job_tx
                .send(Due {
                    device: Device {
                        id: format!("r{i:02}"),
                        vendor: Vendor::Vyos,
                        address: "192.0.2.1".into(),
                        credential: "lab".into(),
                        site: None,
                        capture_bgp: Default::default(),
                        route: Default::default(),
                        interval: crate::DEFAULT_INTERVAL,
                    },
                    forced: false,
                })
                .await
                .unwrap();
        }
        drop(job_tx);
        let stage = tokio::spawn(fetch_stage(
            job_rx,
            out_tx,
            sources,
            limits,
            Arc::new(BTreeMap::new()),
            Arc::new(TokioClock::new(0)),
        ));
        tokio::time::sleep(Duration::from_secs(10)).await;
        // One capture in the channel and 2 fetches that wait to send it.
        assert_eq!(t.calls(), 3);
        assert!(t.max_devices() <= 2);
        let mut n = 0;
        while out_rx.recv().await.is_some() {
            n += 1;
        }
        stage.await.unwrap();
        assert_eq!((n, t.calls()), (20, 20));
    }

    /// 5 sections, read one after the other, each in 2 s.
    struct SlowSerial;

    impl Source for SlowSerial {
        fn vendor(&self) -> Vendor {
            Vendor::Vyos
        }
        fn sections(&self, _: &Device) -> Vec<SectionSpec> {
            ["s0", "s1", "s2", "s3", "s4"]
                .into_iter()
                .map(|name| SectionSpec {
                    name,
                    command: format!("show {name}"),
                    class: Class::Observation,
                    format: Format::Text,
                    volatile: &[],
                    extracts: &[],
                    keep: &[],
                    optional: false,
                })
                .collect()
        }
        fn fetch<'a>(
            &'a self,
            device: &'a Device,
            timeouts: Timeouts,
        ) -> crate::BoxFuture<'a, Vec<RawSection>> {
            Box::pin(crate::fetch_sections(
                self.sections(device),
                timeouts,
                true,
                |c| {
                    Box::pin(async move {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        Ok(c.into_bytes())
                    })
                },
            ))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_device_timeout_keeps_the_sections_that_were_read() {
        let mut sources: BTreeMap<Vendor, Arc<dyn Source>> = BTreeMap::new();
        sources.insert(Vendor::Vyos, Arc::new(SlowSerial));
        let limits = Limits {
            section_timeout: Duration::from_secs(20),
            device_timeout: Duration::from_secs(5),
            ..Limits::default()
        };
        let (job_tx, job_rx) = mpsc::channel(1);
        let (out_tx, mut out_rx) = mpsc::channel(1);
        job_tx
            .send(Due {
                device: Device {
                    id: "r1".into(),
                    vendor: Vendor::Vyos,
                    address: "192.0.2.1".into(),
                    credential: "lab".into(),
                    site: None,
                    capture_bgp: Default::default(),
                    route: Default::default(),
                    interval: crate::DEFAULT_INTERVAL,
                },
                forced: false,
            })
            .await
            .unwrap();
        drop(job_tx);
        let start = tokio::time::Instant::now();
        let stage = tokio::spawn(fetch_stage(
            job_rx,
            out_tx,
            sources,
            limits,
            Arc::new(BTreeMap::new()),
            Arc::new(TokioClock::new(0)),
        ));
        let (capture, _) = out_rx.recv().await.unwrap();
        stage.await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_secs(5));
        let results: Vec<_> = capture.sections.iter().map(|s| s.result.clone()).collect();
        let not_sent = Err(TransportError::Connect(
            "not sent: the time of the device ended".into(),
        ));
        assert_eq!(
            results,
            [
                Ok(b"show s0".to_vec()),
                Ok(b"show s1".to_vec()),
                Err(TransportError::Timeout),
                not_sent.clone(),
                not_sent,
            ]
        );
        assert!(!capture.failed());
    }
}
