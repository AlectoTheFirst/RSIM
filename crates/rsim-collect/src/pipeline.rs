use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rsim_store::{
    Class, DeviceManifest, DeviceUpdate, Entropy, Hash, Row, Snapshot, Store, StoreError,
};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

use crate::{
    Capture, Classified, Device, Due, Inventory, RawSection, Schedule, Scheduler, Source,
    TransportError, Vendor, classify,
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
    fn fill(&mut self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("the operating system gives random bytes");
    }
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
    /// The time for all sections of one device.
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

/// An error that stops a cycle.
#[derive(Debug)]
pub enum CollectError {
    Store(StoreError),
    /// A stage task stopped with a fault.
    Stage(String),
}

impl fmt::Display for CollectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CollectError::Store(e) => write!(f, "store: {e}"),
            CollectError::Stage(e) => write!(f, "stage: {e}"),
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
}

/// Collects the devices of an inventory into a store.
pub struct Collector {
    store: Arc<Store>,
    inventory: Box<dyn Inventory>,
    sources: BTreeMap<Vendor, Arc<dyn Source>>,
    scheduler: Scheduler,
    limits: Limits,
    clock: Arc<dyn Clock>,
    sinks: Vec<Arc<dyn Sink>>,
    state: Arc<BTreeMap<String, DeviceManifest>>,
}

impl fmt::Debug for Collector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Collector")
            .field("store", &self.store.dir())
            .field("vendors", &self.sources.keys().collect::<Vec<_>>())
            .field("limits", &self.limits)
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
        let state = store.latest()?.map(|s| s.devices).unwrap_or_default();
        Ok(Collector {
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

    /// Adds a sink.
    pub fn with_sink(mut self, sink: Arc<dyn Sink>) -> Collector {
        self.sinks.push(sink);
        self
    }

    pub fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Runs the cycles at the interval of the schedule until `stop` is
    /// ready. A store error stops the collector.
    pub async fn run(&mut self, stop: impl Future<Output = ()>) -> Result<(), CollectError> {
        tokio::pin!(stop);
        let mut tick = tokio::time::interval(self.scheduler.schedule().interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = &mut stop => return Ok(()),
                _ = tick.tick() => {
                    self.run_cycle().await?;
                }
            }
        }
    }

    /// Collects the due devices and writes one snapshot.
    pub async fn run_cycle(&mut self) -> Result<CycleReport, CollectError> {
        let now = self.clock.now_ms();
        let devices = self.inventory.devices();
        let due = self.scheduler.due(now, &devices);
        let mut report = CycleReport {
            time: now,
            due: due.len(),
            ..CycleReport::default()
        };
        if due.is_empty() {
            return Ok(report);
        }

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
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("rsim-store-writer".into())
            .spawn(move || {
                let _ = done_tx.send(store_stage(cls_rx, &store, now));
            })
            .map_err(|e| CollectError::Stage(e.to_string()))?;

        let stage = |e: tokio::task::JoinError| CollectError::Stage(e.to_string());
        let (snapshot, mut results) = done_rx
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
        if let Some(s) = snapshot {
            report.snapshot = Some(s.manifest.cycle);
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

/// Fetches the due devices within the limits. A fetch keeps its permits
/// until the next stage takes its capture, so a full channel stops new
/// fetches.
pub(crate) async fn fetch_stage(
    mut jobs: mpsc::Receiver<Due>,
    out: mpsc::Sender<(Capture, bool)>,
    sources: BTreeMap<Vendor, Arc<dyn Source>>,
    limits: Limits,
    clock: Arc<dyn Clock>,
) {
    let global = Arc::new(Semaphore::new(limits.devices));
    let per: BTreeMap<Vendor, Arc<Semaphore>> = [Vendor::Vyos, Vendor::Unifi]
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
        tasks.spawn(async move {
            let collected_at = clock.now_ms();
            let sections = match source {
                Some(s) => {
                    let f = s.fetch(&job.device, limits.section_timeout);
                    match tokio::time::timeout(limits.device_timeout, f).await {
                        Ok(sections) => sections,
                        Err(_) => s
                            .sections(&job.device)
                            .into_iter()
                            .map(|spec| RawSection {
                                spec,
                                result: Err(TransportError::Timeout),
                            })
                            .collect(),
                    }
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

fn store_stage(
    mut rx: mpsc::Receiver<(Result<Classified, StoreError>, bool)>,
    store: &Store,
    time: u64,
) -> Result<(Option<Snapshot>, Vec<DeviceResult>), StoreError> {
    let mut cycle = store.begin(time)?;
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
        cycle.add(DeviceUpdate {
            device: c.device.id.clone(),
            vendor: c.device.vendor.name().to_string(),
            collected_at: c.collected_at,
            sections: c.sections,
            tables,
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
    Ok((snapshot, results))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SectionSpec;
    use crate::fake::FakeTransport;
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
                extract: None,
                optional: false,
            }]
        }
        fn fetch<'a>(
            &'a self,
            device: &'a Device,
            timeout: Duration,
        ) -> crate::BoxFuture<'a, Vec<RawSection>> {
            let t = self.0.clone();
            Box::pin(crate::fetch_sections(
                self.sections(device),
                timeout,
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
                        route: Default::default(),
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
}
