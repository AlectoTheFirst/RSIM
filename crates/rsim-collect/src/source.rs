use std::time::Duration;

use futures_util::future::join_all;
use rsim_store::{Class, Format, Row, TableSchema};
use tokio::time::Instant;

use crate::{BoxFuture, Device, TransportError, Vendor};

/// Changes the bytes of an observation section into the rows of a table.
pub trait Extract: Send + Sync {
    fn table(&self) -> &'static TableSchema;
    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String>;
}

/// A section that a source reads.
#[derive(Clone)]
pub struct SectionSpec {
    /// The name of the section, unique in the device.
    pub name: &'static str,
    /// The command or the API path.
    pub command: String,
    pub class: Class,
    pub format: Format,
    /// The volatile parts. Refer to [`rsim_store::strip_volatile`].
    pub volatile: &'static [&'static str],
    /// The extracts of an observation section, each with its table.
    pub extracts: &'static [&'static dyn Extract],
    /// The members of a JSON section that the change detection covers. With
    /// no pattern, it covers the whole section without the volatile parts.
    /// Refer to [`rsim_store::keep_only`].
    pub keep: &'static [&'static str],
    /// A device can lack the section. A [`TransportError::NotFound`] reply
    /// then gives the status `Absent`, which is not a failure.
    pub optional: bool,
}

impl std::fmt::Debug for SectionSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SectionSpec")
            .field("name", &self.name)
            .field("command", &self.command)
            .field("class", &self.class)
            .field("format", &self.format)
            .field(
                "tables",
                &self
                    .extracts
                    .iter()
                    .map(|e| e.table().name)
                    .collect::<Vec<_>>(),
            )
            .field("optional", &self.optional)
            .finish()
    }
}

/// The result of the read of one section.
#[derive(Clone, Debug)]
pub struct RawSection {
    pub spec: SectionSpec,
    pub result: Result<Vec<u8>, TransportError>,
}

/// The raw sections of one device collection.
#[derive(Clone, Debug)]
pub struct Capture {
    pub device: Device,
    /// The time of the collection, in milliseconds since the Unix epoch.
    pub collected_at: u64,
    pub sections: Vec<RawSection>,
}

impl RawSection {
    /// True if the section is optional and the device does not have it.
    pub fn absent(&self) -> bool {
        self.spec.optional && matches!(self.result, Err(TransportError::NotFound(_)))
    }
}

impl Capture {
    /// True if each section failed. An absent section is not a failure.
    pub fn failed(&self) -> bool {
        self.sections
            .iter()
            .all(|s| s.result.is_err() && !s.absent())
    }
}

/// Reads the sections of a device of one vendor.
pub trait Source: Send + Sync {
    fn vendor(&self) -> Vendor;

    /// The sections of the device, in a fixed order.
    fn sections(&self, device: &Device) -> Vec<SectionSpec>;

    /// Reads each section within the timeouts. A section that fails or does
    /// not finish in its time fails alone, and the sections that are read
    /// keep their results.
    fn fetch<'a>(
        &'a self,
        device: &'a Device,
        timeouts: Timeouts,
    ) -> BoxFuture<'a, Vec<RawSection>>;

    /// Starts a cycle with due devices, before the first fetch of the
    /// cycle.
    fn begin_cycle(&self) {}
}

/// The times of the reads of one device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// The time for one section.
    pub section: Duration,
    /// The end of the time for all sections of the device. A read that does
    /// not finish by then times out, and a section that is not sent by then
    /// is not sent.
    pub deadline: Option<Instant>,
}

impl Timeouts {
    /// The end of the time of a read that starts at `now`.
    fn end(&self, now: Instant) -> Instant {
        let end = now + self.section;
        self.deadline.map_or(end, |d| d.min(end))
    }
}

impl From<Duration> for Timeouts {
    /// The time for one section, with no deadline for the device.
    fn from(section: Duration) -> Timeouts {
        Timeouts {
            section,
            deadline: None,
        }
    }
}

/// Reads the sections through `read`, each with its timeout. The result has
/// the order of `specs`. The reads run at the same time, or one after the
/// other if `serial` is true, so that the time of a read starts when its
/// command is sent. One after the other, a connect error, 2 timeouts in
/// sequence or the deadline of the device stop the fetch, and the sections
/// after them are not sent.
pub async fn fetch_sections<'a, F>(
    specs: Vec<SectionSpec>,
    timeouts: impl Into<Timeouts>,
    serial: bool,
    read: F,
) -> Vec<RawSection>
where
    F: Fn(String) -> BoxFuture<'a, Result<Vec<u8>, TransportError>>,
{
    let times: Timeouts = timeouts.into();
    if serial {
        let mut out = Vec::with_capacity(specs.len());
        let mut timeouts = 0;
        let mut stop: Option<String> = None;
        for spec in specs {
            let now = Instant::now();
            if stop.is_none() && times.deadline.is_some_and(|d| now >= d) {
                stop = Some("the time of the device ended".into());
            }
            if let Some(why) = &stop {
                out.push(RawSection {
                    spec,
                    result: Err(TransportError::Connect(format!("not sent: {why}"))),
                });
                continue;
            }
            let result = tokio::time::timeout_at(times.end(now), read(spec.command.clone()))
                .await
                .unwrap_or(Err(TransportError::Timeout));
            match &result {
                Err(TransportError::Connect(e)) => stop = Some(format!("the connect failed: {e}")),
                Err(TransportError::Timeout) => {
                    timeouts += 1;
                    if timeouts == 2 {
                        stop = Some("the 2 commands before it timed out".into());
                    }
                }
                _ => timeouts = 0,
            }
            out.push(RawSection { spec, result });
        }
        return out;
    }
    let end = times.end(Instant::now());
    let reads = specs.iter().map(|s| {
        let f = read(s.command.clone());
        async move {
            tokio::time::timeout_at(end, f)
                .await
                .unwrap_or(Err(TransportError::Timeout))
        }
    });
    let results = join_all(reads).await;
    specs
        .into_iter()
        .zip(results)
        .map(|(spec, result)| RawSection { spec, result })
        .collect()
}
