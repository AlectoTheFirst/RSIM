use std::time::Duration;

use futures_util::future::join_all;
use rsim_store::{Class, Format, Row, TableSchema};

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
    /// The extract of an observation section with a table.
    pub extract: Option<&'static dyn Extract>,
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
            .field("table", &self.extract.map(|e| e.table().name))
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

    /// Reads each section. A section that fails or does not finish in its
    /// time fails alone.
    fn fetch<'a>(&'a self, device: &'a Device, timeout: Duration)
    -> BoxFuture<'a, Vec<RawSection>>;
}

/// Reads the sections at the same time through `read`, each with its
/// timeout. The result has the order of `specs`.
pub async fn fetch_sections<'a, F>(
    specs: Vec<SectionSpec>,
    timeout: Duration,
    read: F,
) -> Vec<RawSection>
where
    F: Fn(String) -> BoxFuture<'a, Result<Vec<u8>, TransportError>>,
{
    let reads = specs.iter().map(|s| {
        let f = read(s.command.clone());
        async move {
            tokio::time::timeout(timeout, f)
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
