use std::collections::{BTreeMap, BTreeSet};

use rsim_store::{
    Class, DeviceManifest, Hash, Keys, Row, SectionEntry, SectionStatus, change_hash,
};

use crate::{Capture, Device};

/// The result of the classify and hash stage for one device.
#[derive(Clone, Debug)]
pub struct Classified {
    pub device: Device,
    pub collected_at: u64,
    /// The sections of the new device manifest.
    pub sections: Vec<SectionEntry>,
    /// The raw bytes to store, by section index. The entry of each of these
    /// sections names the blob of the bytes.
    pub blobs: Vec<(usize, Vec<u8>)>,
    /// The new rows of each table: the section index and the rows of that
    /// section. A table that is not in the map keeps its rows.
    pub tables: BTreeMap<String, Vec<(usize, Vec<Row>)>>,
    /// The classes of the sections with a new change hash. A section that
    /// differs only in its volatile parts is stored, but its class is not
    /// changed.
    pub changed: BTreeSet<Class>,
    /// True if each section failed.
    pub failed: bool,
    /// The sections that an extract could not change into rows, with the
    /// error. The table of such a section keeps its rows.
    pub extract_errors: Vec<(String, String)>,
}

/// Compares a capture with the previous manifest of the device.
///
/// - A section with the change hash of the previous manifest keeps its
///   entry, unless the collection is forced.
/// - A volatile section with a previous entry keeps it, unless the
///   collection is forced.
/// - A failed read keeps the previous blob and marks it old.
/// - An optional section that the device does not have is absent. A change
///   to or from absent changes the class of the section.
/// - If a section of a table changed, all sections of that table give their
///   rows again. A section with no bytes in the capture gives the rows of
///   its previous blob, which `old_bytes` reads.
pub fn classify(
    keys: &Keys,
    capture: &Capture,
    prev: Option<&DeviceManifest>,
    forced: bool,
    old_bytes: &dyn Fn(&Hash) -> Option<Vec<u8>>,
) -> Classified {
    let mut out = Classified {
        device: capture.device.clone(),
        collected_at: capture.collected_at,
        sections: Vec::new(),
        blobs: Vec::new(),
        tables: BTreeMap::new(),
        changed: BTreeSet::new(),
        failed: capture.failed(),
        extract_errors: Vec::new(),
    };
    for (i, raw) in capture.sections.iter().enumerate() {
        let spec = &raw.spec;
        let old = prev.and_then(|m| m.section(spec.name));
        if raw.absent() {
            let reason = raw.result.as_ref().err().map(|e| e.to_string());
            let entry = match old {
                Some(o) if matches!(o.status, SectionStatus::Absent { .. }) => o.clone(),
                _ => {
                    out.changed.insert(spec.class);
                    SectionEntry {
                        name: spec.name.to_string(),
                        command: spec.command.clone(),
                        class: spec.class,
                        format: spec.format,
                        change_hash: None,
                        blob: None,
                        status: SectionStatus::Absent {
                            reason: reason.unwrap_or_default(),
                        },
                        collected_at: Some(capture.collected_at),
                    }
                }
            };
            out.sections.push(entry);
            continue;
        }
        let read = raw
            .result
            .as_ref()
            .map_err(|e| e.to_string())
            .and_then(|b| {
                change_hash(keys, spec.format, b, spec.volatile)
                    .map(|h| (b, h))
                    .map_err(|e| format!("the reply is not valid: {e}"))
            });
        let entry = match read {
            Err(error) => match old.filter(|o| o.blob.is_some()) {
                Some(o) => SectionEntry {
                    status: SectionStatus::Old { error },
                    ..o.clone()
                },
                None => SectionEntry {
                    name: spec.name.to_string(),
                    command: spec.command.clone(),
                    class: spec.class,
                    format: spec.format,
                    change_hash: None,
                    blob: None,
                    status: SectionStatus::Missing { error },
                    collected_at: None,
                },
            },
            Ok((bytes, hash)) => {
                let keep = old.filter(|o| {
                    o.blob.is_some()
                        && !forced
                        && (o.change_hash == Some(hash) || spec.class == Class::Volatile)
                });
                match keep {
                    Some(o) if o.status == SectionStatus::Fresh => o.clone(),
                    Some(o) => SectionEntry {
                        status: SectionStatus::Fresh,
                        collected_at: Some(capture.collected_at),
                        ..o.clone()
                    },
                    None => {
                        let blob = keys.hash(bytes);
                        if old.and_then(|o| o.blob) != Some(blob) {
                            out.blobs.push((i, bytes.clone()));
                        }
                        if old.and_then(|o| o.change_hash) != Some(hash) {
                            out.changed.insert(spec.class);
                        }
                        SectionEntry {
                            name: spec.name.to_string(),
                            command: spec.command.clone(),
                            class: spec.class,
                            format: spec.format,
                            change_hash: Some(hash),
                            blob: Some(blob),
                            status: SectionStatus::Fresh,
                            collected_at: Some(capture.collected_at),
                        }
                    }
                }
            }
        };
        out.sections.push(entry);
    }

    // The tables with a changed section give all their rows again.
    let changed_tables: BTreeSet<&str> = out
        .blobs
        .iter()
        .filter_map(|(i, _)| capture.sections[*i].spec.extract)
        .map(|e| e.table().name)
        .collect();
    for (i, raw) in capture.sections.iter().enumerate() {
        let Some(extract) = raw.spec.extract else {
            continue;
        };
        let table = extract.table().name;
        if !changed_tables.contains(table) {
            continue;
        }
        let entry = &out.sections[i];
        let bytes = match &raw.result {
            Ok(b) if entry.status == SectionStatus::Fresh => Some(b.clone()),
            _ => entry.blob.as_ref().and_then(old_bytes),
        };
        let Some(bytes) = bytes else {
            continue;
        };
        match extract.rows(&bytes) {
            Ok(rows) => out
                .tables
                .entry(table.to_string())
                .or_default()
                .push((i, rows)),
            Err(e) => out.extract_errors.push((raw.spec.name.to_string(), e)),
        }
    }
    // A table with an extract error keeps all its previous rows.
    for (name, _) in &out.extract_errors {
        if let Some(t) = capture
            .sections
            .iter()
            .find(|s| s.spec.name == name)
            .and_then(|s| s.spec.extract)
        {
            out.tables.remove(t.table().name);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RawSection, SectionSpec, Vendor};
    use rsim_store::Format;

    fn capture(bytes: &[u8]) -> Capture {
        Capture {
            device: Device {
                id: "r1".into(),
                vendor: Vendor::Vyos,
                address: "192.0.2.1".into(),
                credential: "lab".into(),
                site: None,
                route: Default::default(),
            },
            collected_at: 5,
            sections: vec![RawSection {
                spec: SectionSpec {
                    name: "counters",
                    command: "show counters".into(),
                    class: Class::Volatile,
                    format: Format::Text,
                    volatile: &[],
                    extract: None,
                    optional: false,
                },
                result: Ok(bytes.to_vec()),
            }],
        }
    }

    fn manifest(c: &Classified) -> DeviceManifest {
        DeviceManifest {
            device: "r1".into(),
            vendor: "vyos".into(),
            collected_at: 1,
            sections: c.sections.clone(),
            tables: BTreeMap::new(),
        }
    }

    #[test]
    fn a_volatile_section_is_stored_first_and_then_only_when_forced() {
        let keys = Keys::new([1; 32], [2; 32]);
        let none = |_: &Hash| None;
        // With no previous entry, the section is stored.
        let first = classify(&keys, &capture(b"rx 1\n"), None, false, &none);
        assert_eq!(first.blobs.len(), 1);
        assert_eq!(first.changed, BTreeSet::from([Class::Volatile]));
        let prev = manifest(&first);
        // A new value is not stored, and the entry stays.
        let later = classify(&keys, &capture(b"rx 9\n"), Some(&prev), false, &none);
        assert!(later.blobs.is_empty());
        assert!(later.changed.is_empty());
        assert_eq!(later.sections, prev.sections);
        // A forced collection stores the new value.
        let forced = classify(&keys, &capture(b"rx 9\n"), Some(&prev), true, &none);
        assert_eq!(forced.blobs.len(), 1);
        assert_eq!(forced.changed, BTreeSet::from([Class::Volatile]));
        assert_eq!(forced.sections[0].blob, Some(keys.hash(b"rx 9\n")));
        assert_eq!(forced.sections[0].collected_at, Some(5));
    }
}
