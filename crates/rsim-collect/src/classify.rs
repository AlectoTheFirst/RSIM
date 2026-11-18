use std::collections::{BTreeMap, BTreeSet};

use rsim_store::{
    Class, DeviceManifest, Hash, Keys, Row, SectionEntry, SectionStatus, change_hash_kept,
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
    /// error. Such a section is a failed read.
    pub extract_errors: Vec<(String, String)>,
}

/// Compares a capture with the previous manifest of the device.
///
/// - A section with the change hash of the previous manifest keeps its
///   entry, unless the collection is forced.
/// - A volatile section with a previous entry keeps it, unless the
///   collection is forced.
/// - Each extract of a section with a new entry reads the new bytes. If an
///   extract fails, the read of the section failed.
/// - A failed read keeps the previous blob and marks it old. An absent
///   section stays absent when the transport fails.
/// - An optional section that the device does not have is absent. A change
///   to or from absent changes the class of the section.
/// - If a section of a table has a new blob or loses its blob, all sections
///   of that table give their rows again. A section with no bytes in the
///   capture gives the rows of its previous blob, which `old_bytes` reads,
///   and an absent section gives no rows.
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
    // The rows of the new bytes of each section and table.
    let mut new_rows: BTreeMap<(usize, &str), Vec<Row>> = BTreeMap::new();
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
        let keeps = |o: &SectionEntry, hash: Hash| {
            o.blob.is_some()
                && !forced
                && (o.change_hash == Some(hash) || spec.class == Class::Volatile)
        };
        let read = raw
            .result
            .as_ref()
            .map_err(|e| e.to_string())
            .and_then(|b| {
                change_hash_kept(keys, spec.format, b, spec.volatile, spec.keep)
                    .map(|h| (b, h))
                    .map_err(|e| format!("the reply is not valid: {e}"))
            })
            .and_then(|(b, h)| {
                if old.is_some_and(|o| keeps(o, h)) {
                    return Ok((b, h, None));
                }
                let blob = keys.hash(b);
                if old.and_then(|o| o.blob) == Some(blob) {
                    return Ok((b, h, Some(blob)));
                }
                let mut errors = Vec::new();
                for extract in spec.extracts {
                    let table = extract.table().name;
                    match extract.rows(b) {
                        Ok(rows) => {
                            new_rows.insert((i, table), rows);
                        }
                        Err(e) => errors.push(format!("{table}: {e}")),
                    }
                }
                if errors.is_empty() {
                    return Ok((b, h, Some(blob)));
                }
                let error = format!("the reply is not valid: {}", errors.join("; "));
                out.extract_errors
                    .extend(errors.into_iter().map(|e| (spec.name.to_string(), e)));
                Err(error)
            });
        let entry = match read {
            Err(error) => match old {
                Some(o) if o.blob.is_some() => SectionEntry {
                    status: SectionStatus::Old { error },
                    ..o.clone()
                },
                Some(o)
                    if raw.result.is_err() && matches!(o.status, SectionStatus::Absent { .. }) =>
                {
                    o.clone()
                }
                _ => SectionEntry {
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
            Ok((bytes, hash, blob)) => match blob {
                None => {
                    let o = old.expect("a kept section has a previous entry");
                    if o.status == SectionStatus::Fresh {
                        o.clone()
                    } else {
                        SectionEntry {
                            status: SectionStatus::Fresh,
                            collected_at: Some(capture.collected_at),
                            ..o.clone()
                        }
                    }
                }
                Some(blob) => {
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
            },
        };
        out.sections.push(entry);
    }

    // The tables with a section that has a new blob or lost its blob give
    // all their rows again.
    let lost_blob = capture.sections.iter().enumerate().filter(|(i, raw)| {
        out.sections[*i].blob.is_none()
            && prev
                .and_then(|m| m.section(raw.spec.name))
                .is_some_and(|o| o.blob.is_some())
    });
    let changed_tables: BTreeSet<&str> = out
        .blobs
        .iter()
        .map(|(i, _)| *i)
        .chain(lost_blob.map(|(i, _)| i))
        .flat_map(|i| capture.sections[i].spec.extracts)
        .map(|e| e.table().name)
        .collect();
    for t in &changed_tables {
        out.tables.insert(t.to_string(), Vec::new());
    }
    let mut failed_tables = BTreeSet::new();
    for (i, raw) in capture.sections.iter().enumerate() {
        for extract in raw.spec.extracts {
            let table = extract.table().name;
            if !changed_tables.contains(table) {
                continue;
            }
            let entry = &out.sections[i];
            if entry.status == SectionStatus::Fresh
                && let Some(rows) = new_rows.remove(&(i, table))
            {
                out.tables
                    .get_mut(table)
                    .expect("each changed table has an entry")
                    .push((i, rows));
                continue;
            }
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
                Err(e) => {
                    failed_tables.insert(table);
                    out.extract_errors
                        .push((raw.spec.name.to_string(), format!("{table}: {e}")));
                }
            }
        }
    }
    // A table with an extract error keeps all its previous rows.
    for t in failed_tables {
        out.tables.remove(t);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Extract, RawSection, SectionSpec, Vendor};
    use rsim_store::Format;

    fn capture(bytes: &[u8]) -> Capture {
        Capture {
            device: Device {
                id: "r1".into(),
                vendor: Vendor::Vyos,
                address: "192.0.2.1".into(),
                credential: "lab".into(),
                site: None,
                capture_bgp: Default::default(),
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
                    extracts: &[],
                    keep: &[],
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

    /// One row for each line `<interface> <mbps>`. Any other line is an
    /// error.
    struct Speeds;

    impl Extract for Speeds {
        fn table(&self) -> &'static rsim_store::TableSchema {
            &rsim_store::LINK_SPEEDS
        }
        fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
            String::from_utf8_lossy(bytes)
                .lines()
                .map(|l| match l.split_once(' ') {
                    Some((i, m)) => Ok(vec![
                        rsim_store::Cell::Str(i.into()),
                        rsim_store::Cell::U64(m.parse().map_err(|_| format!("bad line {l}"))?),
                        rsim_store::Cell::Null,
                    ]),
                    None => Err(format!("bad line {l}")),
                })
                .collect()
        }
    }

    const SPEEDS: &[&dyn Extract] = &[&Speeds];

    fn observed(
        name: &'static str,
        optional: bool,
        extracts: &'static [&'static dyn Extract],
        result: Result<&[u8], crate::TransportError>,
    ) -> RawSection {
        RawSection {
            spec: SectionSpec {
                name,
                command: format!("show {name}"),
                class: Class::Observation,
                format: Format::Text,
                volatile: &[],
                extracts,
                keep: &[],
                optional,
            },
            result: result.map(<[u8]>::to_vec),
        }
    }

    fn sections(sections: Vec<RawSection>) -> Capture {
        Capture {
            sections,
            ..capture(b"")
        }
    }

    /// The bytes of each blob that a list of results stored.
    fn blobs(keys: &Keys, results: &[&Classified]) -> BTreeMap<Hash, Vec<u8>> {
        results
            .iter()
            .flat_map(|c| c.blobs.iter())
            .map(|(_, b)| (keys.hash(b), b.clone()))
            .collect()
    }

    fn table_rows(c: &Classified) -> Vec<(String, Vec<String>)> {
        c.tables["link_speeds"]
            .iter()
            .map(|(i, rows)| {
                (
                    c.sections[*i].name.clone(),
                    rows.iter()
                        .map(|r| match &r[0] {
                            rsim_store::Cell::Str(s) => s.clone(),
                            _ => String::new(),
                        })
                        .collect(),
                )
            })
            .collect()
    }

    #[test]
    fn an_extract_error_is_a_failed_read_of_its_section() {
        let keys = Keys::new([1; 32], [2; 32]);
        let first = classify(
            &keys,
            &sections(vec![
                observed("a", false, SPEEDS, Ok(b"eth0 1")),
                observed("b", false, SPEEDS, Ok(b"eth1 2")),
            ]),
            None,
            false,
            &|_| None,
        );
        assert!(first.extract_errors.is_empty());
        let m1 = manifest(&first);
        // Section a changes, and section b gives bytes that its extract
        // cannot read.
        let bad = sections(vec![
            observed("a", false, SPEEDS, Ok(b"eth0 5\neth2 5")),
            observed("b", false, SPEEDS, Ok(b"not a speed")),
        ]);
        let stored = blobs(&keys, &[&first]);
        let old = |h: &Hash| stored.get(h).cloned();
        let second = classify(&keys, &bad, Some(&m1), false, &old);
        assert_eq!(second.extract_errors.len(), 1, "{second:?}");
        assert_eq!(second.extract_errors[0].0, "b");
        assert!(matches!(
            second.sections[1].status,
            SectionStatus::Old { .. }
        ));
        assert_eq!(second.sections[1].blob, m1.sections[1].blob);
        assert_eq!(second.sections[1].change_hash, m1.sections[1].change_hash);
        assert_eq!(second.blobs.len(), 1);
        assert_eq!(second.sections[0].status, SectionStatus::Fresh);
        // The table has the new rows of a and the rows of the old blob of b.
        assert_eq!(
            table_rows(&second),
            vec![
                ("a".into(), vec!["eth0".into(), "eth2".into()]),
                ("b".into(), vec!["eth1".into()]),
            ]
        );
        // The same bytes in the next cycle are read again and fail again.
        let m2 = manifest(&second);
        let stored = blobs(&keys, &[&first, &second]);
        let old = |h: &Hash| stored.get(h).cloned();
        let third = classify(&keys, &bad, Some(&m2), false, &old);
        assert_eq!(third.extract_errors.len(), 1, "{third:?}");
        assert!(matches!(
            third.sections[1].status,
            SectionStatus::Old { .. }
        ));
        assert_eq!(third.sections[1].blob, m1.sections[1].blob);
        assert!(third.blobs.is_empty());
        assert!(third.changed.is_empty());
    }

    #[test]
    fn a_section_that_becomes_absent_gives_its_table_again() {
        let keys = Keys::new([1; 32], [2; 32]);
        let first = classify(
            &keys,
            &sections(vec![observed("arp", true, SPEEDS, Ok(b"eth0 1"))]),
            None,
            false,
            &|_| None,
        );
        assert_eq!(table_rows(&first).len(), 1);
        let gone = sections(vec![observed(
            "arp",
            true,
            SPEEDS,
            Err(crate::TransportError::NotFound("404".into())),
        )]);
        let second = classify(&keys, &gone, Some(&manifest(&first)), false, &|_| None);
        assert!(matches!(
            second.sections[0].status,
            SectionStatus::Absent { .. }
        ));
        assert_eq!(second.tables.get("link_speeds"), Some(&Vec::new()));
    }

    #[test]
    fn a_failed_read_keeps_an_absent_section_absent() {
        let keys = Keys::new([1; 32], [2; 32]);
        let none = |_: &Hash| None;
        let read = |r: Result<&[u8], crate::TransportError>| {
            sections(vec![
                observed("zones", true, &[], r),
                observed("config", false, &[], Ok(b"x")),
            ])
        };
        let absent = || Err(crate::TransportError::NotFound("404".into()));
        let failed = || Err(crate::TransportError::Timeout);
        let first = classify(&keys, &read(absent()), None, false, &none);
        assert!(first.changed.contains(&Class::Observation));
        let m1 = manifest(&first);
        let second = classify(&keys, &read(failed()), Some(&m1), false, &none);
        assert_eq!(second.sections[0], m1.sections[0]);
        let m2 = manifest(&second);
        let third = classify(&keys, &read(absent()), Some(&m2), false, &none);
        assert!(third.changed.is_empty(), "{third:?}");
        assert_eq!(third.sections[0], m1.sections[0]);
        // A section that is read after the failure is a change.
        let present = classify(&keys, &read(Ok(b"zone a")), Some(&m2), false, &none);
        assert!(present.changed.contains(&Class::Observation));
        // A failed first read and then an absent section is a change.
        let unread = classify(&keys, &read(failed()), None, false, &none);
        assert!(matches!(
            unread.sections[0].status,
            SectionStatus::Missing { .. }
        ));
        let later = classify(
            &keys,
            &read(absent()),
            Some(&manifest(&unread)),
            false,
            &none,
        );
        assert!(later.changed.contains(&Class::Observation));
    }
}
