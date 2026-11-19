//! The masked source lines of a span of a twin. The file of a span of a
//! store twin is `<device>/<section>@<blob>`, a section blob of the snapshot
//! of the twin; its lines are the lines of the canonical form of the
//! section, with the secrets masked by the mask of the vendor. A section
//! with no mask for its vendor and format is not given. Only the lines that
//! lie inside a source span of a function of the twin are given.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use rsim_contract::json::{SpanJson, StepOut};
use rsim_contract::source::{
    LineRangeJson, MAX_LINES, SourceLineJson, SourceLinesOut, SourceTextJson, StepSourceJson,
};
use rsim_engine::Twin;
use rsim_ingest::mask::{Refusal, section_lines};
use rsim_store::{Snapshot, Store};

use crate::commands::Loaded;
use crate::error::{ErrorCode, QueryError};
use crate::json::VERSION;

/// The store and the snapshot of a store twin. The store is open for
/// reading only.
pub struct SourceStore {
    pub store: Store,
    pub snapshot: Snapshot,
    /// The line ranges of the source spans of the functions of the twin,
    /// built when a request first asks for source lines.
    pub spans: OnceLock<SpanIndex>,
}

impl SourceStore {
    pub fn new(store: Store, snapshot: Snapshot) -> Self {
        SourceStore {
            store,
            snapshot,
            spans: OnceLock::new(),
        }
    }
}

/// The key of a file in the span index: the file with the blob name after
/// its last `@` cut to 12 characters, so the short and the full name of a
/// blob give one key.
fn file_key(file: &str) -> String {
    match file.rsplit_once('@') {
        Some((path, blob)) if blob.len() > 12 && blob.is_char_boundary(12) => {
            format!("{path}@{}", &blob[..12])
        }
        _ => file.to_string(),
    }
}

/// The sorted, merged line ranges of the source spans of all functions of
/// a twin, by file key.
#[derive(Debug, Default)]
pub struct SpanIndex(BTreeMap<String, Vec<(u32, u32)>>);

impl SpanIndex {
    /// The index of each span that a trace step of a function of the twin
    /// can name.
    pub fn of(twin: &Twin) -> Self {
        let mut by_file: BTreeMap<String, Vec<(u32, u32)>> = BTreeMap::new();
        for f in twin.functions() {
            f.each_span(&mut |s| {
                by_file
                    .entry(file_key(&s.file))
                    .or_default()
                    .push((s.first_line, s.last_line));
            });
        }
        for v in by_file.values_mut() {
            v.sort_unstable();
            let mut merged: Vec<(u32, u32)> = Vec::with_capacity(v.len());
            for &(a, b) in v.iter() {
                match merged.last_mut() {
                    Some(m) if a <= m.1.saturating_add(1) => m.1 = m.1.max(b),
                    _ => merged.push((a, b)),
                }
            }
            *v = merged;
        }
        SpanIndex(by_file)
    }

    /// The parts of the lines `first` to `last` of a file that lie inside a
    /// span, in order.
    pub fn covered(&self, file: &str, first: u32, last: u32) -> Vec<(u32, u32)> {
        let Some(v) = self.0.get(&file_key(file)) else {
            return Vec::new();
        };
        let start = v.partition_point(|r| r.1 < first);
        v[start..]
            .iter()
            .take_while(|r| r.0 <= last)
            .map(|r| (r.0.max(first), r.1.min(last)))
            .collect()
    }
}

/// The ranges of `first` to `last` that are not in `covered`.
fn gaps(covered: &[(u32, u32)], first: u32, last: u32) -> Vec<LineRangeJson> {
    let mut out = Vec::new();
    let mut next = first;
    for &(a, b) in covered {
        if a > next {
            out.push(LineRangeJson {
                first_line: next,
                last_line: a - 1,
            });
        }
        next = b.saturating_add(1);
    }
    if next <= last {
        out.push(LineRangeJson {
            first_line: next,
            last_line: last,
        });
    }
    out
}

fn ranges_text(r: &[LineRangeJson]) -> String {
    r.iter()
        .map(|x| {
            if x.first_line == x.last_line {
                x.first_line.to_string()
            } else {
                format!("{}-{}", x.first_line, x.last_line)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn invalid(detail: String) -> QueryError {
    QueryError::new(ErrorCode::InvalidQuery, detail)
}

/// The line range of a parameter `a-b`, or `a` for one line.
pub fn parse_range(text: &str) -> Result<(u32, u32), QueryError> {
    let num = |s: &str| {
        s.trim()
            .parse::<u32>()
            .map_err(|_| invalid(format!("lines {text} is not a range a-b of line numbers")))
    };
    let (first, last) = match text.split_once('-') {
        Some((a, b)) => (num(a)?, num(b)?),
        None => {
            let n = num(text)?;
            (n, n)
        }
    };
    if first == 0 || first > last {
        return Err(invalid(format!(
            "lines {text} is not a range a-b with 1 <= a <= b"
        )));
    }
    Ok((first, last))
}

/// The masked lines of a span of a twin that lie inside a source span of a
/// function of the twin: at most `MAX_LINES` lines from `first`, the ranges
/// that are left out, and the number of the lines after the limit. A span
/// with no line inside a source span of a function is refused.
pub fn text(
    twin: &Loaded,
    file: &str,
    first: u32,
    last: u32,
) -> Result<SourceTextJson, QueryError> {
    if first == 0 || first > last {
        return Err(invalid(format!(
            "lines {first}-{last} is not a range a-b with 1 <= a <= b"
        )));
    }
    let none = |d: String| QueryError::new(ErrorCode::NoSourceText, d);
    let Some(src) = &twin.source else {
        return Err(none(format!(
            "the twin {} has no source text",
            twin.identity.id
        )));
    };
    let not_here = || {
        none(format!(
            "{file} is not a section of the snapshot of the twin {}",
            twin.identity.id
        ))
    };
    let (path, short) = file.rsplit_once('@').ok_or_else(not_here)?;
    let (device, section) = path.rsplit_once('/').ok_or_else(not_here)?;
    let m = src.snapshot.devices.get(device).ok_or_else(not_here)?;
    let entry = m.section(section).ok_or_else(not_here)?;
    let blob = entry.blob.ok_or_else(not_here)?;
    let name = blob.to_string();
    if short.len() < 12 || !name.starts_with(short) {
        return Err(not_here());
    }
    let bytes = src
        .store
        .read_blob(&blob)
        .map_err(|e| QueryError::new(ErrorCode::Store, e.to_string()))?;
    let lines = section_lines(&m.vendor, entry.format, &bytes).map_err(|r| match r {
        Refusal::NoMask { .. } => QueryError::new(
            ErrorCode::NotMasked,
            format!("{file}: {r}, so its lines are not given"),
        ),
        Refusal::Unreadable(_) => QueryError::new(ErrorCode::Store, format!("{file}: {r}")),
    })?;
    let count = u32::try_from(lines.len()).unwrap_or(u32::MAX);
    if last > count {
        return Err(invalid(format!(
            "lines {first}-{last} are beyond the {count} lines of {file}"
        )));
    }
    let key = format!("{device}/{section}@{}", &name[..12]);
    let index = src.spans.get_or_init(|| SpanIndex::of(&twin.twin));
    let covered = index.covered(&key, first, last);
    if covered.is_empty() {
        return Err(QueryError::new(
            ErrorCode::NotASourceSpan,
            format!(
                "lines {first}-{last} of {file} are outside every source span of a function of the twin {}, so they are not given",
                twin.identity.id
            ),
        ));
    }
    let left_out = gaps(&covered, first, last);
    let shown = last.min(first + MAX_LINES - 1);
    let cut = last - shown;
    let mut notes = Vec::new();
    if !left_out.is_empty() {
        notes.push(format!(
            "lines {} are outside every source span of a function of the twin and are left out",
            ranges_text(&left_out)
        ));
    }
    if cut > 0 {
        notes.push(format!(
            "the answer has at most {MAX_LINES} lines; lines {} to {last} are cut",
            shown + 1
        ));
    }
    Ok(SourceTextJson {
        file: file.to_string(),
        first_line: first,
        last_line: last,
        lines: covered
            .iter()
            .flat_map(|&(a, b)| a..=b.min(shown))
            .map(|n| SourceLineJson {
                number: n,
                text: lines[(n - 1) as usize].clone(),
            })
            .collect(),
        left_out,
        cut,
        note: (!notes.is_empty()).then(|| notes.join("; ")),
    })
}

/// The output object of the masked lines of a span.
pub fn lines(
    topology: &str,
    twin: &Loaded,
    file: &str,
    first: u32,
    last: u32,
) -> Result<SourceLinesOut, QueryError> {
    Ok(SourceLinesOut {
        rsim_json: VERSION,
        kind: "source_lines".into(),
        topology: topology.to_string(),
        twin: twin.identity.clone(),
        source: text(twin, file, first, last)?,
    })
}

/// The masked lines of each span, or the error that refuses them.
pub fn of_spans(twin: &Loaded, spans: &[SpanJson]) -> Vec<StepSourceJson> {
    spans
        .iter()
        .map(|s| match text(twin, &s.file, s.first_line, s.last_line) {
            Ok(t) => StepSourceJson::Lines(t),
            Err(error) => StepSourceJson::Refused {
                file: s.file.clone(),
                first_line: s.first_line,
                last_line: s.last_line,
                error,
            },
        })
        .collect()
}

/// Adds the masked lines of each span of the step to a step output.
pub fn attach(out: &mut StepOut, twin: &Loaded) {
    out.source_lines = Some(of_spans(twin, &out.trace_step.provenance));
}
