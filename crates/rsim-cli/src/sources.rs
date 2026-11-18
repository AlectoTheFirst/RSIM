//! The masked source lines of a span of a twin. The file of a span of a
//! store twin is `<device>/<section>@<blob>`, a section blob of the snapshot
//! of the twin; its lines are the lines of the canonical form of the
//! section, with the secrets masked by the mask of the vendor. A section
//! with no mask for its vendor and format is not given.

use rsim_contract::json::{SpanJson, StepOut};
use rsim_contract::source::{
    MAX_LINES, SourceLineJson, SourceLinesOut, SourceTextJson, StepSourceJson,
};
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

/// The masked lines of a span of a twin: at most `MAX_LINES` lines, and
/// the number of the lines after the limit.
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
    let shown = last.min(first + MAX_LINES - 1);
    let cut = last - shown;
    Ok(SourceTextJson {
        file: file.to_string(),
        first_line: first,
        last_line: last,
        lines: (first..=shown)
            .map(|n| SourceLineJson {
                number: n,
                text: lines[(n - 1) as usize].clone(),
            })
            .collect(),
        cut,
        note: (cut > 0).then(|| {
            format!(
                "the answer has at most {MAX_LINES} lines; lines {} to {last} are cut",
                shown + 1
            )
        }),
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
