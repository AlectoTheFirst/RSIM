//! Provenance: the source spans from which a function instance came.

use std::fmt;
use std::sync::Arc;

/// The end of the file of a row span.
pub const ROW_MARK: &str = "#row";

/// Whether a file of a span names the rows of a table, not the lines of a
/// text.
pub fn is_row_file(file: &str) -> bool {
    file.ends_with(ROW_MARK)
}

/// A file and an inclusive line range. In a row span, the file ends with
/// [`ROW_MARK`] and the lines are the row numbers of a table, from 1.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceSpan {
    pub file: Arc<str>,
    pub first_line: u32,
    pub last_line: u32,
}

impl SourceSpan {
    pub fn new(file: impl AsRef<str>, first_line: u32, last_line: u32) -> Self {
        assert!(
            first_line <= last_line,
            "a source span must not run backwards"
        );
        Self {
            file: Arc::from(file.as_ref()),
            first_line,
            last_line,
        }
    }

    pub fn line(file: impl AsRef<str>, line: u32) -> Self {
        Self::new(file, line, line)
    }

    /// The span of the row `row`, from 1, of a table read from `file`.
    pub fn row(file: impl AsRef<str>, row: u32) -> Self {
        Self::line(format!("{}{ROW_MARK}", file.as_ref()), row)
    }

    /// Whether the span names the rows of a table.
    pub fn is_row(&self) -> bool {
        is_row_file(&self.file)
    }
}

impl fmt::Debug for SourceSpan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.first_line == self.last_line {
            write!(f, "{}:{}", self.file, self.first_line)
        } else {
            write!(f, "{}:{}-{}", self.file, self.first_line, self.last_line)
        }
    }
}

impl fmt::Display for SourceSpan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
