//! Provenance: the source spans from which a function instance came (principle 3).

use std::fmt;
use std::sync::Arc;

/// A file and an inclusive line range.
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
