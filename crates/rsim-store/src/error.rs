use std::fmt;

/// An error of the snapshot store.
#[derive(Debug)]
pub enum StoreError {
    /// A file operation failed.
    Io { path: String, error: std::io::Error },
    /// A manifest or a JSON section is not valid JSON.
    Json(String),
    /// A Parquet or Arrow operation failed.
    Table(String),
    /// A blob does not decrypt with the keys, or its content does not have
    /// its name.
    Integrity(String),
    /// A table file has a schema version that this build does not read.
    SchemaVersion {
        table: String,
        found: u32,
        expected: u32,
    },
    /// A file that a manifest names does not exist.
    NotFound(String),
    /// A value is not valid for its field.
    Invalid(String),
    /// A file of the cycle exists, because another writer took the same
    /// cycle number. The cycle publishes nothing.
    Conflict(String),
}

impl StoreError {
    pub(crate) fn io(path: &std::path::Path, error: std::io::Error) -> StoreError {
        StoreError::Io {
            path: path.display().to_string(),
            error,
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io { path, error } => write!(f, "{path}: {error}"),
            StoreError::Json(e) => write!(f, "json: {e}"),
            StoreError::Table(e) => write!(f, "table: {e}"),
            StoreError::Integrity(e) => write!(f, "integrity: {e}"),
            StoreError::SchemaVersion {
                table,
                found,
                expected,
            } => write!(
                f,
                "table {table} has schema version {found}, this build reads version {expected}"
            ),
            StoreError::NotFound(e) => write!(f, "not found: {e}"),
            StoreError::Invalid(e) => write!(f, "invalid: {e}"),
            StoreError::Conflict(e) => write!(f, "conflict: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        StoreError::Json(e.to_string())
    }
}

impl From<parquet::errors::ParquetError> for StoreError {
    fn from(e: parquet::errors::ParquetError) -> Self {
        StoreError::Table(e.to_string())
    }
}

impl From<arrow_schema::ArrowError> for StoreError {
    fn from(e: arrow_schema::ArrowError) -> Self {
        StoreError::Table(e.to_string())
    }
}
