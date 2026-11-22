//! The identity of a twin: a base and an ordered list of what-if layers.
//!
//! The identifier grammar: `builtin.<topology>` for a hand-built topology of the tests,
//! `snap-<cycle>` for a snapshot of the store, and
//! `snap-<cycle>~<scenario>~<hash>` for a scenario on a snapshot. A name is
//! lower-case letters, digits and `-`, so `.` and `~` only separate the
//! parts.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Twin
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TwinJson {
    /// Twin
    pub id: String,
    /// Base
    pub base: String,
    /// Cycle
    pub snapshot: Option<u64>,
    /// Layers
    pub layers: Vec<String>,
}

/// True if `name` is a name of the grammar: lower-case letters, digits and
/// `-`, not empty.
pub fn is_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl TwinJson {
    /// The twin of a hand-built topology of the tests, or an error for a name that is not
    /// a name of the grammar.
    pub fn builtin(topology: &str) -> Result<TwinJson, String> {
        if !is_name(topology) {
            return Err(format!(
                "{topology:?} is not a twin name: lower-case letters, digits and -"
            ));
        }
        let id = format!("builtin.{topology}");
        Ok(TwinJson {
            id: id.clone(),
            base: id,
            snapshot: None,
            layers: Vec::new(),
        })
    }

    /// The twin of a snapshot cycle of the store.
    pub fn snapshot(cycle: u64) -> TwinJson {
        let id = format!("snap-{cycle}");
        TwinJson {
            id: id.clone(),
            base: id,
            snapshot: Some(cycle),
            layers: Vec::new(),
        }
    }

    /// Reads a twin identifier with no scenario. A scenario identifier is
    /// refused until the what-if layers exist.
    pub fn parse(id: &str) -> Result<TwinJson, String> {
        if let Some(t) = id.strip_prefix("builtin.") {
            return TwinJson::builtin(t);
        }
        if let Some(c) = id.strip_prefix("snap-") {
            if c.contains('~') {
                return Err(format!("{id:?}: a scenario twin is not available"));
            }
            return c
                .parse::<u64>()
                .map(TwinJson::snapshot)
                .map_err(|_| format!("{id:?}: the cycle is not a number"));
        }
        Err(format!(
            "{id:?} is not a twin identifier: builtin.<topology> or snap-<cycle>"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identifier_reads_back_to_its_twin() {
        for t in [
            TwinJson::builtin("leaf-spine").unwrap(),
            TwinJson::snapshot(17),
        ] {
            assert_eq!(TwinJson::parse(&t.id), Ok(t.clone()));
            assert!(t.layers.is_empty());
        }
        assert_eq!(TwinJson::snapshot(17).snapshot, Some(17));
    }

    #[test]
    fn a_name_with_a_separator_is_refused() {
        for bad in ["a.b", "a~b", "Upper", "", "a/b", "a b"] {
            assert!(TwinJson::builtin(bad).is_err(), "{bad:?}");
        }
        for bad in ["snap-x", "snap-1~edge~ab12", "other", "builtin.a.b"] {
            assert!(TwinJson::parse(bad).is_err(), "{bad:?}");
        }
    }
}
