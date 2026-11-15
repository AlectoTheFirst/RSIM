//! Errors of the decision diagram engine.

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DdError {
    /// The scratch arena reached its node budget.
    NodeBudget { budget: usize },
    /// An operation tried to create a node in a read-only arena.
    ArenaFrozen,
    /// A level is not below the number of levels of the arena.
    LevelOutOfRange { level: u32, levels: u32 },
    /// An invariant of the node form or of the arena does not hold.
    InvariantBroken(String),
}

impl fmt::Display for DdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DdError::NodeBudget { budget } => write!(f, "the node budget of {budget} is reached"),
            DdError::ArenaFrozen => write!(f, "the arena is read-only"),
            DdError::LevelOutOfRange { level, levels } => {
                write!(
                    f,
                    "level {level} is not below the {levels} levels of the arena"
                )
            }
            DdError::InvariantBroken(d) => write!(f, "invariant broken: {d}"),
        }
    }
}

impl std::error::Error for DdError {}
