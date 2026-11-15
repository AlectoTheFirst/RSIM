//! Reduced ordered binary decision diagrams with complement edges.
//!
//! The engine works with bits and levels. It has no packet types. A root
//! arena holds the nodes that are built once, and freezes into a read-only
//! [`Frozen`] arena that all threads share. A scratch arena reads a frozen
//! arena and holds the nodes of one query, up to a node budget.
//!
//! Each operation returns a `Result`. The engine does not panic.

mod dd;
mod edge;
mod error;
mod hash;
#[cfg(feature = "dd-shadow")]
mod plain;

pub use dd::{Dd, Frozen, MapId};
pub use edge::Edge;
pub use error::DdError;
