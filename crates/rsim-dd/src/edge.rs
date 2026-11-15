//! Edges: a node index and a complement flag in one `u32`.

use std::fmt;

/// A reference to a function: a node and a complement flag.
///
/// Node 0 is the terminal node. The regular edge to it is the constant
/// true, and the complemented edge is the constant false.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Edge(u32);

impl Edge {
    pub const TRUE: Edge = Edge(0);
    pub const FALSE: Edge = Edge(1);

    /// The largest node index that an edge can hold.
    pub(crate) const MAX_INDEX: u32 = u32::MAX >> 1;

    pub(crate) fn new(index: u32, complement: bool) -> Edge {
        Edge((index << 1) | complement as u32)
    }

    pub(crate) fn index(self) -> u32 {
        self.0 >> 1
    }

    /// The complement of the function.
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn not(self) -> Edge {
        Edge(self.0 ^ 1)
    }

    pub fn is_complement(self) -> bool {
        self.0 & 1 == 1
    }

    /// The edge with the complement flag cleared.
    #[must_use]
    pub fn regular(self) -> Edge {
        Edge(self.0 & !1)
    }

    /// The edge with the complement flag of `c` added.
    pub(crate) fn xor_complement(self, c: bool) -> Edge {
        Edge(self.0 ^ c as u32)
    }

    pub fn is_constant(self) -> bool {
        self.index() == 0
    }

    /// The raw value, for the cache keys.
    pub(crate) fn raw(self) -> u32 {
        self.0
    }
}

impl std::ops::Not for Edge {
    type Output = Edge;

    fn not(self) -> Edge {
        Edge::not(self)
    }
}

impl fmt::Debug for Edge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Edge::TRUE => write!(f, "true"),
            Edge::FALSE => write!(f, "false"),
            e if e.is_complement() => write!(f, "!n{}", e.index()),
            e => write!(f, "n{}", e.index()),
        }
    }
}
