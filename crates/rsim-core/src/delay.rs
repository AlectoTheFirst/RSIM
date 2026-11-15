//! Delay in virtual time (section 12). A function never sleeps.

use std::collections::BTreeSet;

use crate::id::FunctionId;

/// A delay component with no data.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DelayGap {
    /// The processing delay of a function.
    Processing(FunctionId),
    /// The delay of the link after an egress function.
    Link(FunctionId),
    /// The load-dependent queueing delay of the link after an egress function,
    /// where the link has no load data. No function emits this kind before
    /// step 7 (section 12).
    Queueing(FunctionId),
}

/// A virtual-time duration in nanoseconds. If a component has no data, the
/// value is a lower bound and the missing components are listed. There are
/// no invented defaults.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Delay {
    known_ns: u64,
    missing: BTreeSet<DelayGap>,
}

impl Delay {
    pub fn zero() -> Self {
        Self::default()
    }

    pub fn known(ns: u64) -> Self {
        Delay {
            known_ns: ns,
            missing: BTreeSet::new(),
        }
    }

    pub fn unknown(gap: DelayGap) -> Self {
        Delay {
            known_ns: 0,
            missing: [gap].into_iter().collect(),
        }
    }

    /// A known value if `ns` is `Some`, else a gap.
    pub fn from_option(ns: Option<u64>, gap: DelayGap) -> Self {
        match ns {
            Some(ns) => Delay::known(ns),
            None => Delay::unknown(gap),
        }
    }

    pub fn add(&self, other: &Delay) -> Delay {
        let mut missing = self.missing.clone();
        missing.extend(other.missing.iter().cloned());
        Delay {
            known_ns: self.known_ns.saturating_add(other.known_ns),
            missing,
        }
    }

    pub fn known_ns(&self) -> u64 {
        self.known_ns
    }

    /// True if components are missing, so that the value is a lower bound.
    pub fn is_lower_bound(&self) -> bool {
        !self.missing.is_empty()
    }

    pub fn missing(&self) -> &BTreeSet<DelayGap> {
        &self.missing
    }
}
