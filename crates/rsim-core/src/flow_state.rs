//! Flow state: the session and NAT state that the forward pass creates. It
//! goes into a function and comes out of a function as a value.

use std::collections::BTreeMap;

use crate::id::{DeviceId, FunctionId};
use crate::packet_set::PacketSet;

/// One firewall session with its NAT binding.
///
/// `relation` is a relation from the forward flow at the session lookup of
/// the device to the forward flow after all translations of the device.
/// See [`PacketSet::session_relation`]. The NAT binding is part of the
/// relation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Session {
    pub relation: PacketSet,
    /// True if the relation changes a flow field.
    pub translated: bool,
    pub created_by: FunctionId,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowState {
    sessions: BTreeMap<DeviceId, Vec<Session>>,
}

impl FlowState {
    pub fn new() -> Self {
        Self::default()
    }

    /// The sessions of a device, in creation order.
    pub fn sessions(&self, device: &DeviceId) -> &[Session] {
        self.sessions.get(device).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn session(&self, device: &DeviceId, index: u32) -> Option<&Session> {
        self.sessions.get(device)?.get(index as usize)
    }

    /// Returns a new flow state with one more session, and its index.
    pub fn with_session(&self, device: &DeviceId, s: Session) -> (FlowState, u32) {
        let mut next = self.clone();
        let v = next.sessions.entry(device.clone()).or_default();
        v.push(s);
        let idx = u32::try_from(v.len() - 1).expect("too many sessions");
        (next, idx)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.values().map(Vec::len).sum()
    }
}
