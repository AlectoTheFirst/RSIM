//! Flow state: the session and NAT state that the forward pass creates. It
//! goes into a function and comes out of a function as a value.

use std::collections::BTreeMap;

use crate::header::FlowKey;
use crate::id::{DeviceId, FunctionId};

/// One firewall session with its NAT binding.
///
/// `forward_in` is the flow key when the packets entered the session lookup
/// of the device. `forward_out` is the key after all translations of the
/// device. A difference between the two is the NAT binding.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Session {
    pub forward_in: FlowKey,
    pub forward_out: FlowKey,
    pub created_by: FunctionId,
}

impl Session {
    pub fn is_translated(&self) -> bool {
        self.forward_in != self.forward_out
    }
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
