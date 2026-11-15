//! Parts that all function types share.

use rsim_core::{
    Branch, Context, Delay, DelayGap, DeviceId, FlowState, FunctionId, Outcome, PacketSet, Reason,
    ReasonCode, SourceSpan,
};

use crate::profile::VendorProfile;

/// The identity, the device, the provenance and the delay data of one
/// function instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    pub id: FunctionId,
    pub device: DeviceId,
    pub provenance: Vec<SourceSpan>,
    /// The processing delay in nanoseconds, from the vendor profile or a
    /// measurement. `None` if there is no data.
    pub processing_delay_ns: Option<u64>,
    /// The name of the vendor profile from which defaults came.
    pub profile: String,
}

impl Meta {
    pub fn new(
        id: impl Into<FunctionId>,
        device: impl Into<DeviceId>,
        profile: &VendorProfile,
    ) -> Self {
        Meta {
            id: id.into(),
            device: device.into(),
            provenance: Vec::new(),
            processing_delay_ns: profile.processing_delay_ns,
            profile: profile.name.clone(),
        }
    }

    pub fn with_span(mut self, s: SourceSpan) -> Self {
        self.provenance.push(s);
        self
    }

    pub fn delay(&self) -> Delay {
        Delay::from_option(
            self.processing_delay_ns,
            DelayGap::Processing(self.id.clone()),
        )
    }

    /// A branch with this function's delay.
    pub fn branch(
        &self,
        packets: PacketSet,
        outcome: Outcome,
        reason: Reason,
        ctx: Context,
        state: &FlowState,
    ) -> Branch {
        Branch::new(packets, outcome, reason, ctx, state.clone(), self.delay())
    }

    pub fn forward(
        &self,
        packets: PacketSet,
        next: &FunctionId,
        code: ReasonCode,
        detail: impl Into<String>,
        ctx: Context,
        state: &FlowState,
    ) -> Branch {
        self.branch(
            packets,
            Outcome::Forward(next.clone()),
            Reason::new(code, detail),
            ctx,
            state,
        )
    }

    pub fn drop(
        &self,
        packets: PacketSet,
        code: ReasonCode,
        detail: impl Into<String>,
        ctx: &Context,
        state: &FlowState,
    ) -> Branch {
        self.branch(
            packets,
            Outcome::Drop,
            Reason::new(code, detail),
            ctx.clone(),
            state,
        )
    }

    pub fn indeterminate(
        &self,
        packets: PacketSet,
        code: ReasonCode,
        detail: impl Into<String>,
        ctx: &Context,
        state: &FlowState,
    ) -> Branch {
        self.branch(
            packets,
            Outcome::Indeterminate,
            Reason::new(code, detail),
            ctx.clone(),
            state,
        )
    }
}

/// Pushes a branch only if its packet set is not empty.
pub fn push_nonempty(out: &mut Vec<Branch>, b: Branch) {
    if !b.packets.is_empty() {
        out.push(b);
    }
}
