//! Firewall session: lookup and commit. The session state is in the flow
//! state value, never in the function.

use rsim_core::{
    Attr, Branch, Context, ContextAttr, Dependency, FieldValue, FlowKey, FlowState, FunctionId,
    FunctionKind, NetFunction, PacketSet, ReasonCode, Rewrite, Session, SessionMatch, Uniform,
};

use crate::common::{Meta, push_nonempty};
use crate::forwarding::meta_methods;

fn rewrite_to(key: &FlowKey) -> Rewrite {
    Rewrite {
        src_ip: Some(key.src_ip),
        dst_ip: Some(key.dst_ip),
        src_port: Some(key.src_port),
        dst_port: Some(key.dst_port),
        ..Rewrite::default()
    }
}

/// Looks up the sessions of the device. A match in the reply direction undoes
/// the NAT binding of the session. A match in the forward direction applies
/// it again. Packets with no match are new; their flow key is kept in the
/// context for the commit.
#[derive(Clone, Debug)]
pub struct SessionLookup {
    pub meta: Meta,
    pub next: FunctionId,
}

impl NetFunction for SessionLookup {
    meta_methods!(FunctionKind::FirewallSession);

    fn requires(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::Device]
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::Session]
    }
    fn reads(&self) -> Vec<Dependency> {
        Vec::new()
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let dev = &self.meta.device;
        let mut out = Vec::new();
        let mut rest = input.clone();
        for (i, s) in state.sessions(dev).iter().enumerate() {
            let index = u32::try_from(i).expect("too many sessions");
            for (dir, key, to) in [
                ("reply", s.forward_out.reversed(), s.forward_in.reversed()),
                ("forward", s.forward_in, s.forward_out),
            ] {
                if rest.is_empty() {
                    break;
                }
                let split = rest.split_flow(&key);
                let mut c = ctx.clone();
                c.session = Attr::Known(if dir == "reply" {
                    SessionMatch::Reply {
                        device: dev.clone(),
                        index,
                    }
                } else {
                    SessionMatch::Forward {
                        device: dev.clone(),
                        index,
                    }
                });
                let detail = if s.is_translated() {
                    format!("{dir} packets of session {index}; the session translation applies")
                } else {
                    format!("{dir} packets of session {index}")
                };
                push_nonempty(
                    &mut out,
                    self.meta.forward(
                        split.matched.rewrite(&rewrite_to(&to)),
                        &self.next,
                        ReasonCode::SessionMatched,
                        detail,
                        c,
                        state,
                    ),
                );
                push_nonempty(
                    &mut out,
                    self.meta.indeterminate(
                        split.uncertain,
                        ReasonCode::UncertainMatch,
                        format!("a field is unknown, so the packets may belong to session {index}"),
                        ctx,
                        state,
                    ),
                );
                rest = split.unmatched;
            }
        }
        match rest.flow_key() {
            Uniform::None => {}
            Uniform::Value(entry) => {
                let mut c = ctx.clone();
                c.session = Attr::Known(SessionMatch::New { entry });
                out.push(self.meta.forward(
                    rest,
                    &self.next,
                    ReasonCode::Passed,
                    "no session matches; the packets are new",
                    c,
                    state,
                ));
            }
            Uniform::Varies => out.push(self.meta.indeterminate(
                rest,
                ReasonCode::UnsupportedSet,
                "step 1 keeps sessions for one flow key only",
                ctx,
                state,
            )),
        }
        out
    }
}

/// Creates the session of new packets, with the NAT binding of the device.
#[derive(Clone, Debug)]
pub struct SessionCommit {
    pub meta: Meta,
    pub next: FunctionId,
}

impl NetFunction for SessionCommit {
    meta_methods!(FunctionKind::FirewallSession);

    fn requires(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::Session]
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::Session]
    }
    fn reads(&self) -> Vec<Dependency> {
        Vec::new()
    }
    fn successors(&self) -> Vec<FunctionId> {
        vec![self.next.clone()]
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let Attr::Known(SessionMatch::New { entry }) = &ctx.session else {
            return vec![self.meta.forward(
                input.clone(),
                &self.next,
                ReasonCode::Passed,
                "the packets belong to an existing session",
                ctx.clone(),
                state,
            )];
        };
        match input.flow_key() {
            Uniform::Value(out_key) => {
                let has_unknown = [out_key.src_port, out_key.dst_port]
                    .contains(&FieldValue::Unknown)
                    || out_key.src_ip == FieldValue::Unknown
                    || out_key.dst_ip == FieldValue::Unknown;
                let (next_state, index) = state.with_session(
                    &self.meta.device,
                    Session {
                        forward_in: *entry,
                        forward_out: out_key,
                        created_by: self.meta.id.clone(),
                    },
                );
                let mut c = ctx.clone();
                c.session = Attr::Known(SessionMatch::Forward {
                    device: self.meta.device.clone(),
                    index,
                });
                let mut detail = format!("session {index} created");
                if has_unknown {
                    detail.push_str(
                        "; a translated field is unknown, so a reply cannot be matched exactly",
                    );
                }
                let mut b = self.meta.forward(
                    input.clone(),
                    &self.next,
                    ReasonCode::SessionCreated,
                    detail,
                    c,
                    state,
                );
                b.state = next_state;
                vec![b]
            }
            Uniform::Varies => vec![self.meta.indeterminate(
                input.clone(),
                ReasonCode::UnsupportedSet,
                "step 1 keeps sessions for one flow key only",
                ctx,
                state,
            )],
            Uniform::None => Vec::new(),
        }
    }
}
