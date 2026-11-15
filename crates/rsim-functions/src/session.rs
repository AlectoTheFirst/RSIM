//! Firewall session: lookup and commit. The session state is in the flow
//! state value, never in the function.

use rsim_core::{
    Attr, Branch, Context, ContextAttr, Dependency, FlowState, FunctionId, FunctionKind,
    NetFunction, PacketSet, ReasonCode, Session, SessionDirection, SessionMatch,
};

use crate::common::{Meta, push_nonempty};
use crate::forwarding::meta_methods;

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
            for dir in [SessionDirection::Reply, SessionDirection::Forward] {
                if rest.is_empty() {
                    break;
                }
                let split = rest.session_lookup(&s.relation, dir);
                let (name, m) = match dir {
                    SessionDirection::Reply => (
                        "reply",
                        SessionMatch::Reply {
                            device: dev.clone(),
                            index,
                        },
                    ),
                    SessionDirection::Forward => (
                        "forward",
                        SessionMatch::Forward {
                            device: dev.clone(),
                            index,
                        },
                    ),
                };
                let mut c = ctx.clone();
                c.session = Attr::Known(m);
                let detail = if s.translated {
                    format!("{name} packets · session {index}, translated")
                } else {
                    format!("{name} packets · session {index}")
                };
                push_nonempty(
                    &mut out,
                    self.meta.forward(
                        split.matched,
                        &self.next,
                        ReasonCode::SessionMatched,
                        detail,
                        c,
                        state,
                    ),
                );
                push_nonempty(
                    &mut out,
                    self.meta.unknown(
                        split.uncertain,
                        ReasonCode::MatchUnknown,
                        format!("port unknown · session {index}"),
                        ctx,
                        state,
                    ),
                );
                push_nonempty(
                    &mut out,
                    self.meta.unknown(
                        split.ambiguous,
                        ReasonCode::MatchUnknown,
                        format!("the {name} flow has more than one binding · session {index}"),
                        ctx,
                        state,
                    ),
                );
                rest = split.unmatched;
            }
        }
        if !rest.is_empty() {
            let mut c = ctx.clone();
            c.session = Attr::Known(SessionMatch::New {
                entry: rest.clone(),
            });
            out.push(self.meta.forward(
                rest,
                &self.next,
                ReasonCode::Passed,
                "no session matches; the packets are new",
                c,
                state,
            ));
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
        if input.is_empty() {
            return Vec::new();
        }
        let relation = entry.session_relation(input);
        let translated = relation.changes_flow();
        let (next_state, index) = state.with_session(
            &self.meta.device,
            Session {
                relation,
                translated,
                created_by: self.meta.id.clone(),
            },
        );
        let mut c = ctx.clone();
        c.session = Attr::Known(SessionMatch::Forward {
            device: self.meta.device.clone(),
            index,
        });
        let mut detail = format!("session {index} created");
        if input.has_unknown_flow_field() {
            detail.push_str("; a translated field is unknown");
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
}
