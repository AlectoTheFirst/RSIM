//! Firewall session: lookup and commit. The session state is in the flow
//! state value, never in the function.

use rsim_core::{
    Attr, Branch, Context, ContextAttr, Dependency, FlowState, FunctionId, FunctionKind,
    NetFunction, PacketSet, ReasonCode, Session, SessionDirection, SessionMatch,
};

use crate::common::{Meta, push_nonempty};
use crate::forwarding::meta_methods;

/// What the session lookup does with the packets of one connection state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateAction {
    /// The packets go on, and the firewall policy passes them.
    Accept,
    /// The packets are dropped at the session lookup.
    Drop,
    /// The packets go on, and the firewall policy evaluates them.
    Continue,
    /// The action is not known, so the packets are unknown.
    Unknown,
}

/// The action of each connection state. The packets of a session have the
/// state established, and all other packets have the state new. The lookup
/// gives no packet the state related or invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateActions {
    pub established: StateAction,
    pub related: StateAction,
    pub invalid: StateAction,
}

impl Default for StateActions {
    /// The packets of a session pass the firewall policy.
    fn default() -> Self {
        StateActions {
            established: StateAction::Accept,
            related: StateAction::Accept,
            invalid: StateAction::Continue,
        }
    }
}

/// Looks up the sessions of the device. A match in the reply direction undoes
/// the NAT binding of the session. A match in the forward direction applies
/// it again. The action of the state established then applies to the
/// matched packets. Packets with no match are new; their flow key is kept in
/// the context for the commit.
#[derive(Clone, Debug)]
pub struct SessionLookup {
    pub meta: Meta,
    pub next: FunctionId,
    pub states: StateActions,
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
                let mut detail = if s.translated {
                    format!("session {index}, {name}, translated")
                } else {
                    format!("session {index}, {name}")
                };
                let matched = match self.states.established {
                    StateAction::Accept => self.meta.forward(
                        split.matched,
                        &self.next,
                        ReasonCode::SessionMatched,
                        detail,
                        c,
                        state,
                    ),
                    StateAction::Continue => {
                        detail.push_str(", no state policy action for established");
                        self.meta.forward(
                            split.matched,
                            &self.next,
                            ReasonCode::SessionMatched,
                            detail,
                            c,
                            state,
                        )
                    }
                    StateAction::Drop => {
                        detail.push_str(", state policy drops established");
                        self.meta
                            .drop(split.matched, ReasonCode::Denied, detail, &c, state)
                    }
                    StateAction::Unknown => {
                        detail.push_str(", state policy action for established not known");
                        self.meta.unknown(
                            split.matched,
                            ReasonCode::MatchUnknown,
                            detail,
                            &c,
                            state,
                        )
                    }
                };
                push_nonempty(&mut out, matched);
                push_nonempty(
                    &mut out,
                    self.meta.unknown(
                        split.uncertain,
                        ReasonCode::MatchUnknown,
                        format!("session {index}, port not known"),
                        ctx,
                        state,
                    ),
                );
                push_nonempty(
                    &mut out,
                    self.meta.unknown(
                        split.ambiguous,
                        ReasonCode::MatchUnknown,
                        format!("session {index}, {name} flow with more than one binding"),
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
                "no session, new",
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
    /// False on a device that keeps a session only for a translated flow,
    /// for example a stateless router with NAT: an untranslated flow gets no
    /// session.
    pub keep_untranslated: bool,
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
        let Attr::Known(SessionMatch::New { entry } | SessionMatch::Untracked { entry }) =
            &ctx.session
        else {
            return vec![self.meta.forward(
                input.clone(),
                &self.next,
                ReasonCode::Passed,
                "existing session",
                ctx.clone(),
                state,
            )];
        };
        if input.is_empty() {
            return Vec::new();
        }
        let relation = entry.session_relation(input);
        let translated = relation.changes_flow();
        if !translated && !self.keep_untranslated {
            return vec![self.meta.forward(
                input.clone(),
                &self.next,
                ReasonCode::Passed,
                "not translated, no session",
                ctx.clone(),
                state,
            )];
        }
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
            detail.push_str(", translated field not known");
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
