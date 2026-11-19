//! The multicast route lookup.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::{
    AddrCond, Attr, Branch, Context, ContextAttr, Dependency, FieldValue, FloodCopy, FlowState,
    FunctionId, FunctionKind, InterfaceId, Mac, Match, NetFunction, PacketSet, PortId, Prefix,
    ReasonCode, Rewrite, RulePredicate, SourceSpan, VrfId,
};

use crate::common::{Meta, push_nonempty};
use crate::forwarding::meta_methods;

/// One multicast route: an (S,G) route with a source, or a (*,G) route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McastRoute {
    pub source: Option<IpAddr>,
    pub group: Prefix,
    /// The incoming interface of the reverse path check.
    pub iif: Option<InterfaceId>,
    /// The outgoing interfaces with their next function, in the order of
    /// the copies.
    pub oifs: Vec<(InterfaceId, FunctionId)>,
    pub spans: Vec<SourceSpan>,
}

/// Looks up the multicast routes of the VRF for packets to a multicast
/// group. A packet that passes the reverse path check gets one copy for
/// each outgoing interface, other than its incoming interface, with the
/// destination MAC of its group. The multicast route state is collected
/// state that changes with the traffic, so a packet with no route, or a
/// packet that only a (*,G) route matches and that fails its reverse path
/// check, is `Unknown`.
#[derive(Clone, Debug)]
pub struct MulticastLookup {
    pub meta: Meta,
    /// The routes of each VRF, the (S,G) routes before the (*,G) routes.
    pub routes: BTreeMap<VrfId, Vec<McastRoute>>,
    /// The function of the packets to a unicast destination. `None` gives
    /// them `Unknown`.
    pub unicast: Option<FunctionId>,
    /// The incoming interface of the reverse path check in place of the
    /// ingress interface, for a packet that the device sends itself.
    pub rpf_interface: Option<InterfaceId>,
    /// Why the routes are not known. With a reason, each multicast packet is
    /// `Unknown`.
    pub unknown: Option<String>,
}

/// The multicast destination ranges of IPv4 and IPv6.
fn multicast() -> RulePredicate {
    RulePredicate::exact(Match {
        dst_ip: AddrCond::prefixes(&["224.0.0.0/4", "ff00::/8"]),
        ..Match::any()
    })
}

/// The destination MAC of an IPv4 multicast group: `01:00:5e` and the low
/// 23 bits of the group.
pub fn group_mac(group: IpAddr) -> Option<Mac> {
    match group {
        IpAddr::V4(a) => {
            let o = a.octets();
            Some(Mac([0x01, 0x00, 0x5e, o[1] & 0x7f, o[2], o[3]]))
        }
        IpAddr::V6(_) => None,
    }
}

impl McastRoute {
    fn predicate(&self) -> RulePredicate {
        RulePredicate::exact(Match {
            src_ip: match self.source {
                Some(s) => AddrCond::In(vec![Prefix::host(s)]),
                None => AddrCond::Any,
            },
            dst_ip: AddrCond::In(vec![self.group]),
            ..Match::any()
        })
    }

    fn name(&self) -> String {
        match self.source {
            Some(s) => format!("({s}, {})", self.group),
            None => format!("(*, {})", self.group),
        }
    }
}

impl NetFunction for MulticastLookup {
    meta_methods!(FunctionKind::MulticastLookup);

    fn each_span(&self, f: &mut dyn FnMut(&rsim_core::SourceSpan)) {
        for s in &self.meta.provenance {
            f(s);
        }
        for s in self.routes.values().flatten().flat_map(|r| &r.spans) {
            f(s);
        }
    }

    fn requires(&self) -> Vec<ContextAttr> {
        let mut v = vec![ContextAttr::Vrf];
        if self.rpf_interface.is_none() {
            v.push(ContextAttr::IngressInterface);
        }
        v
    }
    fn provides(&self) -> Vec<ContextAttr> {
        vec![ContextAttr::EgressInterface]
    }
    fn reads(&self) -> Vec<Dependency> {
        self.routes
            .keys()
            .map(|v| Dependency::RouteTable(self.meta.device.clone(), v.clone()))
            .collect()
    }
    fn successors(&self) -> Vec<FunctionId> {
        let mut v: Vec<FunctionId> = self
            .routes
            .values()
            .flatten()
            .flat_map(|r| r.oifs.iter().map(|o| o.1.clone()))
            .chain(self.unicast.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }
    fn apply(&self, input: &PacketSet, ctx: &Context, state: &FlowState) -> Vec<Branch> {
        let mut out = Vec::new();
        let s = input.split(&multicast());
        let unicast = match &self.unicast {
            Some(next) => self.meta.forward(
                s.unmatched,
                next,
                ReasonCode::Passed,
                "a unicast destination",
                ctx.clone(),
                state,
            ),
            None => self.meta.unknown(
                s.unmatched,
                ReasonCode::IncompleteTable,
                "a unicast destination at a multicast lookup",
                ctx,
                state,
            ),
        };
        push_nonempty(&mut out, unicast);
        push_nonempty(
            &mut out,
            self.meta.unknown(
                s.uncertain,
                ReasonCode::UnknownAttribute,
                "the destination address is not known",
                ctx,
                state,
            ),
        );
        let mut rest = s.matched;
        if rest.is_empty() {
            return out;
        }
        if let Some(why) = &self.unknown {
            out.push(
                self.meta
                    .unknown(rest, ReasonCode::IncompleteTable, why.clone(), ctx, state),
            );
            return out;
        }
        let Some(vrf) = ctx.vrf.known() else {
            out.push(self.meta.unknown(
                rest,
                ReasonCode::UnknownAttribute,
                "the VRF is not known",
                ctx,
                state,
            ));
            return out;
        };
        let incoming = self
            .rpf_interface
            .as_ref()
            .or_else(|| ctx.ingress_interface.known());
        for r in self.routes.get(vrf).into_iter().flatten() {
            if rest.is_empty() {
                break;
            }
            let sp = rest.split(&r.predicate());
            rest = sp.unmatched;
            push_nonempty(
                &mut out,
                self.meta.unknown(
                    sp.uncertain,
                    ReasonCode::MatchUnknown,
                    format!("the match of {} is not known", r.name()),
                    ctx,
                    state,
                ),
            );
            let m = sp.matched;
            if m.is_empty() {
                continue;
            }
            let rpf_ok = match (&r.iif, incoming) {
                (None, _) => true,
                (Some(i), Some(x)) => i == x,
                (Some(_), None) => false,
            };
            if !rpf_ok {
                let detail = format!(
                    "{} in VRF {vrf}: the reverse path check fails, the incoming interface is {}",
                    r.name(),
                    r.iif
                        .as_ref()
                        .map_or("not known".into(), ToString::to_string)
                );
                let b = if r.source.is_some() && incoming.is_some() {
                    self.meta.drop(m, ReasonCode::Denied, detail, ctx, state)
                } else {
                    self.meta
                        .unknown(m, ReasonCode::IncompleteTable, detail, ctx, state)
                };
                out.push(b.with_spans(r.spans.clone()));
                continue;
            }
            let oifs: Vec<&(InterfaceId, FunctionId)> =
                r.oifs.iter().filter(|(i, _)| Some(i) != incoming).collect();
            if oifs.is_empty() {
                out.push(
                    self.meta
                        .drop(
                            m,
                            ReasonCode::NoRoute,
                            format!("{} in VRF {vrf} has no other outgoing interface", r.name()),
                            ctx,
                            state,
                        )
                        .with_spans(r.spans.clone()),
                );
                continue;
            }
            let set = match (r.group.len(), group_mac(r.group.addr())) {
                (32, Some(mac)) => m.rewrite(&Rewrite {
                    dst_mac: Some(FieldValue::Known(mac)),
                    ..Rewrite::default()
                }),
                _ => m.rewrite(&Rewrite {
                    dst_mac: Some(FieldValue::Unknown),
                    ..Rewrite::default()
                }),
            };
            let count = u32::try_from(oifs.len()).expect("too many interfaces");
            let key = r.name();
            for (k, (oif, next)) in oifs.iter().enumerate() {
                let mut c = ctx.clone();
                c.egress_interface = Attr::Known(oif.clone());
                let mut b = self
                    .meta
                    .forward(
                        set.clone(),
                        next,
                        ReasonCode::Routed,
                        format!("{} in VRF {vrf} copy to {oif}", r.name()),
                        c,
                        state,
                    )
                    .with_spans(r.spans.clone());
                b.flood_copy = Some(FloodCopy {
                    flood: self.meta.id.clone(),
                    key: key.clone(),
                    port: PortId::new(oif.to_string()),
                    index: u32::try_from(k).expect("too many interfaces"),
                    count,
                });
                out.push(b);
            }
        }
        push_nonempty(
            &mut out,
            self.meta.unknown(
                rest,
                ReasonCode::IncompleteTable,
                format!("no collected multicast route in VRF {vrf}"),
                ctx,
                state,
            ),
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_group_mac_has_the_low_23_bits_of_the_group() {
        let m = group_mac("233.252.0.20".parse().unwrap()).unwrap();
        assert_eq!(m, Mac([0x01, 0x00, 0x5e, 0x7c, 0x00, 0x14]));
        assert_eq!(group_mac("ff02::1".parse().unwrap()), None);
    }
}
