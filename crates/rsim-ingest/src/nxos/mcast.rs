//! The multicast routes of an NX-OS switch for the flood of a VXLAN segment
//! to a multicast group of the underlay.

use std::collections::{BTreeMap, BTreeSet};

use rsim_core::{FunctionId, InterfaceId, Mac, SourceSpan, VrfId};
use rsim_functions::{McastRoute, group_mac};

use super::config::Interface;
use super::lower::{DEFAULT_VRF, L};
use super::profile::VXLAN_GUIDE;
use super::state::State;
use super::vxlan::Plan;

/// The multicast routes of a switch.
pub(super) struct Mcast {
    /// The routes of the packets that the switch receives.
    pub received: BTreeMap<VrfId, Vec<McastRoute>>,
    /// The routes of the packets that the tunnel end of the switch sends:
    /// no copy goes back to its own tunnel end.
    pub sent: BTreeMap<VrfId, Vec<McastRoute>>,
    /// Why the routes are not known.
    pub unknown: Option<String>,
    /// The routed interfaces that are an outgoing interface.
    pub oifs: BTreeSet<String>,
    /// The destination MAC of each group with a host prefix.
    pub macs: BTreeSet<Mac>,
}

impl L<'_> {
    /// The multicast routes of the switch, or `None` with no multicast route
    /// section. `vpc` is true on a switch of a lowered vPC domain.
    pub(super) fn mcast(
        &mut self,
        st: &State,
        tunnel: &Plan,
        active: &[Interface],
        vpc: bool,
    ) -> Option<Mcast> {
        let rows = st.mroutes.as_ref()?;
        let mut m = Mcast {
            received: BTreeMap::new(),
            sent: BTreeMap::new(),
            unknown: None,
            oifs: BTreeSet::new(),
            macs: BTreeSet::new(),
        };
        let rows = match rows {
            Ok(r) => r,
            Err(why) => {
                m.unknown = Some(why.clone());
                return Some(m);
            }
        };
        let nve = self.cfg.nve.as_ref().map(|n| n.name.clone());
        let mut sorted: Vec<&super::state::MrouteRow> = rows.iter().collect();
        // The (S,G) routes first, then the longer group prefix first.
        sorted.sort_by_key(|r| (r.source.is_none(), std::cmp::Reverse(r.group.len())));
        // The functions that give `Unknown`, each with its reason and the span
        // of the first route that names it.
        let mut sinks: BTreeMap<String, (String, SourceSpan)> = BTreeMap::new();
        let mut sink = |l: &L, f: String, why: String, span: SourceSpan| -> FunctionId {
            let id = l.id(&f);
            sinks.entry(f).or_insert((why, span));
            id
        };
        for r in sorted {
            if let Some(mac) = group_mac(r.group.addr()).filter(|_| r.group.len() == 32) {
                m.macs.insert(mac);
            }
            let mut received = Vec::new();
            let mut sent = Vec::new();
            for o in &r.oifs {
                let to_nve = nve.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(o));
                let next: FunctionId = if to_nve && r.vrf != DEFAULT_VRF {
                    sink(
                        self,
                        format!("mcast/tenant/{}", r.vrf),
                        format!(
                            "{o}: copy of a route of VRF {} into the tunnel not lowered",
                            r.vrf
                        ),
                        r.span.clone(),
                    )
                } else if to_nve {
                    match tunnel {
                        Plan::Exact(_) if vpc => sink(
                            self,
                            "mcast/vpc".into(),
                            "vPC forwarder of a multicast flood not lowered".into(),
                            SourceSpan::line(VXLAN_GUIDE, 1),
                        ),
                        Plan::None => sink(
                            self,
                            "mcast/nve".into(),
                            format!("{o}: no tunnel end that forwards"),
                            r.span.clone(),
                        ),
                        _ => self.id("vxlan-decap"),
                    }
                } else if active.iter().any(|i| i.name == *o) {
                    m.oifs.insert(o.clone());
                    self.id(&format!("mcast/out/{o}"))
                } else {
                    sink(
                        self,
                        format!("mcast/unknown/{o}"),
                        format!("outgoing interface {o} not lowered"),
                        r.span.clone(),
                    )
                };
                received.push((InterfaceId::new(o), next.clone()));
                if !to_nve {
                    sent.push((InterfaceId::new(o), next));
                }
            }
            let route = |oifs| McastRoute {
                source: r.source,
                group: r.group,
                iif: r.iif.as_deref().map(InterfaceId::new),
                oifs,
                spans: vec![r.span.clone()],
            };
            m.received
                .entry(VrfId::new(&r.vrf))
                .or_default()
                .push(route(received));
            m.sent
                .entry(VrfId::new(&r.vrf))
                .or_default()
                .push(route(sent));
        }
        for (f, (why, span)) in sinks {
            let s = self.sink(&f, why, span);
            self.add(s);
        }
        Some(m)
    }
}
