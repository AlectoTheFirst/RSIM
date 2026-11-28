//! The transfers of a path between the processes of one device.
//!
//! - With `advertise l2vpn evpn`, the unicast selection of a VRF is an EVPN
//!   IP prefix route (RFC 9136) of the process of the default VRF with the
//!   route distinguisher of the VRF. The path is a local path with the
//!   attributes of the selection, the local weight, the EVPN export route
//!   targets of the VRF and the address of the tunnel end as its next hop.
//!   A selection from an EVPN import or a VRF leak is not advertised.
//! - A VRF imports an EVPN IP prefix route of the process of the default VRF
//!   whose route targets hold an EVPN import route target of the VRF. A
//!   local path of the default VRF is not imported. The imported path keeps
//!   its attributes, and its next hop resolves in the default VRF.
//! - A VRF imports the unicast selection of another VRF of the device when
//!   an export route target of that VRF is an import route target of the
//!   importing VRF. The leaked path has the weight 0 and the export route
//!   targets, as in HST `simul/rib.py`, and its next hop resolves in the
//!   exporting VRF. A leaked path is not leaked again.

use std::collections::BTreeSet;

use super::process::BgpProcess;
use super::session::Offer;
use super::stage::{ObjectRef, RoutingStage};
use super::{
    BgpPath, DEFAULT_VRF, ExtCommunity, Leaked, LocalOrigin, Peer, Reason, RouteKey, SessionKind,
    Unknown,
};

/// The EVPN IP prefix path at the process `default` of the default VRF for
/// the best path `best` of the process `vrf` of the same device.
pub fn evpn_export(vrf: &BgpProcess, default: &BgpProcess, best: &BgpPath) -> Offer {
    if best.leaked.is_some() || !vrf.targets.advertise_evpn || vrf.targets.rd.is_none() {
        return Offer::None;
    }
    let Some(profile) = default.profile() else {
        return Offer::Unknown(Unknown::new(Reason::NoBgpProfile, default.device.clone()));
    };
    let Some(next_hop) = vrf.targets.evpn_next_hop else {
        return Offer::Unknown(Unknown::new(
            Reason::TunnelEndNotKnown,
            format!("vrf {} at {}", vrf.vrf, vrf.device),
        ));
    };
    let mut p = best.clone();
    p.peer = Peer {
        address: None,
        router_id: default.router_id,
        asn: default.asn,
        kind: SessionKind::Local(LocalOrigin::Redistribute),
    };
    p.next_hop = Some(next_hop);
    p.weight = profile.local_weight;
    p.igp_cost = 0;
    p.tag = None;
    p.originator_id = None;
    p.cluster_list.clear();
    p.ext_communities.extend(
        vrf.targets
            .evpn_export
            .iter()
            .map(|t| ExtCommunity::RouteTarget(*t)),
    );
    p.spans.extend(vrf.targets.spans.iter().cloned());
    Offer::Path(p)
}

/// The path that the process `vrf` imports for the best path `best` of an
/// EVPN IP prefix route of the process of the default VRF of its device.
pub fn evpn_import(vrf: &BgpProcess, best: &BgpPath) -> Offer {
    if vrf.vrf == DEFAULT_VRF || matches!(best.peer.kind, SessionKind::Local(_)) {
        return Offer::None;
    }
    if !best
        .route_targets()
        .any(|t| vrf.targets.evpn_import.contains(&t))
    {
        return Offer::None;
    }
    let mut p = best.clone();
    p.leaked = Some(Leaked {
        vrf: DEFAULT_VRF.to_string(),
        evpn: true,
    });
    p.spans.extend(vrf.targets.spans.iter().cloned());
    Offer::Path(p)
}

/// The path that the process `to` imports for the best path `best` of the
/// process `from` of another VRF of the same device.
pub fn vrf_leak(from: &BgpProcess, to: &BgpProcess, best: &BgpPath) -> Offer {
    if best.leaked.is_some()
        || from.vrf == to.vrf
        || from.targets.export.is_disjoint(&to.targets.import)
    {
        return Offer::None;
    }
    let mut p = best.clone();
    p.weight = 0;
    p.ext_communities.extend(
        from.targets
            .export
            .iter()
            .map(|t| ExtCommunity::RouteTarget(*t)),
    );
    p.leaked = Some(Leaked {
        vrf: from.vrf.clone(),
        evpn: false,
    });
    p.spans.extend(to.targets.spans.iter().cloned());
    Offer::Path(p)
}

/// The form of a transfer between 2 processes of one device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeakKind {
    /// A VRF selection to an EVPN IP prefix route of the default VRF.
    EvpnExport,
    /// An EVPN IP prefix route of the default VRF to a VRF.
    EvpnImport,
    /// A VRF selection to another VRF by the route targets.
    Vrf,
}

/// The stage of one transfer between 2 processes of one device for one
/// route.
pub struct LeakStage<'a> {
    pub from: &'a BgpProcess,
    pub to: &'a BgpProcess,
    pub kind: LeakKind,
    /// The key of the route at `from`.
    pub key: RouteKey,
}

impl RoutingStage for LeakStage<'_> {
    type Input = BgpPath;
    type Output = Offer;

    fn name(&self) -> &'static str {
        match self.kind {
            LeakKind::EvpnExport => "bgp evpn export",
            LeakKind::EvpnImport => "bgp evpn import",
            LeakKind::Vrf => "bgp vrf leak",
        }
    }

    /// The profile and the process of both ends.
    fn reads(&self) -> BTreeSet<ObjectRef> {
        let mut out = BTreeSet::new();
        for p in [self.from, self.to] {
            out.insert(ObjectRef::Profile(p.platform));
            out.insert(ObjectRef::Process {
                device: p.device.clone(),
                vrf: p.vrf.clone(),
            });
        }
        out
    }

    fn run(&self, best: &BgpPath) -> Offer {
        match self.kind {
            LeakKind::EvpnExport => evpn_export(self.from, self.to, best),
            LeakKind::EvpnImport => evpn_import(self.to, best),
            LeakKind::Vrf => vrf_leak(self.from, self.to, best),
        }
    }
}
