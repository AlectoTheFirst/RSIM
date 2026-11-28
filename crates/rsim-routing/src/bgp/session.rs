//! The sessions between processes and the transfer of a path over one
//! session: the export of the sender and the receipt of the receiver.
//!
//! The export of a best path `best` to the neighbour `n`:
//! - The path is not sent back to the peer that it came from.
//! - A path with NO_ADVERTISE is not sent. A path with NO_EXPORT is not
//!   sent to an eBGP peer. A path with NO_EXPORT_SUBCONFED is not sent to
//!   an eBGP or a confederation eBGP peer (RFC 1997).
//! - A path from an iBGP peer goes to an iBGP peer only when one of the 2
//!   peers is a route-reflector client. The reflected path gets the
//!   ORIGINATOR_ID of the iBGP peer that it came from, if it has none, and
//!   the cluster ID of the sender before its CLUSTER_LIST (RFC 4456 8).
//! - The weight is 0 on each session. To an eBGP peer, the local
//!   preference, the ORIGINATOR_ID and the CLUSTER_LIST are removed, and
//!   the MED of a path that the sender does not originate is removed
//!   (RFC 4271 5.1.4). To an iBGP or a confederation eBGP peer, a path with
//!   no local preference gets the default local preference of the sender.
//! - The export policy of the neighbour runs on this path.
//! - To an eBGP peer, the confederation segments are removed and the
//!   confederation ID, or else the AS of the sender, is prepended. A
//!   `local-as` prepends the local AS, and the AS of the sender after it
//!   unless `replace-as` is set. The next hop becomes the local address of
//!   the session.
//! - To a confederation eBGP peer, the member AS of the sender is prepended
//!   in an AS_CONFED_SEQUENCE (RFC 5065). The next hop becomes the local
//!   address of the session for a local path and with `next-hop-self` or
//!   `next-hop-self all`.
//! - To an iBGP peer, the next hop becomes the local address of the session
//!   for a local path, with `next-hop-self all`, and with `next-hop-self`
//!   for a path that is not reflected.
//! - A next hop that a set action of the export policy sets is kept.
//! - Without `send_community` the standard and the large communities are
//!   removed. Without `send_community_extended` the extended communities
//!   are removed. The fields hold the effective settings of the platform.
//! - The sent path has the sender as its peer, the IGP cost 0, no tag and no
//!   leak.
//!
//! The receipt of a path from the neighbour `n`:
//! - An eBGP path whose AS path holds the AS, the confederation ID or the
//!   `local-as` of the receiver is rejected. A confederation eBGP path
//!   whose AS path holds the member AS of the receiver is rejected.
//! - A path whose ORIGINATOR_ID is the router ID of the receiver, or whose
//!   CLUSTER_LIST holds the cluster ID of the receiver, is rejected.
//! - The path gets the peer of the session and the weight 0. An eBGP path
//!   loses its local preference and, with a `local-as` with no
//!   `no-prepend`, gets the local AS prepended.
//! - The import policy of the neighbour runs on this path.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use super::policy::{
    Direction, PolicyResult, neighbor_policy, neighbor_policy_next_hop, policy_reads,
};
use super::process::{BgpProcess, Neighbor, NextHopSelf};
use super::stage::{ObjectRef, RoutingStage};
use super::{BgpPath, Community, Peer, Reason, RouteKey, SessionKind, Unknown};

/// One end of a session: the process and the address of the neighbour in
/// the neighbours of that process.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionEnd {
    pub device: String,
    pub vrf: String,
    pub neighbor: IpAddr,
}

/// A session between 2 processes of the twin. The neighbour address of
/// one end is the local address of the other end.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Session {
    pub a: SessionEnd,
    pub b: SessionEnd,
}

/// The result of a transfer step on a path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Offer {
    /// The step does not send the path, rejects it or denies it.
    None,
    Path(BgpPath),
    Unknown(Unknown),
}

fn families_carry(process: &BgpProcess, n: &Neighbor, key: &RouteKey) -> Result<bool, Unknown> {
    match process.families(n) {
        Some(f) => Ok(f.contains(&key.family)),
        None => Err(Unknown::new(
            Reason::AddressFamilyNotKnown,
            format!(
                "neighbor {} at {} {}",
                n.address, process.device, process.vrf
            ),
        )),
    }
}

fn policy_offer(r: PolicyResult) -> Offer {
    match r {
        PolicyResult::Permit(p) => Offer::Path(p),
        PolicyResult::Deny => Offer::None,
        PolicyResult::Unknown(u) => Offer::Unknown(u),
    }
}

/// The path that `sender` sends to its neighbour `neighbor` for the best
/// path `best` of `key`. `local_address` is the address of the sender on
/// the session.
pub fn export(
    sender: &BgpProcess,
    neighbor: &Neighbor,
    local_address: IpAddr,
    key: &RouteKey,
    best: &BgpPath,
) -> Offer {
    let Some(profile) = sender.profile() else {
        return Offer::Unknown(Unknown::new(Reason::NoBgpProfile, sender.device.clone()));
    };
    if neighbor.shutdown || best.peer.address == Some(neighbor.address) {
        return Offer::None;
    }
    match families_carry(sender, neighbor, key) {
        Ok(true) => {}
        Ok(false) => return Offer::None,
        Err(u) => return Offer::Unknown(u),
    }
    let out = sender.session_kind(neighbor);
    let has = |c: Community| best.communities.contains(&c);
    if has(Community::NO_ADVERTISE)
        || (has(Community::NO_EXPORT) && out == SessionKind::Ebgp)
        || (has(Community::NO_EXPORT_SUBCONFED)
            && matches!(out, SessionKind::Ebgp | SessionKind::ConfedEbgp))
    {
        return Offer::None;
    }
    let reflect = out == SessionKind::Ibgp && best.peer.kind == SessionKind::Ibgp;
    if reflect {
        let from_client = best
            .peer
            .address
            .and_then(|a| sender.neighbors.get(&a))
            .is_some_and(|n| n.route_reflector_client);
        if !from_client && !neighbor.route_reflector_client {
            return Offer::None;
        }
    }
    let local = matches!(best.peer.kind, SessionKind::Local(_));
    let mut p = best.clone();
    p.weight = 0;
    match out {
        SessionKind::Ebgp => {
            p.local_pref = None;
            p.originator_id = None;
            p.cluster_list.clear();
            if !local {
                p.med = None;
            }
        }
        _ => {
            if p.local_pref.is_none() {
                p.local_pref = Some(profile.default_local_pref(&sender.options));
            }
        }
    }
    // The reflected path needs a known ORIGINATOR_ID and cluster ID.
    let mut id_unknown = None;
    if reflect {
        if p.originator_id.is_none() {
            p.originator_id = best.peer.router_id;
            if p.originator_id.is_none() {
                id_unknown = Some(format!(
                    "originator id of the path from {} at {}",
                    best.peer
                        .address
                        .map_or_else(|| "the device".to_string(), |a| a.to_string()),
                    sender.device
                ));
            }
        }
        match sender.cluster_id() {
            Some(c) => p.cluster_list.insert(0, c),
            None => id_unknown = Some(format!("cluster id of {}", sender.device)),
        }
    }
    let (result, next_hop_set) =
        neighbor_policy_next_hop(sender, neighbor, Direction::Export, key, &p, Some(&profile));
    let mut q = match result {
        PolicyResult::Permit(q) => q,
        PolicyResult::Deny => return Offer::None,
        PolicyResult::Unknown(u) => return Offer::Unknown(u),
    };
    if let Some(why) = id_unknown {
        return Offer::Unknown(Unknown::new(Reason::RouterIdNotKnown, why));
    }
    match out {
        SessionKind::Ebgp => {
            let own = sender.confederation_id.unwrap_or(sender.asn);
            let path = q.as_path.without_confed();
            q.as_path = match neighbor.local_as {
                None => path.prepend(&[own]),
                Some(l) if l.replace_as => path.prepend(&[l.asn]),
                Some(l) => path.prepend(&[l.asn, own]),
            };
            if !next_hop_set {
                q.next_hop = Some(local_address);
            }
        }
        SessionKind::ConfedEbgp => {
            q.as_path = q.as_path.prepend_confed(sender.asn);
            let self_hop = q.next_hop.is_none() || neighbor.next_hop_self != NextHopSelf::Off;
            if self_hop && !next_hop_set {
                q.next_hop = Some(local_address);
            }
        }
        _ => {
            let self_hop = q.next_hop.is_none()
                || neighbor.next_hop_self == NextHopSelf::All
                || (neighbor.next_hop_self == NextHopSelf::On && !reflect);
            if self_hop && !next_hop_set {
                q.next_hop = Some(local_address);
            }
        }
    }
    if !neighbor.send_community {
        q.communities.clear();
        q.large_communities.clear();
    }
    if !neighbor.send_community_extended {
        q.ext_communities.clear();
    }
    q.peer = Peer {
        address: Some(local_address),
        router_id: sender.router_id,
        asn: sender.asn,
        kind: out,
    };
    q.igp_cost = 0;
    q.tag = None;
    q.leaked = None;
    Offer::Path(q)
}

/// The path that `receiver` accepts from its neighbour `neighbor` for the
/// sent path `sent` of `key`. `sender_router_id` is the router ID of the
/// sender, `None` when it is not known. An ORIGINATOR_ID or a CLUSTER_LIST
/// loop check that needs a router ID or a cluster ID of the receiver that
/// is not known gives `Unknown` for a path that the import policy permits.
pub fn receive(
    receiver: &BgpProcess,
    neighbor: &Neighbor,
    sender_router_id: Option<Ipv4Addr>,
    key: &RouteKey,
    sent: &BgpPath,
) -> Offer {
    let Some(profile) = receiver.profile() else {
        return Offer::Unknown(Unknown::new(Reason::NoBgpProfile, receiver.device.clone()));
    };
    if neighbor.shutdown {
        return Offer::None;
    }
    match families_carry(receiver, neighbor, key) {
        Ok(true) => {}
        Ok(false) => return Offer::None,
        Err(u) => return Offer::Unknown(u),
    }
    let kind = receiver.session_kind(neighbor);
    let path = &sent.as_path;
    let looped = match kind {
        SessionKind::Ebgp => {
            path.contains(receiver.asn)
                || receiver.confederation_id.is_some_and(|c| path.contains(c))
                || neighbor.local_as.is_some_and(|l| path.contains(l.asn))
        }
        SessionKind::ConfedEbgp => path.contains(receiver.asn),
        _ => false,
    };
    let mut id_unknown = None;
    let originator_loop = match (sent.originator_id, receiver.router_id) {
        (Some(o), Some(r)) => o == r,
        (Some(_), None) => {
            id_unknown = Some(format!("router id of {}", receiver.device));
            false
        }
        (None, _) => false,
    };
    let cluster_loop = match receiver.cluster_id() {
        Some(c) => sent.cluster_list.contains(&c),
        None if !sent.cluster_list.is_empty() => {
            id_unknown = Some(format!("cluster id of {}", receiver.device));
            false
        }
        None => false,
    };
    if looped || originator_loop || cluster_loop {
        return Offer::None;
    }
    let mut p = sent.clone();
    p.weight = 0;
    p.igp_cost = 0;
    p.tag = None;
    if kind == SessionKind::Ebgp {
        p.local_pref = None;
        if let Some(l) = neighbor.local_as.filter(|l| !l.no_prepend) {
            p.as_path = p.as_path.prepend(&[l.asn]);
        }
    }
    p.peer = Peer {
        address: Some(neighbor.address),
        router_id: sender_router_id,
        asn: neighbor.remote_as,
        kind,
    };
    let offer = policy_offer(neighbor_policy(
        receiver,
        neighbor,
        Direction::Import,
        key,
        &p,
        Some(&profile),
    ));
    match (offer, id_unknown) {
        (Offer::Path(_), Some(why)) => Offer::Unknown(Unknown::new(Reason::RouterIdNotKnown, why)),
        (offer, _) => offer,
    }
}

/// The transfer stage of one direction of a session: the export of the end
/// `a` of `session` at `sender` and the receipt of the end `b` at
/// `receiver`.
pub struct SessionStage<'a> {
    pub sender: &'a BgpProcess,
    pub receiver: &'a BgpProcess,
    pub session: &'a Session,
}

impl SessionStage<'_> {
    fn end_reads(p: &BgpProcess, out: &mut BTreeSet<ObjectRef>) {
        out.insert(ObjectRef::Profile(p.platform));
        out.insert(ObjectRef::Process {
            device: p.device.clone(),
            vrf: p.vrf.clone(),
        });
    }
}

impl RoutingStage for SessionStage<'_> {
    /// The key and the best path of the sender.
    type Input = (RouteKey, BgpPath);
    /// The sent path and the accepted path.
    type Output = (Offer, Offer);

    fn name(&self) -> &'static str {
        "bgp session"
    }

    /// The profiles and the processes of both ends, each neighbour of the
    /// sender, the neighbour of the receiver, and the export and the import
    /// policy with the policies and the lists that they use.
    fn reads(&self) -> BTreeSet<ObjectRef> {
        let (s, r) = (self.sender, self.receiver);
        let mut out = BTreeSet::new();
        Self::end_reads(s, &mut out);
        Self::end_reads(r, &mut out);
        for a in s.neighbors.keys() {
            out.insert(ObjectRef::Neighbor {
                device: s.device.clone(),
                vrf: s.vrf.clone(),
                address: *a,
            });
        }
        out.insert(ObjectRef::Neighbor {
            device: r.device.clone(),
            vrf: r.vrf.clone(),
            address: self.session.b.neighbor,
        });
        if let Some(name) = s
            .neighbors
            .get(&self.session.a.neighbor)
            .and_then(|n| n.export_policy.as_ref())
        {
            policy_reads(&s.policy, name, &s.device, &s.vrf, &mut out);
        }
        if let Some(name) = r
            .neighbors
            .get(&self.session.b.neighbor)
            .and_then(|n| n.import_policy.as_ref())
        {
            policy_reads(&r.policy, name, &r.device, &r.vrf, &mut out);
        }
        out
    }

    /// A neighbour that a process does not hold sends or accepts nothing.
    fn run(&self, input: &(RouteKey, BgpPath)) -> (Offer, Offer) {
        let (key, best) = input;
        let (Some(ns), Some(nr)) = (
            self.sender.neighbors.get(&self.session.a.neighbor),
            self.receiver.neighbors.get(&self.session.b.neighbor),
        ) else {
            return (Offer::None, Offer::None);
        };
        let sent = export(self.sender, ns, self.session.b.neighbor, key, best);
        let accepted = match &sent {
            Offer::Path(p) => receive(self.receiver, nr, self.sender.router_id, key, p),
            other => other.clone(),
        };
        (sent, accepted)
    }
}
