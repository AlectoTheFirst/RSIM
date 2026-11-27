//! The changes of an OSPFv2 database: an interface cost, an adjacency
//! down, an interface in another area. Each change gives a new database and
//! a flag that is false when the change alters nothing. The database that
//! a change reads stays the same.

use std::net::{IpAddr, Ipv4Addr};

use super::spf::v2_prefix;
use super::{AreaId, Body, Database, LinkKind, Lsa, LsaKey, LsaType, RouterId, RouterLink};

/// True if the interface of a router at `address` gives the link: the
/// interface address is the link data of a point-to-point, transit or
/// virtual link, and the subnet of a stub link holds the address.
fn link_of_interface(link: &RouterLink, address: Ipv4Addr) -> bool {
    if link.kind == LinkKind::Stub {
        v2_prefix(link.id, link.data).is_some_and(|p| p.contains(IpAddr::V4(address)))
    } else {
        link.data == Some(address)
    }
}

fn links(lsa: &Lsa) -> &[RouterLink] {
    match &lsa.body {
        Body::Router { links } => links,
        _ => &[],
    }
}

fn with_links(lsa: &Lsa, links: Vec<RouterLink>) -> Lsa {
    Lsa {
        body: Body::Router { links },
        ..lsa.clone()
    }
}

fn router_key(area: AreaId, router: RouterId) -> LsaKey {
    LsaKey {
        no_area: false,
        area,
        lsa_type: LsaType::Router,
        lsid: router,
        adv_router: router,
    }
}

/// The stub link that a router advertises for a segment on which it has
/// no adjacency (RFC 2328 12.4.1.2), in place of its transit link to the
/// network.
fn restubbed(links: &[RouterLink], net: &Lsa) -> Vec<RouterLink> {
    let mask = match &net.body {
        Body::Network { mask, .. } => *mask,
        _ => None,
    };
    links
        .iter()
        .filter_map(|l| {
            if l.kind == LinkKind::Transit && l.id == net.lsid {
                let p = v2_prefix(net.lsid, mask)?;
                let IpAddr::V4(id) = p.addr() else {
                    return None;
                };
                Some(RouterLink {
                    kind: LinkKind::Stub,
                    id,
                    data: mask,
                    metric: l.metric,
                    interface_id: None,
                    neighbor_interface_id: None,
                })
            } else {
                Some(l.clone())
            }
        })
        .collect()
}

impl Database {
    fn router_lsas(&self, router: RouterId) -> Vec<Lsa> {
        self.lsas
            .values()
            .filter(|l| l.lsa_type == LsaType::Router && l.adv_router == router)
            .cloned()
            .collect()
    }

    /// The database in which the links that `router` originates from its
    /// interface at `address` have the metric `cost`: the point-to-point,
    /// transit or virtual link of the interface and the stub link of its
    /// subnet, in each area.
    pub fn with_interface_cost(
        &self,
        router: RouterId,
        address: Ipv4Addr,
        cost: u32,
    ) -> (Database, bool) {
        let mut new = self.clone();
        let mut changed = false;
        for lsa in self.router_lsas(router) {
            if !links(&lsa).iter().any(|l| link_of_interface(l, address)) {
                continue;
            }
            changed = true;
            let links = links(&lsa)
                .iter()
                .map(|l| {
                    let mut l = l.clone();
                    if link_of_interface(&l, address) {
                        l.metric = cost;
                    }
                    l
                })
                .collect();
            new.lsas.insert(lsa.key(), with_links(&lsa, links));
        }
        (new, changed)
    }

    /// The database with no adjacency between 2 routers. Over a
    /// point-to-point or virtual link, each end drops its link to the other
    /// and keeps the stub link of the subnet. On a transit network, the
    /// router that is not the designated router leaves the network LSA and
    /// advertises the segment as a stub link (RFC 2328 12.4.1.2). A
    /// designated router with no adjacent neighbour left withdraws the
    /// network LSA and advertises the segment as a stub link (12.4.2). A
    /// transit network on which neither router is the designated router
    /// stays the same.
    pub fn without_adjacency(&self, a: RouterId, b: RouterId) -> (Database, bool) {
        let mut new = self.clone();
        let mut changed = false;
        for area in self.areas() {
            let (Some(la), Some(lb)) = (
                self.lsas.get(&router_key(area, a)),
                self.lsas.get(&router_key(area, b)),
            ) else {
                continue;
            };
            for (lsa, other) in [(la, b), (lb, a)] {
                let kept: Vec<RouterLink> = links(lsa)
                    .iter()
                    .filter(|l| {
                        !(matches!(l.kind, LinkKind::PointToPoint | LinkKind::Virtual)
                            && l.id == other)
                    })
                    .cloned()
                    .collect();
                if kept.len() != links(lsa).len() {
                    new.lsas.insert(lsa.key(), with_links(lsa, kept));
                    changed = true;
                }
            }
            let nets: Vec<Lsa> = self
                .lsas
                .values()
                .filter(|l| l.lsa_type == LsaType::Network && l.area == Some(area))
                .cloned()
                .collect();
            for net in nets {
                let Body::Network { attached, .. } = &net.body else {
                    continue;
                };
                if !attached.contains(&a) || !attached.contains(&b) {
                    continue;
                }
                let leaving = if net.adv_router == a {
                    b
                } else if net.adv_router == b {
                    a
                } else {
                    continue;
                };
                new.detach(&net, area, leaving);
                changed = true;
            }
        }
        (new, changed)
    }

    /// Detaches `leaving` from the network LSA `net` in this database.
    fn detach(&mut self, net: &Lsa, area: AreaId, leaving: RouterId) {
        if let Some(leaver) = self.lsas.get(&router_key(area, leaving)).cloned() {
            let links = restubbed(links(&leaver), net);
            self.lsas.insert(leaver.key(), with_links(&leaver, links));
        }
        let Body::Network { mask, attached } = &net.body else {
            return;
        };
        let remaining: Vec<RouterId> = attached.iter().copied().filter(|r| *r != leaving).collect();
        if remaining.len() >= 2 {
            let kept = Lsa {
                body: Body::Network {
                    mask: *mask,
                    attached: remaining,
                },
                ..net.clone()
            };
            self.lsas.insert(net.key(), kept);
            return;
        }
        self.lsas.remove(&net.key());
        if let Some(dr) = self.lsas.get(&router_key(area, net.adv_router)).cloned() {
            let links = restubbed(links(&dr), net);
            self.lsas.insert(dr.key(), with_links(&dr, links));
        }
    }

    /// The database in which the interface at `address` of `router` is in
    /// `area`. The links of the interface move from the router LSA of their
    /// area to the router LSA of `area`, which the change makes when the
    /// router has none there. A router LSA with no link left is removed. A
    /// network LSA that the router originates for the segment moves with the
    /// links. Each far end of the segment moves with its own change.
    pub fn with_interface_in_area(
        &self,
        router: RouterId,
        address: Ipv4Addr,
        area: AreaId,
    ) -> (Database, bool) {
        let mut new = self.clone();
        let mut moved: Vec<RouterLink> = Vec::new();
        let mut template: Option<Lsa> = None;
        for lsa in self.router_lsas(router) {
            if lsa.area == Some(area) {
                continue;
            }
            let (taken, stay): (Vec<RouterLink>, Vec<RouterLink>) = links(&lsa)
                .iter()
                .cloned()
                .partition(|l| link_of_interface(l, address));
            if taken.is_empty() {
                continue;
            }
            moved.extend(taken);
            if stay.is_empty() {
                new.lsas.remove(&lsa.key());
            } else {
                new.lsas.insert(lsa.key(), with_links(&lsa, stay));
            }
            let nets: Vec<Lsa> = self
                .lsas
                .values()
                .filter(|l| {
                    l.lsa_type == LsaType::Network
                        && l.area == lsa.area
                        && l.lsid == address
                        && l.adv_router == router
                })
                .cloned()
                .collect();
            for net in nets {
                new.lsas.remove(&net.key());
                let relocated = Lsa {
                    area: Some(area),
                    ..net
                };
                new.lsas.insert(relocated.key(), relocated);
            }
            template.get_or_insert(lsa);
        }
        let Some(template) = template else {
            return (new, false);
        };
        let target = new
            .lsas
            .get(&router_key(area, router))
            .cloned()
            .unwrap_or_else(|| Lsa {
                area: Some(area),
                body: Body::Router { links: Vec::new() },
                ..template
            });
        let mut all = links(&target).to_vec();
        all.extend(moved);
        new.lsas
            .insert(router_key(area, router), with_links(&target, all));
        (new, true)
    }
}
