//! The topology of a loaded twin, and the drawing of the paths of an
//! answer.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use rsim_contract::args::TopologyViewArgs;
use rsim_contract::claim;
use rsim_contract::topology::{TopoEdge, TopoNode, TopologyOut};
use rsim_core::FunctionKind;
use rsim_engine::Answer;
use rsim_functions::{
    Egress, LinkFacts, PortEgress, TunnelPeer, VxlanEncap, WireguardEncap, WireguardPeer,
};
use serde_json::{Value, json};

use crate::claims::speed_duplex;
use crate::commands::Loaded;
use crate::error::{ErrorCode, QueryError};
use crate::json::{VERSION, snake};

/// The largest number of nodes of one response.
pub const MAX_NODES: usize = 2000;

fn invalid(d: String) -> QueryError {
    QueryError::new(ErrorCode::InvalidFilter, d)
}

/// The links of the twin: the device of each end, the subject and the
/// link facts.
fn links(t: &Loaded) -> Vec<(String, String, String, Option<&LinkFacts>)> {
    let device_of = |f: &rsim_core::FunctionId| {
        t.function(f)
            .and_then(|x| x.device())
            .map(ToString::to_string)
    };
    let mut out = Vec::new();
    for f in t.functions() {
        let Some(d) = f.device().map(ToString::to_string) else {
            continue;
        };
        let any: &dyn Any = f.as_ref();
        let peers: Vec<(&rsim_core::FunctionId, Option<&LinkFacts>)> =
            if let Some(e) = any.downcast_ref::<Egress>() {
                e.link
                    .iter()
                    .filter_map(|l| Some((l.peer.as_ref()?, l.facts.as_ref())))
                    .collect()
            } else if let Some(p) = any.downcast_ref::<PortEgress>() {
                p.peers
                    .iter()
                    .map(|x| (&x.target, x.link.as_ref()))
                    .collect()
            } else {
                Vec::new()
            };
        for (peer, facts) in peers {
            if let Some(pd) = device_of(peer)
                && pd != d
            {
                out.push((d.clone(), pd, format!("{} to {peer}", f.id()), facts));
            }
        }
    }
    out
}

fn device_nodes(t: &Loaded) -> BTreeMap<String, TopoNode> {
    let mut count: BTreeMap<String, usize> = BTreeMap::new();
    for f in t.functions() {
        if let Some(d) = f.device() {
            *count.entry(d.to_string()).or_default() += 1;
        }
    }
    t.devices()
        .iter()
        .map(|d| {
            let id = d.to_string();
            (
                id.clone(),
                TopoNode {
                    id: id.clone(),
                    kind: "device".into(),
                    label: id.clone(),
                    device: Some(id.clone()),
                    functions: count.get(&id).copied(),
                },
            )
        })
        .collect()
}

fn edge(id: String, layer: &str, from: String, to: String) -> TopoEdge {
    TopoEdge {
        id,
        layer: layer.into(),
        from,
        to,
        facts: Value::Null,
        provenance: Vec::new(),
        claims: BTreeMap::new(),
        branches: Vec::new(),
        overlay: None,
    }
}

/// The physical edges between devices: one edge for each pair of devices,
/// with the links between them.
fn physical(t: &Loaded, want_claim: bool) -> Vec<TopoEdge> {
    let mut by_pair: BTreeMap<(String, String), Vec<rsim_contract::claim::Evidence>> =
        BTreeMap::new();
    for (a, b, subject, facts) in links(t) {
        let key = if a <= b { (a, b) } else { (b, a) };
        by_pair
            .entry(key)
            .or_default()
            .push(speed_duplex(subject, facts));
    }
    by_pair
        .into_iter()
        .map(|((a, b), ev)| {
            let mut e = edge(format!("physical:{a}|{b}"), "physical", a, b);
            e.facts = json!({
                "links": ev.iter().map(|x| json!({
                    "link": x.subject,
                    "local": x.expected,
                    "remote": x.observed
                })).collect::<Vec<_>>()
            });
            e.provenance = ev.iter().flat_map(|x| x.provenance.clone()).collect();
            if want_claim {
                e.claims
                    .insert("link-speed-duplex".into(), claim::combine(&ev).0);
            }
            e
        })
        .collect()
}

/// The node of a WireGuard peer outside the twin: `peer:<endpoint address>`,
/// or `peer:<device>/<interface>/<peer>` for a peer with no endpoint.
fn peer_node_id(device: &str, w: &WireguardEncap, p: &WireguardPeer) -> String {
    match p.endpoint {
        Some((a, _)) => format!("peer:{a}"),
        None => format!("peer:{device}/{}/{}", w.interface, p.name),
    }
}

/// The devices of the twin whose WireGuard source address is the endpoint
/// of a peer, other than `device`.
fn wireguard_far(
    ends: &BTreeMap<std::net::IpAddr, BTreeSet<String>>,
    device: &str,
    p: &WireguardPeer,
) -> Vec<String> {
    p.endpoint
        .and_then(|(a, _)| ends.get(&a))
        .into_iter()
        .flatten()
        .filter(|d| *d != device)
        .cloned()
        .collect()
}

/// The tunnel edges: from each device with a VXLAN encapsulation to each
/// device whose tunnel end is the peer, and from each device with a
/// WireGuard interface to each peer: the device of the twin whose WireGuard
/// source address is the endpoint of the peer, else a node `peer` outside
/// the twin. The nodes of the peers outside the twin come with the edges.
fn overlay(t: &Loaded) -> (Vec<TopoEdge>, BTreeMap<String, TopoNode>) {
    let mut ends: BTreeMap<std::net::IpAddr, BTreeSet<String>> = BTreeMap::new();
    let mut encaps = Vec::new();
    let wg_ends = wireguard_ends(t);
    let mut wgs: Vec<(String, String, &WireguardEncap)> = Vec::new();
    // The gateways of the route next hops that go to each function: the
    // peers of an encapsulation that takes its peer from the next hop.
    let mut gateways: BTreeMap<String, BTreeSet<std::net::IpAddr>> = BTreeMap::new();
    for f in t.functions() {
        let any: &dyn Any = f.as_ref();
        if let Some(e) = any.downcast_ref::<VxlanEncap>()
            && let Some(d) = f.device()
        {
            ends.entry(e.source).or_default().insert(d.to_string());
            encaps.push((d.to_string(), f.id().to_string(), e));
        }
        if let Some(w) = any.downcast_ref::<WireguardEncap>()
            && let Some(d) = f.device()
        {
            wgs.push((d.to_string(), f.id().to_string(), w));
        }
        if let Some(rl) = any.downcast_ref::<rsim_functions::RouteLookup>() {
            for fib in rl.tables.values() {
                for (_, route) in fib.entries() {
                    for nh in route.next_hops() {
                        if let Some(g) = nh.gateway {
                            gateways.entry(nh.next.to_string()).or_default().insert(g);
                        }
                    }
                }
            }
        }
    }
    let mut out: BTreeMap<String, TopoEdge> = BTreeMap::new();
    // The tunnels of each edge, keyed by the encapsulation function and the
    // peer address, so each edge lists each tunnel once and in order.
    let mut tunnels: BTreeMap<String, BTreeMap<(String, String), serde_json::Value>> =
        BTreeMap::new();
    let pairs = encaps.iter().flat_map(|(d, id, e)| {
        let peers: Vec<std::net::IpAddr> = match e.peer {
            TunnelPeer::Fixed(p) => vec![p],
            TunnelPeer::NextHop => gateways.get(id).into_iter().flatten().copied().collect(),
        };
        peers
            .into_iter()
            .map(move |p| (d.clone(), id.clone(), *e, p))
    });
    for (d, encap, e, peer) in pairs {
        for pd in ends.get(&peer).into_iter().flatten() {
            if *pd == d {
                continue;
            }
            let id = format!("overlay:{d}>{pd}");
            out.entry(id.clone())
                .or_insert_with(|| edge(id.clone(), "overlay", d.clone(), pd.clone()));
            let vnis: BTreeSet<u32> = e.vnis.values().copied().collect();
            let mode = match e.peer {
                TunnelPeer::Fixed(_) => "fixed",
                TunnelPeer::NextHop => "next-hop",
            };
            tunnels.entry(id).or_default().insert(
                (encap.clone(), peer.to_string()),
                json!({
                    "encap": encap,
                    "peer_from": mode,
                    "source": e.source.to_string(),
                    "peer": peer.to_string(),
                    "vnis": vnis,
                }),
            );
        }
    }
    let mut peers: BTreeMap<String, TopoNode> = BTreeMap::new();
    for (d, encap, w) in &wgs {
        for p in w.peers() {
            let far = wireguard_far(&wg_ends, d, p);
            let targets = if far.is_empty() {
                let id = peer_node_id(d, w, p);
                peers.entry(id.clone()).or_insert_with(|| TopoNode {
                    id: id.clone(),
                    kind: "peer".into(),
                    label: p.name.clone(),
                    device: None,
                    functions: None,
                });
                vec![id]
            } else {
                far
            };
            for to in targets {
                let id = format!("overlay:{d}>{to}");
                out.entry(id.clone())
                    .or_insert_with(|| edge(id.clone(), "overlay", d.clone(), to.clone()));
                tunnels.entry(id).or_default().insert(
                    (encap.clone(), p.name.clone()),
                    json!({
                        "encap": encap,
                        "peer_from": "fixed",
                        "name": p.name,
                        "source": p.source.as_ref().ok().map(ToString::to_string),
                        "peer": p.endpoint.map(|(a, _)| a.to_string()),
                        "port": p.endpoint.map(|(_, port)| port),
                        "vnis": [],
                    }),
                );
            }
        }
    }
    for (id, x) in &mut out {
        let list: Vec<serde_json::Value> = tunnels
            .remove(id)
            .map(|m| m.into_values().collect())
            .unwrap_or_default();
        x.facts = json!({ "tunnels": list });
    }
    (out.into_values().collect(), peers)
}

/// The WireGuard peer of an encapsulation step: the peer of the function
/// whose spans are the deciding spans of the step, and the node of the
/// peer, a device of the twin or a node `peer`.
fn wireguard_step(
    t: &Loaded,
    ends: &BTreeMap<std::net::IpAddr, BTreeSet<String>>,
    s: &rsim_core::TraceStep,
) -> Option<(String, Option<TopoNode>)> {
    let f = t.function(&s.function)?;
    let any: &dyn Any = f.as_ref();
    let w = any.downcast_ref::<WireguardEncap>()?;
    let d = f.device()?.to_string();
    let p = w
        .peers()
        .iter()
        .find(|p| !p.spans.is_empty() && p.spans.iter().all(|x| s.provenance.contains(x)))?;
    if let Some(far) = wireguard_far(ends, &d, p).into_iter().next() {
        return Some((far, None));
    }
    let id = peer_node_id(&d, w, p);
    let node = TopoNode {
        id: id.clone(),
        kind: "peer".into(),
        label: p.name.clone(),
        device: None,
        functions: None,
    };
    Some((id, Some(node)))
}

/// The source address of each WireGuard peer of the twin, with its devices.
fn wireguard_ends(t: &Loaded) -> BTreeMap<std::net::IpAddr, BTreeSet<String>> {
    let mut ends: BTreeMap<std::net::IpAddr, BTreeSet<String>> = BTreeMap::new();
    for f in t.functions() {
        let any: &dyn Any = f.as_ref();
        if let Some(w) = any.downcast_ref::<WireguardEncap>()
            && let Some(d) = f.device()
        {
            for p in w.peers() {
                if let Ok(s) = p.source {
                    ends.entry(s).or_default().insert(d.to_string());
                }
            }
        }
    }
    ends
}

/// The topology of a twin.
pub fn topology(
    topology: &str,
    t: &Loaded,
    args: &TopologyViewArgs,
) -> Result<TopologyOut, QueryError> {
    let level = args.level.as_deref().unwrap_or("device");
    let all_layers: &[&str] = match level {
        "device" => &["physical", "overlay"],
        "function" => &["function"],
        l => return Err(invalid(format!("{l} is not a level: device or function"))),
    };
    let layers: Vec<String> = match &args.layers {
        Some(l) => {
            for x in l {
                if !all_layers.contains(&x.as_str()) {
                    return Err(invalid(format!(
                        "{x} is not a layer of the level {level}: {}",
                        all_layers.join(", ")
                    )));
                }
            }
            l.clone()
        }
        None => all_layers.iter().map(|s| s.to_string()).collect(),
    };
    let claims = args.claims.clone().unwrap_or_default();
    for c in &claims {
        if c != "link-speed-duplex" {
            return Err(invalid(format!(
                "{c} is not a claim of an edge: link-speed-duplex"
            )));
        }
    }
    let devices = device_nodes(t);
    // The devices of the view: the filter, then the neighbourhood.
    let mut keep: BTreeSet<String> = match &args.devices {
        Some(d) => d
            .iter()
            .filter(|x| devices.contains_key(*x))
            .cloned()
            .collect(),
        None => devices.keys().cloned().collect(),
    };
    let phys = physical(t, claims.iter().any(|c| c == "link-speed-duplex"));
    if let Some(center) = &args.around {
        if !devices.contains_key(center) {
            return Err(invalid(format!("{center} is not a device")));
        }
        let hops = args.hops.unwrap_or(1);
        let mut seen = BTreeSet::from([center.clone()]);
        let mut queue = VecDeque::from([(center.clone(), 0usize)]);
        while let Some((d, n)) = queue.pop_front() {
            if n == hops {
                continue;
            }
            for e in &phys {
                let other = if e.from == d {
                    &e.to
                } else if e.to == d {
                    &e.from
                } else {
                    continue;
                };
                if seen.insert(other.clone()) {
                    queue.push_back((other.clone(), n + 1));
                }
            }
        }
        keep = keep.intersection(&seen).cloned().collect();
    }
    let (nodes, mut edges): (Vec<TopoNode>, Vec<TopoEdge>) = if level == "device" {
        let mut nodes: Vec<TopoNode> = keep.iter().map(|d| devices[d].clone()).collect();
        let mut e = Vec::new();
        if layers.iter().any(|l| l == "physical") {
            e.extend(phys);
        }
        if layers.iter().any(|l| l == "overlay") {
            let (tunnels, peers) = overlay(t);
            let shown: BTreeSet<&str> = tunnels
                .iter()
                .filter(|x| keep.contains(&x.from))
                .map(|x| x.to.as_str())
                .collect();
            nodes.extend(
                peers
                    .values()
                    .filter(|p| shown.contains(p.id.as_str()))
                    .cloned(),
            );
            e.extend(tunnels);
        }
        (nodes, e)
    } else {
        let mut nodes = Vec::new();
        let mut e = Vec::new();
        for f in t.functions() {
            let Some(d) = f.device().map(ToString::to_string) else {
                continue;
            };
            if !keep.contains(&d) {
                continue;
            }
            nodes.push(TopoNode {
                id: f.id().to_string(),
                kind: snake(&f.kind()),
                label: f.id().to_string(),
                device: Some(d),
                functions: None,
            });
            for s in f.successors() {
                e.push(edge(
                    format!("function:{}>{s}", f.id()),
                    "function",
                    f.id().to_string(),
                    s.to_string(),
                ));
            }
        }
        (nodes, e)
    };
    let ids: BTreeSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
    edges.retain(|e| ids.contains(e.from.as_str()) && ids.contains(e.to.as_str()));
    edges.sort_by(|a, b| a.id.cmp(&b.id));
    if nodes.len() > MAX_NODES {
        return Err(invalid(format!(
            "the view has {} nodes, more than {MAX_NODES}; use the level device, the filter devices or around",
            nodes.len()
        )));
    }
    Ok(TopologyOut {
        rsim_json: VERSION,
        kind: "topology".into(),
        topology: topology.to_string(),
        twin: t.identity.clone(),
        level: level.into(),
        layers,
        nodes,
        edges,
    })
}

/// The underlay edges of the hops of a tunnel from `start`: the id, the 2
/// devices of the hop and the overlay edge of the tunnel when it ends at
/// `end`.
fn underlay(
    start: &str,
    end: Option<&str>,
    hops: Vec<(String, String)>,
) -> impl Iterator<Item = (String, String, String, Option<String>)> {
    let tag = match end {
        Some(e) => format!("{start}>{e}"),
        None => start.to_string(),
    };
    let over = end.map(|e| format!("overlay:{start}>{e}"));
    hops.into_iter()
        .map(move |(p, d)| (format!("underlay:{p}>{d}:{tag}"), p, d, over.clone()))
}

/// Adds the edges of a tunnel from `start`: the overlay edge to `end` when
/// the tunnel end is known, and the underlay edges of its hops.
fn close(
    add: &mut impl FnMut(String, &str, &str, &str, usize, Option<String>),
    start: &str,
    end: Option<&str>,
    hops: Vec<(String, String)>,
    b: usize,
) {
    if let Some(e) = end {
        add(format!("overlay:{start}>{e}"), "overlay", start, e, b, None);
    }
    for (id, p, x, over) in underlay(start, end, hops) {
        add(id, "underlay", &p, &x, b, over);
    }
}

/// The drawing of the paths of an answer at the device level. A hop
/// between 2 devices is a `physical` edge; inside a tunnel it is an
/// `underlay` edge that names its `overlay` edge, from the device that
/// encapsulates to the device that decapsulates. The id of an underlay
/// edge holds both tunnel ends. A WireGuard tunnel with no decapsulation in
/// the branch ends at its peer: the device of the twin whose WireGuard
/// source address is the endpoint, else a node `peer`. Another tunnel with
/// no decapsulation in the branch gives underlay edges with only the start
/// device and no overlay edge.
pub fn drawing(topology: &str, t: &Loaded, a: &Answer) -> TopologyOut {
    let devices = device_nodes(t);
    let ends = wireguard_ends(t);
    let mut used: BTreeSet<String> = BTreeSet::new();
    let mut peers: BTreeMap<String, TopoNode> = BTreeMap::new();
    let mut edges: BTreeMap<String, TopoEdge> = BTreeMap::new();
    let mut add =
        |id: String, layer: &str, from: &str, to: &str, b: usize, over: Option<String>| {
            let e = edges
                .entry(id.clone())
                .or_insert_with(|| edge(id, layer, from.to_string(), to.to_string()));
            if !e.branches.contains(&b) {
                e.branches.push(b);
            }
            if e.overlay.is_none() {
                e.overlay = over;
            }
        };
    for b in a.branches() {
        let mut prev: Option<String> = None;
        // The device that encapsulated the packets, the hops of the outer
        // packet since then, and the node of a WireGuard peer, inside a
        // tunnel.
        let mut tunnel: Option<(String, Vec<(String, String)>, Option<String>)> = None;
        for s in &b.steps {
            let Some(d) = s.device.as_ref().map(ToString::to_string) else {
                continue;
            };
            used.insert(d.clone());
            if let Some(p) = &prev
                && *p != d
            {
                match &mut tunnel {
                    Some((_, hops, _)) => hops.push((p.clone(), d.clone())),
                    None => add(
                        format!("physical:{p}>{d}"),
                        "physical",
                        p,
                        &d,
                        b.index,
                        None,
                    ),
                }
            }
            let forwards = matches!(s.outcome, rsim_core::Outcome::Forward(_));
            if s.kind == FunctionKind::Encapsulation && forwards {
                if let Some((start, hops, far)) = tunnel.take() {
                    close(&mut add, &start, far.as_deref(), hops, b.index);
                }
                let far = wireguard_step(t, &ends, s).map(|(far, node)| {
                    if let Some(n) = node {
                        peers.entry(n.id.clone()).or_insert(n);
                    }
                    far
                });
                tunnel = Some((d.clone(), Vec::new(), far));
            }
            if s.kind == FunctionKind::Decapsulation
                && forwards
                && let Some((start, hops, _)) = tunnel.take()
            {
                close(&mut add, &start, Some(&d), hops, b.index);
            }
            prev = Some(d);
        }
        if let Some((start, hops, far)) = tunnel {
            close(&mut add, &start, far.as_deref(), hops, b.index);
        }
    }
    let mut nodes: Vec<TopoNode> = used
        .iter()
        .filter_map(|d| devices.get(d).cloned())
        .collect();
    for (id, n) in peers {
        if edges.values().any(|e| e.to == id) {
            nodes.push(n);
        }
    }
    let mut layers: Vec<String> = edges.values().map(|e| e.layer.clone()).collect();
    layers.sort();
    layers.dedup();
    TopologyOut {
        rsim_json: VERSION,
        kind: "path_drawing".into(),
        topology: topology.to_string(),
        twin: t.identity.clone(),
        level: "device".into(),
        layers,
        nodes,
        edges: edges.into_values().collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use rsim_contract::args::TopologyViewArgs;
    use rsim_contract::twin::TwinJson;
    use rsim_core::{Attr, InterfaceId, VrfId};
    use rsim_engine::TwinBuilder;
    use rsim_functions::{DeviceDelivery, Meta, WireguardEncap, WireguardPeer, WireguardSettings};

    use crate::commands::Loaded;

    fn peer(name: &str, endpoint: &str, source: &str) -> WireguardPeer {
        WireguardPeer {
            name: name.into(),
            allowed: vec!["0.0.0.0/0".parse().unwrap()],
            endpoint: Some((endpoint.parse().unwrap(), 51820)),
            source: Ok(source.parse().unwrap()),
            source_interface: None,
            spans: Vec::new(),
        }
    }

    fn router(b: &mut TwinBuilder, d: &str, peers: Vec<WireguardPeer>) {
        let profile = rsim_topologies::generic_router();
        let next = format!("{d}/route");
        b.add(DeviceDelivery {
            meta: Meta::new(next.as_str(), d, &profile),
        });
        b.add_arc(Arc::new(WireguardEncap::new(
            Meta::new(format!("{d}/wireguard/wg0").as_str(), d, &profile),
            InterfaceId::new("wg0"),
            peers,
            WireguardSettings {
                listen_port: Some(51820),
                unknown: None,
                src_zone: Attr::Unset,
                underlay: VrfId::new("default"),
                next: next.as_str().into(),
            },
        )));
    }

    fn twin() -> Loaded {
        let mut b = TwinBuilder::new();
        router(
            &mut b,
            "r1",
            vec![
                peer("remote", "203.0.113.5", "198.51.100.1"),
                peer("r2", "198.51.100.2", "198.51.100.1"),
            ],
        );
        router(
            &mut b,
            "r2",
            vec![peer("r1", "198.51.100.1", "198.51.100.2")],
        );
        Loaded {
            twin: b.build().expect("the twin builds"),
            identity: TwinJson::builtin("vpn").unwrap(),
            coverage: BTreeMap::new(),
            bgp: BTreeMap::new(),
            facts: BTreeMap::new(),
            seen: Vec::new(),
            tables: Default::default(),
            source: None,
        }
    }

    #[test]
    fn a_wireguard_peer_is_a_device_of_the_twin_or_a_peer_node_outside_it() {
        let out = super::topology("vpn", &twin(), &TopologyViewArgs::default()).unwrap();
        let peers: Vec<(&str, &str)> = out
            .nodes
            .iter()
            .filter(|n| n.kind == "peer")
            .map(|n| (n.id.as_str(), n.label.as_str()))
            .collect();
        assert_eq!(peers, [("peer:203.0.113.5", "remote")]);
        let tunnels: Vec<(&str, &str)> = out
            .edges
            .iter()
            .filter(|e| e.layer == "overlay")
            .map(|e| (e.from.as_str(), e.to.as_str()))
            .collect();
        assert_eq!(
            tunnels,
            [("r1", "peer:203.0.113.5"), ("r1", "r2"), ("r2", "r1")]
        );
        let remote = out
            .edges
            .iter()
            .find(|e| e.to == "peer:203.0.113.5")
            .unwrap();
        assert_eq!(remote.facts["tunnels"][0]["name"], "remote");
        assert_eq!(remote.facts["tunnels"][0]["port"], 51820);
    }

    #[test]
    fn a_view_of_one_device_has_only_the_peers_of_its_tunnels() {
        let args = TopologyViewArgs {
            devices: Some(vec!["r2".into()]),
            ..Default::default()
        };
        let out = super::topology("vpn", &twin(), &args).unwrap();
        assert!(out.nodes.iter().all(|n| n.kind == "device"));
    }
}
