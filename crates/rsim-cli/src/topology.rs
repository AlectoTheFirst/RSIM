//! The topology of a loaded twin, and the drawing of the paths of an
//! answer.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use rsim_contract::args::TopologyViewArgs;
use rsim_contract::claim;
use rsim_contract::topology::{TopoEdge, TopoNode, TopologyOut};
use rsim_core::FunctionKind;
use rsim_engine::Answer;
use rsim_functions::{Egress, LinkFacts, PortEgress, TunnelPeer, VxlanEncap};
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

/// The tunnel edges: from each device with a VXLAN encapsulation to each
/// device whose tunnel end is the peer.
fn overlay(t: &Loaded) -> Vec<TopoEdge> {
    let mut ends: BTreeMap<std::net::IpAddr, BTreeSet<String>> = BTreeMap::new();
    let mut encaps = Vec::new();
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
    let pairs = encaps.iter().flat_map(|(d, id, e)| {
        let peers: Vec<std::net::IpAddr> = match e.peer {
            TunnelPeer::Fixed(p) => vec![p],
            TunnelPeer::NextHop => gateways.get(id).into_iter().flatten().copied().collect(),
        };
        peers.into_iter().map(move |p| (d.clone(), *e, p))
    });
    for (d, e, peer) in pairs {
        for pd in ends.get(&peer).into_iter().flatten() {
            if *pd == d {
                continue;
            }
            let id = format!("overlay:{d}>{pd}");
            let x = out
                .entry(id.clone())
                .or_insert_with(|| edge(id, "overlay", d.clone(), pd.clone()));
            let vnis: BTreeSet<u32> = e.vnis.values().copied().collect();
            x.facts =
                json!({"source": e.source.to_string(), "peer": peer.to_string(), "vnis": vnis});
        }
    }
    out.into_values().collect()
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
        let nodes = keep.iter().map(|d| devices[d].clone()).collect();
        let mut e = Vec::new();
        if layers.iter().any(|l| l == "physical") {
            e.extend(phys);
        }
        if layers.iter().any(|l| l == "overlay") {
            e.extend(overlay(t));
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

/// The drawing of the paths of an answer at the device level. A hop
/// between 2 devices is a `physical` edge; inside a tunnel it is an
/// `underlay` edge that names its `overlay` edge, from the device that
/// encapsulates to the device that decapsulates.
pub fn drawing(topology: &str, t: &Loaded, a: &Answer) -> TopologyOut {
    let devices = device_nodes(t);
    let mut used: BTreeSet<String> = BTreeSet::new();
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
        // The device that encapsulated the packets, inside a tunnel.
        let mut tunnel: Option<String> = None;
        for s in &b.steps {
            let Some(d) = s.device.as_ref().map(ToString::to_string) else {
                continue;
            };
            used.insert(d.clone());
            if let Some(p) = &prev
                && *p != d
            {
                match &tunnel {
                    Some(start) => add(
                        format!("underlay:{p}>{d}:{start}"),
                        "underlay",
                        p,
                        &d,
                        b.index,
                        None,
                    ),
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
                tunnel = Some(d.clone());
            }
            if s.kind == FunctionKind::Decapsulation
                && forwards
                && let Some(start) = tunnel.take()
            {
                add(
                    format!("overlay:{start}>{d}"),
                    "overlay",
                    &start,
                    &d,
                    b.index,
                    None,
                );
            }
            prev = Some(d);
        }
    }
    // An underlay edge names the overlay edge of its tunnel: the overlay
    // edge from its start device.
    let overlay_of: BTreeMap<String, String> = edges
        .values()
        .filter(|e| e.layer == "overlay")
        .map(|e| (e.from.clone(), e.id.clone()))
        .collect();
    for e in edges.values_mut() {
        if e.layer == "underlay"
            && let Some(start) = e.id.rsplit(':').next()
        {
            e.overlay = overlay_of.get(start).cloned();
        }
    }
    let nodes = used
        .iter()
        .filter_map(|d| devices.get(d).cloned())
        .collect();
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
