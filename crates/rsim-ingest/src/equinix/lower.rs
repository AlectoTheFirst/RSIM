//! The lowering of an account: a gate and the circuits of each Fabric port.
//!
//! A frame enters the Fabric port `port/<uuid>` at its gate
//! `port/<uuid>/in`, an `AclMatch` with one rule for the tags of each leg of
//! the port and a last unhandled rule. The circuit function
//! `port/<uuid>/circuit` sends the frame with the tags of the far end to
//! the ingress function of the link peer of the far port, or to a sink
//! with the reason of an end that the twin does not follow.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rsim_core::bits::TPID_8021Q;
use rsim_core::{FunctionId, Match, NetFunction, ObjectId, PortId, RulePredicate, SourceSpan};
use rsim_functions::{
    AclMatch, Circuit, CircuitLeg, FarEnd, Meta, Rule, RuleAction, TagOp, TagStack, Tags,
    VendorProfile, VlanTag,
};

use super::edge::{self, EdgePort};
use super::reader::{Account, Connection, EdgeDevice, EdgeInterface, End, EndKind, Port};

/// The circuit states that end a circuit, from HST `ENDED_CIRCUIT_STATES`.
pub const ENDED_STATES: &[&str] = &["DEPROVISIONED", "DELETED", "CANCELLED"];
/// The TPID of an IEEE 802.1ad service tag, the default of a QinQ port.
pub const TPID_8021AD: u16 = 0x88a8;

/// The result of a circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Both ends are on lowered Fabric ports of the account.
    Lowered,
    /// The state ends the circuit, so the twin has no leg of it.
    Ended,
    /// The frames of its ends are unknown for this reason.
    Unknown(String),
}

/// One circuit of the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitRow {
    pub uuid: String,
    pub name: Option<String>,
    pub kind: Option<String>,
    pub state: Option<String>,
    /// The A end and the Z end as text.
    pub a: String,
    pub z: String,
    pub verdict: Verdict,
    /// The spans of each item of the circuit.
    pub spans: Vec<SourceSpan>,
}

/// The lowering of one Fabric port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortPlan {
    pub name: String,
    /// The reason when the port is not lowered.
    pub reason: Option<String>,
    pub legs: Vec<CircuitLeg>,
    pub span: SourceSpan,
}

/// The functions of an account, the plan of each Fabric port by uuid, the
/// account port of each Network Edge interface that a circuit or a device
/// link group uses, the device of the store of each bound Network Edge
/// device by uuid, the circuits and the notes.
#[derive(Default)]
pub struct Lowered {
    pub functions: Vec<Arc<dyn NetFunction>>,
    pub ports: BTreeMap<String, PortPlan>,
    pub edge_ports: BTreeMap<String, EdgePort>,
    pub bound: BTreeMap<String, String>,
    pub circuits: Vec<CircuitRow>,
    pub notes: Vec<String>,
}

/// The tags of an end on a Fabric port.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Spec {
    Tags(Tags),
    /// Each frame of the port, with its tags unchanged.
    PortBased,
    /// The tags are not known for this reason.
    Bad(String),
}

/// Where an end of a circuit is.
#[derive(Clone, Debug)]
enum At<'a> {
    Port(&'a Port, Spec),
    /// An untagged end on an interface of a Network Edge device of the
    /// account, with the reason when the end is not handled.
    Edge(&'a EdgeDevice, &'a EdgeInterface, Option<String>),
    /// The end is not on a Fabric port or a Network Edge interface of the
    /// account, for this reason.
    Away(String),
}

/// The TPID of a port: `tagProtocolId` in hex, else `0x88a8` for a QinQ
/// port and `0x8100` for each other port.
fn port_tpid(p: &Port) -> Result<u16, String> {
    let qinq = p.encapsulation.as_deref() == Some("QINQ");
    match &p.tpid {
        None => Ok(if qinq { TPID_8021AD } else { TPID_8021Q }),
        Some(t) => {
            let hex = t.trim();
            let hex = hex
                .strip_prefix("0x")
                .or_else(|| hex.strip_prefix("0X"))
                .unwrap_or(hex);
            u16::from_str_radix(hex, 16)
                .map_err(|_| format!("the TPID {t} of the Fabric port {} does not read", p.name))
        }
    }
}

/// The reason why a port is not lowered, or its TPID.
fn port_state(p: &Port) -> Result<u16, String> {
    if let Some(r) = &p.conflict {
        return Err(r.clone());
    }
    match p.state.as_deref() {
        Some("ACTIVE") => {}
        Some(s) => {
            return Err(format!(
                "the state {s} of the Fabric port {} is not handled",
                p.name
            ));
        }
        None => return Err(format!("the Fabric port {} has no state", p.name)),
    }
    match p.encapsulation.as_deref() {
        Some("DOT1Q" | "QINQ" | "UNTAGGED") => {}
        Some(e) => {
            return Err(format!(
                "the encapsulation {e} of the Fabric port {} is not handled",
                p.name
            ));
        }
        None => return Err(format!("the Fabric port {} has no encapsulation", p.name)),
    }
    port_tpid(p)
}

/// A VLAN from 1 to 4094.
fn vlan(v: Option<i64>) -> Option<u16> {
    v.filter(|x| (1..=4094).contains(x)).map(|x| x as u16)
}

/// The tags of an end on a port with the TPID `tpid`. The inner tag of a
/// QinQ end has the TPID `0x8100`.
fn spec(e: &End, tpid: u16, port: &str) -> Spec {
    let outer = |v: u16| VlanTag { vlan: v, tpid };
    match e.protocol.as_deref() {
        Some("DOT1Q") => match vlan(e.tag) {
            Some(v) => Spec::Tags(Tags::one(outer(v))),
            None => Spec::Bad(format!(
                "the DOT1Q end on the Fabric port {port} has no tag"
            )),
        },
        Some("QINQ") => match (vlan(e.s_tag).or(vlan(e.tag)), vlan(e.c_tag)) {
            (Some(o), Some(i)) => Spec::Tags(Tags::two(outer(o), VlanTag::dot1q(i))),
            (Some(_), None) => Spec::Bad(format!(
                "the QINQ end on the Fabric port {port} has no inner tag"
            )),
            (None, _) => Spec::Bad(format!(
                "the QINQ end on the Fabric port {port} has no outer tag"
            )),
        },
        Some("UNTAGGED" | "NULL") => Spec::PortBased,
        Some(t) => Spec::Bad(format!(
            "the link protocol {t} on the Fabric port {port} is not handled"
        )),
        None => Spec::Bad(format!(
            "the end on the Fabric port {port} has no link protocol"
        )),
    }
}

/// The text of an end.
fn end_text(e: &End, ports: &BTreeMap<&str, &Port>) -> String {
    let tags = |e: &End| -> String {
        let words: Vec<String> = [
            e.protocol.clone(),
            e.tag.map(|t| format!("tag {t}")),
            e.s_tag.map(|t| format!("S-tag {t}")),
            e.c_tag.map(|t| format!("C-tag {t}")),
        ]
        .into_iter()
        .flatten()
        .collect();
        if words.is_empty() {
            String::new()
        } else {
            format!(" {}", words.join(" "))
        }
    };
    match &e.kind {
        EndKind::Port(u) => match ports.get(u.as_str()) {
            Some(p) => format!("port {}{}", p.name, tags(e)),
            None => format!("port {u}{}", tags(e)),
        },
        EndKind::ServiceProfile(n) => format!("service profile {n}"),
        EndKind::Device { device, .. } => format!("Network Edge device {device}{}", tags(e)),
        EndKind::Other(t) => format!("end type {t}"),
        EndKind::Missing => "no end".to_string(),
    }
}

/// Two items of one circuit agree when they have the same type, the same
/// state and the same 2 ends with the same tags, in either order.
fn agree(x: &Connection, y: &Connection) -> bool {
    x.kind == y.kind
        && x.state == y.state
        && ((x.a == y.a && x.z == y.z) || (x.a == y.z && x.z == y.a))
}

/// Where an end is, with the ports of the account by uuid and the TPID of
/// each lowered port.
fn at<'a>(
    e: &End,
    by_uuid: &BTreeMap<&str, &'a Port>,
    states: &BTreeMap<&str, Result<u16, String>>,
    edges: &'a [EdgeDevice],
) -> At<'a> {
    match &e.kind {
        EndKind::Port(u) => match (by_uuid.get(u.as_str()), states.get(u.as_str())) {
            (Some(p), Some(Ok(tpid))) => At::Port(p, spec(e, *tpid, &p.name)),
            (Some(p), Some(Err(r))) => At::Port(p, Spec::Bad(r.clone())),
            _ => At::Away("the far end is outside the account".to_string()),
        },
        EndKind::ServiceProfile(n) => At::Away(format!("the far end is the service profile {n}")),
        EndKind::Device {
            device,
            interface,
            interface_id,
        } => match edges.iter().find(|d| d.uuid == *device) {
            None if edges.is_empty() => {
                At::Away("the Network Edge devices of the account are not collected".to_string())
            }
            None => At::Away("the far end is outside the account".to_string()),
            Some(d) => match d.interface(interface.as_deref(), interface_id.as_deref()) {
                None => At::Away(format!(
                    "the end names no interface of the Network Edge device {}",
                    d.name
                )),
                Some(i) => {
                    let bad = e.protocol.as_ref().map(|t| {
                        format!(
                            "the link protocol {t} on the Network Edge device {} is not handled",
                            d.name
                        )
                    });
                    At::Edge(d, i, bad)
                }
            },
        },
        EndKind::Other(t) => At::Away(format!("the end type {t} is not handled")),
        EndKind::Missing => At::Away("an end has no type or no port".to_string()),
    }
}

/// One circuit with its ends and its reason before the legs.
struct Plan<'a> {
    row: CircuitRow,
    ends: [At<'a>; 2],
    reason: Option<String>,
}

/// The id of a function of the account device.
fn fid(device: &str, f: &str) -> FunctionId {
    FunctionId::new(format!("{device}/{f}"))
}

/// A sink: an `AclMatch` whose one unhandled rule gives `Unknown` with the
/// reason and the span.
fn sink(
    device: &str,
    profile: &VendorProfile,
    f: &str,
    reason: &str,
    span: &SourceSpan,
) -> Arc<dyn NetFunction> {
    let id = fid(device, f);
    Arc::new(AclMatch {
        meta: Meta::new(id.clone(), device, profile).with_span(span.clone()),
        acl: ObjectId::new(format!("{device}:{f}")),
        rules: vec![Rule::unhandled(reason, span.clone())],
        default: RuleAction::Deny,
        next: id,
    })
}

/// The key of the tags of a leg on a port: `None` for a port-based leg.
fn tag_key(s: &Spec) -> Option<Option<Tags>> {
    match s {
        Spec::Tags(t) => Some(Some(*t)),
        Spec::PortBased => Some(None),
        Spec::Bad(_) => None,
    }
}

/// The leg of a circuit from a Fabric port to a Network Edge interface.
struct EdgeLeg<'a> {
    port: String,
    device: &'a EdgeDevice,
    tags: Tags,
    fabric: &'a Port,
    circuit: String,
    spans: Vec<SourceSpan>,
}

/// Lowers an account. `peers` gives the ingress function of the link peer
/// of each port of the account by its name, `port/<uuid>` for a Fabric port
/// and `ne-<device uuid>/<interface>` for a Network Edge interface. A port
/// with no peer sends the frames to a sink.
pub fn lower(
    account: &Account,
    profile: &VendorProfile,
    peers: &BTreeMap<String, FunctionId>,
) -> Lowered {
    let device = account.device.as_str();
    let mut out = Lowered {
        notes: account.notes.clone(),
        ..Lowered::default()
    };
    let by_uuid: BTreeMap<&str, &Port> =
        account.ports.iter().map(|p| (p.uuid.as_str(), p)).collect();
    let states: BTreeMap<&str, Result<u16, String>> = account
        .ports
        .iter()
        .map(|p| (p.uuid.as_str(), port_state(p)))
        .collect();

    // The items of each circuit, in uuid order.
    let mut groups: BTreeMap<&str, Vec<&Connection>> = BTreeMap::new();
    for c in &account.connections {
        groups.entry(c.uuid.as_str()).or_default().push(c);
    }
    let mut plans: Vec<Plan<'_>> = Vec::new();
    for (uuid, items) in &groups {
        let c = items[0];
        let row = CircuitRow {
            uuid: (*uuid).to_string(),
            name: c.name.clone(),
            kind: c.kind.clone(),
            state: c.state.clone(),
            a: end_text(&c.a, &by_uuid),
            z: end_text(&c.z, &by_uuid),
            verdict: Verdict::Lowered,
            spans: items.iter().map(|x| x.span.clone()).collect(),
        };
        let ends = [
            at(&c.a, &by_uuid, &states, &account.edge_devices),
            at(&c.z, &by_uuid, &states, &account.edge_devices),
        ];
        let mut plan = Plan {
            row,
            ends,
            reason: None,
        };
        if c.state
            .as_deref()
            .is_some_and(|s| ENDED_STATES.contains(&s))
        {
            plan.row.verdict = Verdict::Ended;
            plans.push(plan);
            continue;
        }
        let reason = if !items.iter().all(|x| agree(x, c)) {
            let r = format!("the {} items of the circuit {uuid} differ", items.len());
            out.notes.push(r.clone());
            Some(r)
        } else if c.kind.as_deref() != Some("EVPL_VC") {
            Some(match &c.kind {
                Some(k) => format!("the circuit type {k} is not handled"),
                None => "the circuit has no type".to_string(),
            })
        } else if c.state.as_deref() != Some("ACTIVE") {
            Some(match &c.state {
                Some(s) => format!("the circuit state {s} is not handled"),
                None => "the circuit has no state".to_string(),
            })
        } else {
            match &plan.ends {
                [At::Port(p, _), At::Port(q, _)] if p.uuid == q.uuid => {
                    let r = format!("the circuit has both ends on the Fabric port {}", p.name);
                    out.notes.push(format!("{uuid}: {r}"));
                    Some(r)
                }
                [At::Port(_, Spec::Bad(r)), _] | [_, At::Port(_, Spec::Bad(r))] => Some(r.clone()),
                [At::Port(_, Spec::PortBased), At::Port(_, Spec::Tags(_))]
                | [At::Port(_, Spec::Tags(_)), At::Port(_, Spec::PortBased)] => {
                    Some("the circuit has a port-based end and a tagged end".to_string())
                }
                [At::Edge(..), At::Edge(..)] => {
                    Some("a circuit between 2 Network Edge interfaces is not handled".to_string())
                }
                [At::Edge(_, _, Some(r)), _] | [_, At::Edge(_, _, Some(r))] => Some(r.clone()),
                [At::Port(_, Spec::PortBased), At::Edge(..)]
                | [At::Edge(..), At::Port(_, Spec::PortBased)] => {
                    Some("the circuit has a port-based end and a Network Edge end".to_string())
                }
                [At::Port(_, Spec::Tags(t)), At::Edge(..)]
                | [At::Edge(..), At::Port(_, Spec::Tags(t))]
                    if t.inner.is_some() =>
                {
                    Some("the circuit has 2 tags at one end and a Network Edge end".to_string())
                }
                [At::Away(r), _] | [_, At::Away(r)] => {
                    if r.ends_with("outside the account") {
                        out.notes.push(format!("{uuid}: {r}"));
                    }
                    Some(r.clone())
                }
                _ => None,
            }
        };
        plan.reason = reason;
        plans.push(plan);
    }

    // A Network Edge interface with more than one circuit, or with a
    // circuit and a device link group, makes each of its circuits unknown.
    let group_ports = edge::group_ports(account);
    let mut edge_claims: BTreeMap<String, (String, Vec<usize>)> = BTreeMap::new();
    for (i, plan) in plans.iter().enumerate() {
        if plan.row.verdict == Verdict::Ended {
            continue;
        }
        for e in &plan.ends {
            if let At::Edge(d, f, _) = e {
                edge_claims
                    .entry(edge::port_name(d, f))
                    .or_insert_with(|| (format!("{} {}", d.name, f.name), Vec::new()))
                    .1
                    .push(i);
            }
        }
    }
    for (port, (text, list)) in &edge_claims {
        if list.len() < 2 && !group_ports.contains(port) {
            continue;
        }
        let r = format!(
            "the Network Edge interface {text} is in more than one circuit or device link group"
        );
        for i in list {
            if plans[*i].reason.is_none() {
                out.notes.push(format!("{}: {r}", plans[*i].row.uuid));
                plans[*i].reason = Some(r.clone());
            }
        }
    }

    // Two legs with the same tags on one port, or a port-based leg with
    // another leg, make each of their circuits unknown.
    let mut claims: BTreeMap<&str, Vec<(Option<Tags>, usize)>> = BTreeMap::new();
    for (i, plan) in plans.iter().enumerate() {
        if plan.row.verdict == Verdict::Ended {
            continue;
        }
        for e in &plan.ends {
            if let At::Port(p, s) = e
                && let Some(k) = tag_key(s)
            {
                claims.entry(p.uuid.as_str()).or_default().push((k, i));
            }
        }
    }
    for (port, list) in &claims {
        let name = &by_uuid[port].name;
        for (k, i) in list {
            let others = list
                .iter()
                .filter(|(k2, j)| j != i && (k.is_none() || k2.is_none() || k2 == k));
            if others.count() == 0 {
                continue;
            }
            let what = match k {
                Some(t) => t.text(),
                None => "each frame".to_string(),
            };
            let r = format!("2 circuits use {what} on the Fabric port {name}");
            if plans[*i].reason.is_none() {
                out.notes.push(format!("{}: {r}", plans[*i].row.uuid));
                plans[*i].reason = Some(r);
            }
        }
    }

    // The legs of each port.
    let mut legs: BTreeMap<&str, Vec<CircuitLeg>> = BTreeMap::new();
    let mut unbound: BTreeMap<&str, &Port> = BTreeMap::new();
    let mut sinks: Vec<(String, String, SourceSpan)> = Vec::new();
    let mut edge_legs: Vec<EdgeLeg<'_>> = Vec::new();
    // The reason of each Network Edge interface of a circuit that is
    // unknown, with the span of the circuit.
    let mut edge_unknown: BTreeMap<String, (String, SourceSpan)> = BTreeMap::new();
    for plan in &mut plans {
        if plan.row.verdict == Verdict::Ended {
            continue;
        }
        let uuid = plan.row.uuid.clone();
        let sink_f = format!("circuit/{uuid}/sink");
        let mut used_sink = false;
        for (i, e) in plan.ends.iter().enumerate() {
            let At::Port(p, s) = e else { continue };
            let &p = p;
            let (near, port_based) = match s {
                Spec::Tags(t) => (*t, false),
                Spec::PortBased => (Tags::one(VlanTag::dot1q(1)), true),
                Spec::Bad(_) => continue,
            };
            if states[p.uuid.as_str()].is_err() {
                continue;
            }
            let far = match (&plan.reason, &plan.ends[1 - i]) {
                (None, At::Port(q, qs)) => {
                    let &q = q;
                    let tags = match qs {
                        Spec::Tags(t) => *t,
                        _ => near,
                    };
                    let peer = match peers.get(&format!("port/{}", q.uuid)) {
                        Some(f) => f.clone(),
                        None => {
                            unbound.insert(q.uuid.as_str(), q);
                            fid(device, &format!("port/{}/unbound", q.uuid))
                        }
                    };
                    FarEnd::Port {
                        port: PortId::new(format!("port/{}", q.uuid)),
                        tags,
                        peer,
                    }
                }
                (None, At::Edge(d, f, _)) => {
                    let port = edge::port_name(d, f);
                    let far = FarEnd::Port {
                        port: PortId::new(&port),
                        tags: near,
                        peer: fid(device, &format!("{port}/out")),
                    };
                    edge_legs.push(EdgeLeg {
                        port,
                        device: d,
                        tags: near,
                        fabric: p,
                        circuit: uuid.clone(),
                        spans: plan.row.spans.clone(),
                    });
                    far
                }
                _ => {
                    used_sink = true;
                    FarEnd::Sink(fid(device, &sink_f))
                }
            };
            legs.entry(p.uuid.as_str()).or_default().push(CircuitLeg {
                circuit: uuid.clone(),
                near,
                far,
                spans: plan.row.spans.clone(),
                port_based,
            });
        }
        if let Some(r) = &plan.reason {
            plan.row.verdict = Verdict::Unknown(r.clone());
            if used_sink {
                sinks.push((sink_f, r.clone(), plan.row.spans[0].clone()));
            }
            for e in &plan.ends {
                if let At::Edge(d, f, _) = e {
                    let port = edge::port_name(d, f);
                    out.edge_ports.insert(
                        port.clone(),
                        EdgePort {
                            device: d.uuid.clone(),
                            interface: f.name.clone(),
                            mac: f.mac,
                            span: d.span.clone(),
                        },
                    );
                    if !group_ports.contains(&port) {
                        edge_unknown
                            .entry(port)
                            .or_insert_with(|| (r.clone(), plan.row.spans[0].clone()));
                    }
                }
            }
        }
    }

    // The functions of each port.
    for p in &account.ports {
        let gate = format!("port/{}/in", p.uuid);
        let circuit = format!("port/{}/circuit", p.uuid);
        let port_legs = legs.remove(p.uuid.as_str()).unwrap_or_default();
        let reason = states[p.uuid.as_str()].as_ref().err().cloned();
        let mut rules: Vec<Rule<RuleAction>> = port_legs
            .iter()
            .map(|l| {
                let predicate = if l.port_based {
                    RulePredicate::exact(Match::any())
                } else {
                    l.near.predicate()
                };
                let mut r = Rule::new(l.circuit.clone(), predicate, RuleAction::Permit);
                r.spans = l.spans.clone();
                r
            })
            .collect();
        let last = reason.clone().unwrap_or_else(|| {
            format!(
                "no circuit for the frame tags on the Fabric port {}",
                p.name
            )
        });
        rules.push(Rule::unhandled(last, p.span.clone()));
        let next = if reason.is_some() { &gate } else { &circuit };
        out.functions.push(Arc::new(AclMatch {
            meta: Meta::new(fid(device, &gate), device, profile).with_span(p.span.clone()),
            acl: ObjectId::new(format!("{device}:port/{}", p.uuid)),
            rules,
            default: RuleAction::Deny,
            next: fid(device, next),
        }));
        if reason.is_none() {
            out.functions.push(Arc::new(Circuit {
                meta: Meta::new(fid(device, &circuit), device, profile).with_span(p.span.clone()),
                port: PortId::new(format!("port/{}", p.uuid)),
                legs: port_legs.clone(),
            }));
        }
        out.ports.insert(
            p.uuid.clone(),
            PortPlan {
                name: p.name.clone(),
                reason,
                legs: port_legs,
                span: p.span.clone(),
            },
        );
    }
    // The Network Edge interface of each circuit: the push of the tag of
    // the Fabric end and the circuit at the entry, and the pop of the tag
    // at the exit.
    for l in &edge_legs {
        let Some(f) = l
            .device
            .interfaces
            .iter()
            .find(|i| edge::port_name(l.device, i) == l.port)
        else {
            continue;
        };
        let e = EdgePort {
            device: l.device.uuid.clone(),
            interface: f.name.clone(),
            mac: f.mac,
            span: l.device.span.clone(),
        };
        let span = l.spans[0].clone();
        let entry = format!("{}/in", l.port);
        let circuit = format!("{}/circuit", l.port);
        let exit = format!("{}/out", l.port);
        out.functions.push(Arc::new(TagStack {
            meta: Meta::new(fid(device, &entry), device, profile).with_span(span.clone()),
            port: PortId::new(&l.port),
            op: TagOp::Push(l.tags.outer),
            next: fid(device, &circuit),
        }));
        let q = l.fabric;
        let peer = match peers.get(&format!("port/{}", q.uuid)) {
            Some(f) => f.clone(),
            None => {
                unbound.insert(q.uuid.as_str(), q);
                fid(device, &format!("port/{}/unbound", q.uuid))
            }
        };
        out.functions.push(Arc::new(Circuit {
            meta: Meta::new(fid(device, &circuit), device, profile).with_span(span.clone()),
            port: PortId::new(&l.port),
            legs: vec![CircuitLeg {
                circuit: l.circuit.clone(),
                near: l.tags,
                far: FarEnd::Port {
                    port: PortId::new(format!("port/{}", q.uuid)),
                    tags: l.tags,
                    peer,
                },
                spans: l.spans.clone(),
                port_based: false,
            }],
        }));
        let next = edge::peer_of(
            device,
            profile,
            &l.port,
            &e,
            &l.device.name,
            peers,
            &mut out.functions,
        );
        out.functions.push(Arc::new(TagStack {
            meta: Meta::new(fid(device, &exit), device, profile).with_span(span),
            port: PortId::new(&l.port),
            op: TagOp::Untag(l.tags.outer),
            next,
        }));
        out.edge_ports.insert(l.port.clone(), e);
    }
    for (port, (r, span)) in &edge_unknown {
        out.functions
            .push(sink(device, profile, &format!("{port}/in"), r, span));
    }
    let circuit_ports: BTreeSet<String> = out.edge_ports.keys().cloned().collect();
    let groups = edge::groups(account, profile, peers, &circuit_ports);
    out.functions.extend(groups.functions);
    out.notes.extend(groups.notes);
    for (port, e) in groups.ports {
        out.edge_ports.entry(port).or_insert(e);
    }
    let (bound, notes) = edge::bound(account);
    out.notes.extend(notes);
    out.functions
        .extend(edge::unbound_devices(account, profile, &bound));
    out.bound = bound;
    for (f, r, span) in &sinks {
        out.functions.push(sink(device, profile, f, r, span));
    }
    for (uuid, p) in unbound {
        out.functions.push(sink(
            device,
            profile,
            &format!("port/{uuid}/unbound"),
            &format!("the Fabric port {} has no binding", p.name),
            &p.span,
        ));
    }
    out.circuits = plans.into_iter().map(|p| p.row).collect();
    out
}
