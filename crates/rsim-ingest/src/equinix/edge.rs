//! The Network Edge part of an account: the bindings of the Network Edge
//! devices, the account port of each Network Edge interface that a circuit
//! or a device link group uses, the device link groups and the twin device
//! of each Network Edge device that no binding names.
//!
//! An account port is `ne-<device uuid>/<interface id>`, or
//! `ne-<device uuid>/<interface name>` for an interface with no id.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rsim_core::{
    BridgeDomainId, FunctionId, Mac, MacCond, Match, NetFunction, ObjectId, PortCond, PortId,
    RulePredicate, SourceSpan,
};
use rsim_functions::{
    AclMatch, BROADCAST, Flood, MacEntry, MacLookup, Meta, PortEgress, PortIngress, PortPeer, Rule,
    RuleAction, VendorProfile,
};

use super::reader::{Account, EdgeDevice, EdgeInterface, LinkGroup};

/// The status of a device link group that carries traffic, from the HST
/// comment in `reasoner/_constants.py`.
pub const GROUP_STATUS: &str = "PROVISIONED";

/// An account port of a Network Edge interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgePort {
    /// The uuid of the Network Edge device.
    pub device: String,
    /// The name of the interface.
    pub interface: String,
    pub mac: Option<Mac>,
    pub span: SourceSpan,
}

/// The account port of an interface of a Network Edge device.
pub fn port_name(d: &EdgeDevice, i: &EdgeInterface) -> String {
    format!("ne-{}/{}", d.uuid, i.id.as_deref().unwrap_or(&i.name))
}

/// The twin device of a Network Edge device that no binding names.
pub fn twin_device(account: &str, d: &EdgeDevice) -> String {
    format!("{account}-ne-{}", d.uuid)
}

/// The device of the store that each bound Network Edge device names, by
/// the uuid of the Network Edge device, and the notes. A binding matches
/// the uuid first, then the name or the host name, with case ignored.
pub fn bound(account: &Account) -> (BTreeMap<String, String>, Vec<String>) {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut notes = Vec::new();
    for b in &account.edge_bindings {
        let key = b.edge_device.as_str();
        let mut found: Vec<&EdgeDevice> = account
            .edge_devices
            .iter()
            .filter(|d| d.uuid.eq_ignore_ascii_case(key))
            .collect();
        if found.is_empty() {
            found = account
                .edge_devices
                .iter()
                .filter(|d| {
                    d.name.eq_ignore_ascii_case(key)
                        || d.host_name
                            .as_deref()
                            .is_some_and(|h| h.eq_ignore_ascii_case(key))
                })
                .collect();
        }
        match found.as_slice() {
            [] => {
                if !account.edge_devices.is_empty() {
                    notes.push(format!(
                        "the binding of {key} names no Network Edge device of the account"
                    ));
                }
            }
            [d] => match out.get(&d.uuid) {
                Some(other) if *other != b.device => notes.push(format!(
                    "the Network Edge device {} has 2 bindings, to {other} and to {}",
                    d.name, b.device
                )),
                _ => {
                    out.insert(d.uuid.clone(), b.device.clone());
                }
            },
            many => notes.push(format!(
                "the binding of {key} names {} Network Edge devices",
                many.len()
            )),
        }
    }
    let mut by_device: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (uuid, device) in &out {
        by_device.entry(device).or_default().push(uuid);
    }
    for (device, list) in by_device {
        if list.len() > 1 {
            let names: Vec<&str> = list
                .iter()
                .filter_map(|u| account.edge_devices.iter().find(|d| d.uuid == *u))
                .map(|d| d.name.as_str())
                .collect();
            notes.push(format!(
                "the Network Edge devices {} are bound to one device {device}",
                names.join(", ")
            ));
        }
    }
    (out, notes)
}

/// The account ports of the members of the device link groups that the
/// account has.
pub fn group_ports(account: &Account) -> BTreeSet<String> {
    let by_uuid: BTreeMap<&str, &EdgeDevice> = account
        .edge_devices
        .iter()
        .map(|d| (d.uuid.as_str(), d))
        .collect();
    account
        .link_groups
        .iter()
        .flat_map(|g| members(g, &by_uuid))
        .filter(|m| m.local.is_some())
        .map(|m| m.port)
        .collect()
}

/// The id of a function of a device.
fn fid(device: &str, f: &str) -> FunctionId {
    FunctionId::new(format!("{device}/{f}"))
}

/// A sink: an `AclMatch` whose one unhandled rule gives `Unknown` with the
/// reason and the span.
pub fn sink(
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

/// The function after the account port `port` of a Network Edge interface:
/// the ingress function of its link peer, else a sink with the reason. The
/// sink goes into `functions`.
pub fn peer_of(
    device: &str,
    profile: &VendorProfile,
    port: &str,
    e: &EdgePort,
    edge_name: &str,
    peers: &BTreeMap<String, FunctionId>,
    functions: &mut Vec<Arc<dyn NetFunction>>,
) -> FunctionId {
    if let Some(p) = peers.get(port) {
        return p.clone();
    }
    let f = format!("{port}/unbound");
    functions.push(sink(
        device,
        profile,
        &f,
        &format!(
            "the Network Edge interface {edge_name} {} has no link",
            e.interface
        ),
        &e.span,
    ));
    fid(device, &f)
}

/// The predicate of a tagged frame as an upper bound with an empty definite
/// match: a rule with it gives `Unknown` for a tagged frame.
fn tagged_bound() -> RulePredicate {
    RulePredicate::bounded(
        Match {
            vlan: PortCond::In(Vec::new()),
            ..Match::any()
        },
        Match {
            vlan: PortCond::In(vec![(0, 4095)]),
            ..Match::any()
        },
    )
}

/// The functions of the device link groups and the notes.
pub struct Groups {
    pub functions: Vec<Arc<dyn NetFunction>>,
    /// The account ports of the members of the account.
    pub ports: BTreeMap<String, EdgePort>,
    pub notes: Vec<String>,
}

/// One member of a group: its account port, and its interface when the
/// account has it.
struct Member<'a> {
    port: String,
    local: Option<(&'a EdgeDevice, &'a EdgeInterface)>,
    /// The text of the member.
    text: String,
}

/// The members of a group.
fn members<'a>(g: &'a LinkGroup, by_uuid: &BTreeMap<&str, &'a EdgeDevice>) -> Vec<Member<'a>> {
    g.members
        .iter()
        .map(|m| {
            let d: Option<&'a EdgeDevice> = by_uuid.get(m.device.as_str()).copied();
            let local = d.and_then(|d| {
                d.interface(None, Some(m.interface_id.as_str()))
                    .map(|i| (d, i))
            });
            match local {
                Some((d, i)) => Member {
                    port: port_name(d, i),
                    local,
                    text: format!("{} {}", d.name, i.name),
                },
                None => Member {
                    port: format!("ne-{}/{}", m.device, m.interface_id),
                    local: None,
                    text: format!("{} interface {}", m.device, m.interface_id),
                },
            }
        })
        .collect()
}

/// Lowers the device link groups of an account. `circuit_ports` holds the
/// account ports that a circuit uses. A group whose state is not handled,
/// or with a member port that a circuit or another group uses, gives
/// `Unknown` for the frames of its members.
pub fn groups(
    account: &Account,
    profile: &VendorProfile,
    peers: &BTreeMap<String, FunctionId>,
    circuit_ports: &BTreeSet<String>,
) -> Groups {
    let device = account.device.as_str();
    let mut out = Groups {
        functions: Vec::new(),
        ports: BTreeMap::new(),
        notes: Vec::new(),
    };
    let by_uuid: BTreeMap<&str, &EdgeDevice> = account
        .edge_devices
        .iter()
        .map(|d| (d.uuid.as_str(), d))
        .collect();
    // The groups of each account port.
    let mut uses: BTreeMap<String, usize> = BTreeMap::new();
    for g in &account.link_groups {
        for m in members(g, &by_uuid) {
            if m.local.is_some() {
                *uses.entry(m.port).or_default() += 1;
            }
        }
    }
    for g in &account.link_groups {
        let name = g.name.clone().unwrap_or_else(|| g.uuid.clone());
        let members = members(g, &by_uuid);
        let shared = members
            .iter()
            .find(|m| m.local.is_some() && (uses[&m.port] > 1 || circuit_ports.contains(&m.port)));
        let reason = match (g.status.as_deref(), shared) {
            (_, Some(m)) => {
                let r = format!(
                    "the Network Edge interface {} is in more than one circuit or device link group",
                    m.text
                );
                out.notes.push(format!("{}: {r}", g.uuid));
                Some(r)
            }
            (Some(GROUP_STATUS), None) => None,
            (Some(s), None) => Some(format!(
                "the state {s} of the device link group {name} is not handled"
            )),
            (None, None) => Some(format!("the device link group {name} has no state")),
        };
        for m in &members {
            if let Some((d, i)) = m.local {
                out.ports.insert(
                    m.port.clone(),
                    EdgePort {
                        device: d.uuid.clone(),
                        interface: i.name.clone(),
                        mac: i.mac,
                        span: g.span.clone(),
                    },
                );
            }
        }
        if let Some(r) = reason {
            for m in members.iter().filter(|m| m.local.is_some()) {
                out.functions.push(sink(
                    device,
                    profile,
                    &format!("{}/in", m.port),
                    &r,
                    &g.span,
                ));
            }
            continue;
        }
        let bd = BridgeDomainId::new(format!("{device}/link-group/{}", g.uuid));
        let mac_f = fid(device, &format!("link-group/{}/mac", g.uuid));
        let unknown_f = fid(device, &format!("link-group/{}/unknown", g.uuid));
        let flood_f = fid(device, &format!("link-group/{}/flood", g.uuid));
        let mut egress: BTreeMap<PortId, FunctionId> = BTreeMap::new();
        let mut flood_ports: Vec<(PortId, FunctionId)> = Vec::new();
        let mut table: BTreeMap<Mac, MacEntry> = BTreeMap::new();
        let mut repeated: BTreeSet<Mac> = BTreeSet::new();
        for m in &members {
            let port = PortId::new(&m.port);
            let out_f = match m.local {
                Some((d, i)) => {
                    let e = &out.ports[&m.port];
                    let gate = format!("{}/in", m.port);
                    let ingress = format!("{}/ingress", m.port);
                    let out_name = format!("{}/out", m.port);
                    out.functions.push(Arc::new(AclMatch {
                        meta: Meta::new(fid(device, &gate), device, profile)
                            .with_span(g.span.clone()),
                        acl: ObjectId::new(format!("{device}:{}", m.port)),
                        rules: vec![
                            Rule::new("tagged frames", tagged_bound(), RuleAction::Deny)
                                .with_span(g.span.clone()),
                            Rule::new(
                                "untagged frames",
                                RulePredicate::exact(Match::any()),
                                RuleAction::Permit,
                            )
                            .with_span(g.span.clone()),
                        ],
                        default: RuleAction::Deny,
                        next: fid(device, &ingress),
                    }));
                    out.functions.push(Arc::new(PortIngress {
                        meta: Meta::new(fid(device, &ingress), device, profile)
                            .with_span(g.span.clone()),
                        port: port.clone(),
                        native: Some(bd.clone()),
                        tagged: BTreeMap::new(),
                        next: mac_f.clone(),
                    }));
                    let target = peer_of(
                        device,
                        profile,
                        &m.port,
                        e,
                        &d.name,
                        peers,
                        &mut out.functions,
                    );
                    out.functions.push(Arc::new(PortEgress {
                        meta: Meta::new(fid(device, &out_name), device, profile)
                            .with_span(g.span.clone()),
                        port: port.clone(),
                        native: Some(bd.clone()),
                        tagged: BTreeMap::new(),
                        peers: vec![PortPeer { target, link: None }],
                        hosts: BTreeMap::new(),
                    }));
                    if let Some(mac) = i.mac {
                        let entry = MacEntry {
                            port: port.clone(),
                            spans: vec![d.span.clone()],
                        };
                        if table.insert(mac, entry).is_some() {
                            repeated.insert(mac);
                        }
                    }
                    fid(device, &out_name)
                }
                None => {
                    let f = format!("link-group/{}/outside/{}", g.uuid, m.port);
                    out.functions.push(sink(
                        device,
                        profile,
                        &f,
                        &format!(
                            "the member {} of the device link group {name} is outside the account",
                            m.text
                        ),
                        &g.span,
                    ));
                    fid(device, &f)
                }
            };
            egress.insert(port.clone(), out_f.clone());
            flood_ports.push((port, out_f));
        }
        for mac in &repeated {
            table.remove(mac);
            out.notes.push(format!(
                "{}: the MAC {mac:?} is on more than one member of the device link group {name}",
                g.uuid
            ));
        }
        out.functions.push(Arc::new(MacLookup {
            meta: Meta::new(mac_f.clone(), device, profile).with_span(g.span.clone()),
            tables: BTreeMap::from([(bd.clone(), table)]),
            egress,
            flood: unknown_f.clone(),
            hairpin: BTreeSet::new(),
            blocked: BTreeMap::new(),
        }));
        let rules = if members.len() == 2 {
            vec![
                Rule::new(
                    "each frame to the other member",
                    RulePredicate::exact(Match::any()),
                    RuleAction::Permit,
                )
                .with_span(g.span.clone()),
            ]
        } else {
            vec![
                Rule::new(
                    "broadcast",
                    RulePredicate::exact(Match {
                        dst_mac: MacCond::In(BTreeSet::from([BROADCAST])),
                        ..Match::any()
                    }),
                    RuleAction::Permit,
                )
                .with_span(g.span.clone()),
                Rule::unhandled(
                    format!("the destination MAC is on no member of the device link group {name}"),
                    g.span.clone(),
                ),
            ]
        };
        out.functions.push(Arc::new(AclMatch {
            meta: Meta::new(unknown_f.clone(), device, profile).with_span(g.span.clone()),
            acl: ObjectId::new(format!("{device}:link-group/{}", g.uuid)),
            rules,
            default: RuleAction::Deny,
            next: flood_f.clone(),
        }));
        out.functions.push(Arc::new(Flood {
            meta: Meta::new(flood_f, device, profile).with_span(g.span.clone()),
            ports: BTreeMap::from([(bd, flood_ports)]),
        }));
    }
    out
}

/// The functions of the twin device of each Network Edge device that no
/// binding names: a sink for each interface of an account port.
pub fn unbound_devices(
    account: &Account,
    profile: &VendorProfile,
    ports: &BTreeMap<String, EdgePort>,
    bound: &BTreeMap<String, String>,
) -> Vec<Arc<dyn NetFunction>> {
    let mut out = Vec::new();
    let mut done: BTreeSet<(String, String)> = BTreeSet::new();
    for e in ports.values() {
        if bound.contains_key(&e.device) {
            continue;
        }
        let Some(d) = account.edge_devices.iter().find(|d| d.uuid == e.device) else {
            continue;
        };
        if !done.insert((e.device.clone(), e.interface.clone())) {
            continue;
        }
        let twin = twin_device(&account.device, d);
        out.push(sink(
            &twin,
            profile,
            &format!("{}/in", e.interface),
            &format!("the Network Edge device {} is not collected", d.name),
            &d.span,
        ));
    }
    out
}
