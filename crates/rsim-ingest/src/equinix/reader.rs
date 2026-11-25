//! The read of the Fabric ports, the connections, the Network Edge devices
//! and the device link groups of an account.

use std::collections::{BTreeMap, BTreeSet};

use rsim_core::{Mac, SourceSpan};

use crate::velocloud::json::{J, Parsed};

/// A Fabric port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Port {
    pub uuid: String,
    /// The name, else the uuid.
    pub name: String,
    pub state: Option<String>,
    /// `encapsulation.type`.
    pub encapsulation: Option<String>,
    /// `encapsulation.tagProtocolId` as written.
    pub tpid: Option<String>,
    pub ibx: Option<String>,
    pub metro: Option<String>,
    pub bandwidth: Option<i64>,
    pub lag: Option<String>,
    /// The cross connect ids: sorted, unique, uppercase, and cut at the
    /// first `-`, as in HST.
    pub cross_connects: Vec<String>,
    /// The reason when the repeated items of the port differ.
    pub conflict: Option<String>,
    pub span: SourceSpan,
}

/// The kind of a circuit end.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EndKind {
    /// A `COLO` end on the Fabric port with this uuid.
    Port(String),
    /// An `SP` end with the name of its service profile, else its uuid.
    ServiceProfile(String),
    /// A `VD` end on an interface of a Network Edge device.
    Device {
        /// The uuid of the device.
        device: String,
        /// The uuid of the interface.
        interface: Option<String>,
        /// The id of the interface.
        interface_id: Option<String>,
    },
    /// Another type.
    Other(String),
    /// An end with no type, or a `COLO` end with no port uuid.
    Missing,
}

/// One end of a connection.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct End {
    pub kind: EndKind,
    /// `linkProtocol.type`.
    pub protocol: Option<String>,
    pub tag: Option<i64>,
    pub s_tag: Option<i64>,
    pub c_tag: Option<i64>,
}

/// A connection item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    pub uuid: String,
    pub name: Option<String>,
    /// `type`.
    pub kind: Option<String>,
    pub state: Option<String>,
    pub bandwidth: Option<i64>,
    pub a: End,
    pub z: End,
    pub span: SourceSpan,
}

/// A binding of a Fabric port to a port of a device of the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The uuid or the name of the Fabric port.
    pub fabric_port: String,
    pub device: String,
    pub port: String,
    pub span: SourceSpan,
}

/// A binding of a Network Edge device to a device of the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeBinding {
    /// The uuid, the name or the host name of the Network Edge device.
    pub edge_device: String,
    pub device: String,
    pub span: SourceSpan,
}

/// An interface of a Network Edge device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeInterface {
    pub id: Option<String>,
    pub uuid: Option<String>,
    pub name: String,
    /// `type`, for example `DATA` or `SSH`.
    pub kind: Option<String>,
    pub mac: Option<Mac>,
}

/// A Network Edge device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeDevice {
    pub uuid: String,
    /// The name, else the host name, else the uuid.
    pub name: String,
    pub host_name: Option<String>,
    pub vendor: Option<String>,
    /// `deviceTypeCode`.
    pub model: Option<String>,
    /// `deviceTypeCategory`.
    pub category: Option<String>,
    pub status: Option<String>,
    pub version: Option<String>,
    pub ibx: Option<String>,
    pub metro: Option<String>,
    /// `redundancyType`.
    pub redundancy: Option<String>,
    /// The interfaces with a name.
    pub interfaces: Vec<EdgeInterface>,
    pub span: SourceSpan,
}

impl EdgeDevice {
    /// The interface with the uuid `uuid`, else with the id `id`.
    pub fn interface(&self, uuid: Option<&str>, id: Option<&str>) -> Option<&EdgeInterface> {
        uuid.and_then(|u| {
            self.interfaces
                .iter()
                .find(|i| i.uuid.as_deref() == Some(u))
        })
        .or_else(|| id.and_then(|n| self.interfaces.iter().find(|i| i.id.as_deref() == Some(n))))
    }
}

/// A member of a device link group: the uuid of its device and the id of
/// its interface.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinkMember {
    pub device: String,
    pub interface_id: String,
}

/// A device link group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkGroup {
    pub uuid: String,
    pub name: Option<String>,
    pub status: Option<String>,
    /// The members, sorted and unique.
    pub members: Vec<LinkMember>,
    /// The smallest `metroLinks[].throughput` with the unit `Mbps`.
    pub bandwidth_mbps: Option<i64>,
    pub span: SourceSpan,
}

/// The ports, the connections, the Network Edge devices, the device link
/// groups and the bindings of an account.
#[derive(Clone, Debug, Default)]
pub struct Account {
    pub device: String,
    pub ports: Vec<Port>,
    /// The items of `connections`, then the items of `edge_connections`.
    pub connections: Vec<Connection>,
    pub bindings: Vec<Binding>,
    pub edge_devices: Vec<EdgeDevice>,
    pub link_groups: Vec<LinkGroup>,
    pub edge_bindings: Vec<EdgeBinding>,
    pub notes: Vec<String>,
}

fn end(j: Option<J<'_>>) -> End {
    let ap = j.and_then(|s| s.obj("accessPoint"));
    let link = ap.and_then(|a| a.obj("linkProtocol"));
    let kind = match ap.and_then(|a| a.str("type")) {
        Some("COLO") => match ap.and_then(|a| a.obj("port")).and_then(|p| p.text("uuid")) {
            Some(u) => EndKind::Port(u),
            None => EndKind::Missing,
        },
        Some("SP") => {
            let profile = ap.and_then(|a| a.obj("profile"));
            EndKind::ServiceProfile(
                profile
                    .and_then(|p| p.text("name").or_else(|| p.text("uuid")))
                    .unwrap_or_default(),
            )
        }
        Some("VD") => {
            let interface = ap.and_then(|a| a.obj("interface"));
            EndKind::Device {
                device: ap
                    .and_then(|a| a.obj("virtualDevice"))
                    .and_then(|d| d.text("uuid"))
                    .unwrap_or_default(),
                interface: interface.and_then(|i| i.text("uuid")),
                interface_id: interface.and_then(|i| i.text("id")),
            }
        }
        Some(t) => EndKind::Other(t.to_string()),
        None => EndKind::Missing,
    };
    End {
        kind,
        protocol: link.and_then(|l| l.text("type")),
        tag: link.and_then(|l| l.int("vlanTag")),
        s_tag: link.and_then(|l| l.int("vlanSTag")),
        c_tag: link.and_then(|l| l.int("vlanCTag")),
    }
}

/// The cross connect ids of a port.
fn cross_connects(p: J<'_>) -> Vec<String> {
    let mut ids: Vec<String> = p
        .list("physicalPorts")
        .into_iter()
        .filter_map(|x| x.obj("tether")?.text("crossConnectId"))
        .map(|id| {
            let id = id.trim().to_uppercase();
            id.split('-').next().unwrap_or_default().to_string()
        })
        .filter(|id| !id.is_empty())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// The first item of each port uuid, in the order of the items. A port whose
/// items differ in a field other than the span gets a conflict and a note.
fn unique(ports: Vec<Port>, notes: &mut Vec<String>) -> Vec<Port> {
    let mut out: Vec<Port> = Vec::new();
    // The count of the items of each port of `out`, and whether they differ.
    let mut items: Vec<(usize, bool)> = Vec::new();
    let mut at: BTreeMap<String, usize> = BTreeMap::new();
    for p in ports {
        match at.get(&p.uuid) {
            Some(&i) => {
                let first = &out[i];
                let same = Port {
                    span: first.span.clone(),
                    ..p
                } == *first;
                items[i].0 += 1;
                items[i].1 |= !same;
            }
            None => {
                at.insert(p.uuid.clone(), out.len());
                out.push(p);
                items.push((1, false));
            }
        }
    }
    for (p, (n, differ)) in out.iter_mut().zip(items) {
        if differ {
            let r = format!("the {n} items of the Fabric port {} differ", p.uuid);
            notes.push(r.clone());
            p.conflict = Some(r);
        }
    }
    out
}

/// Reads the Fabric ports, the connections and the bindings of the sections
/// of an account. An item with no `uuid` is left out with a note, and so is
/// a binding with no Fabric port, device or port. A port has one entry for
/// each uuid.
pub fn read(device: &str, p: &Parsed) -> Account {
    let mut a = Account {
        device: device.to_string(),
        ..Account::default()
    };
    for (n, x) in p
        .root("ports")
        .map(J::rows)
        .unwrap_or_default()
        .into_iter()
        .enumerate()
    {
        let Some(uuid) = x.text("uuid") else {
            a.notes.push(format!("ports: item {} has no uuid", n + 1));
            continue;
        };
        let enc = x.obj("encapsulation");
        let loc = x.obj("location");
        a.ports.push(Port {
            name: x.text("name").unwrap_or_else(|| uuid.clone()),
            state: x.text("state"),
            encapsulation: enc.and_then(|e| e.text("type")),
            tpid: enc.and_then(|e| e.text("tagProtocolId")),
            ibx: loc.and_then(|l| l.text("ibx")),
            metro: loc.and_then(|l| l.text("metroCode")),
            bandwidth: x.int("bandwidth").filter(|b| *b > 0),
            lag: x.obj("lag").and_then(|l| l.text("name")),
            cross_connects: cross_connects(x),
            conflict: None,
            span: x.span(),
            uuid,
        });
    }
    a.ports = unique(std::mem::take(&mut a.ports), &mut a.notes);
    for section in ["connections", "edge_connections"] {
        for (n, x) in p
            .root(section)
            .map(J::rows)
            .unwrap_or_default()
            .into_iter()
            .enumerate()
        {
            let Some(uuid) = x.text("uuid") else {
                a.notes
                    .push(format!("{section}: item {} has no uuid", n + 1));
                continue;
            };
            a.connections.push(Connection {
                uuid,
                name: x.text("name"),
                kind: x.text("type"),
                state: x.text("state"),
                bandwidth: x.int("bandwidth").filter(|b| *b > 0),
                a: end(x.obj("aSide")),
                z: end(x.obj("zSide")),
                span: x.span(),
            });
        }
    }
    a.edge_devices = edge_devices(p, &mut a.notes);
    a.link_groups = link_groups(p, &mut a.notes);
    for (n, x) in p
        .root("bindings")
        .map(J::rows)
        .unwrap_or_default()
        .into_iter()
        .enumerate()
    {
        if let Some(edge_device) = x.text("edge_device") {
            match x.text("device") {
                Some(device) => a.edge_bindings.push(EdgeBinding {
                    edge_device,
                    device,
                    span: x.span(),
                }),
                None => a
                    .notes
                    .push(format!("bindings: item {} is not complete", n + 1)),
            }
            continue;
        }
        match (x.text("fabric_port"), x.text("device"), x.text("port")) {
            (Some(fabric_port), Some(device), Some(port)) => a.bindings.push(Binding {
                fabric_port,
                device,
                port,
                span: x.span(),
            }),
            _ => a
                .notes
                .push(format!("bindings: item {} is not complete", n + 1)),
        }
    }
    a
}

/// The Network Edge devices of `edge_devices`, one for each uuid. An item
/// with no uuid and a repeated uuid are left out with a note.
fn edge_devices(p: &Parsed, notes: &mut Vec<String>) -> Vec<EdgeDevice> {
    let mut out: Vec<EdgeDevice> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (n, x) in p
        .root("edge_devices")
        .map(J::rows)
        .unwrap_or_default()
        .into_iter()
        .enumerate()
    {
        let Some(uuid) = x.text("uuid") else {
            notes.push(format!("edge_devices: item {} has no uuid", n + 1));
            continue;
        };
        if !seen.insert(uuid.clone()) {
            notes.push(format!(
                "edge_devices: the Network Edge device {uuid} is in more than one item"
            ));
            continue;
        }
        let interfaces = x
            .list("interfaces")
            .into_iter()
            .filter_map(|i| {
                Some(EdgeInterface {
                    name: i.text("name")?,
                    id: i.text("id"),
                    uuid: i.text("uuid"),
                    kind: i.text("type"),
                    mac: i.str("macAddress").and_then(|m| m.trim().parse().ok()),
                })
            })
            .collect();
        let host_name = x.text("hostName");
        out.push(EdgeDevice {
            name: x
                .text("name")
                .or_else(|| host_name.clone())
                .unwrap_or_else(|| uuid.clone()),
            host_name,
            vendor: x.text("deviceTypeVendor"),
            model: x.text("deviceTypeCode"),
            category: x.text("deviceTypeCategory"),
            status: x.text("status"),
            version: x.text("version"),
            ibx: x.text("ibx"),
            metro: x.text("metroCode"),
            redundancy: x.text("redundancyType"),
            interfaces,
            span: x.span(),
            uuid,
        });
    }
    out
}

/// The device link groups of `edge_links`. An item with no uuid and a
/// member with no device or interface id are left out with a note.
fn link_groups(p: &Parsed, notes: &mut Vec<String>) -> Vec<LinkGroup> {
    let mut out = Vec::new();
    for (n, x) in p
        .root("edge_links")
        .map(J::rows)
        .unwrap_or_default()
        .into_iter()
        .enumerate()
    {
        let Some(uuid) = x.text("uuid") else {
            notes.push(format!("edge_links: item {} has no uuid", n + 1));
            continue;
        };
        let mut members: Vec<LinkMember> = Vec::new();
        for (k, m) in x.list("linkDevices").into_iter().enumerate() {
            match (m.text("deviceUuid"), m.text("interfaceId")) {
                (Some(device), Some(interface_id)) => members.push(LinkMember {
                    device,
                    interface_id,
                }),
                _ => notes.push(format!(
                    "edge_links: member {} of the device link group {uuid} has no device or interface id",
                    k + 1
                )),
            }
        }
        members.sort();
        members.dedup();
        let bandwidth_mbps = x
            .list("metroLinks")
            .into_iter()
            .filter(|l| {
                l.str("throughputUnit")
                    .is_some_and(|u| u.eq_ignore_ascii_case("mbps"))
            })
            .filter_map(|l| l.int("throughput"))
            .filter(|t| *t > 0)
            .min();
        out.push(LinkGroup {
            name: x.text("groupName"),
            status: x.text("status"),
            members,
            bandwidth_mbps,
            span: x.span(),
            uuid,
        });
    }
    out
}
