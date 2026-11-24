//! The read of the Fabric ports and the connections of an account.

use rsim_core::SourceSpan;

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
    pub span: SourceSpan,
}

/// The kind of a circuit end.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EndKind {
    /// A `COLO` end on the Fabric port with this uuid.
    Port(String),
    /// An `SP` end with the name of its service profile, else its uuid.
    ServiceProfile(String),
    /// A `VD` end on a Network Edge device.
    Device(String),
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

/// The ports and the connections of an account.
#[derive(Clone, Debug, Default)]
pub struct Account {
    pub device: String,
    pub ports: Vec<Port>,
    pub connections: Vec<Connection>,
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
        Some("VD") => EndKind::Device(
            ap.and_then(|a| a.obj("virtualDevice"))
                .and_then(|d| d.text("uuid"))
                .unwrap_or_default(),
        ),
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

/// Reads the Fabric ports and the connections of the sections of an
/// account. An item with no `uuid` is left out with a note.
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
            span: x.span(),
            uuid,
        });
    }
    for (n, x) in p
        .root("connections")
        .map(J::rows)
        .unwrap_or_default()
        .into_iter()
        .enumerate()
    {
        let Some(uuid) = x.text("uuid") else {
            a.notes
                .push(format!("connections: item {} has no uuid", n + 1));
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
    a
}
