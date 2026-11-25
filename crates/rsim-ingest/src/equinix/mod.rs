//! Equinix Fabric: one store device and one twin device for each account.
//! The Fabric ports are the ports of the device, and each circuit joins the
//! tags of its 2 ends.

pub mod coverage;
pub mod edge;
pub mod lower;
pub mod profile;
pub mod reader;

pub use edge::EdgePort;
pub use lower::{CircuitRow, Lowered, PortPlan, Verdict, lower};
pub use profile::profile;
pub use reader::{
    Account, Binding, Connection, EdgeBinding, EdgeDevice, EdgeInterface, End, EndKind, LinkGroup,
    LinkMember, Port, read,
};

/// A Network Edge interface of a bound device. The estate binds its account
/// port to the one port of the device of the store with its MAC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacBinding {
    /// The account port of the interface.
    pub port: String,
    /// The device of the store.
    pub device: String,
    pub mac: Option<rsim_core::Mac>,
    /// The Network Edge device and the interface as text.
    pub text: String,
    pub span: rsim_core::SourceSpan,
}

/// The summaries of an account for the join.
#[derive(Debug, Default)]
pub struct Summaries {
    /// The summary of the account device.
    pub account: crate::links::Summary,
    /// The summary of the twin device of each Network Edge device that no
    /// binding names, by device.
    pub devices: std::collections::BTreeMap<String, crate::links::Summary>,
    pub macs: Vec<MacBinding>,
    pub notes: Vec<String>,
}

/// The summaries of an account for the join. The account summary has the
/// gate of each Fabric port and the entry of each Network Edge interface
/// as its entries, a binding record for each binding whose Fabric port is a
/// port of the account, by uuid or by name, a binding record from each
/// Network Edge interface of a device that no binding names to the port of
/// its twin device, and a transit for each lowered circuit with one tag at
/// each end. A binding that names no Fabric port gives a note.
pub fn summary(account: &Account) -> Summaries {
    let mut s = crate::links::Summary::default();
    let mut notes = Vec::new();
    let mut devices: std::collections::BTreeMap<String, crate::links::Summary> =
        std::collections::BTreeMap::new();
    let mut macs = Vec::new();
    for p in &account.ports {
        let port = format!("port/{}", p.uuid);
        s.entries.insert(
            port.clone(),
            rsim_core::FunctionId::new(format!("{}/{port}/in", account.device)),
        );
        s.port_spans.insert(port.clone(), p.span.clone());
        s.fabric_ports.push(crate::links::FabricPortName {
            port,
            name: p.name.clone(),
            cross_connects: p.cross_connects.clone(),
        });
    }
    for b in &account.bindings {
        let found = account
            .ports
            .iter()
            .find(|p| p.uuid == b.fabric_port)
            .or_else(|| account.ports.iter().find(|p| p.name == b.fabric_port));
        match found {
            Some(p) => s.bindings.push(crate::links::Binding {
                port: format!("port/{}", p.uuid),
                device: b.device.clone(),
                far_port: b.port.clone(),
                span: b.span.clone(),
            }),
            None => notes.push(format!(
                "the binding of {} names no Fabric port of the account",
                b.fabric_port
            )),
        }
    }
    let low = lower(account, &profile(), &std::collections::BTreeMap::new());
    for (port, e) in &low.edge_ports {
        s.entries.insert(
            port.clone(),
            rsim_core::FunctionId::new(format!("{}/{port}/in", account.device)),
        );
        s.port_spans.insert(port.clone(), e.span.clone());
        let Some(d) = account.edge_devices.iter().find(|d| d.uuid == e.device) else {
            continue;
        };
        let text = format!("{} {}", d.name, e.interface);
        match low.bound.get(&e.device) {
            Some(device) => macs.push(MacBinding {
                port: port.clone(),
                device: device.clone(),
                mac: e.mac,
                text,
                span: d.span.clone(),
            }),
            None => {
                let twin = edge::twin_device(&account.device, d);
                s.bindings.push(crate::links::Binding {
                    port: port.clone(),
                    device: twin.clone(),
                    far_port: e.interface.clone(),
                    span: d.span.clone(),
                });
                let t = devices.entry(twin.clone()).or_default();
                t.entries.insert(
                    e.interface.clone(),
                    rsim_core::FunctionId::new(format!("{twin}/{}/in", e.interface)),
                );
                t.port_spans.insert(e.interface.clone(), d.span.clone());
            }
        }
    }
    for (uuid, plan) in &low.ports {
        for leg in plan
            .legs
            .iter()
            .filter(|l| !l.port_based && l.near.inner.is_none())
        {
            // A leg to a Network Edge interface gives no transit.
            let rsim_functions::FarEnd::Port { port, tags, .. } = &leg.far else {
                continue;
            };
            if !port.as_str().starts_with("port/") {
                continue;
            }
            let here = format!("port/{uuid}");
            if tags.inner.is_some() || here.as_str() >= port.as_str() {
                continue;
            }
            s.transits.push(crate::links::Transit {
                circuit: leg.circuit.clone(),
                a: (here, leg.near.outer.vlan),
                b: (port.to_string(), tags.outer.vlan),
                span: leg.spans[0].clone(),
            });
        }
    }
    Summaries {
        account: s,
        devices,
        macs,
        notes,
    }
}

/// The binding records of the MAC bindings of an account, from the MAC of
/// each port of the bound devices, and the notes. A binding binds when
/// exactly one port of its device has the MAC.
pub fn mac_bindings(
    macs: &[MacBinding],
    summaries: &std::collections::BTreeMap<String, crate::links::Summary>,
) -> (Vec<crate::links::Binding>, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    for m in macs {
        let Some(sum) = summaries.get(&m.device) else {
            notes.push(format!(
                "the Network Edge interface {} is bound to {}, which the twin does not have",
                m.text, m.device
            ));
            continue;
        };
        let Some(mac) = m.mac else {
            notes.push(format!(
                "the Network Edge interface {} has no MAC, so it binds to no port of {}",
                m.text, m.device
            ));
            continue;
        };
        let found: Vec<&String> = sum
            .port_macs
            .iter()
            .filter(|(_, x)| **x == mac)
            .map(|(p, _)| p)
            .collect();
        match found.as_slice() {
            [p] => out.push(crate::links::Binding {
                port: m.port.clone(),
                device: m.device.clone(),
                far_port: (*p).clone(),
                span: m.span.clone(),
            }),
            [] => notes.push(format!(
                "no port of {} has the MAC {mac:?} of the Network Edge interface {}",
                m.device, m.text
            )),
            many => notes.push(format!(
                "{} ports of {} have the MAC {mac:?} of the Network Edge interface {}",
                many.len(),
                m.device,
                m.text
            )),
        }
    }
    (out, notes)
}

/// The sections of an account device.
pub const SECTIONS: &[&str] = &[
    "ports",
    "connections",
    "bindings",
    "edge_devices",
    "edge_links",
    "edge_connections",
];

/// The mask of an Equinix section: the secret rule of VeloCloud, with the
/// keys that end with `key`, such as `authenticationKey`.
pub const MASK: crate::mask::JsonMask = crate::mask::JsonMask {
    key: crate::velocloud::mask::secret_key,
    subtrees: &[],
    value_records: crate::mask::no_value_records,
};
