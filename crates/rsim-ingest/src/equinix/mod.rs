//! Equinix Fabric: one store device and one twin device for each account.
//! The Fabric ports are the ports of the device, and each circuit joins the
//! tags of its 2 ends.

pub mod coverage;
pub mod lower;
pub mod profile;
pub mod reader;

pub use lower::{CircuitRow, Lowered, PortPlan, Verdict, lower};
pub use profile::profile;
pub use reader::{Account, Binding, Connection, End, EndKind, Port, read};

/// The summary of an account for the join: the gate of each Fabric port
/// as its entry, and a binding record for each binding whose Fabric port
/// is a port of the account, by uuid or by name. A binding that names no
/// Fabric port gives a note.
pub fn summary(account: &Account) -> (crate::links::Summary, Vec<String>) {
    let mut s = crate::links::Summary::default();
    let mut notes = Vec::new();
    for p in &account.ports {
        let port = format!("port/{}", p.uuid);
        s.entries.insert(
            port.clone(),
            rsim_core::FunctionId::new(format!("{}/{port}/in", account.device)),
        );
        s.port_spans.insert(port, p.span.clone());
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
    (s, notes)
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
