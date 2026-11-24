//! Equinix Fabric: one store device and one twin device for each account.
//! The Fabric ports are the ports of the device, and each circuit joins the
//! tags of its 2 ends.

pub mod coverage;
pub mod lower;
pub mod profile;
pub mod reader;

pub use lower::{CircuitRow, Lowered, PortPlan, Verdict, lower};
pub use profile::profile;
pub use reader::{Account, Connection, End, EndKind, Port, read};

/// The sections of an account device.
pub const SECTIONS: &[&str] = &[
    "ports",
    "connections",
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
