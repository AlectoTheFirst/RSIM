use std::fmt;

use crate::path::Route;

/// The vendor of a device. Each vendor has one source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Vendor {
    Vyos,
    Unifi,
    Nxos,
}

impl Vendor {
    /// All vendors.
    pub const ALL: [Vendor; 3] = [Vendor::Vyos, Vendor::Unifi, Vendor::Nxos];

    pub fn name(self) -> &'static str {
        match self {
            Vendor::Vyos => "vyos",
            Vendor::Unifi => "unifi",
            Vendor::Nxos => "nxos",
        }
    }
}

impl fmt::Display for Vendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A device to collect. For UniFi, the device is one site of a console,
/// and one read of the site gives all its switches and access points.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Device {
    /// The unique name of the device in the store.
    pub id: String,
    pub vendor: Vendor,
    /// The host name or the address of the management plane.
    pub address: String,
    /// The name of the credential in the credential source. The store does
    /// not hold credentials.
    pub credential: String,
    /// The UniFi site. `None` for the other vendors.
    pub site: Option<String>,
    /// The proxy and the jump hosts to the device.
    pub route: Route,
}

/// The devices to collect.
pub trait Inventory: Send + Sync {
    fn devices(&self) -> Vec<Device>;
}

impl Inventory for Vec<Device> {
    fn devices(&self) -> Vec<Device> {
        self.clone()
    }
}
