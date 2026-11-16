use std::fmt;

/// The vendor of a device. Each vendor has one source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Vendor {
    Vyos,
    Unifi,
}

impl Vendor {
    pub fn name(self) -> &'static str {
        match self {
            Vendor::Vyos => "vyos",
            Vendor::Unifi => "unifi",
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
