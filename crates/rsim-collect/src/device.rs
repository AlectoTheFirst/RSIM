use std::fmt;

use crate::path::Route;

/// The vendor of a device. Each vendor has one source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Vendor {
    Vyos,
    Unifi,
    Nxos,
    Iosxr,
    Iosxe,
}

impl Vendor {
    /// All vendors.
    pub const ALL: [Vendor; 5] = [
        Vendor::Vyos,
        Vendor::Unifi,
        Vendor::Nxos,
        Vendor::Iosxr,
        Vendor::Iosxe,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Vendor::Vyos => "vyos",
            Vendor::Unifi => "unifi",
            Vendor::Nxos => "nxos",
            Vendor::Iosxr => "iosxr",
            Vendor::Iosxe => "iosxe",
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
    /// The BGP sections of a router. UniFi has none.
    pub capture_bgp: CaptureBgp,
    /// The proxy and the jump hosts to the device.
    pub route: Route,
}

/// What the collector reads of the BGP of a router.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CaptureBgp {
    /// No BGP section.
    Off,
    /// The summary of each session.
    #[default]
    Sessions,
    /// The summaries, the neighbour detail and the tables of each neighbour.
    All,
}

impl CaptureBgp {
    /// The setting of a word: `off`, `sessions` or `all`.
    pub fn parse(word: &str) -> Option<CaptureBgp> {
        match word {
            "off" => Some(CaptureBgp::Off),
            "sessions" => Some(CaptureBgp::Sessions),
            "all" => Some(CaptureBgp::All),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            CaptureBgp::Off => "off",
            CaptureBgp::Sessions => "sessions",
            CaptureBgp::All => "all",
        }
    }

    /// True if the source reads the session sections.
    pub fn sessions(self) -> bool {
        self != CaptureBgp::Off
    }

    /// True if the source reads the neighbour detail and the tables.
    pub fn all(self) -> bool {
        self == CaptureBgp::All
    }
}

/// The devices to collect.
pub trait Inventory: Send + Sync {
    fn devices(&self) -> Vec<Device>;

    /// The version of the inventory database that gave the devices. The
    /// snapshot manifest records it. `None` with no inventory database.
    fn version(&self) -> Option<u64> {
        None
    }
}

impl Inventory for Vec<Device> {
    fn devices(&self) -> Vec<Device> {
        self.clone()
    }
}

/// The devices of one read of the inventory database, with its version.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InventoryList {
    pub devices: Vec<Device>,
    pub version: Option<u64>,
}

impl Inventory for InventoryList {
    fn devices(&self) -> Vec<Device> {
        self.devices.clone()
    }

    fn version(&self) -> Option<u64> {
        self.version
    }
}
