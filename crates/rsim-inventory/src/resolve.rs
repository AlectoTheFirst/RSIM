//! The inheritance of the settings: a device setting, else the setting of
//! its group, else the default.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::types::{
    CaptureBgp, Device, Group, Ha, Inventory, NetworkEdge, NxosJson, Settings, SshAlgorithms,
    SshMode, TlsTrust,
};

/// The time for all sections of a device, in seconds, with no setting.
pub const DEFAULT_TIMEOUT_SECONDS: u32 = 45;
/// The time for one section, in seconds, with no setting.
pub const DEFAULT_SECTION_TIMEOUT_SECONDS: u32 = 20;
/// The time for one HTTP request, in seconds, with no setting.
pub const DEFAULT_REQUEST_TIMEOUT_SECONDS: u32 = 60;
/// The time for the read of all pages of one section, in seconds, with no
/// setting.
pub const DEFAULT_PAGED_SECTION_TIMEOUT_SECONDS: u32 = 300;
/// The time between 2 collections of a device, in seconds, with no
/// setting.
pub const DEFAULT_INTERVAL_SECONDS: u32 = 60;
/// The requests in flight to an orchestrator with no setting.
pub const DEFAULT_CONCURRENCY: u32 = 4;
/// The seconds after which the modules of an edge are read again, with no
/// setting.
pub const DEFAULT_REFRESH_SECONDS: u32 = 1800;

/// The items of one page of an Equinix read with no setting.
pub const DEFAULT_PAGE_SIZE: u32 = 100;

/// The time between 2 collections and the time for all sections of an
/// Equinix account, in seconds, with no setting.
pub const EQUINIX_DEFAULT_SECONDS: u32 = 900;

/// The TLS trust of a vendor with no setting: the public roots for
/// `velocloud` and `equinix`, else the pin.
pub fn default_tls_trust(vendor: &str) -> TlsTrust {
    if vendor == "velocloud" || vendor == "equinix" {
        TlsTrust::Public
    } else {
        TlsTrust::Pin
    }
}

/// The time between 2 collections of a device of a vendor, in seconds, with
/// no setting.
pub fn default_interval_seconds(vendor: &str) -> u32 {
    if vendor == "equinix" {
        EQUINIX_DEFAULT_SECONDS
    } else {
        DEFAULT_INTERVAL_SECONDS
    }
}

/// The time for all sections of a device of a vendor, in seconds, with no
/// setting.
pub fn default_timeout_seconds(vendor: &str) -> u32 {
    if vendor == "equinix" {
        EQUINIX_DEFAULT_SECONDS
    } else {
        DEFAULT_TIMEOUT_SECONDS
    }
}

/// Setting origin
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Device
    Device,
    /// Group
    Group,
    /// Default
    Default,
}

/// Resolved setting
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Resolved<T> {
    pub value: T,
    pub origin: Origin,
}

impl<T> Resolved<T> {
    /// True if the device or its group sets the value.
    pub fn is_set(&self) -> bool {
        self.origin != Origin::Default
    }
}

fn pick<T: Clone>(device: &Option<T>, group: &Option<T>, default: T) -> Resolved<T> {
    match (device, group) {
        (Some(v), _) => Resolved {
            value: v.clone(),
            origin: Origin::Device,
        },
        (None, Some(v)) => Resolved {
            value: v.clone(),
            origin: Origin::Group,
        },
        (None, None) => Resolved {
            value: default,
            origin: Origin::Default,
        },
    }
}

/// Resolved settings
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResolvedSettings {
    /// Credential
    pub credential: Resolved<Option<String>>,
    /// Route
    pub route: Resolved<Option<String>>,
    pub ssh_algorithms: Resolved<SshAlgorithms>,
    pub ssh_mode: Resolved<SshMode>,
    pub ssh_channels: Resolved<u32>,
    pub nxos_json: Resolved<NxosJson>,
    pub tls_trust: Resolved<TlsTrust>,
    pub tls_ca_file: Resolved<Option<String>>,
    pub capture_bgp: Resolved<CaptureBgp>,
    pub timeout_seconds: Resolved<u32>,
    pub section_timeout_seconds: Resolved<u32>,
    pub request_timeout_seconds: Resolved<u32>,
    pub paged_section_timeout_seconds: Resolved<u32>,
    pub retries: Resolved<u32>,
    pub ha: Resolved<Ha>,
    pub interval_seconds: Resolved<u32>,
    pub orchestrator_release: Resolved<Option<String>>,
    pub api_base: Resolved<Option<String>>,
    pub concurrency: Resolved<u32>,
    pub refresh_seconds: Resolved<u32>,
    pub network_edge: Resolved<NetworkEdge>,
    pub page_size: Resolved<u32>,
}

/// The settings of a device of a vendor that inherits from a group.
pub fn resolve_settings(device: &Settings, group: &Settings, vendor: &str) -> ResolvedSettings {
    let opt = |d: &Option<String>, g: &Option<String>| match (d, g) {
        (Some(v), _) => Resolved {
            value: Some(v.clone()),
            origin: Origin::Device,
        },
        (None, Some(v)) => Resolved {
            value: Some(v.clone()),
            origin: Origin::Group,
        },
        (None, None) => Resolved {
            value: None,
            origin: Origin::Default,
        },
    };
    ResolvedSettings {
        credential: opt(&device.credential, &group.credential),
        route: opt(&device.route, &group.route),
        ssh_algorithms: pick(
            &device.ssh_algorithms,
            &group.ssh_algorithms,
            SshAlgorithms::Modern,
        ),
        ssh_mode: pick(&device.ssh_mode, &group.ssh_mode, SshMode::Exec),
        ssh_channels: pick(&device.ssh_channels, &group.ssh_channels, 1),
        nxos_json: pick(&device.nxos_json, &group.nxos_json, NxosJson::Plain),
        tls_trust: pick(
            &device.tls_trust,
            &group.tls_trust,
            default_tls_trust(vendor),
        ),
        tls_ca_file: opt(&device.tls_ca_file, &group.tls_ca_file),
        capture_bgp: pick(
            &device.capture_bgp,
            &group.capture_bgp,
            CaptureBgp::Sessions,
        ),
        timeout_seconds: pick(
            &device.timeout_seconds,
            &group.timeout_seconds,
            default_timeout_seconds(vendor),
        ),
        section_timeout_seconds: pick(
            &device.section_timeout_seconds,
            &group.section_timeout_seconds,
            DEFAULT_SECTION_TIMEOUT_SECONDS,
        ),
        request_timeout_seconds: pick(
            &device.request_timeout_seconds,
            &group.request_timeout_seconds,
            DEFAULT_REQUEST_TIMEOUT_SECONDS,
        ),
        paged_section_timeout_seconds: pick(
            &device.paged_section_timeout_seconds,
            &group.paged_section_timeout_seconds,
            DEFAULT_PAGED_SECTION_TIMEOUT_SECONDS,
        ),
        retries: pick(&device.retries, &group.retries, 0),
        ha: pick(&device.ha, &group.ha, Ha::None),
        interval_seconds: pick(
            &device.interval_seconds,
            &group.interval_seconds,
            default_interval_seconds(vendor),
        ),
        orchestrator_release: opt(&device.orchestrator_release, &group.orchestrator_release),
        api_base: opt(&device.api_base, &group.api_base),
        concurrency: pick(&device.concurrency, &group.concurrency, DEFAULT_CONCURRENCY),
        refresh_seconds: pick(
            &device.refresh_seconds,
            &group.refresh_seconds,
            DEFAULT_REFRESH_SECONDS,
        ),
        network_edge: pick(&device.network_edge, &group.network_edge, NetworkEdge::Off),
        page_size: pick(&device.page_size, &group.page_size, DEFAULT_PAGE_SIZE),
    }
}

/// Resolved device
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResolvedDevice {
    pub name: String,
    pub group: String,
    /// Vendor
    pub vendor: String,
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub console_site: Option<String>,
    pub settings: ResolvedSettings,
}

/// Resolved devices
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResolvedDevices {
    pub version: u64,
    pub devices: Vec<ResolvedDevice>,
}

/// Resolves one device with its group.
pub fn resolve_device(device: &Device, group: &Group) -> ResolvedDevice {
    ResolvedDevice {
        name: device.name.clone(),
        group: group.name.clone(),
        vendor: group.vendor.clone(),
        address: device.address.clone(),
        site: device.site.clone(),
        location: device.location.clone(),
        console_site: device.console_site.clone(),
        settings: resolve_settings(&device.settings, &group.settings, &group.vendor),
    }
}

impl Inventory {
    pub fn group(&self, name: &str) -> Option<&Group> {
        self.groups.iter().find(|g| g.name == name)
    }

    pub fn route(&self, name: &str) -> Option<&crate::types::Route> {
        self.routes.iter().find(|r| r.name == name)
    }

    pub fn jump_host(&self, name: &str) -> Option<&crate::types::JumpHost> {
        self.jump_hosts.iter().find(|j| j.name == name)
    }

    pub fn credential(&self, name: &str) -> Option<&crate::types::Credential> {
        self.credentials.iter().find(|c| c.name == name)
    }

    /// Each device with its group resolved, in name order. A device whose
    /// group is not in the inventory is an error.
    pub fn resolve(&self) -> Result<Vec<ResolvedDevice>, String> {
        let mut out = Vec::with_capacity(self.devices.len());
        for d in &self.devices {
            let g = self.group(&d.group).ok_or_else(|| {
                format!(
                    "the group {} of the device {} is not known",
                    d.group, d.name
                )
            })?;
            out.push(resolve_device(d, g));
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(settings: Settings) -> Group {
        Group {
            name: "core".into(),
            vendor: "vyos".into(),
            description: None,
            settings,
        }
    }

    fn device(settings: Settings) -> Device {
        Device {
            name: "r1".into(),
            group: "core".into(),
            address: "192.0.2.1".into(),
            site: Some("ams".into()),
            location: None,
            console_site: None,
            settings,
        }
    }

    #[test]
    fn a_device_setting_wins_over_the_group_and_the_group_over_the_default() {
        let g = group(Settings {
            credential: Some("vyos".into()),
            route: Some("bastion".into()),
            capture_bgp: Some(CaptureBgp::All),
            timeout_seconds: Some(90),
            ..Settings::default()
        });
        let d = device(Settings {
            route: Some("direct".into()),
            timeout_seconds: Some(120),
            ssh_mode: Some(SshMode::Shell),
            ..Settings::default()
        });
        let r = resolve_device(&d, &g);
        assert_eq!(r.vendor, "vyos");
        let s = r.settings;
        assert_eq!(s.credential.value.as_deref(), Some("vyos"));
        assert_eq!(s.credential.origin, Origin::Group);
        assert_eq!(s.route.value.as_deref(), Some("direct"));
        assert_eq!(s.route.origin, Origin::Device);
        assert_eq!(
            (s.timeout_seconds.value, s.timeout_seconds.origin),
            (120, Origin::Device)
        );
        assert_eq!(
            (
                s.section_timeout_seconds.value,
                s.section_timeout_seconds.origin
            ),
            (DEFAULT_SECTION_TIMEOUT_SECONDS, Origin::Default)
        );
        assert_eq!(s.capture_bgp.value, CaptureBgp::All);
        assert_eq!(s.ssh_mode.value, SshMode::Shell);
        assert_eq!(s.ssh_algorithms.value, SshAlgorithms::Modern);
        assert!(!s.ssh_algorithms.is_set());
    }

    #[test]
    fn the_defaults_are_no_retry_no_ha_assumption_and_a_direct_route() {
        let s = resolve_device(&device(Settings::default()), &group(Settings::default())).settings;
        assert_eq!(s.retries.value, 0);
        assert_eq!(s.ha.value, Ha::None);
        assert_eq!(s.route.value, None);
        assert_eq!(s.credential.value, None);
        assert_eq!(s.ssh_channels.value, 1);
        assert_eq!(s.tls_trust.value, TlsTrust::Pin);
        assert_eq!(s.capture_bgp.value, CaptureBgp::Sessions);
        assert_eq!(s.timeout_seconds.value, 45);
        assert_eq!(s.request_timeout_seconds.value, 60);
        assert_eq!(s.paged_section_timeout_seconds.value, 300);
        assert_eq!(s.network_edge.value, NetworkEdge::Off);
        assert_eq!(s.page_size.value, 100);
        assert_eq!(
            (s.interval_seconds.value, s.interval_seconds.origin),
            (60, Origin::Default)
        );
        assert_eq!(s.orchestrator_release.value, None);
        assert_eq!(s.api_base.value, None);
        assert_eq!(s.concurrency.value, 4);
        assert_eq!(s.refresh_seconds.value, 1800);
    }

    #[test]
    fn a_velocloud_device_with_no_tls_setting_takes_the_public_roots() {
        let mut g = group(Settings::default());
        g.vendor = "velocloud".into();
        let s = resolve_device(&device(Settings::default()), &g).settings;
        assert_eq!(
            (s.tls_trust.value, s.tls_trust.origin),
            (TlsTrust::Public, Origin::Default)
        );
        g.settings.tls_trust = Some(TlsTrust::Pin);
        let s = resolve_device(&device(Settings::default()), &g).settings;
        assert_eq!(
            (s.tls_trust.value, s.tls_trust.origin),
            (TlsTrust::Pin, Origin::Group)
        );
        g.vendor = "unifi".into();
        g.settings.tls_trust = None;
        let s = resolve_device(&device(Settings::default()), &g).settings;
        assert_eq!(s.tls_trust.value, TlsTrust::Pin);
    }

    #[test]
    fn an_equinix_account_with_no_setting_takes_its_vendor_defaults() {
        let mut g = group(Settings::default());
        g.vendor = "equinix".into();
        let s = resolve_device(&device(Settings::default()), &g).settings;
        assert_eq!(
            (s.tls_trust.value, s.tls_trust.origin),
            (TlsTrust::Public, Origin::Default)
        );
        assert_eq!(
            (s.interval_seconds.value, s.interval_seconds.origin),
            (900, Origin::Default)
        );
        assert_eq!(
            (s.timeout_seconds.value, s.timeout_seconds.origin),
            (900, Origin::Default)
        );
        assert_eq!(s.request_timeout_seconds.value, 60);
        assert_eq!(s.paged_section_timeout_seconds.value, 300);
    }

    #[test]
    fn the_interval_of_a_device_wins_over_its_group() {
        let g = group(Settings {
            interval_seconds: Some(300),
            ..Settings::default()
        });
        let s = resolve_device(&device(Settings::default()), &g).settings;
        assert_eq!(
            (s.interval_seconds.value, s.interval_seconds.origin),
            (300, Origin::Group)
        );
        let d = device(Settings {
            interval_seconds: Some(3_600),
            ..Settings::default()
        });
        let s = resolve_device(&d, &g).settings;
        assert_eq!(
            (s.interval_seconds.value, s.interval_seconds.origin),
            (3_600, Origin::Device)
        );
    }

    #[test]
    fn a_device_of_an_unknown_group_is_an_error() {
        let inv = Inventory {
            devices: vec![device(Settings::default())],
            ..Inventory::default()
        };
        assert!(inv.resolve().unwrap_err().contains("core"));
    }
}
