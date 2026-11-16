//! The handlers of a UniFi site: typed structures from the JSON sections of
//! the site.

use serde_json::Value;

/// A network of the site. Each network is one bridge domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    pub id: String,
    pub name: String,
    pub purpose: String,
    /// The VLAN of the network. `None` for the default network.
    pub vlan: Option<u16>,
    /// The network in CIDR form, if the controller gives one.
    pub subnet: Option<String>,
    pub isolation: bool,
    pub index: usize,
}

/// A WLAN: an SSID and its network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wlan {
    pub id: String,
    pub ssid: String,
    pub network: String,
    pub enabled: bool,
    /// Client isolation: the clients of the SSID cannot reach each other.
    pub isolation: bool,
    /// A guest policy is on.
    pub guest: bool,
    pub index: usize,
}

/// The forwarding mode of a switch port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forward {
    /// The native network and each other network with its tag.
    All,
    /// The native network only.
    Native,
    /// The native network and each network that is not excluded.
    Customize,
    Disabled,
    /// A mode that the handler does not know.
    Other,
}

/// A port of a switch or an access point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Port {
    pub idx: u32,
    pub up: bool,
    pub enabled: bool,
    pub forward: Forward,
    pub native: Option<String>,
    pub excluded: Vec<String>,
    /// The STP state, for example `forwarding`.
    pub stp_state: Option<String>,
    pub isolation: bool,
    pub aggregated: bool,
}

impl Port {
    /// True if the port forwards frames: up, enabled and not blocked by
    /// STP.
    pub fn forwarding(&self) -> bool {
        self.up
            && self.enabled
            && self.forward != Forward::Disabled
            && self.stp_state.as_deref().is_none_or(|s| s == "forwarding")
    }
}

/// The kind of a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeviceKind {
    Switch,
    AccessPoint,
    /// A gateway or another kind that the lowering does not handle.
    Other,
}

/// An SSID on an access point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vap {
    pub ssid: String,
    pub wlan: Option<String>,
    pub up: bool,
}

/// A switch, an access point or another device of the site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub mac: String,
    pub name: String,
    pub kind: DeviceKind,
    pub type_name: String,
    pub ports: Vec<Port>,
    /// The port of the uplink of the device.
    pub uplink_port: Option<u32>,
    /// The MAC of the device of the uplink and its port.
    pub uplink_peer: Option<(String, u32)>,
    /// The LLDP neighbours: the local port and the chassis MAC.
    pub lldp: Vec<(u32, String)>,
    /// The MAC of the gateway of the management network of the device.
    pub gateway_mac: Option<String>,
    pub vaps: Vec<Vap>,
    pub index: usize,
}

/// A client of the site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client {
    pub mac: String,
    pub ip: Option<String>,
    pub name: String,
    pub network: Option<String>,
    pub wired: bool,
    /// The switch and the port of a wired client.
    pub switch: Option<(String, u32)>,
    /// The access point and the SSID of a wireless client.
    pub ap: Option<(String, String)>,
    pub index: usize,
}

/// The handled parts of a UniFi site.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Site {
    pub networks: Vec<Network>,
    pub wlans: Vec<Wlan>,
    pub devices: Vec<Device>,
    pub clients: Vec<Client>,
}

impl Site {
    pub fn network(&self, id: &str) -> Option<&Network> {
        self.networks.iter().find(|n| n.id == id)
    }

    pub fn device(&self, mac: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.mac == mac)
    }
}

/// The items of a section: the `data` array of the reply, or the reply if
/// it is an array.
pub fn items(v: &Value) -> &[Value] {
    match v {
        Value::Object(m) => m
            .get("data")
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice),
        Value::Array(a) => a,
        _ => &[],
    }
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_string)
}

fn b(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn n(v: &Value, k: &str) -> Option<u64> {
    v.get(k).and_then(Value::as_u64)
}

fn strings(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Reads the sections of a site. Each argument is the parsed JSON of one
/// section; a missing section is `Value::Null`.
pub fn read(networks: &Value, wlans: &Value, devices: &Value, clients: &Value) -> Site {
    let networks = items(networks)
        .iter()
        .enumerate()
        .filter_map(|(index, x)| {
            let vlan = b(x, "vlan_enabled")
                .then(|| n(x, "vlan"))
                .flatten()
                .and_then(|v| u16::try_from(v).ok());
            Some(Network {
                id: s(x, "_id")?,
                name: s(x, "name").unwrap_or_default(),
                purpose: s(x, "purpose").unwrap_or_default(),
                vlan,
                subnet: s(x, "ip_subnet"),
                isolation: b(x, "network_isolation_enabled"),
                index,
            })
        })
        .collect();
    let wlans = items(wlans)
        .iter()
        .enumerate()
        .filter_map(|(index, x)| {
            Some(Wlan {
                id: s(x, "_id")?,
                ssid: s(x, "name")?,
                network: s(x, "networkconf_id")?,
                enabled: x.get("enabled").and_then(Value::as_bool).unwrap_or(true),
                isolation: b(x, "l2_isolation"),
                guest: b(x, "is_guest"),
                index,
            })
        })
        .collect();
    let devices = items(devices)
        .iter()
        .enumerate()
        .filter_map(|(index, x)| {
            let type_name = s(x, "type").unwrap_or_default();
            let kind = match type_name.as_str() {
                "usw" => DeviceKind::Switch,
                "uap" => DeviceKind::AccessPoint,
                _ => DeviceKind::Other,
            };
            let ports = x
                .get("port_table")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(port).collect())
                .unwrap_or_default();
            let up = x.get("uplink");
            let uplink_peer = up.and_then(|u| {
                let mac = s(u, "uplink_mac")?;
                let p = u32::try_from(n(u, "uplink_remote_port")?).ok()?;
                Some((mac.to_lowercase(), p))
            });
            let lldp = x
                .get("lldp_table")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|e| {
                            let p = u32::try_from(n(e, "local_port_idx")?).ok()?;
                            Some((p, s(e, "chassis_id")?.to_lowercase()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let mut vaps: Vec<Vap> = x
                .get("vap_table")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| {
                            Some(Vap {
                                ssid: s(v, "essid")?,
                                wlan: s(v, "wlanconf_id"),
                                up: v.get("up").and_then(Value::as_bool).unwrap_or(true),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            vaps.sort_by(|a, b| a.ssid.cmp(&b.ssid));
            vaps.dedup_by(|a, b| a.ssid == b.ssid);
            Some(Device {
                mac: s(x, "mac")?.to_lowercase(),
                name: s(x, "name").unwrap_or_else(|| s(x, "mac").unwrap_or_default()),
                kind,
                type_name,
                ports,
                uplink_port: up
                    .and_then(|u| n(u, "port_idx"))
                    .and_then(|p| u32::try_from(p).ok()),
                uplink_peer,
                lldp,
                gateway_mac: s(x, "gateway_mac").map(|m| m.to_lowercase()),
                vaps,
                index,
            })
        })
        .collect();
    let clients = items(clients)
        .iter()
        .enumerate()
        .filter_map(|(index, x)| {
            let mac = s(x, "mac")?.to_lowercase();
            let wired = b(x, "is_wired");
            let switch = match (s(x, "sw_mac"), n(x, "sw_port")) {
                (Some(m), Some(p)) if wired => u32::try_from(p).ok().map(|p| (m.to_lowercase(), p)),
                _ => None,
            };
            let ap = match (s(x, "ap_mac"), s(x, "essid")) {
                (Some(m), Some(e)) if !wired => Some((m.to_lowercase(), e)),
                _ => None,
            };
            Some(Client {
                name: s(x, "name")
                    .or_else(|| s(x, "hostname"))
                    .unwrap_or_else(|| mac.clone()),
                mac,
                ip: s(x, "ip"),
                network: s(x, "network_id"),
                wired,
                switch,
                ap,
                index,
            })
        })
        .collect();
    Site {
        networks,
        wlans,
        devices,
        clients,
    }
}

fn port(x: &Value) -> Option<Port> {
    let forward = match x.get("forward").and_then(Value::as_str) {
        Some("all") | None => Forward::All,
        Some("native") => Forward::Native,
        Some("customize") => Forward::Customize,
        Some("disabled") => Forward::Disabled,
        Some(_) => Forward::Other,
    };
    Some(Port {
        idx: u32::try_from(n(x, "port_idx")?).ok()?,
        up: b(x, "up"),
        enabled: x.get("enable").and_then(Value::as_bool).unwrap_or(true),
        forward,
        native: s(x, "native_networkconf_id"),
        excluded: strings(x, "excluded_networkconf_ids"),
        stp_state: s(x, "stp_state"),
        isolation: b(x, "isolation"),
        aggregated: x
            .get("aggregated_by")
            .is_some_and(|v| !matches!(v, Value::Bool(false) | Value::Null)),
    })
}
