//! The UniFi source: read-only API paths of a UniFi OS console over HTTPS.
//! One device is one site of a console.

use std::sync::Arc;
use std::time::Duration;

use rsim_store::{CLIENTS, Cell, Class, Format, Row, TableSchema};
use serde_json::Value;

use crate::{
    BoxFuture, Device, Extract, Https, RawSection, SectionSpec, Source, Vendor, fetch_sections,
};

/// Reads the sites of UniFi consoles.
pub struct UnifiSource {
    https: Arc<dyn Https>,
}

impl UnifiSource {
    pub fn new(https: Arc<dyn Https>) -> UnifiSource {
        UnifiSource { https }
    }
}

const DEVICE_VOLATILE: &[&str] = &[
    "/data/*/uptime",
    "/data/*/_uptime",
    "/data/*/last_seen",
    "/data/*/next_interval",
    "/data/*/next_heartbeat_at",
    "/data/*/system-stats",
    "/data/*/sys_stats",
    "/data/*/stat",
    "/data/*/satisfaction",
    "/data/*/*bytes*",
    "/data/*/*packets*",
    "/data/*/*num_sta",
    "/data/*/temperatures",
    "/data/*/general_temperature",
    "/data/*/fan_level",
    "/data/*/total_used_power",
    "/data/*/radio_table_stats",
    "/data/*/uplink/uptime",
    "/data/*/uplink/*bytes*",
    "/data/*/uplink/*packets*",
    "/data/*/port_table/*/*bytes*",
    "/data/*/port_table/*/*packets*",
    "/data/*/port_table/*/*dropped",
    "/data/*/port_table/*/*errors",
    "/data/*/port_table/*/*broadcast",
    "/data/*/port_table/*/*multicast",
    "/data/*/port_table/*/poe_power",
    "/data/*/port_table/*/poe_current",
    "/data/*/port_table/*/poe_voltage",
    "/data/*/port_table/*/satisfaction",
    "/data/*/vap_table/*/*bytes*",
    "/data/*/vap_table/*/*packets*",
    "/data/*/vap_table/*/satisfaction",
    "/data/*/vap_table/*/num_sta",
];

const CLIENT_VOLATILE: &[&str] = &[
    "/data/*/uptime",
    "/data/*/_uptime*",
    "/data/*/last_seen*",
    "/data/*/*bytes*",
    "/data/*/*packets*",
    "/data/*/*rate*",
    "/data/*/*retries*",
    "/data/*/signal",
    "/data/*/rssi",
    "/data/*/noise",
    "/data/*/ccq",
    "/data/*/satisfaction*",
    "/data/*/idletime",
    "/data/*/assoc_time",
    "/data/*/latest_assoc_time",
    "/data/*/anomalies",
    "/data/*/disconnect_timestamp",
];

const META_VOLATILE: &[&str] = &["/meta/count"];

fn spec(
    name: &'static str,
    command: String,
    class: Class,
    volatile: &'static [&'static str],
    extract: Option<&'static dyn Extract>,
) -> SectionSpec {
    SectionSpec {
        name,
        command,
        class,
        format: Format::Json,
        volatile,
        extract,
    }
}

/// The sections of a site. A console has either the classic firewall or the
/// zone firewall, so the paths of the other model fail and their sections
/// are missing.
pub fn sections(site: &str) -> Vec<SectionSpec> {
    use Class::{Configuration, Observation};
    let v1 = |p: &str| format!("/proxy/network/api/s/{site}/{p}");
    let v2 = |p: &str| format!("/proxy/network/v2/api/site/{site}/{p}");
    vec![
        spec(
            "devices",
            v1("stat/device"),
            Observation,
            DEVICE_VOLATILE,
            None,
        ),
        spec(
            "networks",
            v1("rest/networkconf"),
            Configuration,
            META_VOLATILE,
            None,
        ),
        spec(
            "port_profiles",
            v1("rest/portconf"),
            Configuration,
            META_VOLATILE,
            None,
        ),
        spec(
            "wlans",
            v1("rest/wlanconf"),
            Configuration,
            META_VOLATILE,
            None,
        ),
        spec(
            "clients",
            v1("stat/sta"),
            Observation,
            CLIENT_VOLATILE,
            Some(&ClientExtract),
        ),
        spec(
            "firewall_rules",
            v1("rest/firewallrule"),
            Configuration,
            META_VOLATILE,
            None,
        ),
        spec(
            "firewall_groups",
            v1("rest/firewallgroup"),
            Configuration,
            META_VOLATILE,
            None,
        ),
        spec(
            "firewall_zones",
            v2("firewall/zones"),
            Configuration,
            &[],
            None,
        ),
        spec(
            "firewall_policies",
            v2("firewall-policies"),
            Configuration,
            &[],
            None,
        ),
    ]
}

impl Source for UnifiSource {
    fn vendor(&self) -> Vendor {
        Vendor::Unifi
    }

    fn sections(&self, device: &Device) -> Vec<SectionSpec> {
        sections(device.site.as_deref().unwrap_or("default"))
    }

    fn fetch<'a>(
        &'a self,
        device: &'a Device,
        timeout: Duration,
    ) -> BoxFuture<'a, Vec<RawSection>> {
        Box::pin(fetch_sections(
            self.sections(device),
            timeout,
            move |path| {
                let https = self.https.clone();
                Box::pin(async move { https.get(device, &path).await })
            },
        ))
    }
}

/// `stat/sta`: one row for each client.
pub struct ClientExtract;

fn s(v: &Value, key: &str) -> Cell {
    match v.get(key).and_then(Value::as_str) {
        Some(x) if !x.is_empty() => Cell::Str(x.to_string()),
        _ => Cell::Null,
    }
}

fn n(v: &Value, key: &str) -> Cell {
    match v.get(key).and_then(Value::as_u64) {
        Some(x) => Cell::U64(x),
        None => Cell::Null,
    }
}

impl Extract for ClientExtract {
    fn table(&self) -> &'static TableSchema {
        &CLIENTS
    }

    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
        let v: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let data = v
            .get("data")
            .unwrap_or(&v)
            .as_array()
            .ok_or("the reply has no array of clients")?;
        data.iter()
            .map(|c| {
                let mac = c
                    .get("mac")
                    .and_then(Value::as_str)
                    .ok_or("a client has no mac")?;
                let hostname = match s(c, "hostname") {
                    Cell::Null => s(c, "name"),
                    h => h,
                };
                Ok(vec![
                    Cell::Str(mac.to_ascii_lowercase()),
                    s(c, "ip"),
                    hostname,
                    s(c, "network"),
                    n(c, "vlan"),
                    Cell::Bool(c.get("is_wired").and_then(Value::as_bool).unwrap_or(false)),
                    s(c, "ap_mac"),
                    s(c, "sw_mac"),
                    n(c, "sw_port"),
                ])
            })
            .collect()
    }
}
