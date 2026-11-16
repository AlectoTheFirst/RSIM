//! The NX-OS source: read-only `show` commands over SSH, most of them with
//! `| json`.
//!
//! After the fetch, each JSON answer is put in one shape: an empty answer is
//! `{}`, and each `ROW_x` that NX-OS prints as one object for a table with
//! one row becomes a list. The keep lists of the sections, the extracts and
//! the ingestion then see only lists.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use rsim_store::{
    ADDRESSES, Cell, Class, Format, LINK_SPEEDS, LINKS, MAC_TABLE, NEIGHBOURS, ROUTES, Row,
    TableSchema,
};
use serde_json::Value;

use crate::cli::CliRules;
use crate::{
    BoxFuture, Device, Extract, RawSection, SectionSpec, Source, Ssh, TransportError, Vendor,
    fetch_sections,
};

/// The CLI rules of NX-OS: the Cisco rules with no banner strip, because
/// each JSON answer starts with the same line.
pub const RULES: CliRules = CliRules {
    strip_banner: false,
    ..CliRules::CISCO
};

/// The answer of a device with no CDP to the CDP command, with exit status
/// 0.
const CDP_OFF: &str = "Note: CDP not enabled";

/// The BGP session command for all VRFs, and the command for the default
/// VRF that a device gets if it does not have the first.
const BGP_SESSIONS: &str = "show bgp sessions vrf all | json";
const BGP_SESSIONS_DEFAULT: &str = "show bgp sessions | json";

/// The setup commands of a shell on NX-OS.
pub const SHELL_SETUP: [&str; 2] = ["terminal length 0", "terminal width 511"];

/// Reads an NX-OS switch.
pub struct NxosSource {
    ssh: Arc<dyn Ssh>,
    native: BTreeSet<String>,
}

impl NxosSource {
    pub fn new(ssh: Arc<dyn Ssh>) -> NxosSource {
        NxosSource {
            ssh,
            native: BTreeSet::new(),
        }
    }

    /// Sends `| json native` in place of `| json` to a device. NX-OS 9.3
    /// and later have it. A large table, such as a full route table, needs
    /// it, because the plain `| json` pipe stops with `JSONScripterror`.
    pub fn with_native_json(mut self, device: &str) -> NxosSource {
        self.native.insert(device.to_string());
        self
    }
}

const fn row(
    name: &'static str,
    command: &'static str,
    class: Class,
    format: Format,
    optional: bool,
) -> Spec {
    Spec {
        name,
        command,
        class,
        format,
        optional,
        volatile: &[],
        keep: &[],
        extracts: &[],
    }
}

/// A section of the static list.
#[derive(Clone, Copy)]
struct Spec {
    name: &'static str,
    command: &'static str,
    class: Class,
    format: Format,
    optional: bool,
    volatile: &'static [&'static str],
    keep: &'static [&'static str],
    extracts: &'static [&'static dyn Extract],
}

impl Spec {
    const fn keep(self, keep: &'static [&'static str]) -> Spec {
        Spec { keep, ..self }
    }

    const fn volatile(self, volatile: &'static [&'static str]) -> Spec {
        Spec { volatile, ..self }
    }

    const fn extracts(self, extracts: &'static [&'static dyn Extract]) -> Spec {
        Spec { extracts, ..self }
    }
}

/// The fields of `show interface` that the ingestion reads. The counters,
/// the rates and the times change on each read and are not in the list.
const INTERFACE_KEEP: &[&str] = &[
    "/TABLE_interface/ROW_interface/*/interface",
    "/TABLE_interface/ROW_interface/*/admin_state",
    "/TABLE_interface/ROW_interface/*/svi_admin_state",
    "/TABLE_interface/ROW_interface/*/state",
    "/TABLE_interface/ROW_interface/*/svi_line_proto",
    "/TABLE_interface/ROW_interface/*/eth_ip_addr",
    "/TABLE_interface/ROW_interface/*/eth_ip_mask",
    "/TABLE_interface/ROW_interface/*/svi_ip_addr",
    "/TABLE_interface/ROW_interface/*/svi_ip_mask",
    "/TABLE_interface/ROW_interface/*/eth_hw_addr",
    "/TABLE_interface/ROW_interface/*/svi_mac",
    "/TABLE_interface/ROW_interface/*/eth_speed",
    "/TABLE_interface/ROW_interface/*/eth_duplex",
    "/TABLE_interface/ROW_interface/*/eth_bw",
    "/TABLE_interface/ROW_interface/*/desc",
    "/TABLE_interface/ROW_interface/*/svi_desc",
    "/TABLE_interface/ROW_interface/*/*mtu*",
];

const VERSION_KEEP: &[&str] = &[
    "/nxos_ver_str",
    "/sys_ver_str",
    "/host_name",
    "/proc_board_id",
    "/chassis_id",
];

const ROUTE_KEEP: &[&str] = &[
    "/TABLE_vrf/ROW_vrf/*/vrf-name-out",
    "/TABLE_vrf/ROW_vrf/*/TABLE_addrf/ROW_addrf/*/TABLE_prefix/ROW_prefix/*/ipprefix",
    "/TABLE_vrf/ROW_vrf/*/TABLE_addrf/ROW_addrf/*/TABLE_prefix/ROW_prefix/*/TABLE_path/ROW_path/*/ipnexthop",
    "/TABLE_vrf/ROW_vrf/*/TABLE_addrf/ROW_addrf/*/TABLE_prefix/ROW_prefix/*/TABLE_path/ROW_path/*/ifname",
    "/TABLE_vrf/ROW_vrf/*/TABLE_addrf/ROW_addrf/*/TABLE_prefix/ROW_prefix/*/TABLE_path/ROW_path/*/clientname",
    "/TABLE_vrf/ROW_vrf/*/TABLE_addrf/ROW_addrf/*/TABLE_prefix/ROW_prefix/*/TABLE_path/ROW_path/*/metric",
    "/TABLE_vrf/ROW_vrf/*/TABLE_addrf/ROW_addrf/*/TABLE_prefix/ROW_prefix/*/TABLE_path/ROW_path/*/pref",
    "/TABLE_vrf/ROW_vrf/*/TABLE_addrf/ROW_addrf/*/TABLE_prefix/ROW_prefix/*/TABLE_path/ROW_path/*/ubest",
];

const MAC_KEEP: &[&str] = &[
    "/TABLE_mac_address/ROW_mac_address/*/disp_vlan",
    "/TABLE_mac_address/ROW_mac_address/*/disp_mac_addr",
    "/TABLE_mac_address/ROW_mac_address/*/disp_port",
    "/TABLE_mac_address/ROW_mac_address/*/disp_type",
];

const ARP_KEEP: &[&str] = &[
    "/TABLE_vrf/ROW_vrf/*/vrf-name-out",
    "/TABLE_vrf/ROW_vrf/*/TABLE_adj/ROW_adj/*/ip-addr-out",
    "/TABLE_vrf/ROW_vrf/*/TABLE_adj/ROW_adj/*/mac",
    "/TABLE_vrf/ROW_vrf/*/TABLE_adj/ROW_adj/*/intf-out",
];

const LLDP_KEEP: &[&str] = &[
    "/TABLE_nbor_detail/ROW_nbor_detail/*/l_port_id",
    "/TABLE_nbor_detail/ROW_nbor_detail/*/sys_name",
    "/TABLE_nbor_detail/ROW_nbor_detail/*/chassis_id",
    "/TABLE_nbor_detail/ROW_nbor_detail/*/port_id",
    "/TABLE_nbor_detail/ROW_nbor_detail/*/sys_desc",
    "/TABLE_nbor_detail/ROW_nbor_detail/*/port_desc",
];

const CDP_KEEP: &[&str] = &[
    "/TABLE_cdp_neighbor_brief_info/ROW_cdp_neighbor_brief_info/*/device_id",
    "/TABLE_cdp_neighbor_brief_info/ROW_cdp_neighbor_brief_info/*/intf_id",
    "/TABLE_cdp_neighbor_brief_info/ROW_cdp_neighbor_brief_info/*/port_id",
];

/// The sections of an NX-OS switch, in the order of the fetch.
const SPECS: &[Spec] = {
    use Class::{Configuration, Observation, Volatile};
    use Format::{Json, Text};
    &[
        row("config", "show running-config", Configuration, Text, false).volatile(&["!"]),
        row("version", "show version | json", Configuration, Json, false).keep(VERSION_KEEP),
        row(
            "interfaces",
            "show interface | json",
            Observation,
            Json,
            false,
        )
        .keep(INTERFACE_KEEP)
        .extracts(&[&LinkExtract, &AddrExtract, &SpeedExtract]),
        row(
            "lldp",
            "show lldp neighbors detail | json",
            Observation,
            Json,
            true,
        )
        .keep(LLDP_KEEP),
        row("cdp", "show cdp neighbors | json", Observation, Json, true).keep(CDP_KEEP),
        row("vlans", "show vlan | json", Observation, Json, false),
        row("vrfs", "show vrf | json", Configuration, Json, false),
        row(
            "rib",
            "show ip route vrf all | json",
            Observation,
            Json,
            false,
        )
        .keep(ROUTE_KEEP)
        .extracts(&[&RouteExtract]),
        row(
            "mac_table",
            "show mac address-table | json",
            Observation,
            Json,
            false,
        )
        .keep(MAC_KEEP)
        .extracts(&[&MacExtract]),
        row("arp", "show ip arp vrf all | json", Observation, Json, true)
            .keep(ARP_KEEP)
            .extracts(&[&ArpExtract]),
        row(
            "vrf_interfaces",
            "show vrf interface | json",
            Observation,
            Json,
            false,
        ),
        row(
            "acl",
            "show ip access-lists | json",
            Configuration,
            Json,
            false,
        ),
        row(
            "trunks",
            "show interface trunk | json",
            Observation,
            Json,
            true,
        ),
        row("hsrp", "show hsrp all | json", Observation, Json, true),
        row("vrrp", "show vrrp detail | json", Observation, Json, true),
        row("vpc", "show vpc | json", Observation, Json, true),
        row("ospf", "show ip ospf vrf all | json", Volatile, Json, true),
        row(
            "ospf_interfaces",
            "show ip ospf interface vrf all | json",
            Volatile,
            Json,
            true,
        ),
        row(
            "ospf_neighbors",
            "show ip ospf neighbors vrf all | json",
            Volatile,
            Json,
            true,
        ),
        row(
            "ospf_lsdb_router",
            "show ip ospf database router detail vrf all | json",
            Volatile,
            Json,
            true,
        ),
        row(
            "ospf_lsdb_network",
            "show ip ospf database network detail vrf all | json",
            Volatile,
            Json,
            true,
        ),
        row(
            "ospf_lsdb_summary",
            "show ip ospf database summary detail vrf all | json",
            Volatile,
            Json,
            true,
        ),
        row(
            "ospf_lsdb_external",
            "show ip ospf database external detail vrf all | json",
            Volatile,
            Json,
            true,
        ),
        row(
            "ospf_lsdb_nssa_external",
            "show ip ospf database nssa-external detail vrf all | json",
            Volatile,
            Json,
            true,
        ),
        row(
            "ospf_lsdb_asbr_summary",
            "show ip ospf database asbr-summary detail vrf all | json",
            Volatile,
            Json,
            true,
        ),
        row("bgp_sessions", BGP_SESSIONS, Volatile, Json, true),
        row(
            "bgp_neighbors",
            "show bgp vrf all neighbors | json",
            Volatile,
            Json,
            true,
        ),
    ]
};

/// The command with `| json native` in place of a final `| json`.
fn native(command: &str) -> String {
    if command.ends_with("| json") {
        format!("{command} native")
    } else {
        command.to_string()
    }
}

/// The sections of an NX-OS switch. With `native_json`, each JSON command
/// ends with `| json native`.
pub fn sections(native_json: bool) -> Vec<SectionSpec> {
    SPECS
        .iter()
        .map(|s| SectionSpec {
            name: s.name,
            command: if native_json {
                native(s.command)
            } else {
                s.command.to_string()
            },
            class: s.class,
            format: s.format,
            volatile: s.volatile,
            extracts: s.extracts,
            keep: s.keep,
            optional: s.optional,
        })
        .collect()
}

/// Makes each `ROW_x` that is one object a list with that object, and each
/// `ROW_x` that is null an empty list.
pub fn rows_as_lists(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, c) in m.iter_mut() {
                if k.starts_with("ROW_") {
                    match c {
                        Value::Object(_) => *c = Value::Array(vec![c.take()]),
                        Value::Null => *c = Value::Array(Vec::new()),
                        _ => {}
                    }
                }
                rows_as_lists(c);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(rows_as_lists),
        _ => {}
    }
}

/// Puts a JSON answer in its one shape. An answer that is not JSON stays as
/// it is, and the section then fails alone.
fn shape(section: &mut RawSection) {
    if section.spec.format != Format::Json {
        return;
    }
    let Ok(bytes) = &section.result else { return };
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim();
    if text.is_empty() {
        section.result = Ok(b"{}".to_vec());
        return;
    }
    if text.trim_end_matches('.') == CDP_OFF {
        section.result = Err(TransportError::NotFound(CDP_OFF.into()));
        return;
    }
    if let Ok(mut v) = serde_json::from_str::<Value>(text) {
        rows_as_lists(&mut v);
        section.result = Ok(v.to_string().into_bytes());
    }
}

impl Source for NxosSource {
    fn vendor(&self) -> Vendor {
        Vendor::Nxos
    }

    fn sections(&self, device: &Device) -> Vec<SectionSpec> {
        sections(self.native.contains(&device.id))
    }

    fn fetch<'a>(
        &'a self,
        device: &'a Device,
        timeout: Duration,
    ) -> BoxFuture<'a, Vec<RawSection>> {
        Box::pin(async move {
            let serial = self.ssh.serial(device);
            let read = |command: String| -> BoxFuture<'a, _> {
                let ssh = self.ssh.clone();
                Box::pin(async move { ssh.run(device, &command).await })
            };
            let mut out = fetch_sections(self.sections(device), timeout, serial, read).await;
            RULES.apply(&mut out, self.ssh.banner_each_command(device));
            let native = self.native.contains(&device.id);
            if let Some(s) = out.iter_mut().find(|s| s.spec.name == "bgp_sessions")
                && s.absent()
            {
                let mut spec = s.spec.clone();
                spec.command = if native {
                    self::native(BGP_SESSIONS_DEFAULT)
                } else {
                    BGP_SESSIONS_DEFAULT.to_string()
                };
                let mut again = fetch_sections(vec![spec], timeout, true, read).await;
                RULES.apply(&mut again, self.ssh.banner_each_command(device));
                *s = again.remove(0);
            }
            out.iter_mut().for_each(shape);
            out
        })
    }
}

fn json(bytes: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|e| e.to_string())
}

/// The rows of a table: `TABLE_t` then `ROW_t`, a list after [`shape`].
fn rows<'v>(v: &'v Value, table: &str) -> &'v [Value] {
    v.get(format!("TABLE_{table}"))
        .and_then(|t| t.get(format!("ROW_{table}")))
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// A text field. NX-OS prints numbers as strings or as numbers.
fn text(r: &Value, key: &str) -> Option<String> {
    match r.get(key)? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn first(r: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| text(r, k))
}

fn number(r: &Value, keys: &[&str]) -> Option<u64> {
    first(r, keys).and_then(|s| s.trim().parse().ok())
}

fn cell(s: Option<String>) -> Cell {
    s.map_or(Cell::Null, Cell::Str)
}

/// A MAC address in the form `00:00:5e:00:53:01`. NX-OS prints
/// `0000.5e00.5301`. A text that is not a MAC address gives `None`.
pub fn mac(s: &str) -> Option<String> {
    let hex: String = s.chars().filter(char::is_ascii_hexdigit).collect();
    if hex.len() != 12
        || s.chars()
            .any(|c| !c.is_ascii_hexdigit() && !".:-".contains(c))
    {
        return None;
    }
    let hex = hex.to_ascii_lowercase();
    Some(
        (0..6)
            .map(|i| &hex[2 * i..2 * i + 2])
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// The prefix length of a mask: a length or a dotted mask.
fn mask_len(mask: &str) -> Option<u8> {
    let mask = mask.trim().trim_start_matches('/');
    if let Ok(n) = mask.parse::<u8>() {
        return (n <= 32).then_some(n);
    }
    let a: std::net::Ipv4Addr = mask.parse().ok()?;
    let bits = u32::from(a);
    let n = bits.leading_ones();
    (bits.checked_shl(n).unwrap_or(0) == 0).then(|| u8::try_from(n).expect("at most 32"))
}

struct LinkExtract;
struct AddrExtract;
struct SpeedExtract;
struct RouteExtract;
struct MacExtract;
struct ArpExtract;

impl Extract for LinkExtract {
    fn table(&self) -> &'static TableSchema {
        &LINKS
    }

    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
        let v = json(bytes)?;
        rows(&v, "interface")
            .iter()
            .map(|r| {
                let name = text(r, "interface").ok_or("an interface has no name")?;
                let admin = first(
                    r,
                    &["admin_state", "svi_admin_state", "state", "svi_line_proto"],
                );
                let oper = first(r, &["state", "svi_line_proto"]);
                let parent = name.split_once('.').map(|(p, _)| p.to_string());
                let vlan = name
                    .strip_prefix("Vlan")
                    .and_then(|n| n.parse::<u64>().ok());
                Ok(vec![
                    Cell::Str(name.clone()),
                    cell(first(r, &["eth_hw_addr", "svi_mac"]).and_then(|m| mac(&m))),
                    number(r, &["eth_mtu", "svi_mtu"]).map_or(Cell::Null, Cell::U64),
                    Cell::Bool(admin.as_deref() == Some("up")),
                    cell(oper),
                    cell(parent),
                    vlan.map_or(Cell::Null, Cell::U64),
                ])
            })
            .collect()
    }
}

impl Extract for AddrExtract {
    fn table(&self) -> &'static TableSchema {
        &ADDRESSES
    }

    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
        let v = json(bytes)?;
        let mut out = Vec::new();
        for r in rows(&v, "interface") {
            let name = text(r, "interface").ok_or("an interface has no name")?;
            for (a, m) in [
                ("eth_ip_addr", "eth_ip_mask"),
                ("svi_ip_addr", "svi_ip_mask"),
            ] {
                if let (Some(addr), Some(mask)) = (text(r, a), text(r, m)) {
                    let len = mask_len(&mask)
                        .ok_or_else(|| format!("{name}: the mask {mask} is not valid"))?;
                    out.push(vec![
                        Cell::Str(name.clone()),
                        Cell::Str(format!("{addr}/{len}")),
                    ]);
                }
            }
        }
        Ok(out)
    }
}

/// The speed in Mbit/s of `1000 Mb/s` or `10 Gb/s`. `auto-speed` and other
/// texts give `None`.
fn mbps(s: &str) -> Option<u64> {
    let mut w = s.split_whitespace();
    let n: u64 = w.next()?.parse().ok()?;
    match w.next()? {
        "Mb/s" => Some(n),
        "Gb/s" => Some(n * 1000),
        _ => None,
    }
}

impl Extract for SpeedExtract {
    fn table(&self) -> &'static TableSchema {
        &LINK_SPEEDS
    }

    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
        let v = json(bytes)?;
        rows(&v, "interface")
            .iter()
            .filter(|r| r.get("eth_speed").is_some() || r.get("eth_duplex").is_some())
            .map(|r| {
                let name = text(r, "interface").ok_or("an interface has no name")?;
                let duplex = text(r, "eth_duplex").filter(|d| d == "full" || d == "half");
                Ok(vec![
                    Cell::Str(name),
                    text(r, "eth_speed")
                        .and_then(|s| mbps(&s))
                        .map_or(Cell::Null, Cell::U64),
                    cell(duplex),
                ])
            })
            .collect()
    }
}

/// The VRF of a row: `vrf-name-out`, with `default` for an empty name.
fn vrf(r: &Value) -> String {
    text(r, "vrf-name-out")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "default".into())
}

impl Extract for RouteExtract {
    fn table(&self) -> &'static TableSchema {
        &ROUTES
    }

    /// One row for each path. A path with `ubest` false is not selected; a
    /// path with no `ubest` is selected. The next hop is kept as NX-OS
    /// prints it, also with a `%vrf` suffix of a next hop in another VRF.
    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
        let v = json(bytes)?;
        let mut out = Vec::new();
        for vr in rows(&v, "vrf") {
            let vrf = vrf(vr);
            for af in rows(vr, "addrf") {
                for p in rows(af, "prefix") {
                    let prefix = text(p, "ipprefix")
                        .ok_or_else(|| format!("vrf {vrf}: a route has no prefix"))?;
                    for path in rows(p, "path") {
                        let selected = text(path, "ubest")
                            .is_none_or(|b| b.eq_ignore_ascii_case("true") || b == "1");
                        out.push(vec![
                            Cell::Str(vrf.clone()),
                            Cell::Str(prefix.clone()),
                            Cell::Str(text(path, "clientname").unwrap_or_else(|| "unknown".into())),
                            Cell::Bool(selected),
                            number(path, &["pref"]).map_or(Cell::Null, Cell::U64),
                            number(path, &["metric"]).map_or(Cell::Null, Cell::U64),
                            cell(text(path, "ipnexthop")),
                            cell(text(path, "ifname")),
                        ]);
                    }
                }
            }
        }
        Ok(out)
    }
}

impl Extract for MacExtract {
    fn table(&self) -> &'static TableSchema {
        &MAC_TABLE
    }

    /// An entry with the VLAN `-`, such as the MAC address of the router,
    /// gives no row.
    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
        let v = json(bytes)?;
        let mut out = Vec::new();
        for r in rows(&v, "mac_address") {
            let Some(vlan) = text(r, "disp_vlan").and_then(|x| x.trim().parse::<u64>().ok()) else {
                continue;
            };
            let raw = text(r, "disp_mac_addr").ok_or("a MAC entry has no address")?;
            let addr = mac(&raw).ok_or_else(|| format!("{raw} is not a MAC address"))?;
            out.push(vec![
                Cell::U64(vlan),
                Cell::Str(addr),
                cell(text(r, "disp_port").filter(|p| !p.is_empty())),
                cell(text(r, "disp_type")),
            ]);
        }
        Ok(out)
    }
}

impl Extract for ArpExtract {
    fn table(&self) -> &'static TableSchema {
        &NEIGHBOURS
    }

    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
        let v = json(bytes)?;
        let mut out = Vec::new();
        for vr in rows(&v, "vrf") {
            for r in rows(vr, "adj") {
                let (Some(interface), Some(ip)) = (text(r, "intf-out"), text(r, "ip-addr-out"))
                else {
                    return Err("an ARP entry has no interface or address".into());
                };
                out.push(vec![
                    Cell::Str(interface),
                    Cell::Str(ip),
                    cell(text(r, "mac").and_then(|m| mac(&m))),
                    Cell::Null,
                ]);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_row_becomes_a_list() {
        let mut v: Value = serde_json::from_str(
            r#"{"TABLE_vrf":{"ROW_vrf":{"vrf-name-out":"default","TABLE_adj":{"ROW_adj":null}}}}"#,
        )
        .unwrap();
        rows_as_lists(&mut v);
        assert_eq!(
            v,
            serde_json::json!({"TABLE_vrf":{"ROW_vrf":[{"vrf-name-out":"default","TABLE_adj":{"ROW_adj":[]}}]}})
        );
    }

    #[test]
    fn macs_masks_and_speeds_read() {
        assert_eq!(mac("0000.5E00.5301").as_deref(), Some("00:00:5e:00:53:01"));
        assert_eq!(
            mac("00:00:5e:00:53:01").as_deref(),
            Some("00:00:5e:00:53:01")
        );
        assert_eq!(mac("-"), None);
        assert_eq!(mask_len("24"), Some(24));
        assert_eq!(mask_len("255.255.255.0"), Some(24));
        assert_eq!(mask_len("255.0.255.0"), None);
        assert_eq!(mbps("10 Gb/s"), Some(10_000));
        assert_eq!(mbps("1000 Mb/s"), Some(1000));
        assert_eq!(mbps("auto-speed"), None);
    }

    #[test]
    fn native_json_changes_only_json_commands() {
        let s = sections(true);
        assert_eq!(s[0].command, "show running-config");
        assert_eq!(s[1].command, "show version | json native");
        let names: BTreeSet<&str> = s.iter().map(|x| x.name).collect();
        assert_eq!(names.len(), s.len(), "the section names are unique");
    }
}
