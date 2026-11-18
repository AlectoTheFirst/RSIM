//! The VyOS source: read-only commands over SSH.
//!
//! The BGP sections follow the setting of the device, [`CaptureBgp`]: the
//! FRR summary of the sessions of all VRFs and address families, and with
//! `all` the neighbour detail and the tables of each IPv4 unicast
//! neighbour. The summary and the tables of a neighbour are confirmed on
//! one router with one eBGP neighbour in IPv4 unicast in the default VRF; a
//! named VRF, another address family, an empty table and the neighbour
//! detail are not confirmed on a device.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use rsim_store::{
    ADDRESSES, Cell, Class, Format, LINK_SPEEDS, LINKS, NEIGHBOURS, ROUTES, Row, TableSchema,
};
use serde_json::Value;

use crate::bgp::{self, CaptureBgp, Peer};
use crate::{
    BoxFuture, Device, Extract, RawSection, SectionSpec, Source, Ssh, Timeouts, TransportError,
    Vendor, fetch_sections,
};

/// The search path that each operational command sets, because `ip` is in
/// different directories in different VyOS releases.
pub const PATH: &str = "PATH=/usr/sbin:/sbin:/usr/bin:/bin";

/// The wrapper that runs an operational mode command, such as `show`, in
/// the shell of an SSH exec, which has no operational mode.
pub const OP_MODE: &str = "/opt/vyatta/bin/vyatta-op-cmd-wrapper";

/// The command that prints the name, the speed in Mbit/s and the duplex of
/// each link, one link on each line. A value that the kernel does not give
/// is `unknown`.
pub const SPEED_COMMAND: &str = concat!(
    "PATH=/usr/sbin:/sbin:/usr/bin:/bin sh -c '",
    "for i in /sys/class/net/*; do ",
    "n=$(basename \"$i\"); ",
    "s=$(cat \"$i/speed\" 2>/dev/null || echo unknown); ",
    "d=$(cat \"$i/duplex\" 2>/dev/null || echo unknown); ",
    "echo \"$n $s $d\"; ",
    "done'"
);

/// Reads a VyOS router.
pub struct VyosSource {
    ssh: Arc<dyn Ssh>,
}

impl VyosSource {
    pub fn new(ssh: Arc<dyn Ssh>) -> VyosSource {
        VyosSource { ssh }
    }
}

fn spec(
    name: &'static str,
    command: &str,
    class: Class,
    format: Format,
    volatile: &'static [&'static str],
    extracts: &'static [&'static dyn Extract],
) -> SectionSpec {
    SectionSpec {
        name,
        command: command.to_string(),
        class,
        format,
        volatile,
        extracts,
        keep: &[],
        optional: false,
    }
}

/// The sections of a VyOS router without its BGP sections.
fn base_sections() -> Vec<SectionSpec> {
    use Class::{Configuration, Observation};
    use Format::{Json, Text};
    const ROUTE_VOLATILE: &[&str] = &["/*/*/uptime", "/*/*/*/uptime"];
    vec![
        spec(
            "config",
            &format!("{OP_MODE} show configuration json"),
            Configuration,
            Json,
            &[],
            &[],
        ),
        spec(
            "version",
            &format!("{OP_MODE} show version"),
            Configuration,
            Text,
            &["Uptime:"],
            &[],
        ),
        spec(
            "links",
            &format!("{PATH} ip -d -j link show"),
            Observation,
            Json,
            &[
                "/*/linkinfo/info_data/*_timer",
                "/*/linkinfo/info_slave_data/*_timer",
            ],
            &[&LinkExtract],
        ),
        spec(
            "addresses",
            &format!("{PATH} ip -j addr show"),
            Observation,
            Json,
            &[
                "/*/addr_info/*/valid_life_time",
                "/*/addr_info/*/preferred_life_time",
            ],
            &[&AddrExtract],
        ),
        spec(
            "neighbours",
            &format!("{PATH} ip -j neigh show"),
            Observation,
            Json,
            &["/*/state"],
            &[&NeighExtract],
        ),
        spec(
            "link_speeds",
            SPEED_COMMAND,
            Observation,
            Text,
            &[],
            &[&SpeedExtract],
        ),
        spec(
            "routes_ipv4",
            &format!(r#"{PATH} vtysh -c "show ip route vrf all json""#),
            Observation,
            Json,
            ROUTE_VOLATILE,
            &[&RouteExtract],
        ),
        spec(
            "routes_ipv6",
            &format!(r#"{PATH} vtysh -c "show ipv6 route vrf all json""#),
            Observation,
            Json,
            ROUTE_VOLATILE,
            &[&RouteExtract],
        ),
    ]
}

impl Source for VyosSource {
    fn vendor(&self) -> Vendor {
        Vendor::Vyos
    }

    fn sections(&self, device: &Device) -> Vec<SectionSpec> {
        sections_with(device.capture_bgp)
    }

    /// Reads the sections, then the 3 tables of each IPv4 unicast neighbour
    /// of the BGP sessions. A failed or absent answer of the sessions makes
    /// the section of the tables absent, except a connect error or a
    /// timeout, which the section takes as its error, as it does when each
    /// of its commands ends in one.
    fn fetch<'a>(
        &'a self,
        device: &'a Device,
        timeouts: Timeouts,
    ) -> BoxFuture<'a, Vec<RawSection>> {
        Box::pin(async move {
            let serial = self.ssh.serial(device);
            let read = |command: String| -> BoxFuture<'a, _> {
                let ssh = self.ssh.clone();
                Box::pin(async move { ssh.run(device, &command).await })
            };
            let (fixed, routes): (Vec<SectionSpec>, Vec<SectionSpec>) = self
                .sections(device)
                .into_iter()
                .partition(|s| s.name != bgp::ROUTES);
            let mut out = fetch_sections(fixed, timeouts, serial, read).await;
            out.iter_mut().for_each(bgp_answer);
            for spec in routes {
                let peers = out
                    .iter()
                    .find(|s| s.spec.name == bgp::SESSIONS)
                    .map_or_else(
                        || Err(TransportError::NotFound("the sessions are not read".into())),
                        |s| s.result.clone(),
                    )
                    .map(|b| session_peers(&b));
                let parts = match &peers {
                    Ok(p) => Ok(bgp::route_parts(p, bgp_route_command)),
                    Err(e) => Err(e.clone()),
                };
                let mut answers = match &parts {
                    Ok(parts) => bgp::fetch_parts(&spec, parts, timeouts, serial, read).await,
                    Err(_) => Vec::new(),
                };
                answers.iter_mut().for_each(bgp_answer);
                let result =
                    bgp::combined(parts.as_deref(), "the session summary", &answers, |_, a| {
                        bgp::combine_json(peers.as_ref().expect("the parts have peers"), a)
                    });
                out.push(RawSection { spec, result });
            }
            out
        })
    }
}

/// The section of the BGP sessions: FRR `show bgp vrf all summary json`.
pub const BGP_SESSIONS_COMMAND: &str =
    r#"PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show bgp vrf all summary json""#;

/// The command of a table of a neighbour, with the index of its direction
/// in [`bgp::DIRECTIONS`]. The VRF comes before the address family, as the
/// grammar of FRR has it.
pub fn bgp_route_command(vrf: &str, peer: Ipv4Addr, direction: usize) -> String {
    let scope = if vrf == bgp::DEFAULT_VRF {
        String::new()
    } else {
        format!("vrf {vrf} ")
    };
    format!(
        r#"{PATH} vtysh -c "show bgp {scope}ipv4 unicast neighbors {peer} {} json""#,
        bgp::DIRECTIONS[direction]
    )
}

/// The members of the BGP sessions that the change hash covers: the local
/// AS and the router ID of each VRF and address family, and the AS and the
/// state of each neighbour, under a VRF or, in the form with no VRF level,
/// at the top. The VRF, the address family and the address are the keys on
/// these paths. The counters and the up times are not in the list.
const BGP_SESSION_KEEP: &[&str] = &[
    "/*/*/as",
    "/*/*/routerId",
    "/*/*/vrfName",
    "/*/*/peers/*/remoteAs",
    "/*/*/peers/*/localAs",
    "/*/*/peers/*/state",
    "/*/*/peers/*/peerState",
    "/*/as",
    "/*/routerId",
    "/*/peers/*/remoteAs",
    "/*/peers/*/localAs",
    "/*/peers/*/state",
    "/*/peers/*/peerState",
    "/warning",
];

/// The timers, the counters and the up times of the neighbour detail of
/// each VRF.
const BGP_NEIGHBOR_TIMES: &[&str] = &[
    "/*/*/bgpTimer*",
    "/*/*/*Msecs",
    "/*/*/*Msec",
    "/*/*/*Epoch",
    "/*/*/*Thread",
    "/*/*/messageStats",
    "/*/*/connections*",
    "/*/*/lastReset*",
    "/*/*/*Time*",
    "/*/*/addressFamilyInfo/*/*Counter",
    "/*/*/addressFamilyInfo/*/packetQueueLength",
];

/// The table versions of the tables of the neighbours.
const BGP_ROUTE_TIMES: &[&str] = &["/*/*/*/answer/*ableVersion"];

/// The sections of a VyOS router with the BGP sections of the default
/// setting.
pub fn sections() -> Vec<SectionSpec> {
    sections_with(CaptureBgp::default())
}

/// The sections of a VyOS router with the BGP sections of a setting, in
/// the order of the fetch.
pub fn sections_with(capture: CaptureBgp) -> Vec<SectionSpec> {
    use Class::Observation;
    use Format::Json;
    let mut out = base_sections();
    let bgp_spec = |name, command: &str, volatile, keep| SectionSpec {
        keep,
        optional: true,
        ..spec(name, command, Observation, Json, volatile, &[])
    };
    if capture.sessions() {
        out.push(bgp_spec(
            bgp::SESSIONS,
            BGP_SESSIONS_COMMAND,
            &[],
            BGP_SESSION_KEEP,
        ));
    }
    if capture.all() {
        out.push(bgp_spec(
            bgp::NEIGHBORS,
            &format!(r#"{PATH} vtysh -c "show ip bgp vrf all neighbors json""#),
            BGP_NEIGHBOR_TIMES,
            &[],
        ));
        out.push(bgp_spec(
            bgp::ROUTES,
            &format!(
                r#"{PATH} vtysh -c "show bgp [vrf <vrf>] ipv4 unicast neighbors <address> <direction> json""#
            ),
            BGP_ROUTE_TIMES,
            &[],
        ));
    }
    out
}

/// An answer of a BGP command: an empty answer is `{}`, and an answer whose
/// first line starts with `%`, such as the answer of a router with no BGP
/// instance, makes the section absent with that line. The other sections
/// keep their answers.
fn bgp_answer(section: &mut RawSection) {
    if ![bgp::SESSIONS, bgp::NEIGHBORS, bgp::ROUTES].contains(&section.spec.name) {
        return;
    }
    let Ok(bytes) = &section.result else { return };
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim();
    if text.is_empty() {
        section.result = Ok(b"{}".to_vec());
    } else if text.starts_with('%') {
        let line = text.lines().next().unwrap_or_default().to_string();
        section.result = Err(TransportError::NotFound(line));
    }
}

/// The IPv4 unicast neighbours of the BGP sessions: the addresses of
/// `ipv4Unicast/peers` of each VRF, or of the top in the form with no VRF
/// level.
fn session_peers(bytes: &[u8]) -> BTreeSet<Peer> {
    let mut out = BTreeSet::new();
    let Ok(Value::Object(top)) = serde_json::from_slice::<Value>(bytes) else {
        return out;
    };
    let mut add = |vrf: &str, family: Option<&Value>| {
        let Some(Value::Object(peers)) = family.and_then(|f| f.get("peers")) else {
            return;
        };
        for p in peers.keys() {
            if let Ok(address) = p.parse::<Ipv4Addr>() {
                out.insert(Peer {
                    vrf: vrf.to_string(),
                    address,
                });
            }
        }
    };
    if top.contains_key("ipv4Unicast") {
        add(bgp::DEFAULT_VRF, top.get("ipv4Unicast"));
    } else {
        for (vrf, v) in &top {
            add(vrf, v.get("ipv4Unicast"));
        }
    }
    out
}

fn json(bytes: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|e| e.to_string())
}

fn array(v: &Value) -> Result<&Vec<Value>, String> {
    v.as_array()
        .ok_or_else(|| "the reply is not a JSON array".to_string())
}

fn s(v: &Value, key: &str) -> Cell {
    match v.get(key).and_then(Value::as_str) {
        Some(x) => Cell::Str(x.to_string()),
        None => Cell::Null,
    }
}

fn n(v: &Value, key: &str) -> Cell {
    match v.get(key).and_then(Value::as_u64) {
        Some(x) => Cell::U64(x),
        None => Cell::Null,
    }
}

fn required(v: &Value, key: &str, what: &str) -> Result<String, String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("{what} has no {key}"))
}

/// `ip -d -j link show`.
pub struct LinkExtract;

impl Extract for LinkExtract {
    fn table(&self) -> &'static TableSchema {
        &LINKS
    }

    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
        let v = json(bytes)?;
        array(&v)?
            .iter()
            .map(|l| {
                let flags = l.get("flags").and_then(Value::as_array);
                let up = flags.is_some_and(|f| f.iter().any(|x| x.as_str() == Some("UP")));
                let vlan = l
                    .get("linkinfo")
                    .filter(|i| i.get("info_kind").and_then(Value::as_str) == Some("vlan"))
                    .and_then(|i| i.get("info_data"))
                    .map_or(Cell::Null, |d| n(d, "id"));
                Ok(vec![
                    Cell::Str(required(l, "ifname", "a link")?),
                    s(l, "address"),
                    n(l, "mtu"),
                    Cell::Bool(up),
                    s(l, "operstate"),
                    s(l, "link"),
                    vlan,
                ])
            })
            .collect()
    }
}

/// `ip -j addr show`.
pub struct AddrExtract;

impl Extract for AddrExtract {
    fn table(&self) -> &'static TableSchema {
        &ADDRESSES
    }

    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
        let v = json(bytes)?;
        let mut out = Vec::new();
        for l in array(&v)? {
            let ifname = required(l, "ifname", "an interface")?;
            for a in l
                .get("addr_info")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let local = required(a, "local", "an address")?;
                let len = a
                    .get("prefixlen")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| format!("address {local} has no prefixlen"))?;
                out.push(vec![
                    Cell::Str(ifname.clone()),
                    Cell::Str(format!("{local}/{len}")),
                ]);
            }
        }
        Ok(out)
    }
}

/// `ip -j neigh show`.
pub struct NeighExtract;

impl Extract for NeighExtract {
    fn table(&self) -> &'static TableSchema {
        &NEIGHBOURS
    }

    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
        let v = json(bytes)?;
        array(&v)?
            .iter()
            .map(|e| {
                let state = e
                    .get("state")
                    .and_then(Value::as_array)
                    .map_or(Cell::Null, |s| {
                        let names: Vec<&str> = s.iter().filter_map(Value::as_str).collect();
                        Cell::Str(names.join(","))
                    });
                Ok(vec![
                    Cell::Str(required(e, "dev", "a neighbour")?),
                    Cell::Str(required(e, "dst", "a neighbour")?),
                    s(e, "lladdr"),
                    state,
                ])
            })
            .collect()
    }
}

/// The output of [`SPEED_COMMAND`]. A value that is not known is null.
pub struct SpeedExtract;

impl Extract for SpeedExtract {
    fn table(&self) -> &'static TableSchema {
        &LINK_SPEEDS
    }

    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
        let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
        Ok(text
            .lines()
            .filter_map(|line| {
                let mut it = line.split_whitespace();
                let name = it.next()?;
                let speed = it.next().and_then(|x| x.parse::<u64>().ok());
                let duplex = it.next().filter(|d| *d == "full" || *d == "half");
                Some(vec![
                    Cell::Str(name.to_string()),
                    speed.map_or(Cell::Null, Cell::U64),
                    duplex.map_or(Cell::Null, |d| Cell::Str(d.to_string())),
                ])
            })
            .collect())
    }
}

/// `show ip route vrf all json` and `show ipv6 route vrf all json` of FRR.
/// The reply is an object of VRFs, each an object of prefixes, or one
/// object of prefixes. Each next hop of a route gives one row.
pub struct RouteExtract;

impl Extract for RouteExtract {
    fn table(&self) -> &'static TableSchema {
        &ROUTES
    }

    fn rows(&self, bytes: &[u8]) -> Result<Vec<Row>, String> {
        let v = json(bytes)?;
        let top = v.as_object().ok_or("the reply is not a JSON object")?;
        let flat = top.values().all(Value::is_array);
        let vrfs: Vec<(&str, &serde_json::Map<String, Value>)> = if flat {
            vec![("default", top)]
        } else {
            top.iter()
                .map(|(k, p)| {
                    p.as_object()
                        .map(|p| (k.as_str(), p))
                        .ok_or_else(|| format!("vrf {k} is not a JSON object"))
                })
                .collect::<Result<_, _>>()?
        };
        let mut out = Vec::new();
        for (vrf, prefixes) in vrfs {
            for (prefix, routes) in prefixes {
                let routes = routes
                    .as_array()
                    .ok_or_else(|| format!("prefix {prefix} is not a JSON array"))?;
                for r in routes {
                    let vrf = r.get("vrfName").and_then(Value::as_str).unwrap_or(vrf);
                    let base = |hop: Option<&Value>| {
                        vec![
                            Cell::Str(vrf.to_string()),
                            Cell::Str(prefix.clone()),
                            r.get("protocol")
                                .and_then(Value::as_str)
                                .map_or(Cell::Str("unknown".into()), |p| Cell::Str(p.into())),
                            Cell::Bool(r.get("selected").and_then(Value::as_bool).unwrap_or(false)),
                            n(r, "distance"),
                            n(r, "metric"),
                            hop.map_or(Cell::Null, |h| s(h, "ip")),
                            hop.map_or(Cell::Null, |h| s(h, "interfaceName")),
                        ]
                    };
                    let hops = r.get("nexthops").and_then(Value::as_array);
                    match hops.filter(|h| !h.is_empty()) {
                        Some(hops) => out.extend(hops.iter().map(|h| base(Some(h)))),
                        None => out.push(base(None)),
                    }
                }
            }
        }
        Ok(out)
    }
}
