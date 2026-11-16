//! The VyOS source: read-only commands over SSH.

use std::sync::Arc;
use std::time::Duration;

use rsim_store::{
    ADDRESSES, Cell, Class, Format, LINK_SPEEDS, LINKS, NEIGHBOURS, ROUTES, Row, TableSchema,
};
use serde_json::Value;

use crate::{
    BoxFuture, Device, Extract, RawSection, SectionSpec, Source, Ssh, Vendor, fetch_sections,
};

/// The search path that each operational command sets, because `ip` is in
/// different directories in different VyOS releases.
pub const PATH: &str = "PATH=/usr/sbin:/sbin:/usr/bin:/bin";

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
    extract: Option<&'static dyn Extract>,
) -> SectionSpec {
    SectionSpec {
        name,
        command: command.to_string(),
        class,
        format,
        volatile,
        extract,
    }
}

/// The sections of a VyOS router.
pub fn sections() -> Vec<SectionSpec> {
    use Class::{Configuration, Observation};
    use Format::{Json, Text};
    const ROUTE_VOLATILE: &[&str] = &["/*/*/uptime", "/*/*/*/uptime"];
    vec![
        spec(
            "config",
            "show configuration json",
            Configuration,
            Json,
            &[],
            None,
        ),
        spec(
            "version",
            "show version",
            Configuration,
            Text,
            &["Uptime:"],
            None,
        ),
        spec(
            "links",
            &format!("{PATH} ip -d -j link show"),
            Observation,
            Json,
            &[],
            Some(&LinkExtract),
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
            Some(&AddrExtract),
        ),
        spec(
            "neighbours",
            &format!("{PATH} ip -j neigh show"),
            Observation,
            Json,
            &["/*/state"],
            Some(&NeighExtract),
        ),
        spec(
            "link_speeds",
            SPEED_COMMAND,
            Observation,
            Text,
            &[],
            Some(&SpeedExtract),
        ),
        spec(
            "routes_ipv4",
            &format!(r#"{PATH} vtysh -c "show ip route vrf all json""#),
            Observation,
            Json,
            ROUTE_VOLATILE,
            Some(&RouteExtract),
        ),
        spec(
            "routes_ipv6",
            &format!(r#"{PATH} vtysh -c "show ipv6 route vrf all json""#),
            Observation,
            Json,
            ROUTE_VOLATILE,
            Some(&RouteExtract),
        ),
    ]
}

impl Source for VyosSource {
    fn vendor(&self) -> Vendor {
        Vendor::Vyos
    }

    fn sections(&self, _: &Device) -> Vec<SectionSpec> {
        sections()
    }

    fn fetch<'a>(
        &'a self,
        device: &'a Device,
        timeout: Duration,
    ) -> BoxFuture<'a, Vec<RawSection>> {
        Box::pin(fetch_sections(sections(), timeout, move |command| {
            let ssh = self.ssh.clone();
            Box::pin(async move { ssh.run(device, &command).await })
        }))
    }
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
