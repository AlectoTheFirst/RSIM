//! The text OSPF sections of IOS-XE and IOS-XR: `show ip ospf` and `show
//! ospf`, the interface and neighbour commands, and the database of each LSA
//! type, for OSPFv2 and OSPFv3.
//!
//! The database reader is the reader of HST `ospf_lsa_detail_rows` with the
//! OSPFv3 lines: each LSA starts at its `LS age:` line, a `Link States`
//! line gives the area of the LSAs below it, and a `Router with ID` line
//! gives the process. The VRF of a process is the VRF of its `Connected to
//! MPLS VPN Superbackbone, VRF` line, else of its `router ospf <process>
//! vrf <name>` line of the running config, else `default`. When the
//! IOS-XE running config is not fresh, the VRF of an OSPFv2 process with no
//! `Superbackbone` line is not read, and the outcome has a note for the
//! process. The neighbour table has no process column, and a neighbour
//! takes the process of its interface, else the first process.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use rsim_core::SourceSpan;
use rsim_routing::ospf::{AreaType, Interface, Neighbor, RouterId, Version};

use super::{Build, RawLink, RawLsa, RawPrefix, VersionSections, dotted, metric_type, num};
use crate::bgp::Answer;

/// The first word after `key` in a line, without a final comma.
fn after<'l>(line: &'l str, key: &str) -> Option<&'l str> {
    let i = line.find(key)?;
    line[i + key.len()..]
        .split_whitespace()
        .next()
        .map(|w| w.trim_end_matches(','))
}

/// The text after `key` at the start of a trimmed line.
fn field<'l>(line: &'l str, key: &str) -> Option<&'l str> {
    line.strip_prefix(key).map(str::trim)
}

/// The first run of digits of a text.
fn digits(s: &str) -> Option<String> {
    let start = s.find(|c: char| c.is_ascii_digit())?;
    let run: String = s[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    Some(run)
}

/// The text between `open` and the next `)` after it.
fn inside<'l>(line: &'l str, open: &str) -> Option<&'l str> {
    let i = line.find(open)? + open.len();
    let rest = &line[i..];
    Some(rest[..rest.find(')')?].trim())
}

/// A process of the process section.
#[derive(Default)]
struct Process {
    router_id: Option<RouterId>,
    vrf: Option<String>,
    areas: BTreeMap<Ipv4Addr, AreaType>,
}

/// The processes of `show ip ospf`, `show ospf`, `show ipv6 ospf` or `show
/// ospfv3`, from their `Routing Process` lines.
fn processes(text: &str) -> BTreeMap<String, Process> {
    let mut out: BTreeMap<String, Process> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut area: Option<Ipv4Addr> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Routing Process \"") {
            let name = rest.split('"').next().unwrap_or_default();
            let id = name
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_string();
            let p = out.entry(id.clone()).or_default();
            p.router_id = after(t, "with ID ").and_then(|r| r.parse().ok());
            current = Some(id);
            area = None;
            continue;
        }
        let Some(p) = current.as_ref().and_then(|c| out.get_mut(c)) else {
            continue;
        };
        if let Some(v) = after(t, "Connected to MPLS VPN Superbackbone, VRF ") {
            p.vrf = Some(v.to_string());
        } else if let Some(rest) = t.strip_prefix("Area ") {
            let id = match rest.strip_prefix("BACKBONE") {
                Some(b) => b.trim_start_matches('(').trim_end_matches(')'),
                None => rest,
            };
            if rest.split_whitespace().count() == 1
                && let Some(id) = dotted(id)
            {
                p.areas.insert(id, AreaType::Normal);
                area = Some(id);
            }
        } else if let Some(a) = area {
            if t.starts_with("It is a stub area") {
                p.areas.insert(a, AreaType::Stub);
            } else if t.starts_with("It is a NSSA area") {
                p.areas.insert(a, AreaType::Nssa);
            }
        }
    }
    out
}

/// The VRF of each process of the `router ospf <process> vrf <name>` lines
/// of a running config.
fn config_vrfs(config: &str) -> BTreeMap<String, String> {
    config
        .lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            match w.as_slice() {
                ["router", "ospf", p, "vrf", v, ..] => Some((p.to_string(), v.to_string())),
                _ => None,
            }
        })
        .collect()
}

/// An interface with its process.
struct Iface {
    process: Option<String>,
    interface: Interface,
}

/// The interfaces of the interface section: each header line `<name> is
/// up` with an area below it.
fn interfaces(text: &str, file: &str) -> Vec<Iface> {
    let mut out = Vec::new();
    let mut cur: Option<(Iface, u32)> = None;
    let mut last = 0;
    let flush = |cur: &mut Option<(Iface, u32)>, last: u32, out: &mut Vec<Iface>| {
        if let Some((mut i, first)) = cur.take()
            && i.interface.area.is_some()
        {
            i.interface.span = SourceSpan::new(file, first, last.max(first));
            out.push(i);
        }
    };
    for (n, line) in text.lines().enumerate() {
        let n = n as u32 + 1;
        let t = line.trim();
        if !line.starts_with(' ')
            && let Some((name, rest)) = t.split_once(" is ")
            && (rest.starts_with("up")
                || rest.starts_with("down")
                || rest.starts_with("administratively"))
            && !name.contains(' ')
        {
            flush(&mut cur, last, &mut out);
            cur = Some((
                Iface {
                    process: None,
                    interface: Interface {
                        name: name.to_string(),
                        area: None,
                        address: None,
                        interface_id: None,
                        cost: None,
                        span: SourceSpan::line(file, n),
                    },
                },
                n,
            ));
            last = n;
            continue;
        }
        let Some((cur, _)) = cur.as_mut() else {
            continue;
        };
        if !t.is_empty() {
            last = n;
        }
        let i = &mut cur.interface;
        if let Some(a) = after(t, "Internet Address ") {
            let (ip, len) = a.split_once('/').unwrap_or((a, ""));
            i.address = ip.parse::<IpAddr>().ok().map(|ip| (ip, len.parse().ok()));
        }
        let lower = t.to_ascii_lowercase();
        if let Some(i0) = lower.find("link local address ") {
            let a = t[i0 + "link local address ".len()..]
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .trim_end_matches(',');
            if let Ok(ip) = a.parse::<IpAddr>() {
                i.address = Some((ip, None));
            }
        }
        if let Some(id) = after(t, "Interface ID ") {
            i.interface_id = num(id);
        }
        if let Some(a) = after(t, "Area ").and_then(dotted)
            && (t.starts_with("Area ")
                || t.contains(", Area ")
                || t.starts_with("Internet Address"))
        {
            i.area = Some(a);
        }
        if let Some(p) = after(t, "Process ID ") {
            cur.process = Some(p.to_string());
        }
        if let Some(c) = after(t, "Cost: ") {
            i.cost = num(c);
        }
    }
    flush(&mut cur, last, &mut out);
    out
}

/// The neighbours of a neighbour table: each line whose first word is a
/// router ID and whose third word is the state. The address is the first
/// address after the state, and the interface is the last word.
fn neighbors(text: &str, file: &str) -> Vec<Neighbor> {
    text.lines()
        .enumerate()
        .filter_map(|(n, line)| {
            let w: Vec<&str> = line.split_whitespace().collect();
            let router_id: Ipv4Addr = w.first()?.parse().ok()?;
            let state = w.get(2)?;
            if w.len() < 4 || !state.chars().next()?.is_ascii_alphabetic() {
                return None;
            }
            Some(Neighbor {
                router_id,
                address: w[3..].iter().find_map(|x| x.parse::<IpAddr>().ok()),
                interface: w.last().map(|s| s.to_string()),
                state: Some(state.split('/').next().unwrap_or_default().to_string()),
                span: SourceSpan::line(file, n as u32 + 1),
            })
        })
        .collect()
}

/// The LSAs of a database section, with the process and the router ID of
/// each `Router with ID` line.
fn lsas(text: &str, file: &str, routers: &mut BTreeMap<String, RouterId>) -> Vec<(RawLsa, u32)> {
    let mut out: Vec<(RawLsa, u32)> = Vec::new();
    let mut process = String::new();
    let mut area: Option<String> = None;
    let mut cur: Option<(RawLsa, u32)> = None;
    let mut last = 0u32;
    let finish = |cur: &mut Option<(RawLsa, u32)>, last: u32, out: &mut Vec<(RawLsa, u32)>| {
        if let Some((mut r, first)) = cur.take() {
            r.span = SourceSpan::new(file, first, last.max(first));
            out.push((r, first));
        }
    };
    for (n, line) in text.lines().enumerate() {
        let n = n as u32 + 1;
        let t = line.trim();
        if t.contains("Router with ID (") {
            finish(&mut cur, last, &mut out);
            let rid = inside(t, "Router with ID (");
            if let Some(p) = inside(t, "(Process ID ") {
                process = p.split(',').next().unwrap_or_default().trim().to_string();
            }
            if let Some(r) = rid.and_then(|r| r.parse().ok()) {
                routers.insert(process.clone(), r);
            }
            continue;
        }
        if t.contains("Link States") {
            finish(&mut cur, last, &mut out);
            area = inside(t, "(Area ").map(str::to_string);
            continue;
        }
        if let Some(age) = field(t, "LS age:") {
            finish(&mut cur, last, &mut out);
            let mut r = RawLsa::new("", &process, SourceSpan::line(file, n));
            r.area = area.clone();
            r.age = digits(age);
            cur = Some((r, n));
            last = n;
            continue;
        }
        let Some((r, _)) = cur.as_mut() else { continue };
        if t.is_empty() {
            continue;
        }
        last = n;
        line_of_lsa(t, r);
    }
    finish(&mut cur, last, &mut out);
    out
}

/// Reads one line of an LSA.
fn line_of_lsa(t: &str, r: &mut RawLsa) {
    let first = |s: &str| s.split_whitespace().next().map(str::to_string);
    if let Some(v) = field(t, "LS Type:") {
        if let Some(i) = inside(v, "(Interface: ") {
            r.interface = Some(i.to_string());
        }
    } else if let Some(v) = field(t, "Link State ID:") {
        r.lsid = first(v);
    } else if let Some(v) = field(t, "Advertising Router:") {
        r.adv = first(v);
    } else if let Some(v) = field(t, "LS Seq Number:") {
        r.seq = first(v).map(|s| {
            if s.starts_with("0x") || s.starts_with("0X") {
                s
            } else {
                format!("0x{s}")
            }
        });
    } else if let Some(v) = field(t, "Link connected to:") {
        r.links.push(RawLink {
            kind: Some(v.to_string()),
            ..RawLink::default()
        });
    } else if t.starts_with("(Link ID)") {
        if let (Some(l), Some((_, v))) = (r.links.last_mut(), t.split_once(':')) {
            l.id = first(v);
        }
    } else if t.starts_with("(Link Data)") {
        if let (Some(l), Some((_, v))) = (r.links.last_mut(), t.split_once(':')) {
            l.data = first(v);
        }
    } else if let Some(v) = field(t, "TOS 0 Metrics:")
        .or_else(|| field(t, "TOS 0 Metric:"))
        .or_else(|| field(t, "Link Metric:"))
    {
        if let Some(l) = r.links.last_mut() {
            l.metric = first(v);
        }
    } else if let Some(v) = field(t, "Local Interface ID:") {
        if let Some(l) = r.links.last_mut() {
            l.interface_id = first(v);
        }
    } else if let Some(v) =
        field(t, "Neighbor Interface ID:").or_else(|| field(t, "Neighbor (DR) Interface ID:"))
    {
        if let Some(l) = r.links.last_mut() {
            l.neighbor_interface_id = first(v);
        }
    } else if let Some(v) =
        field(t, "Neighbor Router ID:").or_else(|| field(t, "Neighbor (DR) Router ID:"))
    {
        if let Some(l) = r.links.last_mut() {
            l.id = first(v);
        }
    } else if let Some(v) = field(t, "Attached Router:") {
        r.attached.extend(first(v));
    } else if let Some(v) = field(t, "Network Mask:") {
        r.mask = first(v);
    } else if let Some(v) = field(t, "Metric Type:") {
        r.metric_type = metric_type(v);
    } else if let Some(v) = field(t, "Forward Address:").or_else(|| field(t, "Forwarding Address:"))
    {
        r.forwarding = first(v);
    } else if let Some(v) = field(t, "Prefix Address:") {
        r.prefixes.push(RawPrefix {
            prefix: v.to_string(),
            ..RawPrefix::default()
        });
        r.prefix.get_or_insert_with(|| v.to_string());
    } else if let Some(v) = field(t, "Prefix Length:") {
        let len = first(v).map(|l| l.trim_end_matches(',').to_string());
        let metric = after(v, "Metric: ").map(str::to_string);
        if r.prefixes.len() <= 1 {
            r.prefix_len = len.clone();
        }
        if let Some(p) = r.prefixes.last_mut() {
            p.len = len;
            p.metric = metric;
        }
    } else if let Some(v) = field(t, "Link Local Address:") {
        r.link_local = first(v);
    } else if let Some(v) = field(t, "Referenced LSA Type:") {
        r.reference = Some(v.to_string());
    } else if let Some(v) = field(t, "Referenced Link State ID:") {
        r.reference_id = first(v);
    } else if let Some(v) = field(t, "Referenced Advertising Router:") {
        r.reference_adv = first(v);
    } else if let Some(v) = field(t, "Destination Router ID:") {
        r.router = first(v);
    } else if t.starts_with("Metric:") || t.contains(" Metric:") {
        r.metric = after(t, "Metric:").map(str::to_string);
    }
}

/// The databases of an IOS-XE or IOS-XR router for one version. `config`
/// is the running config answer of IOS-XE and `None` for IOS-XR.
pub(crate) fn cisco<'a>(
    v: &VersionSections,
    a: &impl Fn(&str) -> Answer<'a>,
    config: Option<Answer<'a>>,
) -> Build {
    let version = v.version;
    let mut b = Build::default();
    let text = |x: Answer<'a>| match x {
        Answer::Fresh(bytes, file) => Some((String::from_utf8_lossy(bytes).into_owned(), file)),
        _ => None,
    };
    let procs = text(a(v.process))
        .map(|(t, _)| processes(&t))
        .unwrap_or_default();
    let (cfg, cfg_missing) = match (version, config.map(text)) {
        (Version::V2, Some(Some((t, _)))) => (config_vrfs(&t), false),
        (Version::V2, Some(None)) => (BTreeMap::new(), true),
        _ => (BTreeMap::new(), false),
    };
    let vrf_of = |process: &str| -> String {
        procs
            .get(process)
            .and_then(|p| p.vrf.clone())
            .or_else(|| cfg.get(process).cloned())
            .unwrap_or_else(|| "default".to_string())
    };
    for (name, p) in &procs {
        let db = b.db(version, &vrf_of(name), name);
        db.router_id = p.router_id;
        db.area_types = p.areas.clone();
    }
    let first_process = procs.keys().next().cloned();
    let ifaces = text(a(v.interfaces))
        .map(|(t, f)| interfaces(&t, f))
        .unwrap_or_default();
    let mut process_of_iface = BTreeMap::new();
    for i in ifaces {
        let Some(p) = i.process.or_else(|| first_process.clone()) else {
            continue;
        };
        process_of_iface.insert(i.interface.name.clone(), p.clone());
        b.db(version, &vrf_of(&p), &p).interfaces.push(i.interface);
    }
    if let Some((t, f)) = text(a(v.neighbors)) {
        for n in neighbors(&t, f) {
            let p = n
                .interface
                .as_ref()
                .and_then(|i| process_of_iface.get(i).cloned())
                .or_else(|| first_process.clone());
            let Some(p) = p else { continue };
            b.db(version, &vrf_of(&p), &p).neighbors.push(n);
        }
    }
    let mut routers = BTreeMap::new();
    for (name, lsa_type) in v.lsdb {
        let Some((t, f)) = text(a(name)) else {
            continue;
        };
        for (mut raw, _) in lsas(&t, f, &mut routers) {
            raw.vrf = vrf_of(&raw.process);
            b.add(version, *lsa_type, &raw);
        }
    }
    for (p, rid) in routers {
        let db = b.db(version, &vrf_of(&p), &p);
        db.router_id.get_or_insert(rid);
    }
    if cfg_missing {
        let unread: Vec<String> = b
            .dbs
            .keys()
            .map(|(_, p)| p)
            .filter(|p| procs.get(*p).and_then(|x| x.vrf.as_ref()).is_none())
            .map(|p| format!("process {p}"))
            .collect();
        b.vrf_unread = unread;
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_words_after_a_key_and_the_digits_of_an_age() {
        assert_eq!(
            after("Process ID 1, Router ID 192.0.2.1", "Process ID "),
            Some("1")
        );
        assert_eq!(digits("MAXAGE(3600)"), Some("3600".to_string()));
        assert_eq!(
            inside(
                "OSPF Router with ID (192.0.2.1) (Process ID 1)",
                "(Process ID "
            ),
            Some("1")
        );
    }

    #[test]
    fn the_vrf_of_a_process_of_the_running_config() {
        let v = config_vrfs("router ospf 1\nrouter ospf 10 vrf RED\n router-id 192.0.2.1\n");
        assert_eq!(v.get("10").map(String::as_str), Some("RED"));
        assert!(!v.contains_key("1"));
    }

    #[test]
    fn a_process_with_a_stub_area() {
        let p = processes(
            " Routing Process \"ospf 1\" with ID 192.0.2.1\n Area BACKBONE(0)\n Area 1\n    It is a stub area\n",
        );
        let p = &p["1"];
        assert_eq!(p.router_id, Some("192.0.2.1".parse().unwrap()));
        assert_eq!(
            p.areas
                .iter()
                .map(|(a, t)| (a.to_string(), *t))
                .collect::<Vec<_>>(),
            [
                ("0.0.0.0".to_string(), AreaType::Normal),
                ("0.0.0.1".to_string(), AreaType::Stub)
            ]
        );
    }
}
