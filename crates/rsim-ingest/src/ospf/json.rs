//! The JSON OSPF sections: NX-OS `show ip ospf ... vrf all | json` and
//! `show ospfv3 ... vrf all | json`, and the FRR answers of VyOS.
//!
//! NX-OS keys each table by context, one for each process and VRF, under
//! `TABLE_ctx`. A database answer has an area level (`TABLE_area`) with the
//! LSAs below it, or the LSAs right below the context with the area on each
//! LSA; both are read. The keys are those of HST, with the names that HST
//! accepts for each field, and they are not confirmed on a device.
//!
//! The FRR OSPFv2 sections hold one object for each VRF, `{"answer": ...}`
//! or `{"failed": ...}`. An LSA is each object with the key
//! `advertisedRouter`, in the area of the member of `areas` above it. The
//! FRR OSPFv3 sections are the answers of the default VRF; an LSA is each
//! object with the key `advertisingRouter`, in the area of the `areaId` of
//! an object above it.

use rsim_core::SourceSpan;
use std::net::{IpAddr, Ipv4Addr};

use rsim_routing::ospf::{AreaType, Interface, Neighbor, Version};

use super::{
    Build, RawLink, RawLsa, RawPrefix, VersionSections, dotted, num, prefix, truthy, vrf_name,
};
use crate::bgp::Answer;
use crate::stanza::{Body, Document, Stanza, read_json};

fn span(file: &str, s: &Stanza) -> SourceSpan {
    SourceSpan::new(file, s.first_line, s.last_line.max(s.first_line))
}

/// The text of a scalar child, with `null` and an empty text as none.
fn scalar(s: &Stanza, key: &str) -> Option<String> {
    s.get(key)
        .and_then(Stanza::text)
        .filter(|t| *t != "null" && !t.is_empty())
        .map(str::to_string)
}

/// The first of the keys that the stanza has.
fn first(s: &Stanza, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| scalar(s, k))
}

/// The rows of an NX-OS table: `TABLE_<name>/ROW_<name>`, a list or one
/// object.
fn rows<'s>(s: &'s Stanza, name: &str) -> Vec<&'s Stanza> {
    let Some(r) = s
        .get(&format!("TABLE_{name}"))
        .and_then(|t| t.get(&format!("ROW_{name}")))
    else {
        return Vec::new();
    };
    match &r.body {
        Body::Array(items) => items.iter().collect(),
        Body::Object(_) => vec![r],
        Body::Scalar(_) => Vec::new(),
    }
}

/// The document of a fresh JSON answer. Another answer gives `None`; a
/// fresh answer that is not JSON goes in the parts that are not read.
fn doc<'a>(b: &mut Build, name: &str, answer: Answer<'a>) -> Option<(Document, &'a str)> {
    let Answer::Fresh(bytes, file) = answer else {
        return None;
    };
    match read_json(bytes) {
        Ok(d) => Some((d, file)),
        Err(e) => {
            b.unread.push(format!("{name} not JSON: {e}"));
            None
        }
    }
}

// NX-OS.

fn nx_context(ctx: &Stanza) -> (String, String) {
    (
        vrf_name(first(ctx, &["cname", "vrf_name_out", "vrf"]).as_deref()),
        first(ctx, &["ptag", "process_tag", "instance"]).unwrap_or_default(),
    )
}

fn nx_area(s: &Stanza) -> Option<String> {
    first(s, &["aid", "area", "area_id"])
}

fn nx_link(row: &Stanza) -> RawLink {
    RawLink {
        kind: first(row, &["type", "link_type", "lnk_type"]),
        id: first(
            row,
            &[
                "id",
                "link_id",
                "lnk_id",
                "nbr_rid",
                "nbr_router_id",
                "neighbor_router_id",
            ],
        ),
        data: first(row, &["data", "link_data", "lnk_data"]),
        metric: first(row, &["metric", "cost", "tos0_metric"]),
        interface_id: first(row, &["intf_id", "if_id", "ifid", "interface_id"]),
        neighbor_interface_id: first(
            row,
            &[
                "nbr_intf_id",
                "nbr_if_id",
                "nbr_ifid",
                "neighbor_interface_id",
            ],
        ),
    }
}

fn nx_lsa(lsa: &Stanza, vrf: &str, process: &str, area: Option<String>, file: &str) -> RawLsa {
    let mut r = RawLsa::new(vrf, process, span(file, lsa));
    r.area = area.or_else(|| nx_area(lsa));
    r.lsid = first(lsa, &["lsid", "id", "link_id", "ls_id"]);
    r.adv = first(lsa, &["advrouter", "adv_router", "adv_rtr", "advrtr"]);
    r.seq = first(lsa, &["seqno", "seq", "seq_no", "seqnum"]);
    r.age = first(lsa, &["age", "lsa_age"]);
    r.links = rows(lsa, "link").into_iter().map(nx_link).collect();
    r.attached = match lsa.get("attached_rtr").map(|a| &a.body) {
        Some(Body::Array(items)) => items
            .iter()
            .filter_map(Stanza::text)
            .map(str::to_string)
            .collect(),
        _ => rows(lsa, "rtr")
            .into_iter()
            .filter_map(|x| first(x, &["rtr", "rtrid", "attached_rtr", "id"]))
            .collect(),
    };
    r.mask = first(lsa, &["netmask", "mask", "masklen"]);
    r.prefix = first(lsa, &["prefix", "ipv6_prefix", "addr"]);
    r.prefix_len = first(lsa, &["prefixlen", "prefix_len", "plen"]);
    if r.mask.is_none() && r.prefix.is_none() {
        r.mask = r.prefix_len.clone();
    }
    r.metric = first(lsa, &["metric", "cost", "tos0_metric"]);
    r.metric_type = first(
        lsa,
        &["metrictype", "metric_type", "ext_type", "ebit", "e_bit"],
    );
    r.forwarding = first(lsa, &["fwdaddr", "fwd_addr", "forwarding_address"]);
    r.router = first(
        lsa,
        &["dest_rid", "dest_router_id", "destination_router_id"],
    );
    r.link_local = first(
        lsa,
        &[
            "lladdr",
            "link_local_addr",
            "linklocal",
            "link_local_address",
        ],
    );
    r.prefixes = rows(lsa, "prefix")
        .into_iter()
        .filter_map(|p| {
            Some(RawPrefix {
                prefix: first(p, &["prefix", "ipv6_prefix", "addr"])?,
                len: first(p, &["prefixlen", "prefix_len", "plen"]),
                metric: first(p, &["metric", "cost"]),
            })
        })
        .collect();
    r.reference = first(lsa, &["ref_type", "ref_lstype", "reference_type"]);
    r.reference_id = first(lsa, &["ref_lsid", "ref_ls_id", "reference_lsid"]);
    r.reference_adv = first(
        lsa,
        &[
            "ref_advrtr",
            "ref_adv_router",
            "ref_adv_rtr",
            "reference_adv_router",
        ],
    );
    r
}

/// The databases of an NX-OS switch for one version.
pub(crate) fn nxos<'a>(v: &VersionSections, a: &impl Fn(&str) -> Answer<'a>) -> Build {
    let version = v.version;
    let mut b = Build::default();
    if let Some((d, _)) = doc(&mut b, v.process, a(v.process)) {
        for ctx in rows(&d.root, "ctx") {
            let (vrf, process) = nx_context(ctx);
            let db = b.db(version, &vrf, &process);
            db.router_id =
                first(ctx, &["rid", "router_id", "routerid"]).and_then(|r| r.parse().ok());
            for area in rows(ctx, "area") {
                let Some(id) = nx_area(area).as_deref().and_then(dotted) else {
                    continue;
                };
                let kind = if first(area, &["nssa_area", "nssa"]).is_some_and(|x| truthy(&x)) {
                    AreaType::Nssa
                } else if first(area, &["stub_area", "stub"]).is_some_and(|x| truthy(&x)) {
                    AreaType::Stub
                } else {
                    AreaType::Normal
                };
                db.area_types.insert(id, kind);
            }
        }
    }
    if let Some((d, file)) = doc(&mut b, v.interfaces, a(v.interfaces)) {
        for ctx in rows(&d.root, "ctx") {
            let (vrf, process) = nx_context(ctx);
            for row in rows(ctx, "intf") {
                let Some(name) = first(row, &["ifname", "if_name", "intf_name"]) else {
                    continue;
                };
                let address = first(
                    row,
                    &["addr", "ip_addr", "ipaddr", "ipv6_addr", "linklocal"],
                )
                .and_then(|x| {
                    let (a, l) = match x.split_once('/') {
                        Some((a, l)) => (a.to_string(), l.parse().ok()),
                        None => (
                            x.clone(),
                            first(row, &["masklen", "mask_len", "prefixlen"])
                                .and_then(|l| l.parse().ok()),
                        ),
                    };
                    a.parse::<IpAddr>().ok().map(|a| (a, l))
                });
                let interface = Interface {
                    name,
                    area: nx_area(row).as_deref().and_then(dotted),
                    address,
                    interface_id: first(row, &["if_id", "ifid", "intf_id", "interface_id"])
                        .as_deref()
                        .and_then(num),
                    cost: first(row, &["cost", "if_cost"]).as_deref().and_then(num),
                    span: span(file, row),
                };
                b.db(version, &vrf, &process).interfaces.push(interface);
            }
        }
    }
    if let Some((d, file)) = doc(&mut b, v.neighbors, a(v.neighbors)) {
        for ctx in rows(&d.root, "ctx") {
            let (vrf, process) = nx_context(ctx);
            for row in rows(ctx, "nbr") {
                let Some(router_id) = first(row, &["rid", "nbr_rid", "router_id"])
                    .and_then(|r| r.parse::<Ipv4Addr>().ok())
                else {
                    continue;
                };
                let n = Neighbor {
                    router_id,
                    address: first(row, &["addr", "ipaddr", "nbr_addr"])
                        .and_then(|x| x.parse().ok()),
                    interface: first(row, &["intf", "ifname", "if_name"]),
                    state: first(row, &["state", "nbrstate", "nbr_state"]),
                    span: span(file, row),
                };
                b.db(version, &vrf, &process).neighbors.push(n);
            }
        }
    }
    for (name, lsa_type) in v.lsdb {
        let Some((d, file)) = doc(&mut b, name, a(name)) else {
            continue;
        };
        for ctx in rows(&d.root, "ctx") {
            let (vrf, process) = nx_context(ctx);
            let mut raws = Vec::new();
            for area in rows(ctx, "area") {
                for lsa in rows(area, "lsdb") {
                    raws.push(nx_lsa(lsa, &vrf, &process, nx_area(area), file));
                }
            }
            for lsa in rows(ctx, "lsdb") {
                raws.push(nx_lsa(lsa, &vrf, &process, None, file));
            }
            for r in &raws {
                b.add(version, *lsa_type, r);
            }
        }
    }
    b
}

// FRR.

/// The VRFs of a combined OSPFv2 section and their answers. A VRF whose
/// command failed goes in the parts that are not read.
fn frr_vrfs<'d>(b: &mut Build, name: &str, d: &'d Document) -> Vec<(String, &'d Stanza)> {
    let mut out = Vec::new();
    for v in d.root.children() {
        if let Some(e) = scalar(v, "failed") {
            b.unread.push(format!("{name} VRF {} failed: {e}", v.key));
            continue;
        }
        match v.get("answer") {
            Some(answer) if matches!(answer.body, Body::Object(_)) => {
                out.push((vrf_name(Some(&v.key)), answer));
            }
            _ => b
                .unread
                .push(format!("{name} VRF {} answer not JSON", v.key)),
        }
    }
    out
}

/// The answers of a version: the VRFs of the combined OSPFv2 section, or
/// the answer of the default VRF for OSPFv3.
fn frr_answers<'d>(
    b: &mut Build,
    version: Version,
    name: &str,
    d: &'d Document,
) -> Vec<(String, &'d Stanza)> {
    match version {
        Version::V2 => frr_vrfs(b, name, d),
        Version::V3 => vec![("default".to_string(), &d.root)],
    }
}

/// The links of an FRR router LSA: a list, or an object of links.
fn frr_links(lsa: &Stanza, version: Version) -> Vec<RawLink> {
    let list = match version {
        Version::V2 => lsa.get("routerLinks"),
        Version::V3 => lsa.get("lsaDescription"),
    };
    let Some(list) = list else {
        return Vec::new();
    };
    list.children()
        .iter()
        .map(|l| match version {
            Version::V2 => RawLink {
                kind: first(l, &["linkType", "type"]),
                id: first(
                    l,
                    &[
                        "linkId",
                        "neighborRouterId",
                        "designatedRouterAddress",
                        "networkAddress",
                    ],
                ),
                data: first(l, &["linkData", "routerInterfaceAddress", "networkMask"]),
                metric: first(l, &["metric", "tos0Metric"]),
                interface_id: None,
                neighbor_interface_id: None,
            },
            Version::V3 => RawLink {
                kind: first(l, &["type"]),
                id: first(l, &["neighborRouterId"]),
                data: None,
                metric: first(l, &["metric"]),
                interface_id: first(l, &["interfaceId"]),
                neighbor_interface_id: first(l, &["neighborInterfaceId"]),
            },
        })
        .collect()
}

/// The attached routers of an FRR network LSA: a list of IDs, or an
/// object of objects with `attachedRouterId`.
fn frr_attached(lsa: &Stanza) -> Vec<String> {
    let Some(a) = lsa
        .get("attachedRouters")
        .or_else(|| lsa.get("attachedRouter"))
    else {
        return Vec::new();
    };
    a.children()
        .iter()
        .filter_map(|c| {
            c.text()
                .map(str::to_string)
                .or_else(|| scalar(c, "attachedRouterId"))
        })
        .collect()
}

fn frr_lsa(
    lsa: &Stanza,
    version: Version,
    vrf: &str,
    area: Option<String>,
    iface: Option<String>,
    file: &str,
) -> RawLsa {
    let mut r = RawLsa::new(vrf, "", span(file, lsa));
    r.area = area;
    r.interface = iface;
    r.links = frr_links(lsa, version);
    r.attached = frr_attached(lsa);
    match version {
        Version::V2 => {
            r.lsid = first(lsa, &["lsId", "linkStateId"]);
            r.adv = first(lsa, &["advertisedRouter", "advertisingRouter"]);
            r.seq = first(lsa, &["lsaSeqNumber", "sequenceNumber"]).map(|s| {
                if s.starts_with("0x") {
                    s
                } else {
                    format!("0x{s}")
                }
            });
            r.age = first(lsa, &["lsaAge", "age"]);
            r.mask = first(lsa, &["networkMask"]);
            r.metric = first(lsa, &["metric", "tos0Metric"]);
            r.metric_type = first(lsa, &["metricType"]);
            r.forwarding = first(lsa, &["forwardAddress", "forwardingAddress"]);
        }
        Version::V3 => {
            r.lsid = first(lsa, &["linkStateId"]);
            r.adv = first(lsa, &["advertisingRouter"]);
            r.seq = first(lsa, &["lsSequenceNumber"]);
            r.age = first(lsa, &["age"]);
            r.metric = first(lsa, &["metric"]);
            r.metric_type =
                scalar(lsa, "bits").map(|b| (if b.contains('E') { "2" } else { "1" }).to_string());
            r.forwarding = first(lsa, &["forwardingAddress"]);
            r.router = first(lsa, &["destinationRouterId"]);
            r.link_local = first(lsa, &["linkLocalAddress"]);
            r.reference = first(lsa, &["reference"]);
            r.reference_id = first(lsa, &["referenceId"]);
            r.reference_adv = first(lsa, &["referenceAdv"]);
            match lsa.get("prefix").map(|p| &p.body) {
                Some(Body::Scalar(p)) => r.prefix = Some(p.clone()),
                Some(Body::Array(items)) => {
                    r.prefixes = items
                        .iter()
                        .filter_map(|p| {
                            Some(RawPrefix {
                                prefix: scalar(p, "prefix")?,
                                len: None,
                                metric: scalar(p, "metric"),
                            })
                        })
                        .collect();
                }
                _ => {}
            }
        }
    }
    r
}

/// The LSAs below a stanza: each object with the key of the advertising
/// router, with the area and the interface of the stanzas above it.
fn frr_walk(
    s: &Stanza,
    version: Version,
    vrf: &str,
    area: Option<String>,
    iface: Option<String>,
    file: &str,
    out: &mut Vec<RawLsa>,
) {
    let adv_key = match version {
        Version::V2 => "advertisedRouter",
        Version::V3 => "advertisingRouter",
    };
    if s.get(adv_key).is_some() {
        out.push(frr_lsa(s, version, vrf, area, iface, file));
        return;
    }
    let area = scalar(s, "areaId").or(area);
    let iface = first(s, &["interface", "interfaceName"]).or(iface);
    let areas_object = s.key == "areas";
    for c in s.children() {
        let a = if areas_object {
            Some(c.key.clone())
        } else {
            area.clone()
        };
        frr_walk(c, version, vrf, a, iface.clone(), file, out);
    }
}

/// The databases of a VyOS router for one version.
pub(crate) fn frr<'a>(v: &VersionSections, a: &impl Fn(&str) -> Answer<'a>) -> Build {
    let version = v.version;
    let mut b = Build::default();
    if let Some((d, _)) = doc(&mut b, v.process, a(v.process)) {
        for (vrf, ans) in frr_answers(&mut b, version, v.process, &d) {
            let db = b.db(version, &vrf, "");
            db.router_id = scalar(ans, "routerId").and_then(|r| r.parse().ok());
            if let Some(areas) = ans.get("areas") {
                for area in areas.children() {
                    let Some(id) = dotted(&area.key) else {
                        continue;
                    };
                    let flag = |keys: &[&str]| first(area, keys).is_some_and(|x| truthy(&x));
                    let kind = if flag(&["nssa", "areaIsNSSA", "areaIsNssa"]) {
                        AreaType::Nssa
                    } else if flag(&["stub", "areaIsStub"]) {
                        AreaType::Stub
                    } else {
                        AreaType::Normal
                    };
                    db.area_types.insert(id, kind);
                }
            }
        }
    }
    if let Some((d, file)) = doc(&mut b, v.interfaces, a(v.interfaces)) {
        for (vrf, ans) in frr_answers(&mut b, version, v.interfaces, &d) {
            let ifaces = ans.get("interfaces").unwrap_or(ans);
            for row in ifaces.children() {
                let Some(area) = first(row, &["area", "areaId"]) else {
                    continue;
                };
                let address = match version {
                    Version::V2 => scalar(row, "ipAddress").and_then(|x| {
                        x.parse::<IpAddr>().ok().map(|ip| {
                            (
                                ip,
                                scalar(row, "ipAddressPrefixlen").and_then(|l| l.parse().ok()),
                            )
                        })
                    }),
                    Version::V3 => row.get("internetAddress").and_then(|list| {
                        list.children().iter().find_map(|x| {
                            let p = scalar(x, "address")?;
                            let pf = prefix(&p, None)?;
                            (!pf.is_ipv4()).then(|| {
                                let (ip, _) = p.split_once('/').unwrap_or((p.as_str(), ""));
                                ip.parse::<IpAddr>().ok().map(|ip| (ip, Some(pf.len())))
                            })?
                        })
                    }),
                };
                let interface = Interface {
                    name: row.key.clone(),
                    area: dotted(&area),
                    address,
                    interface_id: first(row, &["interfaceId", "ifIndex"])
                        .as_deref()
                        .and_then(num),
                    cost: scalar(row, "cost").as_deref().and_then(num),
                    span: span(file, row),
                };
                b.db(version, &vrf, "").interfaces.push(interface);
            }
        }
    }
    if let Some((d, file)) = doc(&mut b, v.neighbors, a(v.neighbors)) {
        for (vrf, ans) in frr_answers(&mut b, version, v.neighbors, &d) {
            let Some(list) = ans.get("neighbors") else {
                continue;
            };
            let mut found = Vec::new();
            for entry in list.children() {
                let rows: Vec<&Stanza> = match &entry.body {
                    Body::Array(items) => items.iter().collect(),
                    _ => vec![entry],
                };
                for row in rows {
                    let id = scalar(row, "neighborId").unwrap_or_else(|| entry.key.clone());
                    let Ok(router_id) = id.parse::<Ipv4Addr>() else {
                        continue;
                    };
                    found.push(Neighbor {
                        router_id,
                        address: scalar(row, "address").and_then(|x| x.parse().ok()),
                        interface: first(row, &["ifaceName", "interfaceName"])
                            .map(|i| i.split(':').next().unwrap_or_default().trim().to_string()),
                        state: first(row, &["nbrState", "state"]).map(|s| {
                            s.split('/')
                                .next()
                                .unwrap_or_default()
                                .trim()
                                .to_uppercase()
                        }),
                        span: span(file, row),
                    });
                }
            }
            b.db(version, &vrf, "").neighbors.extend(found);
        }
    }
    for (name, lsa_type) in v.lsdb {
        let Some((d, file)) = doc(&mut b, name, a(name)) else {
            continue;
        };
        for (vrf, ans) in frr_answers(&mut b, version, name, &d) {
            let mut raws = Vec::new();
            frr_walk(ans, version, &vrf, None, None, file, &mut raws);
            for r in &raws {
                b.add(version, *lsa_type, r);
            }
        }
    }
    b
}
