//! The twin of a snapshot: the VyOS routers and the UniFi sites, with the
//! links between them, the NX-OS switches, and the IOS-XR routers with no
//! link to another device.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::SourceSpan;
use rsim_engine::TwinBuilder;
use rsim_store::{Hash, Snapshot, Store, StoreError};
use serde_json::Value;

use crate::collected::{self, Collected};
use crate::coverage::{Coverage, classify};
use crate::stanza::read_json;
use crate::{iosxr, nxos, unifi, vyos};

/// The twin builder of a snapshot, with the coverage, the unread handled
/// stanzas and the lowering notes of each device.
pub struct Estate {
    pub builder: TwinBuilder,
    pub coverage: BTreeMap<String, Coverage>,
    pub unread: BTreeMap<String, Vec<String>>,
    pub notes: BTreeMap<String, Vec<String>>,
}

fn short(h: &Hash) -> String {
    h.to_string().chars().take(12).collect()
}

struct Router {
    cfg: vyos::Config,
    col: Collected,
    file: String,
}

/// The sections of one device.
pub enum Input {
    /// A VyOS router: its config section, the file name of the config for
    /// the provenance, and its collected state.
    Vyos {
        name: String,
        config: Vec<u8>,
        file: String,
        collected: Collected,
    },
    /// An NX-OS switch: its running config, the file name of the config
    /// for the provenance, its collected state, and the JSON sections that
    /// the lowering reads, each with its file name.
    Nxos {
        name: String,
        config: Vec<u8>,
        file: String,
        collected: Collected,
        sections: BTreeMap<String, (Vec<u8>, String)>,
    },
    /// An IOS-XR router: its running config, the file name of the config
    /// for the provenance, its collected state, and the text sections that
    /// the lowering reads, each with its file name.
    Iosxr {
        name: String,
        config: Vec<u8>,
        file: String,
        collected: Collected,
        sections: BTreeMap<String, (Vec<u8>, String)>,
    },
    /// A UniFi site: each section with its file name.
    Unifi {
        name: String,
        sections: BTreeMap<String, (Vec<u8>, String)>,
    },
}

/// Reads the inputs of the devices of a snapshot.
pub fn inputs(store: &Store, snap: &Snapshot) -> Result<(Vec<Input>, Vec<String>), StoreError> {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    for (device, m) in &snap.devices {
        let section = |name: &str| -> Result<Option<(Vec<u8>, String)>, StoreError> {
            match m.section(name).and_then(|s| s.blob) {
                Some(b) => Ok(Some((
                    store.read_blob(&b)?,
                    format!("{device}/{name}@{}", short(&b)),
                ))),
                None => Ok(None),
            }
        };
        match m.vendor.as_str() {
            "vyos" => match section("config")? {
                Some((config, file)) => out.push(Input::Vyos {
                    name: device.clone(),
                    config,
                    file,
                    collected: collected::read(store, snap, device)?,
                }),
                None => skipped.push(format!("{device}: no config section")),
            },
            "nxos" => match section("config")? {
                Some((config, file)) => {
                    let mut sections = BTreeMap::new();
                    for name in nxos::SECTIONS {
                        if let Some(x) = section(name)? {
                            sections.insert(name.to_string(), x);
                        }
                    }
                    out.push(Input::Nxos {
                        name: device.clone(),
                        config,
                        file,
                        collected: collected::read(store, snap, device)?,
                        sections,
                    })
                }
                None => skipped.push(format!("{device}: no config section")),
            },
            "iosxr" => match section("config")? {
                Some((config, file)) => {
                    let mut sections = BTreeMap::new();
                    for name in iosxr::SECTIONS {
                        if let Some(x) = section(name)? {
                            sections.insert(name.to_string(), x);
                        }
                    }
                    out.push(Input::Iosxr {
                        name: device.clone(),
                        config,
                        file,
                        collected: collected::read(store, snap, device)?,
                        sections,
                    })
                }
                None => skipped.push(format!("{device}: no config section")),
            },
            "unifi" => {
                let mut sections = BTreeMap::new();
                for name in ["networks", "wlans", "devices", "clients", "port_profiles"] {
                    if let Some(x) = section(name)? {
                        sections.insert(name.to_string(), x);
                    }
                }
                out.push(Input::Unifi {
                    name: device.clone(),
                    sections,
                });
            }
            other => skipped.push(format!("{device}: vendor {other} is not lowered")),
        }
    }
    Ok((out, skipped))
}

/// Builds the twin of the devices of a snapshot.
pub fn build(store: &Store, snap: &Snapshot) -> Result<Estate, StoreError> {
    let (inputs, skipped) = inputs(store, snap)?;
    let mut e = assemble(inputs);
    for s in skipped {
        e.notes.entry("estate".into()).or_default().push(s);
    }
    Ok(e)
}

/// Builds the twin of the inputs: the routers, then each UniFi site joined
/// to the router on its uplink, then each NX-OS switch. An IOS-XR router
/// gives its layer 3 functions with no link to another device.
pub fn assemble(inputs: Vec<Input>) -> Estate {
    let mut e = Estate {
        builder: TwinBuilder::new(),
        coverage: BTreeMap::new(),
        unread: BTreeMap::new(),
        notes: BTreeMap::new(),
    };
    let mut routers: BTreeMap<String, Router> = BTreeMap::new();
    #[allow(clippy::type_complexity)]
    let mut switches: BTreeMap<
        String,
        (
            nxos::Config,
            Collected,
            String,
            BTreeMap<String, (Vec<u8>, String)>,
        ),
    > = BTreeMap::new();
    let mut sites = Vec::new();
    for input in inputs {
        match input {
            Input::Vyos {
                name,
                config,
                file,
                collected: col,
            } => {
                let doc = match read_json(&config) {
                    Ok(d) => d,
                    Err(err) => {
                        e.notes
                            .entry(name)
                            .or_default()
                            .push(format!("the config is not JSON: {err}"));
                        continue;
                    }
                };
                let table = vyos::table(!col.routes.is_empty());
                let cfg = vyos::read(&doc);
                e.coverage.insert(name.clone(), classify(&doc, &table));
                e.unread
                    .insert(name.clone(), vyos::unread(&doc, &table, &cfg.read));
                routers.insert(name, Router { cfg, col, file });
            }
            Input::Nxos {
                name,
                config,
                file,
                collected: col,
                sections,
            } => {
                let doc = nxos::read_text(&config);
                let table = nxos::table(!col.routes.is_empty());
                let cfg = nxos::read(&doc, &table);
                e.coverage.insert(name.clone(), classify(&doc, &table));
                e.unread
                    .insert(name.clone(), nxos::unread(&doc, &table, &cfg.read));
                switches.insert(name, (cfg, col, file, sections));
            }
            Input::Iosxr {
                name,
                config,
                file,
                sections,
                ..
            } => {
                let doc = iosxr::read_text(&config);
                let table = iosxr::table(iosxr::rib_collected(&sections));
                let cfg = iosxr::read(&doc, &table);
                e.coverage.insert(name.clone(), classify(&doc, &table));
                e.unread
                    .insert(name.clone(), iosxr::unread(&doc, &table, &cfg.read));
                let low = iosxr::lower(&name, &file, &iosxr::profile(), &cfg, &sections);
                e.notes.entry(name).or_default().extend(low.notes);
                for f in low.functions {
                    e.builder.add_arc(f);
                }
                for x in low.edges {
                    e.builder.edge_interface(x);
                }
            }
            Input::Unifi { name, sections } => sites.push((name, sections)),
        }
    }

    // The next hops of the routes of the routers: the collected route table
    // and the static routes.
    let mut next_hops: BTreeSet<IpAddr> = BTreeSet::new();
    for r in routers.values() {
        next_hops.extend(
            r.col
                .routes
                .iter()
                .filter_map(|x| x.next_hop.as_deref()?.parse::<IpAddr>().ok()),
        );
        next_hops.extend(
            r.cfg
                .static_routes
                .iter()
                .flat_map(|x| x.gateways.iter())
                .filter_map(|g| g.parse::<IpAddr>().ok()),
        );
    }

    // The first lowering of each NX-OS switch gives its summary. Its next
    // hops join the set, and the summaries give the links and the places of
    // the endpoints.
    let nx_profile = nxos::profile();
    let summaries: BTreeMap<String, crate::links::Summary> = switches
        .iter()
        .map(|(d, (cfg, col, file, sections))| {
            let (_, sum) = nxos::lower(
                d,
                file,
                &nx_profile,
                cfg,
                col,
                sections,
                &crate::links::External::default(),
            );
            (d.clone(), sum)
        })
        .collect();
    for s in summaries.values() {
        next_hops.extend(s.next_hops.iter().copied());
    }
    // The routers give their summaries too: the ports that can end a link.
    let mut summaries = summaries;
    for (d, r) in &routers {
        summaries.insert(d.clone(), vyos::link_summary(d, &r.cfg, &r.col));
    }
    // The MACs of the collected devices: the interfaces of the routers and
    // of the switches, and the UniFi devices. None of them is an endpoint.
    let mut device_macs: BTreeSet<rsim_core::Mac> = BTreeSet::new();
    for r in routers.values() {
        device_macs.extend(
            r.col
                .links
                .iter()
                .filter_map(|l| nxos::state::mac(l.mac.as_deref()?)),
        );
    }
    for (_, col, _, _) in switches.values() {
        device_macs.extend(
            col.links
                .iter()
                .filter_map(|l| nxos::state::mac(l.mac.as_deref()?)),
        );
    }
    for (_, sections) in &sites {
        let devices = sections
            .get("devices")
            .and_then(|(b, _)| serde_json::from_slice::<Value>(b).ok())
            .unwrap_or(Value::Null);
        let site = unifi::read(&Value::Null, &Value::Null, &devices, &Value::Null);
        device_macs.extend(site.devices.iter().filter_map(|d| nxos::state::mac(&d.mac)));
    }
    // The UniFi sites: their coverage, and the summaries of their root
    // devices for the join.
    let mut parsed: Vec<(String, unifi::Site, unifi::Files)> = Vec::new();
    for (device, sections) in &sites {
        let mut cov = Coverage::default();
        let mut docs: BTreeMap<&str, (Value, String)> = BTreeMap::new();
        for (name, (bytes, file)) in sections {
            let v: Value = serde_json::from_slice(bytes).unwrap_or(Value::Null);
            if let Ok(doc) = read_json(bytes) {
                let rules = match name.as_str() {
                    "networks" => Some(&unifi::coverage::NETWORKS),
                    "wlans" => Some(&unifi::coverage::WLANS),
                    "port_profiles" => Some(&unifi::coverage::PORT_PROFILES),
                    _ => None,
                };
                if let Some(r) = rules {
                    unifi::coverage::classify(&doc, name, r, &mut cov);
                }
            }
            docs.insert(name.as_str(), (v, file.clone()));
        }
        e.coverage.insert(device.clone(), cov);
        let get = |n: &str| docs.get(n).map_or(Value::Null, |x| x.0.clone());
        let file = |n: &str| {
            docs.get(n)
                .map_or_else(|| format!("{device}/{n}"), |x| x.1.clone())
        };
        let site = unifi::read(
            &get("networks"),
            &get("wlans"),
            &get("devices"),
            &get("clients"),
        );
        let files = unifi::Files {
            devices: file("devices"),
            clients: file("clients"),
            networks: file("networks"),
            wlans: file("wlans"),
        };
        parsed.push((device.clone(), site, files));
    }
    for (_, site, files) in &parsed {
        summaries.extend(unifi::link_summary(site, files));
    }
    let mut joined = crate::links::join(&summaries, &next_hops, &device_macs);
    for (d, notes) in std::mem::take(&mut joined.notes) {
        e.notes.entry(d).or_default().extend(notes);
    }

    let mut l2: BTreeMap<String, vyos::Layer2Links> = BTreeMap::new();
    let mut extra: BTreeMap<String, Vec<collected::NeighbourRow>> = BTreeMap::new();
    let profile = unifi_profile();
    for (device, site, files) in &parsed {
        // The far end of the link of a root device, from the join.
        let router = site
            .devices
            .iter()
            .filter(|d| d.uplink_peer.is_none())
            .find_map(|d| {
                let port = d.uplink_port?;
                let peers = joined
                    .devices
                    .get(&d.name)?
                    .peers
                    .get(&format!("port/{port}"))?;
                let [p] = peers.as_slice() else {
                    return None;
                };
                let far = summaries.get(&p.far.0)?;
                Some(unifi::RouterPort {
                    device: p.far.0.clone(),
                    interface: p.far.1.clone(),
                    switch: d.mac.clone(),
                    port,
                    mac: *far.port_macs.get(&p.far.1)?,
                    handoff: p.target.clone(),
                    facts: far.facts.get(&p.far.1).cloned(),
                    vlans: far.l3.get(&p.far.1).cloned().unwrap_or_default(),
                    provenance: p.provenance.clone(),
                })
            });
        let low = unifi::lower(device, site, &profile, files, router.as_ref(), &next_hops);
        if let Some(r) = &router {
            // The clients of the site are neighbours of the router on the
            // interface of their VLAN.
            for c in &site.clients {
                let (Some(ip), Some(net)) =
                    (&c.ip, c.network.as_deref().and_then(|n| site.network(n)))
                else {
                    continue;
                };
                if !r.vlans.contains_key(&net.vlan) {
                    continue;
                }
                let interface = match net.vlan {
                    Some(v) => format!("{}.{v}", r.interface),
                    None => r.interface.clone(),
                };
                extra
                    .entry(r.device.clone())
                    .or_default()
                    .push(collected::NeighbourRow {
                        interface,
                        ip: ip.clone(),
                        mac: Some(c.mac.clone()),
                        state: Some("CLIENT".into()),
                        span: SourceSpan::line(
                            &files.clients,
                            u32::try_from(c.index + 1).unwrap_or(u32::MAX),
                        ),
                    });
            }
        }
        e.notes.entry(device.clone()).or_default().extend(low.notes);
        for f in low.functions {
            e.builder.add_arc(f);
        }
        for x in low.endpoints {
            e.builder.endpoint(x);
        }
        for a in low.attachments {
            e.builder.attachment(a);
        }
    }

    // The links of the routers from the join.
    for r in routers.keys() {
        let Some(ext) = joined.devices.get(r) else {
            continue;
        };
        for (iface, peers) in &ext.peers {
            if let [p] = peers.as_slice() {
                l2.entry(r.clone()).or_default().insert(
                    iface.clone(),
                    (p.target.clone(), p.provenance.clone(), p.remote.clone()),
                );
            }
        }
    }

    // The routers, with the layer 2 links.
    let profile = vyos::profile();
    for (device, r) in &routers {
        let links = l2.get(device).cloned().unwrap_or_default();
        let mut col = r.col.clone();
        // A client row replaces an ARP entry with no MAC or a failed
        // state, and does not replace a usable ARP entry.
        for row in extra.remove(device).unwrap_or_default() {
            let usable = |n: &collected::NeighbourRow| {
                n.mac.is_some()
                    && !n
                        .state
                        .as_deref()
                        .is_some_and(|s| s.contains("FAILED") || s.contains("INCOMPLETE"))
            };
            let same = |n: &collected::NeighbourRow| n.ip == row.ip && n.interface == row.interface;
            if col.neighbours.iter().any(|n| same(n) && usable(n)) {
                continue;
            }
            col.neighbours.retain(|n| !same(n));
            col.neighbours.push(row);
        }
        let low = vyos::lower(device, &r.file, &profile, &r.cfg, &col, &links);
        e.notes.entry(device.clone()).or_default().extend(low.notes);
        for f in low.functions {
            e.builder.add_arc(f);
        }
        for x in low.edges {
            e.builder.edge_interface(x);
        }
    }

    // The NX-OS switches, with their links and endpoints.
    for (device, (cfg, col, file, sections)) in &switches {
        let ext = joined.devices.remove(device).unwrap_or_default();
        let (low, _) = nxos::lower(device, file, &nx_profile, cfg, col, sections, &ext);
        e.notes.entry(device.clone()).or_default().extend(low.notes);
        for f in low.functions {
            e.builder.add_arc(f);
        }
        for x in low.edges {
            e.builder.edge_interface(x);
        }
        for x in low.endpoints {
            e.builder.endpoint(x);
        }
        for a in low.attachments {
            e.builder.attachment(a);
        }
    }
    e
}

/// The vendor profile of UniFi switches and access points. They have no
/// ACL, firewall or NAT functions, so only the name and the source matter.
pub fn unifi_profile() -> rsim_functions::VendorProfile {
    rsim_functions::VendorProfile {
        name: "unifi".to_string(),
        acl_default: rsim_functions::RuleAction::Deny,
        firewall_default: rsim_functions::RuleAction::Deny,
        unzoned_interface: rsim_functions::UnzonedInterface::Unknown,
        snat_port: rsim_functions::PortTranslation::Preserve,
        intra_zone_default: None,
        default_vrf: None,
        processing_delay_ns: None,
        source: vec![SourceSpan::line(
            "profiles/unifi: switches and access points",
            1,
        )],
    }
}
