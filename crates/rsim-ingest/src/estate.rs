//! The twin of a snapshot: the VyOS, IOS-XR and IOS-XE routers, the UniFi
//! sites, the NX-OS switches and the IOS-XE switches, with the links between
//! them, and the VeloCloud edges with their transport networks.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rsim_core::{PrefixTable, SourceSpan};
use rsim_engine::TwinBuilder;
use rsim_store::{Hash, Snapshot, Store, StoreError};
use serde_json::Value;

use crate::bgp::{self, SessionSections};
use crate::bgp_peers::{BgpConfig, InterfaceAddresses, address_of};
use crate::collected::{self, Collected};
use crate::coverage::{Coverage, Table, classify};
use crate::facts::{self, DeviceFacts};
use crate::links::{BgpPeerFact, PortAddress, Summary};
use crate::route_tables::RouteTables;
use crate::stanza::{Document, read_json};
use crate::{equinix, iosxe, iosxr, nxos, unifi, velocloud, vyos};

/// The twin builder of a snapshot, with the coverage, the unread handled
/// stanzas, the lowering notes, the BGP peers and the facts of each device.
pub struct Estate {
    pub builder: TwinBuilder,
    pub coverage: BTreeMap<String, Coverage>,
    pub unread: BTreeMap<String, Vec<String>>,
    pub notes: BTreeMap<String, Vec<String>>,
    /// The BGP peer facts of each device with a BGP neighbour, a listen
    /// range or an observed peer.
    pub bgp: BTreeMap<String, Vec<BgpPeerFact>>,
    /// The facts of each device of the snapshot, by twin device; empty for
    /// a twin of inputs with no snapshot.
    pub facts: BTreeMap<String, DeviceFacts>,
    /// The LLDP and CDP records that name a neighbour with no device in the
    /// twin.
    pub seen: Vec<crate::links::SeenNeighbour>,
    /// The circuits of each Equinix account, lowered or not.
    pub fabric: BTreeMap<String, Vec<equinix::CircuitRow>>,
}

fn short(h: &Hash) -> String {
    h.to_string().chars().take(12).collect()
}

/// The sections of a device, each with its file name.
type Sections = BTreeMap<String, (Vec<u8>, String)>;

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
    /// An IOS-XE router or switch: its running config, the file name of
    /// the config for the provenance, its collected state, and the text
    /// sections that the lowering reads, each with its file name.
    Iosxe {
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
    /// A VeloCloud enterprise: each section with its file name.
    Velocloud {
        name: String,
        sections: BTreeMap<String, (Vec<u8>, String)>,
    },
    /// An Equinix Fabric account: each section with its file name.
    Equinix {
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
            "iosxe" => match section("config")? {
                Some((config, file)) => {
                    let mut sections = BTreeMap::new();
                    for name in iosxe::SECTIONS {
                        if let Some(x) = section(name)? {
                            sections.insert(name.to_string(), x);
                        }
                    }
                    out.push(Input::Iosxe {
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
            "velocloud" => {
                let mut sections = BTreeMap::new();
                for name in velocloud::SECTIONS {
                    if let Some(x) = section(name)? {
                        sections.insert(name.to_string(), x);
                    }
                }
                out.push(Input::Velocloud {
                    name: device.clone(),
                    sections,
                });
            }
            "equinix" => {
                let mut sections = BTreeMap::new();
                for name in equinix::SECTIONS {
                    if let Some(x) = section(name)? {
                        sections.insert(name.to_string(), x);
                    }
                }
                out.push(Input::Equinix {
                    name: device.clone(),
                    sections,
                });
            }
            other => skipped.push(format!("{device}: vendor {other} not lowered")),
        }
    }
    Ok((out, skipped))
}

/// Reads the BGP session sections of each router and switch of a
/// snapshot, with the status of each section.
pub fn session_inputs(
    store: &Store,
    snap: &Snapshot,
) -> Result<BTreeMap<String, SessionSections>, StoreError> {
    let mut out = BTreeMap::new();
    for (device, m) in &snap.devices {
        let mut sections = SessionSections::new();
        for name in bgp::sections(&m.vendor) {
            let Some(entry) = m.section(name) else {
                continue;
            };
            let (bytes, file) = match entry.blob {
                Some(b) => (
                    Some(store.read_blob(&b)?),
                    format!("{device}/{name}@{}", short(&b)),
                ),
                None => (None, format!("{device}/{name}")),
            };
            sections.insert((*name).to_string(), bgp::Collected::of(entry, bytes, file));
        }
        out.insert(device.clone(), sections);
    }
    Ok(out)
}

/// Builds the twin of the devices of a snapshot.
pub fn build(store: &Store, snap: &Snapshot) -> Result<Estate, StoreError> {
    let (inputs, skipped) = inputs(store, snap)?;
    let sessions = session_inputs(store, snap)?;
    let mut e = assemble_with(inputs, &sessions);
    e.facts = facts::of_snapshot(store, snap)?;
    for s in skipped {
        e.notes.entry("estate".into()).or_default().push(s);
    }
    Ok(e)
}

/// Builds the twin of the inputs with no BGP session section.
pub fn assemble(inputs: Vec<Input>) -> Estate {
    assemble_with(inputs, &BTreeMap::new())
}

/// Builds the twin of the inputs with the BGP session sections of each
/// device. The first lowering of each NX-OS switch, each IOS-XR router and
/// each IOS-XE router or switch gives its summary, and the VeloCloud edges,
/// the VyOS routers and the root devices of the UniFi sites give theirs;
/// each router and switch adds its BGP peer facts, its local addresses and
/// the addresses of its ports to its summary. The link join of the
/// summaries gives the links. Then each UniFi site, each VyOS router, each
/// NX-OS switch, each IOS-XR router, each IOS-XE device and each VeloCloud
/// edge is lowered with its links.
pub fn assemble_with(inputs: Vec<Input>, sessions: &BTreeMap<String, SessionSections>) -> Estate {
    let mut e = Estate {
        builder: TwinBuilder::new(),
        coverage: BTreeMap::new(),
        unread: BTreeMap::new(),
        notes: BTreeMap::new(),
        bgp: BTreeMap::new(),
        facts: BTreeMap::new(),
        seen: Vec::new(),
        fabric: BTreeMap::new(),
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
    let mut xr: BTreeMap<String, (iosxr::Config, String, Sections)> = BTreeMap::new();
    let mut xe: BTreeMap<String, (iosxe::Config, String, Sections)> = BTreeMap::new();
    let mut sites = Vec::new();
    let mut enterprises: Vec<(String, Sections)> = Vec::new();
    let mut accounts: Vec<(String, Sections)> = Vec::new();
    // True for each device with a BGP stanza that can hold a neighbour and
    // that is not handled when no route rows are collected.
    let mut bgp_hidden: BTreeMap<String, bool> = BTreeMap::new();
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
                            .push(format!("config not JSON: {err}"));
                        continue;
                    }
                };
                let tables = RouteTables::new(
                    col.routes.iter().map(|r| r.vrf.clone()),
                    vyos::dynamic_vrfs(&doc),
                );
                let table = vyos::table(&tables);
                let bare = vyos::table(&RouteTables::uniform(false, vyos::dynamic_vrfs(&doc)));
                bgp_hidden.insert(name.clone(), peers_hidden(&doc, &bare));
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
                let tables = RouteTables::new(
                    col.routes.iter().map(|r| r.vrf.clone()),
                    nxos::dynamic_vrfs(&doc),
                );
                let table = nxos::table(&tables);
                let bare = nxos::table(&RouteTables::uniform(false, nxos::dynamic_vrfs(&doc)));
                bgp_hidden.insert(name.clone(), peers_hidden(&doc, &bare));
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
                let tables =
                    RouteTables::new(iosxr::rib_vrfs(&sections), iosxr::dynamic_vrfs(&doc));
                let table = iosxr::table(&tables);
                let bare = iosxr::table(&RouteTables::uniform(false, iosxr::dynamic_vrfs(&doc)));
                bgp_hidden.insert(name.clone(), peers_hidden(&doc, &bare));
                let cfg = iosxr::read(&doc, &table);
                e.coverage.insert(name.clone(), classify(&doc, &table));
                e.unread
                    .insert(name.clone(), iosxr::unread(&doc, &table, &cfg.read));
                xr.insert(name, (cfg, file, sections));
            }
            Input::Iosxe {
                name,
                config,
                file,
                sections,
                ..
            } => {
                let doc = iosxe::read_text(&config);
                let tables =
                    RouteTables::new(iosxe::rib_vrfs(&sections), iosxe::dynamic_vrfs(&doc));
                let table = iosxe::table(&tables);
                let bare = iosxe::table(&RouteTables::uniform(false, iosxe::dynamic_vrfs(&doc)));
                bgp_hidden.insert(name.clone(), peers_hidden(&doc, &bare));
                let cfg = iosxe::read(&doc, &table);
                e.coverage.insert(name.clone(), classify(&doc, &table));
                e.unread
                    .insert(name.clone(), iosxe::unread(&doc, &table, &cfg.read));
                xe.insert(name, (cfg, file, sections));
            }
            Input::Unifi { name, sections } => sites.push((name, sections)),
            Input::Velocloud { name, sections } => enterprises.push((name, sections)),
            Input::Equinix { name, sections } => accounts.push((name, sections)),
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
    let mut summaries: BTreeMap<String, crate::links::Summary> = switches
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
    // The first lowering of each IOS-XR router gives its summary.
    let xr_profile = iosxr::profile();
    for (d, (cfg, file, sections)) in &xr {
        let (_, sum) = iosxr::lower(
            d,
            file,
            &xr_profile,
            cfg,
            sections,
            &crate::links::External::default(),
        );
        summaries.insert(d.clone(), sum);
    }
    // The first lowering of each IOS-XE device gives its summary.
    let xe_profile = iosxe::profile();
    for (d, (cfg, file, sections)) in &xe {
        let (_, sum) = iosxe::lower(
            d,
            file,
            &xe_profile,
            cfg,
            sections,
            &crate::links::External::default(),
        );
        summaries.insert(d.clone(), sum);
    }
    // The VeloCloud enterprises: the coverage of the shared stanzas and of
    // each edge, and the summary of each edge, whose ports the join links by
    // address.
    let mut ents: Vec<velocloud::Enterprise> = Vec::new();
    for (device, sections) in &enterprises {
        let p = velocloud::Parsed::new(sections);
        let ent = velocloud::read(device, &velocloud::enterprise_of(device, &p), &p, &[]);
        e.coverage.insert(
            device.clone(),
            velocloud::coverage::classify_part(&p, velocloud::coverage::Part::Shared),
        );
        for edge in &ent.edges {
            e.coverage.insert(
                edge.device.clone(),
                velocloud::coverage::classify_part(
                    &p,
                    velocloud::coverage::Part::Edge(&edge.logical_id),
                ),
            );
        }
        summaries.extend(velocloud::summaries(&ent));
        ents.push(ent);
    }
    // The Equinix accounts: the coverage, and the summary of the gates and
    // the bindings of the Fabric ports.
    let mut fabric_accounts: Vec<(String, equinix::Account)> = Vec::new();
    for (device, sections) in &accounts {
        let p = velocloud::Parsed::new(sections);
        let account = equinix::read(device, &p);
        e.coverage
            .insert(device.clone(), equinix::coverage::classify(&p));
        let (sum, notes) = equinix::summary(&account);
        let n = e.notes.entry(device.clone()).or_default();
        n.extend(p.notes);
        n.extend(notes);
        summaries.insert(device.clone(), sum);
        fabric_accounts.push((device.clone(), account));
    }
    for s in summaries.values() {
        next_hops.extend(s.next_hops.iter().copied());
    }
    // The VyOS routers give their summaries too: the ports that can end a
    // link.
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
    for (cfg, _, sections) in xr.values() {
        device_macs.extend(iosxr::device_macs(cfg, sections));
    }
    for (cfg, _, sections) in xe.values() {
        device_macs.extend(iosxe::device_macs(cfg, sections));
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
    // The BGP peers and the local addresses of each router and switch.
    let mut peers = Peers {
        sessions,
        summaries: &mut summaries,
        hidden: &bgp_hidden,
        unread: &e.unread,
    };
    for (d, r) in &routers {
        let i = r.cfg.interfaces.iter().map(|i| {
            let addrs = i.addresses.iter().filter_map(|a| address_of(a)).collect();
            (i.name.clone(), i.vrf.clone(), addrs)
        });
        peers.add(d, "vyos", &r.file, &r.cfg.bgp, interfaces(i));
    }
    for (d, (cfg, _, file, _)) in &switches {
        let i = cfg.interfaces.iter().map(|i| {
            let v4 = i.addresses.iter().map(|a| a.prefix.as_str());
            let v6 = i.ipv6.iter().map(|a| a.0.as_str());
            let addrs = v4.chain(v6).filter_map(address_of).collect();
            (i.name.clone(), i.vrf.clone(), addrs)
        });
        peers.add(d, "nxos", file, &cfg.bgp, interfaces(i));
    }
    for (d, (cfg, file, _)) in &xr {
        let i = cfg.interfaces.iter().map(|i| {
            let v4 = i.addresses.iter().map(|a| a.prefix.as_str());
            let v6 = i.ipv6.iter().map(|a| a.0.as_str());
            let addrs = v4.chain(v6).filter_map(address_of).collect();
            (i.name.clone(), i.vrf.as_ref().map(|v| v.0.clone()), addrs)
        });
        peers.add(d, "iosxr", file, &cfg.bgp, interfaces(i));
    }
    for (d, (cfg, file, _)) in &xe {
        let i = cfg.interfaces.iter().map(|i| {
            let v4 = i.addresses.iter().map(|a| a.prefix.as_str());
            let v6 = i.ipv6.iter().map(|a| a.0.as_str());
            let addrs = v4.chain(v6).filter_map(address_of).collect();
            (i.name.clone(), i.vrf.as_ref().map(|v| v.0.clone()), addrs)
        });
        peers.add(d, "iosxe", file, &cfg.bgp, interfaces(i));
    }
    // The VRFs of the next hops of the collected route tables.
    for (d, r) in &routers {
        if let Some(s) = summaries.get_mut(d) {
            s.next_hop_vrfs = hop_vrfs(&r.col.routes);
        }
    }
    for (d, (_, col, _, _)) in &switches {
        if let Some(s) = summaries.get_mut(d) {
            s.next_hop_vrfs = hop_vrfs(&col.routes);
        }
    }
    let mut joined = crate::links::join(&summaries, &next_hops, &device_macs);
    for (d, notes) in std::mem::take(&mut joined.notes) {
        e.notes.entry(d).or_default().extend(notes);
    }
    // The BGP peers with their far ends; a peer outside the twin is a
    // router, not an endpoint.
    e.bgp = std::mem::take(&mut joined.bgp);
    e.seen = std::mem::take(&mut joined.seen);
    next_hops.extend(joined.bgp_outside.iter().copied());

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
                        span: SourceSpan::row(
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

    // The routers, with the layer 2 links and the addresses of the devices
    // of the twin.
    let profile = vyos::profile();
    let twin_addresses = device_addresses(&summaries);
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
        let low = vyos::lower(
            device,
            &r.file,
            &profile,
            &r.cfg,
            &col,
            &links,
            &twin_addresses,
        );
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

    // The IOS-XR routers, with their links.
    for (device, (cfg, file, sections)) in &xr {
        let ext = joined.devices.remove(device).unwrap_or_default();
        let (low, _) = iosxr::lower(device, file, &xr_profile, cfg, sections, &ext);
        e.notes.entry(device.clone()).or_default().extend(low.notes);
        for f in low.functions {
            e.builder.add_arc(f);
        }
        for x in low.edges {
            e.builder.edge_interface(x);
        }
    }

    // The IOS-XE routers and switches, with their links and endpoints.
    for (device, (cfg, file, sections)) in &xe {
        let ext = joined.devices.remove(device).unwrap_or_default();
        let (low, _) = iosxe::lower(device, file, &xe_profile, cfg, sections, &ext);
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

    // The Equinix accounts: the gate and the circuits of each Fabric port,
    // with the peer of each bound Fabric port.
    let eq_profile = equinix::profile();
    for (device, account) in &fabric_accounts {
        let ext = joined.devices.remove(device).unwrap_or_default();
        let peers: BTreeMap<String, rsim_core::FunctionId> = ext
            .peers
            .iter()
            .filter_map(|(port, list)| {
                let uuid = port.strip_prefix("port/")?;
                Some((uuid.to_string(), list.first()?.target.clone()))
            })
            .collect();
        let low = equinix::lower(account, &eq_profile, &peers);
        e.fabric.insert(device.clone(), low.circuits);
        e.notes.entry(device.clone()).or_default().extend(low.notes);
        for f in low.functions {
            e.builder.add_arc(f);
        }
    }

    // The VeloCloud edges, with their links, and the transport networks.
    let vc_profile = velocloud::profile();
    for ent in &ents {
        let low = velocloud::lower(
            ent,
            &vc_profile,
            velocloud::HubChoice::None,
            &joined.devices,
            &twin_addresses,
        );
        for (d, notes) in low.notes {
            e.notes.entry(d).or_default().extend(notes);
        }
        for f in low.functions {
            e.builder.add_arc(f);
        }
        for x in low.edges {
            e.builder.edge_interface(x);
        }
    }
    e
}

/// The addresses of each interface with its VRF, `default` for an
/// interface with no VRF.
fn interfaces(
    i: impl Iterator<Item = (String, Option<String>, Vec<IpAddr>)>,
) -> InterfaceAddresses {
    i.map(|(name, vrf, addrs)| {
        (
            name,
            (
                vrf.unwrap_or_else(|| crate::bgp_peers::DEFAULT_VRF.to_string()),
                addrs,
            ),
        )
    })
    .collect()
}

/// True if an unhandled or unread stanza of a BGP path can hold a neighbour
/// or a listen range that the peer facts do not have: the stanza is a BGP
/// process, a VRF, an address family, or a neighbour, group, template or
/// listen stanza itself. A setting line, for example a password or a policy
/// line below a neighbour, holds none. A segment `*` or `..` is the value of
/// the segment before it.
pub fn hides_peers(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    if !p.split(['/', ' ']).any(|w| w == "bgp") {
        return false;
    }
    let segs: Vec<&str> = p.split('/').collect();
    let mut last = segs.last().copied().unwrap_or_default();
    if matches!(last, "*" | "..") && segs.len() > 1 {
        last = segs[segs.len() - 2];
    }
    let words: Vec<&str> = last.split_whitespace().collect();
    match words.first().copied().unwrap_or_default() {
        "router" | "vrf" | "address-family" => true,
        "bgp" => words.len() == 1 || words.get(1) == Some(&"listen"),
        "neighbor" | "neighbour" | "neighbor-group" | "session-group" | "peer-group"
        | "template" | "listen" | "range" => words.len() <= 2,
        _ => false,
    }
}

/// True if a stanza of a BGP path that can hold a neighbour or a listen
/// range is unhandled with the table `bare`, the table of the device with
/// no collected route rows. The collected rows make the routing lines of a
/// BGP stanza known-irrelevant, and such a stanza can still hold a
/// neighbour that the reader does not read.
fn peers_hidden(doc: &Document, bare: &Table) -> bool {
    classify(doc, bare).unhandled.keys().any(|p| hides_peers(p))
}

/// The layer 3 addresses of the devices of the twin: the local addresses,
/// the addresses of the ports and the host addresses of the VLANs, which
/// hold the SVI addresses and the active virtual addresses.
fn device_addresses(summaries: &BTreeMap<String, Summary>) -> BTreeSet<IpAddr> {
    let mut out = BTreeSet::new();
    for s in summaries.values() {
        out.extend(s.local_addresses.values().flatten().copied());
        for vlans in s.l3.values() {
            out.extend(vlans.values().flatten().map(|(a, _)| *a));
        }
        for v in s.vlans.values() {
            for (p, _) in v.hosts.entries() {
                if p.len() == if p.addr().is_ipv4() { 32 } else { 128 } {
                    out.insert(p.addr());
                }
            }
        }
    }
    out
}

/// The VRFs of the next hops of the rows of a route table: the VRF of a
/// `%<vrf>` suffix, else the VRF of the row.
fn hop_vrfs(rows: &[collected::RouteRow]) -> BTreeMap<IpAddr, BTreeSet<String>> {
    let mut out: BTreeMap<IpAddr, BTreeSet<String>> = BTreeMap::new();
    for r in rows {
        let Some(hop) = r.next_hop.as_deref() else {
            continue;
        };
        let (addr, vrf) = hop.split_once('%').unwrap_or((hop, r.vrf.as_str()));
        if let Ok(a) = addr.parse::<IpAddr>() {
            out.entry(a).or_default().insert(vrf.to_string());
        }
    }
    out
}

/// The layer 3 address of each port of a summary with its VRF: the
/// addresses of `l3`, the addresses of each other port that ends a link,
/// and the host addresses of the VLANs, which hold the SVI addresses and
/// the active virtual addresses, at the port `Vlan<n>` with their VLAN. The
/// VRF of an address is the one VRF of the interfaces with the address,
/// and of a VLAN host the VRF of its SVI; none for the default VRF or for
/// an address of more than one VRF.
fn port_addresses(sum: &Summary, interfaces: &InterfaceAddresses) -> Vec<PortAddress> {
    let vrf_of = |a: IpAddr| -> Option<String> {
        let vrfs: BTreeSet<&String> = interfaces
            .values()
            .filter(|(_, addrs)| addrs.contains(&a))
            .map(|(v, _)| v)
            .collect();
        match vrfs.into_iter().collect::<Vec<_>>().as_slice() {
            [one] if one.as_str() != crate::bgp_peers::DEFAULT_VRF => Some((*one).clone()),
            _ => None,
        }
    };
    let mut out = Vec::new();
    for (port, vlans) in &sum.l3 {
        let spans: Vec<SourceSpan> = sum.port_spans.get(port).cloned().into_iter().collect();
        for (vlan, addrs) in vlans {
            for (a, _) in addrs {
                out.push(PortAddress {
                    port: port.clone(),
                    address: *a,
                    vlan: *vlan,
                    vrf: vrf_of(*a),
                    spans: spans.clone(),
                });
            }
        }
    }
    for port in sum.entries.keys() {
        if sum.l3.contains_key(port) || sum.ports.contains_key(port) {
            continue;
        }
        let Some((_, addrs)) = interfaces.get(port) else {
            continue;
        };
        let spans: Vec<SourceSpan> = sum.port_spans.get(port).cloned().into_iter().collect();
        for a in addrs {
            out.push(PortAddress {
                port: port.clone(),
                address: *a,
                vlan: None,
                vrf: vrf_of(*a),
                spans: spans.clone(),
            });
        }
    }
    let svi_vrfs = vlan_vrfs(interfaces);
    for (n, v) in &sum.vlans {
        let port = format!("Vlan{n}");
        for (p, host) in v.hosts.entries() {
            if p.len() != if p.addr().is_ipv4() { 32 } else { 128 } {
                continue;
            }
            let a = p.addr();
            if out.iter().any(|x| x.port == port && x.address == a) {
                continue;
            }
            out.push(PortAddress {
                port: port.clone(),
                address: a,
                vlan: Some(*n),
                vrf: svi_vrfs.get(n).cloned(),
                spans: host.spans.clone(),
            });
        }
    }
    out
}

/// The VRF of each SVI `Vlan<n>` in a VRF other than the default VRF.
fn vlan_vrfs(interfaces: &InterfaceAddresses) -> BTreeMap<u16, String> {
    interfaces
        .iter()
        .filter(|(_, (vrf, _))| vrf != crate::bgp_peers::DEFAULT_VRF)
        .filter_map(|(name, (vrf, _))| {
            let n = name.strip_prefix("Vlan")?.parse::<u16>().ok()?;
            Some((n, vrf.clone()))
        })
        .collect()
}

/// The BGP peer facts of the devices, into the summary of each device.
struct Peers<'a> {
    sessions: &'a BTreeMap<String, SessionSections>,
    summaries: &'a mut BTreeMap<String, Summary>,
    /// The devices with a BGP stanza that can hold a neighbour and that is
    /// not handled.
    hidden: &'a BTreeMap<String, bool>,
    unread: &'a BTreeMap<String, Vec<String>>,
}

impl Peers<'_> {
    fn add(
        &mut self,
        device: &str,
        vendor: &str,
        file: &str,
        cfg: &BgpConfig,
        interfaces: InterfaceAddresses,
    ) {
        let none = SessionSections::new();
        let s = bgp::read(vendor, self.sessions.get(device).unwrap_or(&none));
        let mut facts = crate::bgp_peers::facts(device, file, cfg, &s, &interfaces);
        let sum = self.summaries.entry(device.to_string()).or_default();
        let routes = std::mem::take(&mut sum.routes);
        crate::bgp_peers::lookup_sources(&mut facts, &routes, &interfaces);
        sum.local_addresses = crate::bgp_peers::local_addresses(&interfaces);
        sum.port_addresses = port_addresses(sum, &interfaces);
        sum.vlan_vrfs = vlan_vrfs(&interfaces);
        sum.bgp_read = !self.hidden.get(device).copied().unwrap_or(false)
            && !self
                .unread
                .get(device)
                .is_some_and(|u| u.iter().any(|p| hides_peers(p)));
        sum.bgp_peers = facts;
    }
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
