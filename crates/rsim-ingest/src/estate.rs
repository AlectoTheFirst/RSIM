//! The twin of a snapshot: the VyOS routers and the UniFi sites, with the
//! links between them.

use std::collections::BTreeMap;

use rsim_core::{FunctionId, SourceSpan};
use rsim_engine::TwinBuilder;
use rsim_store::{Hash, Snapshot, Store, StoreError};
use serde_json::Value;

use crate::collected::{self, Collected};
use crate::coverage::{Coverage, classify};
use crate::stanza::read_json;
use crate::{unifi, vyos};

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
/// to the router on its uplink.
pub fn assemble(inputs: Vec<Input>) -> Estate {
    let mut e = Estate {
        builder: TwinBuilder::new(),
        coverage: BTreeMap::new(),
        unread: BTreeMap::new(),
        notes: BTreeMap::new(),
    };
    let mut routers: BTreeMap<String, Router> = BTreeMap::new();
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
            Input::Unifi { name, sections } => sites.push((name, sections)),
        }
    }

    let mut l2: BTreeMap<String, vyos::Layer2Links> = BTreeMap::new();
    let mut extra: BTreeMap<String, Vec<collected::NeighbourRow>> = BTreeMap::new();
    let profile = unifi_profile();
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
        let router = router_port(&site, &routers, &files.devices);
        let low = unifi::lower(device, &site, &profile, &files, router.as_ref());
        if let (Some(r), Some((iface, peer))) = (&router, &low.router_peer) {
            l2.entry(r.device.clone())
                .or_default()
                .insert(iface.clone(), (peer.clone(), r.provenance.clone()));
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
    e
}

/// The router port on the uplink of a site. A root device links to the
/// router on the port with an LLDP neighbour that has the MAC of a router
/// interface. With no such neighbour, it links on its uplink port if its
/// gateway MAC is the MAC of a router interface.
fn router_port(
    site: &unifi::Site,
    routers: &BTreeMap<String, Router>,
    devices_file: &str,
) -> Option<unifi::RouterPort> {
    let find = |mac: &str| {
        routers.iter().find_map(|(name, r)| {
            let row = r
                .col
                .links
                .iter()
                .find(|l| l.mac.as_deref().map(str::to_lowercase).as_deref() == Some(mac))?;
            Some((name, r, row))
        })
    };
    for d in site.devices.iter().filter(|d| d.uplink_peer.is_none()) {
        let by_lldp = d
            .lldp
            .iter()
            .find_map(|(p, chassis)| find(chassis).map(|x| (*p, x)));
        let by_gateway = || {
            let p = d.uplink_port?;
            let x = find(d.gateway_mac.as_deref()?)?;
            Some((p, x))
        };
        let Some((port, (name, r, row))) = by_lldp.or_else(by_gateway) else {
            continue;
        };
        let phys = row.parent.clone().unwrap_or_else(|| row.interface.clone());
        let mac = row.mac.as_deref()?.parse().ok()?;
        let mut vlans = BTreeMap::new();
        for (iface, list) in vyos::interface_addresses(&r.cfg, &r.col) {
            let (p, vlan) = vyos::physical(&iface);
            if p == phys {
                vlans.insert(vlan, list);
            }
        }
        let span = SourceSpan::line(devices_file, u32::try_from(d.index + 1).unwrap_or(u32::MAX));
        return Some(unifi::RouterPort {
            device: name.clone(),
            interface: phys.clone(),
            switch: d.mac.clone(),
            port,
            mac,
            handoff: FunctionId::new(format!("{name}/handoff/{phys}")),
            vlans,
            provenance: vec![span, row.span.clone()],
        });
    }
    None
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
