//! The tables of the collected state: the frame of the rows of each device,
//! shared by the twins that hold the same rows, and the join columns.
//!
//! The rows of 1 device in 1 table are a frame of their own (a part), with
//! the key `PartKey`: the store folder, the table, the device and the
//! place of its rows in each store table. A twin holds the parts of its
//! tables, and a process-wide map holds a weak reference to each part, so
//! a twin of a newer snapshot builds only the parts of the devices whose
//! rows changed. The frame of the table is the parts in the key order of
//! their devices. The join columns are filled for each twin after that,
//! from the facts of all devices, so a change of 1 device changes the join
//! columns of the rows of other devices.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use arrow_array::RecordBatch;
use rayon::prelude::*;
use rsim_contract::table::TableDef;
use rsim_functions::PortIngress;

use super::{Owned, key_text, rows_of, store_value, twin_links};
use crate::commands::Loaded;
use crate::frame::{self, Cell, Frame, FrameBuilder};

/// The place of the rows of 1 device in 1 table: the store folder, the
/// table, the device, and for each store table of the table its name, the
/// cycle of its file, the schema version, the first row and the number of
/// rows.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PartKey {
    store: PathBuf,
    table: &'static str,
    device: String,
    rows: Vec<(&'static str, u64, u32, u64, u64)>,
}

/// The rows of each device in each store table of a table, by the name of
/// the store table.
type StoreRows = Vec<(&'static str, Vec<(String, RecordBatch)>)>;

/// The far ends of the links of the twin, by device and interface: the
/// peer device and the peer interface, if the far end has one.
type Peers = HashMap<(String, String), BTreeSet<(String, Option<String>)>>;

/// The parts that a twin holds, by their key.
fn parts() -> &'static Mutex<HashMap<PartKey, Weak<Frame>>> {
    static PARTS: OnceLock<Mutex<HashMap<PartKey, Weak<Frame>>>> = OnceLock::new();
    PARTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The frame of a table of the collected state, with the parts that it is
/// made of. A twin with no store has no rows.
pub(super) fn build(
    t: &Loaded,
    def: &'static TableDef,
) -> Result<(Frame, Vec<Arc<Frame>>), String> {
    let Some(src) = &t.source else {
        let mut f = FrameBuilder::new(def).finish(&key_text);
        fill_joins(t, def, &mut f)?;
        return Ok((f, Vec::new()));
    };
    let schemas = def
        .collected
        .iter()
        .map(|n| rsim_store::table(n).ok_or_else(|| format!("{n} is not a store table")))
        .collect::<Result<Vec<_>, _>>()?;
    // The devices with rows, in the key order of the device.
    let mut devices: Vec<(String, PartKey)> = Vec::new();
    for (device, m) in &src.snapshot.devices {
        let rows: Vec<_> = schemas
            .iter()
            .filter_map(|s| {
                m.tables
                    .get(s.name)
                    .map(|r| (s.name, r.cycle, r.version, r.first_row, r.rows))
            })
            .collect();
        if rows.is_empty() {
            continue;
        }
        let key = PartKey {
            store: src.store.dir().to_path_buf(),
            table: def.name,
            device: device.clone(),
            rows,
        };
        devices.push((key_text(device).unwrap_or_else(|| device.clone()), key));
    }
    devices.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.device.cmp(&b.1.device)));
    let read = |keep: &dyn Fn(&str) -> bool| -> Result<StoreRows, String> {
        schemas
            .iter()
            .map(|s| {
                src.store
                    .read_table_of(&src.snapshot, s, keep)
                    .map(|b| (s.name, b))
                    .map_err(|e| e.to_string())
            })
            .collect()
    };
    if devices.windows(2).any(|w| w[0].0 == w[1].0) {
        // 2 devices with the same key text: the rows of all devices in 1
        // frame, in the key order of the rows.
        let mut b = FrameBuilder::new(def);
        rows_of(def, &read(&|_| true)?, &mut b);
        let mut f = b.finish(&key_text);
        fill_joins(t, def, &mut f)?;
        return Ok((f, Vec::new()));
    }
    let mut held: Vec<Option<Arc<Frame>>> = {
        let map = parts().lock().unwrap_or_else(|e| e.into_inner());
        devices
            .iter()
            .map(|(_, k)| map.get(k).and_then(Weak::upgrade))
            .collect()
    };
    let missing: BTreeSet<&str> = devices
        .iter()
        .zip(&held)
        .filter(|(_, h)| h.is_none())
        .map(|((_, k), _)| k.device.as_str())
        .collect();
    if !missing.is_empty() {
        let tables = read(&|d| missing.contains(d))?;
        let built: BTreeMap<&str, Arc<Frame>> = missing
            .par_iter()
            .map(|d| {
                let own: StoreRows = tables
                    .iter()
                    .map(|(n, batches)| {
                        let rows = batches
                            .iter()
                            .filter(|(x, _)| x.as_str() == *d)
                            .cloned()
                            .collect();
                        (*n, rows)
                    })
                    .collect();
                let mut b = FrameBuilder::new(def);
                rows_of(def, &own, &mut b);
                (*d, Arc::new(b.finish(&key_text)))
            })
            .collect();
        let mut map = parts().lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, w| w.strong_count() > 0);
        for ((_, k), h) in devices.iter().zip(held.iter_mut()) {
            if h.is_none() {
                let f = built[k.device.as_str()].clone();
                map.insert(k.clone(), Arc::downgrade(&f));
                *h = Some(f);
            }
        }
    }
    let held: Vec<Arc<Frame>> = held.into_iter().flatten().collect();
    let refs: Vec<&Frame> = held.iter().map(AsRef::as_ref).collect();
    let mut f = frame::concat(def, &refs);
    fill_joins(t, def, &mut f)?;
    Ok((f, held))
}

/// The reason of a join that finds no value.
const NOT_FOUND: &str = "not_found";
/// The reason of a join that finds 2 or more values.
const AMBIGUOUS: &str = "ambiguous";

/// The one value of a set, or the reason of the join.
fn one<T: Clone + Ord>(set: Option<&BTreeSet<T>>) -> Result<T, &'static str> {
    match set.map(|s| (s.len(), s.first())) {
        Some((1, Some(v))) => Ok(v.clone()),
        Some((n, _)) if n > 1 => Err(AMBIGUOUS),
        _ => Err(NOT_FOUND),
    }
}

/// The facts of the twin that the join columns read.
#[derive(Default)]
pub struct Joins {
    /// The devices with an interface that has the MAC address, from the
    /// store table `links`, by the MAC address in lower case.
    mac_devices: HashMap<String, BTreeSet<String>>,
    /// The devices with the address, from the store table `addresses`.
    address_devices: HashMap<IpAddr, BTreeSet<String>>,
    /// The hosts of the attachments of the twin with the address.
    address_hosts: HashMap<IpAddr, BTreeSet<String>>,
    /// The addresses of the ARP and neighbour rows of each MAC address.
    mac_addresses: HashMap<String, BTreeSet<String>>,
    /// The far end of each link of the twin, by device and interface.
    peers: Peers,
    /// The device and the port of each MAC table row on a port with no
    /// link, by the MAC address.
    access: HashMap<String, BTreeSet<(String, String)>>,
    /// The VLAN of each interface of the store table `links`.
    vlans: HashMap<(String, String), BTreeSet<u64>>,
    /// The bridge domains of the tag of each VLAN of the switch ports of a
    /// device.
    domains: HashMap<(String, u64), BTreeSet<String>>,
}

/// The address of an `<address>/<length>` or of an address.
fn address_of(s: &str) -> Option<IpAddr> {
    s.split('/').next()?.parse().ok()
}

fn text(v: Owned) -> Option<String> {
    match v {
        Owned::Text(s) => Some(s),
        _ => None,
    }
}

impl Joins {
    fn build(t: &Loaded) -> Result<Joins, String> {
        let mut j = Joins::default();
        for l in twin_links(t) {
            if let (Some(d), Some(pd)) = (l.device, l.peer_device) {
                j.peers
                    .entry((d, l.interface))
                    .or_default()
                    .insert((pd, l.peer_interface));
            }
        }
        for a in t.attachments() {
            j.address_hosts
                .entry(a.address)
                .or_default()
                .insert(a.host.clone());
        }
        for f in t.functions() {
            let any: &dyn std::any::Any = f.as_ref();
            if let (Some(p), Some(d)) = (any.downcast_ref::<PortIngress>(), f.device()) {
                for (vlan, bd) in &p.tagged {
                    j.domains
                        .entry((d.to_string(), u64::from(*vlan)))
                        .or_default()
                        .insert(bd.to_string());
                }
            }
        }
        let Some(src) = &t.source else {
            return Ok(j);
        };
        let read = |name: &str| -> Result<Vec<(String, RecordBatch)>, String> {
            let schema =
                rsim_store::table(name).ok_or_else(|| format!("{name} is not a store table"))?;
            src.store
                .read_table(&src.snapshot, schema)
                .map_err(|e| e.to_string())
        };
        for (device, b) in read("links")? {
            for r in 0..b.num_rows() {
                let interface = text(store_value(&b, "interface", r)).unwrap_or_default();
                if let Some(mac) = text(store_value(&b, "mac", r)) {
                    j.mac_devices
                        .entry(mac.to_ascii_lowercase())
                        .or_default()
                        .insert(device.clone());
                }
                if let Owned::Integer(v) = store_value(&b, "vlan", r) {
                    j.vlans
                        .entry((device.clone(), interface))
                        .or_default()
                        .insert(v);
                }
            }
        }
        for (device, b) in read("addresses")? {
            for r in 0..b.num_rows() {
                if let Some(a) = text(store_value(&b, "prefix", r))
                    .as_deref()
                    .and_then(address_of)
                {
                    j.address_devices
                        .entry(a)
                        .or_default()
                        .insert(device.clone());
                }
            }
        }
        for (_, b) in read("neighbours")? {
            for r in 0..b.num_rows() {
                if let (Some(ip), Some(mac)) = (
                    text(store_value(&b, "ip", r)),
                    text(store_value(&b, "mac", r)),
                ) {
                    j.mac_addresses
                        .entry(mac.to_ascii_lowercase())
                        .or_default()
                        .insert(ip);
                }
            }
        }
        for (device, b) in read("mac_table")? {
            for r in 0..b.num_rows() {
                if let (Some(mac), Some(port)) = (
                    text(store_value(&b, "mac", r)),
                    text(store_value(&b, "port", r)),
                ) && !j.peers.contains_key(&(device.clone(), port.clone()))
                {
                    j.access
                        .entry(mac.to_ascii_lowercase())
                        .or_default()
                        .insert((device.clone(), port));
                }
            }
        }
        Ok(j)
    }

    /// The device or the host that has the address or the MAC address.
    fn host(&self, ip: Option<IpAddr>, mac: Option<&str>) -> Result<String, &'static str> {
        let mut all = BTreeSet::new();
        if let Some(ip) = ip {
            all.extend(self.address_devices.get(&ip).into_iter().flatten().cloned());
            all.extend(self.address_hosts.get(&ip).into_iter().flatten().cloned());
        }
        if let Some(mac) = mac {
            all.extend(self.mac_devices.get(mac).into_iter().flatten().cloned());
        }
        one(Some(&all))
    }
}

/// The joins of a twin, built at the first table that needs them.
pub(super) fn joins(t: &Loaded) -> Result<&Joins, String> {
    t.tables
        .1
        .get_or_init(|| Joins::build(t))
        .as_ref()
        .map_err(Clone::clone)
}

/// The value of a join for a row, or its reason; none for a row with no
/// input to the join.
type Join<T = String> = Option<Result<T, &'static str>>;

fn cell<'a>(v: &'a Result<String, &'static str>) -> Cell<'a> {
    v.as_deref().map_or(Cell::Null, Cell::Text)
}

fn reason<'a>(v: &'a Result<String, &'static str>) -> Cell<'a> {
    v.as_ref().err().map_or(Cell::Null, |r| Cell::Text(r))
}

/// Fills the columns `value` and `reason` of a frame from 1 join for each
/// row; a row with no input to the join has both null.
fn fill2(f: &mut Frame, def: &TableDef, value: &str, why: &str, rows: &[Join]) {
    let (v, w) = (
        def.columns.iter().position(|c| c.name == value),
        def.columns.iter().position(|c| c.name == why),
    );
    let (Some(v), Some(w)) = (v, w) else {
        return;
    };
    f.fill(def, v, |r| rows[r].as_ref().map_or(Cell::Null, cell));
    f.fill(def, w, |r| rows[r].as_ref().map_or(Cell::Null, reason));
}

/// Fills the join columns of a frame of a collected table.
fn fill_joins(t: &Loaded, def: &'static TableDef, f: &mut Frame) -> Result<(), String> {
    if !super::JOINED.iter().any(|(n, _)| *n == def.name) {
        return Ok(());
    }
    let j = joins(t)?;
    let col = |name: &str| def.columns.iter().position(|c| c.name == name);
    let text_of =
        |f: &Frame, name: &str, r: usize| col(name).and_then(|c| f.text(r, c)).map(str::to_string);
    let n = f.len();
    let device: Vec<String> = (0..n)
        .map(|r| text_of(f, "device", r).unwrap_or_default())
        .collect();
    let peer = |f: &Frame, port: &str| -> (Vec<Join>, Vec<Join>) {
        let found: Vec<Join<(String, Option<String>)>> = (0..n)
            .map(|r| {
                let p = text_of(f, port, r)?;
                Some(one(j.peers.get(&(device[r].clone(), p))))
            })
            .collect();
        let devices = found
            .iter()
            .map(|x| x.as_ref().map(|x| x.clone().map(|(d, _)| d)))
            .collect();
        let interfaces = found
            .iter()
            .map(|x| {
                x.as_ref().map(|x| match x {
                    Ok((_, Some(i))) => Ok(i.clone()),
                    Ok((_, None)) => Err(NOT_FOUND),
                    Err(e) => Err(*e),
                })
            })
            .collect();
        (devices, interfaces)
    };
    match def.name {
        "interfaces" | "mac" => {
            let port = if def.name == "mac" {
                "port"
            } else {
                "interface"
            };
            let (d, i) = peer(f, port);
            fill_peer(f, def, &d, &i);
        }
        _ => {}
    }
    match def.name {
        "mac" => {
            let vlan = col("vlan");
            let mac: Vec<Option<String>> = (0..n)
                .map(|r| text_of(f, "mac", r).map(|m| m.to_ascii_lowercase()))
                .collect();
            let host: Vec<Join> = (0..n)
                .map(|r| {
                    let m = mac[r].as_deref()?;
                    let by_mac = one(j.mac_devices.get(m));
                    if by_mac != Err(NOT_FOUND) {
                        return Some(by_mac);
                    }
                    let mut hosts = BTreeSet::new();
                    for a in j.mac_addresses.get(m).into_iter().flatten() {
                        if let Some(ip) = address_of(a) {
                            hosts.extend(j.address_devices.get(&ip).into_iter().flatten().cloned());
                            hosts.extend(j.address_hosts.get(&ip).into_iter().flatten().cloned());
                        }
                    }
                    Some(one(Some(&hosts)))
                })
                .collect();
            fill2(f, def, "host", "host_reason", &host);
            let ips: Vec<Option<Vec<String>>> = mac
                .iter()
                .map(|m| {
                    let s = j.mac_addresses.get(m.as_deref()?)?;
                    Some(s.iter().cloned().collect())
                })
                .collect();
            if let (Some(c), Some(w)) = (col("ip"), col("ip_reason")) {
                f.fill(def, c, |r| ips[r].as_deref().map_or(Cell::Null, Cell::List));
                f.fill(def, w, |r| {
                    if mac[r].is_some() && ips[r].is_none() {
                        Cell::Text(NOT_FOUND)
                    } else {
                        Cell::Null
                    }
                });
            }
            let domain: Vec<Join> = (0..n)
                .map(|r| {
                    let v = f.integer(r, vlan?)?;
                    Some(one(j.domains.get(&(device[r].clone(), v))))
                })
                .collect();
            fill2(f, def, "bridge_domain", "bridge_domain_reason", &domain);
        }
        "arp" => {
            let host: Vec<Join> = (0..n)
                .map(|r| {
                    let ip = text_of(f, "ip", r).as_deref().and_then(address_of);
                    let mac = text_of(f, "mac", r).map(|m| m.to_ascii_lowercase());
                    if ip.is_none() && mac.is_none() {
                        return None;
                    }
                    Some(j.host(ip, mac.as_deref()))
                })
                .collect();
            fill2(f, def, "host", "host_reason", &host);
            let vlan: Vec<Join<u64>> = (0..n)
                .map(|r| {
                    let i = text_of(f, "interface", r)?;
                    Some(one(j.vlans.get(&(device[r].clone(), i))))
                })
                .collect();
            if let (Some(c), Some(w)) = (col("vlan"), col("vlan_reason")) {
                f.fill(def, c, |r| match &vlan[r] {
                    Some(Ok(v)) => Cell::Integer(*v),
                    _ => Cell::Null,
                });
                f.fill(def, w, |r| match &vlan[r] {
                    Some(Err(e)) => Cell::Text(e),
                    _ => Cell::Null,
                });
            }
            let access: Vec<Join<(String, String)>> = (0..n)
                .map(|r| {
                    let m = text_of(f, "mac", r)?.to_ascii_lowercase();
                    Some(one(j.access.get(&m)))
                })
                .collect();
            if let (Some(d), Some(p), Some(w)) = (
                col("access_device"),
                col("access_port"),
                col("access_reason"),
            ) {
                f.fill(def, d, |r| match &access[r] {
                    Some(Ok((d, _))) => Cell::Text(d),
                    _ => Cell::Null,
                });
                f.fill(def, p, |r| match &access[r] {
                    Some(Ok((_, p))) => Cell::Text(p),
                    _ => Cell::Null,
                });
                f.fill(def, w, |r| match &access[r] {
                    Some(Err(e)) => Cell::Text(e),
                    _ => Cell::Null,
                });
            }
        }
        "routes" => {
            let hop: Vec<Join> = (0..n)
                .map(|r| {
                    let ip = address_of(&text_of(f, "next_hop", r)?)?;
                    Some(one(j.address_devices.get(&ip)))
                })
                .collect();
            fill2(f, def, "next_hop_device", "next_hop_device_reason", &hop);
        }
        _ => {}
    }
    Ok(())
}

/// Fills the columns `peer_device`, `peer_interface` and `peer_reason`.
fn fill_peer(f: &mut Frame, def: &TableDef, devices: &[Join], interfaces: &[Join]) {
    let col = |name: &str| def.columns.iter().position(|c| c.name == name);
    let (Some(d), Some(i), Some(w)) = (
        col("peer_device"),
        col("peer_interface"),
        col("peer_reason"),
    ) else {
        return;
    };
    f.fill(def, d, |r| devices[r].as_ref().map_or(Cell::Null, cell));
    f.fill(def, i, |r| match &devices[r] {
        Some(Ok(_)) => interfaces[r].as_ref().map_or(Cell::Null, cell),
        _ => Cell::Null,
    });
    f.fill(def, w, |r| devices[r].as_ref().map_or(Cell::Null, reason));
}
