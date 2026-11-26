//! Lowering of a UniFi site into layer 2 function instances, endpoints and
//! attachment records.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use rsim_core::{
    BridgeDomainId, EndpointId, FunctionId, InterfaceId, Mac, NetFunction, PortId, Prefix,
    PrefixTable, SourceSpan, TriePrefixTable,
};
use rsim_engine::{AttachmentKind, AttachmentRecord, Endpoint};
use rsim_functions::{
    Flood, HostMac, HostResolution, LinkEnd, LinkFacts, MacEntry, MacLookup, Meta, PortEgress,
    PortIngress, PortPeer, Unplaced, VendorProfile, WirelessAttachment,
};

use crate::unifi::site::{Client, Device, DeviceKind, Forward, Network, Port, Site, Vap, Wlan};

/// A router interface on the uplink of the site, found by LLDP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterPort {
    /// The router device.
    pub device: String,
    /// The physical interface, for example `eth0`.
    pub interface: String,
    /// The MAC of the UniFi device and its port on the link.
    pub switch: String,
    pub port: u32,
    pub mac: Mac,
    /// The hand-off function of the interface on the router.
    pub handoff: FunctionId,
    /// The addresses of the router on each VLAN of the interface, `None` for
    /// the untagged interface.
    pub vlans: BTreeMap<Option<u16>, Vec<(IpAddr, u8)>>,
    pub provenance: Vec<SourceSpan>,
    /// The physical facts of the router interface.
    pub facts: Option<LinkEnd>,
}

/// The function instances, endpoints, attachment records and notes of a
/// site.
#[derive(Default)]
pub struct Lowered {
    pub functions: Vec<Arc<dyn NetFunction>>,
    pub endpoints: Vec<Endpoint>,
    pub attachments: Vec<AttachmentRecord>,
    /// The ingress function of the UniFi port that the router port links
    /// to, with the router interface and the facts of the UniFi port.
    pub router_peer: Option<(String, FunctionId, LinkEnd)>,
    pub notes: Vec<String>,
}

/// The files of the sections, for the provenance.
pub struct Files {
    pub devices: String,
    pub clients: String,
    pub networks: String,
    pub wlans: String,
}

/// Where a MAC is: a device and a port name such as `port/3` or
/// `wlan/office`.
type Location = (String, String);

struct L<'a> {
    site: &'a Site,
    profile: &'a VendorProfile,
    prefix: &'a str,
    files: &'a Files,
    router: Option<&'a RouterPort>,
    out: Lowered,
}

fn mac(s: &str) -> Option<Mac> {
    s.parse().ok()
}

/// The name of the twin device of a UniFi device.
pub fn device_name(d: &Device) -> String {
    d.name.clone()
}

impl<'a> L<'a> {
    fn dev_name(&self, d: &Device) -> String {
        device_name(d)
    }
    fn id(&self, d: &Device, f: &str) -> FunctionId {
        FunctionId::new(format!("{}/{f}", self.dev_name(d)))
    }
    fn meta(&self, d: &Device, f: &str, spans: Vec<SourceSpan>) -> Meta {
        let mut m = Meta::new(self.id(d, f), self.dev_name(d).as_str(), self.profile);
        m.provenance = spans;
        m
    }
    fn dev_span(&self, d: &Device) -> SourceSpan {
        SourceSpan::row(
            &self.files.devices,
            u32::try_from(d.index + 1).unwrap_or(u32::MAX),
        )
    }
    fn client_span(&self, c: &Client) -> SourceSpan {
        SourceSpan::row(
            &self.files.clients,
            u32::try_from(c.index + 1).unwrap_or(u32::MAX),
        )
    }
    fn bd(&self, n: &Network) -> BridgeDomainId {
        BridgeDomainId::new(format!("{}/{}", self.prefix, n.name))
    }
    /// The default network: the enabled network with no VLAN.
    fn default_network(&self) -> Option<&'a Network> {
        self.site
            .networks
            .iter()
            .find(|n| n.vlan.is_none() && n.purpose != "wan" && n.enabled)
    }
    /// The native bridge domain and the tagged bridge domains of a port. A
    /// port carries no disabled network.
    fn membership(&self, p: &Port) -> (Option<&'a Network>, Vec<&'a Network>) {
        let named = p
            .native
            .as_deref()
            .and_then(|id| self.site.networks.iter().find(|n| n.id == id));
        let native = match named {
            Some(n) => n.enabled.then_some(n),
            None => self.default_network(),
        };
        let others = || {
            self.site.networks.iter().filter(|n| {
                n.vlan.is_some()
                    && n.purpose != "wan"
                    && n.enabled
                    && Some(n.id.as_str()) != native.map(|x| x.id.as_str())
            })
        };
        let tagged = match (p.forward, &p.tagged) {
            (Forward::All, _) => others().collect(),
            (Forward::Customize, Some(ids)) => others().filter(|n| ids.contains(&n.id)).collect(),
            (Forward::Customize, None) => {
                others().filter(|n| !p.excluded.contains(&n.id)).collect()
            }
            (Forward::Native | Forward::Disabled | Forward::Unstated | Forward::Other, _) => {
                Vec::new()
            }
        };
        let native = if p.forward == Forward::Disabled {
            None
        } else {
            native
        };
        (native, tagged)
    }

    /// The parent of a device and the port on the parent.
    fn parent(&self, d: &Device) -> Option<(&'a Device, u32)> {
        let (m, p) = d.uplink_peer.as_ref()?;
        self.site.device(m).map(|x| (x, *p))
    }

    /// The device below `d` on the way to `target`, if `target` is below
    /// `d`.
    fn child_toward(&self, d: &Device, target: &'a Device) -> Option<(&'a Device, u32)> {
        let mut cur = target;
        for _ in 0..self.site.devices.len() {
            let (p, port) = self.parent(cur)?;
            if p.mac == d.mac {
                return Some((cur, port));
            }
            cur = p;
        }
        None
    }

    /// The port of `d` toward a MAC at `loc`. `None` for the router, which
    /// is above the root.
    fn port_toward(&self, d: &Device, loc: Option<&Location>) -> Option<String> {
        match loc {
            Some((dev, port)) if *dev == d.mac => Some(port.clone()),
            Some((dev, _)) => {
                let target = self.site.device(dev)?;
                match self.child_toward(d, target) {
                    Some((_, port)) => Some(format!("port/{port}")),
                    None => d.uplink_port.map(|p| format!("port/{p}")),
                }
            }
            None => match (self.parent(d), self.router) {
                (Some(_), _) => d.uplink_port.map(|p| format!("port/{p}")),
                (None, Some(_)) => self.root_router_port(d).map(|p| format!("port/{p}")),
                (None, None) => None,
            },
        }
    }

    /// The physical facts of a port of a device.
    fn port_facts(&self, d: &Device, idx: u32) -> LinkEnd {
        let p = ports(d).into_iter().find(|p| p.idx == idx);
        LinkEnd {
            speed_mbps: p.as_ref().and_then(|p| p.speed),
            full_duplex: p.as_ref().and_then(|p| p.full_duplex),
            media: p.and_then(|p| p.media),
            spans: vec![self.dev_span(d)],
        }
    }

    /// The port of the device on the link to the router.
    fn root_router_port(&self, d: &Device) -> Option<u32> {
        self.router.filter(|r| r.switch == d.mac).map(|r| r.port)
    }
}

/// The ports of a device. An access point with no port table gets one port
/// for its uplink that carries all networks, and the uplink port of an access
/// point with no mode carries all networks.
fn ports(d: &Device) -> Vec<Port> {
    if !d.ports.is_empty() {
        let mut ports = d.ports.clone();
        if d.kind == DeviceKind::AccessPoint {
            for p in &mut ports {
                if p.forward == Forward::Unstated && Some(p.idx) == d.uplink_port {
                    p.forward = Forward::All;
                }
            }
        }
        return ports;
    }
    match d.uplink_port.or(Some(1)) {
        Some(idx) if d.kind == DeviceKind::AccessPoint => vec![Port {
            idx,
            up: true,
            enabled: true,
            forward: Forward::All,
            native: None,
            excluded: Vec::new(),
            tagged: None,
            stp_state: None,
            isolation: false,
            aggregated: false,
            speed: d.uplink_speed,
            full_duplex: d.uplink_full_duplex,
            media: d.uplink_media.clone(),
        }],
        _ => Vec::new(),
    }
}

/// The enabled WLAN of an SSID on an access point: the WLAN that the access
/// point names, or else the one WLAN of the SSID. `Err` if the access point
/// names no WLAN and the WLANs of the SSID have more than one network.
fn vap_wlan<'s>(site: &'s Site, v: &Vap) -> Result<Option<&'s Wlan>, String> {
    if let Some(id) = &v.wlan {
        return Ok(site.wlans.iter().find(|w| w.id == *id && w.enabled));
    }
    let mut wlans = site.wlans.iter().filter(|w| w.ssid == v.ssid && w.enabled);
    let first = wlans.next();
    if let Some(f) = first
        && wlans.any(|w| w.network != f.network)
    {
        return Err(format!("SSID {} has more than one network", v.ssid));
    }
    Ok(first)
}

/// An SSID port of an access point: the WLAN of its vaps and their radios.
/// `radios_known` is false if a vap of the port names no radio.
struct SsidPort<'s> {
    port: String,
    wlan: &'s Wlan,
    radios: BTreeSet<String>,
    radios_known: bool,
}

/// The SSID ports of the up vaps of an access point, and each SSID whose
/// WLAN is not known with the reason. An SSID with one WLAN on the access
/// point has the port `wlan/<ssid>`, and an SSID with more than one WLAN has
/// the port `wlan/<ssid>/wlan-<id>` for each WLAN.
fn ssid_ports<'s>(site: &'s Site, vaps: &[Vap]) -> (Vec<SsidPort<'s>>, BTreeMap<String, String>) {
    type Wlans<'s> = BTreeMap<&'s str, (&'s Wlan, BTreeSet<String>, bool)>;
    let mut by_ssid: BTreeMap<String, Wlans<'s>> = BTreeMap::new();
    let mut errs = BTreeMap::new();
    for v in vaps.iter().filter(|v| v.up) {
        match vap_wlan(site, v) {
            Ok(Some(w)) => {
                let e = by_ssid
                    .entry(v.ssid.clone())
                    .or_default()
                    .entry(w.id.as_str())
                    .or_insert((w, BTreeSet::new(), true));
                e.1.extend(v.radio.clone());
                e.2 &= v.radio.is_some();
            }
            Ok(None) => {}
            Err(e) => {
                errs.insert(v.ssid.clone(), e);
            }
        }
    }
    let mut out = Vec::new();
    for (ssid, wlans) in by_ssid {
        if errs.contains_key(&ssid) {
            continue;
        }
        let one = wlans.len() == 1;
        for (id, (wlan, radios, radios_known)) in wlans {
            let port = if one {
                format!("wlan/{ssid}")
            } else {
                format!("wlan/{ssid}/wlan-{id}")
            };
            out.push(SsidPort {
                port,
                wlan,
                radios,
                radios_known,
            });
        }
    }
    (out, errs)
}

/// Lowers a site. `prefix` names the bridge domains, for example the
/// device of the site in the store. A client whose address is in
/// `next_hops`, a next hop of a route, is a router and not an endpoint: it
/// keeps its MAC table entries, and a packet to its MAC gives `Unknown` at
/// its port.
pub fn lower(
    prefix: &str,
    site: &Site,
    profile: &VendorProfile,
    files: &Files,
    router: Option<&RouterPort>,
    next_hops: &BTreeSet<IpAddr>,
) -> Lowered {
    let mut l = L {
        site,
        profile,
        prefix,
        files,
        router,
        out: Lowered::default(),
    };
    let devices: Vec<&Device> = site
        .devices
        .iter()
        .filter(|d| {
            if d.kind == DeviceKind::Other {
                l.out.notes.push(format!(
                    "device {} of type {} not lowered",
                    d.name, d.type_name
                ));
                false
            } else {
                true
            }
        })
        .collect();

    // The location and the bridge domain of each client MAC. A client whose
    // network is not the network of its port or SSID, or whose SSID port is
    // not known, is not placed, and each packet from it is unknown. A client
    // whose port has no known network is not placed either.
    let mut located: Vec<(&Client, Location, &Network)> = Vec::new();
    let mut client_wlan: BTreeMap<usize, &Wlan> = BTreeMap::new();
    let mut unplaced: Vec<(&Client, String, String)> = Vec::new();
    for c in &site.clients {
        let mut not_placed = |dev: &str, why: String, notes: &mut Vec<String>| {
            notes.push(format!("client {}: {why}", c.name));
            unplaced.push((c, dev.to_string(), why));
        };
        let (loc, net) = match (&c.switch, &c.ap) {
            (Some((sw, p)), _) => {
                let dev = site.device(sw);
                let port = dev.and_then(|d| ports(d).into_iter().find(|x| x.idx == *p));
                let net = port.and_then(|p| l.membership(&p).0);
                ((sw.clone(), format!("port/{p}")), net)
            }
            (None, Some((ap, ssid))) => {
                let mut vaps: Vec<Vap> = site
                    .device(ap)
                    .map(|d| d.vaps.iter().filter(|v| v.ssid == *ssid).cloned().collect())
                    .unwrap_or_default();
                if vaps.is_empty() {
                    vaps.push(Vap {
                        ssid: ssid.clone(),
                        wlan: None,
                        radio: None,
                        up: true,
                    });
                }
                let (ports, errs) = ssid_ports(site, &vaps);
                if let Some(e) = errs.get(ssid) {
                    not_placed(ap, e.clone(), &mut l.out.notes);
                    continue;
                }
                // With more than one port, the radio of the client picks the
                // port only if each vap of the SSID names its radio.
                let chosen: Vec<&SsidPort> = if ports.len() > 1 {
                    if ports.iter().all(|p| p.radios_known) {
                        ports
                            .iter()
                            .filter(|p| c.radio.as_ref().is_some_and(|r| p.radios.contains(r)))
                            .collect()
                    } else {
                        Vec::new()
                    }
                } else {
                    ports.iter().collect()
                };
                match chosen.as_slice() {
                    [p] => {
                        client_wlan.insert(c.index, p.wlan);
                        ((ap.clone(), p.port.clone()), site.network(&p.wlan.network))
                    }
                    _ if ports.is_empty() => ((ap.clone(), format!("wlan/{ssid}")), None),
                    _ => {
                        let radio = match c.radio.as_deref() {
                            Some(r) => format!("no WLAN on radio {r}"),
                            None => "radio not known".to_string(),
                        };
                        not_placed(
                            ap,
                            format!(
                                "SSID {ssid}: {} WLANs on the access point, {radio}",
                                ports.len()
                            ),
                            &mut l.out.notes,
                        );
                        continue;
                    }
                }
            }
            _ => continue,
        };
        let Some(net) = net else {
            l.out
                .notes
                .push(format!("client {}: network of its port not known", c.name));
            continue;
        };
        if let Some(id) = c.network.as_deref()
            && id != net.id
        {
            not_placed(
                &loc.0,
                format!("network {id} not the network {} of {}", net.name, loc.1),
                &mut l.out.notes,
            );
            continue;
        }
        located.push((c, loc, net));
    }

    // The clients that are next hops of a route.
    let is_router = |c: &Client| {
        c.ip.as_deref()
            .and_then(|i| i.parse::<IpAddr>().ok())
            .is_some_and(|ip| next_hops.contains(&ip))
    };
    for (c, _, _) in located.iter().filter(|(c, _, _)| is_router(c)) {
        l.out.notes.push(format!(
            "client {}: next hop of a route, not an endpoint",
            c.name
        ));
    }

    // The global host table: the client addresses and the router addresses.
    let mut hosts: TriePrefixTable<HostMac> = TriePrefixTable::new();
    for (c, _, _) in &located {
        if let (Some(ip), Some(m)) = (c.ip.as_deref().and_then(|i| i.parse().ok()), mac(&c.mac)) {
            hosts.insert(
                Prefix::host(ip),
                HostMac {
                    mac: m,
                    spans: vec![l.client_span(c)],
                },
            );
        }
    }
    if let Some(r) = router {
        for addrs in r.vlans.values() {
            for (a, _) in addrs {
                hosts.insert(
                    Prefix::host(*a),
                    HostMac {
                        mac: r.mac,
                        spans: r.provenance.clone(),
                    },
                );
            }
        }
    }

    for d in &devices {
        let dports = ports(d);
        let mut mac_tables: BTreeMap<BridgeDomainId, BTreeMap<Mac, MacEntry>> = BTreeMap::new();
        let mut flood: BTreeMap<BridgeDomainId, Vec<(PortId, FunctionId)>> = BTreeMap::new();
        let mut egress: BTreeMap<PortId, FunctionId> = BTreeMap::new();

        // Ports.
        let parent = l.parent(d);
        let router_port = if parent.is_none() {
            l.root_router_port(d)
        } else {
            None
        };
        // The frames of an isolated port go to the MAC lookup `mac/isolated`
        // and the flood `flood/isolated`, which do not reach the other
        // isolated ports of the device.
        let isolated: BTreeSet<PortId> = dports
            .iter()
            .filter(|p| p.isolation)
            .map(|p| PortId::new(format!("port/{}", p.idx)))
            .collect();
        for p in &dports {
            let (native, tagged) = l.membership(p);
            let pid = PortId::new(format!("port/{}", p.idx));
            let span = l.dev_span(d);
            if p.aggregated {
                l.out.notes.push(format!(
                    "{} port {}: link aggregation not lowered",
                    d.name, p.idx
                ));
            }
            let in_id = format!("port/{}/in", p.idx);
            let meta = l.meta(d, &in_id, vec![span.clone()]);
            l.out.functions.push(Arc::new(PortIngress {
                meta,
                port: pid.clone(),
                native: native.map(|n| l.bd(n)),
                tagged: tagged
                    .iter()
                    .filter_map(|n| n.vlan.map(|v| (v, l.bd(n))))
                    .collect(),
                next: l.id(d, if p.isolation { "mac/isolated" } else { "mac" }),
            }));
            // The peer of the port.
            let local = l.port_facts(d, p.idx);
            let (peer, remote) = if Some(p.idx) == d.uplink_port
                && let Some((up, rp)) = parent
            {
                (
                    Some(l.id(up, &format!("port/{rp}/in"))),
                    Some(l.port_facts(up, rp)),
                )
            } else if Some(p.idx) == router_port {
                let r = router.expect("a router port has a router");
                l.out.router_peer = Some((r.interface.clone(), l.id(d, &in_id), local.clone()));
                (Some(r.handoff.clone()), r.facts.clone())
            } else {
                match site.devices.iter().find(|c| {
                    c.uplink_peer.as_ref() == Some(&(d.mac.clone(), p.idx))
                        && c.kind != DeviceKind::Other
                }) {
                    Some(c) => match c.uplink_port {
                        Some(up) => (
                            Some(l.id(c, &format!("port/{up}/in"))),
                            Some(l.port_facts(c, up)),
                        ),
                        None => (None, None),
                    },
                    None => (None, None),
                }
            };
            let link = peer.as_ref().map(|_| LinkFacts { local, remote });
            let port_hosts: BTreeMap<Mac, EndpointId> = located
                .iter()
                .filter(|(c, _, _)| !is_router(c))
                .filter(|(_, loc, _)| loc.0 == d.mac && loc.1 == pid.to_string())
                .filter_map(|(c, _, _)| Some((mac(&c.mac)?, EndpointId::new(endpoint_id(c)))))
                .collect();
            let out_name = format!("port/{}/out", p.idx);
            let meta = l.meta(d, &out_name, vec![span]);
            l.out.functions.push(Arc::new(PortEgress {
                meta,
                port: pid.clone(),
                native: native.map(|n| l.bd(n)),
                tagged: tagged
                    .iter()
                    .filter_map(|n| n.vlan.map(|v| (l.bd(n), v)))
                    .collect(),
                peers: peer
                    .map(|target| PortPeer { target, link })
                    .into_iter()
                    .collect(),
                hosts: port_hosts,
            }));
            let out_id = l.id(d, &out_name);
            egress.insert(pid.clone(), out_id.clone());
            if p.forwarding() {
                for n in native.into_iter().chain(tagged.iter().copied()) {
                    flood
                        .entry(l.bd(n))
                        .or_default()
                        .push((pid.clone(), out_id.clone()));
                }
            }
        }

        // SSIDs.
        let (ssids, ssid_errs) = ssid_ports(site, &d.vaps);
        for (ssid, e) in &ssid_errs {
            l.out
                .notes
                .push(format!("{}: {e}, SSID not lowered", d.name));
            // A flood of each network of the SSID reaches the SSID, where
            // the frame is unknown.
            let pid = PortId::new(format!("wlan/{ssid}"));
            let nets: BTreeSet<&str> = site
                .wlans
                .iter()
                .filter(|w| w.ssid == *ssid && w.enabled)
                .map(|w| w.network.as_str())
                .collect();
            for n in nets.into_iter().filter_map(|id| site.network(id)) {
                let name = format!("wlan/{ssid}/out/{}", n.name);
                let out_id = l.id(d, &name);
                flood
                    .entry(l.bd(n))
                    .or_default()
                    .push((pid.clone(), out_id));
                let meta = l.meta(d, &name, vec![l.dev_span(d)]);
                l.out.functions.push(Arc::new(PortEgress {
                    meta,
                    port: pid.clone(),
                    native: Some(l.bd(n)),
                    tagged: BTreeMap::new(),
                    peers: Vec::new(),
                    hosts: BTreeMap::new(),
                }));
            }
        }
        for sp in &ssids {
            let w = sp.wlan;
            let Some(n) = site.network(&w.network) else {
                continue;
            };
            let pid = PortId::new(&sp.port);
            let span = SourceSpan::row(
                &l.files.wlans,
                u32::try_from(w.index + 1).unwrap_or(u32::MAX),
            );
            let meta = l.meta(d, &format!("{}/in", sp.port), vec![span.clone()]);
            l.out.functions.push(Arc::new(WirelessAttachment {
                meta,
                port: pid.clone(),
                bridge_domain: l.bd(n),
                next: l.id(d, "mac"),
            }));
            let hosts_on: BTreeMap<Mac, EndpointId> = located
                .iter()
                .filter(|(c, _, _)| !is_router(c))
                .filter(|(_, loc, _)| loc.0 == d.mac && loc.1 == pid.to_string())
                .filter_map(|(c, _, _)| Some((mac(&c.mac)?, EndpointId::new(endpoint_id(c)))))
                .collect();
            let out_name = format!("{}/out", sp.port);
            let meta = l.meta(d, &out_name, vec![span]);
            l.out.functions.push(Arc::new(PortEgress {
                meta,
                port: pid.clone(),
                native: Some(l.bd(n)),
                tagged: BTreeMap::new(),
                peers: Vec::new(),
                hosts: hosts_on,
            }));
            let out_id = l.id(d, &out_name);
            egress.insert(pid.clone(), out_id.clone());
            flood.entry(l.bd(n)).or_default().push((pid, out_id));
        }

        // The MAC table from the client attachment and the topology.
        for (c, loc, net) in &located {
            let (Some(m), Some(port)) = (mac(&c.mac), l.port_toward(d, Some(loc))) else {
                continue;
            };
            mac_tables.entry(l.bd(net)).or_default().insert(
                m,
                MacEntry {
                    port: PortId::new(port),
                    spans: vec![l.client_span(c), l.dev_span(d)],
                },
            );
        }
        if let Some(r) = router
            && let Some(port) = l.port_toward(d, None)
        {
            for n in site.networks.iter().filter(|n| n.enabled) {
                if r.vlans.contains_key(&n.vlan) {
                    mac_tables.entry(l.bd(n)).or_default().insert(
                        r.mac,
                        MacEntry {
                            port: PortId::new(port.clone()),
                            spans: r.provenance.clone(),
                        },
                    );
                }
            }
        }
        // An SSID port can send a frame back out to another client of the
        // SSID, unless its WLAN has client isolation. Then the frames of the
        // SSID port cannot reach the wireless clients of the WLAN on any
        // access point.
        let mut hairpin = BTreeSet::new();
        let mut blocked: BTreeMap<PortId, BTreeSet<Mac>> = BTreeMap::new();
        for sp in &ssids {
            let pid = PortId::new(&sp.port);
            if sp.wlan.isolation {
                let macs = located
                    .iter()
                    .filter(|(c, _, _)| {
                        client_wlan
                            .get(&c.index)
                            .is_some_and(|w| w.id == sp.wlan.id)
                    })
                    .filter_map(|(c, _, _)| mac(&c.mac))
                    .collect();
                blocked.insert(pid, macs);
            } else {
                hairpin.insert(pid);
            }
        }
        if !isolated.is_empty() {
            let mut blocked = blocked.clone();
            for pid in &isolated {
                let macs = mac_tables
                    .values()
                    .flat_map(|t| t.iter())
                    .filter(|(_, e)| e.port != *pid && isolated.contains(&e.port))
                    .map(|(m, _)| *m);
                blocked.entry(pid.clone()).or_default().extend(macs);
            }
            let meta = l.meta(d, "mac/isolated", vec![l.dev_span(d)]);
            l.out.functions.push(Arc::new(MacLookup {
                meta,
                tables: mac_tables.clone(),
                egress: egress.clone(),
                flood: l.id(d, "flood/isolated"),
                hairpin: hairpin.clone(),
                blocked,
            }));
            let ports: BTreeMap<BridgeDomainId, Vec<(PortId, FunctionId)>> = flood
                .iter()
                .map(|(bd, v)| {
                    let open = v.iter().filter(|(p, _)| !isolated.contains(p)).cloned();
                    (bd.clone(), open.collect())
                })
                .collect();
            let meta = l.meta(d, "flood/isolated", vec![l.dev_span(d)]);
            l.out.functions.push(Arc::new(Flood { meta, ports }));
        }
        let meta = l.meta(d, "mac", vec![l.dev_span(d)]);
        l.out.functions.push(Arc::new(MacLookup {
            meta,
            tables: mac_tables,
            egress,
            flood: l.id(d, "flood"),
            hairpin,
            blocked,
        }));
        let meta = l.meta(d, "flood", vec![l.dev_span(d)]);
        l.out.functions.push(Arc::new(Flood { meta, ports: flood }));
    }

    // Host attachment points, endpoints and attachment records.
    let mut points: BTreeSet<(String, String)> = BTreeSet::new();
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for (c, loc, net) in located.iter().filter(|(c, _, _)| !is_router(c)) {
        let Some(d) = site.device(&loc.0) else {
            continue;
        };
        if d.kind == DeviceKind::Other {
            continue;
        }
        let Some(ip) = c.ip.as_deref().and_then(|i| i.parse::<IpAddr>().ok()) else {
            continue;
        };
        let id = endpoint_id(c);
        if !ids.insert(id.clone()) {
            l.out.notes.push(format!("client {id} is listed twice"));
            continue;
        }
        l.out.endpoints.push(Endpoint {
            id: EndpointId::new(&id),
            addresses: vec![ip],
        });
        l.out.attachments.push(AttachmentRecord {
            address: ip,
            device: l.dev_name(d).as_str().into(),
            interface: InterfaceId::new(&loc.1),
            kind: AttachmentKind::Client,
            host: id,
            provenance: vec![l.client_span(c)],
        });
        if !points.insert((d.mac.clone(), loc.1.clone())) {
            continue;
        }
        let guest = client_wlan.get(&c.index).is_some_and(|w| w.guest);
        if guest {
            l.out
                .notes
                .push(format!("{} {}: guest policy not lowered", d.name, loc.1));
        }
        let local: Vec<Prefix> = match router.and_then(|r| r.vlans.get(&net.vlan)) {
            Some(addrs) => addrs
                .iter()
                .filter(|(a, len)| *len < if a.is_ipv4() { 32 } else { 128 })
                .map(|(a, len)| Prefix::new(*a, *len))
                .collect(),
            None => net
                .subnet
                .as_deref()
                .and_then(|s| {
                    let (a, len) = s.split_once('/')?;
                    Some(Prefix::new(a.parse().ok()?, len.parse().ok()?))
                })
                .into_iter()
                .collect(),
        };
        let gateway = router
            .filter(|r| r.vlans.contains_key(&net.vlan))
            .map(|r| HostMac {
                mac: r.mac,
                spans: r.provenance.clone(),
            });
        let next = format!("{}/in", loc.1);
        let meta = l.meta(d, &format!("host/{}", loc.1), vec![l.client_span(c)]);
        l.out.functions.push(Arc::new(HostResolution {
            meta,
            interface: InterfaceId::new(&loc.1),
            hosts: hosts.clone(),
            local,
            gateway,
            next: l.id(d, &next),
        }));
    }

    // The clients that are not placed: each packet from one is unknown.
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for (c, dev, why) in unplaced {
        let (Some(d), Some(ip)) = (
            site.device(&dev),
            c.ip.as_deref().and_then(|i| i.parse::<IpAddr>().ok()),
        ) else {
            continue;
        };
        if d.kind == DeviceKind::Other {
            continue;
        }
        let id = endpoint_id(c);
        if !ids.insert(id.clone()) {
            l.out.notes.push(format!("client {id} is listed twice"));
            continue;
        }
        let interface = format!("unplaced/{id}");
        let meta = l.meta(d, &interface, vec![l.client_span(c)]);
        l.out.functions.push(Arc::new(Unplaced {
            meta,
            interface: InterfaceId::new(&interface),
            detail: format!("client {} not placed: {why}", c.name),
        }));
        l.out.attachments.push(AttachmentRecord {
            address: ip,
            device: l.dev_name(d).as_str().into(),
            interface: InterfaceId::new(&interface),
            kind: AttachmentKind::Client,
            host: id,
            provenance: vec![l.client_span(c)],
        });
    }
    l.out
}

/// The summaries of the root devices of a site for the join of the links:
/// a root device has no uplink peer in the site. Each port can end a link,
/// and a frame enters it at its port ingress. The uplink record is the
/// neighbour record of the uplink port, with the gateway MAC as the MAC of
/// the far port. The links between the devices of the site come from the
/// uplink topology of the controller, not from the join.
pub fn link_summary(site: &Site, files: &Files) -> BTreeMap<String, crate::links::Summary> {
    let mut out = BTreeMap::new();
    for d in site
        .devices
        .iter()
        .filter(|d| d.uplink_peer.is_none() && d.kind != DeviceKind::Other)
    {
        let span = SourceSpan::row(
            &files.devices,
            u32::try_from(d.index + 1).unwrap_or(u32::MAX),
        );
        let mut s = crate::links::Summary::default();
        for p in ports(d) {
            let name = format!("port/{}", p.idx);
            s.entries.insert(
                name.clone(),
                FunctionId::new(format!("{}/port/{}/in", d.name, p.idx)),
            );
            s.facts.insert(
                name,
                LinkEnd {
                    speed_mbps: p.speed,
                    full_duplex: p.full_duplex,
                    media: p.media.clone(),
                    spans: vec![span.clone()],
                },
            );
        }
        if let (Some(port), Some(gw)) = (d.uplink_port, d.gateway_mac.as_deref().and_then(mac)) {
            s.neighbours.push(crate::links::Neighbour {
                port: format!("port/{port}"),
                name: None,
                remote_port: None,
                chassis: None,
                port_mac: Some(gw),
                span,
            });
        }
        out.insert(d.name.clone(), s);
    }
    out
}

/// The largest Ethernet frame with the FCS of a port of a UniFi device with
/// the flag `jumboframe_enabled` off. Not confirmed against a device.
pub const FRAME_BYTES: u64 = 1518;

/// The largest Ethernet frame with the FCS of a port of a UniFi device with
/// the flag `jumboframe_enabled` on. Not confirmed against a device.
pub const JUMBO_FRAME_BYTES: u64 = 9216;

/// The bytes of a frame with the FCS on top of the layer 3 packet: the
/// Ethernet header and the FCS.
pub const FRAME_OVERHEAD_BYTES: u64 = 18;

/// The MTU of each port of each device of a site with the flag
/// `jumboframe_enabled`, with the span of the device record.
pub fn mtus(site: &Site, files: &Files) -> crate::mtu::Mtus {
    let mut out = crate::mtu::Mtus::new();
    for d in &site.devices {
        let Some(jumbo) = d.jumbo else {
            continue;
        };
        let span = SourceSpan::row(
            &files.devices,
            u32::try_from(d.index + 1).unwrap_or(u32::MAX),
        );
        for p in ports(d) {
            out.insert(
                (device_name(d), format!("port/{}", p.idx)),
                crate::mtu::InterfaceMtu {
                    bytes: if jumbo {
                        JUMBO_FRAME_BYTES
                    } else {
                        FRAME_BYTES
                    } - FRAME_OVERHEAD_BYTES,
                    span: span.clone(),
                },
            );
        }
    }
    out
}

/// The endpoint name of a client: its name and the end of its MAC.
pub fn endpoint_id(c: &Client) -> String {
    let tail: String = c.mac.chars().filter(|x| *x != ':').skip(6).collect();
    format!("{}-{tail}", c.name.replace(' ', "_"))
}
