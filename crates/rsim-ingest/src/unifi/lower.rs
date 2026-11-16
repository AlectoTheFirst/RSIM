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
    Flood, HostMac, HostResolution, MacEntry, MacLookup, Meta, PortEgress, PortIngress,
    VendorProfile, WirelessAttachment,
};

use crate::unifi::site::{Client, Device, DeviceKind, Forward, Network, Port, Site};

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
}

/// The function instances, endpoints, attachment records and notes of a
/// site.
#[derive(Default)]
pub struct Lowered {
    pub functions: Vec<Arc<dyn NetFunction>>,
    pub endpoints: Vec<Endpoint>,
    pub attachments: Vec<AttachmentRecord>,
    /// The ingress function of the UniFi port that the router port links
    /// to, with the router interface.
    pub router_peer: Option<(String, FunctionId)>,
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

impl<'a> L<'a> {
    fn dev_name(&self, d: &Device) -> String {
        d.name.clone()
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
        SourceSpan::line(
            &self.files.devices,
            u32::try_from(d.index + 1).unwrap_or(u32::MAX),
        )
    }
    fn client_span(&self, c: &Client) -> SourceSpan {
        SourceSpan::line(
            &self.files.clients,
            u32::try_from(c.index + 1).unwrap_or(u32::MAX),
        )
    }
    fn bd(&self, n: &Network) -> BridgeDomainId {
        BridgeDomainId::new(format!("{}/{}", self.prefix, n.name))
    }
    /// The default network: the network with no VLAN.
    fn default_network(&self) -> Option<&'a Network> {
        self.site
            .networks
            .iter()
            .find(|n| n.vlan.is_none() && n.purpose != "wan")
    }
    /// The native bridge domain and the tagged bridge domains of a port.
    fn membership(&self, p: &Port) -> (Option<&'a Network>, Vec<&'a Network>) {
        let native = p
            .native
            .as_deref()
            .and_then(|id| self.site.network(id))
            .or_else(|| self.default_network());
        let others = || {
            self.site.networks.iter().filter(|n| {
                n.vlan.is_some()
                    && n.purpose != "wan"
                    && Some(n.id.as_str()) != native.map(|x| x.id.as_str())
            })
        };
        let tagged = match p.forward {
            Forward::All => others().collect(),
            Forward::Customize => others().filter(|n| !p.excluded.contains(&n.id)).collect(),
            Forward::Native | Forward::Disabled | Forward::Other => Vec::new(),
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

    /// The port of the device on the link to the router.
    fn root_router_port(&self, d: &Device) -> Option<u32> {
        self.router.filter(|r| r.switch == d.mac).map(|r| r.port)
    }
}

/// The ports of a device. An access point with no port table gets one port
/// for its uplink that carries all networks.
fn ports(d: &Device) -> Vec<Port> {
    if !d.ports.is_empty() {
        return d.ports.clone();
    }
    match d.uplink_port.or(Some(1)) {
        Some(idx) if d.kind == DeviceKind::AccessPoint => vec![Port {
            idx,
            up: true,
            enabled: true,
            forward: Forward::All,
            native: None,
            excluded: Vec::new(),
            stp_state: None,
            isolation: false,
            aggregated: false,
        }],
        _ => Vec::new(),
    }
}

/// Lowers a site. `prefix` names the bridge domains, for example the
/// device of the site in the store.
pub fn lower(
    prefix: &str,
    site: &Site,
    profile: &VendorProfile,
    files: &Files,
    router: Option<&RouterPort>,
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
                    "device {} of type {} is not lowered",
                    d.name, d.type_name
                ));
                false
            } else {
                true
            }
        })
        .collect();

    // The location and the bridge domain of each client MAC.
    let wlan_net: BTreeMap<&str, &Network> = site
        .wlans
        .iter()
        .filter_map(|w| site.network(&w.network).map(|n| (w.ssid.as_str(), n)))
        .collect();
    let mut located: Vec<(&Client, Location, &Network)> = Vec::new();
    for c in &site.clients {
        let (loc, net) = match (&c.switch, &c.ap) {
            (Some((sw, p)), _) => {
                let dev = site.device(sw);
                let port = dev.and_then(|d| ports(d).into_iter().find(|x| x.idx == *p));
                let net = port.and_then(|p| l.membership(&p).0.cloned());
                ((sw.clone(), format!("port/{p}")), net)
            }
            (None, Some((ap, ssid))) => (
                (ap.clone(), format!("wlan/{ssid}")),
                wlan_net.get(ssid.as_str()).map(|n| (*n).clone()),
            ),
            _ => continue,
        };
        let Some(net) = net.and_then(|n| site.network(&n.id)) else {
            l.out.notes.push(format!(
                "client {}: the network of its port is not known",
                c.name
            ));
            continue;
        };
        located.push((c, loc, net));
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
        for p in &dports {
            let (native, tagged) = l.membership(p);
            let pid = PortId::new(format!("port/{}", p.idx));
            let span = l.dev_span(d);
            if p.aggregated {
                l.out.notes.push(format!(
                    "{} port {}: link aggregation is not lowered",
                    d.name, p.idx
                ));
            }
            if p.isolation {
                l.out.notes.push(format!(
                    "{} port {}: port isolation is not lowered",
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
                next: l.id(d, "mac"),
            }));
            // The peer of the port.
            let peer = if Some(p.idx) == d.uplink_port
                && let Some((up, rp)) = parent
            {
                Some(l.id(up, &format!("port/{rp}/in")))
            } else if Some(p.idx) == router_port {
                let r = router.expect("a router port has a router");
                l.out.router_peer = Some((r.interface.clone(), l.id(d, &in_id)));
                Some(r.handoff.clone())
            } else {
                site.devices
                    .iter()
                    .find(|c| {
                        c.uplink_peer.as_ref() == Some(&(d.mac.clone(), p.idx))
                            && c.kind != DeviceKind::Other
                    })
                    .and_then(|c| c.uplink_port.map(|up| l.id(c, &format!("port/{up}/in"))))
            };
            let port_hosts: BTreeMap<Mac, EndpointId> = located
                .iter()
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
                peer,
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
        for v in d.vaps.iter().filter(|v| v.up) {
            let Some(w) = site.wlans.iter().find(|w| w.ssid == v.ssid && w.enabled) else {
                continue;
            };
            let Some(n) = site.network(&w.network) else {
                continue;
            };
            let pid = PortId::new(format!("wlan/{}", v.ssid));
            let span = SourceSpan::line(
                &l.files.wlans,
                u32::try_from(w.index + 1).unwrap_or(u32::MAX),
            );
            let meta = l.meta(d, &format!("wlan/{}/in", v.ssid), vec![span.clone()]);
            l.out.functions.push(Arc::new(WirelessAttachment {
                meta,
                port: pid.clone(),
                bridge_domain: l.bd(n),
                next: l.id(d, "mac"),
            }));
            let hosts_on: BTreeMap<Mac, EndpointId> = located
                .iter()
                .filter(|(_, loc, _)| loc.0 == d.mac && loc.1 == pid.to_string())
                .filter_map(|(c, _, _)| Some((mac(&c.mac)?, EndpointId::new(endpoint_id(c)))))
                .collect();
            let out_name = format!("wlan/{}/out", v.ssid);
            let meta = l.meta(d, &out_name, vec![span]);
            l.out.functions.push(Arc::new(PortEgress {
                meta,
                port: pid.clone(),
                native: Some(l.bd(n)),
                tagged: BTreeMap::new(),
                peer: None,
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
            for n in &site.networks {
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
        let meta = l.meta(d, "mac", vec![l.dev_span(d)]);
        l.out.functions.push(Arc::new(MacLookup {
            meta,
            tables: mac_tables,
            egress,
            flood: l.id(d, "flood"),
        }));
        let meta = l.meta(d, "flood", vec![l.dev_span(d)]);
        l.out.functions.push(Arc::new(Flood { meta, ports: flood }));
    }

    // Host attachment points, endpoints and attachment records.
    let mut points: BTreeSet<(String, String)> = BTreeSet::new();
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for (c, loc, net) in &located {
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
        let restricted = loc.1.starts_with("wlan/")
            && site
                .wlans
                .iter()
                .any(|w| format!("wlan/{}", w.ssid) == loc.1 && w.restricted);
        if restricted {
            l.out.notes.push(format!(
                "{} {}: client isolation or a guest policy is not lowered",
                d.name, loc.1
            ));
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
    l.out
}

/// The endpoint name of a client: its name and the end of its MAC.
pub fn endpoint_id(c: &Client) -> String {
    let tail: String = c.mac.chars().filter(|x| *x != ':').skip(6).collect();
    format!("{}-{tail}", c.name.replace(' ', "_"))
}
