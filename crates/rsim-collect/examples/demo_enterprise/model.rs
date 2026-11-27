//! The model of the demo estate: the devices with their interfaces, the
//! links, the hosts and the peers outside the twin.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// The operating system of a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Os {
    Nxos,
    Iosxe,
    Iosxr,
}

impl Os {
    pub fn vendor(self) -> &'static str {
        match self {
            Os::Nxos => "nxos",
            Os::Iosxe => "iosxe",
            Os::Iosxr => "iosxr",
        }
    }
}

/// The role of a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Spine,
    Leaf,
    Border,
    Wan,
    Core,
    Access,
    Inet,
}

/// A MAC address in its 48 bits.
pub type Mac = u64;

/// A MAC in the form of Cisco, `025e.0001.0003`.
pub fn dotted(m: Mac) -> String {
    format!(
        "{:04x}.{:04x}.{:04x}",
        (m >> 32) & 0xffff,
        (m >> 16) & 0xffff,
        m & 0xffff
    )
}

/// A MAC in the form `02:5e:00:01:00:03`.
pub fn colon(m: Mac) -> String {
    (0..6)
        .map(|i| format!("{:02x}", (m >> (40 - 8 * i)) & 0xff))
        .collect::<Vec<_>>()
        .join(":")
}

/// The anycast gateway MAC of the fabrics.
pub const ANYCAST_MAC: Mac = 0x0000_5e00_5300;

/// The virtual MAC of HSRP version 1 group `g`.
pub fn hsrp_mac(g: u16) -> Mac {
    0x0000_0c07_ac00 | u64::from(g & 0xff)
}

/// The routing protocol of the routes that a device learns on an interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Ospf,
    Ebgp,
}

/// The layer 2 or layer 3 mode of an interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// A routed port.
    Routed,
    Loopback,
    /// The SVI of a VLAN.
    Svi(u16),
    /// An access port in a VLAN.
    Access(u16),
    /// A trunk with its VLANs.
    Trunk(Vec<u16>),
    /// A port channel that is a trunk with its VLANs.
    PortChannel(Vec<u16>),
    /// A member of port channel `n`, a trunk with the VLANs.
    Member(u16, Vec<u16>),
    /// The NVE interface.
    Nve,
    /// The management port.
    Mgmt,
}

/// An HSRP group of an SVI.
#[derive(Clone, Debug)]
pub struct Hsrp {
    pub group: u16,
    pub vip: Ipv4Addr,
    pub active: bool,
    pub priority: u16,
    /// The address of the other router of the group.
    pub peer: Ipv4Addr,
}

#[derive(Clone, Debug)]
pub struct Iface {
    pub name: String,
    pub desc: String,
    pub mode: Mode,
    pub mac: Option<Mac>,
    pub vrf: String,
    pub addr: Option<(Ipv4Addr, u8)>,
    /// The secondary address of a loopback: the shared tunnel end of a vPC
    /// pair.
    pub secondary: Option<(Ipv4Addr, u8)>,
    pub hsrp: Option<Hsrp>,
    pub anycast: bool,
    /// The SVI of a layer 3 VNI.
    pub ip_forward: bool,
    pub acl_in: Option<String>,
    /// The routing cost of the interface and the protocol of the routes
    /// that it learns. An interface with none is not a routing adjacency.
    pub routing: Option<(u32, Proto)>,
    /// The interface runs OSPF in area 0.
    pub ospf: bool,
    /// The OSPF cost of an OSPF interface.
    pub ospf_cost: u32,
    /// The OSPF interface is passive.
    pub ospf_passive: bool,
    pub speed: u32,
    pub peer_link: bool,
    /// The spanning tree blocks the port in each VLAN.
    pub blocked: bool,
    pub up: bool,
}

impl Iface {
    pub fn new(name: &str, desc: &str, mode: Mode) -> Iface {
        Iface {
            name: name.to_string(),
            desc: desc.to_string(),
            mode,
            mac: None,
            vrf: "default".into(),
            addr: None,
            secondary: None,
            hsrp: None,
            anycast: false,
            ip_forward: false,
            acl_in: None,
            routing: None,
            ospf: false,
            ospf_cost: 1,
            ospf_passive: false,
            speed: 10_000,
            peer_link: false,
            blocked: false,
            up: true,
        }
    }

    pub fn is_l3(&self) -> bool {
        self.addr.is_some()
    }

    /// The VLAN of an SVI.
    pub fn svi_vlan(&self) -> Option<u16> {
        match self.mode {
            Mode::Svi(v) => Some(v),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Vlan {
    pub id: u16,
    pub name: String,
    pub vni: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct Neighbor {
    pub vrf: String,
    pub addr: Ipv4Addr,
    pub remote_as: u32,
    pub desc: String,
    pub update_source: Option<String>,
    pub evpn: bool,
    pub rr_client: bool,
    pub up: bool,
}

#[derive(Clone, Debug)]
pub struct Bgp {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    pub neighbors: Vec<Neighbor>,
}

#[derive(Clone, Debug)]
pub struct Acl {
    pub name: String,
    /// The sequence number and the text of each entry, in the form of
    /// NX-OS.
    pub entries: Vec<(u32, String)>,
}

/// A static route of the config.
#[derive(Clone, Debug)]
pub struct Static {
    pub vrf: String,
    pub prefix: (Ipv4Addr, u8),
    pub next_hop: Ipv4Addr,
}

#[derive(Clone, Debug)]
pub struct Dev {
    pub name: String,
    pub os: Os,
    pub role: Role,
    /// The site: 0 for Frankfurt and 1 for Paris.
    pub site: usize,
    pub model: &'static str,
    pub serial: String,
    pub version: &'static str,
    pub mgmt: Ipv4Addr,
    pub ifaces: Vec<Iface>,
    pub vlans: Vec<Vlan>,
    /// The VRF, the VNI and the VLAN of the layer 3 VNI.
    pub l3vni: Option<(String, u32, u16)>,
    pub bgp: Option<Bgp>,
    /// The OSPF process redistributes the routes of BGP.
    pub ospf_redistribute_bgp: bool,
    pub vpc_domain: Option<u32>,
    pub vpc_peer: Option<usize>,
    /// The source address of the tunnel end.
    pub vtep: Option<Ipv4Addr>,
    pub nve_peers: Vec<Ipv4Addr>,
    pub acls: Vec<Acl>,
    pub statics: Vec<Static>,
    /// The spanning tree priority of the bridge.
    pub stp_priority: u32,
    pub base_mac: Mac,
}

impl Dev {
    pub fn iface(&self, name: &str) -> &Iface {
        self.ifaces
            .iter()
            .find(|i| i.name == name)
            .unwrap_or_else(|| panic!("{}: no interface {name}", self.name))
    }

    pub fn has_vlan(&self, v: u16) -> bool {
        self.vlans.iter().any(|x| x.id == v)
    }
}

/// A host on an access port.
#[derive(Clone, Debug)]
pub struct Host {
    pub name: String,
    pub mac: Mac,
    pub ip: Ipv4Addr,
    pub dev: usize,
    pub port: String,
    pub vlan: u16,
}

/// A cable between 2 ports.
#[derive(Clone, Debug)]
pub struct Link {
    pub a: (usize, String),
    pub b: (usize, String),
}

/// A router outside the twin on a port of a device.
#[derive(Clone, Debug)]
pub struct External {
    pub dev: usize,
    pub port: String,
    pub name: String,
    pub remote_port: String,
    pub ip: Ipv4Addr,
    pub mac: Mac,
}

#[derive(Clone, Debug, Default)]
pub struct Estate {
    pub devs: Vec<Dev>,
    pub links: Vec<Link>,
    pub hosts: Vec<Host>,
    pub externals: Vec<External>,
}

impl Estate {
    /// The far end of a port with a cable.
    pub fn far(&self, dev: usize, port: &str) -> Option<(usize, String)> {
        self.links.iter().find_map(|l| {
            if l.a.0 == dev && l.a.1 == port {
                Some(l.b.clone())
            } else if l.b.0 == dev && l.b.1 == port {
                Some(l.a.clone())
            } else {
                None
            }
        })
    }

    /// Checks that each address is on one device and each MAC on one
    /// interface or host, except the shared gateway addresses and MACs.
    pub fn check(&self) {
        let mut addrs: BTreeMap<Ipv4Addr, String> = BTreeMap::new();
        let mut macs: BTreeMap<Mac, String> = BTreeMap::new();
        let mut add_addr = |a: Ipv4Addr, who: String| {
            if let Some(o) = addrs.insert(a, who.clone()) {
                panic!("the address {a} is on {o} and on {who}");
            }
        };
        for d in &self.devs {
            let mut names = std::collections::BTreeSet::new();
            for i in &d.ifaces {
                assert!(names.insert(&i.name), "{}: 2 interfaces {}", d.name, i.name);
            }
            for i in &d.ifaces {
                if let Some((a, _)) = i.addr {
                    if i.anycast {
                        continue;
                    }
                    add_addr(a, format!("{}/{}", d.name, i.name));
                }
            }
            for i in &d.ifaces {
                if let Some(m) = i.mac {
                    let who = format!("{}/{}", d.name, i.name);
                    if let Some(o) = macs.insert(m, who.clone()) {
                        let same_po = matches!(i.mode, Mode::PortChannel(_));
                        if !same_po {
                            panic!("the MAC {} is on {o} and on {who}", dotted(m));
                        }
                    }
                }
            }
        }
        for h in &self.hosts {
            add_addr(h.ip, h.name.clone());
            if let Some(o) = macs.insert(h.mac, h.name.clone()) {
                panic!("the MAC {} is on {o} and on {}", dotted(h.mac), h.name);
            }
        }
        for e in &self.externals {
            add_addr(e.ip, e.name.clone());
        }
    }
}

/// The network address of an address and a length.
pub fn network(a: Ipv4Addr, len: u8) -> Ipv4Addr {
    let bits = u32::from(a);
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    Ipv4Addr::from(bits & mask)
}

/// The dotted mask of a length.
pub fn mask(len: u8) -> Ipv4Addr {
    Ipv4Addr::from(if len == 0 { 0 } else { u32::MAX << (32 - len) })
}

pub fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}
